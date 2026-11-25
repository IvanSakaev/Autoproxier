"""Configuration and import of individual proxy nodes."""

import base64
import binascii
import configparser
import copy
import hashlib
import ipaddress
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import yaml

LOG = logging.getLogger(__name__)
MAX_SOURCE_BYTES = 8 * 1024 * 1024
URI_TYPES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "socks", "socks5", "socks5h"}
MIHOMO_TYPES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hysteria", "tuic",
                "wireguard", "socks5", "http", "anytls"}
UDP_NETWORKS = {"udp", "kcp", "mkcp", "quic", "h3", "h3-l4proxy", "hysteria", "mekya"}
XRAY_SERVERS = {"vless": "vnext", "vmess": "vnext", "trojan": "servers",
                "shadowsocks": "servers", "socks": "servers", "http": "servers",
                "hysteria": "servers"}


def url(value, schemes):
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("invalid URL")
    parsed = urlsplit(value)
    if parsed.scheme not in schemes or not parsed.hostname:
        raise ValueError("invalid URL scheme or host")
    if parsed.port == 0:
        raise ValueError("invalid URL port")
    return parsed


@dataclass(frozen=True)
class Settings:
    profiles: tuple[Path, ...] = ()
    subscriptions: tuple[str, ...] = field(default=(), repr=False)
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    scan_interval: float = 1800.0
    health_interval: float = 5.0
    health_failures: int = 2
    retry_interval: float = 15.0
    drain_timeout: float = 120.0
    tcp_timeout: float = 2.0
    tunnel_timeout: float = 5.0
    https_timeout: float = 5.0
    startup_timeout: float = 5.0
    subscription_timeout: float = 15.0
    concurrency: int = 8
    download_bytes: int = 16 * 1024 * 1024
    min_download_bytes: int = 1024 * 1024
    download_timeout: float = 20.0
    check_urls: tuple[str, ...] = (
        "https://www.gstatic.com/generate_204",
        "https://www.cloudflare.com/cdn-cgi/trace",
    )
    download_url: str = "https://speed.cloudflare.com/__down?bytes={bytes}"
    xray: str = "xray"
    mihomo: str = "mihomo"
    curl: str = "curl"

    @classmethod
    def load(cls, path):
        data = json.loads(read_source(path).decode("utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("configuration must be a JSON object")
        defaults = cls()
        for key, value in data.items():
            if key not in cls.__dataclass_fields__:
                raise ValueError("unknown configuration setting")
            default = getattr(defaults, key)
            if isinstance(default, tuple):
                if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                    raise ValueError(f"{key} must be a list of non-empty strings")
                data[key] = tuple(value)
                continue
            if isinstance(default, (int, float)):
                expected = (int,) if type(default) is int else (int, float)
                if (type(value) not in expected or type(value) is float and not math.isfinite(value)
                        or value < 0 or value == 0 and key != "drain_timeout"):
                    raise ValueError(f"invalid numeric setting: {key}")
                continue
            if not isinstance(value, str) or not value:
                raise ValueError(f"{key} must be a non-empty string")
        if "profiles" in data:
            data["profiles"] = tuple(path.parent / p for p in data["profiles"])
        settings = cls(**data)
        if not settings.profiles and not settings.subscriptions:
            raise ValueError("configure at least one profile or subscription")
        if not settings.check_urls or settings.listen_port > 65535:
            raise ValueError("configure a valid listen_port and at least one check URL")
        if settings.min_download_bytes > settings.download_bytes:
            raise ValueError("min_download_bytes must not exceed download_bytes")
        for entry in settings.subscriptions:
            url(entry, {"http", "https"})
        for entry in settings.check_urls:
            url(entry, {"https"})
        url(settings.download_url.replace("{bytes}", str(settings.download_bytes)), {"https"})
        return settings


def read_source(path):
    with path.open("rb") as source:
        data = source.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source exceeds 8 MiB")
    return data


def fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Profile:
    engine: str
    payload: dict | str = field(repr=False)
    host: str
    port: int
    tcp: bool
    wireguard_id: str | None = field(default=None, repr=False)
    key: str = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "key", fingerprint([self.engine, self.payload]))

    @property
    def label(self):
        return f"{self.engine}/{self.key[:12]}"


def endpoint(host, port):
    if (not isinstance(host, str) or not host or
            any(c.isspace() or ord(c) < 32 for c in host)):
        raise ValueError("invalid endpoint host")
    if type(port) not in (int, str) or not 0 < int(port) <= 65535:
        raise ValueError("invalid endpoint port")
    return host, int(port)


def uses_tcp(protocol, network, alpn):
    return not (protocol in {"wireguard", "hysteria", "hysteria2", "hy2", "tuic"}
                or network in UDP_NETWORKS or network in {"xhttp", "splithttp", "masque"}
                and "h3" in alpn)


def decode64(value):
    data = value.encode("ascii") if isinstance(value, str) else value
    data = b"".join(data.split())
    return base64.b64decode(data + b"=" * (-len(data) % 4), altchars=b"-_", validate=True)


def uri_profile(line):
    parsed = urlsplit(line)
    if (parsed.scheme not in URI_TYPES or not parsed.netloc
            or any(c.isspace() or ord(c) < 32 for c in line)):
        raise ValueError("invalid or unsupported proxy URI")
    query = parse_qs(parsed.query)
    authority = parsed
    if parsed.scheme == "vmess" and not parsed.username:
        details = json.loads(decode64(parsed.netloc + parsed.path))
        host, port = endpoint(details["add"], details["port"])
        network = details.get("net", "tcp").lower()
        alpn = details.get("alpn", "").split(",")
    else:
        if parsed.scheme == "ss" and not parsed.username:
            authority = url("ss://" + decode64(parsed.netloc + parsed.path).decode(), {"ss"})
        if parsed.scheme in {"hysteria2", "hy2"}:
            # Port hopping is interpreted by Mihomo. These nodes never get a TCP precheck.
            authority_tail = authority.netloc.rsplit("@", 1)[-1].rsplit("]", 1)[-1]
            port = authority_tail.rpartition(":")[2].split(",")[0].split("-")[0] or 443
            if ":" not in authority_tail:
                port = 443
        else:
            port = authority.port
        host, port = endpoint(authority.hostname, port)
        network = query.get("type", ["tcp"])[0].lower()
        alpn = query.get("alpn", [""])[0].split(",")
    return Profile("mihomo", line.partition("#")[0], host, port,
                   uses_tcp(parsed.scheme, network, alpn))


def mihomo_profile(raw):
    if not isinstance(raw, dict) or raw.get("type") not in MIHOMO_TYPES:
        raise ValueError("unsupported Mihomo node type")
    if raw.get("dialer-proxy") or raw.get("peers"):
        raise ValueError("proxy chains and multi-peer WireGuard nodes are unsupported")
    payload = {**raw, "name": "candidate"}
    node_type = payload["type"]
    host, port = endpoint(payload["server"], payload.get("port", 443))
    identity = None
    if node_type == "wireguard":
        identity = fingerprint([payload["private-key"], payload["public-key"]])
    alpn = payload.get("alpn") or []
    return Profile("mihomo", payload, host, port,
                   uses_tcp(node_type, payload.get("network", "tcp"), alpn), identity)


def xray_profiles(document):
    if not isinstance(document, dict):
        raise ValueError("expected an Xray object")
    outbounds = document.get("outbounds", [document])
    if not isinstance(outbounds, list):
        raise ValueError("expected Xray outbounds array")
    for index, raw in enumerate(outbounds, 1):
        try:
            protocol = raw["protocol"]
            if protocol not in XRAY_SERVERS:
                continue
            stream = raw.get("streamSettings", {})
            sockopt = stream.get("sockopt", {})
            if raw.get("proxySettings") or sockopt.get("dialerProxy"):
                raise ValueError("outbound requires a proxy chain")
            settings = raw["settings"]
            list_key = XRAY_SERVERS[protocol]
            records = settings.get(list_key)
            if records is not None and not isinstance(records, list):
                raise ValueError("expected Xray server array")
            for server_index, server in enumerate(records if records is not None else [settings], 1):
                try:
                    host, port = endpoint(server["address"], server["port"])
                    outbound = copy.deepcopy(raw)
                    outbound["tag"] = "candidate"
                    if records is not None:
                        outbound["settings"][list_key] = [copy.deepcopy(server)]
                    network = stream.get("network", "tcp")
                    alpn = (stream.get("tlsSettings", {}).get("alpn") or [])
                    yield Profile("xray", outbound, host, port,
                                  uses_tcp(protocol, network, alpn))
                except (KeyError, ValueError, TypeError, AttributeError):
                    LOG.warning("Xray outbound %s server %s: invalid endpoint or settings",
                                index, server_index)
        except (KeyError, ValueError, TypeError, AttributeError):
            LOG.warning("Xray outbound %s: invalid or requires another outbound", index)


AWG_NUMERIC = {"jc": "jc", "jmin": "jmin", "jmax": "jmax", "itime": "itime",
               "rekeyaftertime": "rekey-after-time", "rekeytimeout": "rekey-timeout",
               "rejectaftertime": "reject-after-time", "keepalivetimeout": "keepalive-timeout",
               "maxhandshakeattempts": "max-handshake-attempts",
               **{f"s{i}": f"s{i}" for i in range(1, 5)}}
AWG_STRINGS = {"headerprotectionkey": "header-protection-key",
               "contentpaddingaddition": "content-padding-addition",
               "randompaddingaddition": "content-padding-addition",
               **{f"{prefix}{i}": f"{prefix}{i}" for prefix, count in (("h", 4), ("i", 5), ("j", 3))
                  for i in range(1, count + 1)}}
AWG_FLAGS = {"randomtrailers": "random-trailers", "disablecookie": "disable-cookies",
             "disablecookies": "disable-cookies"}
AWG_V3_FIELDS = {"header-protection-key", "content-padding-addition", "rekey-after-time",
                 "rekey-timeout", "reject-after-time", "keepalive-timeout",
                 "max-handshake-attempts", "random-trailers", "disable-cookies"}


def wg_profile(source):
    config = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    config.read_string(source)
    if set(config.sections()) != {"Interface", "Peer"} or config.defaults():
        raise ValueError("expected one [Interface] and one [Peer]")
    interface, peer = config["Interface"], config["Peer"]
    remote = url("socks5://" + peer["endpoint"], {"socks5"})
    host, port = endpoint(remote.hostname, remote.port)
    node = {"type": "wireguard", "server": host, "port": port, "udp": True,
            "private-key": interface["privatekey"], "public-key": peer["publickey"],
            "allowed-ips": [str(ipaddress.ip_network(v.strip(), strict=False))
                            for v in peer["allowedips"].split(",")]}
    for value in interface["address"].split(","):
        address = ipaddress.ip_interface(value.strip()).ip
        node.setdefault("ip" if address.version == 4 else "ipv6", str(address))
    if "dns" in interface:
        dns = []
        for item in interface["dns"].split(","):
            try:
                dns.append(str(ipaddress.ip_address(item.strip())))
            except ValueError:
                continue  # DNS search suffixes are not resolvers.
        if dns:
            node.update({"remote-dns-resolve": True, "dns": dns})
    if "mtu" in interface:
        node["mtu"] = interface.getint("mtu")
    if "presharedkey" in peer:
        node["pre-shared-key"] = peer["presharedkey"]
    if "persistentkeepalive" in peer and peer["persistentkeepalive"].lower() != "off":
        node["persistent-keepalive"] = peer.getint("persistentkeepalive")
    if "reserved" in peer:
        node["reserved"] = [int(v.strip()) for v in peer["reserved"].split(",")]
    options = {target: interface.getint(key) for key, target in AWG_NUMERIC.items()
               if key in interface}
    options.update({target: interface[key] for key, target in AWG_STRINGS.items()
                    if interface.get(key)})
    options.update({target: interface.getboolean(key) for key, target in AWG_FLAGS.items()
                    if key in interface})
    if options:
        version = interface.get("version", "").split(".")[0]
        options["version"] = 3 if version == "3" or AWG_V3_FIELDS.intersection(options) else 2
        node["amnezia-wg-option"] = options
    return mihomo_profile(node)


def local_profiles(path):
    source = read_source(path).decode("utf-8-sig")
    if path.suffix.lower() == ".conf":
        return [wg_profile(source)]
    if path.suffix.lower() == ".json":
        return list(xray_profiles(json.loads(source)))
    raise ValueError("unsupported file extension")


def subscription_profiles(body):
    text = body.decode("utf-8-sig").strip()
    if "://" not in text:
        try:
            decoded = decode64(text).decode("utf-8-sig").strip()
            if "://" in decoded:
                text = decoded
        except (UnicodeError, binascii.Error):
            pass
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if any("://" in line and line.split("://", 1)[0].isalnum() for line in lines):
        rows, parse = lines, uri_profile
    else:
        document = yaml.safe_load(text)
        if not isinstance(document, dict) or not isinstance(document.get("proxies"), list):
            raise ValueError("expected a list of links or a Mihomo proxies list")
        rows, parse = document["proxies"], mihomo_profile
    profiles = []
    for index, row in enumerate(rows, 1):
        try:
            profiles.append(parse(row))
        except (KeyError, ValueError, TypeError, AttributeError):
            LOG.warning("Subscription node %s: unsupported protocol or invalid settings", index)
    if not profiles:
        raise ValueError("subscription has no usable nodes")
    return profiles
