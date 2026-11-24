"""Local SOCKS5 connections, core processes and curl probes."""

import asyncio
import contextlib
import ipaddress
import json
import logging
import secrets
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .profiles import MAX_SOURCE_BYTES

LOG = logging.getLogger(__name__)
LOOPBACK = "127.0.0.1"
FAILURE = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"


class SocksError(OSError):
    pass


async def close_writer(writer):
    writer.close()
    with contextlib.suppress(OSError, TimeoutError):
        async with asyncio.timeout(1):
            await writer.wait_closed()


async def address_bytes(reader, address_type):
    if address_type == 1:
        return await reader.readexactly(6)
    if address_type == 4:
        return await reader.readexactly(18)
    if address_type == 3:
        length = await reader.readexactly(1)
        if not length[0]:
            raise SocksError("empty SOCKS domain")
        return length + await reader.readexactly(length[0] + 2)
    raise SocksError("unsupported SOCKS address type")


def destination(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna")
        return b"\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big")
    return bytes([1 if ip.version == 4 else 4]) + ip.packed + port.to_bytes(2, "big")


async def connect_core(core):
    reader, writer = await asyncio.open_connection(LOOPBACK, core.port)
    try:
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x02":
            raise SocksError("backend did not select authentication")
        password = core.password.encode("ascii")
        writer.write(b"\x01\x09autoproxy" + bytes([len(password)]) + password)
        await writer.drain()
        if await reader.readexactly(2) != b"\x01\x00":
            raise SocksError("backend authentication failed")
        return reader, writer
    except BaseException:
        await close_writer(writer)
        raise


async def request_core(reader, writer, target):
    writer.write(b"\x05\x01\x00" + target)
    await writer.drain()
    reply = await reader.readexactly(4)
    if reply[0] != 5 or reply[2] != 0:
        raise SocksError("invalid backend reply")
    return reply + await address_bytes(reader, reply[3])


async def relay(client_reader, client_writer, upstream_reader, upstream_writer):
    async def copy(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()

    async with asyncio.TaskGroup() as group:
        group.create_task(copy(client_reader, upstream_writer))
        group.create_task(copy(upstream_reader, client_writer))


async def stop_process(process):
    if process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        process.terminate()
    try:
        async with asyncio.timeout(2):
            await process.wait()
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()


def core_config(profile, port, password, directory):
    if profile.engine == "xray":
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": LOOPBACK, "port": port, "protocol": "socks",
                "settings": {"auth": "password", "udp": False,
                             "accounts": [{"user": "autoproxy", "pass": password}]},
            }],
            "outbounds": [profile.payload],
        }
    config = {
        "socks-port": port, "allow-lan": False, "bind-address": LOOPBACK,
        "authentication": [f"autoproxy:{password}"], "skip-auth-prefixes": [],
        "mode": "rule",
        "log-level": "error", "find-process-mode": "off",
        "rules": ["MATCH,candidate"],
    }
    if isinstance(profile.payload, str):
        (directory / "candidate.txt").write_text(profile.payload + "\n", encoding="utf-8")
        config["proxy-providers"] = {"local": {"type": "file", "path": "./candidate.txt"}}
        config["proxy-groups"] = [{
            "name": "candidate", "type": "select", "use": ["local"],
            "empty-fallback": "REJECT", "disable-udp": True,
        }]
    else:
        config["proxies"] = [profile.payload]
    return config


class Core:
    def __init__(self, profile, settings):
        self.profile = profile
        self.settings = settings
        self.process = None
        self.directory = None
        self.port = None
        self.password = secrets.token_hex(16)
        self.startup = None
        self.closing = None
        self.leases = 0
        self.sessions = set()
        self.drain = None

    @property
    def alive(self):
        return self.process is not None and self.process.returncode is None

    async def start(self):
        try:
            self.directory = tempfile.TemporaryDirectory(prefix="autoproxy-")
            directory = Path(self.directory.name)
            with socket.socket() as reservation:
                reservation.bind((LOOPBACK, 0))
                self.port = reservation.getsockname()[1]
                config_path = directory / "config.json"
                config_path.write_text(json.dumps(
                    core_config(self.profile, self.port, self.password, directory)
                ), encoding="utf-8")
            if self.profile.engine == "xray":
                args = [self.settings.xray, "run", "-c", str(config_path)]
            else:
                args = [self.settings.mihomo, "-d", str(directory), "-f", str(config_path)]
            self.process = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            async with asyncio.timeout(self.settings.startup_timeout):
                while self.alive:
                    try:
                        async with asyncio.timeout(0.25):
                            _, writer = await connect_core(self)
                        await close_writer(writer)
                        if self.alive:
                            return
                    except (OSError, TimeoutError, asyncio.IncompleteReadError):
                        await asyncio.sleep(0.05)
            raise OSError("proxy core exited during startup")
        except BaseException:
            await self.close()
            raise

    async def close(self):
        try:
            if self.process is not None:
                await stop_process(self.process)
        finally:
            if self.directory is not None:
                self.directory.cleanup()
                self.directory = None


async def curl(settings, *args, private_url=None):
    command = [settings.curl, "--disable", "--silent", "--noproxy", "", "--proto",
               "=http,https", *args]
    stdin = asyncio.subprocess.DEVNULL
    config = None
    if private_url is not None:
        command.extend(["--config", "-"])
        stdin = asyncio.subprocess.PIPE
        config = ("url = " + json.dumps(private_url, ensure_ascii=False) + "\n").encode()
    process = await asyncio.create_subprocess_exec(
        *command, stdin=stdin, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        output, _ = await process.communicate(config)
    except BaseException:
        await stop_process(process)
        raise
    return process.returncode, output


async def fetch_subscription(settings, url):
    redirect_protocols = "=https" if urlsplit(url).scheme == "https" else "=http,https"
    status, body = await curl(
        settings, "--fail", "--location", "--max-redirs", "5", "--proxy", "",
        "--proto-redir", redirect_protocols, "--max-time", str(settings.subscription_timeout),
        "--max-filesize", str(MAX_SOURCE_BYTES), private_url=url,
    )
    if status or len(body) > MAX_SOURCE_BYTES:
        raise OSError("subscription fetch failed")
    return body


async def tcp_probe(profile, timeout):
    async with asyncio.timeout(timeout):
        _, writer = await asyncio.open_connection(profile.host, profile.port)
        await close_writer(writer)


async def tunnel_probe(core, settings):
    for target_url in settings.check_urls:
        try:
            async with asyncio.timeout(settings.tunnel_timeout):
                reader, writer = await connect_core(core)
                try:
                    target = urlsplit(target_url)
                    reply = await request_core(reader, writer, destination(
                        target.hostname, target.port or 443
                    ))
                    if reply[1] == 0:
                        return
                finally:
                    await close_writer(writer)
        except (OSError, asyncio.IncompleteReadError):
            continue
    raise SocksError("TCP connection through the tunnel failed")


async def measure(settings, core, target, timeout, limit):
    status, output = await curl(
        settings, "--fail", "--proxy", f"socks5h://{LOOPBACK}:{core.port}",
        "--proxy-user", f"autoproxy:{core.password}", "--max-time", str(timeout),
        "--max-filesize", str(limit), "--output", "/dev/null",
        "--write-out", "%{response_code} %{size_download} %{time_starttransfer} %{time_total}",
        "--url", target,
    )
    try:
        code, count, first, total = output.split()
        return status, int(code), int(count), float(first), float(total)
    except ValueError as exc:
        raise OSError("invalid curl measurement") from exc


async def https_probe(core, settings):
    for target in settings.check_urls:
        try:
            status, code, _, first, _ = await measure(
                settings, core, target, settings.https_timeout, 64 * 1024
            )
            if status == 0 and 200 <= code < 300:
                return first
        except OSError:
            continue
    raise OSError("HTTPS check failed")


async def speed_probe(core, settings):
    count_limit = settings.download_bytes
    target = settings.download_url.replace("{bytes}", str(count_limit))
    status, code, count, first, total = await measure(
        settings, core, target, settings.download_timeout, count_limit
    )
    if (200 <= code < 300 and count >= settings.min_download_bytes and total > first
            and (status in (0, 28) or status == 63 and count == count_limit)):
        return count / (total - first)
    return None
