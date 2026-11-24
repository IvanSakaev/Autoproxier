import asyncio
import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from autoproxy.network import (
    FAILURE, Core, address_bytes, close_writer, connect_core, core_config, destination,
    https_probe, relay, request_core, speed_probe, stop_process, tunnel_probe,
)
from autoproxy.profiles import Settings, subscription_profiles, wg_profile, xray_profiles
from autoproxy.service import AutoProxy, DeferredProbe, Result


FIRST = "vless://d6ce054b-20d1-4a76-9b47-9cd209c7640f@first.test:443?security=tls"
SECOND = "hy2://secret@second.test:443,5000-5100#label"
WG = """[Interface]
PrivateKey = test-private
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, example.test
MTU = 1380
Jc = 4
H1 = 10-20
I1 =
HeaderProtectionKey = test-header-protection
RandomTrailers = true
DisableCookie = true
PostUp = never executed

[Peer]
PublicKey = test-public
PresharedKey = test-psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2001:db8::1]:51820
PersistentKeepalive = 25
"""


def example_profile(uri=FIRST):
    return subscription_profiles(uri.encode())[0]


class ParsingTests(unittest.TestCase):
    def test_plain_and_base64_subscription(self):
        data = (FIRST + "#one\n" + SECOND + "\nunsupported://example.test:99").encode()
        wrapped = base64.urlsafe_b64encode(data).rstrip(b"=")
        for body in (data, wrapped):
            with self.assertLogs(level="WARNING") as logs:
                a, b = subscription_profiles(body)
            self.assertNotIn("secret", str(logs.output))
            self.assertTrue(a.tcp)
            self.assertFalse(b.tcp)
            self.assertEqual((b.host, b.port), ("second.test", 443))
        self.assertEqual(example_profile().key, example_profile(FIRST + "#other").key)

    def test_base64_vmess_and_yaml(self):
        record = json.dumps({"add": "example.test", "port": "123", "net": "kcp"}).encode()
        link = b"vmess://" + base64.b64encode(record)
        self.assertFalse(subscription_profiles(link)[0].tcp)
        nodes = subscription_profiles(b"""proxies:
  - {name: a, type: trojan, server: '::1', port: 443}
  - {name: b, type: vless, server: a.test, port: 443, network: xhttp, alpn: [h3]}
rules: [MATCH,DIRECT]
""")
        self.assertEqual([x.tcp for x in nodes], [True, False])

    def test_xray_splits_each_endpoint(self):
        config = {"inbounds": [{}], "outbounds": [
            {"protocol": "freedom"},
            {"protocol": "vless", "settings": {"vnext": [
                {"address": "a.test", "port": 443, "users": [{"id": "fixture"}]},
                {"address": "b.test", "port": 80},
            ]}, "streamSettings": {"network": "ws"}},
            {"protocol": "vmess", "settings": {"address": "::1", "port": 1443},
             "streamSettings": {"network": "kcp"}},
        ]}
        a, b, c = xray_profiles(config)
        self.assertEqual([a.host, b.host, c.host], ["a.test", "b.test", "::1"])
        self.assertEqual(len(a.payload["settings"]["vnext"]), 1)
        self.assertFalse(c.tcp)

    def test_awg_fields_and_identity(self):
        profile = wg_profile(WG)
        self.assertFalse(profile.tcp)
        self.assertEqual(profile.host, "2001:db8::1")
        self.assertEqual(profile.payload["dns"], ["1.1.1.1"])
        self.assertNotIn("postup", profile.payload)
        options = profile.payload["amnezia-wg-option"]
        self.assertEqual(options["version"], 3)
        self.assertEqual(options["h1"], "10-20")
        self.assertNotIn("i1", options)
        self.assertTrue(options["disable-cookies"])
        self.assertEqual(profile.wireguard_id,
                         wg_profile(WG.replace("51820", "51821")).wireguard_id)

    def test_config_paths_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"profiles":["a.json"],"drain_timeout":0,"health_interval":0.1}')
            settings = Settings.load(path)
            self.assertEqual(settings.profiles, (Path(tmp) / "a.json",))
            self.assertEqual(settings.drain_timeout, 0)
            self.assertEqual(settings.health_interval, 0.1)

    def test_generated_provider_cannot_fall_back_to_direct(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config = core_config(example_profile(), 12345, "test-token", directory)
            self.assertEqual(config["rules"], ["MATCH,candidate"])
            self.assertEqual(config["proxy-groups"][0]["empty-fallback"], "REJECT")
            self.assertEqual((directory / "candidate.txt").read_text(), FIRST + "\n")


class MemoryProcess:
    def __init__(self):
        self.returncode = None
        self.exited = asyncio.Event()

    async def wait(self):
        await self.exited.wait()
        return self.returncode


class LocalCore(Core):
    """Authenticated SOCKS backend for integration tests, with an optional local TLS target."""

    target = None

    async def start(self):
        self.process = MemoryProcess()
        self.handlers = set()
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def close(self):
        if not self.alive:
            return
        self.process.returncode = 0
        self.process.exited.set()
        self.server.close()
        tasks = tuple(self.handlers)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.server.wait_closed()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.handlers.add(task)
        upstream = None
        try:
            _, nmethods = await reader.readexactly(2)
            if b"\x02" not in await reader.readexactly(nmethods):
                return
            writer.write(b"\x05\x02")
            version, length = await reader.readexactly(2)
            name = await reader.readexactly(length)
            size = (await reader.readexactly(1))[0]
            password = await reader.readexactly(size)
            if (version, name, password) != (1, b"autoproxy", self.password.encode()):
                return
            writer.write(b"\x01\x00")
            header = await reader.readexactly(4)
            target = await address_bytes(reader, header[-1])
            writer.write(b"\x05\x00" + FAILURE[2:])
            await writer.drain()
            if self.target:
                upstream_reader, upstream = await asyncio.open_connection(*self.target)
                try:
                    await relay(reader, writer, upstream_reader, upstream)
                except* OSError:
                    pass
            else:
                self.last_target = bytes([header[-1]]) + target
                while line := await reader.readline():
                    writer.write(self.profile.host.encode() + b" " + line)
                    await writer.drain()
        except (asyncio.IncompleteReadError, OSError):
            pass
        finally:
            if upstream:
                await close_writer(upstream)
            await close_writer(writer)
            self.handlers.discard(task)


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        try:
            with socket.socket():
                pass
        except PermissionError:
            self.skipTest("environment blocks local TCP sockets")

    async def asyncSetUp(self):
        self.settings = replace(Settings(), drain_timeout=0.2, health_interval=0.05,
                                scan_interval=600, retry_interval=0.05)
        self.service = AutoProxy(self.settings, LocalCore)
        self.a, self.b = example_profile(), example_profile(SECOND)
        self.listener = await asyncio.start_server(self.service.client, "127.0.0.1", 0)
        self.port = self.listener.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.service.stopping = True
        self.listener.close()
        tasks = list(self.service.clients)
        tasks.extend(c.drain for c in self.service.cores.values() if c.drain)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.listener.wait_closed()
        await asyncio.gather(*(core.closing or self.service.close_core(core)
                               for core in tuple(self.service.cores.values())))

    async def connect(self, target="destination.test", expected=0):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.addAsyncCleanup(close_writer, writer)
        writer.write(b"\x05\x01\x00")
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        writer.write(b"\x05\x01\x00" + destination(target, 443))
        reply = await reader.readexactly(4)
        await address_bytes(reader, reply[-1])
        self.assertEqual(reply[1], expected)
        return reader, writer

    async def test_retire_and_force_close(self):
        async with asyncio.timeout(2):
            async with self.service.lease(self.a) as old:
                self.service.activate(old)
            reader, writer = await self.connect()
            writer.write(b"before\n")
            self.assertEqual(await reader.readline(), b"first.test before\n")
            self.assertEqual(old.last_target, destination("destination.test", 443))

            async with self.service.lease(self.b) as new:
                self.service.activate(new)
            new_reader, new_writer = await self.connect("2001:db8::1")
            new_writer.write(b"new\n")
            writer.write(b"after\n")
            self.assertEqual(await new_reader.readline(), b"second.test new\n")
            self.assertEqual(await reader.readline(), b"first.test after\n")
            self.assertEqual(new.last_target, destination("2001:db8::1", 443))
            self.assertEqual(await reader.read(), b"")
            await old.process.wait()

    async def test_no_active_then_recover(self):
        async with asyncio.timeout(2):
            await self.connect(expected=1)
            async with self.service.lease(self.b) as core:
                self.service.activate(core)
            reader, writer = await self.connect()
            writer.write(b"recovered\n")
            self.assertEqual(await reader.readline(), b"second.test recovered\n")

    async def test_precheck_gates_tcp_and_udp_starts_the_tunnel(self):
        with patch("autoproxy.service.tcp_probe", AsyncMock(side_effect=OSError)) as tcp, \
             patch("autoproxy.service.tunnel_probe", AsyncMock()) as tunnel, \
             patch("autoproxy.service.https_probe", AsyncMock(return_value=0.05)) as https:
            self.assertIsNone(await self.service.availability(self.a))
            self.assertFalse(self.service.cores)
            tunnel.assert_not_awaited()
            https.assert_not_awaited()
            result = await self.service.availability(self.b)
            self.assertEqual(result.profile, self.b)
            self.assertEqual(tcp.await_count, 1)
            tunnel.assert_awaited_once()
            https.assert_awaited_once()

    async def test_scan_selects_fastest_and_keeps_reserve(self):
        async def fake_speed(core, settings):
            return 2000 if core.profile is self.b else 500

        with patch.object(self.service, "load_profiles", AsyncMock(return_value=[self.a, self.b])), \
             patch("autoproxy.service.tcp_probe", AsyncMock()), \
             patch("autoproxy.service.https_probe", AsyncMock(return_value=0.05)), \
             patch("autoproxy.service.speed_probe", side_effect=fake_speed):
            await self.service.scan()
        self.assertEqual(self.service.active.profile, self.b)
        self.assertEqual(self.service.reserve.profile, self.a)
        self.assertEqual(len(self.service.results), 2)

    async def test_subscription_reuses_last_successful_refresh(self):
        link = "https://subscription.test/token"
        self.service.settings = replace(self.settings, subscriptions=(link,))
        mock = AsyncMock(side_effect=[(FIRST + "\n" + SECOND).encode(), OSError()])
        with patch("autoproxy.service.fetch_subscription", mock):
            first = await self.service.load_profiles()
            with self.assertLogs(level="WARNING") as logs:
                second = await self.service.load_profiles()
        self.assertEqual(len(first), 2)
        self.assertEqual(first, second)
        self.assertNotIn(link, str(logs.output))

    async def test_run_stops_and_releases_tunnels(self):
        service = AutoProxy(replace(self.settings, listen_port=0), LocalCore)
        stop = asyncio.Event()
        ready = asyncio.Event()

        async def mark_ready(core, settings):
            ready.set()
            return 0.1

        with patch.object(service, "load_profiles", AsyncMock(return_value=[self.b])), \
             patch("autoproxy.service.https_probe", side_effect=mark_ready), \
             patch("autoproxy.service.speed_probe", AsyncMock(return_value=100)):
            runner = asyncio.create_task(service.run(stop))
            try:
                async with asyncio.timeout(2):
                    await ready.wait()
                    stop.set()
                    await runner
            finally:
                runner.cancel()
                await asyncio.gather(runner, return_exceptions=True)
        self.assertFalse(service.cores)

    async def test_process_death_requests_scan_and_promotes_reserve(self):
        async with self.service.lease(self.a) as active, self.service.lease(self.b) as reserve:
            self.service.activate(active)
            self.service.set_reserve(reserve)
        self.service.results[self.b.key] = Result(self.b, 0.1, 100)
        with patch("autoproxy.service.https_probe", AsyncMock(return_value=0.1)):
            health = asyncio.create_task(self.service.health_loop())
            try:
                await active.close()
                async with asyncio.timeout(2):
                    await self.service.scan_requested.wait()
                    while self.service.active is not reserve:
                        await asyncio.sleep(0.01)
            finally:
                health.cancel()
                await asyncio.gather(health, return_exceptions=True)
        self.assertIsNone(self.service.reserve)

    async def test_wireguard_identity_never_runs_twice(self):
        a, b = wg_profile(WG), wg_profile(WG.replace("51820", "51821"))
        async with self.service.lease(a) as first:
            self.service.activate(first)
        with self.assertRaises(DeferredProbe):
            async with self.service.lease(b):
                self.fail("duplicate WireGuard identity started")
        self.service.activate(None)
        async with self.service.lease(b) as second:
            self.assertFalse(first.alive)
            self.assertTrue(second.alive)

    @unittest.skipUnless(shutil.which("curl") and shutil.which("openssl"), "requires curl and openssl")
    async def test_curl_uses_authenticated_backend_and_checks_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            pem = Path(tmp) / "cert.pem"
            key = Path(tmp) / "key.pem"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", str(key), "-out", str(pem), "-subj", "/CN=origin.test",
                 "-addext", "subjectAltName=DNS:origin.test"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(pem, key)

            async def respond(reader, writer):
                try:
                    request = await reader.readuntil(b"\r\n\r\n")
                    body = b"x" * 32768 if b"/download" in request else b"ok"
                    writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
                                 "Connection: close\r\n\r\n".encode())
                    await writer.drain()
                    await asyncio.sleep(0.02)
                    writer.write(body)
                    await writer.drain()
                except (asyncio.IncompleteReadError, OSError):
                    pass
                finally:
                    await close_writer(writer)

            origin = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=tls)
            async with origin, self.service.lease(self.a) as core:
                core.target = ("127.0.0.1", origin.sockets[0].getsockname()[1])
                settings = replace(self.settings, check_urls=("https://origin.test/",),
                                   download_url="https://origin.test/download?bytes={bytes}",
                                   download_bytes=32768, min_download_bytes=1024)
                with patch.dict(os.environ, {"CURL_CA_BUNDLE": str(pem), "NO_PROXY": "*"}):
                    self.assertGreaterEqual(await https_probe(core, settings), 0)
                    self.assertGreater(await speed_probe(core, settings), 0)
                with self.assertRaises(OSError):
                    await https_probe(core, settings)


@unittest.skipUnless(os.environ.get("AUTOPROXY_CORE_DIR"), "set AUTOPROXY_CORE_DIR for real cores")
class ExternalCoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_xray_and_mihomo_relay_through_local_vless(self):
        binaries = Path(os.environ["AUTOPROXY_CORE_DIR"])
        settings = replace(Settings(), xray=str(binaries / "xray"),
                           mihomo=str(binaries / "mihomo"))
        identifier = "d6ce054b-20d1-4a76-9b47-9cd209c7640f"

        async def echo(reader, writer):
            try:
                if data := await reader.readline():
                    writer.write(data)
                    await writer.drain()
            finally:
                await close_writer(writer)

        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        async with target, asyncio.timeout(15):
            target_port = target.sockets[0].getsockname()[1]
            with socket.socket() as held:
                held.bind(("127.0.0.1", 0))
                vless_port = held.getsockname()[1]
            with tempfile.TemporaryDirectory() as tmp:
                config = Path(tmp) / "server.json"
                config.write_text(json.dumps({
                    "inbounds": [{"listen": "127.0.0.1", "port": vless_port,
                                  "protocol": "vless", "settings": {
                                      "clients": [{"id": identifier}], "decryption": "none",
                                  }}],
                    "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"],
                         "port": str(target_port)},
                    ]}}],
                }))
                server = await asyncio.create_subprocess_exec(
                    settings.xray, "run", "-c", str(config), stdout=asyncio.subprocess.DEVNULL,
                )
                try:
                    while True:
                        self.assertIsNone(server.returncode)
                        try:
                            _, writer = await asyncio.open_connection("127.0.0.1", vless_port)
                        except ConnectionRefusedError:
                            await asyncio.sleep(0.05)
                        else:
                            await close_writer(writer)
                            break
                    xray = next(xray_profiles({"protocol": "vless", "settings": {
                        "address": "127.0.0.1", "port": vless_port, "id": identifier,
                        "encryption": "none",
                    }}))
                    mihomo = example_profile(
                        f"vless://{identifier}@127.0.0.1:{vless_port}?security=none"
                    )
                    for profile in (xray, mihomo):
                        core = Core(profile, settings)
                        try:
                            await core.start()
                            reader, writer = await connect_core(core)
                            try:
                                reply = await request_core(
                                    reader, writer, destination("127.0.0.1", target_port)
                                )
                                self.assertEqual(reply[1], 0, profile.engine)
                                writer.write(b"vless test\n")
                                await writer.drain()
                                self.assertEqual(await reader.readline(), b"vless test\n")
                            finally:
                                await close_writer(writer)
                        finally:
                            await core.close()
                finally:
                    await stop_process(server)

    async def test_mihomo_loads_awg_v3_profile(self):
        binary = Path(os.environ["AUTOPROXY_CORE_DIR"]) / "mihomo"

        def key(offset):
            return base64.b64encode(bytes(range(offset, offset + 32))).decode()

        config = (WG.replace("test-private", key(1)).replace("test-public", key(51))
                  .replace("test-psk", key(101)).replace("test-header-protection", key(151))
                  .replace("[2001:db8::1]:51820", "127.0.0.1:51820"))
        core = Core(wg_profile(config), replace(Settings(), mihomo=str(binary)))
        try:
            await core.start()
            self.assertTrue(core.alive)
        finally:
            await core.close()
