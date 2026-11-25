"""Scheduling, profile selection and the stable SOCKS5 listener."""

import asyncio
import configparser
import contextlib
import logging
import os
from dataclasses import dataclass

import yaml

from .network import (
    FAILURE, Core, SocksError, address_bytes, close_writer, connect_core,
    fetch_subscription, https_probe, relay, request_core, speed_probe, tcp_probe,
    tunnel_probe,
)
from .profiles import Profile, local_profiles, subscription_profiles

LOG = logging.getLogger(__name__)
PROBE_ERRORS = (OSError, TimeoutError, asyncio.IncompleteReadError, ValueError)
SOURCE_ERRORS = (OSError, ValueError, KeyError, TypeError, configparser.Error, yaml.YAMLError)


class DeferredProbe(OSError):
    pass


@dataclass
class Result:
    profile: Profile
    latency: float
    speed: float | None = None

    @property
    def rank(self):
        return -(self.speed or 0), self.latency, self.profile.key


class AutoProxy:
    def __init__(self, settings, core_factory=Core):
        self.settings = settings
        self.core_factory = core_factory
        self.cores = {}
        self.active = None
        self.reserve = None
        self.results = {}
        self.subscription_cache = {}
        self.source_cache = {}
        self.clients = set()
        self.scan_requested = asyncio.Event()
        self.active_changed = asyncio.Event()
        self.recovery_done = asyncio.Event()
        self.recovery_done.set()
        self.selection_lock = asyncio.Lock()
        self.scanning = False
        self.stopping = False
        self.deferred = set()

    def request_scan(self, after_current=False):
        if not self.scanning or after_current:
            self.scan_requested.set()

    def collect(self, core):
        if (core is self.active or core is self.reserve or core.sessions or core.leases
                or core.closing is not None or self.stopping):
            return
        core.closing = asyncio.create_task(self.close_core(core))

    async def close_core(self, core):
        try:
            if core.startup is not None:
                core.startup.cancel()
                await asyncio.gather(core.startup, return_exceptions=True)
            await core.close()
        finally:
            if self.cores.get(core.profile.key) is core:
                del self.cores[core.profile.key]
            if core.profile.wireguard_id in self.deferred:
                self.deferred.discard(core.profile.wireguard_id)
                self.request_scan(after_current=True)

    @contextlib.asynccontextmanager
    async def lease(self, profile):
        while True:
            core = self.cores.get(profile.key)
            conflict = next((item for item in self.cores.values()
                             if profile.wireguard_id and item is not core
                             and item.profile.wireguard_id == profile.wireguard_id), None)
            closing = (core or conflict).closing if core or conflict else None
            if closing is None:
                break
            await asyncio.shield(closing)
        if core is None:
            if conflict is not None:
                if conflict is self.active or conflict is self.reserve or conflict.sessions:
                    self.deferred.add(profile.wireguard_id)
                raise DeferredProbe("WireGuard peer already in use")
            core = self.cores[profile.key] = self.core_factory(profile, self.settings)
            core.startup = asyncio.create_task(core.start())
        core.leases += 1
        try:
            await asyncio.shield(core.startup)
            if not core.alive:
                raise OSError("proxy core stopped")
            yield core
        finally:
            core.leases -= 1
            self.collect(core)

    async def expire_sessions(self, core):
        await asyncio.sleep(self.settings.drain_timeout)
        for session in list(core.sessions):
            session.cancel()

    def activate(self, core):
        previous = self.active
        if previous is core:
            return
        self.active = core
        self.active_changed.set()
        if core is not None:
            if core.drain:
                core.drain.cancel()
                core.drain = None
            if self.reserve is core:
                self.reserve = None
            LOG.info("Active profile: %s", core.profile.label)
        else:
            LOG.warning("No active profile")
        if previous is not None:
            if previous.sessions:
                previous.drain = asyncio.create_task(self.expire_sessions(previous))
            self.collect(previous)

    def set_reserve(self, core):
        previous = self.reserve
        self.reserve = core
        if previous is not None:
            self.collect(previous)

    async def client(self, reader, writer):
        task = asyncio.current_task()
        self.clients.add(task)
        upstream = None
        core = None
        replied = False
        try:
            async with asyncio.timeout(self.settings.tunnel_timeout):
                version, count = await reader.readexactly(2)
                if version != 5:
                    return
                if 0 not in await reader.readexactly(count):
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()
                version, command, reserved, address_type = await reader.readexactly(4)
                if version != 5 or reserved != 0:
                    return
                if command != 1 or address_type not in (1, 3, 4):
                    code = 7 if command != 1 else 8
                    writer.write(FAILURE[:1] + bytes([code]) + FAILURE[2:])
                    await writer.drain()
                    return
                target = bytes([address_type]) + await address_bytes(reader, address_type)
                core = self.active
                if core is None and not self.recovery_done.is_set():
                    await self.recovery_done.wait()
                    core = self.active
                if core is None or not core.alive:
                    raise SocksError("no working tunnel")
                # Pin before any await that could let another task switch the active core.
                core.sessions.add(task)
                upstream_reader, upstream = await connect_core(core)
                reply = await request_core(upstream_reader, upstream, target)
                writer.write(reply)
                replied = True
                await writer.drain()
                if reply[1] != 0:
                    return
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            if not replied and not writer.is_closing():
                writer.write(FAILURE)
            return
        else:
            try:
                await relay(reader, writer, upstream_reader, upstream)
            except* OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()
            writer.close()
            if core is not None:
                core.sessions.discard(task)
                if not core.sessions and core.drain:
                    core.drain.cancel()
                    core.drain = None
                self.collect(core)
            self.clients.discard(task)
            if upstream is not None:
                await close_writer(upstream)
            await close_writer(writer)

    async def load_profiles(self):
        found = {}
        for index, path in enumerate(self.settings.profiles, 1):
            subpaths = [path]
            if path.is_dir():
                subpaths = list(path.iterdir())

            for index2, path2 in enumerate(subpaths, 1):
                try:
                    profiles = await asyncio.to_thread(local_profiles, path2)
                except SOURCE_ERRORS as e:
                    LOG.warning("Local source %s/%s: unable to read or parse; using previous nodes", index, index2)
                    LOG.warning("Error was: %s", type(e).__name__+": "+str(e))
                    profiles = self.source_cache.get(path2, [])
                else:
                    self.source_cache[path2] = profiles
                    if not profiles:
                        LOG.warning("Local source %s/%s: no supported standalone profiles", index, index2)
                found.update((profile.key, profile) for profile in profiles)

        limiter = asyncio.Semaphore(self.settings.concurrency)

        async def subscription(index, url):
            async with limiter:
                try:
                    body = await fetch_subscription(self.settings, url)
                    profiles = await asyncio.to_thread(subscription_profiles, body)
                except SOURCE_ERRORS:
                    LOG.warning("Subscription %s: refresh failed; using previous nodes", index)
                    return self.subscription_cache.get(url, [])
                self.subscription_cache[url] = profiles
                return profiles

        subscriptions = await asyncio.gather(*(subscription(i, url) for i, url in
                                               enumerate(self.settings.subscriptions, 1)))
        for profiles in subscriptions:
            found.update((profile.key, profile) for profile in profiles)
        return list(found.values())

    async def availability(self, profile):
        stage = "endpoint TCP"
        try:
            if profile.tcp:
                await tcp_probe(profile, self.settings.tcp_timeout)
            stage = "core startup"
            async with self.lease(profile) as core:
                stage = "tunnel TCP"
                await tunnel_probe(core, self.settings)
                stage = "HTTPS"
                latency = await https_probe(core, self.settings)
                if self.active is None and core.alive:
                    self.activate(core)
                return Result(profile, latency)
        except DeferredProbe:
            LOG.info("%s: deferred, WireGuard peer is busy", profile.label)
        except PROBE_ERRORS:
            LOG.info("%s: failed at %s", profile.label, stage)
        return None

    async def available_profiles(self, profiles):
        queue = iter(profiles)
        results = {}
        peers = {}

        async def worker():
            for profile in queue:
                if profile.wireguard_id:
                    lock = peers.setdefault(profile.wireguard_id, asyncio.Lock())
                    async with lock:
                        result = await self.availability(profile)
                else:
                    result = await self.availability(profile)
                if result is not None:
                    results[profile.key] = result
                    previous = self.results.get(profile.key)
                    if previous is None:
                        self.results[profile.key] = result

        async with asyncio.TaskGroup() as group:
            for _ in range(min(len(profiles), self.settings.concurrency)):
                group.create_task(worker())
        return results

    async def benchmark(self, result):
        try:
            async with self.lease(result.profile) as core:
                result.speed = await speed_probe(core, self.settings)
        except PROBE_ERRORS:
            result.speed = None
        if result.speed is None:
            LOG.info("%s: no usable download measurement", result.profile.label)
        else:
            LOG.info("%s: %.2f Mbit/s", result.profile.label, result.speed * 8 / 1_000_000)

    async def select(self, results, reserve=False):
        async with self.selection_lock:
            if reserve and self.reserve is not None and not self.reserve.alive:
                self.set_reserve(None)
            for result in results:
                if reserve and self.active and self.active.profile.key == result.profile.key:
                    continue
                if not reserve and self.active and self.active.alive:
                    if self.active.profile.key == result.profile.key:
                        return True
                try:
                    async with self.lease(result.profile) as core:
                        await https_probe(core, self.settings)
                        if not core.alive:
                            continue
                        if reserve:
                            # The health monitor may have changed the active profile during the probe.
                            if core is self.active:
                                continue
                            self.set_reserve(core)
                        else:
                            self.activate(core)
                        return True
                except PROBE_ERRORS:
                    if self.reserve and self.reserve.profile.key == result.profile.key:
                        self.set_reserve(None)
            if reserve:
                self.set_reserve(None)
            return False

    async def scan(self):
        profiles = await self.load_profiles()
        configured = {profile.key for profile in profiles}
        self.results = {key: result for key, result in self.results.items() if key in configured}
        LOG.info("Scanning %s unique profiles", len(profiles))
        results = await self.available_profiles(profiles)
        for result in results.values():
            await self.benchmark(result)
        self.results = results
        ranked = sorted(results.values(), key=lambda result: result.rank)
        if not await self.select(ranked) and self.active and self.active.profile.key not in configured:
            self.activate(None)
        await self.select(ranked, reserve=True)
        LOG.info("Scan complete, %s profiles passed HTTPS", len(results))

    async def scan_loop(self):
        while True:
            self.scan_requested.clear()
            self.scanning = True
            try:
                await self.scan()
            finally:
                self.scanning = False
            delay = self.settings.scan_interval if self.active else self.settings.retry_interval
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.scan_requested.wait(), delay)

    async def wait_for_health_check(self, core):
        if core is None:
            await self.active_changed.wait()
            return
        tasks = [asyncio.create_task(self.active_changed.wait()),
                 asyncio.create_task(core.process.wait())]
        try:
            await asyncio.wait(tasks, timeout=self.settings.health_interval,
                               return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def health_loop(self):
        last = None
        failures = 0
        while True:
            core = self.active
            self.active_changed.clear()
            if core is not last:
                last, failures = core, 0
            await self.wait_for_health_check(core)
            if core is None or self.active is not core:
                continue
            if core.alive:
                core.leases += 1
                try:
                    await https_probe(core, self.settings)
                except PROBE_ERRORS:
                    failures += 1
                else:
                    failures = 0
                finally:
                    core.leases -= 1
                    self.collect(core)
            if self.active is not core:
                continue
            if not core.alive or failures >= self.settings.health_failures:
                LOG.warning("%s: active health check failed", core.profile.label)
                ranked = sorted(
                    (r for r in self.results.values() if r.profile.key != core.profile.key),
                    key=lambda r: (not self.reserve or r.profile.key != self.reserve.profile.key,
                                   r.rank),
                )
                self.recovery_done.clear()
                self.activate(None)
                self.request_scan()
                try:
                    await self.select(ranked)
                finally:
                    self.recovery_done.set()

    async def run(self, stop):
        listener = await asyncio.start_server(self.client, self.settings.listen_host, self.settings.listen_port)
        async with listener:
            LOG.info("SOCKS5 listening on %s:%s", self.settings.listen_host, self.settings.listen_port)
            try:
                async with asyncio.TaskGroup() as group:
                    tasks = [group.create_task(self.scan_loop()), group.create_task(self.health_loop())]
                    await stop.wait()
                    self.stopping = True
                    listener.close()
                    for task in tasks:
                        task.cancel()
            finally:
                self.stopping = True
                tasks = list(self.clients)
                tasks.extend(core.drain for core in self.cores.values() if core.drain)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.gather(*(core.closing or self.close_core(core)
                                       for core in tuple(self.cores.values())))
