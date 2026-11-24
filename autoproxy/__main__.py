"""Run AutoProxy as a foreground service."""

import argparse
import asyncio
import logging
import shutil
import signal
import sys
from pathlib import Path

from .profiles import Settings
from .service import AutoProxy


async def run(settings):
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    await AutoProxy(settings).run(stop)


def main():
    parser = argparse.ArgumentParser(description="Select a proxy and serve it on localhost SOCKS5")
    parser.add_argument("-c", "--config", type=Path, default=Path("autoproxy.json"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = Settings.load(args.config)
        required = {"curl": settings.curl}
        if any(path.suffix.lower() == ".json" for path in settings.profiles):
            required["Xray"] = settings.xray
        if settings.subscriptions or any(path.suffix.lower() == ".conf" for path in settings.profiles):
            required["Mihomo"] = settings.mihomo
        for label, executable in required.items():
            if shutil.which(executable) is None:
                raise ValueError(f"{label} executable not found")
        asyncio.run(run(settings))
    except (OSError, ValueError) as exc:
        print(f"autoproxy: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
