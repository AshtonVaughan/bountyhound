"""Entry point — runs mitmproxy + FastAPI on a single asyncio event loop."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy-engine")

PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
API_PORT = int(os.environ.get("API_PORT", "8187"))
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY", "")  # e.g. "http://127.0.0.1:9090"
TRANSPARENT_MODE = os.environ.get("TRANSPARENT_MODE", "").lower() in ("1", "true", "yes")
REVERSE_PROXY = os.environ.get("REVERSE_PROXY", "")  # e.g. "https://target.com"
AUTO_SAVE_INTERVAL = int(os.environ.get("AUTO_SAVE_INTERVAL", "300"))  # seconds


async def run_proxy() -> DumpMaster:
    """Start mitmproxy as an async task."""
    opts_kwargs = {
        "listen_host": "127.0.0.1",
        "listen_port": PROXY_PORT,
        "ssl_insecure": True,
    }

    # HTTP/2 support (Task #32)
    # mitmproxy supports HTTP/2 by default, but we can explicitly enable it
    # opts_kwargs["http2"] = True  # enabled by default in mitmproxy 11

    # Upstream proxy (Task #32)
    if UPSTREAM_PROXY:
        opts_kwargs["mode"] = [f"upstream:{UPSTREAM_PROXY}"]
        log.info(f"Upstream proxy: {UPSTREAM_PROXY}")

    # SOCKS support (Task #32) — set via environment
    socks_proxy = os.environ.get("SOCKS_PROXY", "")
    if socks_proxy:
        opts_kwargs["mode"] = [f"socks5@{PROXY_PORT}"]
        log.info(f"SOCKS5 mode enabled on port {PROXY_PORT}")

    # Transparent proxy mode
    if TRANSPARENT_MODE:
        opts_kwargs["mode"] = ["transparent"]
        log.info("Transparent proxy mode enabled")

    # Reverse proxy mode
    if REVERSE_PROXY:
        opts_kwargs["mode"] = [f"reverse:{REVERSE_PROXY}"]
        log.info(f"Reverse proxy mode: {REVERSE_PROXY}")

    opts = options.Options(**opts_kwargs)
    master = DumpMaster(opts)

    # Load our addon
    from addon import ProxyAddon
    master.addons.add(ProxyAddon())

    log.info(f"mitmproxy listening on 127.0.0.1:{PROXY_PORT}")
    await master.run()
    return master


async def run_api() -> None:
    """Start FastAPI via uvicorn."""
    from api import app
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=API_PORT,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    log.info(f"FastAPI listening on http://127.0.0.1:{API_PORT}")
    await server.serve()


async def run_auto_save() -> None:
    """Periodically auto-save state (Task #36)."""
    while True:
        await asyncio.sleep(AUTO_SAVE_INTERVAL)
        try:
            from persistence import auto_save
            result = auto_save()
            if result:
                log.debug(f"[autosave] Saved: {result.get('flows', 0)} flows")
        except Exception as e:
            log.debug(f"[autosave] Error: {e}")


async def run_scheduled_scans() -> None:
    """Check and run scheduled scans (Task #36)."""
    while True:
        await asyncio.sleep(60)  # Check every minute
        try:
            from state import state
            from models import ScanRequest
            from scanner import start_scan

            now = time.time()
            for scan in state.scheduled_scans:
                if not scan.enabled:
                    continue
                if now >= scan.next_run and scan.next_run > 0:
                    log.info(f"[scheduler] Running scheduled scan: {scan.name}")
                    req = ScanRequest(
                        urls=scan.urls,
                        profile=scan.profile or None,
                    )
                    job = await start_scan(req)
                    scan.last_run = now
                    scan.last_scan_id = job.scan_id
                    scan.next_run = now + scan.interval_minutes * 60
        except Exception as e:
            log.debug(f"[scheduler] Error: {e}")


async def run_job_cleanup() -> None:
    """Periodically clean up completed jobs to bound memory (Task #31)."""
    while True:
        await asyncio.sleep(600)  # every 10 minutes
        try:
            from state import state
            state.cleanup_completed_jobs(max_completed=100)
        except Exception as e:
            log.debug(f"[cleanup] Error: {e}")


async def main() -> None:
    """Run all services concurrently."""
    log.info("Starting proxy engine...")

    # Proxy authentication
    proxy_auth = os.environ.get("PROXY_AUTH", "")  # user:pass format

    # Collaborator server startup
    if os.environ.get("COLLABORATOR_ENABLED", "").lower() in ("true", "1", "yes"):
        from collaborator_server import start_servers
        collab_domain = os.environ.get("COLLABORATOR_DOMAIN", "collab.localhost")
        collab_dns_port = int(os.environ.get("COLLABORATOR_DNS_PORT", "5354"))
        collab_http_port = int(os.environ.get("COLLABORATOR_HTTP_PORT", "9999"))
        collab_smtp_port = int(os.environ.get("COLLABORATOR_SMTP_PORT", "2525"))
        await start_servers(collab_domain, collab_dns_port, collab_http_port, collab_smtp_port)
        log.info(f"Collaborator servers started on domain={collab_domain}")

    # Enhanced scheduler with cron support
    from scheduler import run_scheduler

    tasks = [
        asyncio.create_task(run_proxy()),
        asyncio.create_task(run_api()),
        asyncio.create_task(run_auto_save()),
        asyncio.create_task(run_scheduled_scans()),
        asyncio.create_task(run_job_cleanup()),
        asyncio.create_task(run_scheduler()),
    ]

    # SIGTERM / SIGINT graceful shutdown
    shutdown_event = asyncio.Event()

    def _signal_handler():
        log.info("Received shutdown signal, cleaning up...")
        shutdown_event.set()
        for t in tasks:
            t.cancel()

    loop = asyncio.get_running_loop()
    import signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        log.info("Shutting down gracefully...")
        # Cancel all remaining tasks
        for t in tasks:
            if not t.done():
                t.cancel()
        # Wait for tasks to finish cancellation
        await asyncio.gather(*tasks, return_exceptions=True)
        # Cleanup shared resources
        try:
            from state import state
            if hasattr(state, '_shared_client') and state._shared_client:
                await state._shared_client.aclose()
        except Exception:
            pass
        log.info("Proxy engine stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass