"""Entry point — runs FastAPI + background cleanup for bloodhound-claude."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from logger import setup_root_logging

setup_root_logging(logging.INFO)
log = logging.getLogger("bloodhound-claude")

API_PORT = int(os.environ.get("API_PORT", "8194"))
MCP_MODE = os.environ.get("MCP_MODE", "").lower() in ("1", "true", "yes")


async def run_api() -> None:
    """Start FastAPI via uvicorn on the configured port."""
    import uvicorn
    from api import app

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=API_PORT,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    log.info(f"bloodhound-claude API listening on http://127.0.0.1:{API_PORT}")
    await server.serve()


async def run_job_cleanup() -> None:
    """Periodically clean up completed jobs to bound memory."""
    from state import BloodHoundStateManager

    state = BloodHoundStateManager()
    while True:
        await asyncio.sleep(600)
        try:
            state.cleanup_completed_jobs(max_completed=100)
        except Exception as exc:
            log.debug(f"[cleanup] Error: {exc}")


async def main() -> None:
    """Run all bloodhound-claude services concurrently."""
    log.info("Starting bloodhound-claude...")

    if MCP_MODE:
        from mcp_server import BloodHoundMCP
        mcp = BloodHoundMCP(api_base_url=f"http://127.0.0.1:{API_PORT}")
        mcp.run()
    else:
        tasks = [
            asyncio.create_task(run_api()),
            asyncio.create_task(run_job_cleanup()),
        ]
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            log.info("Shutting down bloodhound-claude...")
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
