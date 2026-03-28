"""Entry point — runs FastAPI + background cleanup for gobuster-claude."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # local models take precedence over bh-core

from logger import setup_root_logging

setup_root_logging(logging.INFO)
log = logging.getLogger("gobuster-claude")

API_PORT = int(os.environ.get("API_PORT", "8193"))
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
    log.info(f"gobuster-claude API listening on http://127.0.0.1:{API_PORT}")
    await server.serve()


async def run_job_cleanup() -> None:
    """Periodically clean up completed jobs to bound memory usage."""
    from state import GobusterStateManager

    state = GobusterStateManager()
    while True:
        await asyncio.sleep(600)  # every 10 minutes
        try:
            state.cleanup_completed_jobs(max_completed=200)
        except Exception as exc:
            log.debug(f"[cleanup] Error during cleanup: {exc}")


async def main() -> None:
    """Run all gobuster-claude services concurrently."""
    log.info("Starting gobuster-claude...")

    if MCP_MODE:
        # Run as MCP server only (embedded in unified MCP hub)
        from mcp_server import GobusterMCP
        mcp = GobusterMCP(api_base_url=f"http://127.0.0.1:{API_PORT}")
        mcp.run()
    else:
        tasks = [
            asyncio.create_task(run_api()),
            asyncio.create_task(run_job_cleanup()),
        ]
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            log.info("Shutting down gobuster-claude...")
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
