"""Entry point — runs FastAPI + MCP server for Nmap."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local models take precedence over bh-core

from logger import setup_root_logging

setup_root_logging(logging.INFO)
log = logging.getLogger("nmap-claude")

API_PORT = int(os.environ.get("API_PORT", "8190"))
MCP_MODE = os.environ.get("MCP_MODE", "").lower() in ("1", "true", "yes")


async def run_api() -> None:
    """Start FastAPI via uvicorn."""
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
    log.info(f"FastAPI listening on http://127.0.0.1:{API_PORT}")
    await server.serve()


async def run_job_cleanup() -> None:
    """Periodically clean up completed jobs to bound memory."""
    from state import NmapStateManager

    state = NmapStateManager()

    while True:
        await asyncio.sleep(600)
        try:
            state.cleanup_completed_jobs(max_completed=100)
        except Exception as e:
            log.debug(f"[cleanup] Error: {e}")


async def main() -> None:
    """Run all services concurrently."""
    log.info("Starting nmap-claude...")

    if MCP_MODE:
        from mcp_server import NmapMCP
        mcp = NmapMCP(api_base_url=f"http://127.0.0.1:{API_PORT}")
        mcp.run()
    else:
        tasks = [
            asyncio.create_task(run_api()),
            asyncio.create_task(run_job_cleanup()),
        ]
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            log.info("Shutting down...")
            for t in tasks:
                t.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
