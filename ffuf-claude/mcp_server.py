"""MCP server for Ffuf tool integration with Claude."""

from __future__ import annotations

import json
import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from mcp_base import BaseToolMCP


class FfufMCP(BaseToolMCP):
    """MCP server for Ffuf web fuzzer."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8191"):
        super().__init__("ffuf-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Ffuf MCP tools."""

        @self.mcp.tool()
        async def ffuf_fuzz(
            url: str,
            wordlist: str,
            method: str = "GET",
            match_status: str = "",
            filter_status: str = "404",
        ) -> str:
            """Fuzz a URL with Ffuf.

            Args:
                url: Target URL (use FUZZ keyword for fuzzing position)
                wordlist: Path to wordlist or URL
                method: HTTP method (GET, POST, etc.)
                match_status: Match by status codes (e.g., '200,204')
                filter_status: Filter out status codes (e.g., '404,500')

            Returns:
                JSON response with job_id and initial status
            """
            payload = {
                "url": url,
                "wordlist": wordlist,
                "method": method,
                "match_status": match_status,
                "filter_status": filter_status,
                "timeout": 300.0,
                "concurrency": 50,
            }

            result = await self._api_request("POST", "/api/fuzz", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def ffuf_status(job_id: str) -> str:
            """Get Ffuf fuzz status and results.

            Args:
                job_id: Job ID from ffuf_fuzz

            Returns:
                JSON response with job status and discovered endpoints
            """
            result = await self._api_request("GET", f"/api/fuzz/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def ffuf_cancel(job_id: str) -> str:
            """Cancel a running Ffuf fuzz.

            Args:
                job_id: Job ID to cancel

            Returns:
                JSON response confirming cancellation
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def ffuf_server_status() -> str:
            """Get Ffuf server status.

            Returns:
                JSON response with job counts and server info
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
