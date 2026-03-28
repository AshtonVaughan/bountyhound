"""MCP server for Amass tool integration with Claude."""

from __future__ import annotations

import json
import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from mcp_base import BaseToolMCP


class AmassMCP(BaseToolMCP):
    """MCP server for Amass subdomain enumeration."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8192"):
        super().__init__("amass-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Amass MCP tools."""

        @self.mcp.tool()
        async def amass_enum(domain: str, passive: bool = False, include_unresolved: bool = False) -> str:
            """Enumerate subdomains for a domain using Amass.

            Args:
                domain: Target domain to enumerate
                passive: Passive enumeration only (no network queries)
                include_unresolved: Include DNS names that don't resolve to IPs

            Returns:
                JSON response with job_id and initial status
            """
            payload = {
                "domain": domain,
                "passive": passive,
                "include_unresolved": include_unresolved,
                "timeout": 600.0,
                "concurrency": 10,
            }

            result = await self._api_request("POST", "/api/enum", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def amass_status(job_id: str) -> str:
            """Get Amass enumeration status and results.

            Args:
                job_id: Job ID from amass_enum

            Returns:
                JSON response with job status and discovered subdomains
            """
            result = await self._api_request("GET", f"/api/enum/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def amass_cancel(job_id: str) -> str:
            """Cancel a running Amass enumeration.

            Args:
                job_id: Job ID to cancel

            Returns:
                JSON response confirming cancellation
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def amass_server_status() -> str:
            """Get Amass server status.

            Returns:
                JSON response with job counts and server info
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
