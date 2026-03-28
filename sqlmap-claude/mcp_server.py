"""MCP server for SQLMap tool integration with Claude."""

from __future__ import annotations

import json
import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from mcp_base import BaseToolMCP


class SqlmapMCP(BaseToolMCP):
    """MCP server for SQLMap SQL injection testing."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8189"):
        super().__init__("sqlmap-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register SQLMap MCP tools."""

        @self.mcp.tool()
        async def sqlmap_test(
            url: str,
            method: str = "GET",
            data: str = "",
            level: int = 1,
            risk: int = 1,
        ) -> str:
            """Test a URL for SQL injection vulnerabilities.

            Args:
                url: Target URL to test
                method: HTTP method (GET, POST, etc.)
                data: POST body data (if applicable)
                level: Detection level 1-5 (higher = more thorough)
                risk: Risk level 1-3 (higher = more aggressive)

            Returns:
                JSON response with job_id and initial status
            """
            payload = {
                "url": url,
                "method": method,
                "data": data,
                "level": level,
                "risk": risk,
                "timeout": 300.0,
            }

            result = await self._api_request("POST", "/api/test", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def sqlmap_status(job_id: str) -> str:
            """Get SQLMap test status and findings.

            Args:
                job_id: Job ID from sqlmap_test

            Returns:
                JSON response with job status and vulnerabilities
            """
            result = await self._api_request("GET", f"/api/test/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def sqlmap_cancel(job_id: str) -> str:
            """Cancel a running SQLMap test.

            Args:
                job_id: Job ID to cancel

            Returns:
                JSON response confirming cancellation
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def sqlmap_server_status() -> str:
            """Get SQLMap server status.

            Returns:
                JSON response with job counts and server info
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
