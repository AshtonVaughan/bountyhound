"""MCP server for Nuclei tool integration with Claude."""

from __future__ import annotations

import json
import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from mcp_base import BaseToolMCP


class NucleiMCP(BaseToolMCP):
    """MCP server for Nuclei scanning."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8188"):
        super().__init__("nuclei-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Nuclei MCP tools."""

        @self.mcp.tool()
        async def nuclei_scan(urls: str, templates: str = "", severity: str = "") -> str:
            """Scan URLs with Nuclei templates.

            Args:
                urls: Comma-separated URLs to scan
                templates: Comma-separated template names (e.g., 'http,cves')
                severity: Filter by severity (critical, high, medium, low, info)

            Returns:
                JSON response with job_id and initial status
            """
            url_list = [u.strip() for u in urls.split(",") if u.strip()]
            template_list = [t.strip() for t in templates.split(",") if t.strip()]

            payload = {
                "urls": url_list,
                "templates": template_list,
                "timeout": 300.0,
                "concurrency": 10,
            }
            if severity:
                payload["severity"] = severity

            result = await self._api_request("POST", "/api/scan", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def nuclei_status(job_id: str) -> str:
            """Get Nuclei scan status and results.

            Args:
                job_id: Job ID from nuclei_scan

            Returns:
                JSON response with job status and findings
            """
            result = await self._api_request("GET", f"/api/scan/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def nuclei_cancel(job_id: str) -> str:
            """Cancel a running Nuclei scan.

            Args:
                job_id: Job ID to cancel

            Returns:
                JSON response confirming cancellation
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def nuclei_server_status() -> str:
            """Get Nuclei server status.

            Returns:
                JSON response with job counts and server info
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
