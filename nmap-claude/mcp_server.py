"""MCP server for Nmap tool integration with Claude."""

from __future__ import annotations

import json
import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from mcp_base import BaseToolMCP


class NmapMCP(BaseToolMCP):
    """MCP server for Nmap network scanning."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8190"):
        super().__init__("nmap-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Nmap MCP tools."""

        @self.mcp.tool()
        async def nmap_scan(targets: str, ports: str = "", scan_type: str = "sV", aggressive: bool = False) -> str:
            """Scan targets with Nmap.

            Args:
                targets: Comma-separated targets (IPs, hostnames, or CIDR)
                ports: Specific ports (e.g., '80,443' or '1-10000')
                scan_type: Scan type - sV (service), sS (syn), sT (connect), sU (UDP)
                aggressive: Enable aggressive scanning (-A flag)

            Returns:
                JSON response with job_id and initial status
            """
            target_list = [t.strip() for t in targets.split(",") if t.strip()]

            payload = {
                "targets": target_list,
                "scan_type": scan_type,
                "ports": ports,
                "aggressive": aggressive,
                "timeout": 600.0,
                "concurrency": 10,
            }

            result = await self._api_request("POST", "/api/scan", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def nmap_status(job_id: str) -> str:
            """Get Nmap scan status and results.

            Args:
                job_id: Job ID from nmap_scan

            Returns:
                JSON response with job status and open ports
            """
            result = await self._api_request("GET", f"/api/scan/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def nmap_cancel(job_id: str) -> str:
            """Cancel a running Nmap scan.

            Args:
                job_id: Job ID to cancel

            Returns:
                JSON response confirming cancellation
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def nmap_server_status() -> str:
            """Get Nmap server status.

            Returns:
                JSON response with job counts and server info
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
