"""MCP server for nessus-claude — Nessus vulnerability scanner integration."""

from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from mcp_base import BaseToolMCP


class NessusMCP(BaseToolMCP):
    """MCP server providing Nessus vulnerability scanning."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8196"):
        super().__init__("nessus-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Nessus MCP tool functions."""

        @self.mcp.tool()
        async def nessus_scan(
            targets: str,
            access_key: str,
            secret_key: str,
            scan_template: str = "basic",
            scan_name: str = "",
            nessus_url: str = "https://127.0.0.1:8834",
            ssh_username: str = "",
            ssh_password: str = "",
        ) -> str:
            """Launch a Nessus vulnerability scan via REST API.

            Initiates a scan on the Nessus instance and polls until completion.
            Requires valid Nessus API keys (generate in Nessus UI under My Account).

            Args:
                targets: Comma-separated IP addresses, ranges, or hostnames
                access_key: Nessus API access key
                secret_key: Nessus API secret key
                scan_template: Scan template name (basic, advanced, webapp, compliance)
                scan_name: Display name in Nessus UI
                nessus_url: Nessus instance URL (default: https://127.0.0.1:8834)
                ssh_username: SSH username for credential scanning (optional)
                ssh_password: SSH password for credential scanning (optional)

            Returns:
                JSON with job_id; poll nessus_scan_status for results
            """
            target_list = [t.strip() for t in targets.split(",") if t.strip()]
            payload = {
                "targets": target_list,
                "scan_template": scan_template,
                "scan_name": scan_name or f"BountyHound scan",
                "nessus_url": nessus_url,
                "access_key": access_key,
                "secret_key": secret_key,
                "ssh_username": ssh_username,
                "ssh_password": ssh_password,
                "timeout": 7200.0,
            }
            result = await self._api_request("POST", "/api/scan", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def nessus_scan_status(job_id: str) -> str:
            """Get Nessus scan status and vulnerability findings.

            Args:
                job_id: Job ID from nessus_scan

            Returns:
                JSON with vulnerabilities list, severity counts, hosts scanned
            """
            result = await self._api_request("GET", f"/api/scan/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def nessus_export(
            scan_id: int,
            access_key: str,
            secret_key: str,
            export_format: str = "nessus",
            nessus_url: str = "https://127.0.0.1:8834",
        ) -> str:
            """Export a Nessus scan to file (nessus, pdf, csv, or html).

            Downloads the export file to the server's export directory.

            Args:
                scan_id: Nessus internal scan ID
                access_key: Nessus API access key
                secret_key: Nessus API secret key
                export_format: nessus, pdf, csv, or html
                nessus_url: Nessus instance URL

            Returns:
                JSON with job_id; poll nessus_export_status for file path
            """
            payload = {
                "scan_id": scan_id,
                "export_format": export_format,
                "nessus_url": nessus_url,
                "access_key": access_key,
                "secret_key": secret_key,
                "timeout": 300.0,
            }
            result = await self._api_request("POST", "/api/export", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def nessus_export_status(job_id: str) -> str:
            """Get Nessus export job status and file path.

            Args:
                job_id: Job ID from nessus_export

            Returns:
                JSON with export_file path when completed
            """
            result = await self._api_request("GET", f"/api/export/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def nessus_server_status() -> str:
            """Get nessus-claude service health and job counts.

            Returns:
                JSON with running/completed/error job counts
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
