"""MCP server for zeek-claude — network traffic analysis and forensics."""

from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from mcp_base import BaseToolMCP


class ZeekMCP(BaseToolMCP):
    """MCP server providing Zeek network traffic analysis."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8198"):
        super().__init__("zeek-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Zeek MCP tool functions."""

        @self.mcp.tool()
        async def zeek_analyze_pcap(
            pcap_file: str,
            extract_files: bool = False,
            timeout: float = 600.0,
        ) -> str:
            """Analyze a PCAP file with Zeek for network security indicators.

            Runs Zeek to generate structured logs (conn, dns, http, ssl, weird),
            then automatically analyses them for:
              - Port scans and suspicious connections
              - DNS tunneling and high-frequency beaconing
              - Cleartext HTTP credentials
              - Suspicious User-Agents (scanners, exploit tools)
              - Weak TLS versions and invalid certificates
              - Protocol anomalies (weird.log)

            Args:
                pcap_file: Absolute path to PCAP or PCAPNG file on the server
                extract_files: Extract file payloads from the PCAP (saves to output dir)
                timeout: Analysis timeout in seconds

            Returns:
                JSON with job_id; poll zeek_analyze_status for results
            """
            payload = {
                "pcap_file": pcap_file,
                "extract_files": extract_files,
                "analyze_dns": True,
                "analyze_http": True,
                "analyze_ssl": True,
                "analyze_conn": True,
                "timeout": timeout,
            }
            result = await self._api_request("POST", "/api/analyze", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def zeek_analyze_status(job_id: str) -> str:
            """Get Zeek PCAP analysis status and security findings.

            Args:
                job_id: Job ID from zeek_analyze_pcap or zeek_live_capture

            Returns:
                JSON with findings, log_files, conn_count, dns_count, http_count, ssl_count
            """
            result = await self._api_request("GET", f"/api/analyze/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def zeek_live_capture(
            interface: str,
            duration: float = 60.0,
        ) -> str:
            """Run Zeek against a live network interface for real-time analysis.

            Captures traffic on the specified interface for the given duration,
            then analyses the generated logs for security indicators.
            Requires root/admin privileges.

            Args:
                interface: Network interface name (e.g. eth0, en0, ens33)
                duration: Capture duration in seconds (default: 60)

            Returns:
                JSON with job_id; poll zeek_analyze_status for results
            """
            payload = {
                "interface": interface,
                "duration": duration,
                "timeout": duration + 30.0,
            }
            result = await self._api_request("POST", "/api/live", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def zeek_query_log(
            log_dir: str,
            log_type: str = "conn",
            filter_expr: str = "",
            limit: int = 500,
        ) -> str:
            """Query an existing Zeek log directory for specific records.

            Reads the specified log type (conn, dns, http, ssl, etc.) and
            optionally filters rows using a Python boolean expression on the row dict.

            Common log types: conn, dns, http, ssl, files, weird, notice, ftp, smtp

            Filter examples:
              "id.resp_p == '443'"
              "method == 'POST' and int(request_body_len) > 1000"
              "rcode_name != 'NOERROR'"

            Args:
                log_dir: Directory containing Zeek .log files
                log_type: Log name without extension (e.g. conn, dns, http, ssl)
                filter_expr: Optional Python filter expression (evaluated per row)
                limit: Maximum rows to return

            Returns:
                JSON with job_id; poll zeek_query_status for rows
            """
            payload = {
                "log_dir": log_dir,
                "log_type": log_type,
                "filter_expr": filter_expr,
                "limit": limit,
                "timeout": 60.0,
            }
            result = await self._api_request("POST", "/api/query", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def zeek_query_status(job_id: str) -> str:
            """Get Zeek log query results.

            Args:
                job_id: Job ID from zeek_query_log

            Returns:
                JSON with rows list and row_count
            """
            result = await self._api_request("GET", f"/api/query/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def zeek_cancel(job_id: str) -> str:
            """Cancel a running Zeek job.

            Args:
                job_id: Job ID to cancel

            Returns:
                Confirmation JSON
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def zeek_server_status() -> str:
            """Get zeek-claude service health and supported log types.

            Returns:
                JSON with job counts and supported log types
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
