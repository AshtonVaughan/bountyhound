"""MCP server for gobuster-claude — exposes Gobuster enumeration to Claude."""

from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))
sys.path.insert(0, ".")  # local dir first

from mcp_base import BaseToolMCP


class GobusterMCP(BaseToolMCP):
    """MCP server providing Gobuster directory/DNS/vhost enumeration."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8193"):
        super().__init__("gobuster-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register all Gobuster MCP tool functions."""

        @self.mcp.tool()
        async def gobuster_dir(
            target: str,
            wordlist: str = "/usr/share/wordlists/dirb/common.txt",
            extensions: str = "",
            threads: int = 10,
            status_codes: str = "200,204,301,302,307,401,403",
        ) -> str:
            """Enumerate directories and files on a web server using Gobuster.

            Discovers hidden paths, admin panels, backup files, and sensitive
            endpoints by brute-forcing with a wordlist.

            Args:
                target: Full URL to enumerate (e.g. https://example.com)
                wordlist: Path to wordlist file on the server
                extensions: Comma-separated file extensions to test (e.g. php,html,txt,bak)
                threads: Number of concurrent threads (default 10)
                status_codes: Comma-separated HTTP status codes to flag (default: 200,204,301,302,307,401,403)

            Returns:
                JSON with job_id; poll gobuster_status for results
            """
            ext_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
            code_list = [int(c.strip()) for c in status_codes.split(",") if c.strip().isdigit()]

            payload = {
                "target": target,
                "mode": "dir",
                "wordlist": wordlist,
                "extensions": ext_list,
                "status_codes": code_list,
                "threads": threads,
                "timeout": 600.0,
            }
            result = await self._api_request("POST", "/api/enumerate", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def gobuster_dns(
            domain: str,
            wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            threads: int = 10,
        ) -> str:
            """Enumerate subdomains via DNS brute-forcing with Gobuster.

            Discovers live subdomains of the target domain by resolving
            wordlist entries as DNS hostnames.

            Args:
                domain: Target domain (e.g. example.com — no http://)
                wordlist: Path to subdomain wordlist
                threads: Concurrent threads

            Returns:
                JSON with job_id; poll gobuster_status for results
            """
            payload = {
                "target": domain,
                "mode": "dns",
                "wordlist": wordlist,
                "threads": threads,
                "timeout": 600.0,
            }
            result = await self._api_request("POST", "/api/enumerate", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def gobuster_vhost(
            target: str,
            wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            threads: int = 10,
        ) -> str:
            """Enumerate virtual hosts on a web server with Gobuster.

            Sends Host headers from a wordlist to discover hidden vhosts
            on a shared IP or CDN-fronted server.

            Args:
                target: Base URL (e.g. https://10.10.10.10 or https://example.com)
                wordlist: Subdomain/vhost wordlist path
                threads: Concurrent threads

            Returns:
                JSON with job_id; poll gobuster_status for results
            """
            payload = {
                "target": target,
                "mode": "vhost",
                "wordlist": wordlist,
                "threads": threads,
                "timeout": 600.0,
            }
            result = await self._api_request("POST", "/api/enumerate", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def gobuster_s3(
            wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
            threads: int = 10,
        ) -> str:
            """Enumerate public/misconfigured AWS S3 buckets with Gobuster.

            Tries wordlist entries as S3 bucket names and reports Open,
            AuthRequired, or DoesNotExist status.

            Args:
                wordlist: Wordlist of potential bucket names
                threads: Concurrent threads

            Returns:
                JSON with job_id; poll gobuster_status for results
            """
            payload = {
                "target": "s3",
                "mode": "s3",
                "wordlist": wordlist,
                "threads": threads,
                "timeout": 600.0,
            }
            result = await self._api_request("POST", "/api/enumerate", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def gobuster_status(job_id: str) -> str:
            """Get Gobuster enumeration status and results.

            Args:
                job_id: Job ID returned by any gobuster_* start tool

            Returns:
                JSON with status, total_findings, and results list
            """
            result = await self._api_request("GET", f"/api/enumerate/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def gobuster_cancel(job_id: str) -> str:
            """Cancel a running Gobuster enumeration.

            Args:
                job_id: Job ID to cancel

            Returns:
                Confirmation JSON
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def gobuster_list_wordlists() -> str:
            """List available wordlists on the server.

            Returns:
                JSON with available and all_known wordlist paths
            """
            result = await self._api_request("GET", "/api/wordlists")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def gobuster_server_status() -> str:
            """Get gobuster-claude service health and job counts.

            Returns:
                JSON with running/completed/error/cancelled counts
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
