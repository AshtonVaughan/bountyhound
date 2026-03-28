"""MCP server for metasploit-claude — exploit execution and session management."""

from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from mcp_base import BaseToolMCP


class MetasploitMCP(BaseToolMCP):
    """MCP server providing Metasploit exploit execution and session control."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8195"):
        super().__init__("metasploit-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register all Metasploit MCP tool functions."""

        @self.mcp.tool()
        async def metasploit_run(
            module_type: str,
            module_path: str,
            options: str = "",
            payload: str = "",
            payload_lhost: str = "",
            payload_lport: str = "4444",
            timeout: float = 300.0,
        ) -> str:
            """Execute a Metasploit module (exploit, auxiliary, post, or scanner).

            Runs the module via msfconsole resource script in the background.
            Poll metasploit_run_status to retrieve sessions opened and findings.

            Args:
                module_type: Module type — exploit, auxiliary, post, scanner
                module_path: Module path (e.g. scanner/portscan/tcp, windows/smb/ms17_010_eternalblue)
                options: Comma-separated KEY=VALUE pairs (e.g. RHOSTS=10.0.0.1,RPORT=445)
                payload: Payload path for exploits (e.g. windows/x64/meterpreter/reverse_tcp)
                payload_lhost: LHOST for reverse payloads (your IP)
                payload_lport: LPORT for reverse payloads (default 4444)
                timeout: Execution timeout in seconds

            Returns:
                JSON with job_id; poll metasploit_run_status for results
            """
            # Parse options string KEY=VALUE,KEY=VALUE into dict
            opts: dict[str, str] = {}
            for pair in options.split(","):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    opts[k.strip()] = v.strip()

            payload_opts: dict[str, str] = {}
            if payload_lhost:
                payload_opts["LHOST"] = payload_lhost
            if payload_lport:
                payload_opts["LPORT"] = payload_lport

            payload = payload.strip()

            payload_req = {
                "module_type": module_type,
                "module_path": module_path,
                "options": opts,
                "payload": payload,
                "payload_options": payload_opts,
                "run_as_job": True,
                "use_rpc": False,
                "timeout": timeout,
            }
            result = await self._api_request("POST", "/api/run", payload_req)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def metasploit_run_status(job_id: str) -> str:
            """Get Metasploit module execution status, sessions, and findings.

            Args:
                job_id: Job ID from metasploit_run

            Returns:
                JSON with status, sessions_opened, findings, and output
            """
            result = await self._api_request("GET", f"/api/run/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def metasploit_search(
            query: str,
            module_type: str = "",
            platform: str = "",
            rank: str = "",
        ) -> str:
            """Search the Metasploit module database.

            Find exploits, auxiliaries, and post-exploitation modules by
            CVE number, module name, platform, keyword, or rank.

            Args:
                query: Search terms (e.g. 'ms17-010', 'eternalblue', 'CVE-2021-44228')
                module_type: Filter by type — exploit, auxiliary, post (leave blank for all)
                platform: Platform filter — windows, linux, osx, multi (leave blank for all)
                rank: Minimum rank — excellent, great, good, normal, average, low

            Returns:
                JSON with job_id; poll metasploit_search_status for module list
            """
            payload = {
                "query": query,
                "module_type": module_type,
                "platform": platform,
                "rank": rank,
                "timeout": 60.0,
            }
            result = await self._api_request("POST", "/api/search", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def metasploit_search_status(job_id: str) -> str:
            """Get Metasploit module search results.

            Args:
                job_id: Job ID from metasploit_search

            Returns:
                JSON with list of matching modules including path, rank, description
            """
            result = await self._api_request("GET", f"/api/search/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def metasploit_session_exec(
            session_id: int,
            command: str,
        ) -> str:
            """Execute a command in an open Meterpreter or shell session.

            Send arbitrary commands to an active post-exploitation session.
            Works with both Meterpreter and generic shell sessions.

            Args:
                session_id: Session ID (from sessions_opened in run job)
                command: Command to execute (e.g. 'sysinfo', 'getuid', 'shell whoami')

            Returns:
                JSON with job_id; poll metasploit_session_status for output
            """
            payload = {
                "session_id": session_id,
                "command": command,
                "use_rpc": False,
                "timeout": 60.0,
            }
            result = await self._api_request("POST", "/api/session", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def metasploit_session_status(job_id: str) -> str:
            """Get session command execution output.

            Args:
                job_id: Job ID from metasploit_session_exec

            Returns:
                JSON with command output string
            """
            result = await self._api_request("GET", f"/api/session/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def metasploit_list_sessions() -> str:
            """List all active Metasploit sessions.

            Returns all Meterpreter and shell sessions opened by exploit jobs,
            with host info, session type, and access level.

            Returns:
                JSON with sessions list and total count
            """
            result = await self._api_request("GET", "/api/sessions")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def metasploit_common_modules() -> str:
            """List commonly used Metasploit module paths for reference.

            Returns categorised module paths for scanners, exploits, post-exploitation
            modules, and payload suggestions by platform.

            Returns:
                JSON with categorised module references
            """
            result = await self._api_request("GET", "/api/modules/common")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def metasploit_cancel(job_id: str) -> str:
            """Cancel a running Metasploit job.

            Args:
                job_id: Job ID to cancel

            Returns:
                Confirmation JSON
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def metasploit_server_status() -> str:
            """Get metasploit-claude service health and job counts.

            Returns:
                JSON with job counts and active session count
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
