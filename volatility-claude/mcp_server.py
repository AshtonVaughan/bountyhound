"""MCP server for volatility-claude — memory forensics and malware analysis."""

from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from mcp_base import BaseToolMCP


class VolatilityMCP(BaseToolMCP):
    """MCP server providing Volatility3 memory forensics capabilities."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8197"):
        super().__init__("volatility-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register Volatility MCP tool functions."""

        @self.mcp.tool()
        async def volatility_plugin(
            memory_image: str,
            plugin: str,
            plugin_args: str = "",
            symbol_path: str = "",
            timeout: float = 300.0,
        ) -> str:
            """Run a Volatility3 plugin against a memory dump image.

            Executes the specified plugin and returns structured results with
            automatic security finding analysis for malware detection plugins.

            Args:
                memory_image: Absolute path to memory dump file (.raw, .lime, .mem, .dmp)
                plugin: Volatility3 plugin name (e.g. windows.pslist.PsList, linux.malfind.Malfind)
                plugin_args: Space-separated KEY=VALUE plugin arguments (e.g. PID=1234)
                symbol_path: Custom symbol/ISF file directory path
                timeout: Plugin execution timeout in seconds

            Returns:
                JSON with job_id; poll volatility_plugin_status for results
            """
            args_dict: dict[str, str] = {}
            for pair in plugin_args.split():
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    args_dict[k.strip()] = v.strip()

            payload = {
                "memory_image": memory_image,
                "plugin": plugin,
                "plugin_args": args_dict,
                "symbol_path": symbol_path,
                "timeout": timeout,
            }
            result = await self._api_request("POST", "/api/plugin", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def volatility_plugin_status(job_id: str) -> str:
            """Get Volatility plugin execution results and findings.

            Args:
                job_id: Job ID from volatility_plugin

            Returns:
                JSON with raw_output rows, security findings, OS profile, and row count
            """
            result = await self._api_request("GET", f"/api/plugin/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def volatility_triage(
            memory_image: str,
            os_family: str = "windows",
            timeout: float = 1800.0,
        ) -> str:
            """Run a full forensic triage batch against a memory image.

            Automatically runs the recommended plugin set for the target OS:
            - Windows: pslist, pstree, cmdline, netscan, malfind, svcscan, hashdump
            - Linux: pslist, pstree, bash, netfilter, malfind, lsmod

            Aggregates all findings into a single result with indicator classification.

            Args:
                memory_image: Absolute path to memory dump file
                os_family: Target OS — 'windows' or 'linux'
                timeout: Total triage timeout in seconds (default 30 min)

            Returns:
                JSON with job_id; poll volatility_batch_status for complete results
            """
            # Fetch triage plugins from server
            triage_resp = await self._api_request("GET", f"/api/triage-plugins?os={os_family}")
            plugins = triage_resp.get("plugins", [])

            payload = {
                "memory_image": memory_image,
                "plugins": plugins,
                "stop_on_error": False,
                "timeout": timeout,
            }
            result = await self._api_request("POST", "/api/batch", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def volatility_batch(
            memory_image: str,
            plugins: str,
            timeout: float = 1800.0,
        ) -> str:
            """Run a custom set of Volatility3 plugins as a batch.

            Args:
                memory_image: Absolute path to memory dump file
                plugins: Comma-separated list of Volatility3 plugin names
                timeout: Total batch timeout in seconds

            Returns:
                JSON with job_id; poll volatility_batch_status for results
            """
            plugin_list = [p.strip() for p in plugins.split(",") if p.strip()]
            payload = {
                "memory_image": memory_image,
                "plugins": plugin_list,
                "stop_on_error": False,
                "timeout": timeout,
            }
            result = await self._api_request("POST", "/api/batch", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def volatility_batch_status(job_id: str) -> str:
            """Get batch analysis progress and aggregated security findings.

            Args:
                job_id: Job ID from volatility_triage or volatility_batch

            Returns:
                JSON with plugins_completed, plugins_failed, all_findings, plugin_results
            """
            result = await self._api_request("GET", f"/api/batch/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def volatility_list_triage_plugins(os_family: str = "windows") -> str:
            """List the recommended triage plugin set for an OS.

            Args:
                os_family: 'windows' or 'linux'

            Returns:
                JSON with list of plugin names
            """
            result = await self._api_request("GET", f"/api/triage-plugins?os={os_family}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def volatility_server_status() -> str:
            """Get volatility-claude service health and job counts.

            Returns:
                JSON with running/completed/error job counts
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
