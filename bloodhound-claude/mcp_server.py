"""MCP server for bloodhound-claude — AD enumeration and graph attack paths."""

from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from mcp_base import BaseToolMCP


class BloodHoundMCP(BaseToolMCP):
    """MCP server providing BloodHound AD enumeration and graph analysis."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8194"):
        super().__init__("bloodhound-claude", api_base_url)

    def _register_tools(self) -> None:
        """Register BloodHound MCP tool functions."""

        @self.mcp.tool()
        async def bloodhound_collect(
            domain: str,
            dc: str = "",
            username: str = "",
            password: str = "",
            collection_methods: str = "Default",
            stealth: bool = False,
            nameserver: str = "",
        ) -> str:
            """Collect Active Directory data with BloodHound (bloodhound-python).

            Runs SharpHound-compatible data collection against the target AD domain.
            Gathers users, groups, computers, ACLs, sessions, and trust relationships.
            Output JSON files are saved for import into BloodHound CE or classic.

            Args:
                domain: Target AD domain FQDN (e.g. corp.local)
                dc: Domain controller IP or hostname (leave blank for auto-discover)
                username: AD username for authentication (domain\\user or user@domain)
                password: AD password
                collection_methods: Comma-separated methods: Default, All, DCOnly, Session, ACL, Trusts, LocalAdmin
                stealth: Enable stealth mode (slower, fewer queries per host)
                nameserver: Custom DNS server IP for resolution

            Returns:
                JSON with job_id; poll bloodhound_collect_status for completion
            """
            methods = [m.strip() for m in collection_methods.split(",") if m.strip()]
            payload = {
                "domain": domain,
                "dc": dc,
                "username": username,
                "password": password,
                "collection_methods": methods,
                "stealth": stealth,
                "nameserver": nameserver,
                "use_python_collector": True,
                "timeout": 3600.0,
            }
            result = await self._api_request("POST", "/api/collect", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def bloodhound_collect_status(job_id: str) -> str:
            """Get BloodHound collection status and output file paths.

            Args:
                job_id: Job ID from bloodhound_collect

            Returns:
                JSON with status, output_files, objects_collected
            """
            result = await self._api_request("GET", f"/api/collect/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def bloodhound_query(
            query: str,
            database_url: str = "bolt://127.0.0.1:7687",
            database_user: str = "neo4j",
            database_password: str = "bloodhound",
            limit: int = 500,
        ) -> str:
            """Execute a raw Cypher query against BloodHound's Neo4j database.

            Use this for custom AD graph queries. Supports all standard Cypher
            syntax including MATCH, WHERE, RETURN, ORDER BY, and aggregations.

            Args:
                query: Cypher query string (LIMIT auto-appended if absent)
                database_url: Neo4j bolt URL (default: bolt://127.0.0.1:7687)
                database_user: Neo4j username (default: neo4j)
                database_password: Neo4j password (default: bloodhound)
                limit: Maximum result rows to return

            Returns:
                JSON with job_id; poll bloodhound_query_status for results
            """
            payload = {
                "query": query,
                "database_url": database_url,
                "database_user": database_user,
                "database_password": database_password,
                "limit": limit,
                "timeout": 120.0,
            }
            result = await self._api_request("POST", "/api/query", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def bloodhound_query_status(job_id: str) -> str:
            """Get Cypher query results from BloodHound.

            Args:
                job_id: Job ID from bloodhound_query

            Returns:
                JSON with rows and row_count
            """
            result = await self._api_request("GET", f"/api/query/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def bloodhound_builtin_query(
            query_name: str,
            database_url: str = "bolt://127.0.0.1:7687",
            database_user: str = "neo4j",
            database_password: str = "bloodhound",
        ) -> str:
            """Run a built-in BloodHound Cypher query by name.

            Available queries:
              kerberoastable         — Enabled users with SPNs
              asreproastable         — Users with pre-auth disabled
              unconstrained_delegation — Computers with unconstrained delegation
              da_sessions            — Computers with domain admin sessions
              path_to_da             — Shortest paths to Domain Admins
              computers_with_admin   — Groups with AdminTo on computers
              dcsync_principals      — Non-standard principals with DCSync rights
              laps_computers         — Computers without LAPS enabled

            Args:
                query_name: One of the query names listed above
                database_url: Neo4j bolt URL
                database_user: Neo4j username
                database_password: Neo4j password

            Returns:
                JSON with job_id; poll bloodhound_query_status for results
            """
            # Fetch built-in queries to validate
            queries_resp = await self._api_request("GET", "/api/queries")
            queries = queries_resp.get("queries", {})
            if query_name not in queries:
                available = list(queries.keys())
                return json.dumps({
                    "error": f"Unknown query '{query_name}'",
                    "available": available,
                })

            payload = {
                "query": queries[query_name],
                "database_url": database_url,
                "database_user": database_user,
                "database_password": database_password,
                "limit": 500,
                "timeout": 120.0,
            }
            result = await self._api_request("POST", "/api/query", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def bloodhound_find_paths(
            source: str,
            target: str = "Domain Admins",
            path_type: str = "shortest",
            database_url: str = "bolt://127.0.0.1:7687",
            database_user: str = "neo4j",
            database_password: str = "bloodhound",
            max_paths: int = 10,
        ) -> str:
            """Find attack paths between two Active Directory nodes.

            Identifies exploitation chains from a compromised account or computer
            to a high-value target like Domain Admins. Scores paths by risk.

            Args:
                source: Source node name (e.g. 'JDOE@CORP.LOCAL') or leave blank for built-in path_type
                target: Target node name (e.g. 'Domain Admins@CORP.LOCAL')
                path_type: shortest | all | kerberoastable | asreproastable | unconstrained_delegation
                database_url: Neo4j bolt URL
                database_user: Neo4j username
                database_password: Neo4j password
                max_paths: Maximum number of paths to return

            Returns:
                JSON with job_id; poll bloodhound_paths_status for results
            """
            payload = {
                "source": source,
                "target": target,
                "path_type": path_type,
                "database_url": database_url,
                "database_user": database_user,
                "database_password": database_password,
                "max_paths": max_paths,
                "timeout": 120.0,
            }
            result = await self._api_request("POST", "/api/paths", payload)
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def bloodhound_paths_status(job_id: str) -> str:
            """Get attack path analysis results.

            Args:
                job_id: Job ID from bloodhound_find_paths

            Returns:
                JSON with paths, findings, and risk scores
            """
            result = await self._api_request("GET", f"/api/paths/{job_id}")
            return json.dumps(result, indent=2, default=str)

        @self.mcp.tool()
        async def bloodhound_cancel(job_id: str) -> str:
            """Cancel any running BloodHound job.

            Args:
                job_id: Job ID to cancel

            Returns:
                Confirmation JSON
            """
            result = await self._api_request("POST", f"/api/cancel/{job_id}")
            return json.dumps(result, indent=2)

        @self.mcp.tool()
        async def bloodhound_server_status() -> str:
            """Get bloodhound-claude service health and job summary.

            Returns:
                JSON with job counts and available built-in queries
            """
            result = await self._api_request("GET", "/api/status")
            return json.dumps(result, indent=2)
