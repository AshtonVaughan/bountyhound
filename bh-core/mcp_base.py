"""Base MCP server template for BountyHound tools."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

log = logging.getLogger("bh-core.mcp")


class BaseToolMCP:
    """Base class for MCP tool servers.

    Subclasses implement tool-specific logic by overriding methods.
    """

    def __init__(self, tool_name: str, api_base_url: str = "http://127.0.0.1:8188"):
        """Initialize MCP server.

        Args:
            tool_name: Name of the tool (e.g. "nuclei", "sqlmap").
            api_base_url: Base URL for the API server.
        """
        self.tool_name = tool_name
        self.api_base_url = api_base_url
        self.mcp = FastMCP(
            tool_name,
            instructions=f"BountyHound {tool_name.title()} Tool - Security scanning and testing",
        )
        self._register_tools()

    def _register_tools(self) -> None:
        """Override this method to register tool-specific MCP tools."""
        raise NotImplementedError

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Make HTTP request to the API server.

        Args:
            method: HTTP method (GET, POST, etc).
            endpoint: API endpoint (e.g. "/api/scan").
            json_data: JSON body for POST requests.
            timeout: Request timeout in seconds.

        Returns:
            Response JSON as dictionary.
        """
        import httpx

        url = f"{self.api_base_url}{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.request(method, url, json=json_data)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            log.error(f"API request failed: {e}")
            raise

    def run(self) -> None:
        """Run the MCP server."""
        self.mcp.run()
