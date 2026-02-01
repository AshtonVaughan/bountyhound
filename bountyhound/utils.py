"""Utility functions for BountyHound."""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not found."""

    pass


@dataclass
class ToolResult:
    """Result from running an external tool."""

    stdout: str
    stderr: str
    returncode: int


def find_tool(name: str, config_path: str | None = None) -> Optional[str]:
    """Find an external tool by name.

    Args:
        name: Tool name (e.g., 'subfinder', 'nuclei')
        config_path: Optional explicit path from config

    Returns:
        Path to tool if found, None otherwise
    """
    if config_path:
        return config_path if shutil.which(config_path) else None
    return shutil.which(name)


def run_tool(
    name: str,
    args: list[str],
    config_path: str | None = None,
    timeout: int | None = None,
    input_data: str | None = None,
) -> ToolResult:
    """Run an external tool and capture output.

    Args:
        name: Tool name
        args: Command line arguments
        config_path: Optional explicit path from config
        timeout: Timeout in seconds
        input_data: Data to pass to stdin

    Returns:
        ToolResult with stdout, stderr, returncode

    Raises:
        ToolNotFoundError: If tool is not installed
    """
    tool_path = find_tool(name, config_path)
    if tool_path is None:
        raise ToolNotFoundError(
            f"Tool '{name}' not found. Install it or configure the path in ~/.bountyhound/config.yaml"
        )

    try:
        result = subprocess.run(
            [tool_path] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        return ToolResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(stdout="", stderr="Tool execution timed out", returncode=-1)


def parse_json_lines(output: str) -> list[dict]:
    """Parse newline-delimited JSON output (common format for security tools)."""
    import json

    results = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results
