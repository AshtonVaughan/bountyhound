"""Shared subprocess execution for BountyHound CLI security tools.

Canonical implementation of subprocess helpers used by both tool_bridge.py
(agent-side async wrappers) and tool_runner.py (MCP server). All subprocess
execution logic lives here - consumers import and re-export as needed.

Stdlib only. Python 3.10+.
"""

import json
import shutil
import subprocess


class ToolNotFoundError(Exception):
    """Raised when a CLI tool binary is not found on PATH."""


class ToolTimeoutError(Exception):
    """Raised when a CLI tool exceeds its timeout."""


def check_tool_available(name: str) -> bool:
    """Check whether a CLI tool binary exists on PATH.

    Args:
        name: Name of the binary to look up (e.g. "nuclei", "nmap").

    Returns:
        True if the tool is found, False otherwise.
    """
    return shutil.which(name) is not None


def _try_parse_json(stdout: str) -> object | None:
    """Attempt to parse stdout as JSON, falling back to JSONL.

    JSONL (one JSON object per line) is common for tools like nuclei.
    Returns a list of parsed objects for JSONL, a single object for
    plain JSON, or None if parsing fails entirely.
    """
    try:
        return json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        pass

    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return None

    parsed: list[object] = []
    for ln in lines:
        try:
            parsed.append(json.loads(ln))
        except (json.JSONDecodeError, ValueError):
            return None

    return parsed if len(parsed) != 1 else parsed[0]


def run_tool(
    cmd: list[str],
    timeout: int = 300,
    parse_json: bool = False,
    stdin_data: str | None = None,
) -> dict:
    """Run a CLI tool as a subprocess and return structured output.

    Args:
        cmd: Command and arguments as a list (e.g. ["nmap", "-sV", "target"]).
        timeout: Maximum seconds to wait before killing the process.
        parse_json: If True, attempt to parse stdout as JSON/JSONL.
        stdin_data: Optional string to pipe to the process's stdin.

    Returns:
        Dict with keys: status, stdout, stderr, returncode, and
        optionally parsed (when parse_json is True).

    Raises:
        ToolNotFoundError: If the command binary is not on PATH.
        ToolTimeoutError: If the process exceeds the timeout.
    """
    if not check_tool_available(cmd[0]):
        raise ToolNotFoundError(f"Tool not found on PATH: {cmd[0]}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(
            f"Tool timed out after {timeout}s: {cmd[0]}"
        ) from exc

    result: dict = {
        "status": "completed" if proc.returncode == 0 else "error",
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }

    if parse_json:
        result["parsed"] = _try_parse_json(proc.stdout)

    return result
