"""Tests for tool_runner.py - shared subprocess infrastructure for MCP tools."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'mcp-unified-server'))
from tool_runner import run_tool, check_tool_available, ToolNotFoundError, ToolTimeoutError


def test_check_tool_available_existing():
    """echo exists on all platforms."""
    assert check_tool_available("echo") is True


def test_check_tool_available_nonexistent():
    assert check_tool_available("nonexistent_xyz_99") is False


def test_run_tool_echo():
    result = run_tool(["echo", "hello"])
    assert result["status"] == "completed"
    assert "hello" in result["stdout"]
    assert result["returncode"] == 0


def test_run_tool_timeout():
    with pytest.raises(ToolTimeoutError):
        run_tool(["python", "-c", "import time; time.sleep(10)"], timeout=1)


def test_run_tool_not_found():
    with pytest.raises(ToolNotFoundError):
        run_tool(["nonexistent_tool_xyz"])


def test_run_tool_parse_json():
    result = run_tool(
        ["python", "-c", "print('{\"key\":\"value\"}')"], parse_json=True
    )
    assert result["parsed"] == {"key": "value"}


def test_run_tool_parse_json_invalid():
    result = run_tool(["python", "-c", "print('not json')"], parse_json=True)
    assert result["parsed"] is None


def test_run_tool_nonzero_exit():
    result = run_tool(["python", "-c", "import sys; sys.exit(1)"])
    assert result["status"] == "error"
    assert result["returncode"] == 1
