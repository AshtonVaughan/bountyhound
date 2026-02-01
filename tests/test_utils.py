"""Tests for utility functions."""

import subprocess
from unittest.mock import patch, MagicMock

from bountyhound.utils import find_tool, run_tool, ToolNotFoundError


def test_find_tool_returns_path_when_found():
    # Test with a tool that should exist on any system
    with patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/python"
        path = find_tool("python")
        assert path == "/usr/bin/python"


def test_find_tool_returns_none_when_not_found():
    with patch("shutil.which") as mock_which:
        mock_which.return_value = None
        path = find_tool("nonexistent_tool_xyz")
        assert path is None


def test_run_tool_returns_output():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="output line 1\noutput line 2",
            stderr="",
            returncode=0
        )
        result = run_tool("echo", ["hello"])
        assert result.returncode == 0
        assert "output" in result.stdout


def test_run_tool_raises_on_missing_tool():
    with patch("bountyhound.utils.find_tool") as mock_find:
        mock_find.return_value = None
        try:
            run_tool("nonexistent_tool", [])
            assert False, "Should have raised ToolNotFoundError"
        except ToolNotFoundError as e:
            assert "nonexistent_tool" in str(e)
