"""Tests for subdomain enumeration."""

from unittest.mock import patch, MagicMock

from bountyhound.recon.subdomains import SubdomainScanner
from bountyhound.utils import ToolResult


def test_parse_subfinder_output():
    scanner = SubdomainScanner()
    output = "api.example.com\nwww.example.com\nmail.example.com\n"
    results = scanner.parse_output(output)
    assert len(results) == 3
    assert "api.example.com" in results


def test_run_returns_subdomains():
    scanner = SubdomainScanner()
    with patch("bountyhound.recon.subdomains.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout="api.example.com\nwww.example.com\n",
            stderr="",
            returncode=0
        )
        results = scanner.run("example.com")
        assert len(results) == 2
        assert "api.example.com" in results


def test_run_handles_empty_output():
    scanner = SubdomainScanner()
    with patch("bountyhound.recon.subdomains.run_tool") as mock_run:
        mock_run.return_value = ToolResult(stdout="", stderr="", returncode=0)
        results = scanner.run("example.com")
        assert results == []
