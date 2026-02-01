"""Tests for port scanning."""

from unittest.mock import patch

from bountyhound.recon.ports import PortScanner
from bountyhound.utils import ToolResult


def test_parse_nmap_output():
    scanner = PortScanner()
    # Simplified nmap greppable output format
    output = """Host: 1.2.3.4 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.0/, 80/open/tcp//http//nginx/, 443/open/tcp//https//"""
    results = scanner.parse_output(output)
    assert len(results) == 1
    assert results["1.2.3.4"][0]["port"] == 22
    assert results["1.2.3.4"][0]["service"] == "ssh"


def test_run_returns_open_ports():
    scanner = PortScanner()
    with patch("bountyhound.recon.ports.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout="Host: 1.2.3.4 ()	Ports: 80/open/tcp//http//nginx/\n",
            stderr="",
            returncode=0
        )
        results = scanner.run(["1.2.3.4"])
        assert "1.2.3.4" in results
        assert results["1.2.3.4"][0]["port"] == 80
