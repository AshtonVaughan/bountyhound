"""Tests for HTTP probing."""

from unittest.mock import patch

from bountyhound.recon.httpx import HttpProber
from bountyhound.utils import ToolResult


def test_parse_httpx_json_output():
    prober = HttpProber()
    output = '''{"url":"https://api.example.com","status_code":200,"tech":["nginx"]}
{"url":"https://www.example.com","status_code":301,"tech":["cloudflare"]}'''
    results = prober.parse_output(output)
    assert len(results) == 2
    assert results[0]["url"] == "https://api.example.com"
    assert results[0]["status_code"] == 200


def test_run_returns_live_hosts():
    prober = HttpProber()
    with patch("bountyhound.recon.httpx.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout='{"url":"https://api.example.com","status_code":200,"tech":["nginx"]}\n',
            stderr="",
            returncode=0
        )
        results = prober.run(["api.example.com", "www.example.com"])
        assert len(results) == 1
        assert results[0]["url"] == "https://api.example.com"


def test_run_handles_empty_output():
    prober = HttpProber()
    with patch("bountyhound.recon.httpx.run_tool") as mock_run:
        mock_run.return_value = ToolResult(stdout="", stderr="", returncode=0)
        results = prober.run(["example.com"])
        assert results == []
