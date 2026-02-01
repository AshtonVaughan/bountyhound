"""Tests for vulnerability scanning."""

from unittest.mock import patch

from bountyhound.scan.nuclei import NucleiScanner
from bountyhound.utils import ToolResult


def test_parse_nuclei_json_output():
    scanner = NucleiScanner()
    output = '''{"template-id":"cve-2021-1234","name":"Test Vuln","severity":"high","host":"https://example.com","matched-at":"https://example.com/vuln"}
{"template-id":"xss-detection","name":"XSS","severity":"medium","host":"https://example.com","matched-at":"https://example.com/search"}'''
    results = scanner.parse_output(output)
    assert len(results) == 2
    assert results[0]["severity"] == "high"
    assert results[0]["template"] == "cve-2021-1234"


def test_run_returns_findings():
    scanner = NucleiScanner()
    with patch("bountyhound.scan.nuclei.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout='{"template-id":"sqli","name":"SQL Injection","severity":"critical","host":"https://example.com","matched-at":"https://example.com/login"}\n',
            stderr="",
            returncode=0
        )
        results = scanner.run(["https://example.com"])
        assert len(results) == 1
        assert results[0]["severity"] == "critical"


def test_run_handles_no_findings():
    scanner = NucleiScanner()
    with patch("bountyhound.scan.nuclei.run_tool") as mock_run:
        mock_run.return_value = ToolResult(stdout="", stderr="", returncode=0)
        results = scanner.run(["https://example.com"])
        assert results == []
