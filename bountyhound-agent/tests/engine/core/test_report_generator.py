"""
Unit tests for engine.core.report_generator

Covers: generate(), generate_from_requests(), save(),
        _build_exploit(), _build_diff_table(), helper functions.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(**overrides):
    """Return a minimal finding dict, with optional overrides."""
    base = {
        'title': 'IDOR on /api/users/{id}',
        'severity': 'HIGH',
        'vuln_type': 'IDOR',
        'endpoint': 'https://example.com/api/users/42',
        'description': 'User B can read User A profile.',
    }
    base.update(overrides)
    return base


@pytest.fixture
def finding():
    return _make_finding()


@pytest.fixture
def generator(tmp_path):
    """Build a ReportGenerator with all external deps mocked."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    with patch('engine.core.report_generator.EvidenceVault') as MockVault, \
         patch('engine.core.report_generator.RequestLogger') as MockLogger, \
         patch('engine.core.report_generator.BountyHoundConfig') as MockCfg:

        MockCfg.reports_dir.return_value = reports_dir
        vault_inst = MagicMock()
        vault_inst.get_manifest.return_value = []
        MockVault.return_value = vault_inst
        MockLogger.return_value = MagicMock()

        from engine.core.report_generator import ReportGenerator
        gen = ReportGenerator('example.com')
        # Ensure the reports_dir attribute points at tmp
        gen.reports_dir = reports_dir
        yield gen


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestRequestToCurl:
    """Tests for the module-level _request_to_curl helper."""

    def test_get_request(self):
        from engine.core.report_generator import _request_to_curl
        req = {'method': 'GET', 'url': 'https://example.com/api/v1'}
        curl = _request_to_curl(req)
        assert 'curl -s' in curl
        assert 'https://example.com/api/v1' in curl
        assert '-X' not in curl  # GET should omit -X

    def test_post_with_body(self):
        from engine.core.report_generator import _request_to_curl
        req = {
            'method': 'POST',
            'url': 'https://example.com/api/login',
            'req_headers': json.dumps({'Content-Type': 'application/json'}),
            'req_body': '{"user":"a"}',
        }
        curl = _request_to_curl(req)
        assert '-X POST' in curl
        assert "-d " in curl
        assert 'Content-Type: application/json' in curl

    def test_authorization_header_parameterized(self):
        from engine.core.report_generator import _request_to_curl
        req = {
            'method': 'GET',
            'url': 'https://example.com/api/me',
            'req_headers': json.dumps({'Authorization': 'Bearer secret123'}),
        }
        curl = _request_to_curl(req)
        assert '$AUTH_TOKEN' in curl
        assert 'secret123' not in curl


class TestTruncate:
    def test_short_text_unchanged(self):
        from engine.core.report_generator import _truncate
        assert _truncate('hello', 500) == 'hello'

    def test_long_text_truncated(self):
        from engine.core.report_generator import _truncate
        result = _truncate('x' * 600, 500)
        assert len(result) < 600
        assert '(truncated)' in result

    def test_none_returns_empty(self):
        from engine.core.report_generator import _truncate
        assert _truncate(None) == ''


# ---------------------------------------------------------------------------
# ReportGenerator.generate()
# ---------------------------------------------------------------------------

class TestGenerate:
    def test_returns_markdown_with_title(self, generator, finding):
        report = generator.generate(finding)
        assert report.startswith('# IDOR on /api/users/{id}')

    def test_mandatory_sections_present(self, generator, finding):
        report = generator.generate(finding)
        assert '## Prerequisites' in report
        assert '## Step 0: Setup' in report
        assert '## Step 1: Baseline' in report
        assert '## Step 2: Exploit' in report
        assert '## Before/After Diff' in report
        assert '## Reproduction Script' in report
        assert '## Impact' in report

    def test_hackerone_extras_included(self, generator, finding):
        report = generator.generate(finding, platform='hackerone')
        assert '## Supporting Material' in report

    def test_bugcrowd_extras_included(self, generator, finding):
        report = generator.generate(finding, platform='bugcrowd')
        assert '## Severity Justification' in report

    def test_idor_prerequisites_two_accounts(self, generator, finding):
        report = generator.generate(finding)
        assert 'Account A (victim)' in report
        assert 'Account B (attacker)' in report


# ---------------------------------------------------------------------------
# ReportGenerator.generate_from_requests()
# ---------------------------------------------------------------------------

class TestGenerateFromRequests:
    def test_enriches_finding_with_request_data(self, generator):
        """Baseline and exploit request IDs should inject curl + response."""
        mock_requests = [
            {
                'id': 10,
                'method': 'GET',
                'url': 'https://example.com/api/users/42',
                'req_headers': '{}',
                'req_body': '',
                'resp_body': '{"name":"Alice"}',
                'status_code': 200,
            },
            {
                'id': 20,
                'method': 'GET',
                'url': 'https://example.com/api/users/42',
                'req_headers': '{}',
                'req_body': '',
                'resp_body': '{"name":"Alice"}',
                'status_code': 200,
            },
        ]
        generator.logger.get_requests.return_value = mock_requests

        finding = _make_finding()
        report = generator.generate_from_requests(
            finding,
            baseline_request_id=10,
            exploit_request_id=20,
        )
        # The enriched finding should have baseline/exploit data injected
        assert 'Alice' in report
        assert '## Step 2: Exploit' in report


# ---------------------------------------------------------------------------
# ReportGenerator.save()
# ---------------------------------------------------------------------------

class TestSave:
    def test_save_creates_report_and_script(self, generator, finding, tmp_path):
        report_text = '# Test Report\nContent here.'
        filepath = generator.save(report_text, finding)

        assert Path(filepath).exists()
        assert Path(filepath).read_text(encoding='utf-8') == report_text

        # A reproduce.py companion should also be written
        report_dir = Path(filepath).parent
        py_files = list(report_dir.glob('*_reproduce.py'))
        assert len(py_files) == 1

    def test_save_filename_contains_vuln_type(self, generator):
        finding = _make_finding(vuln_type='XSS')
        filepath = generator.save('# XSS report', finding)
        assert 'xss' in Path(filepath).name.lower()


# ---------------------------------------------------------------------------
# ReportGenerator._build_exploit()
# ---------------------------------------------------------------------------

class TestBuildExploit:
    def test_uses_exploit_curl_when_provided(self, generator):
        finding = _make_finding(exploit_curl="curl -s 'https://example.com/pwn'")
        section = generator._build_exploit(finding)
        assert "https://example.com/pwn" in section

    def test_uses_curl_command_fallback(self, generator):
        finding = _make_finding(curl_command="curl -s 'https://example.com/alt'")
        section = generator._build_exploit(finding)
        assert "https://example.com/alt" in section

    def test_auto_generates_curl_with_payload(self, generator):
        finding = _make_finding(payload={'id': '1 OR 1=1'})
        section = generator._build_exploit(finding)
        assert 'OR 1=1' in section
        assert '-d' in section

    def test_exploit_response_shown(self, generator):
        finding = _make_finding(exploit_response='{"leaked":"secret"}')
        section = generator._build_exploit(finding)
        assert 'leaked' in section
        assert 'THIS IS THE BUG' in section


# ---------------------------------------------------------------------------
# ReportGenerator._build_diff_table()
# ---------------------------------------------------------------------------

class TestBuildDiffTable:
    def test_custom_diff_rows(self, generator):
        rows = [
            {'field': 'user_id', 'normal': '42', 'exploit': '42', 'should_be': 'denied'},
        ]
        finding = _make_finding(diff_rows=rows)
        section = generator._build_diff_table(finding)
        assert 'user_id' in section
        assert 'denied' in section
        assert '| Field |' in section

    def test_auto_diff_from_json_responses(self, generator):
        finding = _make_finding(
            baseline_response='{"name":"Alice","role":"user"}',
            exploit_response='{"name":"Alice","role":"user"}',
            baseline_status=200,
            exploit_status=200,
        )
        section = generator._build_diff_table(finding)
        assert 'body.name' in section
        assert 'Alice' in section

    def test_fallback_when_no_responses(self, generator):
        finding = _make_finding()
        section = generator._build_diff_table(finding)
        assert 'LEAKED' in section
        assert 'HTTP Status' in section
