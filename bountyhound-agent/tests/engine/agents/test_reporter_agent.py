"""
Comprehensive tests for ReporterAgent
"""

import pytest
import tempfile
import json
from pathlib import Path
from engine.agents.reporter_agent import ReporterAgent


@pytest.fixture
def reporter():
    """Create ReporterAgent instance."""
    return ReporterAgent()


@pytest.fixture
def sample_idor_finding():
    """Sample IDOR finding."""
    return {
        'title': 'IDOR in /api/orders leads to Unauthorized Access to Customer Data',
        'severity': 'HIGH',
        'vuln_type': 'IDOR',
        'description': 'The /api/orders endpoint does not verify ownership of the requested order.',
        'http_request': """POST /api/orders/12345 HTTP/1.1
Host: example.com
Authorization: Bearer attacker_token

{}""",
        'http_response': {
            'success': True,
            'order': {
                'id': 12345,
                'customer_email': 'victim@example.com',
                'address': '123 Victim St'
            }
        },
        'steps': [
            'Log in to the application with Account A',
            'Obtain an order ID from Account B (victim)',
            'Send GET request to /api/orders/{victim_order_id} with Account A token',
            'Observe that the order data is returned without authorization check'
        ],
        'impact': 'Attacker can access any user\'s order history, delivery addresses, and payment information.',
        'expected_behavior': 'The server should return 403 Forbidden when requesting another user\'s order.',
        'actual_behavior': 'The server returns the order data without checking ownership.',
        'remediation': 'Add authorization check to verify order.user_id == current_user.id',
        'attachments': [
            {'name': 'screenshot_1.png', 'description': 'Request in Burp Suite'},
            {'name': 'response.json', 'description': 'Full response showing victim data'}
        ]
    }


@pytest.fixture
def sample_xss_finding():
    """Sample XSS finding."""
    return {
        'title': 'Reflected XSS in Search Parameter',
        'severity': 'MEDIUM',
        'vuln_type': 'XSS',
        'description': 'The search parameter is reflected in the response without sanitization.',
        'command': 'curl "https://example.com/search?q=<script>alert(document.domain)</script>"',
        'steps': [
            'Navigate to https://example.com/search',
            'Enter payload: <script>alert(document.domain)</script>',
            'Submit the search form',
            'Observe script execution in browser'
        ]
    }


@pytest.fixture
def sample_graphql_finding():
    """Sample GraphQL auth bypass finding."""
    return {
        'title': 'Missing Authorization on GraphQL Mutations',
        'severity': 'CRITICAL',
        'vuln_type': 'GraphQL Auth',
        'description': 'GraphQL gateway forwards mutations without authentication.',
        'http_request': """POST /graphql HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "query": "mutation { deleteUser(id: \\"12345\\") { success } }"
}""",
        'http_response': {'data': {'deleteUser': {'success': True}}},
        'architecture': 'Apollo GraphQL Gateway + gRPC microservices',
        'discovery_method': 'Field suggestions enumeration',
        'related_findings': '29 total mutations lack authentication',
        'data_exposure': True,
        'data_modification': True,
        'network_accessible': True,
        'authenticated': False
    }


# ============================================================================
# Basic Functionality Tests
# ============================================================================

def test_reporter_initialization(reporter):
    """Test ReporterAgent initializes correctly."""
    assert reporter is not None
    assert reporter.templates is not None
    assert len(reporter.templates) == 3
    assert 'hackerone' in reporter.templates
    assert 'bugcrowd' in reporter.templates
    assert 'intigriti' in reporter.templates


def test_severity_constants(reporter):
    """Test severity constants are defined."""
    assert reporter.SEVERITY_CRITICAL == "CRITICAL"
    assert reporter.SEVERITY_HIGH == "HIGH"
    assert reporter.SEVERITY_MEDIUM == "MEDIUM"
    assert reporter.SEVERITY_LOW == "LOW"
    assert reporter.SEVERITY_INFO == "INFO"


def test_platform_constants(reporter):
    """Test platform constants are defined."""
    assert reporter.PLATFORM_HACKERONE == "hackerone"
    assert reporter.PLATFORM_BUGCROWD == "bugcrowd"
    assert reporter.PLATFORM_INTIGRITI == "intigriti"


def test_cwe_mappings(reporter):
    """Test CWE mappings exist for common vulnerability types."""
    assert reporter.CWE_MAP['IDOR'] == 'CWE-639'
    assert reporter.CWE_MAP['XSS'] == 'CWE-79'
    assert reporter.CWE_MAP['SQLi'] == 'CWE-89'
    assert reporter.CWE_MAP['GraphQL Auth'] == 'CWE-862'


# ============================================================================
# Report Generation Tests
# ============================================================================

def test_generate_report_hackerone(reporter, sample_idor_finding):
    """Test HackerOne report generation."""
    report = reporter.generate_report(
        sample_idor_finding,
        target='example.com',
        platform='hackerone'
    )

    assert report is not None
    assert len(report) > 100

    # Check required sections
    assert '## Summary' in report
    assert '## Expected vs Actual Behavior' in report
    assert '## Steps to Reproduce' in report
    assert '## Impact' in report
    assert '## Supporting Material' in report
    assert '## Recommended Fix' in report

    # Check content
    assert sample_idor_finding['title'] in report
    assert 'IDOR' in report
    assert 'victim@example.com' in report


def test_generate_report_bugcrowd(reporter, sample_idor_finding):
    """Test Bugcrowd report generation."""
    report = reporter.generate_report(
        sample_idor_finding,
        target='example.com',
        platform='bugcrowd'
    )

    assert report is not None
    assert '## Description' in report
    assert '## Proof of Concept' in report
    assert '## Severity Justification' in report
    assert 'CVSS' in report


def test_generate_report_intigriti(reporter, sample_xss_finding):
    """Test Intigriti report generation."""
    report = reporter.generate_report(
        sample_xss_finding,
        target='example.com',
        platform='intigriti'
    )

    assert report is not None
    assert '## Environment' in report
    assert '## Attachments' in report
    assert 'Browser:' in report
    assert 'OS:' in report


def test_generate_report_missing_fields(reporter):
    """Test report generation fails with missing required fields."""
    invalid_finding = {'title': 'Test'}

    with pytest.raises(ValueError, match="Missing required field"):
        reporter.generate_report(invalid_finding, target='example.com')


def test_generate_report_defaults_to_hackerone(reporter, sample_idor_finding):
    """Test invalid platform defaults to HackerOne."""
    report = reporter.generate_report(
        sample_idor_finding,
        target='example.com',
        platform='invalid_platform'
    )

    # Should use HackerOne template
    assert '## Expected vs Actual Behavior' in report


# ============================================================================
# Format Finding Tests
# ============================================================================

def test_format_finding_critical(reporter):
    """Test formatting critical finding."""
    finding = {
        'title': 'RCE via File Upload',
        'severity': 'CRITICAL',
        'vuln_type': 'RCE',
        'description': 'Arbitrary code execution'
    }

    formatted = reporter.format_finding(finding)

    assert 'RCE via File Upload' in formatted
    assert 'CRITICAL' in formatted
    assert 'CWE-94' in formatted


def test_format_finding_high(reporter, sample_idor_finding):
    """Test formatting high severity finding."""
    formatted = reporter.format_finding(sample_idor_finding)

    assert 'HIGH' in formatted
    assert 'IDOR' in formatted


def test_format_finding_info(reporter):
    """Test formatting info finding."""
    finding = {
        'title': 'Version Disclosure',
        'severity': 'INFO',
        'vuln_type': 'Info Disclosure',
        'description': 'Server version leaked'
    }

    formatted = reporter.format_finding(finding)

    assert 'INFO' in formatted


# ============================================================================
# Severity Calculation Tests
# ============================================================================

def test_calculate_severity_critical(reporter):
    """Test severity calculation for critical finding."""
    finding = {
        'severity': 'HIGH',
        'data_exposure': True,
        'auth_bypass': True,
        'financial_loss': True,
        'network_accessible': True
    }

    result = reporter.calculate_severity(finding)

    assert result['severity'] == 'CRITICAL'
    assert result['cvss_score'] >= 9.0
    assert 'CVSS:3.1' in result['cvss_vector']


def test_calculate_severity_high(reporter):
    """Test severity calculation for high finding."""
    finding = {
        'severity': 'MEDIUM',
        'data_exposure': True,
        'network_accessible': True
    }

    result = reporter.calculate_severity(finding)

    assert result['severity'] in ['HIGH', 'MEDIUM']
    assert result['cvss_score'] >= 4.0


def test_calculate_severity_authenticated(reporter):
    """Test authenticated vulnerabilities get lower score."""
    finding_unauth = {
        'severity': 'HIGH',
        'authenticated': False
    }

    finding_auth = {
        'severity': 'HIGH',
        'authenticated': True
    }

    result_unauth = reporter.calculate_severity(finding_unauth)
    result_auth = reporter.calculate_severity(finding_auth)

    assert result_unauth['cvss_score'] > result_auth['cvss_score']


def test_calculate_severity_user_interaction(reporter):
    """Test user interaction reduces severity."""
    finding_no_ui = {
        'severity': 'HIGH',
        'requires_user_interaction': False
    }

    finding_with_ui = {
        'severity': 'HIGH',
        'requires_user_interaction': True
    }

    result_no_ui = reporter.calculate_severity(finding_no_ui)
    result_with_ui = reporter.calculate_severity(finding_with_ui)

    assert result_no_ui['cvss_score'] > result_with_ui['cvss_score']


def test_calculate_severity_caps_at_ten(reporter):
    """Test severity score caps at 10.0."""
    finding = {
        'severity': 'CRITICAL',
        'data_exposure': True,
        'auth_bypass': True,
        'financial_loss': True,
        'network_accessible': True
    }

    result = reporter.calculate_severity(finding)

    assert result['cvss_score'] <= 10.0


# ============================================================================
# PoC Generation Tests
# ============================================================================

def test_generate_poc_http_request(reporter, sample_idor_finding):
    """Test PoC generation with HTTP request."""
    poc = reporter.generate_poc(sample_idor_finding)

    assert 'HTTP Request Example' in poc
    assert '```http' in poc
    assert 'POST /api/orders/12345' in poc


def test_generate_poc_http_response(reporter, sample_idor_finding):
    """Test PoC generation with HTTP response."""
    poc = reporter.generate_poc(sample_idor_finding)

    assert 'Response' in poc
    assert '```json' in poc
    assert 'victim@example.com' in poc


def test_generate_poc_command(reporter, sample_xss_finding):
    """Test PoC generation with command."""
    poc = reporter.generate_poc(sample_xss_finding)

    assert 'Command' in poc
    assert '```bash' in poc
    assert 'curl' in poc


def test_generate_poc_code_example(reporter):
    """Test PoC generation with code example."""
    finding = {
        'title': 'Test',
        'severity': 'LOW',
        'vuln_type': 'Test',
        'description': 'Test',
        'code_example': 'print("hello")',
        'code_language': 'python'
    }

    poc = reporter.generate_poc(finding)

    assert 'Code Example' in poc
    assert '```python' in poc
    assert 'print("hello")' in poc


def test_generate_poc_empty(reporter):
    """Test PoC generation with no data."""
    finding = {
        'title': 'Test',
        'severity': 'LOW',
        'vuln_type': 'Test',
        'description': 'Test'
    }

    poc = reporter.generate_poc(finding)

    assert '*(No PoC available)*' in poc


def test_generate_poc_response_dict(reporter):
    """Test PoC handles dict response."""
    finding = {
        'title': 'Test',
        'severity': 'LOW',
        'vuln_type': 'Test',
        'description': 'Test',
        'http_response': {'success': True, 'data': 'test'}
    }

    poc = reporter.generate_poc(finding)

    assert 'success' in poc
    assert 'true' in poc.lower()


def test_generate_poc_response_string(reporter):
    """Test PoC handles string response."""
    finding = {
        'title': 'Test',
        'severity': 'LOW',
        'vuln_type': 'Test',
        'description': 'Test',
        'http_response': 'HTTP/1.1 200 OK\\n\\n{"data": "test"}'
    }

    poc = reporter.generate_poc(finding)

    assert 'HTTP/1.1 200 OK' in poc


# ============================================================================
# Impact Generation Tests (continued)
# ============================================================================

def test_generate_impact_idor(reporter, sample_idor_finding):
    """Test impact generation for IDOR."""
    impact = reporter.generate_impact(sample_idor_finding, 'example.com')
    assert 'access' in impact.lower()
    assert 'data' in impact.lower()


def test_generate_impact_xss(reporter, sample_xss_finding):
    """Test impact generation for XSS."""
    impact = reporter.generate_impact(sample_xss_finding, 'example.com')
    assert 'JavaScript' in impact or 'script' in impact.lower()


def test_generate_impact_custom(reporter):
    """Test custom impact is used when provided."""
    finding = {'title': 'Test', 'severity': 'HIGH', 'vuln_type': 'IDOR', 'description': 'Test', 'impact': 'Custom impact'}
    impact = reporter.generate_impact(finding, 'test.com')
    assert impact == 'Custom impact'


# ============================================================================
# Batch Report Tests
# ============================================================================

def test_generate_batch_report(reporter, sample_idor_finding, sample_xss_finding):
    """Test batch report generation."""
    findings = [sample_idor_finding, sample_xss_finding]
    report = reporter.generate_batch_report(findings, target='example.com')
    assert 'Vulnerability Report - example.com' in report
    assert 'Findings:** 2' in report
    assert 'IDOR' in report
    assert 'XSS' in report


def test_generate_batch_report_empty(reporter):
    """Test batch report with no findings."""
    report = reporter.generate_batch_report([], target='example.com')
    assert 'No findings' in report


# ============================================================================
# File Operations Tests
# ============================================================================

def test_save_report(reporter, sample_idor_finding):
    """Test saving report to file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / 'reports' / 'finding_001.md'
        report = reporter.generate_report(sample_idor_finding, target='example.com')
        saved_path = reporter.save_report(report, output_path)
        assert saved_path.exists()
        assert saved_path.is_file()


def test_save_report_creates_directories(reporter, sample_idor_finding):
    """Test save_report creates parent directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / 'a' / 'b' / 'c' / 'report.md'
        report = reporter.generate_report(sample_idor_finding, target='example.com')
        saved_path = reporter.save_report(report, output_path)
        assert saved_path.exists()


# ============================================================================
# Integration Tests
# ============================================================================

def test_full_workflow(reporter, sample_graphql_finding):
    """Test complete report generation workflow."""
    report = reporter.generate_report(sample_graphql_finding, target='doordash.com', platform='hackerone')
    assert '# Missing Authorization on GraphQL Mutations' in report
    assert '## Summary' in report
    assert '## Expected vs Actual Behavior' in report
    assert 'GraphQL' in report
    assert 'CWE-862' in report


def test_cvss_vector_generation(reporter, sample_graphql_finding):
    """Test CVSS vector string generation."""
    result = reporter.calculate_severity(sample_graphql_finding)
    vector = result['cvss_vector']
    assert vector.startswith('CVSS:3.1/')
    assert '/AV:' in vector
    assert '/C:' in vector


def test_multiple_platforms(reporter, sample_idor_finding):
    """Test all platform templates."""
    for platform in ['hackerone', 'bugcrowd', 'intigriti']:
        report = reporter.generate_report(sample_idor_finding, target='example.com', platform=platform)
        assert len(report) > 100
        assert sample_idor_finding['title'] in report
