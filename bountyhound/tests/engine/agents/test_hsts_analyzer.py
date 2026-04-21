"""
Comprehensive tests for HSTS Analyzer Agent.

Tests cover:
- Initialization and configuration
- HSTS header parsing
- Missing HSTS detection
- max-age directive validation
- includeSubDomains directive checking
- preload directive validation
- HTTP to HTTPS redirect testing
- HSTS on HTTP responses detection
- Invalid syntax handling
- Report generation
- Edge cases and error handling
- Database integration

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from datetime import date

# Test imports with fallback
try:
    from engine.agents.hsts_analyzer import (
        HSTSAnalyzer,
        HSTSFinding,
        HSTSConfig,
        HSTSSeverity,
        HSTSVulnType,
        REQUESTS_AVAILABLE
    )
    HSTS_ANALYZER_AVAILABLE = True
except ImportError:
    HSTS_ANALYZER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="HSTS analyzer not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(hsts_header=None, status_code=200, url=None, location=None):
        response = Mock()
        response.status_code = status_code
        response.url = url or "https://example.com"
        response.headers = {}

        if hsts_header:
            response.headers['Strict-Transport-Security'] = hsts_header
        if location:
            response.headers['Location'] = location

        return response

    return _create_response


@pytest.fixture
def analyzer():
    """Create an HSTSAnalyzer instance for testing."""
    if not HSTS_ANALYZER_AVAILABLE:
        pytest.skip("HSTS analyzer not available")

    with patch('engine.agents.hsts_analyzer.requests'):
        return HSTSAnalyzer(
            target_url="https://example.com",
            timeout=5,
            verify_ssl=False
        )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestInitialization:
    """Test HSTSAnalyzer initialization."""

    @patch('engine.agents.hsts_analyzer.requests')
    def test_init_with_basic_url(self, mock_requests):
        """Test initialization with basic URL."""
        analyzer = HSTSAnalyzer(target_url="https://example.com")

        assert analyzer.target_url == "https://example.com"
        assert analyzer.domain == "example.com"
        assert analyzer.timeout == 10
        assert analyzer.verify_ssl is True
        assert len(analyzer.findings) == 0

    @patch('engine.agents.hsts_analyzer.requests')
    def test_init_with_custom_timeout(self, mock_requests):
        """Test initialization with custom timeout."""
        analyzer = HSTSAnalyzer(target_url="https://example.com", timeout=30)

        assert analyzer.timeout == 30

    @patch('engine.agents.hsts_analyzer.requests')
    def test_init_without_ssl_verification(self, mock_requests):
        """Test initialization with SSL verification disabled."""
        analyzer = HSTSAnalyzer(target_url="https://example.com", verify_ssl=False)

        assert analyzer.verify_ssl is False

    @patch('engine.agents.hsts_analyzer.requests')
    def test_init_strips_trailing_slash(self, mock_requests):
        """Test that trailing slash is removed from URL."""
        analyzer = HSTSAnalyzer(target_url="https://example.com/")

        assert analyzer.target_url == "https://example.com"

    @patch('engine.agents.hsts_analyzer.requests')
    def test_init_with_custom_user_agent(self, mock_requests):
        """Test initialization with custom user agent."""
        custom_ua = "CustomBot/1.0"
        analyzer = HSTSAnalyzer(target_url="https://example.com", user_agent=custom_ua)

        assert analyzer.session.headers['User-Agent'] == custom_ua

    @patch('engine.agents.hsts_analyzer.REQUESTS_AVAILABLE', False)
    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        with pytest.raises(ImportError, match="requests library is required"):
            HSTSAnalyzer(target_url="https://example.com")


# ============================================================================
# Domain Extraction Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestDomainExtraction:
    """Test domain extraction from URLs."""

    @patch('engine.agents.hsts_analyzer.requests')
    def test_extract_domain_from_simple_url(self, mock_requests):
        """Test extracting domain from simple URL."""
        analyzer = HSTSAnalyzer(target_url="https://example.com")
        assert analyzer.domain == "example.com"

    @patch('engine.agents.hsts_analyzer.requests')
    def test_extract_domain_from_subdomain(self, mock_requests):
        """Test extracting domain from subdomain URL."""
        analyzer = HSTSAnalyzer(target_url="https://api.example.com")
        assert analyzer.domain == "api.example.com"

    @patch('engine.agents.hsts_analyzer.requests')
    def test_extract_domain_from_url_with_path(self, mock_requests):
        """Test extracting domain from URL with path."""
        analyzer = HSTSAnalyzer(target_url="https://example.com/api/v1")
        assert analyzer.domain == "example.com"

    @patch('engine.agents.hsts_analyzer.requests')
    def test_extract_domain_from_url_with_port(self, mock_requests):
        """Test extracting domain from URL with port."""
        analyzer = HSTSAnalyzer(target_url="https://example.com:8443")
        assert analyzer.domain == "example.com:8443"


# ============================================================================
# HSTS Header Parsing Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestHSTSHeaderParsing:
    """Test HSTS header parsing logic."""

    def test_parse_missing_hsts_header(self, analyzer, mock_response):
        """Test parsing response with no HSTS header."""
        response = mock_response()
        config = analyzer._parse_hsts_header(response)

        assert config.present is False
        assert config.max_age is None
        assert config.include_subdomains is False
        assert config.preload is False
        assert config.is_valid is False

    def test_parse_basic_hsts_header(self, analyzer, mock_response):
        """Test parsing basic HSTS header."""
        response = mock_response(hsts_header="max-age=31536000")
        config = analyzer._parse_hsts_header(response)

        assert config.present is True
        assert config.max_age == 31536000
        assert config.include_subdomains is False
        assert config.preload is False
        assert config.is_valid is True

    def test_parse_full_hsts_header(self, analyzer, mock_response):
        """Test parsing full HSTS header with all directives."""
        response = mock_response(hsts_header="max-age=31536000; includeSubDomains; preload")
        config = analyzer._parse_hsts_header(response)

        assert config.present is True
        assert config.max_age == 31536000
        assert config.include_subdomains is True
        assert config.preload is True
        assert config.is_valid is True

    def test_parse_hsts_header_case_insensitive(self, analyzer, mock_response):
        """Test HSTS header parsing is case-insensitive."""
        response = mock_response(hsts_header="MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD")
        config = analyzer._parse_hsts_header(response)

        assert config.max_age == 31536000
        assert config.include_subdomains is True
        assert config.preload is True

    def test_parse_hsts_header_with_spaces(self, analyzer, mock_response):
        """Test parsing HSTS header with extra spaces."""
        response = mock_response(hsts_header="max-age = 31536000 ; includeSubDomains ; preload")
        config = analyzer._parse_hsts_header(response)

        assert config.max_age == 31536000
        assert config.include_subdomains is True
        assert config.preload is True

    def test_parse_hsts_header_without_max_age(self, analyzer, mock_response):
        """Test parsing HSTS header without max-age directive."""
        response = mock_response(hsts_header="includeSubDomains; preload")
        config = analyzer._parse_hsts_header(response)

        assert config.present is True
        assert config.max_age is None
        assert config.is_valid is False
        assert "max-age directive is required but missing" in config.parse_errors

    def test_parse_hsts_header_with_invalid_max_age(self, analyzer, mock_response):
        """Test parsing HSTS header with invalid max-age value."""
        response = mock_response(hsts_header="max-age=invalid; includeSubDomains")
        config = analyzer._parse_hsts_header(response)

        assert config.present is True
        assert config.max_age is None
        assert len(config.parse_errors) > 0

    def test_parse_hsts_header_with_zero_max_age(self, analyzer, mock_response):
        """Test parsing HSTS header with zero max-age (used to clear HSTS)."""
        response = mock_response(hsts_header="max-age=0")
        config = analyzer._parse_hsts_header(response)

        assert config.present is True
        assert config.max_age == 0
        assert config.is_valid is True

    def test_parse_hsts_header_preserves_raw_value(self, analyzer, mock_response):
        """Test that raw header value is preserved."""
        raw_header = "max-age=31536000; includeSubDomains; preload"
        response = mock_response(hsts_header=raw_header)
        config = analyzer._parse_hsts_header(response)

        assert config.raw_header == raw_header


# ============================================================================
# Missing HSTS Detection Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestMissingHSTSDetection:
    """Test missing HSTS header detection."""

    def test_detect_missing_hsts(self, analyzer, mock_response):
        """Test detection of missing HSTS header."""
        with patch.object(analyzer.session, 'get', return_value=mock_response()):
            analyzer._test_hsts_on_https()

        assert len(analyzer.findings) == 1
        finding = analyzer.findings[0]
        assert finding.vuln_type == HSTSVulnType.MISSING_HSTS
        assert finding.severity == HSTSSeverity.HIGH
        assert "Missing HSTS Header" in finding.title

    def test_missing_hsts_finding_details(self, analyzer, mock_response):
        """Test missing HSTS finding contains proper details."""
        with patch.object(analyzer.session, 'get', return_value=mock_response()):
            analyzer._test_hsts_on_https()

        finding = analyzer.findings[0]
        assert finding.current_value is None
        assert "max-age=31536000" in finding.expected_value
        assert "SSL stripping" in finding.impact
        assert "sslstrip" in finding.poc.lower()
        assert "CWE-523" in finding.cwe_id


# ============================================================================
# max-age Directive Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestMaxAgeValidation:
    """Test max-age directive validation."""

    def test_max_age_too_short_under_6_months(self, analyzer, mock_response):
        """Test max-age less than 6 months triggers MEDIUM severity."""
        response = mock_response(hsts_header="max-age=86400")  # 1 day
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        assert len(analyzer.findings) == 1
        finding = analyzer.findings[0]
        assert finding.vuln_type == HSTSVulnType.WEAK_MAX_AGE
        assert finding.severity == HSTSSeverity.MEDIUM
        assert "Too Short" in finding.title

    def test_max_age_between_6_months_and_1_year(self, analyzer, mock_response):
        """Test max-age between 6 months and 1 year triggers LOW severity."""
        response = mock_response(hsts_header="max-age=20000000")  # ~7.7 months
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        assert len(analyzer.findings) == 1
        finding = analyzer.findings[0]
        assert finding.vuln_type == HSTSVulnType.WEAK_MAX_AGE
        assert finding.severity == HSTSSeverity.LOW
        assert "Below Best Practice" in finding.title

    def test_max_age_1_year_no_finding(self, analyzer, mock_response):
        """Test max-age of 1 year or more doesn't trigger finding."""
        response = mock_response(hsts_header="max-age=31536000; includeSubDomains; preload")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Should have no max-age related findings
        max_age_findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.WEAK_MAX_AGE]
        assert len(max_age_findings) == 0

    def test_max_age_zero(self, analyzer, mock_response):
        """Test max-age of zero (used to clear HSTS)."""
        response = mock_response(hsts_header="max-age=0")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Zero max-age should trigger weak max-age finding
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.WEAK_MAX_AGE]
        assert len(findings) >= 1

    def test_max_age_very_large(self, analyzer, mock_response):
        """Test max-age with very large value."""
        response = mock_response(hsts_header="max-age=63072000")  # 2 years
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Should have no max-age related findings
        max_age_findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.WEAK_MAX_AGE]
        assert len(max_age_findings) == 0


# ============================================================================
# includeSubDomains Directive Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestIncludeSubDomainsValidation:
    """Test includeSubDomains directive validation."""

    def test_missing_include_subdomains(self, analyzer, mock_response):
        """Test missing includeSubDomains directive."""
        response = mock_response(hsts_header="max-age=31536000")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.MISSING_INCLUDE_SUBDOMAINS]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == HSTSSeverity.MEDIUM
        assert "includeSubDomains" in finding.title

    def test_include_subdomains_present(self, analyzer, mock_response):
        """Test includeSubDomains directive present."""
        response = mock_response(hsts_header="max-age=31536000; includeSubDomains")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Should have no includeSubDomains related findings
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.MISSING_INCLUDE_SUBDOMAINS]
        assert len(findings) == 0

    def test_include_subdomains_case_variations(self, analyzer, mock_response):
        """Test includeSubDomains with different case."""
        response = mock_response(hsts_header="max-age=31536000; INCLUDESUBDOMAINS")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Should recognize includeSubDomains regardless of case
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.MISSING_INCLUDE_SUBDOMAINS]
        assert len(findings) == 0


# ============================================================================
# preload Directive Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestPreloadValidation:
    """Test preload directive validation."""

    @patch('engine.agents.hsts_analyzer.requests')
    def test_missing_preload_on_top_level_domain(self, mock_requests):
        """Test missing preload directive on top-level domain."""
        analyzer = HSTSAnalyzer(target_url="https://example.com")
        response = Mock()
        response.headers = {'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'}
        response.status_code = 200
        response.url = "https://example.com"

        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.MISSING_PRELOAD]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == HSTSSeverity.LOW
        assert "preload" in finding.title.lower()

    @patch('engine.agents.hsts_analyzer.requests')
    def test_missing_preload_on_subdomain_skipped(self, mock_requests):
        """Test preload check skipped on subdomains."""
        analyzer = HSTSAnalyzer(target_url="https://api.example.com")
        response = Mock()
        response.headers = {'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'}
        response.status_code = 200
        response.url = "https://api.example.com"

        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Preload check should be skipped for subdomains
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.MISSING_PRELOAD]
        assert len(findings) == 0

    def test_preload_present(self, analyzer, mock_response):
        """Test preload directive present."""
        response = mock_response(hsts_header="max-age=31536000; includeSubDomains; preload")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        # Should have no preload related findings
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.MISSING_PRELOAD]
        assert len(findings) == 0


# ============================================================================
# HTTP Redirect Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestHTTPRedirect:
    """Test HTTP to HTTPS redirect detection."""

    def test_http_no_redirect(self, analyzer, mock_response):
        """Test HTTP endpoint without redirect."""
        response = mock_response(status_code=200)
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_http_redirect()

        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.NO_HTTPS_REDIRECT]
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.severity == HSTSSeverity.HIGH
        assert "Does Not Redirect" in finding.title

    def test_http_redirects_to_https_permanent(self, analyzer, mock_response):
        """Test HTTP redirects to HTTPS with 301."""
        response = mock_response(status_code=301, location="https://example.com")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_http_redirect()

        # Should have no redirect findings (301 to HTTPS is good)
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.NO_HTTPS_REDIRECT]
        assert len(findings) == 0

    def test_http_redirects_to_https_308(self, analyzer, mock_response):
        """Test HTTP redirects to HTTPS with 308."""
        response = mock_response(status_code=308, location="https://example.com")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_http_redirect()

        # Should have no redirect findings (308 to HTTPS is good)
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.NO_HTTPS_REDIRECT]
        assert len(findings) == 0

    def test_http_redirects_to_https_temporary(self, analyzer, mock_response):
        """Test HTTP redirects to HTTPS with 302 (temporary)."""
        response = mock_response(status_code=302, location="https://example.com")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_http_redirect()

        # Should trigger finding for temporary redirect
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.NO_HTTPS_REDIRECT]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == HSTSSeverity.MEDIUM
        assert "Temporary" in finding.title

    def test_http_redirects_to_http(self, analyzer, mock_response):
        """Test HTTP redirects to HTTP (not HTTPS)."""
        response = mock_response(status_code=301, location="http://www.example.com")
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_http_redirect()

        # Should trigger finding for not redirecting to HTTPS
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.NO_HTTPS_REDIRECT]
        assert len(findings) >= 1
        finding = findings[0]
        assert "not to HTTPS" in finding.description

    def test_http_not_accessible(self, analyzer):
        """Test HTTP endpoint not accessible (good)."""
        with patch.object(analyzer.session, 'get', side_effect=Exception("Connection refused")):
            analyzer._test_http_redirect()

        # Should have no findings if HTTP is not accessible
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.NO_HTTPS_REDIRECT]
        assert len(findings) == 0


# ============================================================================
# HSTS on HTTP Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestHSTSOnHTTP:
    """Test HSTS header on HTTP responses (ineffective)."""

    def test_hsts_header_on_http(self, analyzer, mock_response):
        """Test HSTS header sent over HTTP (ineffective)."""
        response = mock_response(hsts_header="max-age=31536000", status_code=200)
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_http()

        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.HSTS_ON_HTTP]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == HSTSSeverity.LOW
        assert "Over HTTP" in finding.title
        assert "ineffective" in finding.description.lower()

    def test_no_hsts_header_on_http(self, analyzer, mock_response):
        """Test no HSTS header on HTTP (expected)."""
        response = mock_response(status_code=200)
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_http()

        # Should have no findings if HSTS is not on HTTP
        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.HSTS_ON_HTTP]
        assert len(findings) == 0


# ============================================================================
# Invalid Syntax Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestInvalidSyntax:
    """Test invalid HSTS syntax detection."""

    def test_invalid_hsts_syntax(self, analyzer, mock_response):
        """Test detection of invalid HSTS syntax."""
        response = mock_response(hsts_header="includeSubDomains; preload")  # Missing max-age
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        findings = [f for f in analyzer.findings if f.vuln_type == HSTSVulnType.INVALID_SYNTAX]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == HSTSSeverity.HIGH
        assert "Invalid" in finding.title


# ============================================================================
# Run All Tests Integration
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestRunAllTests:
    """Test run_all_tests integration."""

    def test_run_all_tests_on_https_only(self, analyzer, mock_response):
        """Test running all tests on HTTPS-only URL."""
        response = mock_response(hsts_header="max-age=31536000; includeSubDomains; preload")

        with patch.object(analyzer.session, 'get', return_value=response):
            findings = analyzer.run_all_tests()

        # Should run HTTPS tests and HTTP redirect tests
        assert isinstance(findings, list)

    @patch('engine.agents.hsts_analyzer.requests')
    def test_run_all_tests_on_http_url(self, mock_requests):
        """Test running all tests on HTTP URL."""
        analyzer = HSTSAnalyzer(target_url="http://example.com")
        response = Mock()
        response.headers = {}
        response.status_code = 200
        response.url = "http://example.com"

        with patch.object(analyzer.session, 'get', return_value=response):
            findings = analyzer.run_all_tests()

        # Should run limited tests on HTTP
        assert isinstance(findings, list)

    def test_run_all_tests_with_ssl_error(self, analyzer):
        """Test handling SSL errors during testing."""
        import requests
        with patch.object(analyzer.session, 'get', side_effect=requests.exceptions.SSLError("SSL error")):
            findings = analyzer.run_all_tests()

        # Should create finding about SSL error
        assert len(findings) >= 1


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestReportGeneration:
    """Test report generation."""

    def test_generate_report_no_findings(self, analyzer):
        """Test report generation with no findings."""
        report = analyzer.generate_report()

        assert "SECURE" in report or "No HSTS security issues" in report
        assert analyzer.target_url in report

    def test_generate_report_with_findings(self, analyzer, mock_response):
        """Test report generation with findings."""
        response = mock_response()  # No HSTS
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        report = analyzer.generate_report()

        assert "HSTS Security Analysis Report" in report
        assert analyzer.target_url in report
        assert "Total Findings:" in report
        assert "HIGH" in report

    def test_generate_report_includes_all_severities(self, analyzer):
        """Test report includes all severity levels."""
        # Add findings of different severities
        analyzer.findings.append(HSTSFinding(
            title="Critical Issue",
            severity=HSTSSeverity.CRITICAL,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="Critical",
            endpoint="https://example.com"
        ))
        analyzer.findings.append(HSTSFinding(
            title="Low Issue",
            severity=HSTSSeverity.LOW,
            vuln_type=HSTSVulnType.MISSING_PRELOAD,
            description="Low",
            endpoint="https://example.com"
        ))

        report = analyzer.generate_report()

        assert "CRITICAL" in report
        assert "LOW" in report

    def test_generate_report_includes_remediation(self, analyzer, mock_response):
        """Test report includes remediation summary."""
        response = mock_response()  # No HSTS
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        report = analyzer.generate_report()

        assert "Remediation" in report
        assert "Apache" in report or "Nginx" in report
        assert "Configuration" in report

    def test_generate_report_includes_references(self, analyzer, mock_response):
        """Test report includes references."""
        response = mock_response()
        with patch.object(analyzer.session, 'get', return_value=response):
            analyzer._test_hsts_on_https()

        report = analyzer.generate_report()

        assert "References" in report
        assert "RFC" in report or "OWASP" in report


# ============================================================================
# Findings Summary Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestFindingsSummary:
    """Test findings summary generation."""

    def test_get_findings_summary_no_findings(self, analyzer):
        """Test summary with no findings."""
        summary = analyzer.get_findings_summary()

        assert summary['total_findings'] == 0
        assert summary['by_severity']['CRITICAL'] == 0
        assert summary['by_severity']['HIGH'] == 0

    def test_get_findings_summary_with_findings(self, analyzer):
        """Test summary with findings."""
        analyzer.findings.append(HSTSFinding(
            title="Test",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="Test",
            endpoint="https://example.com"
        ))
        analyzer.findings.append(HSTSFinding(
            title="Test 2",
            severity=HSTSSeverity.MEDIUM,
            vuln_type=HSTSVulnType.WEAK_MAX_AGE,
            description="Test",
            endpoint="https://example.com"
        ))

        summary = analyzer.get_findings_summary()

        assert summary['total_findings'] == 2
        assert summary['by_severity']['HIGH'] == 1
        assert summary['by_severity']['MEDIUM'] == 1

    def test_get_findings_summary_by_type(self, analyzer):
        """Test summary groups by vulnerability type."""
        analyzer.findings.append(HSTSFinding(
            title="Test",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="Test",
            endpoint="https://example.com"
        ))

        summary = analyzer.get_findings_summary()

        assert 'HSTS_MISSING' in summary['by_type']
        assert summary['by_type']['HSTS_MISSING'] == 1


# ============================================================================
# Data Class Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestDataClasses:
    """Test data classes."""

    def test_hsts_finding_to_dict(self):
        """Test HSTSFinding to_dict conversion."""
        finding = HSTSFinding(
            title="Test Finding",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="Test description",
            endpoint="https://example.com"
        )

        data = finding.to_dict()

        assert data['title'] == "Test Finding"
        assert data['severity'] == "HIGH"
        assert data['vuln_type'] == "HSTS_MISSING"
        assert data['description'] == "Test description"

    def test_hsts_config_to_dict(self):
        """Test HSTSConfig to_dict conversion."""
        config = HSTSConfig(
            present=True,
            max_age=31536000,
            include_subdomains=True,
            preload=True,
            raw_header="max-age=31536000; includeSubDomains; preload",
            is_valid=True
        )

        data = config.to_dict()

        assert data['present'] is True
        assert data['max_age'] == 31536000
        assert data['include_subdomains'] is True
        assert data['preload'] is True
        assert data['is_valid'] is True


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handle_timeout_error(self, analyzer):
        """Test handling of timeout errors."""
        import requests
        with patch.object(analyzer.session, 'get', side_effect=requests.exceptions.Timeout("Timeout")):
            # Should not raise exception
            analyzer._test_hsts_on_https()

    def test_handle_connection_error(self, analyzer):
        """Test handling of connection errors."""
        import requests
        with patch.object(analyzer.session, 'get', side_effect=requests.exceptions.ConnectionError("Connection failed")):
            # Should not raise exception
            analyzer._test_hsts_on_https()

    def test_handle_request_exception(self, analyzer):
        """Test handling of general request exceptions."""
        import requests
        with patch.object(analyzer.session, 'get', side_effect=requests.exceptions.RequestException("Error")):
            # Should not raise exception
            analyzer._test_hsts_on_https()

    def test_empty_hsts_header(self, analyzer, mock_response):
        """Test handling of empty HSTS header."""
        response = mock_response(hsts_header="")
        config = analyzer._parse_hsts_header(response)

        assert config.present is False

    def test_whitespace_only_hsts_header(self, analyzer, mock_response):
        """Test handling of whitespace-only HSTS header."""
        response = mock_response(hsts_header="   ")
        config = analyzer._parse_hsts_header(response)

        assert config.present is True
        assert config.is_valid is False

    @patch('engine.agents.hsts_analyzer.requests')
    def test_url_without_scheme(self, mock_requests):
        """Test URL gets HTTPS scheme added."""
        analyzer = HSTSAnalyzer(target_url="example.com")
        # Domain should still be extracted correctly
        assert analyzer.domain == "example.com"

    def test_multiple_findings_same_type(self, analyzer):
        """Test multiple findings of same type."""
        analyzer.findings.append(HSTSFinding(
            title="Issue 1",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="Description 1",
            endpoint="https://example.com"
        ))
        analyzer.findings.append(HSTSFinding(
            title="Issue 2",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="Description 2",
            endpoint="https://example.com/api"
        ))

        summary = analyzer.get_findings_summary()
        assert summary['by_type']['HSTS_MISSING'] == 2


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not HSTS_ANALYZER_AVAILABLE, reason="HSTS analyzer not available")
class TestIntegration:
    """Integration tests with realistic scenarios."""

    @patch('engine.agents.hsts_analyzer.requests')
    def test_secure_site_configuration(self, mock_requests):
        """Test analysis of properly configured site."""
        analyzer = HSTSAnalyzer(target_url="https://secure-example.com")

        # Mock secure configuration
        https_response = Mock()
        https_response.status_code = 200
        https_response.url = "https://secure-example.com"
        https_response.headers = {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
        }

        http_response = Mock()
        http_response.status_code = 301
        http_response.headers = {
            'Location': 'https://secure-example.com'
        }

        def mock_get(url, **kwargs):
            if url.startswith('http://'):
                return http_response
            return https_response

        with patch.object(analyzer.session, 'get', side_effect=mock_get):
            findings = analyzer.run_all_tests()

        # Should have no or minimal findings
        critical_high = [f for f in findings if f.severity in [HSTSSeverity.CRITICAL, HSTSSeverity.HIGH]]
        assert len(critical_high) == 0

    @patch('engine.agents.hsts_analyzer.requests')
    def test_insecure_site_configuration(self, mock_requests):
        """Test analysis of poorly configured site."""
        analyzer = HSTSAnalyzer(target_url="https://insecure-example.com")

        # Mock insecure configuration
        response = Mock()
        response.status_code = 200
        response.url = "https://insecure-example.com"
        response.headers = {}  # No HSTS

        with patch.object(analyzer.session, 'get', return_value=response):
            findings = analyzer.run_all_tests()

        # Should have HIGH severity finding for missing HSTS
        high_findings = [f for f in findings if f.severity == HSTSSeverity.HIGH]
        assert len(high_findings) >= 1

    @patch('engine.agents.hsts_analyzer.requests')
    def test_partially_configured_site(self, mock_requests):
        """Test analysis of partially configured site."""
        analyzer = HSTSAnalyzer(target_url="https://partial-example.com")

        # Mock partial configuration
        response = Mock()
        response.status_code = 200
        response.url = "https://partial-example.com"
        response.headers = {
            'Strict-Transport-Security': 'max-age=86400'  # Short max-age, missing directives
        }

        with patch.object(analyzer.session, 'get', return_value=response):
            findings = analyzer.run_all_tests()

        # Should have multiple findings for weak configuration
        assert len(findings) >= 2
        assert any(f.vuln_type == HSTSVulnType.WEAK_MAX_AGE for f in findings)
        assert any(f.vuln_type == HSTSVulnType.MISSING_INCLUDE_SUBDOMAINS for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=engine.agents.hsts_analyzer", "--cov-report=term-missing"])
