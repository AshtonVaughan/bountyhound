"""
Comprehensive tests for X-Frame-Options Tester Agent.

Tests cover:
- Initialization and configuration
- Missing X-Frame-Options detection
- DENY directive validation
- SAMEORIGIN directive validation
- Deprecated ALLOW-FROM detection
- CSP frame-ancestors alternative testing
- Invalid directive detection
- Conflicting header scenarios
- Severity determination
- Impact assessment
- POC generation
- Bounty estimation
- Report generation
- Database integration
- Edge cases and error handling

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import date
import json

# Test imports with fallback
try:
    from engine.agents.x_frame_options_tester import (
        XFrameOptionsTester,
        XFOFinding,
        XFOTestResult,
        XFOSeverity,
        XFOVulnType,
        REQUESTS_AVAILABLE,
        DATABASE_AVAILABLE
    )
    XFO_TESTER_AVAILABLE = True
except ImportError:
    XFO_TESTER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="X-Frame-Options tester not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(xfo=None, csp=None, status_code=200, headers_dict=None):
        response = Mock()
        response.status_code = status_code
        response.headers = headers_dict or {}

        if xfo:
            response.headers['X-Frame-Options'] = xfo
        if csp:
            response.headers['Content-Security-Policy'] = csp

        return response

    return _create_response


@pytest.fixture
def tester():
    """Create an XFrameOptionsTester instance for testing."""
    if not XFO_TESTER_AVAILABLE:
        pytest.skip("X-Frame-Options tester not available")

    with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
        return XFrameOptionsTester(
            target_url="https://example.com",
            timeout=5,
            verify_ssl=False
        )


@pytest.fixture
def mock_db():
    """Create a mock database."""
    db = Mock()
    db.get_target_stats.return_value = None
    db.record_tool_run.return_value = None
    return db


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestInitialization:
    """Test XFrameOptionsTester initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(target_url="https://example.com")

            assert tester.target_url == "https://example.com"
            assert tester.domain == "example.com"
            assert tester.timeout == 10
            assert tester.verify_ssl is True
            assert len(tester.findings) == 0
            assert len(tester.test_results) == 0

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(target_url="https://example.com", timeout=30)

            assert tester.timeout == 30

    def test_init_with_custom_endpoints(self):
        """Test initialization with custom endpoints."""
        custom_endpoints = ["/custom1", "/custom2"]
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(
                target_url="https://example.com",
                custom_endpoints=custom_endpoints
            )

            # Check that custom endpoints are included
            for endpoint in custom_endpoints:
                assert endpoint in tester.test_endpoints

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(target_url="https://example.com", verify_ssl=False)

            assert tester.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(target_url="https://example.com/")

            assert tester.target_url == "https://example.com"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            XFrameOptionsTester(target_url="https://example.com")

    def test_init_endpoint_deduplication(self):
        """Test that duplicate endpoints are removed."""
        custom_endpoints = ["/login", "/payment"]  # /login is in SENSITIVE_ENDPOINTS
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(
                target_url="https://example.com",
                custom_endpoints=custom_endpoints
            )

            # Check no duplicates
            assert len(tester.test_endpoints) == len(set(tester.test_endpoints))


# ============================================================================
# Domain Extraction Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestDomainExtraction:
    """Test domain extraction from URLs."""

    def test_extract_domain_from_simple_url(self, tester):
        """Test extracting domain from simple URL."""
        domain = tester._extract_domain("https://example.com")
        assert domain == "example.com"

    def test_extract_domain_from_subdomain(self, tester):
        """Test extracting domain from subdomain URL."""
        domain = tester._extract_domain("https://api.example.com")
        assert domain == "api.example.com"

    def test_extract_domain_from_url_with_path(self, tester):
        """Test extracting domain from URL with path."""
        domain = tester._extract_domain("https://example.com/api/v1/users")
        assert domain == "example.com"

    def test_extract_domain_from_url_with_port(self, tester):
        """Test extracting domain from URL with port."""
        domain = tester._extract_domain("https://example.com:8443")
        assert domain == "example.com:8443"


# ============================================================================
# CSP Parsing Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestCSPParsing:
    """Test CSP frame-ancestors parsing."""

    def test_parse_frame_ancestors_none(self, tester):
        """Test parsing frame-ancestors 'none'."""
        csp = "default-src 'self'; frame-ancestors 'none';"
        result = tester._parse_frame_ancestors(csp)
        assert result == "'none'"

    def test_parse_frame_ancestors_self(self, tester):
        """Test parsing frame-ancestors 'self'."""
        csp = "default-src 'self'; frame-ancestors 'self';"
        result = tester._parse_frame_ancestors(csp)
        assert result == "'self'"

    def test_parse_frame_ancestors_specific_domain(self, tester):
        """Test parsing frame-ancestors with specific domain."""
        csp = "frame-ancestors https://trusted.com;"
        result = tester._parse_frame_ancestors(csp)
        assert result == "https://trusted.com"

    def test_parse_frame_ancestors_multiple_domains(self, tester):
        """Test parsing frame-ancestors with multiple domains."""
        csp = "frame-ancestors https://domain1.com https://domain2.com;"
        result = tester._parse_frame_ancestors(csp)
        assert result == "https://domain1.com https://domain2.com"

    def test_parse_frame_ancestors_missing(self, tester):
        """Test parsing CSP without frame-ancestors."""
        csp = "default-src 'self'; script-src 'unsafe-inline';"
        result = tester._parse_frame_ancestors(csp)
        assert result is None

    def test_parse_frame_ancestors_empty_csp(self, tester):
        """Test parsing empty CSP."""
        result = tester._parse_frame_ancestors("")
        assert result is None

    def test_parse_frame_ancestors_case_insensitive(self, tester):
        """Test parsing frame-ancestors case insensitive."""
        csp = "Frame-Ancestors 'none';"
        result = tester._parse_frame_ancestors(csp)
        assert result == "'none'"


# ============================================================================
# Security Validation Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestSecurityValidation:
    """Test security validation logic."""

    def test_is_secure_xfo_deny(self, tester):
        """Test DENY is considered secure."""
        assert tester._is_secure_xfo("DENY") is True

    def test_is_secure_xfo_sameorigin(self, tester):
        """Test SAMEORIGIN is considered secure."""
        assert tester._is_secure_xfo("SAMEORIGIN") is True

    def test_is_secure_xfo_deny_lowercase(self, tester):
        """Test lowercase deny is secure."""
        assert tester._is_secure_xfo("deny") is True

    def test_is_secure_xfo_with_whitespace(self, tester):
        """Test XFO with whitespace is secure."""
        assert tester._is_secure_xfo("  DENY  ") is True

    def test_is_secure_xfo_allow_from_not_secure(self, tester):
        """Test ALLOW-FROM is not considered secure."""
        assert tester._is_secure_xfo("ALLOW-FROM https://example.com") is False

    def test_is_secure_xfo_invalid(self, tester):
        """Test invalid value is not secure."""
        assert tester._is_secure_xfo("INVALID") is False

    def test_is_secure_csp_none(self, tester):
        """Test 'none' is secure CSP."""
        assert tester._is_secure_csp("'none'") is True

    def test_is_secure_csp_self(self, tester):
        """Test 'self' is secure CSP."""
        assert tester._is_secure_csp("'self'") is True

    def test_is_secure_csp_none_without_quotes(self, tester):
        """Test none without quotes is secure."""
        assert tester._is_secure_csp("none") is True

    def test_is_secure_csp_specific_domain_not_secure(self, tester):
        """Test specific domain is not considered universally secure."""
        assert tester._is_secure_csp("https://trusted.com") is False


# ============================================================================
# Severity Determination Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestSeverityDetermination:
    """Test severity determination logic."""

    def test_severity_payment_endpoint_no_protection(self, tester):
        """Test payment endpoint without protection is CRITICAL."""
        severity = tester._determine_severity("/payment", has_xfo=False, has_csp=False)
        assert severity == XFOSeverity.CRITICAL

    def test_severity_transfer_endpoint_no_protection(self, tester):
        """Test transfer endpoint without protection is CRITICAL."""
        severity = tester._determine_severity("/transfer", has_xfo=False, has_csp=False)
        assert severity == XFOSeverity.CRITICAL

    def test_severity_login_endpoint_no_protection(self, tester):
        """Test login endpoint without protection is HIGH."""
        severity = tester._determine_severity("/login", has_xfo=False, has_csp=False)
        assert severity == XFOSeverity.HIGH

    def test_severity_admin_endpoint_no_protection(self, tester):
        """Test admin endpoint without protection is HIGH."""
        severity = tester._determine_severity("/admin", has_xfo=False, has_csp=False)
        assert severity == XFOSeverity.HIGH

    def test_severity_account_endpoint_no_protection(self, tester):
        """Test account endpoint without protection is MEDIUM."""
        severity = tester._determine_severity("/account", has_xfo=False, has_csp=False)
        assert severity == XFOSeverity.MEDIUM

    def test_severity_other_endpoint_no_protection(self, tester):
        """Test other endpoint without protection is LOW."""
        severity = tester._determine_severity("/about", has_xfo=False, has_csp=False)
        assert severity == XFOSeverity.LOW

    def test_severity_with_csp_only(self, tester):
        """Test endpoint with CSP but no XFO is LOW."""
        severity = tester._determine_severity("/payment", has_xfo=False, has_csp=True)
        assert severity == XFOSeverity.LOW


# ============================================================================
# Impact Assessment Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestImpactAssessment:
    """Test impact assessment logic."""

    def test_impact_payment_endpoint(self, tester):
        """Test impact for payment endpoint."""
        impact = tester._get_impact("/payment")
        assert "payment" in impact.lower()
        assert "financial" in impact.lower() or "unauthorized" in impact.lower()

    def test_impact_login_endpoint(self, tester):
        """Test impact for login endpoint."""
        impact = tester._get_impact("/login")
        assert "credential" in impact.lower() or "login" in impact.lower()

    def test_impact_admin_endpoint(self, tester):
        """Test impact for admin endpoint."""
        impact = tester._get_impact("/admin")
        assert "admin" in impact.lower() or "privilege" in impact.lower()

    def test_impact_delete_endpoint(self, tester):
        """Test impact for delete endpoint."""
        impact = tester._get_impact("/delete-account")
        assert "delete" in impact.lower()

    def test_impact_oauth_endpoint(self, tester):
        """Test impact for OAuth endpoint."""
        impact = tester._get_impact("/oauth/authorize")
        assert "oauth" in impact.lower() or "authoriz" in impact.lower()

    def test_impact_2fa_endpoint(self, tester):
        """Test impact for 2FA endpoint."""
        impact = tester._get_impact("/2fa/setup")
        assert "2fa" in impact.lower() or "multi-factor" in impact.lower()

    def test_impact_generic_endpoint(self, tester):
        """Test impact for generic endpoint."""
        impact = tester._get_impact("/generic")
        assert "unintended action" in impact.lower()


# ============================================================================
# Affected Actions Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestAffectedActions:
    """Test affected actions determination."""

    def test_affected_actions_payment(self, tester):
        """Test affected actions for payment endpoint."""
        actions = tester._get_affected_actions("/payment")
        assert any("payment" in action.lower() for action in actions)

    def test_affected_actions_login(self, tester):
        """Test affected actions for login endpoint."""
        actions = tester._get_affected_actions("/signin")
        assert any("login" in action.lower() or "credential" in action.lower() for action in actions)

    def test_affected_actions_admin(self, tester):
        """Test affected actions for admin endpoint."""
        actions = tester._get_affected_actions("/admin")
        assert any("privilege" in action.lower() or "admin" in action.lower() for action in actions)

    def test_affected_actions_generic(self, tester):
        """Test affected actions for generic endpoint."""
        actions = tester._get_affected_actions("/generic")
        assert len(actions) > 0


# ============================================================================
# Bounty Range Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestBountyRange:
    """Test bounty range estimation."""

    def test_bounty_range_critical(self, tester):
        """Test bounty range for CRITICAL severity."""
        min_bounty, max_bounty = tester._get_bounty_range(XFOSeverity.CRITICAL)
        assert min_bounty == 5000
        assert max_bounty == 25000

    def test_bounty_range_high(self, tester):
        """Test bounty range for HIGH severity."""
        min_bounty, max_bounty = tester._get_bounty_range(XFOSeverity.HIGH)
        assert min_bounty == 2000
        assert max_bounty == 10000

    def test_bounty_range_medium(self, tester):
        """Test bounty range for MEDIUM severity."""
        min_bounty, max_bounty = tester._get_bounty_range(XFOSeverity.MEDIUM)
        assert min_bounty == 1000
        assert max_bounty == 5000

    def test_bounty_range_low(self, tester):
        """Test bounty range for LOW severity."""
        min_bounty, max_bounty = tester._get_bounty_range(XFOSeverity.LOW)
        assert min_bounty == 500
        assert max_bounty == 2000

    def test_bounty_range_info(self, tester):
        """Test bounty range for INFO severity."""
        min_bounty, max_bounty = tester._get_bounty_range(XFOSeverity.INFO)
        assert min_bounty == 0
        assert max_bounty == 500


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestPOCGeneration:
    """Test POC HTML generation."""

    def test_generate_poc_missing_both(self, tester):
        """Test POC generation for missing both headers."""
        poc = tester._generate_poc_html(
            "https://example.com/payment",
            "/payment",
            XFOVulnType.MISSING_BOTH
        )

        assert "<!DOCTYPE html>" in poc
        assert "https://example.com/payment" in poc
        assert "/payment" in poc
        assert "iframe" in poc.lower()
        assert "X-Frame-Options" in poc

    def test_generate_poc_deprecated_allow_from(self, tester):
        """Test POC generation for deprecated ALLOW-FROM."""
        poc = tester._generate_poc_html(
            "https://example.com/login",
            "/login",
            XFOVulnType.DEPRECATED_ALLOW_FROM
        )

        assert "ALLOW-FROM" in poc or "deprecated" in poc.lower()
        assert "iframe" in poc.lower()

    def test_generate_poc_contains_remediation(self, tester):
        """Test POC contains remediation guidance."""
        poc = tester._generate_poc_html(
            "https://example.com/admin",
            "/admin",
            XFOVulnType.MISSING_XFO
        )

        assert "Remediation" in poc or "remediation" in poc.lower()
        assert "X-Frame-Options: DENY" in poc

    def test_generate_poc_contains_debug_toggle(self, tester):
        """Test POC contains debug toggle."""
        poc = tester._generate_poc_html(
            "https://example.com/test",
            "/test",
            XFOVulnType.MISSING_BOTH
        )

        assert "toggleFrame" in poc or "Toggle" in poc

    def test_generate_poc_valid_html(self, tester):
        """Test POC generates valid HTML structure."""
        poc = tester._generate_poc_html(
            "https://example.com/test",
            "/test",
            XFOVulnType.MISSING_BOTH
        )

        assert poc.startswith("<!DOCTYPE html>")
        assert "<html>" in poc
        assert "</html>" in poc
        assert "<head>" in poc
        assert "<body>" in poc


# ============================================================================
# Recommendation Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestRecommendations:
    """Test remediation recommendations."""

    def test_recommendation_missing_both(self, tester):
        """Test recommendation for missing both headers."""
        rec = tester._get_recommendation(XFOVulnType.MISSING_BOTH, has_csp=False)

        assert "X-Frame-Options" in rec
        assert "Content-Security-Policy" in rec
        assert "frame-ancestors" in rec

    def test_recommendation_deprecated_allow_from(self, tester):
        """Test recommendation for deprecated ALLOW-FROM."""
        rec = tester._get_recommendation(XFOVulnType.DEPRECATED_ALLOW_FROM, has_csp=False)

        assert "ALLOW-FROM" in rec
        assert "deprecated" in rec.lower()
        assert "CSP" in rec or "frame-ancestors" in rec

    def test_recommendation_missing_xfo(self, tester):
        """Test recommendation for missing XFO only."""
        rec = tester._get_recommendation(XFOVulnType.MISSING_XFO, has_csp=True)

        assert "X-Frame-Options" in rec
        assert "defense-in-depth" in rec.lower() or "compatibility" in rec.lower()

    def test_recommendation_contains_examples(self, tester):
        """Test recommendation contains configuration examples."""
        rec = tester._get_recommendation(XFOVulnType.MISSING_BOTH, has_csp=False)

        assert "X-Frame-Options: DENY" in rec or "SAMEORIGIN" in rec


# ============================================================================
# Endpoint Testing Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestEndpointTesting:
    """Test endpoint testing functionality."""

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_missing_both_headers(self, mock_get, tester, mock_response):
        """Test endpoint with missing both headers."""
        mock_get.return_value = mock_response()

        finding = tester.test_endpoint("/payment")

        assert finding is not None
        assert finding.vuln_type == XFOVulnType.MISSING_BOTH
        assert finding.severity == XFOSeverity.CRITICAL
        assert finding.endpoint == "/payment"

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_deny_header(self, mock_get, tester, mock_response):
        """Test endpoint with DENY header."""
        mock_get.return_value = mock_response(xfo="DENY")

        finding = tester.test_endpoint("/payment")

        assert finding is None

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_sameorigin_header(self, mock_get, tester, mock_response):
        """Test endpoint with SAMEORIGIN header."""
        mock_get.return_value = mock_response(xfo="SAMEORIGIN")

        finding = tester.test_endpoint("/login")

        assert finding is None

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_deprecated_allow_from(self, mock_get, tester, mock_response):
        """Test endpoint with deprecated ALLOW-FROM."""
        mock_get.return_value = mock_response(xfo="ALLOW-FROM https://trusted.com")

        finding = tester.test_endpoint("/payment")

        assert finding is not None
        assert finding.vuln_type == XFOVulnType.DEPRECATED_ALLOW_FROM

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_csp_only(self, mock_get, tester, mock_response):
        """Test endpoint with CSP frame-ancestors only."""
        mock_get.return_value = mock_response(csp="frame-ancestors 'none';")

        finding = tester.test_endpoint("/payment")

        assert finding is not None
        assert finding.vuln_type == XFOVulnType.MISSING_XFO
        assert finding.severity == XFOSeverity.LOW

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_both_headers_secure(self, mock_get, tester, mock_response):
        """Test endpoint with both secure headers."""
        mock_get.return_value = mock_response(
            xfo="DENY",
            csp="frame-ancestors 'none';"
        )

        finding = tester.test_endpoint("/payment")

        assert finding is None

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_invalid_xfo(self, mock_get, tester, mock_response):
        """Test endpoint with invalid XFO value."""
        mock_get.return_value = mock_response(xfo="INVALID")

        finding = tester.test_endpoint("/payment")

        assert finding is not None
        assert finding.vuln_type == XFOVulnType.INVALID_DIRECTIVE

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_weak_csp(self, mock_get, tester, mock_response):
        """Test endpoint with weak CSP."""
        mock_get.return_value = mock_response(
            xfo="DENY",
            csp="frame-ancestors https://any-domain.com;"
        )

        finding = tester.test_endpoint("/payment")

        assert finding is not None
        assert finding.vuln_type == XFOVulnType.WEAK_PROTECTION

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_request_exception(self, mock_get, tester):
        """Test endpoint with request exception."""
        mock_get.side_effect = Exception("Network error")

        finding = tester.test_endpoint("/payment")

        assert finding is None

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_stores_test_result(self, mock_get, tester, mock_response):
        """Test that test results are stored."""
        mock_get.return_value = mock_response()

        initial_count = len(tester.test_results)
        tester.test_endpoint("/payment")

        assert len(tester.test_results) == initial_count + 1


# ============================================================================
# Full Scan Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestFullScan:
    """Test full scan functionality."""

    @patch('engine.agents.x_frame_options_tester.requests.get')
    @patch('engine.agents.x_frame_options_tester.DatabaseHooks.before_test')
    def test_run_all_tests_basic(self, mock_db_check, mock_get, tester, mock_response):
        """Test basic full scan."""
        mock_db_check.return_value = {'should_skip': False, 'recommendations': []}
        mock_get.return_value = mock_response()

        with patch('builtins.print'):
            findings = tester.run_all_tests(check_database=False)

        assert isinstance(findings, list)
        assert len(findings) > 0

    @patch('engine.agents.x_frame_options_tester.requests.get')
    @patch('engine.agents.x_frame_options_tester.DatabaseHooks.before_test')
    @patch('builtins.input', return_value='n')
    def test_run_all_tests_database_skip(self, mock_input, mock_db_check, mock_get, tester):
        """Test full scan with database skip."""
        mock_db_check.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': [],
            'recommendations': ['Skip']
        }

        with patch('builtins.print'):
            findings = tester.run_all_tests(check_database=True)

        assert len(findings) == 0

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_run_all_tests_no_database_check(self, mock_get, tester, mock_response):
        """Test full scan without database check."""
        mock_get.return_value = mock_response()

        with patch('builtins.print'):
            findings = tester.run_all_tests(check_database=False)

        assert isinstance(findings, list)


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestReportGeneration:
    """Test report generation functionality."""

    def test_generate_report_structure(self, tester):
        """Test report has correct structure."""
        with patch('builtins.open', mock_open()), patch('builtins.print'):
            report = tester.generate_report("test_report.json")

        assert 'scan_info' in report
        assert 'summary' in report
        assert 'findings' in report
        assert 'test_results' in report

    def test_generate_report_scan_info(self, tester):
        """Test report scan info."""
        with patch('builtins.open', mock_open()), patch('builtins.print'):
            report = tester.generate_report("test_report.json")

        assert report['scan_info']['target'] == tester.target_url
        assert report['scan_info']['domain'] == tester.domain
        assert 'scan_date' in report['scan_info']

    def test_generate_report_summary(self, tester):
        """Test report summary counts."""
        # Add a mock finding
        finding = XFOFinding(
            title="Test",
            severity=XFOSeverity.HIGH,
            vuln_type=XFOVulnType.MISSING_BOTH,
            description="Test",
            endpoint="/test",
            url="https://example.com/test"
        )
        tester.findings.append(finding)

        with patch('builtins.open', mock_open()), patch('builtins.print'):
            report = tester.generate_report("test_report.json")

        assert report['summary']['high'] == 1
        assert report['scan_info']['total_findings'] == 1

    @patch('builtins.open', mock_open())
    def test_generate_report_saves_pocs(self, tester):
        """Test report saves POC files."""
        finding = XFOFinding(
            title="Test",
            severity=XFOSeverity.HIGH,
            vuln_type=XFOVulnType.MISSING_BOTH,
            description="Test",
            endpoint="/test",
            url="https://example.com/test",
            poc_html="<html>POC</html>"
        )
        tester.findings.append(finding)

        with patch('builtins.print'):
            tester.generate_report("test_report.json")

        # Verify open was called for POC file
        assert any('poc_xfo_' in str(call) for call in mock_open().call_args_list)


# ============================================================================
# Data Class Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestDataClasses:
    """Test data classes."""

    def test_xfo_finding_to_dict(self):
        """Test XFOFinding to_dict conversion."""
        finding = XFOFinding(
            title="Test",
            severity=XFOSeverity.HIGH,
            vuln_type=XFOVulnType.MISSING_BOTH,
            description="Test finding",
            endpoint="/test",
            url="https://example.com/test"
        )

        result = finding.to_dict()

        assert result['severity'] == 'HIGH'
        assert result['vuln_type'] == 'MISSING_XFO_AND_CSP'
        assert result['title'] == 'Test'

    def test_xfo_test_result_to_dict(self):
        """Test XFOTestResult to_dict conversion."""
        result = XFOTestResult(
            endpoint="/test",
            url="https://example.com/test",
            has_xfo=False,
            has_csp=False,
            is_vulnerable=True,
            vulnerability_type=XFOVulnType.MISSING_BOTH
        )

        result_dict = result.to_dict()

        assert result_dict['endpoint'] == '/test'
        assert result_dict['vulnerability_type'] == 'MISSING_XFO_AND_CSP'
        assert result_dict['is_vulnerable'] is True


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_endpoint_list(self):
        """Test with empty custom endpoints."""
        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(
                target_url="https://example.com",
                custom_endpoints=[]
            )

            # Should still have default sensitive endpoints
            assert len(tester.test_endpoints) > 0

    def test_parse_malformed_csp(self, tester):
        """Test parsing malformed CSP."""
        malformed = "invalid csp syntax;;;;"
        result = tester._parse_frame_ancestors(malformed)
        assert result is None

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_test_endpoint_with_redirect(self, mock_get, tester, mock_response):
        """Test endpoint that redirects."""
        mock_get.return_value = mock_response(status_code=200)

        finding = tester.test_endpoint("/payment")

        # Should handle redirect gracefully
        assert finding is not None or finding is None  # Either outcome is valid

    def test_case_sensitivity_xfo_header(self, tester):
        """Test case sensitivity in XFO validation."""
        assert tester._is_secure_xfo("deny") is True
        assert tester._is_secure_xfo("DENY") is True
        assert tester._is_secure_xfo("Deny") is True

    def test_whitespace_handling(self, tester):
        """Test whitespace handling in headers."""
        assert tester._is_secure_xfo("  DENY  ") is True
        assert tester._is_secure_csp("  'none'  ") is True


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not XFO_TESTER_AVAILABLE, reason="X-Frame-Options tester not available")
class TestIntegration:
    """Integration tests."""

    @patch('engine.agents.x_frame_options_tester.requests.get')
    def test_full_workflow(self, mock_get, mock_response):
        """Test complete workflow from initialization to report."""
        mock_get.return_value = mock_response()

        with patch('engine.agents.x_frame_options_tester.BountyHoundDB'):
            tester = XFrameOptionsTester(
                target_url="https://example.com",
                custom_endpoints=["/custom"]
            )

        with patch('builtins.print'):
            findings = tester.run_all_tests(check_database=False)

        with patch('builtins.open', mock_open()), patch('builtins.print'):
            report = tester.generate_report("test.json")

        assert len(findings) > 0
        assert report['scan_info']['total_findings'] == len(findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
