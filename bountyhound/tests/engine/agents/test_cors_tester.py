"""
Comprehensive tests for CORS Tester Agent.

Tests cover:
- Initialization and configuration
- Wildcard with credentials detection
- Origin reflection testing
- Null origin bypass
- Subdomain trust exploitation
- Pre-flight bypass attempts
- Credential exposure testing
- Protocol downgrade attacks
- Regex bypass techniques
- Finding management
- Report generation
- Edge cases and error handling
- All POC generation methods

Target: 95%+ code coverage with 25+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.cors_tester import (
        CORSTester,
        CORSFinding,
        CORSTestResult,
        CORSSeverity,
        CORSVulnType,
        REQUESTS_AVAILABLE
    )
    CORS_TESTER_AVAILABLE = True
except ImportError:
    CORS_TESTER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="CORS tester not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(acao=None, acac=None, acah=None, acam=None, vary=None, status_code=200):
        response = Mock()
        response.status_code = status_code
        response.headers = {}

        if acao:
            response.headers['Access-Control-Allow-Origin'] = acao
        if acac:
            response.headers['Access-Control-Allow-Credentials'] = acac
        if acah:
            response.headers['Access-Control-Allow-Headers'] = acah
        if acam:
            response.headers['Access-Control-Allow-Methods'] = acam
        if vary:
            response.headers['Vary'] = vary

        return response

    return _create_response


@pytest.fixture
def tester():
    """Create a CORSTester instance for testing."""
    if not CORS_TESTER_AVAILABLE:
        pytest.skip("CORS tester not available")

    return CORSTester(
        target_url="https://api.example.com/users",
        timeout=5,
        verify_ssl=False
    )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestInitialization:
    """Test CORSTester initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        tester = CORSTester(target_url="https://api.example.com")

        assert tester.target_url == "https://api.example.com"
        assert tester.domain == "api.example.com"
        assert tester.timeout == 10
        assert tester.verify_ssl is True
        assert len(tester.findings) == 0
        assert len(tester.test_results) == 0

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        tester = CORSTester(target_url="https://example.com", timeout=30)

        assert tester.timeout == 30

    def test_init_with_custom_origins(self):
        """Test initialization with custom origins."""
        custom_origins = ["https://custom1.com", "https://custom2.com"]
        tester = CORSTester(
            target_url="https://api.example.com",
            custom_origins=custom_origins
        )

        # Check that custom origins are included
        for origin in custom_origins:
            assert origin in tester.test_origins

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        tester = CORSTester(target_url="https://example.com", verify_ssl=False)

        assert tester.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        tester = CORSTester(target_url="https://api.example.com/")

        assert tester.target_url == "https://api.example.com"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            CORSTester(target_url="https://example.com")


# ============================================================================
# Domain Extraction Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestDomainExtraction:
    """Test domain extraction from URLs."""

    def test_extract_domain_from_simple_url(self):
        """Test extracting domain from simple URL."""
        tester = CORSTester(target_url="https://example.com")
        assert tester.domain == "example.com"

    def test_extract_domain_from_subdomain(self):
        """Test extracting domain from subdomain URL."""
        tester = CORSTester(target_url="https://api.example.com")
        assert tester.domain == "api.example.com"

    def test_extract_domain_from_url_with_path(self):
        """Test extracting domain from URL with path."""
        tester = CORSTester(target_url="https://api.example.com/v1/users")
        assert tester.domain == "api.example.com"

    def test_extract_domain_from_url_with_port(self):
        """Test extracting domain from URL with port."""
        tester = CORSTester(target_url="https://api.example.com:8443/api")
        assert tester.domain == "api.example.com:8443"


# ============================================================================
# Origin List Building Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestOriginListBuilding:
    """Test origin list building logic."""

    def test_build_origin_list_contains_attack_origins(self, tester):
        """Test that origin list contains attack origins."""
        assert "https://evil.com" in tester.test_origins
        assert "https://attacker.com" in tester.test_origins

    def test_build_origin_list_contains_null_origins(self, tester):
        """Test that origin list contains null origin variants."""
        assert "null" in tester.test_origins
        assert "Null" in tester.test_origins

    def test_build_origin_list_contains_subdomain_variants(self):
        """Test that origin list contains subdomain variants."""
        tester = CORSTester(target_url="https://api.example.com")

        # Should include evil subdomain variants
        assert any("evil.example.com" in origin for origin in tester.test_origins)

    def test_build_origin_list_contains_protocol_variants(self, tester):
        """Test that origin list contains protocol variants."""
        assert any(origin.startswith("http://") for origin in tester.test_origins)
        assert any(origin.startswith("https://") for origin in tester.test_origins)

    def test_build_origin_list_no_duplicates(self, tester):
        """Test that origin list contains no duplicates."""
        assert len(tester.test_origins) == len(set(tester.test_origins))


# ============================================================================
# CORS Request Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestCORSRequest:
    """Test CORS request making."""

    @patch('requests.request')
    def test_make_cors_request_basic(self, mock_request, tester, mock_response):
        """Test basic CORS request."""
        mock_request.return_value = mock_response(acao="https://evil.com")

        result = tester._make_cors_request("https://evil.com")

        assert result is not None
        assert result.has_cors is True
        assert result.acao_header == "https://evil.com"
        assert result.origin == "https://evil.com"

    @patch('requests.request')
    def test_make_cors_request_with_credentials(self, mock_request, tester, mock_response):
        """Test CORS request with credentials header."""
        mock_request.return_value = mock_response(
            acao="https://evil.com",
            acac="true"
        )

        result = tester._make_cors_request("https://evil.com", with_credentials=True)

        assert result.acac_header == "true"

    @patch('requests.request')
    def test_make_cors_request_options_method(self, mock_request, tester, mock_response):
        """Test CORS preflight OPTIONS request."""
        mock_request.return_value = mock_response(
            acao="https://evil.com",
            acam="GET, POST, PUT",
            acah="Content-Type"
        )

        result = tester._make_cors_request("https://evil.com", method="OPTIONS")

        assert result.acam_header == "GET, POST, PUT"
        assert result.acah_header == "Content-Type"

    @patch('requests.request')
    def test_make_cors_request_no_cors_headers(self, mock_request, tester, mock_response):
        """Test request to endpoint without CORS headers."""
        mock_request.return_value = mock_response()

        result = tester._make_cors_request("https://evil.com")

        assert result.has_cors is False
        assert result.acao_header is None

    @patch('requests.request')
    def test_make_cors_request_handles_exception(self, mock_request, tester):
        """Test that request exceptions are handled gracefully."""
        import requests
        mock_request.side_effect = requests.exceptions.Timeout()

        result = tester._make_cors_request("https://evil.com")

        assert result is None

    @patch('requests.request')
    def test_make_cors_request_stores_result(self, mock_request, tester, mock_response):
        """Test that request results are stored."""
        mock_request.return_value = mock_response(acao="*")

        initial_count = len(tester.test_results)
        tester._make_cors_request("https://evil.com")

        assert len(tester.test_results) == initial_count + 1


# ============================================================================
# Wildcard with Credentials Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestWildcardWithCredentials:
    """Test wildcard ACAO with credentials detection."""

    @patch('requests.request')
    def test_wildcard_with_credentials_detected(self, mock_request, tester, mock_response):
        """Test detection of wildcard with credentials."""
        mock_request.return_value = mock_response(acao="*", acac="true")

        findings = tester.test_wildcard_with_credentials()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.WILDCARD_WITH_CREDENTIALS
        assert findings[0].severity == CORSSeverity.INFO

    @patch('requests.request')
    def test_wildcard_without_credentials_not_reported(self, mock_request, tester, mock_response):
        """Test that wildcard without credentials is not reported."""
        mock_request.return_value = mock_response(acao="*")

        findings = tester.test_wildcard_with_credentials()

        assert len(findings) == 0

    @patch('requests.request')
    def test_wildcard_with_credentials_includes_poc(self, mock_request, tester, mock_response):
        """Test that finding includes POC."""
        mock_request.return_value = mock_response(acao="*", acac="true")

        findings = tester.test_wildcard_with_credentials()

        assert len(findings[0].poc) > 0
        assert "curl" in findings[0].poc


# ============================================================================
# Origin Reflection Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestOriginReflection:
    """Test origin reflection vulnerability detection."""

    @patch('requests.request')
    def test_origin_reflection_without_credentials(self, mock_request, tester, mock_response):
        """Test origin reflection without credentials."""
        mock_request.return_value = mock_response(acao="https://evil.com")

        findings = tester.test_origin_reflection()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.ORIGIN_REFLECTION
        assert findings[0].severity == CORSSeverity.HIGH

    @patch('requests.request')
    def test_origin_reflection_with_credentials(self, mock_request, tester, mock_response):
        """Test origin reflection with credentials (critical)."""
        mock_request.return_value = mock_response(acao="https://evil.com", acac="true")

        findings = tester.test_origin_reflection()

        assert len(findings) == 1
        assert findings[0].severity == CORSSeverity.CRITICAL

    @patch('requests.request')
    def test_origin_reflection_includes_exploit_poc(self, mock_request, tester, mock_response):
        """Test that finding includes JavaScript exploit POC."""
        mock_request.return_value = mock_response(acao="https://evil.com", acac="true")

        findings = tester.test_origin_reflection()

        assert "fetch" in findings[0].poc
        assert "https://evil.com" in findings[0].poc

    @patch('requests.request')
    def test_origin_reflection_not_detected_when_origin_differs(self, mock_request, tester, mock_response):
        """Test that reflection is not detected when origin doesn't match."""
        mock_request.return_value = mock_response(acao="https://trusted.com")

        findings = tester.test_origin_reflection()

        assert len(findings) == 0


# ============================================================================
# Null Origin Bypass Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestNullOriginBypass:
    """Test null origin bypass detection."""

    @patch('requests.request')
    def test_null_origin_bypass_detected(self, mock_request, tester, mock_response):
        """Test detection of null origin bypass."""
        mock_request.return_value = mock_response(acao="null")

        findings = tester.test_null_origin_bypass()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.NULL_ORIGIN_BYPASS
        assert findings[0].severity == CORSSeverity.MEDIUM

    @patch('requests.request')
    def test_null_origin_with_credentials_is_high(self, mock_request, tester, mock_response):
        """Test null origin with credentials is HIGH severity."""
        mock_request.return_value = mock_response(acao="null", acac="true")

        findings = tester.test_null_origin_bypass()

        assert findings[0].severity == CORSSeverity.HIGH

    @patch('requests.request')
    def test_null_origin_includes_iframe_poc(self, mock_request, tester, mock_response):
        """Test that finding includes sandboxed iframe POC."""
        mock_request.return_value = mock_response(acao="null")

        findings = tester.test_null_origin_bypass()

        assert "iframe" in findings[0].poc
        assert "sandbox" in findings[0].poc

    @patch('requests.request')
    def test_null_origin_tests_variants(self, mock_request, tester, mock_response):
        """Test that multiple null origin variants are tested."""
        # Only first variant should trigger finding
        responses = [
            mock_response(acao="null"),
            mock_response(acao="Null"),
        ]
        mock_request.side_effect = responses

        findings = tester.test_null_origin_bypass()

        # Should only report once
        assert len(findings) == 1


# ============================================================================
# Subdomain Trust Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestSubdomainTrust:
    """Test subdomain trust exploitation detection."""

    @patch('requests.request')
    def test_subdomain_trust_detected(self, mock_request, mock_response):
        """Test detection of subdomain trust vulnerability."""
        tester = CORSTester(target_url="https://api.example.com")
        mock_request.return_value = mock_response(acao="https://evil.example.com")

        findings = tester.test_subdomain_trust()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.SUBDOMAIN_TRUST

    @patch('requests.request')
    def test_subdomain_trust_not_tested_without_subdomain(self, mock_request, tester):
        """Test that subdomain trust is not tested for simple domains."""
        tester.domain = "example"

        findings = tester.test_subdomain_trust()

        assert len(findings) == 0

    @patch('requests.request')
    def test_subdomain_trust_with_credentials_is_high(self, mock_request, mock_response):
        """Test subdomain trust with credentials is HIGH severity."""
        tester = CORSTester(target_url="https://api.example.com")
        mock_request.return_value = mock_response(acao="https://evil.example.com", acac="true")

        findings = tester.test_subdomain_trust()

        assert findings[0].severity == CORSSeverity.HIGH


# ============================================================================
# Preflight Bypass Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestPreflightBypass:
    """Test preflight bypass detection."""

    @patch('requests.request')
    def test_preflight_origin_reflection_detected(self, mock_request, tester, mock_response):
        """Test detection of origin reflection in preflight."""
        mock_request.return_value = mock_response(
            acao="https://evil.com",
            acam="GET, POST"
        )

        findings = tester.test_preflight_bypass()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.PREFLIGHT_BYPASS

    @patch('requests.request')
    def test_preflight_dangerous_methods_detected(self, mock_request, tester, mock_response):
        """Test detection of dangerous methods in preflight."""
        mock_request.return_value = mock_response(
            acao="https://evil.com",
            acam="GET, POST, DELETE, PUT"
        )

        findings = tester.test_preflight_bypass()

        assert len(findings) == 1
        assert "DELETE" in findings[0].description or "PUT" in findings[0].description

    @patch('requests.request')
    def test_preflight_wildcard_headers_detected(self, mock_request, tester, mock_response):
        """Test detection of wildcard headers in preflight."""
        mock_request.return_value = mock_response(
            acao="https://evil.com",
            acah="*"
        )

        findings = tester.test_preflight_bypass()

        assert len(findings) == 1
        assert "wildcard" in findings[0].description.lower()

    @patch('requests.request')
    def test_preflight_includes_options_poc(self, mock_request, tester, mock_response):
        """Test that preflight finding includes OPTIONS POC."""
        mock_request.return_value = mock_response(
            acao="https://evil.com",
            acam="PUT"
        )

        findings = tester.test_preflight_bypass()

        assert "OPTIONS" in findings[0].poc


# ============================================================================
# Protocol Downgrade Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestProtocolDowngrade:
    """Test protocol downgrade vulnerability detection."""

    @patch('requests.request')
    def test_protocol_downgrade_detected(self, mock_request, tester, mock_response):
        """Test detection of HTTP origin accepted by HTTPS endpoint."""
        http_origin = f"http://{tester.domain}"
        mock_request.return_value = mock_response(acao=http_origin)

        findings = tester.test_protocol_downgrade()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.PROTOCOL_DOWNGRADE
        assert findings[0].severity == CORSSeverity.MEDIUM

    @patch('requests.request')
    def test_protocol_downgrade_not_tested_for_http_target(self, mock_request):
        """Test that protocol downgrade is not tested for HTTP targets."""
        tester = CORSTester(target_url="http://api.example.com")

        findings = tester.test_protocol_downgrade()

        assert len(findings) == 0

    @patch('requests.request')
    def test_protocol_downgrade_includes_cwe(self, mock_request, tester, mock_response):
        """Test that protocol downgrade includes CWE-319."""
        http_origin = f"http://{tester.domain}"
        mock_request.return_value = mock_response(acao=http_origin)

        findings = tester.test_protocol_downgrade()

        assert findings[0].cwe_id == "CWE-319"


# ============================================================================
# Regex Bypass Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestRegexBypass:
    """Test regex bypass vulnerability detection."""

    @patch('requests.request')
    def test_regex_bypass_suffix_detected(self, mock_request, tester, mock_response):
        """Test detection of suffix-based regex bypass."""
        bypass_origin = f"https://{tester.domain}.evil.com"
        mock_request.return_value = mock_response(acao=bypass_origin)

        findings = tester.test_regex_bypass()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.REGEX_BYPASS
        assert findings[0].severity == CORSSeverity.HIGH

    @patch('requests.request')
    def test_regex_bypass_includes_recommendation(self, mock_request, tester, mock_response):
        """Test that regex bypass includes proper recommendation."""
        bypass_origin = f"https://{tester.domain}evil.com"
        mock_request.return_value = mock_response(acao=bypass_origin)

        findings = tester.test_regex_bypass()

        assert "regex" in findings[0].recommendation.lower()
        assert "anchor" in findings[0].recommendation.lower() or "exact" in findings[0].recommendation.lower()


# ============================================================================
# Credential Exposure Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestCredentialExposure:
    """Test credential exposure detection."""

    @patch('requests.request')
    def test_credential_exposure_detected(self, mock_request, tester, mock_response):
        """Test detection of credentials being allowed."""
        same_origin = f"https://{tester.domain}"
        mock_request.return_value = mock_response(acao=same_origin, acac="true")

        findings = tester.test_credential_exposure()

        assert len(findings) == 1
        assert findings[0].vuln_type == CORSVulnType.CREDENTIAL_EXPOSURE
        assert findings[0].severity == CORSSeverity.INFO

    @patch('requests.request')
    def test_credential_exposure_not_detected_without_acac(self, mock_request, tester, mock_response):
        """Test that no finding is created without ACAC header."""
        same_origin = f"https://{tester.domain}"
        mock_request.return_value = mock_response(acao=same_origin)

        findings = tester.test_credential_exposure()

        assert len(findings) == 0


# ============================================================================
# Full Test Suite Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestFullTestSuite:
    """Test running complete test suite."""

    @patch('requests.request')
    def test_run_all_tests_executes_all_checks(self, mock_request, tester, mock_response):
        """Test that run_all_tests executes all test methods."""
        mock_request.return_value = mock_response()

        findings = tester.run_all_tests()

        # Should make requests for all test categories
        assert mock_request.call_count >= 8

    @patch('requests.request')
    def test_run_all_tests_returns_findings(self, mock_request, tester, mock_response):
        """Test that run_all_tests returns all findings."""
        mock_request.return_value = mock_response(acao="https://evil.com", acac="true")

        findings = tester.run_all_tests()

        assert len(findings) > 0
        assert all(isinstance(f, CORSFinding) for f in findings)

    @patch('requests.request')
    def test_run_all_tests_stores_findings_in_tester(self, mock_request, tester, mock_response):
        """Test that findings are stored in tester instance."""
        mock_request.return_value = mock_response(acao="https://evil.com")

        tester.run_all_tests()

        assert len(tester.findings) > 0


# ============================================================================
# Finding Management Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestFindingManagement:
    """Test finding management methods."""

    def test_get_findings_by_severity(self, tester):
        """Test filtering findings by severity."""
        # Add test findings
        tester.findings.append(CORSFinding(
            title="Critical",
            severity=CORSSeverity.CRITICAL,
            vuln_type=CORSVulnType.ORIGIN_REFLECTION,
            description="Test",
            endpoint=tester.target_url,
            origin_tested="https://evil.com"
        ))
        tester.findings.append(CORSFinding(
            title="High",
            severity=CORSSeverity.HIGH,
            vuln_type=CORSVulnType.REGEX_BYPASS,
            description="Test",
            endpoint=tester.target_url,
            origin_tested="https://evil.com"
        ))

        critical = tester.get_findings_by_severity(CORSSeverity.CRITICAL)
        high = tester.get_findings_by_severity(CORSSeverity.HIGH)

        assert len(critical) == 1
        assert len(high) == 1

    def test_get_critical_findings(self, tester):
        """Test getting only critical findings."""
        tester.findings.append(CORSFinding(
            title="Critical",
            severity=CORSSeverity.CRITICAL,
            vuln_type=CORSVulnType.ORIGIN_REFLECTION,
            description="Test",
            endpoint=tester.target_url,
            origin_tested="https://evil.com"
        ))

        critical = tester.get_critical_findings()

        assert len(critical) == 1
        assert critical[0].severity == CORSSeverity.CRITICAL


# ============================================================================
# Summary Generation Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestSummaryGeneration:
    """Test summary report generation."""

    @patch('requests.request')
    def test_get_summary_structure(self, mock_request, tester, mock_response):
        """Test summary report structure."""
        mock_request.return_value = mock_response()
        tester.run_all_tests()

        summary = tester.get_summary()

        assert 'target' in summary
        assert 'total_tests' in summary
        assert 'total_findings' in summary
        assert 'severity_breakdown' in summary
        assert 'vulnerable' in summary
        assert 'findings' in summary

    @patch('requests.request')
    def test_get_summary_severity_breakdown(self, mock_request, tester, mock_response):
        """Test severity breakdown in summary."""
        mock_request.return_value = mock_response(acao="https://evil.com", acac="true")
        tester.run_all_tests()

        summary = tester.get_summary()
        breakdown = summary['severity_breakdown']

        assert 'CRITICAL' in breakdown
        assert 'HIGH' in breakdown
        assert 'MEDIUM' in breakdown
        assert 'LOW' in breakdown
        assert 'INFO' in breakdown

    @patch('requests.request')
    def test_get_summary_vulnerable_flag(self, mock_request, tester, mock_response):
        """Test vulnerable flag is set correctly."""
        # Test with vulnerability
        mock_request.return_value = mock_response(acao="https://evil.com")
        tester.run_all_tests()
        summary = tester.get_summary()

        assert summary['vulnerable'] is True

    @patch('requests.request')
    def test_get_summary_not_vulnerable(self, mock_request, tester, mock_response):
        """Test vulnerable flag when no findings."""
        mock_request.return_value = mock_response()
        tester.run_all_tests()
        summary = tester.get_summary()

        assert summary['vulnerable'] is False


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestPOCGeneration:
    """Test POC generation methods."""

    def test_generate_curl_poc(self, tester):
        """Test curl command POC generation."""
        poc = tester._generate_curl_poc("https://evil.com")

        assert "curl" in poc
        assert tester.target_url in poc
        assert "https://evil.com" in poc
        assert "Origin:" in poc

    def test_generate_exploit_poc_without_credentials(self, tester):
        """Test JavaScript exploit POC without credentials."""
        poc = tester._generate_exploit_poc("https://evil.com", False)

        assert "fetch" in poc
        assert tester.target_url in poc
        assert "https://evil.com" in poc
        assert "credentials" not in poc

    def test_generate_exploit_poc_with_credentials(self, tester):
        """Test JavaScript exploit POC with credentials."""
        poc = tester._generate_exploit_poc("https://evil.com", True)

        assert "fetch" in poc
        assert "credentials: 'include'" in poc

    def test_generate_null_origin_poc(self, tester):
        """Test null origin exploit POC."""
        poc = tester._generate_null_origin_poc(True)

        assert "iframe" in poc
        assert "sandbox" in poc
        assert tester.target_url in poc

    def test_generate_preflight_poc(self, tester):
        """Test preflight request POC."""
        poc = tester._generate_preflight_poc("https://evil.com")

        assert "OPTIONS" in poc
        assert "POST" in poc
        assert "Access-Control-Request-Method" in poc


# ============================================================================
# Data Conversion Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestDataConversion:
    """Test data conversion methods."""

    def test_cors_finding_to_dict(self):
        """Test CORSFinding to dict conversion."""
        finding = CORSFinding(
            title="Test",
            severity=CORSSeverity.HIGH,
            vuln_type=CORSVulnType.ORIGIN_REFLECTION,
            description="Test description",
            endpoint="https://api.example.com",
            origin_tested="https://evil.com"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['title'] == "Test"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['vuln_type'] == "CORS_ORIGIN_REFLECTION"

    def test_cors_test_result_to_dict(self):
        """Test CORSTestResult to dict conversion."""
        result = CORSTestResult(
            endpoint="https://api.example.com",
            origin="https://evil.com",
            has_cors=True,
            acao_header="https://evil.com",
            is_vulnerable=True,
            vulnerability_type=CORSVulnType.ORIGIN_REFLECTION
        )

        result_dict = result.to_dict()

        assert result_dict['has_cors'] is True
        assert result_dict['vulnerability_type'] == "CORS_ORIGIN_REFLECTION"


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not CORS_TESTER_AVAILABLE, reason="CORS tester not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_tester_with_empty_domain(self):
        """Test tester with empty domain."""
        tester = CORSTester(target_url="https://")

        # Should not crash
        findings = tester.test_regex_bypass()
        assert len(findings) == 0

    def test_finding_with_default_date(self):
        """Test that finding gets default date."""
        finding = CORSFinding(
            title="Test",
            severity=CORSSeverity.HIGH,
            vuln_type=CORSVulnType.ORIGIN_REFLECTION,
            description="Test",
            endpoint="https://api.example.com",
            origin_tested="https://evil.com"
        )

        assert finding.discovered_date == date.today().isoformat()

    @patch('requests.request')
    def test_handles_none_result_from_request(self, mock_request, tester):
        """Test handling of None result from failed request."""
        mock_request.return_value = None

        # Should not crash
        findings = tester.test_origin_reflection()
        assert len(findings) == 0

    def test_cors_test_result_without_vulnerability(self):
        """Test CORSTestResult without vulnerability."""
        result = CORSTestResult(
            endpoint="https://api.example.com",
            origin="https://evil.com",
            has_cors=False
        )

        assert result.is_vulnerable is False
        assert result.vulnerability_type is None
