"""
Comprehensive tests for Referrer-Policy Analyzer Agent.

Tests cover:
- Initialization and configuration
- Missing Referrer-Policy detection
- Unsafe-url policy detection
- No-referrer-when-downgrade policy detection
- Origin-when-cross-origin policy detection
- Sensitive data leakage detection (tokens, sessions, passwords, etc.)
- URL parameter analysis
- Policy strength assessment
- Finding management
- Report generation
- Edge cases and error handling
- All POC generation methods
- Database integration

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.referrer_policy_analyzer import (
        ReferrerPolicyAnalyzer,
        ReferrerPolicyFinding,
        ReferrerPolicyTestResult,
        ReferrerPolicySeverity,
        ReferrerPolicyVulnType,
        REQUESTS_AVAILABLE
    )
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Referrer-Policy analyzer not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(referrer_policy=None, status_code=200, url=None):
        response = Mock()
        response.status_code = status_code
        response.headers = {}
        response.url = url or "https://api.example.com/users"

        if referrer_policy:
            response.headers['Referrer-Policy'] = referrer_policy

        return response

    return _create_response


@pytest.fixture
def analyzer():
    """Create a ReferrerPolicyAnalyzer instance for testing."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("Referrer-Policy analyzer not available")

    return ReferrerPolicyAnalyzer(
        target_url="https://api.example.com/users",
        timeout=5,
        verify_ssl=False
    )


@pytest.fixture
def analyzer_with_sensitive_url():
    """Create analyzer with URL containing sensitive parameters."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("Referrer-Policy analyzer not available")

    return ReferrerPolicyAnalyzer(
        target_url="https://api.example.com/reset?token=secret123&email=user@example.com",
        timeout=5,
        verify_ssl=False
    )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestInitialization:
    """Test ReferrerPolicyAnalyzer initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        analyzer = ReferrerPolicyAnalyzer(target_url="https://api.example.com")

        assert analyzer.target_url == "https://api.example.com"
        assert analyzer.domain == "api.example.com"
        assert analyzer.timeout == 10
        assert analyzer.verify_ssl is True
        assert len(analyzer.findings) == 0
        assert len(analyzer.test_results) == 0

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://example.com",
            timeout=30
        )

        assert analyzer.timeout == 30

    def test_init_with_ssl_disabled(self):
        """Test initialization with SSL verification disabled."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://example.com",
            verify_ssl=False
        )

        assert analyzer.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com/"
        )

        assert analyzer.target_url == "https://api.example.com"

    def test_init_with_custom_sensitive_patterns(self):
        """Test initialization with custom sensitive patterns."""
        custom_patterns = {
            'custom_token': r'custom_token=([^&\s]+)',
            'internal_id': r'internal_id=([^&\s]+)'
        }

        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://example.com",
            custom_sensitive_patterns=custom_patterns
        )

        assert 'custom_token' in analyzer.sensitive_patterns
        assert 'internal_id' in analyzer.sensitive_patterns
        # Default patterns should still exist
        assert 'token' in analyzer.sensitive_patterns
        assert 'session' in analyzer.sensitive_patterns

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            ReferrerPolicyAnalyzer(target_url="https://example.com")

    def test_init_parses_url_components(self):
        """Test that URL components are parsed correctly."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com:8443/v1/users?page=1"
        )

        assert analyzer.parsed_url.scheme == "https"
        assert analyzer.parsed_url.netloc == "api.example.com:8443"
        assert analyzer.parsed_url.path == "/v1/users"
        assert analyzer.domain == "api.example.com:8443"


# ============================================================================
# Sensitive Data Detection Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestSensitiveDataDetection:
    """Test sensitive data detection in URLs."""

    def test_detect_token_in_url(self, analyzer):
        """Test detection of token parameter."""
        url = "https://example.com/api?token=abc123"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'token' in result
        assert 'token' in result['token']

    def test_detect_session_in_url(self, analyzer):
        """Test detection of session parameter."""
        url = "https://example.com?sessionid=xyz789"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'session' in result

    def test_detect_password_in_url(self, analyzer):
        """Test detection of password parameter."""
        url = "https://example.com/login?password=secret123"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'password' in result

    def test_detect_api_key_in_url(self, analyzer):
        """Test detection of API key parameter."""
        url = "https://example.com/api?api_key=sk_live_123456"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'api_key' in result

    def test_detect_email_in_url(self, analyzer):
        """Test detection of email parameter."""
        url = "https://example.com/verify?email=user@example.com"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'email' in result

    def test_detect_multiple_sensitive_params(self, analyzer):
        """Test detection of multiple sensitive parameters."""
        url = "https://example.com/reset?token=abc&email=user@test.com&session=xyz"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'token' in result
        assert 'email' in result
        assert 'session' in result

    def test_detect_case_insensitive(self, analyzer):
        """Test case-insensitive detection."""
        url = "https://example.com?TOKEN=abc&Session=xyz"
        result = analyzer._detect_sensitive_data_in_url(url)

        assert 'token' in result
        assert 'session' in result

    def test_no_sensitive_data_in_clean_url(self, analyzer):
        """Test no false positives on clean URL."""
        url = "https://example.com/api/users?page=1&limit=10"
        result = analyzer._detect_sensitive_data_in_url(url)

        # Should not detect any sensitive data
        assert len(result) == 0


# ============================================================================
# Token Analysis Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestTokenAnalysis:
    """Test URL token analysis."""

    def test_analyze_url_detects_token_keyword(self, analyzer):
        """Test detection of token-like parameter names."""
        url = "https://example.com?access_token=xyz123"
        result = analyzer._analyze_url_for_tokens(url)

        assert len(result) > 0
        assert any('access_token' in r for r in result)

    def test_analyze_url_detects_jwt_pattern(self, analyzer):
        """Test detection of JWT-like values."""
        url = "https://example.com?auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = analyzer._analyze_url_for_tokens(url)

        assert len(result) > 0
        assert any('JWT' in r for r in result)

    def test_analyze_url_detects_long_token_like_values(self, analyzer):
        """Test detection of long alphanumeric values (likely tokens)."""
        url = "https://example.com?id=abc123def456ghi789jkl012mno345"
        result = analyzer._analyze_url_for_tokens(url)

        assert len(result) > 0
        assert any('token-like' in r for r in result)

    def test_analyze_url_ignores_short_values(self, analyzer):
        """Test that short parameter values are not flagged."""
        url = "https://example.com?page=1&limit=10&sort=asc"
        result = analyzer._analyze_url_for_tokens(url)

        assert len(result) == 0

    def test_analyze_url_detects_auth_related_params(self, analyzer):
        """Test detection of auth-related parameter names."""
        url = "https://example.com?api_key=test&bearer_token=test2&oauth=test3"
        result = analyzer._analyze_url_for_tokens(url)

        assert len(result) >= 3


# ============================================================================
# Missing Policy Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestMissingPolicy:
    """Test missing Referrer-Policy detection."""

    @patch('requests.get')
    def test_missing_policy_detected_low_severity(self, mock_get, analyzer, mock_response):
        """Test detection of missing policy on clean URL."""
        mock_get.return_value = mock_response()

        findings = analyzer.test_missing_policy()

        assert len(findings) == 1
        assert findings[0].vuln_type == ReferrerPolicyVulnType.MISSING_POLICY
        assert findings[0].severity == ReferrerPolicySeverity.LOW

    @patch('requests.get')
    def test_missing_policy_high_severity_with_token(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test missing policy with sensitive URL is HIGH severity."""
        mock_get.return_value = mock_response(
            url="https://api.example.com/reset?token=secret123"
        )

        findings = analyzer_with_sensitive_url.test_missing_policy()

        assert len(findings) == 1
        assert findings[0].severity == ReferrerPolicySeverity.HIGH
        assert len(findings[0].leaked_data) > 0

    @patch('requests.get')
    def test_missing_policy_includes_poc(self, mock_get, analyzer, mock_response):
        """Test that missing policy finding includes POC."""
        mock_get.return_value = mock_response()

        findings = analyzer.test_missing_policy()

        assert len(findings[0].poc) > 0
        assert "Referer" in findings[0].poc

    @patch('requests.get')
    def test_missing_policy_stores_result(self, mock_get, analyzer, mock_response):
        """Test that test result is stored."""
        mock_get.return_value = mock_response()

        initial_count = len(analyzer.test_results)
        analyzer.test_missing_policy()

        assert len(analyzer.test_results) == initial_count + 1

    @patch('requests.get')
    def test_missing_policy_no_finding_when_present(self, mock_get, analyzer, mock_response):
        """Test no finding when policy is present."""
        mock_get.return_value = mock_response(referrer_policy="strict-origin-when-cross-origin")

        findings = analyzer.test_missing_policy()

        assert len(findings) == 0


# ============================================================================
# Unsafe-URL Policy Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestUnsafeUrlPolicy:
    """Test unsafe-url policy detection."""

    @patch('requests.get')
    def test_unsafe_url_detected(self, mock_get, analyzer, mock_response):
        """Test detection of unsafe-url policy."""
        mock_get.return_value = mock_response(referrer_policy="unsafe-url")

        findings = analyzer.test_unsafe_url_policy()

        assert len(findings) == 1
        assert findings[0].vuln_type == ReferrerPolicyVulnType.UNSAFE_URL
        assert findings[0].severity == ReferrerPolicySeverity.MEDIUM

    @patch('requests.get')
    def test_unsafe_url_high_severity_with_sensitive_data(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test unsafe-url with sensitive data is HIGH severity."""
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com/reset?token=secret123"
        )

        findings = analyzer_with_sensitive_url.test_unsafe_url_policy()

        assert len(findings) == 1
        assert findings[0].severity == ReferrerPolicySeverity.HIGH

    @patch('requests.get')
    def test_unsafe_url_includes_comprehensive_poc(self, mock_get, analyzer, mock_response):
        """Test that unsafe-url finding includes comprehensive POC."""
        mock_get.return_value = mock_response(referrer_policy="unsafe-url")

        findings = analyzer.test_unsafe_url_policy()

        assert "HTTP" in findings[0].poc
        assert "evil.com" in findings[0].poc

    @patch('requests.get')
    def test_unsafe_url_not_detected_for_other_policies(self, mock_get, analyzer, mock_response):
        """Test unsafe-url not detected for other policies."""
        mock_get.return_value = mock_response(referrer_policy="no-referrer")

        findings = analyzer.test_unsafe_url_policy()

        assert len(findings) == 0


# ============================================================================
# No-Referrer-When-Downgrade Policy Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestNoReferrerWhenDowngradePolicy:
    """Test no-referrer-when-downgrade policy detection."""

    @patch('requests.get')
    def test_downgrade_policy_detected(self, mock_get, analyzer, mock_response):
        """Test detection of no-referrer-when-downgrade policy."""
        mock_get.return_value = mock_response(
            referrer_policy="no-referrer-when-downgrade"
        )

        findings = analyzer.test_no_referrer_when_downgrade_policy()

        assert len(findings) == 1
        assert findings[0].vuln_type == ReferrerPolicyVulnType.NO_REFERRER_WHEN_DOWNGRADE

    @patch('requests.get')
    def test_downgrade_policy_severity_based_on_content(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test severity escalates with sensitive data."""
        mock_get.return_value = mock_response(
            referrer_policy="no-referrer-when-downgrade",
            url="https://api.example.com/reset?token=secret123"
        )

        findings = analyzer_with_sensitive_url.test_no_referrer_when_downgrade_policy()

        assert len(findings) == 1
        assert findings[0].severity == ReferrerPolicySeverity.MEDIUM

    @patch('requests.get')
    def test_downgrade_policy_not_detected_when_missing(self, mock_get, analyzer, mock_response):
        """Test already handled by missing policy test."""
        mock_get.return_value = mock_response()  # No policy

        findings = analyzer.test_no_referrer_when_downgrade_policy()

        # Should return empty - handled by test_missing_policy
        assert len(findings) == 0


# ============================================================================
# Origin-When-Cross-Origin Policy Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestOriginWhenCrossOriginPolicy:
    """Test origin-when-cross-origin policy detection."""

    @patch('requests.get')
    def test_origin_when_cross_origin_with_sensitive_data(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test detection when sensitive data present."""
        mock_get.return_value = mock_response(
            referrer_policy="origin-when-cross-origin",
            url="https://api.example.com/reset?token=secret123"
        )

        findings = analyzer_with_sensitive_url.test_origin_when_cross_origin_policy()

        assert len(findings) == 1
        assert findings[0].vuln_type == ReferrerPolicyVulnType.ORIGIN_WHEN_CROSS_ORIGIN
        assert findings[0].severity == ReferrerPolicySeverity.LOW

    @patch('requests.get')
    def test_origin_when_cross_origin_no_finding_without_sensitive_data(self, mock_get, analyzer, mock_response):
        """Test no finding when no sensitive data."""
        mock_get.return_value = mock_response(
            referrer_policy="origin-when-cross-origin"
        )

        findings = analyzer.test_origin_when_cross_origin_policy()

        assert len(findings) == 0

    @patch('requests.get')
    def test_origin_when_cross_origin_poc_includes_xss_scenario(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test POC includes XSS attack scenario."""
        mock_get.return_value = mock_response(
            referrer_policy="origin-when-cross-origin",
            url="https://api.example.com/reset?token=secret123"
        )

        findings = analyzer_with_sensitive_url.test_origin_when_cross_origin_policy()

        assert "XSS" in findings[0].poc or "same-origin" in findings[0].poc


# ============================================================================
# Sensitive Data Leakage Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestSensitiveDataLeakage:
    """Test sensitive data leakage detection."""

    @patch('requests.get')
    def test_token_leakage_critical(self, mock_get, mock_response):
        """Test token leakage is CRITICAL severity."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com?token=abc123"
        )
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com?token=abc123"
        )

        findings = analyzer.test_sensitive_data_leakage()

        assert len(findings) > 0
        # Find token leakage finding
        token_findings = [f for f in findings if 'token' in f.leaked_data]
        assert len(token_findings) > 0
        assert token_findings[0].severity == ReferrerPolicySeverity.CRITICAL

    @patch('requests.get')
    def test_session_leakage_critical(self, mock_get, mock_response):
        """Test session leakage is CRITICAL severity."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com?sessionid=xyz789"
        )
        mock_get.return_value = mock_response(
            referrer_policy="no-referrer-when-downgrade",
            url="https://api.example.com?sessionid=xyz789"
        )

        findings = analyzer.test_sensitive_data_leakage()

        session_findings = [f for f in findings if 'session' in f.leaked_data]
        assert len(session_findings) > 0
        assert session_findings[0].severity == ReferrerPolicySeverity.CRITICAL

    @patch('requests.get')
    def test_password_leakage_critical(self, mock_get, mock_response):
        """Test password leakage is CRITICAL severity."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com/login?password=secret"
        )
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com/login?password=secret"
        )

        findings = analyzer.test_sensitive_data_leakage()

        password_findings = [f for f in findings if 'password' in f.leaked_data]
        assert len(password_findings) > 0
        assert password_findings[0].severity == ReferrerPolicySeverity.CRITICAL

    @patch('requests.get')
    def test_email_leakage_medium(self, mock_get, mock_response):
        """Test email leakage is MEDIUM severity."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com?email=user@test.com"
        )
        mock_get.return_value = mock_response(
            referrer_policy="origin-when-cross-origin",
            url="https://api.example.com?email=user@test.com"
        )

        findings = analyzer.test_sensitive_data_leakage()

        email_findings = [f for f in findings if 'email' in f.leaked_data]
        assert len(email_findings) > 0
        assert email_findings[0].severity == ReferrerPolicySeverity.MEDIUM

    @patch('requests.get')
    def test_multiple_sensitive_params_multiple_findings(self, mock_get, mock_response):
        """Test multiple sensitive parameters create multiple findings."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com?token=abc&session=xyz&email=user@test.com"
        )
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com?token=abc&session=xyz&email=user@test.com"
        )

        findings = analyzer.test_sensitive_data_leakage()

        assert len(findings) >= 3  # At least token, session, email

    @patch('requests.get')
    def test_no_leakage_with_secure_policy(self, mock_get, mock_response):
        """Test no findings with secure policy."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com?token=abc"
        )
        mock_get.return_value = mock_response(
            referrer_policy="no-referrer",
            url="https://api.example.com?token=abc"
        )

        findings = analyzer.test_sensitive_data_leakage()

        assert len(findings) == 0

    @patch('requests.get')
    def test_leakage_poc_includes_exploitation(self, mock_get, mock_response):
        """Test that leakage POC includes exploitation scenario."""
        analyzer = ReferrerPolicyAnalyzer(
            target_url="https://api.example.com?token=abc123"
        )
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com?token=abc123"
        )

        findings = analyzer.test_sensitive_data_leakage()

        assert len(findings) > 0
        assert "evil.com" in findings[0].poc
        assert "Referer" in findings[0].poc


# ============================================================================
# Full Test Suite Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestFullTestSuite:
    """Test running complete test suite."""

    @patch('requests.get')
    def test_run_all_tests_executes_all_checks(self, mock_get, analyzer, mock_response):
        """Test that run_all_tests executes all test methods."""
        mock_get.return_value = mock_response()

        findings = analyzer.run_all_tests()

        # Should make at least one request per test method
        assert mock_get.call_count >= 5

    @patch('requests.get')
    def test_run_all_tests_returns_findings(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test that run_all_tests returns all findings."""
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com/reset?token=secret123"
        )

        findings = analyzer_with_sensitive_url.run_all_tests()

        assert len(findings) > 0
        assert all(isinstance(f, ReferrerPolicyFinding) for f in findings)

    @patch('requests.get')
    def test_run_all_tests_stores_findings(self, mock_get, analyzer, mock_response):
        """Test that findings are stored in analyzer instance."""
        mock_get.return_value = mock_response()

        analyzer.run_all_tests()

        # At least missing policy finding
        assert len(analyzer.findings) > 0

    @patch('requests.get')
    def test_run_all_tests_handles_request_failure(self, mock_get, analyzer):
        """Test handling of request failures."""
        mock_get.return_value = None

        findings = analyzer.run_all_tests()

        # Should not crash, may have empty findings
        assert isinstance(findings, list)


# ============================================================================
# Finding Management Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestFindingManagement:
    """Test finding management methods."""

    def test_get_findings_by_severity(self, analyzer):
        """Test filtering findings by severity."""
        # Add test findings
        analyzer.findings.append(ReferrerPolicyFinding(
            title="Critical",
            severity=ReferrerPolicySeverity.CRITICAL,
            vuln_type=ReferrerPolicyVulnType.TOKEN_LEAKAGE,
            description="Test",
            endpoint=analyzer.target_url
        ))
        analyzer.findings.append(ReferrerPolicyFinding(
            title="High",
            severity=ReferrerPolicySeverity.HIGH,
            vuln_type=ReferrerPolicyVulnType.MISSING_POLICY,
            description="Test",
            endpoint=analyzer.target_url
        ))

        critical = analyzer.get_findings_by_severity(ReferrerPolicySeverity.CRITICAL)
        high = analyzer.get_findings_by_severity(ReferrerPolicySeverity.HIGH)

        assert len(critical) == 1
        assert len(high) == 1

    def test_get_critical_findings(self, analyzer):
        """Test getting only critical findings."""
        analyzer.findings.append(ReferrerPolicyFinding(
            title="Critical",
            severity=ReferrerPolicySeverity.CRITICAL,
            vuln_type=ReferrerPolicyVulnType.TOKEN_LEAKAGE,
            description="Test",
            endpoint=analyzer.target_url
        ))
        analyzer.findings.append(ReferrerPolicyFinding(
            title="Low",
            severity=ReferrerPolicySeverity.LOW,
            vuln_type=ReferrerPolicyVulnType.WEAK_POLICY,
            description="Test",
            endpoint=analyzer.target_url
        ))

        critical = analyzer.get_critical_findings()

        assert len(critical) == 1
        assert critical[0].severity == ReferrerPolicySeverity.CRITICAL


# ============================================================================
# Summary Generation Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestSummaryGeneration:
    """Test summary report generation."""

    @patch('requests.get')
    def test_get_summary_structure(self, mock_get, analyzer, mock_response):
        """Test summary report structure."""
        mock_get.return_value = mock_response()
        analyzer.run_all_tests()

        summary = analyzer.get_summary()

        assert 'target' in summary
        assert 'total_tests' in summary
        assert 'total_findings' in summary
        assert 'severity_breakdown' in summary
        assert 'vulnerable' in summary
        assert 'findings' in summary

    @patch('requests.get')
    def test_get_summary_severity_breakdown(self, mock_get, analyzer, mock_response):
        """Test severity breakdown in summary."""
        mock_get.return_value = mock_response()
        analyzer.run_all_tests()

        summary = analyzer.get_summary()
        breakdown = summary['severity_breakdown']

        assert 'CRITICAL' in breakdown
        assert 'HIGH' in breakdown
        assert 'MEDIUM' in breakdown
        assert 'LOW' in breakdown
        assert 'INFO' in breakdown

    @patch('requests.get')
    def test_get_summary_vulnerable_flag(self, mock_get, analyzer, mock_response):
        """Test vulnerable flag is set correctly."""
        mock_get.return_value = mock_response()
        analyzer.run_all_tests()
        summary = analyzer.get_summary()

        # Should have at least missing policy finding
        assert summary['vulnerable'] is True

    @patch('requests.get')
    def test_get_summary_not_vulnerable_with_secure_policy(self, mock_get, analyzer, mock_response):
        """Test vulnerable flag when secure policy present."""
        mock_get.return_value = mock_response(
            referrer_policy="no-referrer"
        )
        analyzer.run_all_tests()
        summary = analyzer.get_summary()

        assert summary['vulnerable'] is False


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestReportGeneration:
    """Test comprehensive report generation."""

    @patch('requests.get')
    def test_generate_report_with_findings(self, mock_get, analyzer, mock_response):
        """Test report generation with findings."""
        mock_get.return_value = mock_response()
        analyzer.run_all_tests()

        report = analyzer.generate_report()

        assert "Referrer-Policy Security Analysis Report" in report
        assert analyzer.target_url in report
        assert "Total Findings:" in report

    @patch('requests.get')
    def test_generate_report_secure_status(self, mock_get, analyzer, mock_response):
        """Test report for secure endpoint."""
        mock_get.return_value = mock_response(
            referrer_policy="no-referrer"
        )
        analyzer.run_all_tests()

        report = analyzer.generate_report()

        assert "SECURE" in report
        assert "No Referrer-Policy issues found" in report

    @patch('requests.get')
    def test_generate_report_includes_remediation(self, mock_get, analyzer_with_sensitive_url, mock_response):
        """Test report includes remediation section."""
        mock_get.return_value = mock_response(
            referrer_policy="unsafe-url",
            url="https://api.example.com/reset?token=secret123"
        )
        analyzer_with_sensitive_url.run_all_tests()

        report = analyzer_with_sensitive_url.generate_report()

        assert "Remediation Priority" in report
        assert "Configuration Examples" in report

    @patch('requests.get')
    def test_generate_report_includes_policy_comparison(self, mock_get, analyzer, mock_response):
        """Test report includes policy comparison table."""
        mock_get.return_value = mock_response()
        analyzer.run_all_tests()

        report = analyzer.generate_report()

        assert "Policy Comparison" in report
        assert "no-referrer" in report
        assert "unsafe-url" in report


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestPOCGeneration:
    """Test POC generation methods."""

    def test_generate_missing_policy_poc(self, analyzer):
        """Test POC for missing policy."""
        poc = analyzer._generate_missing_policy_poc()

        assert "Referer" in poc
        assert analyzer.target_url in poc
        assert "DevTools" in poc

    def test_generate_unsafe_url_poc(self, analyzer):
        """Test POC for unsafe-url policy."""
        poc = analyzer._generate_unsafe_url_poc()

        assert "unsafe-url" in poc
        assert "evil.com" in poc
        assert analyzer.target_url in poc
        assert "HTTP" in poc

    def test_generate_downgrade_poc(self, analyzer):
        """Test POC for no-referrer-when-downgrade."""
        poc = analyzer._generate_downgrade_poc()

        assert "no-referrer-when-downgrade" in poc
        assert "https://evil.com" in poc
        assert analyzer.target_url in poc

    def test_generate_origin_when_cross_origin_poc(self, analyzer):
        """Test POC for origin-when-cross-origin."""
        poc = analyzer._generate_origin_when_cross_origin_poc()

        assert "origin-when-cross-origin" in poc
        assert "XSS" in poc or "same-origin" in poc

    def test_generate_sensitive_leakage_poc(self, analyzer):
        """Test POC for sensitive data leakage."""
        poc = analyzer._generate_sensitive_leakage_poc('token', ['access_token'])

        assert "token" in poc.lower()
        assert "access_token" in poc
        assert "evil.com" in poc
        assert "Referer" in poc


# ============================================================================
# Data Conversion Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestDataConversion:
    """Test data conversion methods."""

    def test_finding_to_dict(self):
        """Test ReferrerPolicyFinding to dict conversion."""
        finding = ReferrerPolicyFinding(
            title="Test",
            severity=ReferrerPolicySeverity.HIGH,
            vuln_type=ReferrerPolicyVulnType.TOKEN_LEAKAGE,
            description="Test description",
            endpoint="https://api.example.com"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['title'] == "Test"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['vuln_type'] == "REFERRER_TOKEN_LEAKAGE"

    def test_test_result_to_dict(self):
        """Test ReferrerPolicyTestResult to dict conversion."""
        result = ReferrerPolicyTestResult(
            endpoint="https://api.example.com",
            has_referrer_policy=True,
            policy_value="unsafe-url",
            is_vulnerable=True,
            vulnerability_type=ReferrerPolicyVulnType.UNSAFE_URL
        )

        result_dict = result.to_dict()

        assert result_dict['has_referrer_policy'] is True
        assert result_dict['policy_value'] == "unsafe-url"
        assert result_dict['vulnerability_type'] == "REFERRER_UNSAFE_URL"


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_finding_with_default_date(self):
        """Test that finding gets default date."""
        finding = ReferrerPolicyFinding(
            title="Test",
            severity=ReferrerPolicySeverity.HIGH,
            vuln_type=ReferrerPolicyVulnType.TOKEN_LEAKAGE,
            description="Test",
            endpoint="https://api.example.com"
        )

        assert finding.discovered_date == date.today().isoformat()

    @patch('requests.get')
    def test_handles_request_exception(self, mock_get, analyzer):
        """Test handling of request exceptions."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        # Should not crash
        findings = analyzer.test_missing_policy()
        assert len(findings) == 0

    def test_analyzer_with_url_no_query(self, analyzer):
        """Test analyzer with URL without query parameters."""
        result = analyzer._detect_sensitive_data_in_url(analyzer.target_url)

        assert isinstance(result, dict)

    def test_test_result_without_vulnerability(self):
        """Test ReferrerPolicyTestResult without vulnerability."""
        result = ReferrerPolicyTestResult(
            endpoint="https://api.example.com",
            has_referrer_policy=True
        )

        assert result.is_vulnerable is False
        assert result.vulnerability_type is None

    def test_empty_findings_list(self, analyzer):
        """Test behavior with empty findings."""
        critical = analyzer.get_critical_findings()

        assert len(critical) == 0
        assert isinstance(critical, list)

    @patch('requests.get')
    def test_case_insensitive_policy_detection(self, mock_get, analyzer, mock_response):
        """Test policy detection is case-insensitive."""
        mock_get.return_value = mock_response(referrer_policy="UNSAFE-URL")

        findings = analyzer.test_unsafe_url_policy()

        # Should detect despite uppercase
        assert len(findings) == 1
