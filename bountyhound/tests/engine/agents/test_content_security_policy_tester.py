"""
Comprehensive tests for Content Security Policy Tester Agent.

Tests cover:
- Initialization and configuration
- CSP extraction from headers and meta tags
- CSP parsing and directive analysis
- unsafe-inline and unsafe-eval detection
- Weak source detection (*, http:, data:, blob:)
- Missing critical directives (base-uri, object-src, script-src)
- JSONP endpoint bypass opportunities
- Base-URI bypass exploitation
- Nonce implementation weaknesses (static, weak)
- Wildcard subdomain risks
- Protocol downgrade vulnerabilities
- Finding management and reporting
- POC generation for all vulnerability types
- Edge cases and error handling

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.content_security_policy_tester import (
        ContentSecurityPolicyTester,
        CSPFinding,
        CSPTestResult,
        CSPSeverity,
        CSPVulnType,
        REQUESTS_AVAILABLE,
        BS4_AVAILABLE
    )
    CSP_TESTER_AVAILABLE = True
except ImportError:
    CSP_TESTER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="CSP tester not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(csp_header=None, csp_meta=None, report_only=None,
                        html_content="<html><head></head><body></body></html>",
                        status_code=200):
        response = Mock()
        response.status_code = status_code
        response.headers = {}
        response.text = html_content

        if csp_header:
            response.headers['Content-Security-Policy'] = csp_header

        if report_only:
            response.headers['Content-Security-Policy-Report-Only'] = report_only

        if csp_meta and '<meta' not in html_content:
            response.text = f'<html><head><meta http-equiv="Content-Security-Policy" content="{csp_meta}"></head><body></body></html>'

        return response

    return _create_response


@pytest.fixture
def tester():
    """Create a ContentSecurityPolicyTester instance for testing."""
    if not CSP_TESTER_AVAILABLE:
        pytest.skip("CSP tester not available")

    return ContentSecurityPolicyTester(
        target_url="https://example.com/app",
        timeout=5,
        verify_ssl=False,
        nonce_tests=3
    )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestInitialization:
    """Test ContentSecurityPolicyTester initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        tester = ContentSecurityPolicyTester(target_url="https://example.com")

        assert tester.target_url == "https://example.com"
        assert tester.domain == "example.com"
        assert tester.base_domain == "example.com"
        assert tester.timeout == 10
        assert tester.verify_ssl is True
        assert tester.nonce_tests == 3
        assert len(tester.findings) == 0

    def test_init_with_subdomain(self):
        """Test initialization with subdomain URL."""
        tester = ContentSecurityPolicyTester(target_url="https://api.example.com")

        assert tester.domain == "api.example.com"
        assert tester.base_domain == "example.com"

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        tester = ContentSecurityPolicyTester(target_url="https://example.com", timeout=30)

        assert tester.timeout == 30

    def test_init_with_custom_nonce_tests(self):
        """Test initialization with custom nonce test count."""
        tester = ContentSecurityPolicyTester(
            target_url="https://example.com",
            nonce_tests=5
        )

        assert tester.nonce_tests == 5

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        tester = ContentSecurityPolicyTester(
            target_url="https://example.com",
            verify_ssl=False
        )

        assert tester.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        tester = ContentSecurityPolicyTester(target_url="https://example.com/")

        assert tester.target_url == "https://example.com"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            ContentSecurityPolicyTester(target_url="https://example.com")


# ============================================================================
# Domain Extraction Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestDomainExtraction:
    """Test domain extraction logic."""

    def test_extract_domain_from_simple_url(self):
        """Test extracting domain from simple URL."""
        tester = ContentSecurityPolicyTester(target_url="https://example.com")
        assert tester.domain == "example.com"
        assert tester.base_domain == "example.com"

    def test_extract_domain_from_subdomain(self):
        """Test extracting domain from subdomain URL."""
        tester = ContentSecurityPolicyTester(target_url="https://api.example.com")
        assert tester.domain == "api.example.com"
        assert tester.base_domain == "example.com"

    def test_extract_domain_from_url_with_path(self):
        """Test extracting domain from URL with path."""
        tester = ContentSecurityPolicyTester(target_url="https://api.example.com/v1/users")
        assert tester.domain == "api.example.com"
        assert tester.base_domain == "example.com"

    def test_extract_domain_from_url_with_port(self):
        """Test extracting domain from URL with port."""
        tester = ContentSecurityPolicyTester(target_url="https://api.example.com:8443/api")
        assert tester.domain == "api.example.com:8443"

    def test_extract_base_domain_from_deep_subdomain(self):
        """Test extracting base domain from deep subdomain."""
        tester = ContentSecurityPolicyTester(target_url="https://api.v1.staging.example.com")
        assert tester.base_domain == "example.com"


# ============================================================================
# CSP Extraction Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestCSPExtraction:
    """Test CSP extraction from headers and meta tags."""

    @patch('requests.get')
    def test_extract_csp_from_header(self, mock_get, tester, mock_response):
        """Test extracting CSP from HTTP header."""
        mock_get.return_value = mock_response(
            csp_header="default-src 'self'"
        )

        tester._fetch_page()
        result = tester._extract_csp(mock_get.return_value)

        assert result.has_csp is True
        assert result.csp_header == "default-src 'self'"
        assert 'default-src' in result.directives

    @patch('requests.get')
    def test_extract_csp_from_meta_tag(self, mock_get, tester, mock_response):
        """Test extracting CSP from meta tag."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        mock_get.return_value = mock_response(
            csp_meta="script-src 'self'"
        )

        result = tester._extract_csp(mock_get.return_value)

        assert result.has_csp is True
        assert result.csp_meta == "script-src 'self'"

    @patch('requests.get')
    def test_extract_report_only_header(self, mock_get, tester, mock_response):
        """Test extracting CSP-Report-Only header."""
        mock_get.return_value = mock_response(
            csp_header="default-src 'self'",
            report_only="script-src 'none'"
        )

        result = tester._extract_csp(mock_get.return_value)

        assert result.report_only == "script-src 'none'"

    @patch('requests.get')
    def test_extract_no_csp(self, mock_get, tester, mock_response):
        """Test page without CSP."""
        mock_get.return_value = mock_response()

        result = tester._extract_csp(mock_get.return_value)

        assert result.has_csp is False
        assert result.csp_header is None

    @patch('requests.get')
    def test_prefer_header_over_meta(self, mock_get, tester, mock_response):
        """Test that header CSP is preferred over meta tag."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        mock_get.return_value = mock_response(
            csp_header="default-src 'self'",
            csp_meta="script-src 'unsafe-inline'"
        )

        result = tester._extract_csp(mock_get.return_value)

        # Should parse the header, not the meta
        assert 'default-src' in result.directives


# ============================================================================
# CSP Parsing Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestCSPParsing:
    """Test CSP string parsing."""

    def test_parse_simple_csp(self, tester):
        """Test parsing simple CSP."""
        csp = "default-src 'self'"
        directives = tester._parse_csp(csp)

        assert 'default-src' in directives
        assert directives['default-src'] == ["'self'"]

    def test_parse_multiple_directives(self, tester):
        """Test parsing multiple directives."""
        csp = "default-src 'self'; script-src 'unsafe-inline'; style-src https:"
        directives = tester._parse_csp(csp)

        assert len(directives) == 3
        assert 'default-src' in directives
        assert 'script-src' in directives
        assert 'style-src' in directives

    def test_parse_multiple_sources(self, tester):
        """Test parsing directive with multiple sources."""
        csp = "script-src 'self' 'unsafe-inline' https://cdn.example.com"
        directives = tester._parse_csp(csp)

        assert len(directives['script-src']) == 3
        assert "'self'" in directives['script-src']
        assert "'unsafe-inline'" in directives['script-src']
        assert "https://cdn.example.com" in directives['script-src']

    def test_parse_empty_directive(self, tester):
        """Test parsing CSP with empty directive."""
        csp = "default-src 'self'; ; script-src 'none'"
        directives = tester._parse_csp(csp)

        assert 'default-src' in directives
        assert 'script-src' in directives

    def test_parse_directive_without_sources(self, tester):
        """Test parsing directive without sources."""
        csp = "upgrade-insecure-requests"
        directives = tester._parse_csp(csp)

        assert 'upgrade-insecure-requests' in directives
        assert directives['upgrade-insecure-requests'] == []


# ============================================================================
# Unsafe Directives Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestUnsafeDirectives:
    """Test unsafe-inline and unsafe-eval detection."""

    @patch('requests.get')
    def test_unsafe_inline_in_script_src(self, mock_get, tester, mock_response):
        """Test detection of unsafe-inline in script-src."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' 'unsafe-inline'"
        )

        findings = tester.run_all_tests()

        unsafe_inline_findings = [f for f in findings if f.vuln_type == CSPVulnType.UNSAFE_INLINE]
        assert len(unsafe_inline_findings) >= 1
        assert unsafe_inline_findings[0].severity == CSPSeverity.HIGH
        assert 'script-src' in unsafe_inline_findings[0].title

    @patch('requests.get')
    def test_unsafe_eval_in_script_src(self, mock_get, tester, mock_response):
        """Test detection of unsafe-eval in script-src."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' 'unsafe-eval'"
        )

        findings = tester.run_all_tests()

        unsafe_eval_findings = [f for f in findings if f.vuln_type == CSPVulnType.UNSAFE_EVAL]
        assert len(unsafe_eval_findings) >= 1
        assert unsafe_eval_findings[0].severity == CSPSeverity.HIGH

    @patch('requests.get')
    def test_unsafe_inline_in_style_src(self, mock_get, tester, mock_response):
        """Test detection of unsafe-inline in style-src."""
        mock_get.return_value = mock_response(
            csp_header="style-src 'unsafe-inline'"
        )

        findings = tester.run_all_tests()

        unsafe_inline_findings = [f for f in findings if f.vuln_type == CSPVulnType.UNSAFE_INLINE]
        assert len(unsafe_inline_findings) >= 1
        assert 'style-src' in unsafe_inline_findings[0].title

    @patch('requests.get')
    def test_unsafe_inline_in_default_src(self, mock_get, tester, mock_response):
        """Test detection of unsafe-inline in default-src."""
        mock_get.return_value = mock_response(
            csp_header="default-src 'unsafe-inline'"
        )

        findings = tester.run_all_tests()

        unsafe_inline_findings = [f for f in findings if f.vuln_type == CSPVulnType.UNSAFE_INLINE]
        assert len(unsafe_inline_findings) >= 1

    @patch('requests.get')
    def test_no_unsafe_findings_with_safe_csp(self, mock_get, tester, mock_response):
        """Test that no unsafe findings for safe CSP."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' 'nonce-abc123'"
        )

        findings = tester.run_all_tests()

        unsafe_findings = [f for f in findings if f.vuln_type in [CSPVulnType.UNSAFE_INLINE, CSPVulnType.UNSAFE_EVAL]]
        assert len([f for f in unsafe_findings if 'unsafe' in f.title.lower()]) == 0


# ============================================================================
# Weak Sources Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestWeakSources:
    """Test weak source detection."""

    @patch('requests.get')
    def test_wildcard_source(self, mock_get, tester, mock_response):
        """Test detection of wildcard source (*)."""
        mock_get.return_value = mock_response(
            csp_header="script-src *"
        )

        findings = tester.run_all_tests()

        weak_findings = [f for f in findings if f.vuln_type == CSPVulnType.OVERLY_PERMISSIVE]
        assert len(weak_findings) >= 1
        assert weak_findings[0].severity == CSPSeverity.CRITICAL
        assert weak_findings[0].source == '*'

    @patch('requests.get')
    def test_http_scheme_source(self, mock_get, tester, mock_response):
        """Test detection of http: scheme."""
        mock_get.return_value = mock_response(
            csp_header="script-src http:"
        )

        findings = tester.run_all_tests()

        weak_findings = [f for f in findings if f.vuln_type == CSPVulnType.OVERLY_PERMISSIVE]
        assert len(weak_findings) >= 1
        assert any(f.source == 'http:' for f in weak_findings)

    @patch('requests.get')
    def test_https_scheme_source(self, mock_get, tester, mock_response):
        """Test detection of https: scheme."""
        mock_get.return_value = mock_response(
            csp_header="script-src https:"
        )

        findings = tester.run_all_tests()

        weak_findings = [f for f in findings if f.vuln_type == CSPVulnType.OVERLY_PERMISSIVE]
        assert len(weak_findings) >= 1
        assert any(f.source == 'https:' for f in weak_findings)

    @patch('requests.get')
    def test_data_uri_source(self, mock_get, tester, mock_response):
        """Test detection of data: URIs."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' data:"
        )

        findings = tester.run_all_tests()

        weak_findings = [f for f in findings if f.vuln_type == CSPVulnType.OVERLY_PERMISSIVE]
        assert len(weak_findings) >= 1
        assert any(f.source == 'data:' for f in weak_findings)

    @patch('requests.get')
    def test_blob_uri_source(self, mock_get, tester, mock_response):
        """Test detection of blob: URIs."""
        mock_get.return_value = mock_response(
            csp_header="script-src blob:"
        )

        findings = tester.run_all_tests()

        weak_findings = [f for f in findings if f.vuln_type == CSPVulnType.OVERLY_PERMISSIVE]
        assert len(weak_findings) >= 1
        assert any(f.source == 'blob:' for f in weak_findings)


# ============================================================================
# Missing Directives Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestMissingDirectives:
    """Test missing critical directive detection."""

    @patch('requests.get')
    def test_missing_base_uri(self, mock_get, tester, mock_response):
        """Test detection of missing base-uri."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self'"
        )

        findings = tester.run_all_tests()

        missing_findings = [f for f in findings if f.vuln_type == CSPVulnType.MISSING_DIRECTIVE and f.directive == 'base-uri']
        assert len(missing_findings) == 1
        assert missing_findings[0].severity == CSPSeverity.HIGH

    @patch('requests.get')
    def test_missing_object_src(self, mock_get, tester, mock_response):
        """Test detection of missing object-src."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self'"
        )

        findings = tester.run_all_tests()

        missing_findings = [f for f in findings if f.vuln_type == CSPVulnType.MISSING_DIRECTIVE and f.directive == 'object-src']
        assert len(missing_findings) == 1
        assert missing_findings[0].severity == CSPSeverity.MEDIUM

    @patch('requests.get')
    def test_missing_script_src_without_default(self, mock_get, tester, mock_response):
        """Test detection of missing script-src without default-src."""
        mock_get.return_value = mock_response(
            csp_header="style-src 'self'"
        )

        findings = tester.run_all_tests()

        missing_findings = [f for f in findings if f.vuln_type == CSPVulnType.MISSING_DIRECTIVE and f.directive == 'script-src']
        assert len(missing_findings) == 1

    @patch('requests.get')
    def test_missing_frame_ancestors(self, mock_get, tester, mock_response):
        """Test detection of missing frame-ancestors."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self'"
        )

        findings = tester.run_all_tests()

        missing_findings = [f for f in findings if f.vuln_type == CSPVulnType.MISSING_DIRECTIVE and f.directive == 'frame-ancestors']
        assert len(missing_findings) == 1

    @patch('requests.get')
    def test_no_missing_with_default_src(self, mock_get, tester, mock_response):
        """Test that default-src covers some missing directives."""
        mock_get.return_value = mock_response(
            csp_header="default-src 'self'; base-uri 'self'"
        )

        findings = tester.run_all_tests()

        # Should not report script-src as missing since default-src is present
        missing_script = [f for f in findings if f.vuln_type == CSPVulnType.MISSING_DIRECTIVE and f.directive == 'script-src']
        assert len(missing_script) == 0


# ============================================================================
# JSONP Bypass Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestJSONPBypass:
    """Test JSONP endpoint bypass detection."""

    @patch('requests.get')
    def test_jsonp_direct_domain_match(self, mock_get, tester, mock_response):
        """Test detection of directly allowed JSONP domain."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' https://www.google.com"
        )

        findings = tester.run_all_tests()

        jsonp_findings = [f for f in findings if f.vuln_type == CSPVulnType.JSONP_BYPASS]
        assert len(jsonp_findings) >= 1
        assert 'google.com' in jsonp_findings[0].description

    @patch('requests.get')
    def test_jsonp_wildcard_match(self, mock_get, tester, mock_response):
        """Test detection of JSONP via wildcard pattern."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' https://*.google.com"
        )

        findings = tester.run_all_tests()

        jsonp_findings = [f for f in findings if f.vuln_type == CSPVulnType.JSONP_BYPASS]
        assert len(jsonp_findings) >= 1

    @patch('requests.get')
    def test_jsonp_yandex(self, mock_get, tester, mock_response):
        """Test detection of Yandex JSONP endpoint."""
        mock_get.return_value = mock_response(
            csp_header="script-src https://suggest.yandex.com"
        )

        findings = tester.run_all_tests()

        jsonp_findings = [f for f in findings if f.vuln_type == CSPVulnType.JSONP_BYPASS]
        assert len(jsonp_findings) >= 1

    @patch('requests.get')
    def test_no_jsonp_with_safe_domains(self, mock_get, tester, mock_response):
        """Test that no JSONP findings for safe domains."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' https://cdn.example.com"
        )

        findings = tester.run_all_tests()

        jsonp_findings = [f for f in findings if f.vuln_type == CSPVulnType.JSONP_BYPASS]
        # Should not find JSONP issues for example.com
        assert len(jsonp_findings) == 0


# ============================================================================
# Base-URI Bypass Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestBaseURIBypass:
    """Test base-uri bypass detection."""

    @patch('requests.get')
    def test_base_uri_bypass_with_relative_urls(self, mock_get, tester, mock_response):
        """Test detection of base-uri bypass with relative URLs."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        html = """<html>
<head><script src="app.js"></script></head>
<body><script src="utils.js"></script></body>
</html>"""

        mock_get.return_value = mock_response(
            csp_header="script-src 'self'",
            html_content=html
        )

        findings = tester.run_all_tests()

        base_uri_findings = [f for f in findings if f.vuln_type == CSPVulnType.BASE_URI_BYPASS]
        assert len(base_uri_findings) == 1
        assert base_uri_findings[0].severity == CSPSeverity.HIGH
        assert 'app.js' in base_uri_findings[0].metadata['relative_urls']

    @patch('requests.get')
    def test_no_base_uri_bypass_with_absolute_urls(self, mock_get, tester, mock_response):
        """Test that no base-uri bypass with absolute URLs."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        html = """<html>
<head><script src="https://cdn.example.com/app.js"></script></head>
<body><script src="/js/utils.js"></script></body>
</html>"""

        mock_get.return_value = mock_response(
            csp_header="script-src 'self' https://cdn.example.com",
            html_content=html
        )

        findings = tester.run_all_tests()

        base_uri_findings = [f for f in findings if f.vuln_type == CSPVulnType.BASE_URI_BYPASS]
        # No truly relative URLs (/ prefix or full URL)
        assert len(base_uri_findings) == 0

    @patch('requests.get')
    def test_no_base_uri_bypass_when_directive_present(self, mock_get, tester, mock_response):
        """Test that no finding when base-uri is present."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        html = """<html><head><script src="app.js"></script></head></html>"""

        mock_get.return_value = mock_response(
            csp_header="script-src 'self'; base-uri 'self'",
            html_content=html
        )

        findings = tester.run_all_tests()

        base_uri_findings = [f for f in findings if f.vuln_type == CSPVulnType.BASE_URI_BYPASS]
        assert len(base_uri_findings) == 0


# ============================================================================
# Nonce Implementation Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestNonceImplementation:
    """Test nonce implementation weakness detection."""

    @patch('requests.get')
    def test_static_nonce_detection(self, mock_get, tester, mock_response):
        """Test detection of static nonce."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        html = """<html>
<head><script nonce="abc123">console.log('test');</script></head>
</html>"""

        # Return same nonce for all requests
        mock_get.return_value = mock_response(
            csp_header="script-src 'nonce-abc123'",
            html_content=html
        )

        findings = tester.run_all_tests()

        static_nonce_findings = [f for f in findings if f.vuln_type == CSPVulnType.STATIC_NONCE]
        assert len(static_nonce_findings) == 1
        assert static_nonce_findings[0].severity == CSPSeverity.CRITICAL
        assert 'abc123' in static_nonce_findings[0].description

    @patch('requests.get')
    def test_weak_nonce_detection(self, mock_get, tester, mock_response):
        """Test detection of weak (short) nonce."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        html_templates = [
            '<html><head><script nonce="abc1">test</script></head></html>',
            '<html><head><script nonce="abc2">test</script></head></html>',
            '<html><head><script nonce="abc3">test</script></head></html>',
        ]

        responses = [
            mock_response(csp_header="script-src 'nonce-abc1'", html_content=html_templates[0]),
            mock_response(csp_header="script-src 'nonce-abc2'", html_content=html_templates[1]),
            mock_response(csp_header="script-src 'nonce-abc3'", html_content=html_templates[2]),
        ]

        mock_get.side_effect = responses

        findings = tester.run_all_tests()

        weak_nonce_findings = [f for f in findings if f.vuln_type == CSPVulnType.WEAK_NONCE]
        assert len(weak_nonce_findings) >= 1
        assert weak_nonce_findings[0].severity == CSPSeverity.MEDIUM

    @patch('requests.get')
    def test_no_nonce_findings_without_nonce_usage(self, mock_get, tester, mock_response):
        """Test that no nonce findings when nonces not used."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self'"
        )

        findings = tester.run_all_tests()

        nonce_findings = [f for f in findings if f.vuln_type in [CSPVulnType.STATIC_NONCE, CSPVulnType.WEAK_NONCE]]
        assert len(nonce_findings) == 0


# ============================================================================
# Wildcard Subdomain Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestWildcardSubdomains:
    """Test wildcard subdomain risk detection."""

    @patch('requests.get')
    def test_wildcard_subdomain_detection(self, mock_get, tester, mock_response):
        """Test detection of wildcard subdomain."""
        mock_get.return_value = mock_response(
            csp_header="script-src https://*.example.com"
        )

        findings = tester.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == CSPVulnType.WILDCARD_SUBDOMAIN]
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0].severity == CSPSeverity.MEDIUM
        assert 'example.com' in wildcard_findings[0].metadata['base_domain']

    @patch('requests.get')
    def test_wildcard_with_protocol(self, mock_get, tester, mock_response):
        """Test detection of wildcard with explicit protocol."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self' https://*.cdn.example.com"
        )

        findings = tester.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == CSPVulnType.WILDCARD_SUBDOMAIN]
        assert len(wildcard_findings) >= 1

    @patch('requests.get')
    def test_no_wildcard_with_explicit_subdomain(self, mock_get, tester, mock_response):
        """Test that explicit subdomain is not flagged."""
        mock_get.return_value = mock_response(
            csp_header="script-src https://cdn.example.com"
        )

        findings = tester.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == CSPVulnType.WILDCARD_SUBDOMAIN]
        assert len(wildcard_findings) == 0


# ============================================================================
# Protocol Downgrade Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestProtocolDowngrade:
    """Test protocol downgrade vulnerability detection."""

    @patch('requests.get')
    def test_http_scheme_on_https_page(self, mock_get, tester, mock_response):
        """Test detection of http: scheme on HTTPS page."""
        mock_get.return_value = mock_response(
            csp_header="script-src http:"
        )

        findings = tester.run_all_tests()

        downgrade_findings = [f for f in findings if f.vuln_type == CSPVulnType.PROTOCOL_DOWNGRADE]
        assert len(downgrade_findings) >= 1
        assert downgrade_findings[0].severity == CSPSeverity.MEDIUM

    @patch('requests.get')
    def test_http_url_on_https_page(self, mock_get, tester, mock_response):
        """Test detection of HTTP URL on HTTPS page."""
        mock_get.return_value = mock_response(
            csp_header="script-src http://cdn.example.com"
        )

        findings = tester.run_all_tests()

        downgrade_findings = [f for f in findings if f.vuln_type == CSPVulnType.PROTOCOL_DOWNGRADE]
        assert len(downgrade_findings) >= 1

    @patch('requests.get')
    def test_no_protocol_downgrade_on_http_page(self, mock_get, mock_response):
        """Test that no protocol downgrade on HTTP page."""
        tester = ContentSecurityPolicyTester(target_url="http://example.com")

        mock_get.return_value = mock_response(
            csp_header="script-src http://cdn.example.com"
        )

        findings = tester.run_all_tests()

        downgrade_findings = [f for f in findings if f.vuln_type == CSPVulnType.PROTOCOL_DOWNGRADE]
        assert len(downgrade_findings) == 0


# ============================================================================
# Full Test Suite Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestFullTestSuite:
    """Test running complete test suite."""

    @patch('requests.get')
    def test_run_all_tests_with_vulnerable_csp(self, mock_get, tester, mock_response):
        """Test full test suite with vulnerable CSP."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'unsafe-inline' * http:"
        )

        findings = tester.run_all_tests()

        assert len(findings) > 0
        assert tester.test_result.is_vulnerable is True
        assert len(tester.test_result.vulnerability_types) > 0

    @patch('requests.get')
    def test_run_all_tests_with_secure_csp(self, mock_get, tester, mock_response):
        """Test full test suite with secure CSP."""
        mock_get.return_value = mock_response(
            csp_header="default-src 'none'; script-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'"
        )

        findings = tester.run_all_tests()

        # Should have minimal findings (maybe missing form-action)
        critical_high = [f for f in findings if f.severity in [CSPSeverity.CRITICAL, CSPSeverity.HIGH]]
        assert len(critical_high) == 0

    @patch('requests.get')
    def test_run_all_tests_without_csp(self, mock_get, tester, mock_response):
        """Test full test suite when no CSP present."""
        mock_get.return_value = mock_response()

        findings = tester.run_all_tests()

        assert len(findings) == 0
        assert tester.test_result.has_csp is False

    @patch('requests.get')
    def test_run_all_tests_stores_findings(self, mock_get, tester, mock_response):
        """Test that findings are stored in tester instance."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'unsafe-inline'"
        )

        returned_findings = tester.run_all_tests()

        assert len(tester.findings) == len(returned_findings)
        assert tester.findings == returned_findings


# ============================================================================
# Finding Management Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestFindingManagement:
    """Test finding management methods."""

    def test_get_findings_by_severity(self, tester):
        """Test filtering findings by severity."""
        tester.findings = [
            CSPFinding(
                title="Critical",
                severity=CSPSeverity.CRITICAL,
                vuln_type=CSPVulnType.STATIC_NONCE,
                description="Test",
                endpoint=tester.target_url
            ),
            CSPFinding(
                title="High",
                severity=CSPSeverity.HIGH,
                vuln_type=CSPVulnType.UNSAFE_INLINE,
                description="Test",
                endpoint=tester.target_url
            ),
        ]

        critical = tester.get_findings_by_severity(CSPSeverity.CRITICAL)
        high = tester.get_findings_by_severity(CSPSeverity.HIGH)

        assert len(critical) == 1
        assert len(high) == 1

    def test_get_critical_findings(self, tester):
        """Test getting only critical findings."""
        tester.findings = [
            CSPFinding(
                title="Critical",
                severity=CSPSeverity.CRITICAL,
                vuln_type=CSPVulnType.STATIC_NONCE,
                description="Test",
                endpoint=tester.target_url
            ),
        ]

        critical = tester.get_critical_findings()

        assert len(critical) == 1
        assert critical[0].severity == CSPSeverity.CRITICAL


# ============================================================================
# Summary Generation Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestSummaryGeneration:
    """Test summary report generation."""

    @patch('requests.get')
    def test_get_summary_structure(self, mock_get, tester, mock_response):
        """Test summary report structure."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'self'"
        )

        tester.run_all_tests()
        summary = tester.get_summary()

        assert 'target' in summary
        assert 'has_csp' in summary
        assert 'total_findings' in summary
        assert 'severity_breakdown' in summary
        assert 'vulnerable' in summary
        assert 'findings' in summary

    @patch('requests.get')
    def test_get_summary_severity_breakdown(self, mock_get, tester, mock_response):
        """Test severity breakdown in summary."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'unsafe-inline' *"
        )

        tester.run_all_tests()
        summary = tester.get_summary()
        breakdown = summary['severity_breakdown']

        assert 'CRITICAL' in breakdown
        assert 'HIGH' in breakdown
        assert 'MEDIUM' in breakdown
        assert 'LOW' in breakdown
        assert 'INFO' in breakdown

    @patch('requests.get')
    def test_get_summary_vulnerable_flag(self, mock_get, tester, mock_response):
        """Test vulnerable flag is set correctly."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'unsafe-inline'"
        )

        tester.run_all_tests()
        summary = tester.get_summary()

        assert summary['vulnerable'] is True

    @patch('requests.get')
    def test_get_summary_not_vulnerable(self, mock_get, tester, mock_response):
        """Test vulnerable flag when no findings."""
        mock_get.return_value = mock_response(
            csp_header="default-src 'none'; script-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'"
        )

        tester.run_all_tests()
        summary = tester.get_summary()

        assert summary['vulnerable'] is False


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestPOCGeneration:
    """Test POC generation methods."""

    def test_generate_unsafe_inline_script_poc(self, tester):
        """Test POC generation for unsafe-inline in script-src."""
        poc = tester._generate_unsafe_inline_poc('script-src')

        assert 'img' in poc or 'svg' in poc
        assert 'onerror' in poc or 'onload' in poc

    def test_generate_unsafe_inline_style_poc(self, tester):
        """Test POC generation for unsafe-inline in style-src."""
        poc = tester._generate_unsafe_inline_poc('style-src')

        assert 'style' in poc
        assert 'body' in poc

    def test_generate_unsafe_eval_poc(self, tester):
        """Test POC generation for unsafe-eval."""
        poc = tester._generate_unsafe_eval_poc()

        assert 'eval' in poc
        assert 'setTimeout' in poc or 'Function' in poc

    def test_generate_weak_source_wildcard_poc(self, tester):
        """Test POC generation for wildcard source."""
        poc = tester._generate_weak_source_poc('script-src', '*')

        assert 'evil.com' in poc
        assert 'script' in poc

    def test_generate_weak_source_data_poc(self, tester):
        """Test POC generation for data: source."""
        poc = tester._generate_weak_source_poc('script-src', 'data:')

        assert 'data:' in poc

    def test_generate_missing_base_uri_poc(self, tester):
        """Test POC generation for missing base-uri."""
        poc = tester._generate_missing_directive_poc('base-uri')

        assert 'base' in poc
        assert 'href' in poc

    def test_generate_jsonp_poc(self, tester):
        """Test POC generation for JSONP bypass."""
        poc = tester._generate_jsonp_poc('www.google.com', '/api?callback={callback}')

        assert 'google.com' in poc
        assert 'script' in poc

    def test_generate_base_uri_bypass_poc(self, tester):
        """Test POC generation for base-uri bypass."""
        poc = tester._generate_base_uri_poc(['app.js', 'utils.js'])

        assert 'base' in poc
        assert 'app.js' in poc

    def test_generate_static_nonce_poc(self, tester):
        """Test POC generation for static nonce."""
        poc = tester._generate_static_nonce_poc('abc123')

        assert 'abc123' in poc
        assert 'nonce' in poc

    def test_generate_wildcard_poc(self, tester):
        """Test POC generation for wildcard subdomain."""
        poc = tester._generate_wildcard_poc('*.example.com', 'example.com')

        assert 'example.com' in poc

    def test_generate_protocol_downgrade_poc(self, tester):
        """Test POC generation for protocol downgrade."""
        poc = tester._generate_protocol_downgrade_poc('http:')

        assert 'http' in poc


# ============================================================================
# Data Conversion Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestDataConversion:
    """Test data conversion methods."""

    def test_csp_finding_to_dict(self):
        """Test CSPFinding to dict conversion."""
        finding = CSPFinding(
            title="Test",
            severity=CSPSeverity.HIGH,
            vuln_type=CSPVulnType.UNSAFE_INLINE,
            description="Test description",
            endpoint="https://example.com",
            directive="script-src"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['title'] == "Test"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['vuln_type'] == "CSP_UNSAFE_INLINE"

    def test_csp_test_result_to_dict(self):
        """Test CSPTestResult to dict conversion."""
        result = CSPTestResult(
            endpoint="https://example.com",
            has_csp=True,
            csp_header="default-src 'self'",
            is_vulnerable=True,
            vulnerability_types=[CSPVulnType.UNSAFE_INLINE, CSPVulnType.MISSING_DIRECTIVE]
        )

        result_dict = result.to_dict()

        assert result_dict['has_csp'] is True
        assert 'CSP_UNSAFE_INLINE' in result_dict['vulnerability_types']


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not CSP_TESTER_AVAILABLE, reason="CSP tester not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_finding_with_default_date(self):
        """Test that finding gets default date."""
        finding = CSPFinding(
            title="Test",
            severity=CSPSeverity.HIGH,
            vuln_type=CSPVulnType.UNSAFE_INLINE,
            description="Test",
            endpoint="https://example.com"
        )

        assert finding.discovered_date == date.today().isoformat()

    @patch('requests.get')
    def test_handles_request_failure(self, mock_get, tester):
        """Test handling of failed HTTP request."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        findings = tester.run_all_tests()

        assert len(findings) == 0

    @patch('requests.get')
    def test_handles_malformed_html(self, mock_get, tester, mock_response):
        """Test handling of malformed HTML."""
        if not BS4_AVAILABLE:
            pytest.skip("BeautifulSoup not available")

        mock_get.return_value = mock_response(
            csp_header="script-src 'self'",
            html_content="<html><head><script src="
        )

        # Should not crash
        findings = tester.run_all_tests()
        assert isinstance(findings, list)

    def test_extract_base_domain_from_single_part(self, tester):
        """Test base domain extraction from single part domain."""
        result = tester._extract_base_domain("localhost")

        assert result is None

    def test_parse_empty_csp(self, tester):
        """Test parsing empty CSP string."""
        directives = tester._parse_csp("")

        assert len(directives) == 0

    @patch('requests.get')
    def test_multiple_same_severity_findings(self, mock_get, tester, mock_response):
        """Test handling multiple findings of same severity."""
        mock_get.return_value = mock_response(
            csp_header="script-src 'unsafe-inline' 'unsafe-eval' http:"
        )

        findings = tester.run_all_tests()

        high_findings = tester.get_findings_by_severity(CSPSeverity.HIGH)
        assert len(high_findings) >= 2
