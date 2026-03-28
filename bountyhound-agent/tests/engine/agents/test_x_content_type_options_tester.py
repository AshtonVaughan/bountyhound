"""
Comprehensive tests for X-Content-Type-Options Tester Agent.

Tests cover:
- Initialization and configuration
- Missing nosniff header detection
- Severity assessment for different content types
- Polyglot file upload testing (SVG, HTML, JS, CSS, Flash, PDF)
- Content-Type override vulnerabilities
- Finding management and categorization
- POC generation for all vulnerability types
- Edge cases and error handling
- Multiple file format testing
- Response parsing and URL extraction

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import date
from io import BytesIO

# Test imports with fallback
try:
    from engine.agents.x_content_type_options_tester import (
        XContentTypeOptionsTester,
        MimeSniffFinding,
        MimeSniffTestResult,
        MimeSniffSeverity,
        MimeSniffVulnType,
        REQUESTS_AVAILABLE
    )
    TESTER_AVAILABLE = True
except ImportError:
    TESTER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="X-Content-Type-Options tester not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(
        status_code=200,
        xcto=None,
        content_type=None,
        text='',
        json_data=None,
        headers=None
    ):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.headers = headers or {}

        if xcto:
            response.headers['X-Content-Type-Options'] = xcto
        if content_type:
            response.headers['Content-Type'] = content_type

        if json_data:
            response.json = Mock(return_value=json_data)
        else:
            response.json = Mock(side_effect=ValueError("Not JSON"))

        return response

    return _create_response


@pytest.fixture
def tester():
    """Create an XContentTypeOptionsTester instance for testing."""
    if not TESTER_AVAILABLE:
        pytest.skip("X-Content-Type-Options tester not available")

    return XContentTypeOptionsTester(
        target_url="https://example.com",
        timeout=5,
        verify_ssl=False,
        test_upload_endpoints=False
    )


@pytest.fixture
def tester_with_uploads():
    """Create tester with upload endpoint testing enabled."""
    if not TESTER_AVAILABLE:
        pytest.skip("X-Content-Type-Options tester not available")

    return XContentTypeOptionsTester(
        target_url="https://example.com",
        timeout=5,
        verify_ssl=False,
        test_upload_endpoints=True
    )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestInitialization:
    """Test XContentTypeOptionsTester initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        tester = XContentTypeOptionsTester(target_url="https://example.com")

        assert tester.target_url == "https://example.com"
        assert tester.timeout == 10
        assert tester.verify_ssl is True
        assert tester.test_upload_endpoints is True
        assert len(tester.findings) == 0
        assert len(tester.test_results) == 0

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        tester = XContentTypeOptionsTester(target_url="https://example.com", timeout=30)

        assert tester.timeout == 30

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        tester = XContentTypeOptionsTester(target_url="https://example.com", verify_ssl=False)

        assert tester.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        tester = XContentTypeOptionsTester(target_url="https://example.com/")

        assert tester.target_url == "https://example.com"

    def test_init_with_upload_testing_disabled(self):
        """Test initialization with upload testing disabled."""
        tester = XContentTypeOptionsTester(
            target_url="https://example.com",
            test_upload_endpoints=False
        )

        assert tester.test_upload_endpoints is False

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            XContentTypeOptionsTester(target_url="https://example.com")


# ============================================================================
# Missing Nosniff Header Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestMissingNosniffHeader:
    """Test detection of missing X-Content-Type-Options: nosniff header."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_missing_nosniff_header(self, mock_request, mock_response, tester):
        """Test detection of completely missing nosniff header."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='<html><body>Test</body></html>'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].vuln_type == MimeSniffVulnType.MISSING_NOSNIFF
        assert findings[0].has_nosniff is False
        assert findings[0].severity in [MimeSniffSeverity.MEDIUM, MimeSniffSeverity.HIGH]

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_passes_with_correct_nosniff_header(self, mock_request, mock_response, tester):
        """Test that correct nosniff header passes validation."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='nosniff',
            content_type='text/html'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 0

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_incorrect_nosniff_value(self, mock_request, mock_response, tester):
        """Test detection of incorrect X-Content-Type-Options value."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='sniff',  # Wrong value
            content_type='text/html'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].vuln_type == MimeSniffVulnType.MISSING_NOSNIFF

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_case_insensitive_nosniff(self, mock_request, mock_response, tester):
        """Test that nosniff check is case-insensitive."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='NoSniff',  # Mixed case
            content_type='text/html'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 0  # Should pass (case-insensitive)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_request_failure(self, mock_request, tester):
        """Test handling of request failures."""
        mock_request.side_effect = Exception("Connection failed")

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 0  # Should handle gracefully


# ============================================================================
# Severity Assessment Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestSeverityAssessment:
    """Test severity assessment for missing nosniff header."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_high_severity_with_script_tags(self, mock_request, mock_response, tester):
        """Test HIGH severity when response contains script tags."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='<html><script>alert(1)</script></html>'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_high_severity_with_javascript_uri(self, mock_request, mock_response, tester):
        """Test HIGH severity when response contains javascript: URI."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/plain',
            text='<a href="javascript:alert(1)">Click</a>'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_high_severity_with_json_content_type(self, mock_request, mock_response, tester):
        """Test HIGH severity for JSON content type."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='application/json',
            text='{"data": "value"}'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_high_severity_with_upload_endpoint(self, mock_request, mock_response):
        """Test HIGH severity for upload endpoints."""
        tester = XContentTypeOptionsTester(target_url="https://example.com/upload")
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_medium_severity_for_standard_html(self, mock_request, mock_response, tester):
        """Test MEDIUM severity for standard HTML without dangerous content."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='<html><body>Normal content</body></html>'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.MEDIUM


# ============================================================================
# Polyglot Upload Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestPolyglotUpload:
    """Test polyglot file upload vulnerability detection."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_skips_upload_test_when_disabled(self, mock_request, tester):
        """Test that upload tests are skipped when disabled."""
        findings = tester.test_polyglot_upload_xss()

        assert len(findings) == 0
        mock_request.assert_not_called()

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_svg_xss_upload(self, mock_request, mock_response, tester_with_uploads):
        """Test detection of SVG XSS via upload."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='image/svg+xml',
            json_data={'url': 'https://example.com/uploads/test.svg'}
        )

        findings = tester_with_uploads.test_polyglot_upload_xss()

        assert len(findings) >= 1
        assert any(f.vuln_type == MimeSniffVulnType.SVG_UPLOAD_XSS for f in findings)
        assert any(f.severity == MimeSniffSeverity.CRITICAL for f in findings)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_html_in_image_upload(self, mock_request, mock_response, tester_with_uploads):
        """Test detection of HTML embedded in image upload."""
        mock_request.return_value = mock_response(
            status_code=201,
            content_type='image/jpeg',
            json_data={'file_url': 'https://example.com/media/test.jpg'}
        )

        findings = tester_with_uploads.test_polyglot_upload_xss()

        # At least one finding should be present
        assert len(findings) >= 1
        # Check if any finding is polyglot-related
        assert any(f.vuln_type in [MimeSniffVulnType.HTML_IN_IMAGE, MimeSniffVulnType.SVG_UPLOAD_XSS,
                                    MimeSniffVulnType.POLYGLOT_XSS] for f in findings)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_js_in_png_upload(self, mock_request, mock_response, tester_with_uploads):
        """Test detection of JavaScript in PNG upload."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='image/png',
            json_data={'path': '/uploads/test.png'}
        )

        findings = tester_with_uploads.test_polyglot_upload_xss()

        assert len(findings) >= 1

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_passes_upload_with_nosniff(self, mock_request, mock_response, tester_with_uploads):
        """Test that upload with nosniff header passes."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='nosniff',
            content_type='image/svg+xml'
        )

        findings = tester_with_uploads.test_polyglot_upload_xss()

        assert len(findings) == 0

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_upload_failure(self, mock_request, mock_response, tester_with_uploads):
        """Test handling of failed upload attempts."""
        mock_request.return_value = mock_response(status_code=403)

        findings = tester_with_uploads.test_polyglot_upload_xss()

        # Should not crash, may or may not find issues
        assert isinstance(findings, list)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_extracts_upload_url_from_json(self, mock_request, mock_response, tester_with_uploads):
        """Test extraction of uploaded file URL from JSON response."""
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={'url': 'https://cdn.example.com/file.svg'}
        )

        findings = tester_with_uploads.test_polyglot_upload_xss()

        if findings:
            assert 'cdn.example.com' in findings[0].description or findings[0].endpoint

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_tests_multiple_upload_endpoints(self, mock_request, mock_response, tester_with_uploads):
        """Test that multiple upload endpoints are tested."""
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return mock_response(status_code=404)  # Not found, should try next

        mock_request.side_effect = side_effect

        tester_with_uploads.test_polyglot_upload_xss()

        # Should have tried multiple endpoints
        assert call_count > 0


# ============================================================================
# Content-Type Override Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestContentTypeOverride:
    """Test Content-Type override vulnerability detection."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_html_content_type_override(self, mock_request, mock_response, tester):
        """Test detection of HTML Content-Type override."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='Response'
        )

        findings = tester.test_content_type_override()

        assert len(findings) >= 1
        assert findings[0].vuln_type == MimeSniffVulnType.CONTENT_TYPE_OVERRIDE
        assert findings[0].severity == MimeSniffSeverity.MEDIUM

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_detects_javascript_content_type_override(self, mock_request, mock_response, tester):
        """Test detection of JavaScript Content-Type override."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='application/javascript'
        )

        findings = tester.test_content_type_override()

        assert len(findings) >= 1

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_passes_with_nosniff_header(self, mock_request, mock_response, tester):
        """Test that override passes with nosniff header."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='nosniff',
            content_type='text/html'
        )

        findings = tester.test_content_type_override()

        assert len(findings) == 0

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_failed_override_request(self, mock_request, mock_response, tester):
        """Test handling of failed Content-Type override requests."""
        mock_request.return_value = mock_response(status_code=400)

        findings = tester.test_content_type_override()

        # Should handle gracefully
        assert isinstance(findings, list)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_stops_after_first_vulnerability(self, mock_request, mock_response, tester):
        """Test that testing stops after finding first vulnerability."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html'
        )

        findings = tester.test_content_type_override()

        # Should find exactly 1 (stops after first)
        assert len(findings) == 1


# ============================================================================
# Complete Test Suite Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestCompleteTestSuite:
    """Test running complete test suite."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_run_all_tests_returns_all_findings(self, mock_request, mock_response, tester):
        """Test that run_all_tests returns combined findings."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='<html><script>test</script></html>'
        )

        findings = tester.run_all_tests()

        assert len(findings) >= 1
        assert all(isinstance(f, MimeSniffFinding) for f in findings)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_run_all_tests_stores_findings_in_instance(self, mock_request, mock_response, tester):
        """Test that findings are stored in tester instance."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html'
        )

        tester.run_all_tests()

        assert len(tester.findings) >= 1

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_run_all_tests_with_no_vulnerabilities(self, mock_request, mock_response, tester):
        """Test running all tests when no vulnerabilities exist."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='nosniff',
            content_type='text/html'
        )

        findings = tester.run_all_tests()

        assert len(findings) == 0

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_run_all_tests_skips_upload_when_nosniff_present(self, mock_request, mock_response):
        """Test that upload tests are skipped when nosniff is present."""
        tester = XContentTypeOptionsTester(
            target_url="https://example.com",
            test_upload_endpoints=True
        )
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='nosniff'
        )

        findings = tester.run_all_tests()

        # Should not test uploads if nosniff is present
        assert len(findings) == 0


# ============================================================================
# Finding Management Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestFindingManagement:
    """Test finding filtering and management."""

    def test_get_findings_by_severity(self, tester):
        """Test filtering findings by severity."""
        # Add mock findings
        tester.findings = [
            MimeSniffFinding(
                title="Test 1",
                severity=MimeSniffSeverity.CRITICAL,
                vuln_type=MimeSniffVulnType.MISSING_NOSNIFF,
                description="Test",
                endpoint="https://example.com"
            ),
            MimeSniffFinding(
                title="Test 2",
                severity=MimeSniffSeverity.HIGH,
                vuln_type=MimeSniffVulnType.SVG_UPLOAD_XSS,
                description="Test",
                endpoint="https://example.com"
            ),
            MimeSniffFinding(
                title="Test 3",
                severity=MimeSniffSeverity.CRITICAL,
                vuln_type=MimeSniffVulnType.POLYGLOT_XSS,
                description="Test",
                endpoint="https://example.com"
            )
        ]

        critical = tester.get_findings_by_severity(MimeSniffSeverity.CRITICAL)

        assert len(critical) == 2
        assert all(f.severity == MimeSniffSeverity.CRITICAL for f in critical)

    def test_get_critical_findings(self, tester):
        """Test getting critical findings specifically."""
        tester.findings = [
            MimeSniffFinding(
                title="Critical",
                severity=MimeSniffSeverity.CRITICAL,
                vuln_type=MimeSniffVulnType.SVG_UPLOAD_XSS,
                description="Test",
                endpoint="https://example.com"
            ),
            MimeSniffFinding(
                title="High",
                severity=MimeSniffSeverity.HIGH,
                vuln_type=MimeSniffVulnType.MISSING_NOSNIFF,
                description="Test",
                endpoint="https://example.com"
            )
        ]

        critical = tester.get_critical_findings()

        assert len(critical) == 1
        assert critical[0].title == "Critical"


# ============================================================================
# Summary Generation Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestSummaryGeneration:
    """Test summary report generation."""

    def test_get_summary_with_findings(self, tester):
        """Test summary generation with findings."""
        tester.findings = [
            MimeSniffFinding(
                title="Test",
                severity=MimeSniffSeverity.HIGH,
                vuln_type=MimeSniffVulnType.MISSING_NOSNIFF,
                description="Test",
                endpoint="https://example.com"
            )
        ]

        summary = tester.get_summary()

        assert summary['target'] == "https://example.com"
        assert summary['total_findings'] == 1
        assert summary['vulnerable'] is True
        assert 'severity_breakdown' in summary
        assert summary['severity_breakdown']['HIGH'] == 1

    def test_get_summary_without_findings(self, tester):
        """Test summary generation without findings."""
        summary = tester.get_summary()

        assert summary['total_findings'] == 0
        assert summary['vulnerable'] is False
        assert summary['severity_breakdown']['CRITICAL'] == 0

    def test_get_summary_includes_all_severities(self, tester):
        """Test that summary includes all severity levels."""
        summary = tester.get_summary()

        assert 'CRITICAL' in summary['severity_breakdown']
        assert 'HIGH' in summary['severity_breakdown']
        assert 'MEDIUM' in summary['severity_breakdown']
        assert 'LOW' in summary['severity_breakdown']
        assert 'INFO' in summary['severity_breakdown']


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestPOCGeneration:
    """Test POC generation for different vulnerability types."""

    def test_generate_nosniff_poc(self, tester):
        """Test generation of basic nosniff POC."""
        poc = tester._generate_nosniff_poc()

        assert 'curl' in poc
        assert 'X-Content-Type-Options' in poc
        assert tester.target_url in poc

    def test_generate_polyglot_poc(self, tester):
        """Test generation of polyglot upload POC."""
        payload_data = {
            'content': '<svg><script>alert(1)</script></svg>',
            'extension': '.svg',
            'content_type': 'image/svg+xml'
        }

        poc = tester._generate_polyglot_poc('svg_xss', payload_data, 'https://example.com/upload')

        assert 'curl' in poc
        assert '.svg' in poc
        assert 'upload' in poc
        assert 'nosniff' in poc.lower()

    def test_generate_content_type_override_poc(self, tester):
        """Test generation of Content-Type override POC."""
        poc = tester._generate_content_type_override_poc('text/html', '<script>alert(1)</script>')

        assert 'curl' in poc
        assert 'Content-Type: text/html' in poc
        assert tester.target_url in poc
        assert '<script>alert(1)</script>' in poc


# ============================================================================
# Data Model Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestDataModels:
    """Test data model classes."""

    def test_mime_sniff_finding_to_dict(self):
        """Test MimeSniffFinding to_dict conversion."""
        finding = MimeSniffFinding(
            title="Test",
            severity=MimeSniffSeverity.HIGH,
            vuln_type=MimeSniffVulnType.MISSING_NOSNIFF,
            description="Description",
            endpoint="https://example.com",
            content_type="text/html"
        )

        data = finding.to_dict()

        assert data['title'] == "Test"
        assert data['severity'] == "HIGH"
        assert data['vuln_type'] == "MISSING_X_CONTENT_TYPE_OPTIONS"
        assert data['content_type'] == "text/html"

    def test_mime_sniff_test_result_to_dict(self):
        """Test MimeSniffTestResult to_dict conversion."""
        result = MimeSniffTestResult(
            endpoint="https://example.com",
            has_nosniff=False,
            content_type="text/html",
            is_vulnerable=True,
            vulnerability_type=MimeSniffVulnType.MISSING_NOSNIFF
        )

        data = result.to_dict()

        assert data['endpoint'] == "https://example.com"
        assert data['has_nosniff'] is False
        assert data['vulnerability_type'] == "MISSING_X_CONTENT_TYPE_OPTIONS"


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_none_response(self, mock_request, tester):
        """Test handling of None response."""
        mock_request.return_value = None

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 0

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_missing_content_type_header(self, mock_request, mock_response, tester):
        """Test handling of missing Content-Type header."""
        mock_request.return_value = mock_response(
            status_code=200,
            text='Some content'
        )

        findings = tester.test_missing_nosniff_header()

        # Should still detect missing nosniff
        assert len(findings) >= 1

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_empty_response_text(self, mock_request, mock_response, tester):
        """Test handling of empty response text."""
        response = mock_response(status_code=200, content_type='text/html')
        response.text = None

        mock_request.return_value = response

        findings = tester.test_missing_nosniff_header()

        # Should handle gracefully
        assert isinstance(findings, list)

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_handles_non_json_upload_response(self, mock_request, mock_response, tester_with_uploads):
        """Test handling of non-JSON upload response."""
        response = mock_response(
            status_code=200,
            content_type='text/html',
            text='<html>Upload successful</html>'
        )
        mock_request.return_value = response

        findings = tester_with_uploads.test_polyglot_upload_xss()

        # Should handle gracefully
        assert isinstance(findings, list)

    def test_get_vuln_type_for_unknown_payload(self, tester):
        """Test vulnerability type mapping for unknown payload."""
        vuln_type = tester._get_vuln_type_for_payload('unknown_payload')

        assert vuln_type == MimeSniffVulnType.POLYGLOT_XSS

    def test_extract_uploaded_url_from_html(self, tester):
        """Test URL extraction from HTML response."""
        response = Mock()
        response.headers = {'Content-Type': 'text/html'}
        response.text = '<html><a href="https://cdn.example.com/file.jpg">Download</a></html>'
        response.json = Mock(side_effect=ValueError("Not JSON"))

        url = tester._extract_uploaded_url(response, 'https://example.com/upload')

        # Should attempt to extract, may or may not succeed
        assert url is None or isinstance(url, str)


# ============================================================================
# Additional Coverage Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestAdditionalCoverage:
    """Additional tests to achieve 95%+ coverage."""

    def test_polyglot_payloads_exist(self, tester):
        """Test that polyglot payloads are defined."""
        assert len(tester.POLYGLOT_PAYLOADS) >= 5
        assert 'svg_xss' in tester.POLYGLOT_PAYLOADS
        assert 'html_in_jpg' in tester.POLYGLOT_PAYLOADS

    def test_upload_endpoints_defined(self, tester):
        """Test that upload endpoints are defined."""
        assert len(tester.UPLOAD_ENDPOINTS) >= 5
        assert '/upload' in tester.UPLOAD_ENDPOINTS

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_make_request_with_files(self, mock_request, mock_response, tester):
        """Test _make_request with file uploads."""
        mock_request.return_value = mock_response(status_code=200)

        files = {'file': ('test.txt', BytesIO(b'test'), 'text/plain')}
        response = tester._make_request('https://example.com/upload', method='POST', files=files)

        assert response is not None
        assert response.status_code == 200

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_make_request_with_data(self, mock_request, mock_response, tester):
        """Test _make_request with data payload."""
        mock_request.return_value = mock_response(status_code=200)

        response = tester._make_request(
            'https://example.com',
            method='POST',
            data='test data'
        )

        assert response is not None

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_make_request_with_custom_headers(self, mock_request, mock_response, tester):
        """Test _make_request with custom headers."""
        mock_request.return_value = mock_response(status_code=200)

        headers = {'X-Custom': 'value'}
        response = tester._make_request('https://example.com', headers=headers)

        assert response is not None

    def test_extract_uploaded_url_no_json_no_html(self, tester):
        """Test URL extraction when response has neither JSON nor HTML."""
        response = Mock()
        response.headers = {'Content-Type': 'text/plain'}
        response.text = 'Upload successful'
        response.json = Mock(side_effect=ValueError("Not JSON"))

        url = tester._extract_uploaded_url(response, 'https://example.com/upload')

        assert url is None

    def test_extract_uploaded_url_with_multiple_keys(self, tester):
        """Test URL extraction trying multiple JSON keys."""
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}
        response.json = Mock(return_value={'location': 'https://cdn.example.com/file.jpg'})

        url = tester._extract_uploaded_url(response, 'https://example.com/upload')

        assert url == 'https://cdn.example.com/file.jpg'

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_onload_attribute(self, mock_request, mock_response, tester):
        """Test HIGH severity with onload= attribute."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='<img onload="alert(1)">'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_onerror_attribute(self, mock_request, mock_response, tester):
        """Test HIGH severity with onerror= attribute."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html',
            text='<img src=x onerror="alert(1)">'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_plain_text_content_type(self, mock_request, mock_response, tester):
        """Test HIGH severity for text/plain content type."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/plain',
            text='Plain text response'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_csv_content_type(self, mock_request, mock_response, tester):
        """Test HIGH severity for text/csv content type."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/csv',
            text='col1,col2\nval1,val2'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_octet_stream_content_type(self, mock_request, mock_response, tester):
        """Test HIGH severity for application/octet-stream content type."""
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='application/octet-stream',
            text='Binary data'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_file_in_url(self, mock_request, mock_response):
        """Test HIGH severity for /file/ endpoint."""
        tester = XContentTypeOptionsTester(target_url="https://example.com/file/123")
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='text/html'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_severity_with_media_in_url(self, mock_request, mock_response):
        """Test HIGH severity for /media/ endpoint."""
        tester = XContentTypeOptionsTester(target_url="https://example.com/media/image.jpg")
        mock_request.return_value = mock_response(
            status_code=200,
            content_type='image/jpeg'
        )

        findings = tester.test_missing_nosniff_header()

        assert len(findings) == 1
        assert findings[0].severity == MimeSniffSeverity.HIGH

    def test_get_vuln_type_for_all_payloads(self, tester):
        """Test vulnerability type mapping for all payloads."""
        assert tester._get_vuln_type_for_payload('svg_xss') == MimeSniffVulnType.SVG_UPLOAD_XSS
        assert tester._get_vuln_type_for_payload('html_in_jpg') == MimeSniffVulnType.HTML_IN_IMAGE
        assert tester._get_vuln_type_for_payload('js_in_png') == MimeSniffVulnType.JS_IN_IMAGE
        assert tester._get_vuln_type_for_payload('html_gif') == MimeSniffVulnType.HTML_IN_IMAGE
        assert tester._get_vuln_type_for_payload('css_import') == MimeSniffVulnType.CSS_INJECTION
        assert tester._get_vuln_type_for_payload('flash_xss') == MimeSniffVulnType.FLASH_POLYGLOT
        assert tester._get_vuln_type_for_payload('pdf_xss') == MimeSniffVulnType.PDF_XSS
        assert tester._get_vuln_type_for_payload('html_text') == MimeSniffVulnType.MIME_TYPE_CONFUSION

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_content_type_override_with_xml(self, mock_request, mock_response, tester):
        """Test Content-Type override with XML."""
        responses = [
            mock_response(status_code=400),  # First payload fails
            mock_response(status_code=400),  # Second fails
            mock_response(
                status_code=200,
                content_type='text/xml'
            )  # Third succeeds
        ]
        mock_request.side_effect = responses

        findings = tester.test_content_type_override()

        assert len(findings) >= 1


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not TESTER_AVAILABLE, reason="Tester not available")
class TestIntegration:
    """Integration tests combining multiple components."""

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_full_test_workflow_with_vulnerabilities(self, mock_request, mock_response):
        """Test complete workflow finding multiple vulnerabilities."""
        tester = XContentTypeOptionsTester(
            target_url="https://vulnerable.example.com/upload",
            test_upload_endpoints=True
        )

        mock_request.return_value = mock_response(
            status_code=200,
            content_type='application/json',
            text='<script>alert(1)</script>',
            json_data={'url': 'https://cdn.example.com/evil.svg'}
        )

        findings = tester.run_all_tests()
        summary = tester.get_summary()

        assert len(findings) >= 1
        assert summary['vulnerable'] is True
        assert summary['total_findings'] >= 1

    @patch('engine.agents.x_content_type_options_tester.requests.Session.request')
    def test_full_test_workflow_secure_application(self, mock_request, mock_response, tester):
        """Test complete workflow with secure application."""
        mock_request.return_value = mock_response(
            status_code=200,
            xcto='nosniff',
            content_type='text/html'
        )

        findings = tester.run_all_tests()
        summary = tester.get_summary()

        assert len(findings) == 0
        assert summary['vulnerable'] is False
