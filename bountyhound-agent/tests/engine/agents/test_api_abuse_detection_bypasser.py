"""
Comprehensive tests for API Abuse Detection Bypasser Agent.

Tests cover:
- Initialization and configuration
- Rate limiting bypass detection (no limits, XFF, session rotation, GraphQL aliasing, endpoint variation)
- Bot detection bypasses (User-Agent, JavaScript challenge)
- CAPTCHA bypasses (not enforced, token manipulation, automation_code)
- Fingerprinting evasion
- WAF detection
- Report generation
- POC code generation
- Finding management
- Edge cases and error handling

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from datetime import date

# Test imports with fallback
try:
    from engine.agents.api_abuse_detection_bypasser import (
        APIAbuseDetectionBypasser,
        BypassVulnerability,
        RateLimitProfile,
        BypassSeverity,
        BypassCategory,
        REQUESTS_AVAILABLE
    )
    BYPASSER_AVAILABLE = True
except ImportError:
    BYPASSER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="API Abuse Detection Bypasser not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, text="", headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.headers = headers or {}
        return response
    return _create_response


@pytest.fixture
def bypasser():
    """Create a bypasser instance for testing."""
    if not BYPASSER_AVAILABLE:
        pytest.skip("Bypasser not available")

    return APIAbuseDetectionBypasser(
        target="https://api.example.com",
        timeout=5,
        verify_ssl=False
    )


@pytest.fixture
def mock_session():
    """Create a mock session."""
    session = Mock()
    session.verify = False
    return session


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestInitialization:
    """Test bypasser initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        bypasser = APIAbuseDetectionBypasser(target="https://api.example.com")

        assert bypasser.target == "https://api.example.com"
        assert bypasser.timeout == 10
        assert bypasser.verify_ssl is True
        assert len(bypasser.discovered_bypasses) == 0
        assert len(bypasser.rate_limit_profiles) == 0

    def test_init_with_trailing_slash(self):
        """Test URL normalization with trailing slash."""
        bypasser = APIAbuseDetectionBypasser(target="https://api.example.com/")

        assert bypasser.target == "https://api.example.com"

    def test_init_with_custom_settings(self):
        """Test initialization with custom settings."""
        bypasser = APIAbuseDetectionBypasser(
            target="https://test.com",
            timeout=5,
            verify_ssl=False
        )

        assert bypasser.timeout == 5
        assert bypasser.verify_ssl is False

    def test_user_agents_loaded(self, bypasser):
        """Test that user agents are loaded."""
        assert len(bypasser.user_agents) > 0
        assert all('Mozilla' in ua for ua in bypasser.user_agents)

    def test_languages_loaded(self, bypasser):
        """Test that language headers are loaded."""
        assert len(bypasser.languages) > 0
        assert 'en-US,en;q=0.9' in bypasser.languages


# ============================================================================
# Rate Limiting Bypass Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestRateLimitingBypasses:
    """Test rate limiting bypass detection."""

    @patch('engine.agents.api_abuse_detection_bypasser.time.time')
    def test_no_rate_limiting_detected(self, mock_time, bypasser, mock_response):
        """Test detection of no rate limiting."""
        mock_time.side_effect = [0, 10]  # 10 second test duration

        # Mock session to never return 429
        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(status_code=200)

            result = bypasser._test_no_rate_limiting('/api/auth/login')

            assert result is not None
            assert result.vuln_id == "ABD-RATE-001"
            assert result.severity == BypassSeverity.CRITICAL
            assert result.category == BypassCategory.RATE_LIMITING
            assert "No Rate Limiting" in result.name
            assert len(result.evidence) > 0

    def test_no_rate_limiting_non_auth_endpoint(self, bypasser, mock_response):
        """Test no rate limiting on non-auth endpoint (lower severity)."""
        with patch('engine.agents.api_abuse_detection_bypasser.time.time', side_effect=[0, 5]):
            with patch.object(bypasser.session, 'post') as mock_post:
                mock_post.return_value = mock_response(status_code=200)

                result = bypasser._test_no_rate_limiting('/api/users/search')

                assert result is not None
                assert result.severity == BypassSeverity.HIGH  # Not CRITICAL for non-auth

    def test_rate_limiting_exists(self, bypasser, mock_response):
        """Test when rate limiting does exist."""
        with patch.object(bypasser.session, 'post') as mock_post:
            # Return 429 after 10 requests
            mock_post.side_effect = [mock_response(200)] * 10 + [mock_response(429)]

            result = bypasser._test_no_rate_limiting('/api/auth/login')

            assert result is None  # No bypass found
            assert '/api/auth/login' in bypasser.rate_limit_profiles

    def test_xff_bypass_detected(self, bypasser, mock_response):
        """Test X-Forwarded-For bypass detection."""
        with patch.object(bypasser.session, 'post') as mock_post:
            # First 20 requests succeed, then rate limited
            # Then XFF request succeeds
            responses = [mock_response(200)] * 20 + [mock_response(429)]

            def side_effect(*args, **kwargs):
                if 'X-Forwarded-For' in kwargs.get('headers', {}):
                    return mock_response(200)
                if len(responses) > 0:
                    return responses.pop(0)
                return mock_response(429)

            mock_post.side_effect = side_effect

            result = bypasser._test_xff_bypass('/api/auth/login')

            assert result is not None
            assert result.vuln_id == "ABD-RATE-002"
            assert result.severity == BypassSeverity.HIGH
            assert "X-Forwarded-For" in result.name
            assert any("X-Forwarded-For" in e for e in result.evidence)

    def test_xff_bypass_not_vulnerable(self, bypasser, mock_response):
        """Test when XFF bypass doesn't work."""
        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(429)  # Always rate limited

            result = bypasser._test_xff_bypass('/api/auth/login')

            assert result is None

    @patch('engine.agents.api_abuse_detection_bypasser.requests.Session')
    def test_session_rotation_bypass(self, mock_session_class, bypasser, mock_response):
        """Test session rotation bypass detection."""
        # Create mock sessions
        session1 = Mock()
        session2 = Mock()
        session1.verify = False
        session2.verify = False

        # Session 1 gets rate limited, session 2 doesn't
        session1.post.side_effect = [mock_response(200)] * 20 + [mock_response(429)]
        session2.post.return_value = mock_response(200)

        mock_session_class.side_effect = [session1, session2]

        result = bypasser._test_session_rotation_bypass('/api/auth/login')

        assert result is not None
        assert result.vuln_id == "ABD-RATE-005"
        assert result.severity == BypassSeverity.MEDIUM
        assert "Session Rotation" in result.name

    def test_graphql_aliasing_bypass(self, bypasser, mock_response):
        """Test GraphQL aliasing bypass detection."""
        with patch.object(bypasser.session, 'post') as mock_post:
            # Both single and aliased queries succeed
            mock_post.return_value = mock_response(status_code=200)

            result = bypasser._test_graphql_aliasing_bypass()

            assert result is not None
            assert result.vuln_id == "ABD-RATE-003"
            assert result.severity == BypassSeverity.HIGH
            assert "GraphQL Aliasing" in result.name
            assert "20x bypass" in result.evidence

    def test_graphql_not_available(self, bypasser, mock_response):
        """Test when GraphQL endpoint doesn't exist."""
        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(status_code=404)

            result = bypasser._test_graphql_aliasing_bypass()

            assert result is None

    def test_endpoint_variation_bypass(self, bypasser, mock_response):
        """Test endpoint variation bypass detection."""
        with patch.object(bypasser.session, 'post') as mock_post:
            def side_effect(url, *args, **kwargs):
                if '/api/auth/login' in url:
                    return mock_response(429)
                elif '/api/v1/auth/login' in url:
                    return mock_response(200)
                return mock_response(404)

            mock_post.side_effect = side_effect

            result = bypasser._test_endpoint_variation_bypass()

            assert result is not None
            assert result.vuln_id == "ABD-RATE-004"
            assert result.severity == BypassSeverity.MEDIUM
            assert "Endpoint Variation" in result.name


# ============================================================================
# Bot Detection Bypass Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestBotDetectionBypasses:
    """Test bot detection bypass detection."""

    def test_user_agent_bypass(self, bypasser, mock_response):
        """Test User-Agent only bot detection."""
        with patch.object(bypasser.session, 'get') as mock_get:
            def side_effect(*args, **kwargs):
                headers = kwargs.get('headers', {})
                ua = headers.get('User-Agent', '')

                if 'python-requests' in ua:
                    return mock_response(403)
                elif 'Chrome' in ua:
                    return mock_response(200)
                return mock_response(403)

            mock_get.side_effect = side_effect

            result = bypasser._test_user_agent_bypass()

            assert result is not None
            assert result.vuln_id == "ABD-BOT-001"
            assert result.severity == BypassSeverity.MEDIUM
            assert "User-Agent" in result.name
            assert "python-requests" in result.evidence[0]

    def test_user_agent_bypass_not_vulnerable(self, bypasser, mock_response):
        """Test when User-Agent bypass doesn't work."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.return_value = mock_response(403)  # Always blocked

            result = bypasser._test_user_agent_bypass()

            assert result is None

    def test_no_javascript_challenge(self, bypasser, mock_response):
        """Test detection of no JavaScript challenge."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.return_value = mock_response(
                status_code=200,
                text="<html><body>Normal content</body></html>"
            )

            result = bypasser._test_javascript_challenge_bypass()

            assert result is not None
            assert result.vuln_id == "ABD-BOT-002"
            assert result.severity == BypassSeverity.LOW
            assert "No JavaScript Challenge" in result.name

    def test_javascript_challenge_detected(self, bypasser, mock_response):
        """Test when JavaScript challenge is present."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.return_value = mock_response(
                status_code=200,
                text="<html>Checking your browser before accessing...</html>"
            )

            result = bypasser._test_javascript_challenge_bypass()

            # Should not return a finding when challenge is present
            assert result is None


# ============================================================================
# CAPTCHA Bypass Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestCaptchaBypasses:
    """Test CAPTCHA bypass detection."""

    def test_captcha_not_enforced(self, bypasser, mock_response):
        """Test detection of unenforced CAPTCHA."""
        endpoints = ['/api/auth/login', '/api/auth/register']

        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(status_code=200)

            results = bypasser._test_no_captcha_enforcement(endpoints)

            assert len(results) > 0
            assert results[0].vuln_id == "ABD-CAPTCHA-001"
            assert results[0].severity == BypassSeverity.HIGH
            assert "CAPTCHA Not Enforced" in results[0].name

    def test_captcha_enforced(self, bypasser, mock_response):
        """Test when CAPTCHA is properly enforced."""
        endpoints = ['/api/auth/login']

        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(
                status_code=400,
                text='{"error": "captcha required"}'
            )

            results = bypasser._test_no_captcha_enforcement(endpoints)

            assert len(results) == 0

    def test_captcha_token_not_validated(self, bypasser, mock_response):
        """Test CAPTCHA token validation bypass."""
        endpoints = ['/api/auth/login']

        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(status_code=200)

            results = bypasser._test_captcha_response_manipulation(endpoints)

            assert len(results) > 0
            assert results[0].vuln_id == "ABD-CAPTCHA-002"
            assert results[0].severity == BypassSeverity.CRITICAL
            assert "CAPTCHA Token Not Validated" in results[0].name

    def test_automation_code_bypass(self, bypasser, mock_response):
        """Test automation_code bypass detection."""
        endpoints = ['/api/auth/register']

        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(
                status_code=200,
                text='{"success": true, "automation_code": "accepted"}'
            )

            result = bypasser._test_automation_code_bypass(endpoints)

            assert result is not None
            assert result.vuln_id == "ABD-CAPTCHA-003"
            assert result.severity == BypassSeverity.CRITICAL
            assert "Automation Code" in result.name

    def test_automation_code_rejected(self, bypasser, mock_response):
        """Test when automation_code is rejected."""
        endpoints = ['/api/auth/register']

        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(
                status_code=400,
                text='{"error": "invalid request"}'
            )

            result = bypasser._test_automation_code_bypass(endpoints)

            assert result is None


# ============================================================================
# Fingerprinting & WAF Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestFingerprintingAndWAF:
    """Test fingerprinting evasion and WAF detection."""

    def test_header_rotation_technique(self, bypasser):
        """Test header rotation technique documentation."""
        result = bypasser._test_header_rotation()

        assert result is not None
        assert result.vuln_id == "ABD-FINGER-001"
        assert result.severity == BypassSeverity.LOW
        assert result.category == BypassCategory.FINGERPRINTING

    def test_waf_detection_cloudflare(self, bypasser, mock_response):
        """Test Cloudflare WAF detection."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.return_value = mock_response(
                status_code=200,
                headers={'cf-ray': '12345-SFO'}
            )

            result = bypasser._test_waf_detection()

            assert result is not None
            assert result.vuln_id == "ABD-WAF-001"
            assert result.severity == BypassSeverity.INFO
            assert "cloudflare" in result.description.lower()

    def test_waf_detection_akamai(self, bypasser, mock_response):
        """Test Akamai WAF detection."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.return_value = mock_response(
                status_code=200,
                headers={'x-akamai-request-id': 'abc123'}
            )

            result = bypasser._test_waf_detection()

            assert result is not None
            assert "akamai" in result.description.lower()

    def test_no_waf_detected(self, bypasser, mock_response):
        """Test when no WAF is detected."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.return_value = mock_response(status_code=200, headers={})

            result = bypasser._test_waf_detection()

            # Info finding may still be returned, but no WAF headers
            if result:
                assert result.severity == BypassSeverity.INFO


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestPOCGeneration:
    """Test POC code generation."""

    def test_no_limit_poc(self, bypasser):
        """Test no rate limiting POC generation."""
        poc = bypasser._generate_no_limit_poc("https://api.example.com/login")

        assert "import requests" in poc
        assert "range(1000)" in poc
        assert "https://api.example.com/login" in poc

    def test_xff_bypass_poc(self, bypasser):
        """Test XFF bypass POC generation."""
        poc = bypasser._generate_xff_bypass_poc("https://api.example.com/login")

        assert "X-Forwarded-For" in poc
        assert "random.randint" in poc
        assert "fake_ip" in poc

    def test_graphql_alias_poc(self, bypasser):
        """Test GraphQL aliasing POC generation."""
        poc = bypasser._generate_graphql_alias_poc("https://api.example.com/graphql")

        assert "query" in poc
        assert "user" in poc
        assert "20 aliases" in poc.lower()

    def test_ua_bypass_poc(self, bypasser):
        """Test User-Agent bypass POC generation."""
        poc = bypasser._generate_ua_bypass_poc("https://api.example.com/api")

        assert "User-Agent" in poc
        assert "user_agents" in poc
        assert "Mozilla" in poc

    def test_automation_code_poc(self, bypasser):
        """Test automation_code bypass POC generation."""
        poc = bypasser._generate_automation_code_poc("https://api.example.com/register")

        assert "automation_code" in poc
        assert "BYPASS123" in poc
        assert "range(1000)" in poc

    def test_header_rotation_poc(self, bypasser):
        """Test header rotation POC generation."""
        poc = bypasser._generate_header_rotation_poc()

        assert "User-Agent" in poc
        assert "Accept-Language" in poc
        assert "random.choice" in poc


# ============================================================================
# Full Workflow Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestFullWorkflow:
    """Test complete bypass discovery workflow."""

    def test_discover_all_bypasses_success(self, bypasser, mock_response):
        """Test full bypass discovery."""
        with patch.object(bypasser.session, 'post') as mock_post, \
             patch.object(bypasser.session, 'get') as mock_get:

            # Mock responses for different tests
            mock_post.return_value = mock_response(200)
            mock_get.return_value = mock_response(200, text="Normal page")

            endpoints = ['/api/auth/login']
            results = bypasser.discover_all_bypasses(endpoints)

            assert isinstance(results, list)
            assert len(results) > 0
            assert all(isinstance(r, BypassVulnerability) for r in results)

    def test_default_endpoints_used(self, bypasser):
        """Test that default endpoints are used when none provided."""
        endpoints = bypasser._get_default_endpoints()

        assert len(endpoints) > 0
        assert '/api/auth/login' in endpoints
        assert '/graphql' in endpoints

    def test_requests_not_available(self):
        """Test behavior when requests library not available."""
        bypasser = APIAbuseDetectionBypasser("https://api.example.com")

        with patch('engine.agents.api_abuse_detection_bypasser.REQUESTS_AVAILABLE', False):
            with pytest.raises(ImportError, match="requests library is required"):
                bypasser.discover_all_bypasses()


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestReportGeneration:
    """Test report generation."""

    def test_generate_report_empty(self, bypasser):
        """Test report generation with no findings."""
        report = bypasser.generate_report()

        assert "API Abuse Detection Bypass Report" in report
        assert "Total Bypasses**: 0" in report
        assert bypasser.target in report

    def test_generate_report_with_findings(self, bypasser):
        """Test report generation with findings."""
        # Add test findings
        bypasser.discovered_bypasses = [
            BypassVulnerability(
                vuln_id="ABD-RATE-001",
                name="Test Bypass",
                category=BypassCategory.RATE_LIMITING,
                severity=BypassSeverity.HIGH,
                confidence=0.9,
                description="Test description",
                bypass_technique="Test technique",
                evidence=["Evidence 1", "Evidence 2"],
                impact="Test impact",
                recommendation="Test recommendation"
            )
        ]

        report = bypasser.generate_report()

        assert "Total Bypasses**: 1" in report
        assert "ABD-RATE-001" in report
        assert "Test Bypass" in report
        assert "HIGH" in report
        assert "Evidence 1" in report

    def test_generate_report_severity_breakdown(self, bypasser):
        """Test severity breakdown in report."""
        bypasser.discovered_bypasses = [
            BypassVulnerability(
                vuln_id="ABD-001",
                name="Critical Finding",
                category=BypassCategory.CAPTCHA,
                severity=BypassSeverity.CRITICAL,
                confidence=0.95,
                description="Critical",
                bypass_technique="Test"
            ),
            BypassVulnerability(
                vuln_id="ABD-002",
                name="Low Finding",
                category=BypassCategory.FINGERPRINTING,
                severity=BypassSeverity.LOW,
                confidence=0.6,
                description="Low",
                bypass_technique="Test"
            )
        ]

        report = bypasser.generate_report()

        assert "**CRITICAL**: 1" in report
        assert "**LOW**: 1" in report

    def test_get_findings_by_severity(self, bypasser):
        """Test filtering findings by severity."""
        bypasser.discovered_bypasses = [
            BypassVulnerability(
                vuln_id="ABD-001",
                name="High",
                category=BypassCategory.RATE_LIMITING,
                severity=BypassSeverity.HIGH,
                confidence=0.8,
                description="Test",
                bypass_technique="Test"
            ),
            BypassVulnerability(
                vuln_id="ABD-002",
                name="Low",
                category=BypassCategory.BOT_DETECTION,
                severity=BypassSeverity.LOW,
                confidence=0.6,
                description="Test",
                bypass_technique="Test"
            )
        ]

        high_findings = bypasser.get_findings_by_severity(BypassSeverity.HIGH)
        low_findings = bypasser.get_findings_by_severity(BypassSeverity.LOW)

        assert len(high_findings) == 1
        assert len(low_findings) == 1
        assert high_findings[0].vuln_id == "ABD-001"

    def test_get_findings_by_category(self, bypasser):
        """Test filtering findings by category."""
        bypasser.discovered_bypasses = [
            BypassVulnerability(
                vuln_id="ABD-001",
                name="Rate Limit",
                category=BypassCategory.RATE_LIMITING,
                severity=BypassSeverity.HIGH,
                confidence=0.8,
                description="Test",
                bypass_technique="Test"
            ),
            BypassVulnerability(
                vuln_id="ABD-002",
                name="CAPTCHA",
                category=BypassCategory.CAPTCHA,
                severity=BypassSeverity.CRITICAL,
                confidence=0.9,
                description="Test",
                bypass_technique="Test"
            )
        ]

        rate_limit_findings = bypasser.get_findings_by_category(BypassCategory.RATE_LIMITING)
        captcha_findings = bypasser.get_findings_by_category(BypassCategory.CAPTCHA)

        assert len(rate_limit_findings) == 1
        assert len(captcha_findings) == 1
        assert captcha_findings[0].vuln_id == "ABD-002"


# ============================================================================
# Data Model Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestDataModels:
    """Test data model classes."""

    def test_bypass_vulnerability_creation(self):
        """Test BypassVulnerability creation."""
        vuln = BypassVulnerability(
            vuln_id="TEST-001",
            name="Test Vuln",
            category=BypassCategory.RATE_LIMITING,
            severity=BypassSeverity.HIGH,
            confidence=0.85,
            description="Test description",
            bypass_technique="Test technique"
        )

        assert vuln.vuln_id == "TEST-001"
        assert vuln.category == BypassCategory.RATE_LIMITING
        assert vuln.severity == BypassSeverity.HIGH
        assert vuln.confidence == 0.85
        assert vuln.discovered_date == date.today().isoformat()

    def test_bypass_vulnerability_to_dict(self):
        """Test BypassVulnerability to_dict conversion."""
        vuln = BypassVulnerability(
            vuln_id="TEST-001",
            name="Test",
            category=BypassCategory.CAPTCHA,
            severity=BypassSeverity.CRITICAL,
            confidence=0.9,
            description="Test",
            bypass_technique="Test"
        )

        data = vuln.to_dict()

        assert data['vuln_id'] == "TEST-001"
        assert data['category'] == "captcha"  # Enum converted to string
        assert data['severity'] == "CRITICAL"

    def test_rate_limit_profile_creation(self):
        """Test RateLimitProfile creation."""
        profile = RateLimitProfile(
            endpoint="/api/login",
            threshold=100,
            window_seconds=60,
            limit_type="ip"
        )

        assert profile.endpoint == "/api/login"
        assert profile.threshold == 100
        assert profile.window_seconds == 60
        assert profile.limit_type == "ip"


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_network_timeout_handled(self, bypasser):
        """Test handling of network timeouts."""
        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.side_effect = Exception("Timeout")

            result = bypasser._test_no_rate_limiting('/api/login')

            assert result is None  # Should handle gracefully

    def test_invalid_response_handled(self, bypasser, mock_response):
        """Test handling of invalid responses."""
        with patch.object(bypasser.session, 'get') as mock_get:
            mock_get.side_effect = Exception("Invalid response")

            result = bypasser._test_user_agent_bypass()

            assert result is None

    def test_profile_rate_limit(self, bypasser):
        """Test rate limit profiling."""
        bypasser._profile_rate_limit('/api/test', 50, 30.5)

        assert '/api/test' in bypasser.rate_limit_profiles
        profile = bypasser.rate_limit_profiles['/api/test']
        assert profile.threshold == 50
        assert profile.window_seconds == 30

    def test_empty_endpoint_list(self, bypasser, mock_response):
        """Test with empty endpoint list."""
        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.return_value = mock_response(200)

            results = bypasser.test_rate_limit_bypasses([])

            # Should still test GraphQL and endpoint variation
            assert isinstance(results, list)

    def test_all_requests_fail(self, bypasser):
        """Test when all requests fail."""
        with patch.object(bypasser.session, 'post') as mock_post:
            mock_post.side_effect = Exception("Connection error")

            result = bypasser._test_no_rate_limiting('/api/login')

            assert result is None


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not BYPASSER_AVAILABLE, reason="Bypasser not available")
class TestIntegration:
    """Integration tests."""

    def test_complete_scan_workflow(self, bypasser, mock_response):
        """Test complete scanning workflow."""
        with patch.object(bypasser.session, 'post') as mock_post, \
             patch.object(bypasser.session, 'get') as mock_get:

            mock_post.return_value = mock_response(200)
            mock_get.return_value = mock_response(200, text="Normal")

            # Run full scan
            results = bypasser.discover_all_bypasses(['/api/auth/login'])

            # Generate report
            report = bypasser.generate_report()

            # Verify workflow
            assert len(results) > 0
            assert len(report) > 0
            assert bypasser.discovered_bypasses == results

    def test_multiple_categories_detected(self, bypasser, mock_response):
        """Test detection across multiple categories."""
        with patch.object(bypasser.session, 'post') as mock_post, \
             patch.object(bypasser.session, 'get') as mock_get:

            mock_post.return_value = mock_response(200)
            mock_get.return_value = mock_response(200, text="Normal")

            results = bypasser.discover_all_bypasses(['/api/auth/login'])

            categories = set(r.category for r in results)

            # Should find multiple categories
            assert len(categories) > 1


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
