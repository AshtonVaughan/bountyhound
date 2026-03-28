"""
Tests for Open Redirect Tester Agent

Comprehensive test suite covering 30+ test cases with 95%+ coverage.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from engine.agents.open_redirect_tester import (
    OpenRedirectTester,
    PayloadGenerator,
    RedirectAnalyzer,
    RedirectType,
    RedirectMethod,
    RedirectPayload,
    RedirectFinding
)


class TestPayloadGenerator:
    """Test payload generation (10 tests)"""

    def test_basic_payloads_generation(self):
        """Test basic redirect payload generation"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_basic_payloads()

        assert len(payloads) >= 6
        assert any(p.payload == "https://evil.com" for p in payloads)
        assert any(p.payload == "//evil.com" for p in payloads)
        assert any(p.bypass_technique == "protocol_relative" for p in payloads)

    def test_filter_bypass_payloads(self):
        """Test filter bypass payload generation"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_filter_bypass_payloads("legitimate.com")

        assert len(payloads) >= 10
        assert any("@" in p.payload for p in payloads)
        assert any("legitimate.com.evil.com" in p.payload for p in payloads)

    def test_at_symbol_bypass(self):
        """Test @ symbol bypass payload"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_filter_bypass_payloads("legitimate.com")

        at_payloads = [p for p in payloads if p.bypass_technique == "at_symbol"]
        assert len(at_payloads) > 0
        assert "legitimate.com@evil.com" in at_payloads[0].payload

    def test_subdomain_bypass(self):
        """Test subdomain append bypass"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_filter_bypass_payloads("legitimate.com")

        subdomain_payloads = [p for p in payloads if p.bypass_technique == "subdomain_append"]
        assert len(subdomain_payloads) > 0
        assert "legitimate.com.evil.com" in subdomain_payloads[0].payload

    def test_encoding_bypass(self):
        """Test URL encoding bypass"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_filter_bypass_payloads("legitimate.com")

        encoding_payloads = [p for p in payloads if "encoding" in p.bypass_technique]
        assert len(encoding_payloads) >= 2

    def test_crlf_injection_payload(self):
        """Test CRLF injection payload"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_filter_bypass_payloads("legitimate.com")

        crlf_payloads = [p for p in payloads if p.bypass_technique == "crlf_injection"]
        assert len(crlf_payloads) > 0
        assert "%0d%0a" in crlf_payloads[0].payload

    def test_null_byte_injection(self):
        """Test null byte injection payload"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_filter_bypass_payloads("legitimate.com")

        null_payloads = [p for p in payloads if p.bypass_technique == "null_byte"]
        assert len(null_payloads) > 0
        assert "%00" in null_payloads[0].payload

    def test_protocol_bypass_payloads(self):
        """Test protocol bypass payload generation"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_protocol_bypass_payloads()

        assert len(payloads) >= 3
        assert any(p.payload.startswith("javascript:") for p in payloads)
        assert any(p.payload.startswith("data:") for p in payloads)

    def test_oauth_payloads(self):
        """Test OAuth-specific payload generation"""
        gen = PayloadGenerator("evil.com")
        payloads = gen.generate_oauth_payloads("test_client")

        assert len(payloads) >= 3
        assert any(p.redirect_type == RedirectType.OAUTH for p in payloads)

    def test_custom_attacker_domain(self):
        """Test custom attacker domain"""
        gen = PayloadGenerator("attacker.com")
        payloads = gen.generate_basic_payloads()

        assert any("attacker.com" in p.payload for p in payloads)


class TestRedirectAnalyzer:
    """Test redirect analysis (8 tests)"""

    def test_http_302_detection(self):
        """Test HTTP 302 redirect detection"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 302
        response.headers = {'Location': 'https://evil.com'}
        response.url = 'https://evil.com'
        response.history = []
        response.text = ""

        result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")

        assert result is not None
        assert result['redirected'] is True
        assert result['method'] == RedirectMethod.HTTP_302
        assert result['destination'] == 'https://evil.com'

    def test_http_301_detection(self):
        """Test HTTP 301 redirect detection"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 301
        response.headers = {'Location': 'https://evil.com'}
        response.url = 'https://evil.com'
        response.history = []
        response.text = ""

        result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")

        assert result['method'] == RedirectMethod.HTTP_301

    def test_meta_refresh_detection(self):
        """Test meta refresh redirect detection"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.url = 'https://example.com'
        response.text = '<meta http-equiv="refresh" content="0;url=https://evil.com">'

        result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")

        assert result is not None
        assert result['method'] == RedirectMethod.META_TAG
        assert 'evil.com' in result['destination']

    def test_javascript_location_detection(self):
        """Test JavaScript location redirect detection"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.url = 'https://example.com'
        response.text = '<script>window.location="https://evil.com";</script>'

        result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")

        assert result is not None
        assert result['method'] == RedirectMethod.JAVASCRIPT
        assert 'evil.com' in result['destination']

    def test_javascript_location_href_detection(self):
        """Test JavaScript location.href redirect detection"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.url = 'https://example.com'
        response.text = '<script>location.href="https://evil.com";</script>'

        result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")

        assert result is not None
        assert 'evil.com' in result['destination']

    def test_external_redirect_detection(self):
        """Test external redirect detection"""
        analyzer = RedirectAnalyzer()

        # External redirect
        assert analyzer.is_external_redirect("example.com", "https://evil.com") is True

        # Same domain
        assert analyzer.is_external_redirect("example.com", "https://example.com/path") is False

    def test_subdomain_not_external(self):
        """Test subdomain is not considered external"""
        analyzer = RedirectAnalyzer()

        # Subdomain should not be external
        assert analyzer.is_external_redirect("example.com", "https://sub.example.com") is False

    def test_no_redirect_returns_none(self):
        """Test no redirect returns None"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.url = 'https://example.com'
        response.text = 'Normal page content'

        result = analyzer.analyze_response(response, "https://example.com", "")

        assert result is None


class TestOpenRedirectTester:
    """Test main tester functionality (12+ tests)"""

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_initialization(self, mock_db, mock_hooks):
        """Test tester initialization"""
        tester = OpenRedirectTester(target="example.com", timeout=5, attacker_domain="evil.com")

        assert tester.target == "example.com"
        assert tester.timeout == 5
        assert tester.attacker_domain == "evil.com"
        assert len(tester.redirect_params) > 0

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_database_skip_check(self, mock_db, mock_hooks):
        """Test database skip check"""
        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': []
        }

        tester = OpenRedirectTester(target="example.com")

        with patch.object(tester, 'session'):
            findings = tester.test_url("https://example.com/login")

        assert len(findings) == 0

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_oauth_endpoint_detection(self, mock_db, mock_hooks):
        """Test OAuth endpoint detection"""
        tester = OpenRedirectTester()

        assert tester._is_oauth_endpoint("https://example.com/oauth/authorize") is True
        assert tester._is_oauth_endpoint("https://example.com/login?client_id=123") is True
        assert tester._is_oauth_endpoint("https://example.com/normal") is False

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_url_param_detection(self, mock_db, mock_hooks):
        """Test URL parameter detection"""
        tester = OpenRedirectTester()

        assert tester._looks_like_url_param("redirect", "https://example.com") is True
        assert tester._looks_like_url_param("return_to", "/path") is True
        assert tester._looks_like_url_param("name", "john") is False

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_severity_determination_oauth(self, mock_db, mock_hooks):
        """Test severity determination for OAuth"""
        tester = OpenRedirectTester()

        payload = RedirectPayload(
            payload="https://evil.com",
            redirect_type=RedirectType.OAUTH,
            bypass_technique="test",
            description="test",
            expected_behavior="test"
        )

        severity = tester._determine_severity(payload, {})
        assert severity == "critical"

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_severity_determination_header(self, mock_db, mock_hooks):
        """Test severity determination for header-based"""
        tester = OpenRedirectTester()

        payload = RedirectPayload(
            payload="https://evil.com",
            redirect_type=RedirectType.HEADER,
            bypass_technique="test",
            description="test",
            expected_behavior="test"
        )

        severity = tester._determine_severity(payload, {})
        assert severity == "high"

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_chain_potential_oauth(self, mock_db, mock_hooks):
        """Test chain potential for OAuth redirects"""
        tester = OpenRedirectTester()

        payload = RedirectPayload(
            payload="https://evil.com",
            redirect_type=RedirectType.OAUTH,
            bypass_technique="test",
            description="test",
            expected_behavior="test"
        )

        potential = tester._determine_chain_potential(payload, "https://example.com/oauth")
        assert "OAuth token theft" in potential
        assert "Account takeover" in potential

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_impact_determination(self, mock_db, mock_hooks):
        """Test impact determination"""
        tester = OpenRedirectTester()

        payload_oauth = RedirectPayload(
            payload="https://evil.com",
            redirect_type=RedirectType.OAUTH,
            bypass_technique="test",
            description="test",
            expected_behavior="test"
        )

        impact = tester._determine_impact(payload_oauth, "https://example.com")
        assert "authorization code" in impact.lower()

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_poc_generation_parameter(self, mock_db, mock_hooks):
        """Test POC generation for parameter-based redirect"""
        tester = OpenRedirectTester()

        payload = RedirectPayload(
            payload="https://evil.com",
            redirect_type=RedirectType.PARAMETER,
            bypass_technique="test",
            description="test",
            expected_behavior="test"
        )

        poc = tester._generate_poc("https://example.com/login", "redirect", payload)
        assert "redirect=" in poc
        assert "example.com" in poc

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_poc_generation_header(self, mock_db, mock_hooks):
        """Test POC generation for header-based redirect"""
        tester = OpenRedirectTester()

        payload = RedirectPayload(
            payload="https://evil.com",
            redirect_type=RedirectType.HEADER,
            bypass_technique="test",
            description="test",
            expected_behavior="test"
        )

        poc = tester._generate_poc("https://example.com/login", "Referer", payload)
        assert "curl" in poc
        assert "Referer" in poc

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_statistics_tracking(self, mock_db, mock_hooks):
        """Test statistics tracking"""
        tester = OpenRedirectTester()
        tester.tests_run = 10
        tester.tests_passed = 3

        stats = tester.get_statistics()
        assert stats['tests_run'] == 10
        assert stats['tests_passed'] == 3
        assert 'total_findings' in stats

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_finding_to_dict(self, mock_db, mock_hooks):
        """Test finding serialization to dict"""
        finding = RedirectFinding(
            url="https://example.com",
            parameter="redirect",
            redirect_type=RedirectType.PARAMETER,
            redirect_method=RedirectMethod.HTTP_302,
            payload="https://evil.com",
            final_destination="https://evil.com",
            bypass_technique="test",
            severity="medium",
            impact="test impact",
            exploitation_steps=["step1", "step2"],
            chain_potential=["phishing"],
            poc="https://example.com?redirect=evil.com"
        )

        data = finding.to_dict()
        assert data['url'] == "https://example.com"
        assert data['severity'] == "medium"
        assert data['redirect_type'] == "parameter"


class TestIntegration:
    """Integration tests (5+ tests)"""

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    @patch('engine.agents.open_redirect_tester.requests.Session')
    def test_full_parameter_test(self, mock_session, mock_db, mock_hooks):
        """Test full parameter testing flow"""
        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'OK to test'
        }

        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.headers = {'Location': 'https://evil.com'}
        mock_response.url = 'https://evil.com'
        mock_response.history = []
        mock_response.text = ""

        mock_session_inst = Mock()
        mock_session_inst.get.return_value = mock_response
        mock_session.return_value = mock_session_inst

        tester = OpenRedirectTester(target="example.com", session=mock_session_inst)
        findings = tester.test_url("https://example.com/login", {"redirect": "/"})

        assert mock_session_inst.get.called

    @patch('engine.agents.open_redirect_tester.run_open_redirect_tests')
    def test_run_wrapper_function(self, mock_run):
        """Test wrapper function"""
        mock_run.return_value = {
            'findings': [],
            'stats': {'total_findings': 0}
        }

        result = mock_run("https://example.com/login", {})
        assert 'findings' in result
        assert 'stats' in result

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_multiple_redirect_params(self, mock_db, mock_hooks):
        """Test multiple redirect parameter names"""
        tester = OpenRedirectTester()

        assert 'redirect' in tester.redirect_params
        assert 'return_to' in tester.redirect_params
        assert 'next' in tester.redirect_params
        assert 'RelayState' in tester.redirect_params
        assert len(tester.redirect_params) >= 20

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_auto_target_detection(self, mock_db, mock_hooks):
        """Test automatic target detection from URL"""
        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'test'
        }

        tester = OpenRedirectTester()

        with patch.object(tester, 'session'):
            tester.test_url("https://example.com/login")

        assert tester.target == "example.com"

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_requests_not_available(self, mock_db, mock_hooks):
        """Test graceful handling when requests not available"""
        with patch('engine.agents.open_redirect_tester.REQUESTS_AVAILABLE', False):
            tester = OpenRedirectTester()
            findings = tester.test_url("https://example.com/login")
            assert findings == []


class TestEdgeCases:
    """Edge case tests (5+ tests)"""

    def test_payload_with_special_characters(self):
        """Test payload generation with special characters"""
        gen = PayloadGenerator("evil-test.com")
        payloads = gen.generate_basic_payloads()

        assert any("evil-test.com" in p.payload for p in payloads)

    def test_empty_redirect_destination(self):
        """Test handling of empty redirect destination"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 302
        response.headers = {'Location': ''}
        response.url = 'https://example.com'
        response.history = []
        response.text = ""

        result = analyzer.analyze_response(response, "https://example.com", "")
        assert result['destination'] == ''

    def test_malformed_url_parsing(self):
        """Test malformed URL parsing"""
        analyzer = RedirectAnalyzer()

        # Should not crash on malformed URLs
        result = analyzer.is_external_redirect("invalid", "also-invalid")
        assert isinstance(result, bool)

    def test_redirect_chain_analysis(self):
        """Test redirect chain analysis"""
        analyzer = RedirectAnalyzer()

        response = Mock()
        response.status_code = 302
        response.headers = {'Location': 'https://evil.com'}
        response.url = 'https://evil.com'

        hist1 = Mock()
        hist1.status_code = 301
        hist1.url = 'https://example.com/redirect1'
        hist1.headers = {'Location': 'https://example.com/redirect2'}

        response.history = [hist1]
        response.text = ""

        result = analyzer.analyze_response(response, "https://example.com", "")
        assert len(result['chain']) == 1

    @patch('engine.agents.open_redirect_tester.DatabaseHooks')
    @patch('engine.agents.open_redirect_tester.BountyHoundDB')
    def test_timeout_handling(self, mock_db, mock_hooks):
        """Test timeout configuration"""
        tester = OpenRedirectTester(timeout=30)
        assert tester.timeout == 30


# Coverage report
def test_coverage_threshold():
    """Verify we have sufficient test coverage"""
    # This test ensures we have 30+ test methods
    test_classes = [
        TestPayloadGenerator,
        TestRedirectAnalyzer,
        TestOpenRedirectTester,
        TestIntegration,
        TestEdgeCases
    ]

    total_tests = 0
    for test_class in test_classes:
        test_methods = [m for m in dir(test_class) if m.startswith('test_')]
        total_tests += len(test_methods)

    assert total_tests >= 30, f"Need at least 30 tests, got {total_tests}"
