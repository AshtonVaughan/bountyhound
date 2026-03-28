"""
Tests for API Gateway Bypass Tester Agent

Comprehensive test coverage including:
- Path normalization bypass
- Header injection
- Method override
- Protocol confusion
- Cache poisoning
- Rate limiting bypass
- Direct backend access
- Host header attacks
- Database integration
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, date

from engine.agents.api_gateway_bypass_tester import (
    APIGatewayBypassTester,
    GatewayBypassVulnerability,
    GatewaySeverity,
    BypassTechnique
)


class TestGatewayBypassVulnerability:
    """Test GatewayBypassVulnerability dataclass"""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability instance"""
        vuln = GatewayBypassVulnerability(
            vuln_id="GW-PATH-001",
            severity=GatewaySeverity.CRITICAL,
            technique=BypassTechnique.PATH_NORMALIZATION,
            title="Path Traversal Bypass",
            description="Gateway allows path traversal",
            endpoint="/admin",
            evidence={"payload": "/../admin"},
            remediation="Normalize paths",
            cwe="CWE-22",
            cvss_score=9.1
        )

        assert vuln.vuln_id == "GW-PATH-001"
        assert vuln.severity == GatewaySeverity.CRITICAL
        assert vuln.technique == BypassTechnique.PATH_NORMALIZATION
        assert vuln.cvss_score == 9.1

    def test_vulnerability_to_dict(self):
        """Test converting vulnerability to dictionary"""
        vuln = GatewayBypassVulnerability(
            vuln_id="GW-HDR-001",
            severity=GatewaySeverity.HIGH,
            technique=BypassTechnique.HEADER_INJECTION,
            title="Header Injection",
            description="X-Forwarded-For bypass",
            endpoint="/api/admin",
            evidence={"header": "X-Forwarded-For"},
            remediation="Validate headers",
            cwe="CWE-284",
            cvss_score=8.5
        )

        result = vuln.to_dict()

        assert result['vuln_id'] == "GW-HDR-001"
        assert result['severity'] == "high"
        assert result['technique'] == "header_injection"
        assert result['cvss_score'] == 8.5


class TestAPIGatewayBypassTesterInit:
    """Test APIGatewayBypassTester initialization"""

    def test_init_basic(self):
        """Test basic initialization"""
        tester = APIGatewayBypassTester("https://api.example.com")

        assert tester.gateway_url == "https://api.example.com"
        assert tester.target_domain == "api.example.com"
        assert tester.backend_url is None
        assert len(tester.vulnerabilities) == 0

    def test_init_with_backend(self):
        """Test initialization with backend URL"""
        tester = APIGatewayBypassTester(
            gateway_url="https://api.example.com",
            backend_url="http://backend.internal:8080"
        )

        assert tester.gateway_url == "https://api.example.com"
        assert tester.backend_url == "http://backend.internal:8080"

    def test_init_with_custom_headers(self):
        """Test initialization with custom headers"""
        headers = {"Authorization": "Bearer token123"}
        tester = APIGatewayBypassTester(
            gateway_url="https://api.example.com",
            headers=headers
        )

        assert "Authorization" in tester.session.headers
        assert tester.session.headers["Authorization"] == "Bearer token123"

    def test_init_with_custom_domain(self):
        """Test initialization with custom target domain"""
        tester = APIGatewayBypassTester(
            gateway_url="https://api.example.com",
            target_domain="example.com"
        )

        assert tester.target_domain == "example.com"

    def test_trailing_slash_removed(self):
        """Test that trailing slash is removed from gateway URL"""
        tester = APIGatewayBypassTester("https://api.example.com/")
        assert tester.gateway_url == "https://api.example.com"


class TestPathNormalization:
    """Test path normalization bypass detection"""

    @patch('requests.Session.get')
    def test_path_normalization_basic(self, mock_get):
        """Test basic path normalization bypass"""
        # Baseline: 403 Forbidden
        baseline_response = Mock()
        baseline_response.status_code = 403

        # Bypass: 200 OK
        bypass_response = Mock()
        bypass_response.status_code = 200
        bypass_response.text = "Admin panel"

        mock_get.side_effect = [baseline_response, bypass_response]

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_path_normalization()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.CRITICAL
        assert vulns[0].technique == BypassTechnique.PATH_NORMALIZATION

    @patch('requests.Session.get')
    def test_path_normalization_no_bypass(self, mock_get):
        """Test when path normalization doesn't work"""
        # All responses return 403
        response = Mock()
        response.status_code = 403

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_path_normalization()

        assert len(vulns) == 0

    @patch('requests.Session.get')
    def test_path_normalization_already_accessible(self, mock_get):
        """Test when endpoint is already accessible (not protected)"""
        # Baseline returns 200 - already accessible
        response = Mock()
        response.status_code = 200

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_path_normalization()

        # Should skip testing if already accessible
        assert len(vulns) == 0

    @patch('requests.Session.get')
    @patch('engine.agents.api_gateway_bypass_tester.DatabaseHooks.get_successful_payloads')
    def test_path_normalization_with_proven_payloads(self, mock_payloads, mock_get):
        """Test using proven payloads from database"""
        # Mock proven payloads
        mock_payloads.return_value = [
            {'payload': '/../{path}', 'context': 'dot_dot_slash', 'success_count': 5}
        ]

        baseline_response = Mock()
        baseline_response.status_code = 403

        bypass_response = Mock()
        bypass_response.status_code = 200
        bypass_response.text = "Admin"

        mock_get.side_effect = [baseline_response, bypass_response]

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_path_normalization()

        assert len(vulns) > 0
        mock_payloads.assert_called_once()


class TestHeaderInjection:
    """Test header injection bypass detection"""

    @patch('requests.Session.get')
    def test_header_injection_x_forwarded_for(self, mock_get):
        """Test X-Forwarded-For header injection"""
        baseline_response = Mock()
        baseline_response.status_code = 403

        bypass_response = Mock()
        bypass_response.status_code = 200
        bypass_response.text = "Admin access"

        mock_get.side_effect = [baseline_response, bypass_response]

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_header_injection()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.CRITICAL
        assert vulns[0].technique == BypassTechnique.HEADER_INJECTION
        assert "X-Forwarded-For" in str(vulns[0].evidence)

    @patch('requests.Session.get')
    def test_header_injection_multiple_attempts(self, mock_get):
        """Test trying multiple header injection techniques"""
        baseline_response = Mock()
        baseline_response.status_code = 403

        # First 5 attempts fail, 6th succeeds
        responses = [baseline_response]  # Baseline
        responses.extend([Mock(status_code=403) for _ in range(5)])  # Failures
        responses.append(Mock(status_code=200, text="Success"))  # Success

        mock_get.side_effect = responses

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_header_injection()

        assert len(vulns) > 0

    @patch('requests.Session.get')
    def test_header_injection_no_bypass(self, mock_get):
        """Test when header injection doesn't work"""
        response = Mock()
        response.status_code = 403

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_header_injection()

        assert len(vulns) == 0

    @patch('requests.Session.get')
    @patch('engine.agents.api_gateway_bypass_tester.DatabaseHooks.check_duplicate')
    def test_header_injection_duplicate_check(self, mock_dup, mock_get):
        """Test duplicate checking for header injection findings"""
        mock_dup.return_value = {'is_duplicate': False}

        baseline_response = Mock()
        baseline_response.status_code = 403

        bypass_response = Mock()
        bypass_response.status_code = 200
        bypass_response.text = "Bypassed"

        mock_get.side_effect = [baseline_response, bypass_response]

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_header_injection()

        assert len(vulns) > 0


class TestMethodOverride:
    """Test HTTP method override bypass detection"""

    @patch('requests.Session.delete')
    @patch('requests.Session.post')
    def test_method_override_header(self, mock_post, mock_delete):
        """Test method override via X-HTTP-Method-Override header"""
        baseline_response = Mock()
        baseline_response.status_code = 403

        bypass_response = Mock()
        bypass_response.status_code = 204  # Successful DELETE

        mock_delete.return_value = baseline_response
        mock_post.return_value = bypass_response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_method_override()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.HIGH
        assert vulns[0].technique == BypassTechnique.METHOD_OVERRIDE

    @patch('requests.Session.delete')
    @patch('requests.Session.post')
    def test_method_override_query_param(self, mock_post, mock_delete):
        """Test method override via query parameter"""
        baseline_response = Mock()
        baseline_response.status_code = 405

        bypass_response = Mock()
        bypass_response.status_code = 200

        mock_delete.return_value = baseline_response
        mock_post.return_value = bypass_response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_method_override()

        assert len(vulns) > 0

    @patch('requests.Session.delete')
    @patch('requests.Session.post')
    def test_method_override_already_allowed(self, mock_post, mock_delete):
        """Test when DELETE is already allowed"""
        response = Mock()
        response.status_code = 204  # DELETE already works

        mock_delete.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_method_override()

        # Should skip if already allowed
        assert len(vulns) == 0


class TestProtocolConfusion:
    """Test protocol confusion attack detection"""

    @patch('requests.Session.post')
    def test_protocol_confusion_cl_te(self, mock_post):
        """Test CL.TE request smuggling"""
        response = Mock()
        response.status_code = 200
        response.text = "admin panel content"

        mock_post.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_protocol_confusion()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.CRITICAL
        assert vulns[0].technique == BypassTechnique.PROTOCOL_CONFUSION

    @patch('requests.Session.post')
    def test_protocol_confusion_no_smuggling(self, mock_post):
        """Test when request smuggling doesn't work"""
        response = Mock()
        response.status_code = 400
        response.text = "Bad request"

        mock_post.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_protocol_confusion()

        assert len(vulns) == 0


class TestCachePoisoning:
    """Test cache poisoning detection"""

    @patch('requests.Session.get')
    def test_cache_poisoning_detected(self, mock_get):
        """Test successful cache poisoning"""
        first_response = Mock()
        first_response.status_code = 200
        first_response.text = "Content"
        first_response.headers = {}

        second_response = Mock()
        second_response.status_code = 200
        second_response.text = "evil.com injected"  # Poison persisted
        second_response.headers = {}

        mock_get.side_effect = [first_response, second_response]

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_cache_poisoning()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.HIGH
        assert vulns[0].technique == BypassTechnique.CACHE_POISONING

    @patch('requests.Session.get')
    def test_cache_poisoning_not_detected(self, mock_get):
        """Test when cache poisoning doesn't work"""
        response = Mock()
        response.status_code = 200
        response.text = "Normal content"
        response.headers = {}

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_cache_poisoning()

        assert len(vulns) == 0


class TestRateLimitingBypass:
    """Test rate limiting bypass detection"""

    @patch('requests.Session.get')
    def test_rate_limiting_bypass(self, mock_get):
        """Test successful rate limit bypass"""
        # Simulate rate limiting being triggered
        responses = [Mock(status_code=200) for _ in range(10)]
        responses.append(Mock(status_code=429))  # Rate limited

        # Then bypass works
        responses.append(Mock(status_code=200))

        mock_get.side_effect = responses

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_rate_limiting_bypass()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.MEDIUM
        assert vulns[0].technique == BypassTechnique.RATE_LIMIT_BYPASS

    @patch('requests.Session.get')
    def test_rate_limiting_not_present(self, mock_get):
        """Test when no rate limiting is detected"""
        response = Mock()
        response.status_code = 200

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_rate_limiting_bypass()

        assert len(vulns) == 0

    @patch('requests.Session.get')
    def test_rate_limiting_bypass_fails(self, mock_get):
        """Test when rate limit bypass doesn't work"""
        # Trigger rate limit
        responses = [Mock(status_code=200) for _ in range(5)]
        responses.append(Mock(status_code=429))

        # All bypass attempts also get 429
        responses.extend([Mock(status_code=429) for _ in range(5)])

        mock_get.side_effect = responses

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_rate_limiting_bypass()

        assert len(vulns) == 0


class TestDirectBackendAccess:
    """Test direct backend access detection"""

    @patch('requests.Session.get')
    def test_direct_backend_accessible(self, mock_get):
        """Test when backend is directly accessible"""
        response = Mock()
        response.status_code = 200
        response.text = "Backend service"

        mock_get.return_value = response

        tester = APIGatewayBypassTester(
            gateway_url="https://api.example.com",
            backend_url="http://backend.internal:8080"
        )
        vulns = tester.test_direct_backend_access()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.HIGH
        assert vulns[0].technique == BypassTechnique.DIRECT_BACKEND

    @patch('requests.Session.get')
    def test_direct_backend_not_accessible(self, mock_get):
        """Test when backend is not accessible"""
        response = Mock()
        response.status_code = 503

        mock_get.return_value = response

        tester = APIGatewayBypassTester(
            gateway_url="https://api.example.com",
            backend_url="http://backend.internal:8080"
        )
        vulns = tester.test_direct_backend_access()

        assert len(vulns) == 0

    def test_direct_backend_no_url_provided(self):
        """Test when no backend URL is provided"""
        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_direct_backend_access()

        assert len(vulns) == 0


class TestHostHeaderAttacks:
    """Test Host header attack detection"""

    @patch('requests.Session.get')
    def test_host_header_injection(self, mock_get):
        """Test Host header injection vulnerability"""
        response = Mock()
        response.status_code = 200
        response.text = "Welcome to evil.com"  # Reflected host
        response.headers = {}

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_host_header_attacks()

        assert len(vulns) > 0
        assert vulns[0].severity == GatewaySeverity.MEDIUM
        assert vulns[0].technique == BypassTechnique.HOST_HEADER_ATTACK

    @patch('requests.Session.get')
    def test_host_header_not_reflected(self, mock_get):
        """Test when Host header is not reflected"""
        response = Mock()
        response.status_code = 200
        response.text = "Normal content"
        response.headers = {}

        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_host_header_attacks()

        assert len(vulns) == 0


class TestReportGeneration:
    """Test report generation"""

    def test_generate_report(self, tmp_path):
        """Test generating vulnerability report"""
        tester = APIGatewayBypassTester("https://api.example.com")

        # Add some test vulnerabilities
        tester.vulnerabilities.append(GatewayBypassVulnerability(
            vuln_id="GW-TEST-001",
            severity=GatewaySeverity.CRITICAL,
            technique=BypassTechnique.PATH_NORMALIZATION,
            title="Test Vulnerability",
            description="Test description",
            endpoint="/admin",
            evidence={"test": "data"},
            remediation="Fix it",
            cwe="CWE-22",
            cvss_score=9.0
        ))

        output_file = tmp_path / "report.json"
        report = tester.generate_report(str(output_file))

        assert output_file.exists()
        assert report['gateway'] == "https://api.example.com"
        assert report['vulnerabilities']['critical'] == 1
        assert len(report['findings']) == 1

    def test_generate_report_multiple_severities(self, tmp_path):
        """Test report with multiple severity levels"""
        tester = APIGatewayBypassTester("https://api.example.com")

        tester.vulnerabilities.extend([
            GatewayBypassVulnerability(
                vuln_id="GW-001", severity=GatewaySeverity.CRITICAL,
                technique=BypassTechnique.PATH_NORMALIZATION,
                title="Critical", description="desc", endpoint="/a",
                evidence={}, remediation="fix", cvss_score=9.0
            ),
            GatewayBypassVulnerability(
                vuln_id="GW-002", severity=GatewaySeverity.HIGH,
                technique=BypassTechnique.HEADER_INJECTION,
                title="High", description="desc", endpoint="/b",
                evidence={}, remediation="fix", cvss_score=7.5
            ),
            GatewayBypassVulnerability(
                vuln_id="GW-003", severity=GatewaySeverity.MEDIUM,
                technique=BypassTechnique.CACHE_POISONING,
                title="Medium", description="desc", endpoint="/c",
                evidence={}, remediation="fix", cvss_score=5.0
            ),
        ])

        output_file = tmp_path / "report.json"
        report = tester.generate_report(str(output_file))

        assert report['vulnerabilities']['critical'] == 1
        assert report['vulnerabilities']['high'] == 1
        assert report['vulnerabilities']['medium'] == 1
        assert report['vulnerabilities']['low'] == 0


class TestDatabaseIntegration:
    """Test database integration"""

    @patch('engine.agents.api_gateway_bypass_tester.DatabaseHooks.before_test')
    @patch('requests.Session.get')
    def test_database_context_check(self, mock_get, mock_before_test):
        """Test database context checking before testing"""
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Never tested before',
            'previous_findings': [],
            'recommendations': ['Full test recommended']
        }

        # Mock responses to prevent actual HTTP calls
        response = Mock()
        response.status_code = 403
        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        results = tester.run_comprehensive_test()

        mock_before_test.assert_called_once_with('api.example.com', 'api_gateway_bypass_tester')
        assert results['database_context']['reason'] == 'Never tested before'

    @patch('engine.agents.api_gateway_bypass_tester.BountyHoundDB')
    def test_save_finding_to_db(self, mock_db_class):
        """Test saving finding to database"""
        mock_db = Mock()
        mock_db_class.return_value = mock_db

        tester = APIGatewayBypassTester("https://api.example.com")

        vuln = GatewayBypassVulnerability(
            vuln_id="GW-TEST-001",
            severity=GatewaySeverity.CRITICAL,
            technique=BypassTechnique.PATH_NORMALIZATION,
            title="Test Finding",
            description="Test",
            endpoint="/admin",
            evidence={"test": "data"},
            remediation="Fix",
            cvss_score=9.0
        )

        tester._save_finding_to_db(vuln)

        # Note: Actual DB methods would be called here
        # This tests the flow works without errors

    @patch('engine.agents.api_gateway_bypass_tester.BountyHoundDB')
    def test_record_successful_payload(self, mock_db_class):
        """Test recording successful payload to database"""
        mock_db = Mock()
        mock_db_class.return_value = mock_db

        tester = APIGatewayBypassTester("https://api.example.com")
        tester._record_successful_payload(
            vuln_type='PATH_NORMALIZATION',
            payload='/../{path}',
            context='dot_dot_slash'
        )

        # Verify no exceptions raised


class TestComprehensiveTest:
    """Test comprehensive testing workflow"""

    @patch('requests.Session.get')
    @patch('requests.Session.post')
    @patch('requests.Session.delete')
    def test_run_comprehensive_test(self, mock_delete, mock_post, mock_get):
        """Test running full comprehensive test"""
        # Mock all responses to prevent actual HTTP calls
        response = Mock()
        response.status_code = 403
        response.text = "Forbidden"
        response.headers = {}

        mock_get.return_value = response
        mock_post.return_value = response
        mock_delete.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")
        results = tester.run_comprehensive_test()

        assert 'gateway' in results
        assert 'tests_run' in results
        assert 'vulnerabilities' in results
        assert len(results['tests_run']) == 8  # All 8 test phases

    @patch('requests.Session.get')
    def test_run_comprehensive_test_with_findings(self, mock_get):
        """Test comprehensive test with actual findings"""
        # First request returns 403, second returns 200 (bypass found)
        baseline = Mock()
        baseline.status_code = 403

        bypass = Mock()
        bypass.status_code = 200
        bypass.text = "Admin panel"

        mock_get.side_effect = [baseline, bypass] + [baseline] * 100

        tester = APIGatewayBypassTester("https://api.example.com")
        results = tester.run_comprehensive_test()

        assert len(results['vulnerabilities']) > 0


class TestErrorHandling:
    """Test error handling"""

    @patch('requests.Session.get')
    def test_network_error_handling(self, mock_get):
        """Test handling of network errors"""
        mock_get.side_effect = Exception("Network error")

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_path_normalization()

        # Should not crash, just return empty list
        assert len(vulns) == 0

    @patch('requests.Session.get')
    def test_timeout_handling(self, mock_get):
        """Test handling of timeouts"""
        import requests
        mock_get.side_effect = requests.Timeout("Request timed out")

        tester = APIGatewayBypassTester("https://api.example.com")
        vulns = tester.test_header_injection()

        assert len(vulns) == 0

    def test_invalid_url_handling(self):
        """Test handling of invalid URLs"""
        # Should not crash on initialization
        tester = APIGatewayBypassTester("not-a-valid-url")
        assert tester.gateway_url == "not-a-valid-url"


class TestEdgeCases:
    """Test edge cases"""

    def test_empty_vulnerability_list(self):
        """Test with no vulnerabilities found"""
        tester = APIGatewayBypassTester("https://api.example.com")
        assert len(tester.vulnerabilities) == 0

    @patch('requests.Session.get')
    def test_mixed_status_codes(self, mock_get):
        """Test handling of various HTTP status codes"""
        responses = [
            Mock(status_code=200),
            Mock(status_code=301),
            Mock(status_code=403),
            Mock(status_code=404),
            Mock(status_code=500),
        ]
        mock_get.side_effect = responses

        tester = APIGatewayBypassTester("https://api.example.com")
        # Should handle all status codes gracefully

    def test_special_characters_in_url(self):
        """Test URLs with special characters"""
        tester = APIGatewayBypassTester("https://api.example.com/path?param=value&foo=bar")
        assert "https://api.example.com/path?param=value&foo=bar" in tester.gateway_url


# Performance tests
class TestPerformance:
    """Test performance characteristics"""

    @patch('requests.Session.get')
    def test_rate_limit_detection_performance(self, mock_get):
        """Test that rate limit detection doesn't take too long"""
        response = Mock()
        response.status_code = 200
        mock_get.return_value = response

        tester = APIGatewayBypassTester("https://api.example.com")

        start = time.time()
        tester.test_rate_limiting_bypass()
        duration = time.time() - start

        # Should complete within reasonable time even with 100 requests
        assert duration < 5  # 5 seconds max


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=engine.agents.api_gateway_bypass_tester", "--cov-report=term-missing"])
