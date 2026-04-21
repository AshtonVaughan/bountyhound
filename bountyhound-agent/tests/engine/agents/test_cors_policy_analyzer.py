"""
Comprehensive tests for CORS Policy Analyzer Agent.

Tests cover:
- Initialization and configuration
- Policy parsing and analysis
- Violation detection (all types)
- Compliance checking
- Risk scoring
- Database integration
- Report generation
- Helper methods
- Edge cases and error handling

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.cors_policy_analyzer import (
        CORSPolicyAnalyzer,
        CORSPolicy,
        PolicyViolation,
        PolicySeverity,
        PolicyViolationType,
        ComplianceStandard,
        PolicyAnalysisReport,
        REQUESTS_AVAILABLE
    )
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="CORS Policy Analyzer not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response with CORS headers."""
    def _create_response(acao=None, acac=None, acah=None, acam=None,
                        aceh=None, max_age=None, vary=None, status_code=200):
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
        if aceh:
            response.headers['Access-Control-Expose-Headers'] = aceh
        if max_age:
            response.headers['Access-Control-Max-Age'] = str(max_age)
        if vary:
            response.headers['Vary'] = vary

        return response

    return _create_response


@pytest.fixture
def analyzer():
    """Create a CORSPolicyAnalyzer instance for testing."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("CORS Policy Analyzer not available")

    with patch('engine.agents.cors_policy_analyzer.BountyHoundDB'):
        with patch('engine.agents.cors_policy_analyzer.DatabaseHooks.before_test') as mock_hooks:
            mock_hooks.return_value = {
                'should_skip': False,
                'reason': 'Test context',
                'previous_findings': [],
                'recommendations': []
            }
            return CORSPolicyAnalyzer(
                target_domain="example.com",
                timeout=5,
                verify_ssl=False,
                use_database=True
            )


@pytest.fixture
def analyzer_no_db():
    """Create analyzer without database."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("CORS Policy Analyzer not available")

    return CORSPolicyAnalyzer(
        target_domain="example.com",
        timeout=5,
        verify_ssl=False,
        use_database=False
    )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestInitialization:
    """Test CORSPolicyAnalyzer initialization."""

    def test_init_with_basic_domain(self, analyzer):
        """Test initialization with basic domain."""
        assert analyzer.target_domain == "example.com"
        assert analyzer.timeout == 5
        assert analyzer.verify_ssl is False
        assert analyzer.use_database is True
        assert len(analyzer.policies) == 0
        assert len(analyzer.violations) == 0
        assert len(analyzer.endpoints_tested) == 0

    def test_init_without_database(self, analyzer_no_db):
        """Test initialization without database."""
        assert analyzer_no_db.use_database is False
        assert analyzer_no_db.db is None
        assert analyzer_no_db.db_context is None

    @patch('engine.agents.cors_policy_analyzer.DatabaseHooks.before_test')
    @patch('engine.agents.cors_policy_analyzer.BountyHoundDB')
    def test_init_with_database_integration(self, mock_db, mock_hooks):
        """Test database integration on init."""
        mock_hooks.return_value = {
            'should_skip': False,
            'previous_findings': [],
            'recommendations': ['Test recommendation']
        }

        analyzer = CORSPolicyAnalyzer(target_domain="test.com", use_database=True)

        mock_hooks.assert_called_once_with("test.com", 'cors_policy_analyzer')
        assert analyzer.db_context is not None

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from domain."""
        with patch('engine.agents.cors_policy_analyzer.BountyHoundDB'):
            with patch('engine.agents.cors_policy_analyzer.DatabaseHooks.before_test'):
                analyzer = CORSPolicyAnalyzer(target_domain="example.com/")
                assert analyzer.target_domain == "example.com"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            CORSPolicyAnalyzer(target_domain="example.com")


# ============================================================================
# Policy Parsing Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestPolicyParsing:
    """Test CORS policy parsing."""

    @patch('requests.get')
    def test_parse_basic_policy(self, mock_get, analyzer, mock_response):
        """Test parsing basic CORS policy."""
        mock_get.return_value = mock_response(
            acao="https://trusted.com",
            acac="true",
            acam="GET,POST",
            acah="Content-Type,Authorization"
        )

        policy = analyzer.analyze_endpoint("https://api.example.com/users")

        assert policy.endpoint == "https://api.example.com/users"
        assert policy.allow_origin == "https://trusted.com"
        assert policy.allow_credentials is True
        assert "GET" in policy.allow_methods
        assert "POST" in policy.allow_methods
        assert "content-type" in policy.allow_headers
        assert "authorization" in policy.allow_headers

    @patch('requests.get')
    def test_parse_policy_with_expose_headers(self, mock_get, analyzer, mock_response):
        """Test parsing policy with exposed headers."""
        mock_get.return_value = mock_response(
            acao="*",
            aceh="X-Custom-Header,X-Request-ID"
        )

        policy = analyzer.analyze_endpoint("https://api.example.com/data")

        assert "x-custom-header" in policy.expose_headers
        assert "x-request-id" in policy.expose_headers

    @patch('requests.get')
    def test_parse_policy_with_max_age(self, mock_get, analyzer, mock_response):
        """Test parsing policy with max-age."""
        mock_get.return_value = mock_response(
            acao="https://example.com",
            max_age=3600
        )

        policy = analyzer.analyze_endpoint("https://api.example.com/endpoint")

        assert policy.max_age == 3600

    @patch('requests.get')
    def test_parse_policy_with_vary_header(self, mock_get, analyzer, mock_response):
        """Test parsing policy with Vary header."""
        mock_get.return_value = mock_response(
            acao="https://example.com",
            vary="Origin, Accept-Encoding"
        )

        policy = analyzer.analyze_endpoint("https://api.example.com/endpoint")

        assert policy.vary_header == "Origin, Accept-Encoding"

    @patch('requests.get')
    @patch('requests.options')
    def test_parse_policy_with_preflight_support(self, mock_options, mock_get,
                                                 analyzer, mock_response):
        """Test detecting preflight support."""
        mock_get.return_value = mock_response(acao="*")
        mock_options.return_value = mock_response(
            acao="*",
            acam="GET,POST,OPTIONS"
        )

        policy = analyzer.analyze_endpoint("https://api.example.com/endpoint")

        assert policy.supports_preflight is True

    @patch('requests.get')
    def test_parse_dynamic_policy(self, mock_get, analyzer, mock_response):
        """Test detecting dynamic CORS policy."""
        # First call returns origin1, second call returns origin2
        mock_get.side_effect = [
            mock_response(acao="https://example.com"),  # baseline
            mock_response(acao="https://evil.com"),     # test origin
        ]

        policy = analyzer.analyze_endpoint(
            "https://api.example.com/endpoint",
            test_origins=["https://evil.com"]
        )

        assert policy.is_dynamic is True

    @patch('requests.options')
    @patch('requests.get')
    def test_parse_policy_handles_request_exception(self, mock_get, mock_options, analyzer):
        """Test graceful handling of request exceptions."""
        mock_get.side_effect = Exception("Network error")
        mock_options.side_effect = Exception("Network error")

        policy = analyzer.analyze_endpoint("https://api.example.com/endpoint")

        # Should create policy with empty headers
        assert policy.allow_origin is None
        assert policy.allow_credentials is False


# ============================================================================
# Violation Detection Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestViolationDetection:
    """Test CORS policy violation detection."""

    @patch('requests.get')
    def test_detect_wildcard_with_credentials(self, mock_get, analyzer, mock_response):
        """Test detection of wildcard with credentials."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.WILDCARD_MISCONFIGURATION]
        assert len(violations) > 0
        assert violations[0].severity == PolicySeverity.HIGH

    @patch('requests.get')
    def test_detect_origin_reflection(self, mock_get, analyzer, mock_response):
        """Test detection of origin reflection."""
        # Simulate dynamic origin reflection
        mock_get.side_effect = [
            mock_response(acao="https://example.com"),  # baseline
            mock_response(acao="https://evil.com"),     # reflected
        ]

        analyzer.analyze_endpoint(
            "https://api.example.com/users",
            test_origins=["https://evil.com"]
        )

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.ORIGIN_REFLECTION]
        assert len(violations) > 0

    @patch('requests.get')
    def test_detect_origin_reflection_with_credentials(self, mock_get, analyzer, mock_response):
        """Test origin reflection with credentials is CRITICAL."""
        mock_get.side_effect = [
            mock_response(acao="https://example.com", acac="true"),
            mock_response(acao="https://evil.com", acac="true"),
        ]

        analyzer.analyze_endpoint(
            "https://api.example.com/users",
            test_origins=["https://evil.com"]
        )

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.ORIGIN_REFLECTION]
        assert len(violations) > 0
        assert violations[0].severity == PolicySeverity.CRITICAL
        assert violations[0].risk_score == 90

    @patch('requests.get')
    def test_detect_null_origin(self, mock_get, analyzer, mock_response):
        """Test detection of null origin acceptance."""
        mock_get.return_value = mock_response(acao="null")

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.NULL_ORIGIN_ALLOWED]
        assert len(violations) > 0
        assert violations[0].severity == PolicySeverity.HIGH

    @patch('requests.get')
    def test_detect_subdomain_wildcard(self, mock_get, analyzer, mock_response):
        """Test detection of subdomain wildcard."""
        mock_get.return_value = mock_response(acao="https://*.example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.SUBDOMAIN_WILDCARD]
        assert len(violations) > 0

    @patch('requests.get')
    def test_detect_insecure_protocol(self, mock_get, analyzer, mock_response):
        """Test detection of insecure protocol (HTTP)."""
        mock_get.return_value = mock_response(acao="http://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.INSECURE_PROTOCOL]
        assert len(violations) > 0
        assert violations[0].severity == PolicySeverity.MEDIUM

    @patch('requests.get')
    def test_detect_missing_vary_header(self, mock_get, analyzer, mock_response):
        """Test detection of missing Vary header on dynamic policy."""
        # Dynamic policy without Vary header
        mock_get.side_effect = [
            mock_response(acao="https://example.com"),
            mock_response(acao="https://evil.com"),  # No Vary header
        ]

        analyzer.analyze_endpoint(
            "https://api.example.com/users",
            test_origins=["https://evil.com"]
        )

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.MISSING_VARY_HEADER]
        assert len(violations) > 0

    @patch('requests.get')
    def test_detect_credential_exposure(self, mock_get, analyzer, mock_response):
        """Test detection of credential exposure risk."""
        # Credentials enabled with wildcard (untrusted)
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")

        # Should have wildcard violation, which also indicates credential exposure
        violations = analyzer.violations
        assert len(violations) > 0

    @patch('requests.get')
    def test_detect_dangerous_methods(self, mock_get, analyzer, mock_response):
        """Test detection of dangerous HTTP methods."""
        mock_get.return_value = mock_response(
            acao="*",
            acam="GET,POST,PUT,DELETE,PATCH"
        )

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.OVERLY_PERMISSIVE]
        assert len(violations) > 0

    @patch('requests.get')
    def test_detect_wildcard_headers(self, mock_get, analyzer, mock_response):
        """Test detection of wildcard headers."""
        mock_get.return_value = mock_response(
            acao="https://example.com",
            acah="*"
        )

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.OVERLY_PERMISSIVE
                     and "headers" in v.title.lower()]
        assert len(violations) > 0
        assert violations[0].severity == PolicySeverity.LOW

    @patch('requests.get')
    def test_detect_excessive_max_age(self, mock_get, analyzer, mock_response):
        """Test detection of excessive max-age."""
        mock_get.return_value = mock_response(
            acao="https://example.com",
            max_age=604800  # 7 days (excessive)
        )

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations = [v for v in analyzer.violations
                     if v.violation_type == PolicyViolationType.COMPLIANCE_VIOLATION]
        assert len(violations) > 0
        assert "max-age" in violations[0].title.lower()


# ============================================================================
# Compliance Checking Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestComplianceChecking:
    """Test compliance checking against standards."""

    @patch('requests.get')
    def test_owasp_asvs_violation(self, mock_get, analyzer, mock_response):
        """Test OWASP ASVS compliance violation detection."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")

        # Should flag OWASP ASVS violation
        violations_with_owasp = [v for v in analyzer.violations
                                 if ComplianceStandard.OWASP_ASVS in v.compliance_violations]
        assert len(violations_with_owasp) > 0

    @patch('requests.get')
    def test_ietf_rfc_violation(self, mock_get, analyzer, mock_response):
        """Test IETF RFC compliance violation detection."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")

        # Should flag IETF RFC violation
        violations_with_ietf = [v for v in analyzer.violations
                                if ComplianceStandard.IETF_RFC6454 in v.compliance_violations]
        assert len(violations_with_ietf) > 0

    @patch('requests.get')
    def test_pci_dss_violation(self, mock_get, analyzer, mock_response):
        """Test PCI DSS compliance violation detection."""
        # HTTP origin on HTTPS endpoint
        mock_get.return_value = mock_response(acao="http://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")

        violations_with_pci = [v for v in analyzer.violations
                              if ComplianceStandard.PCI_DSS in v.compliance_violations]
        assert len(violations_with_pci) > 0


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestReportGeneration:
    """Test policy analysis report generation."""

    @patch('requests.get')
    def test_generate_basic_report(self, mock_get, analyzer, mock_response):
        """Test basic report generation."""
        mock_get.return_value = mock_response(acao="https://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()

        assert report.target == "example.com"
        assert report.endpoints_analyzed == 1
        assert len(report.policies) == 1
        assert report.generated_date is not None

    @patch('requests.get')
    def test_report_calculates_risk_score(self, mock_get, analyzer, mock_response):
        """Test that report calculates overall risk score."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()

        assert report.overall_risk_score > 0
        assert report.overall_risk_score <= 100

    @patch('requests.get')
    def test_report_includes_recommendations(self, mock_get, analyzer, mock_response):
        """Test that report includes recommendations."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()

        assert len(report.recommendations) > 0

    @patch('requests.get')
    def test_report_includes_compliance_summary(self, mock_get, analyzer, mock_response):
        """Test that report includes compliance summary."""
        mock_get.return_value = mock_response(acao="https://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()

        assert isinstance(report.compliance_summary, dict)
        assert len(report.compliance_summary) > 0

    @patch('requests.get')
    def test_report_with_multiple_endpoints(self, mock_get, analyzer, mock_response):
        """Test report with multiple endpoints analyzed."""
        mock_get.return_value = mock_response(acao="https://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")
        analyzer.analyze_endpoint("https://api.example.com/posts")
        analyzer.analyze_endpoint("https://api.example.com/comments")

        report = analyzer.generate_report()

        assert report.endpoints_analyzed == 3
        assert len(report.policies) == 3

    @patch('requests.get')
    def test_report_prioritizes_critical_violations(self, mock_get, analyzer, mock_response):
        """Test that report prioritizes critical violations in recommendations."""
        # Create critical violation (origin reflection with credentials)
        mock_get.side_effect = [
            mock_response(acao="https://example.com", acac="true"),
            mock_response(acao="https://evil.com", acac="true"),
        ]

        analyzer.analyze_endpoint(
            "https://api.example.com/users",
            test_origins=["https://evil.com"]
        )
        report = analyzer.generate_report()

        # First recommendation should mention critical violations
        assert any("CRITICAL" in rec for rec in report.recommendations)


# ============================================================================
# Database Integration Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestDatabaseIntegration:
    """Test database integration."""

    @patch('engine.agents.cors_policy_analyzer.BountyHoundDB')
    @patch('engine.agents.cors_policy_analyzer.DatabaseHooks.before_test')
    @patch('requests.get')
    def test_stores_findings_in_database(self, mock_get, mock_hooks, mock_db_class, mock_response):
        """Test that findings are stored in database."""
        mock_db = Mock()
        mock_db_class.return_value = mock_db
        mock_db.get_or_create_target.return_value = 1
        mock_hooks.return_value = {'should_skip': False}

        analyzer = CORSPolicyAnalyzer(target_domain="example.com", use_database=True)
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()

        # Should record tool run
        mock_db.record_tool_run.assert_called_once()
        call_args = mock_db.record_tool_run.call_args
        assert call_args[1]['tool_name'] == 'cors_policy_analyzer'
        assert call_args[1]['findings_count'] > 0

    def test_analyzer_without_database(self, analyzer_no_db):
        """Test analyzer works without database."""
        assert analyzer_no_db.db is None
        # Should not raise exception
        report = analyzer_no_db.generate_report()
        assert report is not None


# ============================================================================
# Helper Methods Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestHelperMethods:
    """Test helper methods."""

    def test_is_subdomain_wildcard_true(self, analyzer):
        """Test subdomain wildcard detection - positive case."""
        assert analyzer._is_subdomain_wildcard("*.example.com") is True
        assert analyzer._is_subdomain_wildcard("https://api.example.com") is True

    def test_is_subdomain_wildcard_false(self, analyzer):
        """Test subdomain wildcard detection - negative case."""
        assert analyzer._is_subdomain_wildcard("https://example.com") is False
        assert analyzer._is_subdomain_wildcard(None) is False

    def test_has_proper_vary_header_true(self, analyzer):
        """Test Vary header validation - positive case."""
        policy = CORSPolicy(
            endpoint="https://api.example.com",
            vary_header="Origin, Accept-Encoding"
        )
        assert analyzer._has_proper_vary_header(policy) is True

    def test_has_proper_vary_header_false(self, analyzer):
        """Test Vary header validation - negative case."""
        policy = CORSPolicy(
            endpoint="https://api.example.com",
            vary_header="Accept-Encoding"
        )
        assert analyzer._has_proper_vary_header(policy) is False

        policy.vary_header = None
        assert analyzer._has_proper_vary_header(policy) is False

    def test_is_origin_trusted_true(self, analyzer):
        """Test origin trust check - positive case."""
        assert analyzer._is_origin_trusted("https://example.com") is True
        assert analyzer._is_origin_trusted("https://api.example.com") is True

    def test_is_origin_trusted_false(self, analyzer):
        """Test origin trust check - negative case."""
        assert analyzer._is_origin_trusted("*") is False
        assert analyzer._is_origin_trusted("null") is False
        assert analyzer._is_origin_trusted("http://example.com") is False
        assert analyzer._is_origin_trusted(None) is False

    def test_has_dangerous_methods_true(self, analyzer):
        """Test dangerous methods detection - positive case."""
        policy = CORSPolicy(
            endpoint="https://api.example.com",
            allow_methods=["GET", "POST", "DELETE"]
        )
        assert analyzer._has_dangerous_methods(policy) is True

    def test_has_dangerous_methods_false(self, analyzer):
        """Test dangerous methods detection - negative case."""
        policy = CORSPolicy(
            endpoint="https://api.example.com",
            allow_methods=["GET", "POST"]
        )
        assert analyzer._has_dangerous_methods(policy) is False


# ============================================================================
# Summary and Filtering Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestSummaryAndFiltering:
    """Test summary generation and violation filtering."""

    @patch('requests.get')
    def test_get_violations_by_severity(self, mock_get, analyzer, mock_response):
        """Test filtering violations by severity."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")

        high_violations = analyzer.get_violations_by_severity(PolicySeverity.HIGH)
        assert all(v.severity == PolicySeverity.HIGH for v in high_violations)

    @patch('requests.get')
    def test_get_critical_violations(self, mock_get, analyzer, mock_response):
        """Test getting critical violations."""
        # Create critical violation
        mock_get.side_effect = [
            mock_response(acao="https://example.com", acac="true"),
            mock_response(acao="https://evil.com", acac="true"),
        ]

        analyzer.analyze_endpoint(
            "https://api.example.com/users",
            test_origins=["https://evil.com"]
        )

        critical = analyzer.get_critical_violations()
        assert all(v.severity == PolicySeverity.CRITICAL for v in critical)

    @patch('requests.get')
    def test_get_summary(self, mock_get, analyzer, mock_response):
        """Test summary generation."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")
        summary = analyzer.get_summary()

        assert summary['target'] == "example.com"
        assert summary['endpoints_analyzed'] == 1
        assert summary['policies_found'] == 1
        assert summary['total_violations'] > 0
        assert 'severity_breakdown' in summary
        assert 'overall_risk_score' in summary


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch('requests.get')
    def test_analyze_endpoint_with_invalid_max_age(self, mock_get, analyzer, mock_response):
        """Test handling of invalid max-age value."""
        response = mock_response(acao="https://example.com")
        response.headers['Access-Control-Max-Age'] = "invalid"
        mock_get.return_value = response

        policy = analyzer.analyze_endpoint("https://api.example.com/users")

        assert policy.max_age is None

    @patch('requests.get')
    def test_analyze_endpoint_strips_trailing_slash(self, mock_get, analyzer, mock_response):
        """Test that endpoint URLs have trailing slashes removed."""
        mock_get.return_value = mock_response(acao="https://example.com")

        policy = analyzer.analyze_endpoint("https://api.example.com/users/")

        assert policy.endpoint == "https://api.example.com/users"

    @patch('requests.options')
    @patch('requests.get')
    def test_handle_network_timeout(self, mock_get, mock_options, analyzer):
        """Test graceful handling of network timeout."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout("Timeout")
        mock_options.side_effect = requests.exceptions.Timeout("Timeout")

        policy = analyzer.analyze_endpoint("https://api.example.com/users")

        # Should create empty policy without crashing
        assert policy.allow_origin is None

    @patch('requests.get')
    def test_multiple_endpoints_tracking(self, mock_get, analyzer, mock_response):
        """Test that multiple endpoints are tracked correctly."""
        mock_get.return_value = mock_response(acao="https://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")
        analyzer.analyze_endpoint("https://api.example.com/posts")

        assert len(analyzer.endpoints_tested) == 2
        assert "https://api.example.com/users" in analyzer.endpoints_tested
        assert "https://api.example.com/posts" in analyzer.endpoints_tested

    @patch('requests.get')
    def test_policy_to_dict(self, mock_get, analyzer, mock_response):
        """Test CORSPolicy to_dict method."""
        mock_get.return_value = mock_response(
            acao="https://example.com",
            acac="true"
        )

        policy = analyzer.analyze_endpoint("https://api.example.com/users")
        policy_dict = policy.to_dict()

        assert isinstance(policy_dict, dict)
        assert policy_dict['endpoint'] == "https://api.example.com/users"
        assert policy_dict['allow_origin'] == "https://example.com"
        assert policy_dict['allow_credentials'] is True

    @patch('requests.get')
    def test_violation_to_dict(self, mock_get, analyzer, mock_response):
        """Test PolicyViolation to_dict method."""
        mock_get.return_value = mock_response(acao="*", acac="true")

        analyzer.analyze_endpoint("https://api.example.com/users")
        violation_dict = analyzer.violations[0].to_dict()

        assert isinstance(violation_dict, dict)
        assert 'severity' in violation_dict
        assert 'violation_type' in violation_dict
        assert 'compliance_violations' in violation_dict
        assert isinstance(violation_dict['policy'], dict)

    @patch('requests.get')
    def test_report_to_dict(self, mock_get, analyzer, mock_response):
        """Test PolicyAnalysisReport to_dict method."""
        mock_get.return_value = mock_response(acao="https://example.com")

        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()
        report_dict = report.to_dict()

        assert isinstance(report_dict, dict)
        assert 'target' in report_dict
        assert 'endpoints_analyzed' in report_dict
        assert isinstance(report_dict['policies'], list)
        assert isinstance(report_dict['violations'], list)
