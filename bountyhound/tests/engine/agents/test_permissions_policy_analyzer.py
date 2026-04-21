"""
Comprehensive tests for Permissions-Policy Analyzer Agent.

Tests cover:
- Initialization and configuration
- Missing Permissions-Policy detection
- Legacy Feature-Policy header detection
- Dangerous permission exposure (camera, microphone, geolocation, payment, USB, Bluetooth)
- Wildcard (*) usage detection
- Permissive allowlist detection
- Policy parsing
- POC generation
- Report generation
- Edge cases and error handling
- Database integration

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.permissions_policy_analyzer import (
        PermissionsPolicyAnalyzer,
        PermissionsPolicyFinding,
        PermissionsPolicyAnalysis,
        PermissionsSeverity,
        PermissionsVulnType,
        DANGEROUS_PERMISSIONS,
        REQUESTS_AVAILABLE
    )
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Permissions-Policy analyzer not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(permissions_policy=None, feature_policy=None, status_code=200):
        response = Mock()
        response.status_code = status_code
        response.headers = {}

        if permissions_policy:
            response.headers['Permissions-Policy'] = permissions_policy
        if feature_policy:
            response.headers['Feature-Policy'] = feature_policy

        return response

    return _create_response


@pytest.fixture
def analyzer():
    """Create a PermissionsPolicyAnalyzer instance for testing."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("Permissions-Policy analyzer not available")

    return PermissionsPolicyAnalyzer(
        target_url="https://example.com",
        timeout=5,
        verify_ssl=False
    )


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestInitialization:
    """Test PermissionsPolicyAnalyzer initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com")

        assert analyzer.target_url == "https://example.com"
        assert analyzer.domain == "example.com"
        assert analyzer.scheme == "https"
        assert analyzer.timeout == 10
        assert analyzer.verify_ssl is True
        assert len(analyzer.findings) == 0
        assert len(analyzer.endpoints) == 1
        assert analyzer.endpoints[0] == '/'

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com", timeout=30)

        assert analyzer.timeout == 30

    def test_init_with_custom_endpoints(self):
        """Test initialization with custom endpoints."""
        custom_endpoints = ['/api/v1', '/dashboard', '/admin']
        analyzer = PermissionsPolicyAnalyzer(
            target_url="https://example.com",
            custom_endpoints=custom_endpoints
        )

        assert '/' in analyzer.endpoints
        for endpoint in custom_endpoints:
            assert endpoint in analyzer.endpoints

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com", verify_ssl=False)

        assert analyzer.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com/")

        assert analyzer.target_url == "https://example.com"

    def test_init_extracts_domain_from_subdomain(self):
        """Test domain extraction from subdomain URL."""
        analyzer = PermissionsPolicyAnalyzer(target_url="https://api.example.com")

        assert analyzer.domain == "api.example.com"

    def test_init_extracts_domain_with_port(self):
        """Test domain extraction from URL with port."""
        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com:8443")

        assert analyzer.domain == "example.com:8443"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            PermissionsPolicyAnalyzer(target_url="https://example.com")


# ============================================================================
# Policy Parsing Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestPolicyParsing:
    """Test Permissions-Policy header parsing."""

    def test_parse_empty_policy(self, analyzer):
        """Test parsing empty policy."""
        result = analyzer._parse_permissions_policy("")

        assert result == {}

    def test_parse_single_directive_empty_allowlist(self, analyzer):
        """Test parsing single directive with empty allowlist."""
        policy = "camera=()"
        result = analyzer._parse_permissions_policy(policy)

        assert 'camera' in result
        assert result['camera'] == []

    def test_parse_single_directive_self(self, analyzer):
        """Test parsing directive with self."""
        policy = "camera=(self)"
        result = analyzer._parse_permissions_policy(policy)

        assert 'camera' in result
        assert result['camera'] == ['self']

    def test_parse_single_directive_with_origin(self, analyzer):
        """Test parsing directive with origin."""
        policy = 'camera=(self "https://trusted.com")'
        result = analyzer._parse_permissions_policy(policy)

        assert 'camera' in result
        assert 'self' in result['camera']
        assert 'https://trusted.com' in result['camera']

    def test_parse_multiple_directives(self, analyzer):
        """Test parsing multiple directives."""
        policy = 'camera=(), microphone=(self), geolocation=(self "https://maps.com")'
        result = analyzer._parse_permissions_policy(policy)

        assert 'camera' in result
        assert 'microphone' in result
        assert 'geolocation' in result
        assert result['camera'] == []
        assert result['microphone'] == ['self']
        assert len(result['geolocation']) == 2

    def test_parse_directive_with_wildcard(self, analyzer):
        """Test parsing directive with wildcard."""
        policy = "camera=(*)"
        result = analyzer._parse_permissions_policy(policy)

        assert 'camera' in result
        assert result['camera'] == ['*']

    def test_parse_directive_with_multiple_origins(self, analyzer):
        """Test parsing directive with multiple origins."""
        policy = 'payment=(self "https://pay1.com" "https://pay2.com" "https://pay3.com")'
        result = analyzer._parse_permissions_policy(policy)

        assert 'payment' in result
        assert len(result['payment']) == 4
        assert 'self' in result['payment']
        assert 'https://pay1.com' in result['payment']

    def test_parse_directive_with_spaces(self, analyzer):
        """Test parsing directive with extra spaces."""
        policy = '  camera = ( self )  ,  microphone = ( )  '
        result = analyzer._parse_permissions_policy(policy)

        assert 'camera' in result
        assert 'microphone' in result


# ============================================================================
# Missing Policy Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestMissingPolicy:
    """Test detection of missing Permissions-Policy headers."""

    @patch('requests.Session.get')
    def test_detect_missing_policy(self, mock_get, analyzer, mock_response):
        """Test detection of missing Permissions-Policy and Feature-Policy."""
        mock_get.return_value = mock_response()

        findings = analyzer.run_all_tests()

        assert len(findings) > 0
        missing_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.MISSING_POLICY]
        assert len(missing_findings) == 1
        assert missing_findings[0].severity == PermissionsSeverity.MEDIUM

    @patch('requests.Session.get')
    def test_missing_policy_has_poc(self, mock_get, analyzer, mock_response):
        """Test that missing policy finding includes POC."""
        mock_get.return_value = mock_response()

        findings = analyzer.run_all_tests()
        missing_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.MISSING_POLICY]

        assert missing_findings[0].poc != ""
        assert "iframe" in missing_findings[0].poc.lower()
        assert "curl" in missing_findings[0].poc.lower()

    @patch('requests.Session.get')
    def test_missing_policy_has_recommendation(self, mock_get, analyzer, mock_response):
        """Test that missing policy finding includes recommendation."""
        mock_get.return_value = mock_response()

        findings = analyzer.run_all_tests()
        missing_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.MISSING_POLICY]

        assert missing_findings[0].recommendation != ""
        assert "Permissions-Policy" in missing_findings[0].recommendation


# ============================================================================
# Legacy Feature-Policy Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestLegacyFeaturePolicy:
    """Test detection of legacy Feature-Policy header."""

    @patch('requests.Session.get')
    def test_detect_legacy_feature_policy(self, mock_get, analyzer, mock_response):
        """Test detection of Feature-Policy header without Permissions-Policy."""
        mock_get.return_value = mock_response(feature_policy="camera 'none'; microphone 'none'")

        findings = analyzer.run_all_tests()

        legacy_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.LEGACY_FEATURE_POLICY]
        assert len(legacy_findings) == 1
        assert legacy_findings[0].severity == PermissionsSeverity.LOW

    @patch('requests.Session.get')
    def test_legacy_policy_stores_header(self, mock_get, analyzer, mock_response):
        """Test that legacy policy finding stores the header value."""
        feature_policy = "camera 'none'; microphone 'self'"
        mock_get.return_value = mock_response(feature_policy=feature_policy)

        findings = analyzer.run_all_tests()
        legacy_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.LEGACY_FEATURE_POLICY]

        assert legacy_findings[0].policy_header == feature_policy


# ============================================================================
# Dangerous Permissions Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestDangerousPermissions:
    """Test detection of dangerous permission exposures."""

    @patch('requests.Session.get')
    def test_detect_missing_camera_restriction(self, mock_get, analyzer, mock_response):
        """Test detection of missing camera restriction."""
        # Policy exists but doesn't restrict camera
        mock_get.return_value = mock_response(permissions_policy="geolocation=()")

        findings = analyzer.run_all_tests()

        camera_findings = [f for f in findings if f.permission_name == 'camera']
        assert len(camera_findings) > 0
        assert camera_findings[0].severity == PermissionsSeverity.HIGH

    @patch('requests.Session.get')
    def test_detect_missing_microphone_restriction(self, mock_get, analyzer, mock_response):
        """Test detection of missing microphone restriction."""
        mock_get.return_value = mock_response(permissions_policy="camera=()")

        findings = analyzer.run_all_tests()

        mic_findings = [f for f in findings if f.permission_name == 'microphone']
        assert len(mic_findings) > 0
        assert mic_findings[0].severity == PermissionsSeverity.HIGH

    @patch('requests.Session.get')
    def test_detect_missing_geolocation_restriction(self, mock_get, analyzer, mock_response):
        """Test detection of missing geolocation restriction."""
        mock_get.return_value = mock_response(permissions_policy="camera=()")

        findings = analyzer.run_all_tests()

        geo_findings = [f for f in findings if f.permission_name == 'geolocation']
        assert len(geo_findings) > 0
        assert geo_findings[0].vuln_type == PermissionsVulnType.GEOLOCATION_EXPOSED

    @patch('requests.Session.get')
    def test_detect_missing_payment_restriction(self, mock_get, analyzer, mock_response):
        """Test detection of missing payment restriction."""
        mock_get.return_value = mock_response(permissions_policy="camera=()")

        findings = analyzer.run_all_tests()

        payment_findings = [f for f in findings if f.permission_name == 'payment']
        assert len(payment_findings) > 0
        assert payment_findings[0].vuln_type == PermissionsVulnType.PAYMENT_EXPOSED

    @patch('requests.Session.get')
    def test_detect_missing_usb_restriction(self, mock_get, analyzer, mock_response):
        """Test detection of missing USB restriction."""
        mock_get.return_value = mock_response(permissions_policy="camera=()")

        findings = analyzer.run_all_tests()

        usb_findings = [f for f in findings if f.permission_name == 'usb']
        assert len(usb_findings) > 0
        assert usb_findings[0].severity == PermissionsSeverity.MEDIUM

    @patch('requests.Session.get')
    def test_detect_missing_bluetooth_restriction(self, mock_get, analyzer, mock_response):
        """Test detection of missing Bluetooth restriction."""
        mock_get.return_value = mock_response(permissions_policy="camera=()")

        findings = analyzer.run_all_tests()

        bt_findings = [f for f in findings if f.permission_name == 'bluetooth']
        assert len(bt_findings) > 0
        assert bt_findings[0].vuln_type == PermissionsVulnType.BLUETOOTH_EXPOSED

    @patch('requests.Session.get')
    def test_camera_with_self_is_flagged(self, mock_get, analyzer, mock_response):
        """Test that camera=(self) is flagged as permissive."""
        mock_get.return_value = mock_response(permissions_policy="camera=(self)")

        findings = analyzer.run_all_tests()

        camera_findings = [f for f in findings if f.permission_name == 'camera']
        assert len(camera_findings) > 0
        # Should flag as permissive even with self
        assert any('Permissive' in f.title or 'self' in f.current_allowlist for f in camera_findings)


# ============================================================================
# Wildcard Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestWildcardDetection:
    """Test detection of wildcard (*) usage."""

    @patch('requests.Session.get')
    def test_detect_wildcard_in_camera(self, mock_get, analyzer, mock_response):
        """Test detection of wildcard in camera permission."""
        mock_get.return_value = mock_response(permissions_policy="camera=(*)")

        findings = analyzer.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.WILDCARD_DANGEROUS]
        assert len(wildcard_findings) > 0
        camera_wildcard = [f for f in wildcard_findings if f.permission_name == 'camera']
        assert len(camera_wildcard) > 0
        assert camera_wildcard[0].severity == PermissionsSeverity.HIGH

    @patch('requests.Session.get')
    def test_detect_wildcard_in_microphone(self, mock_get, analyzer, mock_response):
        """Test detection of wildcard in microphone permission."""
        mock_get.return_value = mock_response(permissions_policy="microphone=(*)")

        findings = analyzer.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.WILDCARD_DANGEROUS
                            and f.permission_name == 'microphone']
        assert len(wildcard_findings) > 0
        assert wildcard_findings[0].severity == PermissionsSeverity.HIGH

    @patch('requests.Session.get')
    def test_wildcard_in_non_dangerous_permission_lower_severity(self, mock_get, analyzer, mock_response):
        """Test that wildcard in non-dangerous permission has lower severity."""
        mock_get.return_value = mock_response(permissions_policy="autoplay=(*)")

        findings = analyzer.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.WILDCARD_DANGEROUS
                            and f.permission_name == 'autoplay']
        if wildcard_findings:
            # Should be MEDIUM, not HIGH
            assert wildcard_findings[0].severity == PermissionsSeverity.MEDIUM

    @patch('requests.Session.get')
    def test_wildcard_poc_generated(self, mock_get, analyzer, mock_response):
        """Test that wildcard finding includes POC."""
        mock_get.return_value = mock_response(permissions_policy="camera=(*)")

        findings = analyzer.run_all_tests()

        wildcard_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.WILDCARD_DANGEROUS]
        assert wildcard_findings[0].poc != ""
        assert "iframe" in wildcard_findings[0].poc.lower()


# ============================================================================
# Permissive Allowlist Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestPermissiveAllowlists:
    """Test detection of overly permissive allowlists."""

    @patch('requests.Session.get')
    def test_detect_allowlist_with_3_origins(self, mock_get, analyzer, mock_response):
        """Test detection of allowlist with 3+ origins."""
        policy = 'camera=(self "https://cdn1.com" "https://cdn2.com" "https://cdn3.com")'
        mock_get.return_value = mock_response(permissions_policy=policy)

        findings = analyzer.run_all_tests()

        permissive_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.PERMISSIVE_ALLOWLIST]
        assert len(permissive_findings) > 0

    @patch('requests.Session.get')
    def test_allowlist_with_2_origins_not_flagged(self, mock_get, analyzer, mock_response):
        """Test that allowlist with 2 origins is not flagged."""
        policy = 'camera=(self "https://cdn.com")'
        mock_get.return_value = mock_response(permissions_policy=policy)

        findings = analyzer.run_all_tests()

        permissive_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.PERMISSIVE_ALLOWLIST
                              and f.permission_name == 'camera']
        # Should not flag allowlist with only 2 origins
        assert len(permissive_findings) == 0

    @patch('requests.Session.get')
    def test_permissive_allowlist_severity(self, mock_get, analyzer, mock_response):
        """Test that permissive allowlist has LOW severity."""
        policy = 'payment=(self "https://pay1.com" "https://pay2.com" "https://pay3.com")'
        mock_get.return_value = mock_response(permissions_policy=policy)

        findings = analyzer.run_all_tests()

        permissive_findings = [f for f in findings if f.vuln_type == PermissionsVulnType.PERMISSIVE_ALLOWLIST]
        assert permissive_findings[0].severity == PermissionsSeverity.LOW


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestPOCGeneration:
    """Test proof-of-concept generation."""

    def test_generate_missing_policy_poc(self, analyzer):
        """Test POC generation for missing policy."""
        poc = analyzer._generate_missing_policy_poc("https://example.com")

        assert "iframe" in poc.lower()
        assert "curl" in poc.lower()
        assert "example.com" in poc

    def test_generate_permission_poc_with_allowlist(self, analyzer):
        """Test POC generation for permission with allowlist."""
        poc = analyzer._generate_permission_poc(
            "https://example.com",
            "camera",
            ["self", "https://trusted.com"]
        )

        assert "camera" in poc
        assert "iframe" in poc.lower()
        assert poc != ""

    def test_generate_permission_poc_without_allowlist(self, analyzer):
        """Test POC generation for permission without allowlist."""
        poc = analyzer._generate_permission_poc("https://example.com", "microphone", None)

        assert "microphone" in poc
        assert "iframe" in poc.lower()
        assert poc != ""

    def test_generate_wildcard_poc(self, analyzer):
        """Test POC generation for wildcard permission."""
        poc = analyzer._generate_wildcard_poc("https://example.com", "geolocation")

        assert "geolocation" in poc
        assert "*" in poc or "wildcard" in poc.lower()
        assert "iframe" in poc.lower()


# ============================================================================
# Summary and Report Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestSummaryAndReports:
    """Test summary and report generation."""

    @patch('requests.Session.get')
    def test_generate_summary(self, mock_get, analyzer, mock_response):
        """Test summary generation."""
        mock_get.return_value = mock_response(permissions_policy="autoplay=(*)")

        analyzer.run_all_tests()
        summary = analyzer.generate_summary()

        assert 'total_findings' in summary
        assert 'by_severity' in summary
        assert 'by_vuln_type' in summary
        assert 'endpoints_tested' in summary
        assert 'dangerous_permissions_exposed' in summary
        assert 'wildcard_permissions' in summary

    @patch('requests.Session.get')
    def test_summary_counts_by_severity(self, mock_get, analyzer, mock_response):
        """Test that summary correctly counts findings by severity."""
        mock_get.return_value = mock_response(permissions_policy="camera=(*)")

        analyzer.run_all_tests()
        summary = analyzer.generate_summary()

        assert summary['total_findings'] > 0
        assert isinstance(summary['by_severity'], dict)

    @patch('requests.Session.get')
    def test_summary_tracks_dangerous_permissions(self, mock_get, analyzer, mock_response):
        """Test that summary tracks dangerous permissions exposed."""
        mock_get.return_value = mock_response(permissions_policy="geolocation=()")

        analyzer.run_all_tests()
        summary = analyzer.generate_summary()

        # Many dangerous permissions are exposed (missing from policy)
        assert len(summary['dangerous_permissions_exposed']) > 0

    @patch('requests.Session.get')
    def test_generate_report(self, mock_get, analyzer, mock_response):
        """Test full report generation."""
        mock_get.return_value = mock_response(permissions_policy="camera=(*)")

        analyzer.run_all_tests()
        report = analyzer.generate_report()

        assert "PERMISSIONS-POLICY SECURITY ANALYSIS REPORT" in report
        assert analyzer.target_url in report
        assert "SEVERITY BREAKDOWN" in report
        assert "DETAILED FINDINGS" in report

    @patch('requests.Session.get')
    def test_report_includes_all_findings(self, mock_get, analyzer, mock_response):
        """Test that report includes all findings."""
        mock_get.return_value = mock_response()

        analyzer.run_all_tests()
        report = analyzer.generate_report()

        # Should include details from findings
        assert len(report) > 100  # Should be substantial
        for finding in analyzer.findings[:3]:  # Check first few findings
            assert finding.title in report or finding.vuln_type.value in report


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch('requests.Session.get')
    def test_handle_request_exception(self, mock_get, analyzer):
        """Test handling of request exceptions."""
        mock_get.side_effect = Exception("Network error")

        # Should not raise exception
        findings = analyzer.run_all_tests()

        # Should return empty or handle gracefully
        assert isinstance(findings, list)

    @patch('requests.Session.get')
    def test_handle_timeout(self, mock_get, analyzer):
        """Test handling of request timeout."""
        import requests
        mock_get.side_effect = requests.Timeout("Request timeout")

        findings = analyzer.run_all_tests()
        assert isinstance(findings, list)

    @patch('requests.Session.get')
    def test_multiple_endpoints(self, mock_get, mock_response):
        """Test analysis of multiple endpoints."""
        mock_get.return_value = mock_response(permissions_policy="camera=()")

        analyzer = PermissionsPolicyAnalyzer(
            target_url="https://example.com",
            custom_endpoints=['/api', '/dashboard']
        )

        findings = analyzer.run_all_tests()

        assert len(analyzer.analyses) == 3  # /, /api, /dashboard

    @patch('requests.Session.get')
    def test_empty_permissions_policy_header(self, mock_get, analyzer, mock_response):
        """Test handling of empty Permissions-Policy header."""
        mock_get.return_value = mock_response(permissions_policy="")

        findings = analyzer.run_all_tests()

        # Should detect as missing policy
        assert any(f.vuln_type == PermissionsVulnType.MISSING_POLICY for f in findings)

    def test_vuln_type_mapping(self, analyzer):
        """Test vulnerability type mapping for permissions."""
        assert analyzer._get_vuln_type_for_permission('camera') == PermissionsVulnType.CAMERA_EXPOSED
        assert analyzer._get_vuln_type_for_permission('microphone') == PermissionsVulnType.MICROPHONE_EXPOSED
        assert analyzer._get_vuln_type_for_permission('geolocation') == PermissionsVulnType.GEOLOCATION_EXPOSED
        assert analyzer._get_vuln_type_for_permission('payment') == PermissionsVulnType.PAYMENT_EXPOSED
        assert analyzer._get_vuln_type_for_permission('usb') == PermissionsVulnType.USB_EXPOSED
        assert analyzer._get_vuln_type_for_permission('bluetooth') == PermissionsVulnType.BLUETOOTH_EXPOSED

    def test_vuln_type_mapping_unknown(self, analyzer):
        """Test vulnerability type mapping for unknown permissions."""
        result = analyzer._get_vuln_type_for_permission('unknown-permission')
        assert result == PermissionsVulnType.MISSING_POLICY


# ============================================================================
# Finding Dataclass Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestFindingDataclass:
    """Test PermissionsPolicyFinding dataclass."""

    def test_finding_to_dict(self):
        """Test conversion of finding to dictionary."""
        finding = PermissionsPolicyFinding(
            title="Test Finding",
            severity=PermissionsSeverity.HIGH,
            vuln_type=PermissionsVulnType.CAMERA_EXPOSED,
            description="Test description",
            endpoint="https://example.com",
            permission_name="camera"
        )

        result = finding.to_dict()

        assert result['title'] == "Test Finding"
        assert result['severity'] == "HIGH"
        assert result['vuln_type'] == "PERMISSIONS_POLICY_CAMERA_EXPOSED"
        assert result['permission_name'] == "camera"

    def test_finding_default_values(self):
        """Test finding default values."""
        finding = PermissionsPolicyFinding(
            title="Test",
            severity=PermissionsSeverity.MEDIUM,
            vuln_type=PermissionsVulnType.MISSING_POLICY,
            description="Test",
            endpoint="https://example.com"
        )

        assert finding.cwe_id == "CWE-1021"
        assert finding.discovered_date == date.today().isoformat()
        assert finding.poc == ""
        assert finding.impact == ""


# ============================================================================
# Analysis Dataclass Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestAnalysisDataclass:
    """Test PermissionsPolicyAnalysis dataclass."""

    def test_analysis_to_dict(self):
        """Test conversion of analysis to dictionary."""
        analysis = PermissionsPolicyAnalysis(
            endpoint="https://example.com",
            has_permissions_policy=True,
            has_feature_policy=False,
            permissions_policy_header="camera=()",
            parsed_directives={'camera': []}
        )

        result = analysis.to_dict()

        assert result['endpoint'] == "https://example.com"
        assert result['has_permissions_policy'] is True
        assert result['has_feature_policy'] is False
        assert result['permissions_policy_header'] == "camera=()"
        assert 'camera' in result['parsed_directives']


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not ANALYZER_AVAILABLE, reason="Analyzer not available")
class TestIntegration:
    """Integration tests for complete workflows."""

    @patch('requests.Session.get')
    def test_complete_analysis_workflow(self, mock_get, mock_response):
        """Test complete analysis workflow from init to report."""
        # Setup
        mock_get.return_value = mock_response(
            permissions_policy='camera=(self "https://cdn.com" "https://cdn2.com" "https://cdn3.com")'
        )

        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com")

        # Execute
        findings = analyzer.run_all_tests()
        summary = analyzer.generate_summary()
        report = analyzer.generate_report()

        # Verify
        assert len(findings) > 0
        assert summary['total_findings'] > 0
        assert len(report) > 0
        assert "example.com" in report

    @patch('requests.Session.get')
    def test_analysis_with_multiple_vulnerabilities(self, mock_get, mock_response):
        """Test analysis detecting multiple vulnerability types."""
        # Policy with multiple issues
        mock_get.return_value = mock_response(
            permissions_policy='camera=(*), geolocation=(self "https://a.com" "https://b.com" "https://c.com")'
        )

        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com")
        findings = analyzer.run_all_tests()

        # Should detect:
        # - Wildcard in camera (HIGH)
        # - Permissive allowlist for geolocation (LOW)
        # - Missing restrictions for other dangerous permissions (HIGH/MEDIUM)
        assert len(findings) > 3

        vuln_types = {f.vuln_type for f in findings}
        assert PermissionsVulnType.WILDCARD_DANGEROUS in vuln_types

    @patch('requests.Session.get')
    def test_analysis_with_secure_policy(self, mock_get, mock_response):
        """Test analysis with secure policy (minimal findings)."""
        # Secure policy restricting all dangerous permissions
        secure_policy = (
            'camera=(), microphone=(), geolocation=(), payment=(), '
            'usb=(), bluetooth=(), sync-xhr=()'
        )
        mock_get.return_value = mock_response(permissions_policy=secure_policy)

        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com")
        findings = analyzer.run_all_tests()

        # Should have minimal findings (maybe some INFO or LOW)
        high_findings = [f for f in findings if f.severity in [PermissionsSeverity.HIGH, PermissionsSeverity.CRITICAL]]
        assert len(high_findings) == 0  # No high/critical with secure policy
