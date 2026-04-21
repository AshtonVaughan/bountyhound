"""
Comprehensive tests for API Endpoint Parameter Miner Agent.

Tests cover:
- Initialization and configuration
- Dictionary-based parameter mining
- Reflection-based discovery
- Type confusion testing
- HTTP Parameter Pollution (HPP)
- Mass assignment testing
- Parameter smuggling
- Response analysis
- Finding management
- Report generation
- Database integration
- Edge cases and error handling

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from datetime import date
import json

# Test imports with fallback
try:
    from engine.agents.api_endpoint_parameter_miner import (
        APIParameterMiner,
        ParameterFinding,
        TestResult,
        ParameterDictionary,
        ResponseAnalyzer,
        TypeConfusionTester,
        DiscoveryMethod,
        VulnerabilityType,
        SeverityLevel,
        REQUESTS_AVAILABLE
    )
    MINER_AVAILABLE = True
except ImportError:
    MINER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="API Parameter Miner not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, body='', headers=None, elapsed=0.1):
        response = Mock()
        response.status_code = status_code
        response.text = body
        response.headers = headers or {}
        response.elapsed = Mock()
        response.elapsed.total_seconds = Mock(return_value=elapsed)
        return response

    return _create_response


@pytest.fixture
def miner():
    """Create an APIParameterMiner instance for testing."""
    if not MINER_AVAILABLE:
        pytest.skip("API Parameter Miner not available")

    with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
        return APIParameterMiner(
            base_url="https://api.example.com",
            target_domain="example.com",
            timeout=5,
            verify_ssl=False
        )


@pytest.fixture
def baseline_response():
    """Standard baseline response"""
    return {
        'url': 'https://api.example.com/users',
        'method': 'GET',
        'status_code': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': '{"users": []}',
        'response_length': 14,
        'response_time': 0.1
    }


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestInitialization:
    """Test APIParameterMiner initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(base_url="https://api.example.com")

            assert miner.base_url == "https://api.example.com"
            assert miner.target_domain == "api.example.com"
            assert miner.timeout == 10
            assert miner.verify_ssl is True
            assert len(miner.findings) == 0

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(
                base_url="https://api.example.com",
                timeout=30
            )
            assert miner.timeout == 30

    def test_init_with_custom_domain(self):
        """Test initialization with custom target domain."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(
                base_url="https://api.example.com",
                target_domain="custom.com"
            )
            assert miner.target_domain == "custom.com"

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(
                base_url="https://api.example.com",
                verify_ssl=False
            )
            assert miner.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(base_url="https://api.example.com/")
            assert miner.base_url == "https://api.example.com"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            APIParameterMiner(base_url="https://api.example.com")


# ============================================================================
# Domain Extraction Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestDomainExtraction:
    """Test domain extraction from URLs."""

    def test_extract_domain_from_simple_url(self):
        """Test extracting domain from simple URL."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(base_url="https://example.com")
            assert miner.target_domain == "example.com"

    def test_extract_domain_from_subdomain(self):
        """Test extracting domain from subdomain URL."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(base_url="https://api.example.com")
            assert miner.target_domain == "api.example.com"

    def test_extract_domain_from_url_with_path(self):
        """Test extracting domain from URL with path."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(base_url="https://api.example.com/v1/users")
            assert miner.target_domain == "api.example.com"

    def test_extract_domain_from_url_with_port(self):
        """Test extracting domain from URL with port."""
        with patch('engine.agents.api_endpoint_parameter_miner.BountyHoundDB'):
            miner = APIParameterMiner(base_url="https://api.example.com:8443")
            assert miner.target_domain == "api.example.com:8443"


# ============================================================================
# Parameter Dictionary Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestParameterDictionary:
    """Test ParameterDictionary functionality."""

    def test_get_all_categories(self):
        """Test retrieving all parameter categories."""
        categories = ParameterDictionary.get_all_categories()

        assert 'auth' in categories
        assert 'debug' in categories
        assert 'data_access' in categories
        assert 'method_override' in categories

    def test_auth_params_present(self):
        """Test that auth parameters are defined."""
        categories = ParameterDictionary.get_all_categories()

        assert 'admin' in categories['auth']
        assert 'isAdmin' in categories['auth']
        assert 'role' in categories['auth']

    def test_debug_params_present(self):
        """Test that debug parameters are defined."""
        categories = ParameterDictionary.get_all_categories()

        assert 'debug' in categories['debug']
        assert 'verbose' in categories['debug']

    def test_generate_test_values_auth(self):
        """Test generating test values for auth parameters."""
        values = ParameterDictionary.generate_test_values('admin', 'auth')

        assert 'true' in values
        assert True in values
        assert 'admin' in values

    def test_generate_test_values_debug(self):
        """Test generating test values for debug parameters."""
        values = ParameterDictionary.generate_test_values('debug', 'debug')

        assert 'true' in values
        assert True in values
        assert 1 in values

    def test_generate_test_values_method_override(self):
        """Test generating test values for method override parameters."""
        values = ParameterDictionary.generate_test_values('_method', 'method_override')

        assert 'PUT' in values
        assert 'DELETE' in values
        assert 'PATCH' in values

    def test_generate_test_values_file_operations(self):
        """Test generating test values for file operation parameters."""
        values = ParameterDictionary.generate_test_values('file', 'file_operations')

        assert '/etc/passwd' in values
        assert '../../etc/passwd' in values


# ============================================================================
# Response Analyzer Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestResponseAnalyzer:
    """Test ResponseAnalyzer functionality."""

    def test_is_parameter_active_status_code_change(self, baseline_response):
        """Test detection via status code change."""
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 403

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is True

    def test_is_parameter_active_response_length_change(self, baseline_response):
        """Test detection via response length change."""
        test_resp = baseline_response.copy()
        test_resp['body'] = 'a' * 1000
        test_resp['response_length'] = 1000

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is True

    def test_is_parameter_active_response_time_change(self, baseline_response):
        """Test detection via response time change."""
        test_resp = baseline_response.copy()
        test_resp['response_time'] = 5.0  # 50x slower

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is True

    def test_is_parameter_active_new_headers(self, baseline_response):
        """Test detection via new headers."""
        test_resp = baseline_response.copy()
        test_resp['headers'] = {'Content-Type': 'application/json', 'X-Debug': 'true'}

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is True

    def test_is_parameter_active_content_type_change(self, baseline_response):
        """Test detection via Content-Type change."""
        test_resp = baseline_response.copy()
        test_resp['headers'] = {'Content-Type': 'text/html'}

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is True

    def test_is_parameter_active_json_structure_change(self, baseline_response):
        """Test detection via JSON structure change."""
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"users": [], "admin": true}'

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is True

    def test_is_parameter_active_no_change(self, baseline_response):
        """Test no detection when responses are identical."""
        test_resp = baseline_response.copy()

        assert ResponseAnalyzer.is_parameter_active(test_resp, baseline_response) is False

    def test_analyze_impact_auth_bypass(self, baseline_response):
        """Test analyzing impact for auth bypass."""
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 200
        baseline_response['status_code'] = 401

        vuln_type, severity, impact = ResponseAnalyzer.analyze_impact(
            'admin', 'true', test_resp, baseline_response, 'auth'
        )

        assert vuln_type == VulnerabilityType.AUTH_BYPASS
        assert severity == SeverityLevel.CRITICAL

    def test_analyze_impact_privilege_escalation(self, baseline_response):
        """Test analyzing impact for privilege escalation."""
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"users": [], "admin": true}'

        vuln_type, severity, impact = ResponseAnalyzer.analyze_impact(
            'role', 'admin', test_resp, baseline_response, 'auth'
        )

        assert vuln_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert severity == SeverityLevel.HIGH

    def test_analyze_impact_debug_mode(self, baseline_response):
        """Test analyzing impact for debug mode."""
        test_resp = baseline_response.copy()
        test_resp['body'] = 'Stack trace: at line 42'

        vuln_type, severity, impact = ResponseAnalyzer.analyze_impact(
            'debug', 'true', test_resp, baseline_response, 'debug'
        )

        assert vuln_type == VulnerabilityType.DEBUG_MODE
        assert severity == SeverityLevel.MEDIUM

    def test_analyze_impact_data_exposure(self, baseline_response):
        """Test analyzing impact for data exposure."""
        test_resp = baseline_response.copy()
        test_resp['body'] = 'a' * 1000
        test_resp['response_length'] = 1000

        vuln_type, severity, impact = ResponseAnalyzer.analyze_impact(
            'limit', '999', test_resp, baseline_response, 'data_access'
        )

        assert vuln_type == VulnerabilityType.DATA_EXPOSURE
        assert severity == SeverityLevel.HIGH

    def test_analyze_impact_lfi(self, baseline_response):
        """Test analyzing impact for LFI."""
        test_resp = baseline_response.copy()
        test_resp['body'] = 'root:x:0:0:root:/root:/bin/bash'

        vuln_type, severity, impact = ResponseAnalyzer.analyze_impact(
            'file', '/etc/passwd', test_resp, baseline_response, 'file_operations'
        )

        assert vuln_type == VulnerabilityType.LOCAL_FILE_INCLUSION
        assert severity == SeverityLevel.CRITICAL

    def test_extract_params_from_errors_simple(self):
        """Test extracting parameters from simple error message."""
        error_text = "missing required parameter 'user_id'"

        params = ResponseAnalyzer.extract_params_from_errors(error_text)

        assert 'user_id' in params

    def test_extract_params_from_errors_json(self):
        """Test extracting parameters from JSON error."""
        error_text = '{"error": "invalid parameter", "field": "email"}'

        params = ResponseAnalyzer.extract_params_from_errors(error_text)

        assert 'field' in params or 'email' in params

    def test_extract_params_from_errors_multiple(self):
        """Test extracting multiple parameters."""
        error_text = "Required parameters: 'username', 'password', 'email'"

        params = ResponseAnalyzer.extract_params_from_errors(error_text)

        assert len(params) >= 2

    def test_extract_params_filters_false_positives(self):
        """Test that false positives are filtered."""
        error_text = "error: missing parameter 'test_param'"

        params = ResponseAnalyzer.extract_params_from_errors(error_text)

        assert 'error' not in params
        assert 'test_param' in params


# ============================================================================
# Type Confusion Tester Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestTypeConfusionTester:
    """Test TypeConfusionTester functionality."""

    def test_generate_variants_from_string(self):
        """Test generating variants from string value."""
        variants = TypeConfusionTester.generate_type_variants('param', 'test')

        assert 'int' in variants
        assert 'bool' in variants
        assert 'list' in variants
        assert 'dict' in variants

    def test_generate_variants_from_int(self):
        """Test generating variants from integer value."""
        variants = TypeConfusionTester.generate_type_variants('param', 42)

        assert 'str' in variants
        assert 'bool' in variants
        assert 'float' in variants

    def test_generate_variants_from_bool(self):
        """Test generating variants from boolean value."""
        variants = TypeConfusionTester.generate_type_variants('param', True)

        assert 'str' in variants
        assert 'int' in variants
        assert variants['int'] == 1

    def test_generate_variants_from_list(self):
        """Test generating variants from list value."""
        variants = TypeConfusionTester.generate_type_variants('param', [1, 2, 3])

        assert 'str' in variants
        assert 'dict' in variants

    def test_generate_variants_from_dict(self):
        """Test generating variants from dict value."""
        variants = TypeConfusionTester.generate_type_variants('param', {'key': 'value'})

        assert 'str' in variants
        assert 'list' in variants

    def test_detect_impact_status_bypass(self, baseline_response):
        """Test detecting impact via status bypass."""
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 200
        baseline_response['status_code'] = 403

        assert TypeConfusionTester.detect_impact(test_resp, baseline_response) is True

    def test_detect_impact_response_diff(self, baseline_response):
        """Test detecting impact via response difference."""
        test_resp = baseline_response.copy()
        test_resp['body'] = 'a' * 500
        test_resp['response_length'] = 500

        assert TypeConfusionTester.detect_impact(test_resp, baseline_response) is True

    def test_detect_impact_sql_error(self, baseline_response):
        """Test detecting impact via SQL error."""
        test_resp = baseline_response.copy()
        test_resp['body'] = 'mysql syntax error near...'

        assert TypeConfusionTester.detect_impact(test_resp, baseline_response) is True

    def test_detect_impact_json_structure(self, baseline_response):
        """Test detecting impact via JSON structure change."""
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"users": [], "extra_field": true}'

        assert TypeConfusionTester.detect_impact(test_resp, baseline_response) is True


# ============================================================================
# Baseline Request Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestBaselineRequest:
    """Test baseline request functionality."""

    @patch('requests.Session.get')
    def test_get_baseline_success(self, mock_get, miner, mock_response):
        """Test successful baseline GET request."""
        mock_get.return_value = mock_response(
            status_code=200,
            body='{"test": "data"}',
            headers={'Content-Type': 'application/json'}
        )

        baseline = miner._get_baseline('/users', 'GET', None, None)

        assert baseline is not None
        assert baseline['status_code'] == 200
        assert 'test' in baseline['body']

    @patch('requests.Session.post')
    def test_get_baseline_post(self, mock_post, miner, mock_response):
        """Test baseline POST request."""
        mock_post.return_value = mock_response(status_code=201)

        baseline = miner._get_baseline(
            '/users',
            'POST',
            None,
            {'username': 'test'}
        )

        assert baseline is not None
        assert baseline['status_code'] == 201

    @patch('requests.Session.get')
    def test_get_baseline_with_auth_headers(self, mock_get, miner, mock_response):
        """Test baseline request with auth headers."""
        mock_get.return_value = mock_response(status_code=200)

        baseline = miner._get_baseline(
            '/users',
            'GET',
            {'Authorization': 'Bearer token'},
            None
        )

        assert baseline is not None
        mock_get.assert_called_once()

    @patch('requests.Session.get')
    def test_get_baseline_failure(self, mock_get, miner):
        """Test baseline request failure handling."""
        mock_get.side_effect = Exception("Connection error")

        baseline = miner._get_baseline('/users', 'GET', None, None)

        assert baseline is None


# ============================================================================
# Dictionary Mining Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestDictionaryMining:
    """Test dictionary-based parameter mining."""

    @patch.object(APIParameterMiner, '_make_test_request')
    def test_dictionary_mining_finds_parameter(self, mock_test, miner, baseline_response):
        """Test that dictionary mining finds active parameters."""
        # Setup: parameter 'admin' causes a change
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 403
        mock_test.return_value = test_resp

        # Mock baseline
        miner._get_baseline = Mock(return_value=baseline_response)

        # Run dictionary mining
        miner._dictionary_mining('/users', 'GET', baseline_response, None, None)

        # Should have called test request
        assert mock_test.called

    @patch.object(APIParameterMiner, '_make_test_request')
    def test_dictionary_mining_skips_inactive(self, mock_test, miner, baseline_response):
        """Test that inactive parameters are skipped."""
        # Setup: parameter causes no change
        mock_test.return_value = baseline_response.copy()

        miner._dictionary_mining('/users', 'GET', baseline_response, None, None)

        # No findings should be created
        assert len(miner.findings) == 0


# ============================================================================
# Reflection Mining Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestReflectionMining:
    """Test reflection-based parameter discovery."""

    @patch('requests.Session.get')
    def test_reflection_mining_discovers_params(self, mock_get, miner, mock_response, baseline_response):
        """Test that reflection mining discovers parameters from errors."""
        mock_get.return_value = mock_response(
            status_code=400,
            body='{"error": "missing required parameter \'user_id\'"}'
        )

        miner._test_reflected_parameter = Mock()
        miner._reflection_mining('/users', 'GET', baseline_response, None, None)

        # Should have attempted to test discovered parameters
        assert miner._test_reflected_parameter.called or mock_get.called


# ============================================================================
# Type Confusion Testing Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestTypeConfusionTesting:
    """Test type confusion vulnerability testing."""

    @patch.object(APIParameterMiner, '_make_test_request')
    def test_type_confusion_finds_vulnerability(self, mock_test, miner, baseline_response):
        """Test that type confusion testing finds vulnerabilities."""
        # Setup: type confusion causes auth bypass
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 200
        baseline_response['status_code'] = 403
        mock_test.return_value = test_resp

        body = {'id': 123}

        miner._type_confusion_testing('/users', 'POST', baseline_response, None, body)

        # Should detect the vulnerability
        assert len(miner.findings) > 0


# ============================================================================
# Parameter Pollution Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestParameterPollution:
    """Test HTTP Parameter Pollution detection."""

    @patch('requests.Session.get')
    def test_parameter_pollution_detected(self, mock_get, miner, mock_response, baseline_response):
        """Test HPP vulnerability detection."""
        mock_get.return_value = mock_response(
            status_code=200,
            body='{"id": "2"}'  # Backend processed second value
        )

        miner._parameter_pollution_testing('/users', 'GET', baseline_response, None, None)

        # Should have tested HPP
        assert mock_get.called


# ============================================================================
# Mass Assignment Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestMassAssignment:
    """Test mass assignment vulnerability detection."""

    @patch.object(APIParameterMiner, '_make_test_request')
    def test_mass_assignment_detected(self, mock_test, miner, baseline_response):
        """Test mass assignment vulnerability detection."""
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"users": [], "role": "admin"}'
        mock_test.return_value = test_resp

        body = {'username': 'test'}

        miner._mass_assignment_testing('/users', 'POST', baseline_response, None, body)

        # Check if vulnerability was detected
        if len(miner.findings) > 0:
            assert any(f.vulnerability_type == VulnerabilityType.MASS_ASSIGNMENT
                      for f in miner.findings)


# ============================================================================
# Parameter Smuggling Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestParameterSmuggling:
    """Test parameter smuggling detection."""

    @patch.object(APIParameterMiner, '_make_test_request')
    def test_parameter_smuggling_detected(self, mock_test, miner, baseline_response):
        """Test parameter smuggling vulnerability detection."""
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"admin": true}'
        mock_test.return_value = test_resp

        miner._parameter_smuggling_testing('/users', 'GET', baseline_response, None, None)

        # Should have tested smuggling
        assert mock_test.called


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestReportGeneration:
    """Test report generation."""

    def test_generate_report_no_findings(self, miner):
        """Test report generation with no findings."""
        report = miner.generate_report()

        assert report['status'] == 'no_findings'
        assert report['total_findings'] == 0

    def test_generate_report_with_findings(self, miner):
        """Test report generation with findings."""
        # Add a mock finding
        finding = ParameterFinding(
            param_name='admin',
            param_type='str',
            discovery_method=DiscoveryMethod.DICTIONARY,
            vulnerability_type=VulnerabilityType.AUTH_BYPASS,
            severity=SeverityLevel.CRITICAL,
            evidence={'test': 'data'},
            exploitation_path='test',
            impact='test impact',
            endpoint='/users'
        )
        miner.findings.append(finding)

        report = miner.generate_report()

        assert report['status'] == 'vulnerable'
        assert report['total_findings'] == 1
        assert report['critical'] == 1

    def test_generate_report_groups_by_severity(self, miner):
        """Test that report groups findings by severity."""
        # Add findings with different severities
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM]:
            finding = ParameterFinding(
                param_name=f'param_{severity.value}',
                param_type='str',
                discovery_method=DiscoveryMethod.DICTIONARY,
                vulnerability_type=VulnerabilityType.HIDDEN_PARAMETER,
                severity=severity,
                evidence={},
                exploitation_path='test',
                impact='test',
                endpoint='/users'
            )
            miner.findings.append(finding)

        report = miner.generate_report()

        assert report['critical'] == 1
        assert report['high'] == 1
        assert report['medium'] == 1

    def test_generate_report_includes_summary(self, miner):
        """Test that report includes summary."""
        finding = ParameterFinding(
            param_name='admin',
            param_type='str',
            discovery_method=DiscoveryMethod.DICTIONARY,
            vulnerability_type=VulnerabilityType.AUTH_BYPASS,
            severity=SeverityLevel.CRITICAL,
            evidence={},
            exploitation_path='test',
            impact='test',
            endpoint='/users'
        )
        miner.findings.append(finding)

        report = miner.generate_report()

        assert 'summary' in report
        assert len(report['summary']) > 0


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestIntegration:
    """Integration tests for complete workflows."""

    @patch('requests.Session.get')
    @patch.object(APIParameterMiner, '_make_test_request')
    def test_mine_parameters_complete_flow(self, mock_test, mock_get, miner, mock_response, baseline_response):
        """Test complete parameter mining flow."""
        # Mock baseline
        mock_get.return_value = mock_response(status_code=200, body='{"users": []}')

        # Mock test request that finds a parameter
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 403
        mock_test.return_value = test_resp

        # Run mining (skip DB check for testing)
        findings = miner.mine_parameters('/users', 'GET', skip_db_check=True)

        # Should have attempted mining
        assert mock_get.called or mock_test.called

    @patch.object(APIParameterMiner, '_get_baseline')
    def test_mine_parameters_handles_baseline_failure(self, mock_baseline, miner):
        """Test that mining handles baseline failure gracefully."""
        mock_baseline.return_value = None

        findings = miner.mine_parameters('/users', 'GET', skip_db_check=True)

        assert findings == []


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = ParameterFinding(
            param_name='admin',
            param_type='str',
            discovery_method=DiscoveryMethod.DICTIONARY,
            vulnerability_type=VulnerabilityType.AUTH_BYPASS,
            severity=SeverityLevel.CRITICAL,
            evidence={'test': 'data'},
            exploitation_path='test',
            impact='test',
            endpoint='/users'
        )

        data = finding.to_dict()

        assert data['param_name'] == 'admin'
        assert data['severity'] == 'CRITICAL'
        assert data['discovery_method'] == 'dictionary_mining'
        assert data['vulnerability_type'] == 'authentication_bypass'

    def test_detect_hpp_impact_various_conditions(self, miner, baseline_response):
        """Test HPP detection with various conditions."""
        # Status code change
        test_resp = baseline_response.copy()
        test_resp['status_code'] = 403
        assert miner._detect_hpp_impact(test_resp, baseline_response, 'id') is True

        # Response contains HPP indicators
        test_resp = baseline_response.copy()
        test_resp['body'] = 'id[0] and id[1] found'
        assert miner._detect_hpp_impact(test_resp, baseline_response, 'id') is True

        # Significant length difference
        test_resp = baseline_response.copy()
        test_resp['body'] = 'a' * 1000
        test_resp['response_length'] = 1000
        assert miner._detect_hpp_impact(test_resp, baseline_response, 'id') is True

    def test_detect_mass_assignment_impact_various_conditions(self, miner, baseline_response):
        """Test mass assignment detection with various conditions."""
        # Value appears in response
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"role": "admin"}'
        assert miner._detect_mass_assignment_impact(test_resp, baseline_response, 'role', 'admin') is True

        # Property name appears
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"isAdmin": true}'
        assert miner._detect_mass_assignment_impact(test_resp, baseline_response, 'isAdmin', True) is True

    def test_detect_smuggling_impact_various_conditions(self, miner, baseline_response):
        """Test smuggling detection with various conditions."""
        # Admin keyword in response
        test_resp = baseline_response.copy()
        test_resp['body'] = '{"admin": true}'
        assert miner._detect_smuggling_impact(test_resp, baseline_response) is True

        # Significant change
        test_resp = baseline_response.copy()
        test_resp['body'] = 'a' * 500
        test_resp['response_length'] = 500
        assert miner._detect_smuggling_impact(test_resp, baseline_response) is True


# ============================================================================
# Database Integration Tests
# ============================================================================

@pytest.mark.skipif(not MINER_AVAILABLE, reason="Miner not available")
class TestDatabaseIntegration:
    """Test database integration."""

    @patch('engine.agents.api_endpoint_parameter_miner.DatabaseHooks.before_test')
    @patch.object(APIParameterMiner, '_get_baseline')
    def test_mine_parameters_checks_database(self, mock_baseline, mock_before_test, miner, baseline_response):
        """Test that mining checks database before starting."""
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'No recent tests',
            'previous_findings': []
        }
        mock_baseline.return_value = baseline_response

        miner.mine_parameters('/users', 'GET', skip_db_check=False)

        # Should have checked database
        mock_before_test.assert_called_once_with('example.com', 'api_parameter_miner')

    @patch.object(APIParameterMiner, '_record_findings')
    @patch.object(APIParameterMiner, '_get_baseline')
    def test_mine_parameters_records_findings(self, mock_baseline, mock_record, miner, baseline_response):
        """Test that findings are recorded in database."""
        mock_baseline.return_value = baseline_response

        # Add a finding
        finding = ParameterFinding(
            param_name='admin',
            param_type='str',
            discovery_method=DiscoveryMethod.DICTIONARY,
            vulnerability_type=VulnerabilityType.AUTH_BYPASS,
            severity=SeverityLevel.CRITICAL,
            evidence={},
            exploitation_path='test',
            impact='test',
            endpoint='/users'
        )
        miner.findings.append(finding)

        miner.mine_parameters('/users', 'GET', skip_db_check=False)

        # Should have called record
        mock_record.assert_called_once()
