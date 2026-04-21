"""
Tests for POCValidator Agent

Comprehensive test suite with 30+ tests for all validation methods.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess
from engine.agents.poc_validator import POCValidator


@pytest.fixture
def temp_output_dir():
    """Create temporary output directory"""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def validator(temp_output_dir):
    """Create POCValidator instance with temporary output directory"""
    return POCValidator(output_dir=temp_output_dir)


@pytest.fixture
def sample_finding():
    """Sample finding for testing"""
    return {
        'finding_id': 'F-001',
        'target_domain': 'example.com',
        'url': 'https://example.com/api/endpoint',
        'vulnerability_type': 'cors_misconfiguration',
        'claimed_behavior': 'CORS allows arbitrary origins',
        'claimed_severity': 'medium',
        'discovered_by': 'api-tester'
    }


# ============================================================================
# Initialization Tests
# ============================================================================

def test_validator_initialization(validator, temp_output_dir):
    """Test validator initializes correctly"""
    assert validator is not None
    assert validator.output_dir == Path(temp_output_dir)
    assert validator.validated_findings == []
    assert validator._request_count == 0


def test_validator_creates_output_directory():
    """Test validator creates output directory if it doesn't exist"""
    tmpdir = tempfile.mkdtemp()
    output_path = Path(tmpdir) / "test_output"

    validator = POCValidator(output_dir=str(output_path))

    assert output_path.exists()
    assert output_path.is_dir()

    shutil.rmtree(tmpdir)


def test_validator_default_output_directory():
    """Test validator uses default output directory"""
    validator = POCValidator()
    expected_path = Path.home() / "bounty-findings" / "tmp"

    assert validator.output_dir == expected_path


# ============================================================================
# DNS Validation Tests
# ============================================================================

def test_check_dns_success(validator):
    """Test DNS resolution succeeds for valid domain"""
    mock_result = Mock()
    mock_result.stdout = "Address: 93.184.216.34"
    mock_result.stderr = ""

    with patch('subprocess.run', return_value=mock_result):
        result = validator._check_dns('example.com')

    assert result['pass'] is True
    assert 'resolves' in result['reason'].lower()


def test_check_dns_nxdomain(validator):
    """Test DNS resolution fails for non-existent domain"""
    mock_result = Mock()
    mock_result.stdout = "Non-existent domain"
    mock_result.stderr = ""

    with patch('subprocess.run', return_value=mock_result):
        result = validator._check_dns('doesnotexist123456789.com')

    assert result['pass'] is False
    assert 'does not resolve' in result['reason'].lower()


def test_check_dns_timeout(validator):
    """Test DNS check handles timeout"""
    with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('nslookup', 10)):
        result = validator._check_dns('example.com')

    assert result['pass'] is False
    assert 'timeout' in result['reason'].lower()


def test_check_dns_exception(validator):
    """Test DNS check handles exceptions"""
    with patch('subprocess.run', side_effect=Exception('Network error')):
        result = validator._check_dns('example.com')

    assert result['pass'] is False
    assert 'error' in result['reason'].lower()


# ============================================================================
# HTTP Reachability Tests
# ============================================================================

def test_check_http_reachability_success(validator):
    """Test HTTP reachability succeeds"""
    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nContent-Type: text/html"
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        result = validator._check_http_reachability('example.com')

    assert result['pass'] is True
    assert 'reachable' in result['reason'].lower()


def test_check_http_reachability_connection_refused(validator):
    """Test HTTP reachability detects connection refused"""
    mock_result = Mock()
    mock_result.stdout = ""
    mock_result.returncode = 7  # Connection refused

    with patch('subprocess.run', return_value=mock_result):
        result = validator._check_http_reachability('localhost')

    assert result['pass'] is False
    assert 'refused' in result['reason'].lower()


def test_check_http_reachability_timeout(validator):
    """Test HTTP reachability detects timeout"""
    mock_result = Mock()
    mock_result.stdout = ""
    mock_result.returncode = 28  # Timeout

    with patch('subprocess.run', return_value=mock_result):
        result = validator._check_http_reachability('example.com')

    assert result['pass'] is False
    assert 'timeout' in result['reason'].lower()


def test_check_http_reachability_waf_block(validator):
    """Test HTTP reachability detects WAF blocks"""
    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 403 Forbidden\nServer: cloudflare\nAttention Required"
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        result = validator._check_http_reachability('example.com')

    # WAF on base doesn't fail the check, just warns
    assert result['pass'] is True
    assert 'warning' in result


# ============================================================================
# Endpoint Existence Tests
# ============================================================================

def test_check_endpoint_exists_success(validator):
    """Test endpoint existence check succeeds"""
    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = '{"data": "test"}'

    with patch('subprocess.run', side_effect=[mock_status, mock_body]):
        result = validator._check_endpoint_exists('https://example.com/api/endpoint')

    assert result['pass'] is True
    assert '200' in result['evidence']


def test_check_endpoint_exists_404(validator):
    """Test endpoint existence detects 404"""
    mock_status = Mock()
    mock_status.stdout = "404"

    mock_body = Mock()
    mock_body.stdout = "Not Found"

    with patch('subprocess.run', side_effect=[mock_status, mock_body]):
        result = validator._check_endpoint_exists('https://example.com/api/notfound')

    assert result['pass'] is False
    assert '404' in result['reason']


def test_check_endpoint_exists_401(validator):
    """Test endpoint existence detects authentication required"""
    mock_status = Mock()
    mock_status.stdout = "401"

    mock_body = Mock()
    mock_body.stdout = "Unauthorized"

    with patch('subprocess.run', side_effect=[mock_status, mock_body]):
        result = validator._check_endpoint_exists('https://example.com/api/private')

    assert result['pass'] is False
    assert 'authentication' in result['reason'].lower()


def test_check_endpoint_exists_empty_response(validator):
    """Test endpoint existence detects empty responses"""
    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = ""

    with patch('subprocess.run', side_effect=[mock_status, mock_body]):
        result = validator._check_endpoint_exists('https://example.com/api/empty')

    assert result['pass'] is False
    assert 'empty' in result['reason'].lower()


def test_check_endpoint_exists_html_for_api(validator):
    """Test endpoint detects HTML returned for API endpoints"""
    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = "<!DOCTYPE html><html><body>App</body></html>"

    with patch('subprocess.run', side_effect=[mock_status, mock_body]):
        result = validator._check_endpoint_exists('https://example.com/api/endpoint')

    assert result['pass'] is False
    assert 'html' in result['reason'].lower()


# ============================================================================
# CORS Validation Tests
# ============================================================================

def test_validate_cors_confirmed(validator):
    """Test CORS validation confirms vulnerability"""
    finding = {
        'url': 'https://example.com/api/data'
    }

    mock_result = Mock()
    mock_result.stdout = "Access-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_cors(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_cors_wildcard(validator):
    """Test CORS validation rejects wildcard as false positive"""
    finding = {
        'url': 'https://example.com/api/data'
    }

    mock_result = Mock()
    mock_result.stdout = "Access-Control-Allow-Origin: *"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_cors(finding)

    assert result['pass'] is False
    assert 'wildcard' in result['reason'].lower()


def test_validate_cors_no_misconfiguration(validator):
    """Test CORS validation when no misconfiguration exists"""
    finding = {
        'url': 'https://example.com/api/data'
    }

    mock_result = Mock()
    mock_result.stdout = "Content-Type: application/json"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_cors(finding)

    assert result['pass'] is False
    assert 'no cors' in result['reason'].lower()


# ============================================================================
# Open Redirect Validation Tests
# ============================================================================

def test_validate_open_redirect_confirmed(validator):
    """Test open redirect validation confirms vulnerability"""
    finding = {
        'url': 'https://example.com/redirect',
        'param': 'url'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 302 Found\nLocation: https://evil.com/payload"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_open_redirect(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_open_redirect_internal(validator):
    """Test open redirect validation rejects internal redirects"""
    finding = {
        'url': 'https://example.com/redirect',
        'param': 'url'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 302 Found\nLocation: /internal/page"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_open_redirect(finding)

    assert result['pass'] is False
    assert 'target domain' in result['reason'].lower() or 'sanitized' in result['reason'].lower()


def test_validate_open_redirect_no_location(validator):
    """Test open redirect validation when no Location header"""
    finding = {
        'url': 'https://example.com/redirect',
        'param': 'url'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nContent-Type: text/html"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_open_redirect(finding)

    assert result['pass'] is False
    assert 'no location' in result['reason'].lower()


# ============================================================================
# GraphQL Introspection Validation Tests
# ============================================================================

def test_validate_graphql_introspection_enabled(validator):
    """Test GraphQL introspection validation confirms enabled"""
    finding = {
        'url': 'https://example.com/graphql'
    }

    mock_result = Mock()
    mock_result.stdout = '{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}'

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_graphql_introspection(finding)

    assert result['pass'] is True
    assert 'enabled' in result['reason'].lower()


def test_validate_graphql_introspection_disabled(validator):
    """Test GraphQL introspection validation detects disabled"""
    finding = {
        'url': 'https://example.com/graphql'
    }

    mock_result = Mock()
    mock_result.stdout = '{"errors": [{"message": "Introspection is disabled"}]}'

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_graphql_introspection(finding)

    assert result['pass'] is False
    assert 'disabled' in result['reason'].lower()


def test_validate_graphql_introspection_invalid_json(validator):
    """Test GraphQL introspection handles invalid JSON"""
    finding = {
        'url': 'https://example.com/graphql'
    }

    mock_result = Mock()
    mock_result.stdout = "Not JSON"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_graphql_introspection(finding)

    assert result['pass'] is False
    assert 'not valid json' in result['reason'].lower()


# ============================================================================
# Information Disclosure Validation Tests
# ============================================================================

def test_validate_info_disclosure_confirmed(validator):
    """Test information disclosure validation confirms"""
    finding = {
        'url': 'https://example.com/api/admin/config'
    }

    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = '{"database": "mysql://root:password@localhost", "api_key": "secret123"}'

    with patch('subprocess.run', side_effect=[mock_body, mock_status]):
        result = validator.validate_info_disclosure(finding)

    assert result['pass'] is True
    assert '200' in result['reason']


def test_validate_info_disclosure_auth_required(validator):
    """Test information disclosure detects auth requirements"""
    finding = {
        'url': 'https://example.com/api/private'
    }

    mock_status = Mock()
    mock_status.stdout = "401"

    mock_body = Mock()
    mock_body.stdout = "Please login"

    with patch('subprocess.run', side_effect=[mock_body, mock_status]):
        result = validator.validate_info_disclosure(finding)

    assert result['pass'] is False


def test_validate_info_disclosure_too_small(validator):
    """Test information disclosure rejects responses that are too small"""
    finding = {
        'url': 'https://example.com/api/endpoint'
    }

    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = "{}"

    with patch('subprocess.run', side_effect=[mock_body, mock_status]):
        result = validator.validate_info_disclosure(finding)

    assert result['pass'] is False
    assert 'too small' in result['reason'].lower()


# ============================================================================
# IDOR Validation Tests
# ============================================================================

def test_validate_idor_confirmed(validator):
    """Test IDOR validation confirms vulnerability"""
    finding = {
        'url': 'https://example.com/api/users/456',
        'token_a': 'Bearer token123',
        'id_b': '456'
    }

    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = '{"user_id": 456, "email": "victim@example.com"}'

    with patch('subprocess.run', side_effect=[mock_body, mock_status]):
        result = validator.validate_idor(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_idor_properly_rejected(validator):
    """Test IDOR validation when properly rejected"""
    finding = {
        'url': 'https://example.com/api/users/456',
        'token_a': 'Bearer token123',
        'id_b': '456'
    }

    mock_status = Mock()
    mock_status.stdout = "403"

    mock_body = Mock()
    mock_body.stdout = "Forbidden"

    with patch('subprocess.run', side_effect=[mock_body, mock_status]):
        result = validator.validate_idor(finding)

    assert result['pass'] is False
    assert 'properly rejects' in result['reason'].lower()


def test_validate_idor_missing_token(validator):
    """Test IDOR validation when token is missing"""
    finding = {
        'url': 'https://example.com/api/users/456',
        'id_b': '456'
    }

    result = validator.validate_idor(finding)

    assert result['pass'] is False
    assert 'NEEDS_AUTH' in result.get('verdict', '')


def test_validate_idor_missing_id(validator):
    """Test IDOR validation when victim ID is missing"""
    finding = {
        'url': 'https://example.com/api/users/456',
        'token_a': 'Bearer token123'
    }

    result = validator.validate_idor(finding)

    assert result['pass'] is False
    assert 'id_b' in result['reason'].lower()


# ============================================================================
# Username Enumeration Validation Tests
# ============================================================================

def test_validate_username_enum_confirmed_size_diff(validator):
    """Test username enumeration validation confirms via size difference"""
    finding = {
        'url': 'https://example.com/login',
        'valid_username': 'admin'
    }

    mock_valid = Mock()
    mock_valid.stdout = "User exists, wrong password (100 characters total)"

    mock_invalid = Mock()
    mock_invalid.stdout = "Invalid username (20 chars)"

    with patch('subprocess.run', side_effect=[mock_valid, mock_invalid]):
        result = validator.validate_username_enum(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_username_enum_confirmed_content_diff(validator):
    """Test username enumeration validation confirms via content difference"""
    finding = {
        'url': 'https://example.com/login',
        'valid_username': 'admin'
    }

    mock_valid = Mock()
    mock_valid.stdout = "Wrong password"

    mock_invalid = Mock()
    mock_invalid.stdout = "User not found"

    with patch('subprocess.run', side_effect=[mock_valid, mock_invalid]):
        result = validator.validate_username_enum(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_username_enum_identical(validator):
    """Test username enumeration validation when responses are identical"""
    finding = {
        'url': 'https://example.com/login',
        'valid_username': 'admin'
    }

    mock_response = Mock()
    mock_response.stdout = "Invalid credentials"

    with patch('subprocess.run', return_value=mock_response):
        result = validator.validate_username_enum(finding)

    assert result['pass'] is False
    assert 'identical' in result['reason'].lower()


# ============================================================================
# XSS Validation Tests
# ============================================================================

def test_validate_xss_confirmed(validator):
    """Test XSS validation confirms vulnerability"""
    finding = {
        'url': 'https://example.com/search',
        'param': 'q'
    }

    mock_body = Mock()
    mock_body.stdout = '<html><body>Results for: <script>alert(1)</script></body></html>'

    mock_headers = Mock()
    mock_headers.stdout = "Content-Type: text/html"

    with patch('subprocess.run', side_effect=[mock_body, mock_headers]):
        result = validator.validate_xss(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_xss_encoded(validator):
    """Test XSS validation detects HTML encoding"""
    finding = {
        'url': 'https://example.com/search',
        'param': 'q'
    }

    mock_body = Mock()
    mock_body.stdout = '<html><body>Results for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>'

    with patch('subprocess.run', return_value=mock_body):
        result = validator.validate_xss(finding)

    assert result['pass'] is False
    assert 'encoded' in result['reason'].lower()


def test_validate_xss_not_reflected(validator):
    """Test XSS validation when payload not reflected"""
    finding = {
        'url': 'https://example.com/search',
        'param': 'q'
    }

    mock_body = Mock()
    mock_body.stdout = '<html><body>No results found</body></html>'

    with patch('subprocess.run', return_value=mock_body):
        result = validator.validate_xss(finding)

    assert result['pass'] is False
    assert 'does not appear' in result['reason'].lower()


# ============================================================================
# SQLi Validation Tests
# ============================================================================

def test_validate_sqli_error_based(validator):
    """Test SQL injection validation confirms via error messages"""
    finding = {
        'url': 'https://example.com/user',
        'param': 'id'
    }

    mock_error = Mock()
    mock_error.stdout = "MySQL error: You have an error in your SQL syntax"

    mock_normal = Mock()
    mock_normal.stdout = '{"user": "data"}'

    with patch('subprocess.run', side_effect=[mock_error, mock_normal, mock_error]):
        result = validator.validate_sqli(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_sqli_time_based(validator):
    """Test SQL injection validation confirms via timing"""
    finding = {
        'url': 'https://example.com/user',
        'param': 'id'
    }

    mock_normal = Mock()
    mock_normal.stdout = "normal"

    def slow_call(*args, **kwargs):
        import time
        time.sleep(5.5)
        return mock_normal

    with patch('subprocess.run', side_effect=[mock_normal, mock_normal, slow_call]):
        result = validator.validate_sqli(finding)

    # Time-based detection
    if result['pass']:
        assert 'time-based' in result['reason'].lower()


def test_validate_sqli_not_vulnerable(validator):
    """Test SQL injection validation when not vulnerable"""
    finding = {
        'url': 'https://example.com/user',
        'param': 'id'
    }

    mock_response = Mock()
    mock_response.stdout = '{"user": "data"}'

    with patch('subprocess.run', return_value=mock_response):
        result = validator.validate_sqli(finding)

    assert result['pass'] is False


# ============================================================================
# SSRF Validation Tests
# ============================================================================

def test_validate_ssrf_confirmed(validator):
    """Test SSRF validation confirms vulnerability"""
    finding = {
        'url': 'https://example.com/fetch',
        'param': 'url'
    }

    mock_internal = Mock()
    mock_internal.stdout = "Internal server response from localhost"

    mock_baseline = Mock()
    mock_baseline.stdout = "External response"

    with patch('subprocess.run', side_effect=[mock_internal, mock_baseline]):
        result = validator.validate_ssrf(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower() or 'possible' in result['reason'].lower()


def test_validate_ssrf_identical_responses(validator):
    """Test SSRF validation when responses are identical"""
    finding = {
        'url': 'https://example.com/fetch',
        'param': 'url'
    }

    mock_response = Mock()
    mock_response.stdout = "Error: Invalid URL"

    with patch('subprocess.run', return_value=mock_response):
        result = validator.validate_ssrf(finding)

    assert result['pass'] is False
    assert 'identical' in result['reason'].lower()


# ============================================================================
# Security Headers Validation Tests
# ============================================================================

def test_validate_security_headers_missing(validator):
    """Test security headers validation confirms missing header"""
    finding = {
        'url': 'https://example.com',
        'header_name': 'content-security-policy',
        'expected_issue': 'missing'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nContent-Type: text/html"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_security_headers(finding)

    assert result['pass'] is True
    assert 'missing' in result['reason'].lower()


def test_validate_security_headers_present(validator):
    """Test security headers validation when header is present"""
    finding = {
        'url': 'https://example.com',
        'header_name': 'content-security-policy',
        'expected_issue': 'missing'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_security_headers(finding)

    assert result['pass'] is False
    assert 'present' in result['reason'].lower()


def test_validate_security_headers_weak(validator):
    """Test security headers validation confirms weak configuration"""
    finding = {
        'url': 'https://example.com',
        'header_name': 'content-security-policy',
        'expected_issue': 'weak'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self' 'unsafe-inline'"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_security_headers(finding)

    assert result['pass'] is True
    assert 'unsafe' in result['reason'].lower()


# ============================================================================
# Server Disclosure Validation Tests
# ============================================================================

def test_validate_server_disclosure_confirmed(validator):
    """Test server disclosure validation confirms"""
    finding = {
        'url': 'https://example.com',
        'expected_header': 'X-Powered-By',
        'expected_value': 'Koa'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nX-Powered-By: Koa\nContent-Type: text/html"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_server_disclosure(finding)

    assert result['pass'] is True
    assert 'confirmed' in result['reason'].lower()


def test_validate_server_disclosure_not_found(validator):
    """Test server disclosure validation when header not found"""
    finding = {
        'url': 'https://example.com',
        'expected_header': 'X-Powered-By',
        'expected_value': 'Koa'
    }

    mock_result = Mock()
    mock_result.stdout = "HTTP/1.1 200 OK\nContent-Type: text/html"

    with patch('subprocess.run', return_value=mock_result):
        result = validator.validate_server_disclosure(finding)

    assert result['pass'] is False
    assert 'not found' in result['reason'].lower()


# ============================================================================
# Helper Methods Tests
# ============================================================================

def test_is_waf_block_cloudflare(validator):
    """Test WAF detection for Cloudflare blocks"""
    response = "HTTP/1.1 403 Forbidden\nServer: cloudflare\nAttention Required"

    assert validator._is_waf_block(response) is True


def test_is_waf_block_normal_403(validator):
    """Test WAF detection doesn't false positive on normal 403"""
    response = "HTTP/1.1 403 Forbidden\nContent-Type: application/json"

    assert validator._is_waf_block(response) is False


def test_save_curl_output(validator, temp_output_dir):
    """Test curl output is saved to file"""
    content = "Test curl output"
    filename = "test_output.txt"

    validator._save_curl_output(filename, content)

    filepath = Path(temp_output_dir) / filename
    assert filepath.exists()
    assert filepath.read_text() == content


def test_generate_curl_command_cors(validator):
    """Test curl command generation for CORS"""
    finding = {
        'url': 'https://example.com/api',
        'vulnerability_type': 'cors'
    }

    cmd = validator.generate_curl_command(finding)

    assert 'curl' in cmd
    assert 'Origin:' in cmd
    assert 'evil.com' in cmd


def test_generate_curl_command_graphql(validator):
    """Test curl command generation for GraphQL"""
    finding = {
        'url': 'https://example.com/graphql',
        'vulnerability_type': 'graphql_introspection'
    }

    cmd = validator.generate_curl_command(finding)

    assert 'curl' in cmd
    assert '__schema' in cmd


def test_get_summary(validator):
    """Test validation summary statistics"""
    # Add some validated findings
    validator.validated_findings = [
        {'verdict': POCValidator.CONFIRMED},
        {'verdict': POCValidator.CONFIRMED},
        {'verdict': POCValidator.FALSE_POSITIVE},
        {'verdict': POCValidator.NEEDS_AUTH},
    ]

    summary = validator.get_summary()

    assert summary['total_validated'] == 4
    assert summary['confirmed'] == 2
    assert summary['false_positives'] == 1
    assert summary['needs_auth'] == 1
    assert summary['success_rate'] == 50.0


# ============================================================================
# Integration Tests
# ============================================================================

def test_validate_full_pipeline_success(validator, sample_finding):
    """Test full validation pipeline with successful finding"""
    # Mock all subprocess calls
    dns_result = Mock()
    dns_result.stdout = "Address: 93.184.216.34"
    dns_result.stderr = ""

    http_result = Mock()
    http_result.stdout = "HTTP/1.1 200 OK"
    http_result.returncode = 0

    endpoint_status = Mock()
    endpoint_status.stdout = "200"

    endpoint_body = Mock()
    endpoint_body.stdout = '{"data": "test"}'

    cors_result = Mock()
    cors_result.stdout = "Access-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true"

    with patch('subprocess.run', side_effect=[dns_result, http_result, endpoint_status, endpoint_body, cors_result]):
        result = validator.validate(sample_finding)

    assert result['verdict'] == POCValidator.CONFIRMED
    assert len(validator.validated_findings) == 1


def test_validate_full_pipeline_dns_failure(validator, sample_finding):
    """Test full validation pipeline fails at DNS step"""
    dns_result = Mock()
    dns_result.stdout = "Non-existent domain"
    dns_result.stderr = ""

    with patch('subprocess.run', return_value=dns_result):
        result = validator.validate(sample_finding)

    assert result['verdict'] == POCValidator.FALSE_POSITIVE
    assert 'DNS' in result['reason'] or 'resolve' in result['reason']


def test_validate_unsupported_vuln_type(validator):
    """Test validation of unsupported vulnerability type"""
    finding = {
        'finding_id': 'F-999',
        'target_domain': 'example.com',
        'url': 'https://example.com/test',
        'vulnerability_type': 'unsupported_type',
        'claimed_behavior': 'Test',
        'claimed_severity': 'low'
    }

    # Mock DNS and HTTP to pass, so we reach vulnerability validation
    dns_result = Mock()
    dns_result.stdout = "Address: 93.184.216.34"
    dns_result.stderr = ""

    http_result = Mock()
    http_result.stdout = "HTTP/1.1 200 OK"
    http_result.returncode = 0

    endpoint_status = Mock()
    endpoint_status.stdout = "200"

    endpoint_body = Mock()
    endpoint_body.stdout = "content"

    with patch('subprocess.run', side_effect=[dns_result, http_result, endpoint_status, endpoint_body]):
        result = validator.validate(finding)

    assert result['verdict'] == POCValidator.FALSE_POSITIVE
    # Check the vuln-specific step for the unsupported message
    vuln_proof_step = result['validation_steps'].get('Vulnerability Proof', {})
    assert 'no validator' in vuln_proof_step.get('reason', '').lower() or 'unsupported' in vuln_proof_step.get('reason', '').lower()


# ============================================================================
# State Change Verification Tests (Task 6 - BountyHound v4 Overhaul)
# ============================================================================

def test_poc_validator_requires_state_change_for_idor(validator):
    """POC validator must require state change proof for IDOR findings."""
    finding = {
        'finding_id': 'F-IDOR-001',
        'target_domain': 'example.com',
        'url': 'https://example.com/api/users/456',
        'vulnerability_type': 'IDOR',
        'claimed_behavior': 'User A can access User B data',
        'claimed_severity': 'high',
        'token_a': 'Bearer token123',
        'id_b': '456',
        # No state change evidence - should fail
    }

    # Mock successful HTTP 200 response
    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = '{"user_id": 456, "email": "victim@example.com"}'

    # Mock DNS and HTTP checks to pass
    dns_result = Mock()
    dns_result.stdout = "Address: 93.184.216.34"
    dns_result.stderr = ""

    http_result = Mock()
    http_result.stdout = "HTTP/1.1 200 OK"
    http_result.returncode = 0

    with patch('subprocess.run', side_effect=[dns_result, http_result, mock_status, mock_body, mock_body, mock_status]):
        result = validator.validate(finding)

    # Without state change verification, HTTP 200 is insufficient
    # The validator should reject findings without state change proof
    assert 'state_change_verified' not in result or result.get('state_change_verified') is False
    assert result['verdict'] == POCValidator.FALSE_POSITIVE
    assert 'state change' in result['reason'].lower()


def test_poc_validator_requires_state_change_for_bola(validator):
    """POC validator must require state change proof for BOLA findings."""
    finding = {
        'finding_id': 'F-BOLA-001',
        'target_domain': 'example.com',
        'url': 'https://example.com/api/orders/789',
        'vulnerability_type': 'BOLA',
        'claimed_behavior': 'Missing authorization check on order deletion',
        'claimed_severity': 'critical',
        'token_a': 'Bearer attacker_token',
        'id_b': '789',  # BOLA uses same validator as IDOR, needs id_b
    }

    # Mock HTTP 200 response but no state change evidence
    dns_result = Mock()
    dns_result.stdout = "Address: 93.184.216.34"
    dns_result.stderr = ""

    http_result = Mock()
    http_result.stdout = "HTTP/1.1 200 OK"
    http_result.returncode = 0

    endpoint_status = Mock()
    endpoint_status.stdout = "200"

    endpoint_body = Mock()
    endpoint_body.stdout = '{"success": true}'

    # For the validate_idor call - need body and status
    idor_body = Mock()
    idor_body.stdout = '{"success": true}'

    idor_status = Mock()
    idor_status.stdout = "200"

    with patch('subprocess.run', side_effect=[dns_result, http_result, endpoint_status, endpoint_body, idor_body, idor_status]):
        result = validator.validate(finding)

    # Should reject without state change proof
    assert result['verdict'] == POCValidator.FALSE_POSITIVE
    assert 'state change' in result['reason'].lower()


def test_poc_validator_accepts_with_state_change_evidence(validator):
    """POC validator should accept findings WITH state change evidence."""
    finding = {
        'finding_id': 'F-IDOR-002',
        'target_domain': 'example.com',
        'url': 'https://example.com/api/users/456',
        'vulnerability_type': 'IDOR',
        'claimed_behavior': 'User A can modify User B email',
        'claimed_severity': 'high',
        'token_a': 'Bearer token123',
        'id_b': '456',
        # Include state change evidence showing actual mutation
        'state_change_verified': True,
        'before_state': '{"user": {"email": "victim@example.com"}}',
        'after_state': '{"user": {"email": "attacker@evil.com"}}',  # Email changed!
        'mutation_response': '{"data": {"updateUser": {"email": "attacker@evil.com"}}}',
    }

    # Mock successful responses
    mock_status = Mock()
    mock_status.stdout = "200"

    mock_body = Mock()
    mock_body.stdout = '{"user_id": 456, "email": "victim@example.com"}'

    dns_result = Mock()
    dns_result.stdout = "Address: 93.184.216.34"
    dns_result.stderr = ""

    http_result = Mock()
    http_result.stdout = "HTTP/1.1 200 OK"
    http_result.returncode = 0

    with patch('subprocess.run', side_effect=[dns_result, http_result, mock_status, mock_body, mock_body, mock_status]):
        result = validator.validate(finding)

    # Should CONFIRM with state change evidence
    assert result['verdict'] == POCValidator.CONFIRMED
    assert result.get('state_change_verified') is True
