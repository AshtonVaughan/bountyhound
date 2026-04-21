"""
Comprehensive tests for Cookie Security Analyzer Agent

Tests cover:
- Security flag detection (Secure, HttpOnly, SameSite)
- Cookie prefix validation (__Secure-, __Host-)
- Session fixation detection
- Session ID predictability
- Cookie injection vulnerabilities
- Cookie overflow/bombing
- Cookie scope issues
- Database integration
- Edge cases and error handling

Target: 95%+ code coverage
"""

import pytest
import json
from datetime import date
from unittest.mock import Mock, patch, MagicMock
from http.cookies import SimpleCookie

from engine.agents.cookie_security_analyzer import (
    CookieSecurityAnalyzer,
    CookieFinding,
    CookieInfo,
    CookieSeverity,
    CookieVulnType
)


@pytest.fixture
def mock_requests():
    """Mock requests module."""
    with patch('engine.agents.cookie_security_analyzer.requests') as mock_req:
        yield mock_req


@pytest.fixture
def mock_db():
    """Mock BountyHoundDB."""
    with patch('engine.agents.cookie_security_analyzer.BountyHoundDB') as mock:
        db_instance = Mock()
        mock.return_value = db_instance
        yield db_instance


@pytest.fixture
def mock_db_hooks():
    """Mock DatabaseHooks."""
    with patch('engine.agents.cookie_security_analyzer.DatabaseHooks') as mock:
        yield mock


@pytest.fixture
def analyzer(mock_requests, mock_db):
    """Create analyzer instance with mocked dependencies."""
    return CookieSecurityAnalyzer(
        target_url="https://example.com",
        timeout=5,
        verify_ssl=True,
        db=mock_db
    )


class TestCookieInfo:
    """Test CookieInfo dataclass methods."""

    def test_is_session_cookie_by_name(self):
        """Test session cookie detection by name patterns."""
        session_names = ['sessionid', 'SESSID', 'auth_token', 'jwt', 'access_token',
                        'refresh', 'login', 'user_session', 'account', 'csrf']

        for name in session_names:
            cookie = CookieInfo(name=name, value='test123')
            assert cookie.is_session_cookie(), f"{name} should be detected as session cookie"

    def test_is_session_cookie_by_value(self):
        """Test session cookie detection by value patterns."""
        # Long random string (hex/base64 pattern)
        cookie = CookieInfo(name='cookie', value='a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6')
        assert cookie.is_session_cookie()

        # Short value
        cookie = CookieInfo(name='cookie', value='short')
        assert not cookie.is_session_cookie()

        # All digits
        cookie = CookieInfo(name='cookie', value='12345678901234567890')
        assert not cookie.is_session_cookie()

    def test_has_valid_prefix_secure(self):
        """Test __Secure- prefix validation."""
        # Valid __Secure- prefix
        cookie = CookieInfo(name='__Secure-token', value='abc', secure=True)
        valid, msg = cookie.has_valid_prefix()
        assert valid
        assert '__Secure- prefix valid' in msg

        # Invalid __Secure- without Secure flag
        cookie = CookieInfo(name='__Secure-token', value='abc', secure=False)
        valid, msg = cookie.has_valid_prefix()
        assert not valid
        assert 'requires Secure flag' in msg

    def test_has_valid_prefix_host(self):
        """Test __Host- prefix validation."""
        # Valid __Host- prefix
        cookie = CookieInfo(name='__Host-token', value='abc', secure=True, path='/', domain=None)
        valid, msg = cookie.has_valid_prefix()
        assert valid
        assert '__Host- prefix valid' in msg

        # Invalid __Host- without Secure
        cookie = CookieInfo(name='__Host-token', value='abc', secure=False, path='/')
        valid, msg = cookie.has_valid_prefix()
        assert not valid
        assert 'requires Secure flag' in msg

        # Invalid __Host- with wrong path
        cookie = CookieInfo(name='__Host-token', value='abc', secure=True, path='/admin')
        valid, msg = cookie.has_valid_prefix()
        assert not valid
        assert 'requires Path=/' in msg

        # Invalid __Host- with Domain
        cookie = CookieInfo(name='__Host-token', value='abc', secure=True, path='/', domain='.example.com')
        valid, msg = cookie.has_valid_prefix()
        assert not valid
        assert 'requires no Domain' in msg

    def test_has_valid_prefix_no_prefix(self):
        """Test cookies without special prefix."""
        cookie = CookieInfo(name='session', value='abc')
        valid, msg = cookie.has_valid_prefix()
        assert valid
        assert msg is None

    def test_get_lifetime_seconds(self):
        """Test lifetime calculation."""
        # Max-Age set
        cookie = CookieInfo(name='test', value='abc', max_age=3600)
        assert cookie.get_lifetime_seconds() == 3600

        # Session cookie (no expiry)
        cookie = CookieInfo(name='test', value='abc')
        assert cookie.get_lifetime_seconds() is None


class TestCookieSecurityAnalyzer:
    """Test CookieSecurityAnalyzer main class."""

    def test_init(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer.target_url == "https://example.com"
        assert analyzer.domain == "example.com"
        assert analyzer.is_https is True
        assert analyzer.timeout == 5
        assert analyzer.verify_ssl is True
        assert len(analyzer.findings) == 0
        assert len(analyzer.collected_cookies) == 0

    def test_init_http_url(self, mock_requests, mock_db):
        """Test initialization with HTTP URL."""
        analyzer = CookieSecurityAnalyzer(
            target_url="http://example.com",
            db=mock_db
        )
        assert analyzer.is_https is False

    def test_extract_domain(self, analyzer):
        """Test domain extraction from URL."""
        assert analyzer._extract_domain("https://api.example.com/path") == "api.example.com"
        assert analyzer._extract_domain("http://example.com:8080") == "example.com:8080"

    def test_parse_cookie_header(self, analyzer):
        """Test parsing Set-Cookie headers."""
        header = "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600"
        cookie = analyzer._parse_cookie_header(header, "/login")

        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.secure is True
        assert cookie.httponly is True
        assert cookie.samesite == "Strict"
        assert cookie.path == "/"
        assert cookie.max_age == 3600
        assert cookie.endpoint == "/login"

    def test_parse_cookie_header_invalid(self, analyzer):
        """Test parsing invalid cookie header."""
        cookie = analyzer._parse_cookie_header("invalid", "/")
        assert cookie is None

    def test_collect_cookies(self, analyzer, mock_requests):
        """Test cookie collection from endpoints."""
        # Mock response
        mock_response = Mock()
        mock_response.headers.get.return_value = "session=abc123; Secure; HttpOnly"
        mock_response.cookies = []

        analyzer.session.get = Mock(return_value=mock_response)

        analyzer.collect_cookies(['/'])

        assert len(analyzer.collected_cookies) == 1
        assert 'session' in analyzer.collected_cookies
        analyzer.session.get.assert_called_once()

    def test_collect_cookies_from_response_cookies(self, analyzer, mock_requests):
        """Test collecting cookies from response.cookies object."""
        # Mock cookie object
        mock_cookie = Mock()
        mock_cookie.name = 'auth'
        mock_cookie.value = 'token123'
        mock_cookie.domain = 'example.com'
        mock_cookie.path = '/'
        mock_cookie.secure = True
        mock_cookie._rest = {'HttpOnly': True, 'SameSite': 'Lax'}
        mock_cookie.expires = None

        mock_response = Mock()
        mock_response.headers.get.return_value = ""
        mock_response.cookies = [mock_cookie]

        analyzer.session.get = Mock(return_value=mock_response)

        analyzer.collect_cookies(['/api'])

        assert 'auth' in analyzer.collected_cookies
        assert analyzer.collected_cookies['auth'].value == 'token123'

    def test_collect_cookies_error_handling(self, analyzer, mock_requests):
        """Test error handling during cookie collection."""
        analyzer.session.get = Mock(side_effect=Exception("Connection error"))

        # Should not raise exception
        analyzer.collect_cookies(['/'])

        assert len(analyzer.collected_cookies) == 0

    def test_test_security_flags_missing_secure(self, analyzer):
        """Test detection of missing Secure flag."""
        analyzer.collected_cookies['session'] = CookieInfo(
            name='session',
            value='abc123',
            secure=False,
            httponly=True,
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        assert len(findings) > 0
        secure_findings = [f for f in findings if f.vuln_type == CookieVulnType.MISSING_SECURE]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == CookieSeverity.HIGH
        assert 'Secure flag' in secure_findings[0].title

    def test_test_security_flags_missing_httponly(self, analyzer):
        """Test detection of missing HttpOnly flag."""
        analyzer.collected_cookies['sessionid'] = CookieInfo(
            name='sessionid',
            value='abc123',
            secure=True,
            httponly=False,
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        httponly_findings = [f for f in findings if f.vuln_type == CookieVulnType.MISSING_HTTPONLY]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == CookieSeverity.HIGH
        assert 'HttpOnly' in httponly_findings[0].title

    def test_test_security_flags_missing_samesite(self, analyzer):
        """Test detection of missing SameSite attribute."""
        analyzer.collected_cookies['auth'] = CookieInfo(
            name='auth',
            value='token',
            secure=True,
            httponly=True,
            samesite=None,
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        samesite_findings = [f for f in findings if f.vuln_type == CookieVulnType.MISSING_SAMESITE]
        assert len(samesite_findings) == 1
        assert samesite_findings[0].severity == CookieSeverity.HIGH

    def test_test_security_flags_samesite_none_no_secure(self, analyzer):
        """Test SameSite=None without Secure flag."""
        analyzer.collected_cookies['tracking'] = CookieInfo(
            name='tracking',
            value='xyz',
            secure=False,
            samesite='None',
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        findings_samesite = [f for f in findings if f.vuln_type == CookieVulnType.SAMESITE_NONE_NO_SECURE]
        assert len(findings_samesite) == 1
        assert findings_samesite[0].severity == CookieSeverity.HIGH

    def test_test_security_flags_invalid_prefix(self, analyzer):
        """Test invalid cookie prefix detection."""
        analyzer.collected_cookies['__Secure-token'] = CookieInfo(
            name='__Secure-token',
            value='abc',
            secure=False,  # Invalid: __Secure- requires Secure
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        prefix_findings = [f for f in findings if f.vuln_type == CookieVulnType.INVALID_PREFIX]
        assert len(prefix_findings) == 1
        assert prefix_findings[0].severity == CookieSeverity.MEDIUM

    def test_test_security_flags_long_lifetime(self, analyzer):
        """Test detection of excessive cookie lifetime."""
        analyzer.collected_cookies['sessionid'] = CookieInfo(
            name='sessionid',
            value='abc',
            max_age=86400 * 30,  # 30 days
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        lifetime_findings = [f for f in findings if f.vuln_type == CookieVulnType.LONG_LIFETIME]
        assert len(lifetime_findings) == 1
        assert lifetime_findings[0].severity == CookieSeverity.LOW

    def test_test_security_flags_non_session_cookie(self, analyzer):
        """Test that non-session cookies get lower severity."""
        analyzer.collected_cookies['prefs'] = CookieInfo(
            name='prefs',
            value='dark',
            secure=False,
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        # Should still flag missing Secure, but with lower severity
        secure_findings = [f for f in findings if f.vuln_type == CookieVulnType.MISSING_SECURE]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == CookieSeverity.MEDIUM

    def test_test_cookie_injection(self, analyzer, mock_requests):
        """Test cookie injection vulnerability detection."""
        # Mock response with reflected payload in Set-Cookie
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers.get.return_value = "test=test\r\nSet-Cookie: injected=true"

        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.test_cookie_injection()

        injection_findings = [f for f in findings if f.vuln_type == CookieVulnType.COOKIE_INJECTION]
        assert len(injection_findings) >= 1
        assert injection_findings[0].severity == CookieSeverity.HIGH
        assert 'injection' in injection_findings[0].title.lower()

    def test_test_cookie_injection_no_vulnerability(self, analyzer, mock_requests):
        """Test cookie injection when no vulnerability exists."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers.get.return_value = "safe=value"

        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.test_cookie_injection()

        assert len(findings) == 0

    def test_test_cookie_injection_error_handling(self, analyzer, mock_requests):
        """Test error handling in cookie injection tests."""
        analyzer.session.get = Mock(side_effect=Exception("Network error"))

        # Should not raise exception
        findings = analyzer.test_cookie_injection()

        assert len(findings) == 0

    def test_test_session_fixation_no_credentials(self, analyzer):
        """Test session fixation skips without credentials."""
        findings = analyzer.test_session_fixation()

        assert len(findings) == 0

    def test_test_session_fixation_vulnerable(self, analyzer, mock_requests):
        """Test session fixation vulnerability detection."""
        analyzer.credentials = {
            'login_endpoint': '/login',
            'username': 'testuser',
            'password': 'testpass'
        }

        # Add session cookie
        analyzer.collected_cookies['sessionid'] = CookieInfo(
            name='sessionid',
            value='fixed_session_123',
            endpoint='/'
        )

        # Mock responses
        mock_get_response = Mock()
        mock_post_response = Mock()

        analyzer.session.get = Mock(return_value=mock_get_response)
        analyzer.session.post = Mock(return_value=mock_post_response)

        # Mock collect_cookies to keep same session ID
        original_collect = analyzer.collect_cookies
        def mock_collect(endpoints):
            # Session ID stays the same (vulnerable!)
            pass

        analyzer.collect_cookies = mock_collect

        findings = analyzer.test_session_fixation()

        fixation_findings = [f for f in findings if f.vuln_type == CookieVulnType.SESSION_FIXATION]
        assert len(fixation_findings) >= 1
        assert fixation_findings[0].severity == CookieSeverity.CRITICAL

    def test_test_session_fixation_no_session_cookies(self, analyzer, mock_requests):
        """Test session fixation when no session cookies found."""
        analyzer.credentials = {
            'login_endpoint': '/login',
            'username': 'test',
            'password': 'test'
        }

        # No session cookies
        analyzer.collected_cookies = {}

        mock_response = Mock()
        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.test_session_fixation()

        assert len(findings) == 0

    def test_test_session_fixation_error_handling(self, analyzer, mock_requests):
        """Test error handling in session fixation test."""
        analyzer.credentials = {
            'login_endpoint': '/login',
            'username': 'test',
            'password': 'test'
        }

        analyzer.session.get = Mock(side_effect=Exception("Connection error"))

        # Should not raise exception
        findings = analyzer.test_session_fixation()

        assert len(findings) == 0

    def test_test_session_prediction_sequential(self, analyzer, mock_requests):
        """Test detection of sequential session IDs."""
        # Mock multiple sequential session IDs
        session_values = ['1001', '1002', '1003', '1004', '1005']

        mock_cookies = []
        for val in session_values:
            mock_cookie = Mock()
            mock_cookie.name = 'sessionid'
            mock_cookie.value = val
            mock_cookie.secure = True
            mock_cookie._rest = {'HttpOnly': True}
            mock_cookies.append([mock_cookie])

        mock_responses = [Mock(cookies=cookies) for cookies in mock_cookies]

        with patch('engine.agents.cookie_security_analyzer.requests.Session') as mock_session_class:
            mock_session_instance = Mock()
            mock_session_instance.get.side_effect = mock_responses
            mock_session_class.return_value = mock_session_instance

            findings = analyzer.test_session_prediction()

        sequential_findings = [f for f in findings if f.vuln_type == CookieVulnType.SEQUENTIAL_SESSION_ID]
        assert len(sequential_findings) >= 1
        assert sequential_findings[0].severity == CookieSeverity.CRITICAL

    def test_test_session_prediction_hex_sequential(self, analyzer, mock_requests):
        """Test detection of sequential hex session IDs."""
        session_values = ['a01', 'a02', 'a03', 'a04', 'a05']

        mock_cookies = []
        for val in session_values:
            mock_cookie = Mock()
            mock_cookie.name = 'session'
            mock_cookie.value = val
            mock_cookie.secure = True
            mock_cookie._rest = {}
            mock_cookies.append([mock_cookie])

        mock_responses = [Mock(cookies=cookies) for cookies in mock_cookies]

        with patch('engine.agents.cookie_security_analyzer.requests.Session') as mock_session_class:
            mock_session = Mock()
            mock_session.get.side_effect = mock_responses
            mock_session_class.return_value = mock_session

            findings = analyzer.test_session_prediction()

        assert len(findings) >= 1

    def test_test_session_prediction_low_entropy(self, analyzer, mock_requests):
        """Test detection of low entropy session IDs."""
        # Short session IDs (low entropy)
        session_values = ['abc1', 'xyz2', 'def3', 'ghi4', 'jkl5']

        mock_cookies = []
        for val in session_values:
            mock_cookie = Mock()
            mock_cookie.name = 'sid'
            mock_cookie.value = val
            mock_cookie.secure = True
            mock_cookie._rest = {}
            mock_cookies.append([mock_cookie])

        mock_responses = [Mock(cookies=cookies) for cookies in mock_cookies]

        with patch('engine.agents.cookie_security_analyzer.requests.Session') as mock_session_class:
            mock_session = Mock()
            mock_session.get.side_effect = mock_responses
            mock_session_class.return_value = mock_session

            findings = analyzer.test_session_prediction()

        entropy_findings = [f for f in findings if f.vuln_type == CookieVulnType.LOW_ENTROPY_SESSION]
        assert len(entropy_findings) >= 1
        assert entropy_findings[0].severity == CookieSeverity.HIGH

    def test_test_session_prediction_timestamp_pattern(self, analyzer, mock_requests):
        """Test detection of timestamp-based session IDs."""
        import time
        current_ts = str(int(time.time()))[:8]

        session_values = [f'{current_ts}001', f'{current_ts}002', f'{current_ts}003',
                         f'{current_ts}004', f'{current_ts}005']

        mock_cookies = []
        for val in session_values:
            mock_cookie = Mock()
            mock_cookie.name = 'session'
            mock_cookie.value = val
            mock_cookie.secure = True
            mock_cookie._rest = {}
            mock_cookies.append([mock_cookie])

        mock_responses = [Mock(cookies=cookies) for cookies in mock_cookies]

        with patch('engine.agents.cookie_security_analyzer.requests.Session') as mock_session_class:
            mock_session = Mock()
            mock_session.get.side_effect = mock_responses
            mock_session_class.return_value = mock_session

            findings = analyzer.test_session_prediction()

        timestamp_findings = [f for f in findings if f.vuln_type == CookieVulnType.TIMESTAMP_SESSION]
        assert len(timestamp_findings) >= 1

    def test_test_session_prediction_insufficient_samples(self, analyzer, mock_requests):
        """Test session prediction with insufficient session IDs."""
        # Only 2 session IDs (need at least 3)
        session_values = ['abc123', 'xyz789']

        mock_cookies = []
        for val in session_values:
            mock_cookie = Mock()
            mock_cookie.name = 'session'
            mock_cookie.value = val
            mock_cookie.secure = True
            mock_cookie._rest = {}
            mock_cookies.append([mock_cookie])

        mock_responses = [Mock(cookies=cookies) for cookies in mock_cookies]

        with patch('engine.agents.cookie_security_analyzer.requests.Session') as mock_session_class:
            mock_session = Mock()
            mock_session.get.side_effect = mock_responses
            mock_session_class.return_value = mock_session

            findings = analyzer.test_session_prediction()

        # Should not produce findings with insufficient data
        assert len(findings) == 0

    def test_test_session_prediction_no_session_cookies(self, analyzer, mock_requests):
        """Test session prediction when no session cookies found."""
        # Non-session cookies
        mock_cookie = Mock()
        mock_cookie.name = 'prefs'
        mock_cookie.value = 'dark'
        mock_cookie.secure = False
        mock_cookie._rest = {}

        mock_response = Mock(cookies=[mock_cookie])

        with patch('engine.agents.cookie_security_analyzer.requests.Session') as mock_session_class:
            mock_session = Mock()
            mock_session.get.return_value = mock_response
            mock_session_class.return_value = mock_session

            findings = analyzer.test_session_prediction()

        assert len(findings) == 0

    def test_test_cookie_overflow(self, analyzer, mock_requests):
        """Test cookie overflow vulnerability detection."""
        # Server accepts large cookie
        mock_response = Mock()
        mock_response.status_code = 200

        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.test_cookie_overflow()

        overflow_findings = [f for f in findings if f.vuln_type == CookieVulnType.COOKIE_OVERFLOW]
        assert len(overflow_findings) >= 1
        assert overflow_findings[0].severity == CookieSeverity.MEDIUM

    def test_test_cookie_overflow_rejected(self, analyzer, mock_requests):
        """Test when server properly rejects oversized cookies."""
        # Server rejects with 431
        mock_response = Mock()
        mock_response.status_code = 431

        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.test_cookie_overflow()

        # Should not report finding if server rejects properly
        overflow_findings = [f for f in findings if f.vuln_type == CookieVulnType.COOKIE_OVERFLOW]
        assert len(overflow_findings) == 0

    def test_test_cookie_bombing(self, analyzer, mock_requests):
        """Test cookie bombing vulnerability detection."""
        # Server accepts many cookies
        mock_response = Mock()
        mock_response.status_code = 200

        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.test_cookie_overflow()

        bombing_findings = [f for f in findings if f.vuln_type == CookieVulnType.COOKIE_BOMBING]
        assert len(bombing_findings) >= 1

    def test_test_cookie_overflow_error_handling(self, analyzer, mock_requests):
        """Test error handling in cookie overflow tests."""
        analyzer.session.get = Mock(side_effect=Exception("Connection error"))

        # Should not raise exception
        findings = analyzer.test_cookie_overflow()

        # May have no findings or partial findings depending on which test failed
        assert isinstance(findings, list)

    def test_test_cookie_scope_broad_domain(self, analyzer):
        """Test detection of overly broad cookie domain."""
        analyzer.domain = "api.example.com"
        analyzer.collected_cookies['sessionid'] = CookieInfo(
            name='sessionid',
            value='abc123',
            domain='.example.com',  # Too broad
            endpoint='/'
        )

        findings = analyzer.test_cookie_scope()

        scope_findings = [f for f in findings if f.vuln_type == CookieVulnType.COOKIE_SCOPE_DOMAIN]
        assert len(scope_findings) >= 1
        assert scope_findings[0].severity == CookieSeverity.HIGH

    def test_test_cookie_scope_broad_path(self, analyzer):
        """Test detection of overly broad cookie path."""
        analyzer.target_url = "https://example.com/admin"
        analyzer.collected_cookies['admin_session'] = CookieInfo(
            name='admin_session',
            value='abc',
            path='/',  # Too broad for admin cookie
            endpoint='/admin'
        )

        findings = analyzer.test_cookie_scope()

        path_findings = [f for f in findings if f.vuln_type == CookieVulnType.COOKIE_SCOPE_PATH]
        assert len(path_findings) >= 1
        assert path_findings[0].severity == CookieSeverity.MEDIUM

    def test_test_cookie_scope_no_issues(self, analyzer):
        """Test when cookie scope is properly configured."""
        analyzer.collected_cookies['session'] = CookieInfo(
            name='session',
            value='abc',
            domain='example.com',  # No leading dot
            path='/',
            endpoint='/'
        )

        findings = analyzer.test_cookie_scope()

        # Should have no scope findings
        scope_findings = [f for f in findings if
                         f.vuln_type in [CookieVulnType.COOKIE_SCOPE_DOMAIN,
                                        CookieVulnType.COOKIE_SCOPE_PATH]]
        assert len(scope_findings) == 0

    def test_run_all_tests(self, analyzer, mock_db_hooks, mock_requests):
        """Test running all tests."""
        # Mock database check
        mock_db_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Ready to test',
            'previous_findings': [],
            'recommendations': []
        }

        # Add test cookie
        analyzer.collected_cookies['session'] = CookieInfo(
            name='session',
            value='abc123',
            secure=False,
            httponly=False,
            endpoint='/'
        )

        # Mock requests for tests that make HTTP calls
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers.get.return_value = ""
        mock_response.cookies = []
        analyzer.session.get = Mock(return_value=mock_response)
        analyzer.session.post = Mock(return_value=mock_response)

        findings = analyzer.run_all_tests()

        # Should have findings from at least security flags test
        assert len(findings) > 0
        assert len(analyzer.findings) > 0

    def test_run_all_tests_should_skip(self, analyzer, mock_db_hooks):
        """Test skipping when database suggests."""
        mock_db_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': [],
            'recommendations': []
        }

        findings = analyzer.run_all_tests()

        assert len(findings) == 0

    def test_run_all_tests_no_cookies(self, analyzer, mock_db_hooks, mock_requests):
        """Test when no cookies are found."""
        mock_db_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Ready',
            'previous_findings': [],
            'recommendations': []
        }

        # Mock response with no cookies
        mock_response = Mock()
        mock_response.headers.get.return_value = ""
        mock_response.cookies = []
        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.run_all_tests()

        assert len(findings) == 0

    def test_get_findings_by_severity(self, analyzer):
        """Test filtering findings by severity."""
        analyzer.findings = [
            CookieFinding(
                title="Critical Issue",
                severity=CookieSeverity.CRITICAL,
                vuln_type=CookieVulnType.SESSION_FIXATION,
                description="Test",
                cookie_name="test",
                endpoint="/"
            ),
            CookieFinding(
                title="High Issue",
                severity=CookieSeverity.HIGH,
                vuln_type=CookieVulnType.MISSING_HTTPONLY,
                description="Test",
                cookie_name="test",
                endpoint="/"
            )
        ]

        critical = analyzer.get_findings_by_severity(CookieSeverity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].title == "Critical Issue"

        high = analyzer.get_findings_by_severity(CookieSeverity.HIGH)
        assert len(high) == 1

    def test_get_summary(self, analyzer):
        """Test summary generation."""
        analyzer.collected_cookies = {
            'session': CookieInfo(name='session', value='abc', endpoint='/'),
            'prefs': CookieInfo(name='prefs', value='dark', endpoint='/')
        }

        analyzer.findings = [
            CookieFinding(
                title="Issue 1",
                severity=CookieSeverity.CRITICAL,
                vuln_type=CookieVulnType.SESSION_FIXATION,
                description="Test",
                cookie_name="test",
                endpoint="/"
            ),
            CookieFinding(
                title="Issue 2",
                severity=CookieSeverity.HIGH,
                vuln_type=CookieVulnType.MISSING_HTTPONLY,
                description="Test",
                cookie_name="test",
                endpoint="/"
            )
        ]

        summary = analyzer.get_summary()

        assert summary['target'] == "https://example.com"
        assert summary['total_cookies'] == 2
        assert summary['total_findings'] == 2
        assert summary['vulnerable'] is True
        assert summary['severity_breakdown']['CRITICAL'] == 1
        assert summary['severity_breakdown']['HIGH'] == 1

    def test_is_sequential_integers(self, analyzer):
        """Test sequential detection with integer IDs."""
        assert analyzer._is_sequential(['1001', '1002', '1003']) is True
        assert analyzer._is_sequential(['100', '200', '300']) is False  # Gap too large
        assert analyzer._is_sequential(['abc', 'def', 'ghi']) is False

    def test_is_sequential_hex(self, analyzer):
        """Test sequential detection with hex IDs."""
        assert analyzer._is_sequential(['a01', 'a02', 'a03']) is True
        assert analyzer._is_sequential(['ff', '100', '101']) is True

    def test_check_entropy(self, analyzer):
        """Test entropy checking."""
        # Low entropy (short IDs)
        finding = analyzer._check_entropy('session', ['abc1', 'xyz2', 'def3'])
        assert finding is not None
        assert finding.vuln_type == CookieVulnType.LOW_ENTROPY_SESSION

        # Good entropy (long IDs)
        finding = analyzer._check_entropy('session',
                                         ['a1b2c3d4e5f6g7h8i9j0',
                                          'z9y8x7w6v5u4t3s2r1q0',
                                          'p0o9i8u7y6t5r4e3w2q1'])
        assert finding is None

    def test_has_timestamp_pattern(self, analyzer):
        """Test timestamp pattern detection."""
        import time
        current_ts = str(int(time.time()))[:8]

        # With timestamp
        assert analyzer._has_timestamp_pattern([f'{current_ts}abc', f'{current_ts}xyz']) is True

        # Without timestamp
        assert analyzer._has_timestamp_pattern(['random123', 'random456']) is False


class TestCookieFinding:
    """Test CookieFinding dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        finding = CookieFinding(
            title="Test Finding",
            severity=CookieSeverity.HIGH,
            vuln_type=CookieVulnType.MISSING_SECURE,
            description="Test description",
            cookie_name="session",
            endpoint="/",
            evidence={'key': 'value'},
            poc="curl test",
            impact="High impact",
            remediation="Fix it",
            cwe_id="CWE-614"
        )

        result = finding.to_dict()

        assert result['title'] == "Test Finding"
        assert result['severity'] == "HIGH"
        assert result['vuln_type'] == "COOKIE_MISSING_SECURE"
        assert result['cookie_name'] == "session"
        assert result['cwe_id'] == "CWE-614"

    def test_default_date(self):
        """Test default discovered_date is set."""
        finding = CookieFinding(
            title="Test",
            severity=CookieSeverity.LOW,
            vuln_type=CookieVulnType.MISSING_SECURE,
            description="Test",
            cookie_name="test",
            endpoint="/"
        )

        assert finding.discovered_date == date.today().isoformat()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_analyzer_without_requests(self, mock_db):
        """Test that analyzer requires requests library."""
        with patch('engine.agents.cookie_security_analyzer.REQUESTS_AVAILABLE', False):
            with pytest.raises(ImportError, match="requests library required"):
                CookieSecurityAnalyzer(target_url="https://example.com", db=mock_db)

    def test_collect_cookies_multiple_endpoints(self, analyzer, mock_requests):
        """Test collecting from multiple endpoints."""
        mock_response1 = Mock()
        mock_response1.headers.get.return_value = "session1=abc"
        mock_response1.cookies = []

        mock_response2 = Mock()
        mock_response2.headers.get.return_value = "session2=xyz"
        mock_response2.cookies = []

        analyzer.session.get = Mock(side_effect=[mock_response1, mock_response2])

        analyzer.collect_cookies(['/page1', '/page2'])

        assert analyzer.session.get.call_count == 2

    def test_parse_cookie_with_all_attributes(self, analyzer):
        """Test parsing cookie with all possible attributes."""
        header = ("auth=token123; Domain=.example.com; Path=/api; Secure; HttpOnly; "
                 "SameSite=Strict; Max-Age=3600; Expires=Wed, 21 Oct 2025 07:28:00 GMT")

        cookie = analyzer._parse_cookie_header(header, "/api")

        assert cookie.name == "auth"
        assert cookie.domain == ".example.com"
        assert cookie.path == "/api"
        assert cookie.secure is True
        assert cookie.httponly is True
        assert cookie.samesite == "Strict"
        assert cookie.max_age == 3600

    def test_multiple_findings_same_cookie(self, analyzer):
        """Test that same cookie can have multiple findings."""
        analyzer.collected_cookies['bad_cookie'] = CookieInfo(
            name='sessionid',
            value='abc',
            secure=False,
            httponly=False,
            samesite=None,
            endpoint='/'
        )

        findings = analyzer.test_security_flags()

        # Should have at least 3 findings (missing Secure, HttpOnly, SameSite)
        assert len(findings) >= 3

    def test_run_all_tests_with_credentials(self, analyzer, mock_db_hooks, mock_requests):
        """Test running all tests including session fixation with credentials."""
        analyzer.credentials = {
            'login_endpoint': '/login',
            'username': 'test',
            'password': 'test'
        }

        mock_db_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Ready',
            'previous_findings': [],
            'recommendations': []
        }

        analyzer.collected_cookies['session'] = CookieInfo(
            name='session',
            value='fixed_session',
            endpoint='/'
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers.get.return_value = ""
        mock_response.cookies = []
        analyzer.session.get = Mock(return_value=mock_response)
        analyzer.session.post = Mock(return_value=mock_response)

        findings = analyzer.run_all_tests()

        # Should include findings from all test methods
        assert len(findings) > 0


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_full_analysis_workflow(self, mock_db, mock_db_hooks, mock_requests):
        """Test complete analysis workflow."""
        mock_db_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Ready to test',
            'previous_findings': [],
            'recommendations': []
        }

        analyzer = CookieSecurityAnalyzer(
            target_url="https://vulnerable-site.com",
            credentials={
                'login_endpoint': '/login',
                'username': 'test',
                'password': 'test'
            },
            db=mock_db
        )

        # Mock cookie collection
        mock_cookie = Mock()
        mock_cookie.name = 'SESSIONID'
        mock_cookie.value = 'insecure_session_123'
        mock_cookie.domain = '.vulnerable-site.com'
        mock_cookie.path = '/'
        mock_cookie.secure = False
        mock_cookie._rest = {}
        mock_cookie.expires = None

        mock_response = Mock()
        mock_response.headers.get.return_value = ""
        mock_response.cookies = [mock_cookie]
        mock_response.status_code = 200

        analyzer.session.get = Mock(return_value=mock_response)
        analyzer.session.post = Mock(return_value=mock_response)

        findings = analyzer.run_all_tests(endpoints=['/'])

        # Should have multiple findings
        assert len(findings) > 0

        # Check summary
        summary = analyzer.get_summary()
        assert summary['vulnerable'] is True
        assert summary['total_findings'] > 0

    def test_secure_site_analysis(self, mock_db, mock_db_hooks, mock_requests):
        """Test analysis of properly secured site."""
        mock_db_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Ready',
            'previous_findings': [],
            'recommendations': []
        }

        analyzer = CookieSecurityAnalyzer(
            target_url="https://secure-site.com",
            db=mock_db
        )

        # Mock secure cookie
        mock_cookie = Mock()
        mock_cookie.name = '__Host-session'
        mock_cookie.value = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'
        mock_cookie.domain = None
        mock_cookie.path = '/'
        mock_cookie.secure = True
        mock_cookie._rest = {'HttpOnly': True, 'SameSite': 'Strict', 'Max-Age': 3600}
        mock_cookie.expires = None

        mock_response = Mock()
        mock_response.headers.get.return_value = ""
        mock_response.cookies = [mock_cookie]
        mock_response.status_code = 431  # Rejects oversized cookies

        analyzer.session.get = Mock(return_value=mock_response)

        findings = analyzer.run_all_tests()

        # Secure site should have minimal or no findings
        critical_findings = [f for f in findings if f.severity == CookieSeverity.CRITICAL]
        assert len(critical_findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=engine.agents.cookie_security_analyzer",
                 "--cov-report=term-missing", "--cov-report=html"])
