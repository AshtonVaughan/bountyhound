"""
Comprehensive tests for API Authentication Chain Tester Agent

Tests cover:
- JWT algorithm confusion attacks
- JWT signature bypass
- Weak JWT secret detection
- Token refresh replay attacks
- Token rotation validation
- Token revocation testing
- API key exposure detection
- HMAC timing attacks
- Token leakage vectors
- Database integration
- Edge cases and error handling

Target: 30+ tests, 95%+ coverage
"""

import pytest
import json
import base64
import hashlib
import hmac
import time
from typing import Dict, Any
from unittest.mock import Mock, patch, MagicMock

from engine.agents.api_authentication_chain_tester import (
    APIAuthenticationChainTester,
    AuthFinding,
    AuthTestResult,
    AuthVulnSeverity,
    AuthVulnType,
    execute_api_auth_test
)


class TestAPIAuthenticationChainTester:
    """Test API Authentication Chain Tester functionality."""

    @pytest.fixture
    def tester(self):
        """Create tester instance without database."""
        return APIAuthenticationChainTester(
            target_url="https://api.example.com",
            timeout=5,
            verify_ssl=False,
            use_database=False
        )

    @pytest.fixture
    def mock_response(self):
        """Create mock HTTP response."""
        def _create_response(status_code=200, json_data=None, text='', headers=None):
            mock_resp = Mock()
            mock_resp.status_code = status_code
            mock_resp.json = Mock(return_value=json_data or {})
            mock_resp.text = text
            mock_resp.headers = headers or {}
            return mock_resp
        return _create_response

    def _create_jwt(self, header: Dict, payload: Dict, secret: str = 'secret') -> str:
        """Helper to create JWT token."""
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        message = f"{header_b64}.{payload_b64}"

        if header.get('alg') == 'none':
            return f"{header_b64}.{payload_b64}."

        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    # Test 1: Initialization
    def test_initialization(self, tester):
        """Test tester initialization."""
        assert tester is not None
        assert tester.target_url == "https://api.example.com"
        assert tester.timeout == 5
        assert tester.verify_ssl is False
        assert tester.use_database is False
        assert isinstance(tester.result, AuthTestResult)

    # Test 2: Initialization with database
    def test_initialization_with_database(self):
        """Test tester initialization with database enabled."""
        tester = APIAuthenticationChainTester(
            target_url="https://api.example.com",
            use_database=True
        )
        assert tester.use_database is True
        assert hasattr(tester, 'db')

    # Test 3: JWT detection
    def test_is_jwt_valid(self, tester):
        """Test JWT token detection."""
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'}
        )
        assert tester._is_jwt(token) is True

    # Test 4: Invalid JWT detection
    def test_is_jwt_invalid(self, tester):
        """Test invalid JWT detection."""
        assert tester._is_jwt('not.a.jwt') is False
        assert tester._is_jwt('invalid') is False
        assert tester._is_jwt('') is False

    # Test 5: JWT decoding
    def test_decode_jwt(self, tester):
        """Test JWT decoding."""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123', 'role': 'admin'}
        token = self._create_jwt(header, payload)

        decoded_header, decoded_payload, signature = tester._decode_jwt(token)

        assert decoded_header == header
        assert decoded_payload == payload
        assert signature is not None

    # Test 6: JWT decoding invalid token
    def test_decode_jwt_invalid(self, tester):
        """Test JWT decoding with invalid token."""
        header, payload, sig = tester._decode_jwt('invalid.token')
        assert header is None
        assert payload is None
        assert sig is None

    # Test 7: JWT 'none' algorithm creation
    def test_create_jwt_none_algorithm(self, tester):
        """Test creating JWT with 'none' algorithm."""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}

        none_token = tester._create_jwt_with_alg(payload, header, 'none', '')

        assert none_token.endswith('.')
        parts = none_token.split('.')
        assert len(parts) == 3
        assert parts[2] == ''

    # Test 8: JWT signature generation
    def test_generate_jwt_signature(self, tester):
        """Test JWT signature generation."""
        message = "header.payload"
        secret = "secret"

        sig = tester._generate_jwt_signature(message, secret, 'HS256')

        assert len(sig) > 0
        assert '=' not in sig  # Base64url encoded

    # Test 9: Discover auth endpoints (mocked)
    @patch('requests.post')
    @patch('requests.get')
    def test_discover_auth_endpoints(self, mock_get, mock_post, tester, mock_response):
        """Test authentication endpoint discovery."""
        mock_post.return_value = mock_response(401)
        mock_get.return_value = mock_response(404)

        tester._discover_auth_endpoints()

        # Should attempt to discover endpoints
        assert mock_post.called or mock_get.called

    # Test 10: Identify auth schemes (mocked)
    @patch('requests.get')
    def test_identify_auth_schemes(self, mock_get, tester, mock_response):
        """Test authentication scheme identification."""
        mock_get.return_value = mock_response(
            401,
            headers={'WWW-Authenticate': 'Bearer realm="api"'}
        )

        tester._identify_auth_schemes()

        assert 'bearer' in tester.result.auth_schemes

    # Test 11: Obtain JWT token (mocked)
    @patch('requests.post')
    def test_obtain_jwt_token(self, mock_post, tester, mock_response):
        """Test obtaining JWT token."""
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'}
        )

        tester.result.auth_endpoints['login'] = 'https://api.example.com/login'
        mock_post.return_value = mock_response(200, {'token': token})

        result_token = tester._obtain_jwt_token()

        assert result_token == token
        assert len(tester.result.captured_tokens) == 1

    # Test 12: JWT algorithm confusion detection
    @patch('requests.get')
    def test_jwt_algorithm_confusion_none(self, mock_get, tester, mock_response):
        """Test JWT 'none' algorithm confusion detection."""
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'}
        )

        # Mock successful authentication with 'none' token
        mock_get.return_value = mock_response(200)

        tester._test_jwt_algorithm_confusion(token)

        # Should detect 'none' algorithm vulnerability
        none_vulns = [f for f in tester.result.findings
                      if f.vuln_type == AuthVulnType.JWT_ALGORITHM_NONE]
        assert len(none_vulns) == 1
        assert none_vulns[0].severity == AuthVulnSeverity.CRITICAL

    # Test 13: JWT RS256 to HS256 confusion
    def test_jwt_rs256_to_hs256_confusion(self, tester):
        """Test RS256 to HS256 algorithm confusion detection."""
        token = self._create_jwt(
            {'alg': 'RS256', 'typ': 'JWT'},
            {'sub': 'user123'}
        )

        tester._test_jwt_algorithm_confusion(token)

        # Should suggest RS256 to HS256 attack
        confusion_vulns = [f for f in tester.result.findings
                          if f.vuln_type == AuthVulnType.JWT_ALGORITHM_CONFUSION]
        assert len(confusion_vulns) == 1
        assert confusion_vulns[0].severity == AuthVulnSeverity.HIGH

    # Test 14: JWT signature bypass
    @patch('requests.get')
    def test_jwt_signature_bypass(self, mock_get, tester, mock_response):
        """Test JWT signature bypass detection."""
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'}
        )

        # Mock accepting unsigned token
        mock_get.return_value = mock_response(200)

        tester._test_jwt_signature_bypass(token)

        bypass_vulns = [f for f in tester.result.findings
                       if f.vuln_type == AuthVulnType.JWT_SIGNATURE_BYPASS]
        assert len(bypass_vulns) == 1
        assert bypass_vulns[0].severity == AuthVulnSeverity.CRITICAL

    # Test 15: Weak JWT secret detection
    def test_jwt_weak_secret_detection(self, tester):
        """Test weak JWT secret detection."""
        weak_secret = 'secret'
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'},
            weak_secret
        )

        tester._test_jwt_weak_secret(token)

        weak_secret_vulns = [f for f in tester.result.findings
                            if f.vuln_type == AuthVulnType.JWT_WEAK_SECRET]
        assert len(weak_secret_vulns) == 1
        assert weak_secret_vulns[0].severity == AuthVulnSeverity.CRITICAL
        assert weak_secret in weak_secret_vulns[0].evidence['cracked_secret']

    # Test 16: Strong JWT secret not detected
    def test_jwt_strong_secret_not_detected(self, tester):
        """Test that strong secrets are not flagged."""
        strong_secret = 'very_strong_secret_not_in_wordlist_1234567890'
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'},
            strong_secret
        )

        tester._test_jwt_weak_secret(token)

        weak_secret_vulns = [f for f in tester.result.findings
                            if f.vuln_type == AuthVulnType.JWT_WEAK_SECRET]
        assert len(weak_secret_vulns) == 0

    # Test 17: JWT token testing
    @patch('requests.get')
    def test_jwt_token_testing_success(self, mock_get, tester, mock_response):
        """Test JWT token validation."""
        token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'}
        )

        mock_get.return_value = mock_response(200)

        result = tester._test_jwt_token(token)
        assert result is True

    # Test 18: JWT token testing failure
    @patch('requests.get')
    def test_jwt_token_testing_failure(self, mock_get, tester, mock_response):
        """Test JWT token rejection."""
        token = 'invalid.token.here'

        mock_get.return_value = mock_response(401)

        result = tester._test_jwt_token(token)
        assert result is False

    # Test 19: Obtain token pair (mocked)
    @patch('requests.post')
    def test_obtain_token_pair(self, mock_post, tester, mock_response):
        """Test obtaining access and refresh token pair."""
        tester.result.auth_endpoints['login'] = 'https://api.example.com/login'

        mock_post.return_value = mock_response(200, {
            'access_token': 'access_123',
            'refresh_token': 'refresh_456'
        })

        access, refresh = tester._obtain_token_pair()

        assert access == 'access_123'
        assert refresh == 'refresh_456'

    # Test 20: Refresh token replay detection
    @patch('requests.post')
    def test_refresh_token_replay(self, mock_post, tester, mock_response):
        """Test refresh token replay vulnerability detection."""
        refresh_url = 'https://api.example.com/refresh'
        refresh_token = 'refresh_token_123'

        # Mock successful replay
        mock_post.return_value = mock_response(200, {'access_token': 'new_token'})

        tester._test_refresh_token_replay(refresh_url, refresh_token)

        replay_vulns = [f for f in tester.result.findings
                       if f.vuln_type == AuthVulnType.REFRESH_TOKEN_REPLAY]
        assert len(replay_vulns) == 1
        assert replay_vulns[0].severity == AuthVulnSeverity.HIGH

    # Test 21: Refresh token rotation testing
    @patch('requests.post')
    def test_refresh_token_not_rotated(self, mock_post, tester, mock_response):
        """Test refresh token rotation detection."""
        refresh_url = 'https://api.example.com/refresh'
        refresh_token = 'refresh_token_123'

        # Mock returning same refresh token
        mock_post.return_value = mock_response(200, {
            'access_token': 'new_access',
            'refresh_token': refresh_token  # Same token
        })

        tester._test_refresh_token_rotation(refresh_url, refresh_token)

        rotation_vulns = [f for f in tester.result.findings
                         if f.vuln_type == AuthVulnType.REFRESH_TOKEN_NOT_ROTATED]
        assert len(rotation_vulns) == 1
        assert rotation_vulns[0].severity == AuthVulnSeverity.MEDIUM

    # Test 22: Token revocation testing
    @patch('requests.post')
    @patch('requests.get')
    def test_token_not_revoked(self, mock_get, mock_post, tester, mock_response):
        """Test token revocation detection."""
        tester.result.auth_endpoints['login'] = 'https://api.example.com/login'
        tester.result.auth_endpoints['logout'] = 'https://api.example.com/logout'

        token = 'access_token_123'

        # Mock login
        mock_post.side_effect = [
            mock_response(200, {'access_token': token, 'refresh_token': 'refresh'}),
            mock_response(200)  # Logout
        ]

        # Mock token still valid after logout
        mock_get.return_value = mock_response(200)

        tester._test_token_revocation()

        revocation_vulns = [f for f in tester.result.findings
                           if f.vuln_type == AuthVulnType.TOKEN_NOT_REVOKED]
        assert len(revocation_vulns) == 1
        assert revocation_vulns[0].severity == AuthVulnSeverity.MEDIUM

    # Test 23: API key exposure detection
    @patch('requests.get')
    def test_api_key_exposure(self, mock_get, tester, mock_response):
        """Test API key exposure detection."""
        exposed_html = '''
        <script>
        const config = {
            apiKey: "sk_live_1234567890abcdef1234567890",
            api_key: "another_key_here_12345678"
        };
        </script>
        '''

        mock_get.return_value = mock_response(200, text=exposed_html)

        tester._test_api_key_exposure()

        exposure_vulns = [f for f in tester.result.findings
                         if f.vuln_type == AuthVulnType.API_KEY_EXPOSURE]
        assert len(exposure_vulns) == 1
        assert exposure_vulns[0].severity == AuthVulnSeverity.CRITICAL

    # Test 24: HMAC timing difference detection
    def test_has_timing_difference(self, tester):
        """Test timing difference detection."""
        # Significant difference
        timing_data = [
            {'signature': 'aaa', 'avg_time': 0.1},
            {'signature': 'bbb', 'avg_time': 0.5}
        ]
        assert tester._has_timing_difference(timing_data) is True

        # No significant difference
        timing_data = [
            {'signature': 'aaa', 'avg_time': 0.1},
            {'signature': 'bbb', 'avg_time': 0.11}
        ]
        assert tester._has_timing_difference(timing_data) is False

    # Test 25: HMAC timing attack detection
    @patch('requests.get')
    def test_hmac_timing_attack(self, mock_get, tester):
        """Test HMAC timing attack detection."""
        # Mock responses with varying times
        responses = []
        for i in range(30):
            mock_resp = Mock()
            mock_resp.status_code = 401
            responses.append(mock_resp)

        mock_get.side_effect = responses

        # Manually inject timing differences
        with patch('time.time') as mock_time:
            # Simulate timing variance
            times = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9,
                    1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9,
                    2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9]
            mock_time.side_effect = times

            tester._test_hmac_timing_attack()

    # Test 26: Token in URL detection
    @patch('requests.get')
    def test_token_in_url(self, mock_get, tester, mock_response):
        """Test token in URL detection."""
        mock_get.return_value = mock_response(401, text='Invalid token provided')

        tester._test_token_in_url()

        url_vulns = [f for f in tester.result.findings
                    if f.vuln_type == AuthVulnType.TOKEN_IN_URL]
        assert len(url_vulns) == 1
        assert url_vulns[0].severity == AuthVulnSeverity.MEDIUM

    # Test 27: Token in error messages
    @patch('requests.get')
    def test_token_in_errors(self, mock_get, tester, mock_response):
        """Test token leakage in error messages."""
        token = 'test_secret_token_12345'
        error_text = f'Invalid token: {token}'

        mock_get.return_value = mock_response(400, text=error_text)

        tester._test_token_in_errors()

        error_vulns = [f for f in tester.result.findings
                      if f.vuln_type == AuthVulnType.TOKEN_LEAKAGE_ERROR]
        assert len(error_vulns) == 1
        assert error_vulns[0].severity == AuthVulnSeverity.MEDIUM

    # Test 28: AuthFinding to dict
    def test_auth_finding_to_dict(self):
        """Test AuthFinding serialization."""
        finding = AuthFinding(
            title="Test Finding",
            severity=AuthVulnSeverity.HIGH,
            vuln_type=AuthVulnType.JWT_WEAK_SECRET,
            description="Test description",
            endpoint="https://api.example.com",
            evidence={'key': 'value'},
            bounty_estimate="$1,000-$3,000"
        )

        result = finding.to_dict()

        assert result['title'] == "Test Finding"
        assert result['severity'] == "HIGH"
        assert result['vuln_type'] == "JWT_WEAK_SECRET"
        assert result['evidence'] == {'key': 'value'}

    # Test 29: AuthTestResult bounty calculation
    def test_auth_test_result_bounty_calculation(self):
        """Test total bounty calculation."""
        result = AuthTestResult(target_url="https://api.example.com")

        result.findings.append(AuthFinding(
            title="Finding 1",
            severity=AuthVulnSeverity.CRITICAL,
            vuln_type=AuthVulnType.JWT_ALGORITHM_NONE,
            description="Test",
            endpoint="https://api.example.com",
            bounty_estimate="$5,000-$15,000"
        ))

        result.findings.append(AuthFinding(
            title="Finding 2",
            severity=AuthVulnSeverity.HIGH,
            vuln_type=AuthVulnType.REFRESH_TOKEN_REPLAY,
            description="Test",
            endpoint="https://api.example.com",
            bounty_estimate="$3,000-$8,000"
        ))

        total = result._calculate_total_bounty()
        assert total == "$8,000-$23,000"

    # Test 30: AuthTestResult to dict
    def test_auth_test_result_to_dict(self):
        """Test AuthTestResult serialization."""
        result = AuthTestResult(target_url="https://api.example.com")
        result.findings.append(AuthFinding(
            title="Test",
            severity=AuthVulnSeverity.CRITICAL,
            vuln_type=AuthVulnType.JWT_ALGORITHM_NONE,
            description="Test",
            endpoint="https://api.example.com"
        ))

        data = result.to_dict()

        assert data['target_url'] == "https://api.example.com"
        assert data['total_findings'] == 1
        assert data['critical'] == 1
        assert len(data['findings']) == 1

    # Test 31: Execute API auth test function
    @patch('engine.agents.api_authentication_chain_tester.APIAuthenticationChainTester')
    def test_execute_api_auth_test(self, mock_tester_class):
        """Test execute_api_auth_test wrapper function."""
        mock_tester = Mock()
        mock_result = AuthTestResult(target_url="https://api.example.com")
        mock_tester.run_comprehensive_test.return_value = mock_result
        mock_tester_class.return_value = mock_tester

        result = execute_api_auth_test("https://api.example.com")

        assert result['target_url'] == "https://api.example.com"
        mock_tester_class.assert_called_once()
        mock_tester.run_comprehensive_test.assert_called_once()

    # Test 32: Execute with custom config
    @patch('engine.agents.api_authentication_chain_tester.APIAuthenticationChainTester')
    def test_execute_api_auth_test_custom_config(self, mock_tester_class):
        """Test execute_api_auth_test with custom configuration."""
        mock_tester = Mock()
        mock_result = AuthTestResult(target_url="https://api.example.com")
        mock_tester.run_comprehensive_test.return_value = mock_result
        mock_tester_class.return_value = mock_tester

        config = {
            'timeout': 20,
            'verify_ssl': False,
            'use_database': False
        }

        result = execute_api_auth_test("https://api.example.com", config)

        mock_tester_class.assert_called_once_with(
            target_url="https://api.example.com",
            timeout=20,
            verify_ssl=False,
            use_database=False
        )

    # Test 33: Multiple weak secrets
    def test_multiple_weak_secrets(self, tester):
        """Test detection of various weak secrets."""
        weak_secrets = ['password', 'test', '12345', '']

        for secret in weak_secrets:
            tester.result.findings = []  # Reset findings
            token = self._create_jwt(
                {'alg': 'HS256', 'typ': 'JWT'},
                {'sub': 'user123'},
                secret
            )

            tester._test_jwt_weak_secret(token)

            weak_secret_vulns = [f for f in tester.result.findings
                                if f.vuln_type == AuthVulnType.JWT_WEAK_SECRET]
            assert len(weak_secret_vulns) == 1
            assert weak_secret_vulns[0].evidence['cracked_secret'] == secret

    # Test 34: Error handling - network errors
    @patch('requests.get')
    def test_network_error_handling(self, mock_get, tester):
        """Test handling of network errors."""
        mock_get.side_effect = Exception("Network error")

        # Should not raise exception
        try:
            tester._identify_auth_schemes()
            tester._test_api_key_exposure()
        except Exception:
            pytest.fail("Should handle network errors gracefully")

    # Test 35: Database integration test
    @patch('engine.core.db_hooks.DatabaseHooks.before_test')
    def test_database_integration(self, mock_before_test):
        """Test database integration for skip logic."""
        mock_before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': []
        }

        tester = APIAuthenticationChainTester(
            target_url="https://api.example.com",
            use_database=True
        )

        result = tester.run_comprehensive_test()

        mock_before_test.assert_called_once()
        assert len(result.findings) == 0

    # Test 36: Comprehensive flow test
    @patch('requests.post')
    @patch('requests.get')
    def test_comprehensive_flow(self, mock_get, mock_post, tester, mock_response):
        """Test comprehensive authentication testing flow."""
        # Setup mocks
        weak_token = self._create_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'user123'},
            'secret'
        )

        mock_post.return_value = mock_response(200, {'token': weak_token})
        mock_get.return_value = mock_response(200)

        tester.result.auth_endpoints['login'] = 'https://api.example.com/login'

        # Run tests
        tester._test_jwt_vulnerabilities()

        # Should find multiple vulnerabilities
        assert len(tester.result.findings) > 0

        # Should have captured token
        assert len(tester.result.captured_tokens) > 0


class TestAuthVulnSeverity:
    """Test AuthVulnSeverity enum."""

    def test_severity_levels(self):
        """Test severity level values."""
        assert AuthVulnSeverity.CRITICAL.value == "CRITICAL"
        assert AuthVulnSeverity.HIGH.value == "HIGH"
        assert AuthVulnSeverity.MEDIUM.value == "MEDIUM"
        assert AuthVulnSeverity.LOW.value == "LOW"
        assert AuthVulnSeverity.INFO.value == "INFO"


class TestAuthVulnType:
    """Test AuthVulnType enum."""

    def test_vuln_types(self):
        """Test vulnerability type values."""
        assert AuthVulnType.JWT_ALGORITHM_NONE.value == "JWT_ALGORITHM_NONE"
        assert AuthVulnType.JWT_WEAK_SECRET.value == "JWT_WEAK_SECRET"
        assert AuthVulnType.REFRESH_TOKEN_REPLAY.value == "REFRESH_TOKEN_REPLAY"
        assert AuthVulnType.API_KEY_EXPOSURE.value == "API_KEY_EXPOSURE"
        assert AuthVulnType.HMAC_TIMING_ATTACK.value == "HMAC_TIMING_ATTACK"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=engine.agents.api_authentication_chain_tester', '--cov-report=term-missing'])
