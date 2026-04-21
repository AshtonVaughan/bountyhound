"""
Comprehensive tests for JWT Analyzer Agent

Tests cover:
- JWT decoding and parsing
- Algorithm confusion attacks
- 'none' algorithm bypass
- Weak secret detection
- Header injection (jwk, jku, x5u)
- Expiration validation
- Kid SQL injection
- Kid path traversal
- Signature validation bypass
- Key confusion attacks
- Missing claims detection
- Edge cases and error handling
"""

import pytest
import time
import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any

from engine.agents.jwt_analyzer import (
    JWTAnalyzer,
    JWTVulnerability,
    JWTAnalysisResult
)


class TestJWTAnalyzer:
    """Test JWT Analyzer functionality."""

    def test_initialization(self):
        """Test JWT analyzer initialization."""
        analyzer = JWTAnalyzer()
        assert analyzer is not None
        assert isinstance(analyzer.analyzed_tokens, list)
        assert len(analyzer.analyzed_tokens) == 0

    def test_decode_valid_token(self):
        """Test decoding a valid JWT token."""
        analyzer = JWTAnalyzer()

        # Create a simple token
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': '1234567890', 'name': 'Test User', 'iat': 1516239022}

        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        assert result.is_valid is True
        assert result.header == header
        assert result.payload == payload
        assert len(result.signature) > 0

    def test_decode_invalid_format(self):
        """Test decoding token with invalid format."""
        analyzer = JWTAnalyzer()

        # Invalid: only 2 parts
        result = analyzer.analyze_token('header.payload')
        assert result.is_valid is False
        assert len(result.warnings) > 0
        assert 'expected 3 parts' in result.warnings[0].lower()

    def test_decode_invalid_base64(self):
        """Test decoding token with invalid base64."""
        analyzer = JWTAnalyzer()

        # Invalid base64
        result = analyzer.analyze_token('invalid!!!.invalid!!!.sig')
        assert result.is_valid is False
        assert len(result.warnings) > 0

    def test_algorithm_confusion_rs256_to_hs256(self):
        """Test detection of RS256 to HS256 algorithm confusion."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'RS256', 'typ': 'JWT'}
        payload = {'sub': 'user123', 'role': 'user'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        # Should detect potential algorithm confusion
        alg_confusion_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'ALGORITHM_CONFUSION']
        assert len(alg_confusion_vulns) == 1

        vuln = alg_confusion_vulns[0]
        assert vuln.severity == 'HIGH'
        assert 'RS256' in vuln.title
        assert 'HS256' in vuln.description
        assert vuln.evidence['current_algorithm'] == 'RS256'
        assert vuln.evidence['attack_algorithm'] == 'HS256'

    def test_none_algorithm_detection(self):
        """Test detection of 'none' algorithm vulnerability."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        # Should always suggest testing 'none' algorithm
        none_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'NONE_ALGORITHM']
        assert len(none_vulns) == 1

        vuln = none_vulns[0]
        assert vuln.severity == 'CRITICAL'
        assert 'none' in vuln.title.lower()
        assert 'unsigned_token' in vuln.evidence

    def test_none_algorithm_active(self):
        """Test detection of active 'none' algorithm."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {'sub': 'user123', 'admin': True}

        # Create unsigned token
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        token = f"{header_b64}.{payload_b64}."

        result = analyzer.analyze_token(token)

        # Should detect active 'none' algorithm
        active_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'NONE_ALGORITHM_ACTIVE']
        assert len(active_vulns) == 1

        vuln = active_vulns[0]
        assert vuln.severity == 'CRITICAL'
        assert vuln.cvss_score == 10.0
        assert 'NO signature' in vuln.description

    def test_weak_secret_detection_common(self):
        """Test detection of common weak secrets."""
        analyzer = JWTAnalyzer()

        weak_secrets = ['secret', 'password', 'test', '12345', '']

        for weak_secret in weak_secrets:
            analyzer = JWTAnalyzer()  # Fresh analyzer for each test

            header = {'alg': 'HS256', 'typ': 'JWT'}
            payload = {'sub': 'user123'}
            token = self._create_token(header, payload, weak_secret)

            result = analyzer.analyze_token(token)

            weak_secret_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'WEAK_SECRET']
            assert len(weak_secret_vulns) == 1, f"Failed to detect weak secret: {weak_secret}"

            vuln = weak_secret_vulns[0]
            assert vuln.severity == 'CRITICAL'
            assert vuln.evidence['cracked_secret'] == weak_secret
            assert 'forge' in vuln.description.lower()

    def test_weak_secret_not_found(self):
        """Test that strong secrets are not flagged."""
        analyzer = JWTAnalyzer()

        strong_secret = 'very_long_random_secret_that_is_not_in_wordlist_12345678901234567890'
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, strong_secret)

        result = analyzer.analyze_token(token)

        weak_secret_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'WEAK_SECRET']
        assert len(weak_secret_vulns) == 0

    def test_weak_secret_length(self):
        """Test detection of short secret."""
        analyzer = JWTAnalyzer()

        short_secret = 'short'  # < 32 bytes
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, short_secret)

        result = analyzer.analyze_token(token, original_secret=short_secret)

        length_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'WEAK_SECRET_LENGTH']
        assert len(length_vulns) == 1

        vuln = length_vulns[0]
        assert vuln.severity == 'HIGH'
        assert vuln.evidence['secret_length'] < 32
        assert vuln.evidence['recommended_length'] == 32

    def test_jwk_header_injection(self):
        """Test detection of embedded JWK header."""
        analyzer = JWTAnalyzer()

        header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'jwk': {
                'kty': 'RSA',
                'n': 'base64_encoded_modulus',
                'e': 'AQAB'
            }
        }
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        jwk_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'JWK_INJECTION']
        assert len(jwk_vulns) == 1

        vuln = jwk_vulns[0]
        assert vuln.severity == 'HIGH'
        assert 'jwk' in vuln.evidence
        assert 'inject' in vuln.description.lower()

    def test_jku_header_injection(self):
        """Test detection of JKU header."""
        analyzer = JWTAnalyzer()

        jku_url = 'https://attacker.com/jwks.json'
        header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'jku': jku_url
        }
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        jku_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'JKU_INJECTION']
        assert len(jku_vulns) == 1

        vuln = jku_vulns[0]
        assert vuln.severity == 'HIGH'
        assert vuln.evidence['jku'] == jku_url
        assert 'SSRF' in vuln.description

    def test_x5u_header_injection(self):
        """Test detection of X5U header."""
        analyzer = JWTAnalyzer()

        x5u_url = 'https://attacker.com/cert.pem'
        header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'x5u': x5u_url
        }
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        x5u_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'X5U_INJECTION']
        assert len(x5u_vulns) == 1

        vuln = x5u_vulns[0]
        assert vuln.severity == 'HIGH'
        assert vuln.evidence['x5u'] == x5u_url

    def test_expired_token_detection(self):
        """Test detection of expired tokens."""
        analyzer = JWTAnalyzer()

        # Create expired token (expired 1 hour ago)
        exp = int(time.time()) - 3600
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123', 'exp': exp}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        expired_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'EXPIRED_TOKEN']
        assert len(expired_vulns) == 1

        vuln = expired_vulns[0]
        assert vuln.severity == 'MEDIUM'
        assert vuln.evidence['expired_seconds'] > 3500  # ~1 hour
        assert 'expired' in vuln.title.lower()

    def test_missing_expiration(self):
        """Test detection of missing expiration claim."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}  # No exp claim
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        missing_exp_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'MISSING_EXPIRATION']
        assert len(missing_exp_vulns) == 1

        vuln = missing_exp_vulns[0]
        assert vuln.severity == 'MEDIUM'
        assert 'exp' in vuln.evidence['missing_claims']

    def test_premature_token(self):
        """Test detection of not-yet-valid tokens (nbf)."""
        analyzer = JWTAnalyzer()

        # Token not valid until 1 hour from now
        nbf = int(time.time()) + 3600
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123', 'nbf': nbf}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        premature_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'PREMATURE_TOKEN']
        assert len(premature_vulns) == 1

        vuln = premature_vulns[0]
        assert vuln.severity == 'LOW'

    def test_kid_sql_injection(self):
        """Test detection of SQL injection potential in kid parameter."""
        analyzer = JWTAnalyzer()

        header = {
            'alg': 'HS256',
            'typ': 'JWT',
            'kid': 'key123'
        }
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        kid_sqli_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'KID_SQLI_POTENTIAL']
        assert len(kid_sqli_vulns) == 1

        vuln = kid_sqli_vulns[0]
        assert vuln.severity == 'HIGH'
        assert 'SQL injection' in vuln.description
        assert 'test_payloads' in vuln.evidence

    def test_kid_sql_injection_active(self):
        """Test detection of active SQL injection in kid."""
        analyzer = JWTAnalyzer()

        malicious_kid = "' OR '1'='1"
        header = {
            'alg': 'HS256',
            'typ': 'JWT',
            'kid': malicious_kid
        }
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        active_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'KID_INJECTION_ACTIVE']
        assert len(active_vulns) == 1

        vuln = active_vulns[0]
        assert vuln.severity == 'CRITICAL'
        assert vuln.evidence['kid'] == malicious_kid

    def test_kid_path_traversal(self):
        """Test detection of path traversal in kid parameter."""
        analyzer = JWTAnalyzer()

        path_traversal_kids = [
            '../../etc/passwd',
            '../../../keys/secret.key',
            'C:/Windows/System32/config/SAM'
        ]

        for kid in path_traversal_kids:
            analyzer = JWTAnalyzer()

            header = {
                'alg': 'HS256',
                'typ': 'JWT',
                'kid': kid
            }
            payload = {'sub': 'user123'}
            token = self._create_token(header, payload, 'secret')

            result = analyzer.analyze_token(token)

            path_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'KID_PATH_TRAVERSAL']
            assert len(path_vulns) == 1, f"Failed to detect path traversal in: {kid}"

            vuln = path_vulns[0]
            assert vuln.severity == 'HIGH'
            assert 'path traversal' in vuln.title.lower()

    def test_signature_validation_bypass(self):
        """Test detection of signature validation bypass."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123', 'role': 'user'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        sig_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'SIGNATURE_NOT_VERIFIED']
        assert len(sig_vulns) == 1

        vuln = sig_vulns[0]
        assert vuln.severity == 'CRITICAL'
        assert 'modified_token' in vuln.evidence
        assert 'modified_payload' in vuln.evidence
        # Modified payload should have privilege escalation attempt
        assert vuln.evidence['modified_payload'] != payload

    def test_missing_audience_claim(self):
        """Test detection of missing audience claim."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}  # No aud claim
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        aud_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'MISSING_AUDIENCE']
        assert len(aud_vulns) == 1

        vuln = aud_vulns[0]
        assert vuln.severity == 'MEDIUM'
        assert 'aud' in vuln.evidence['missing_claims']

    def test_missing_issuer_claim(self):
        """Test detection of missing issuer claim."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}  # No iss claim
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        iss_vulns = [v for v in result.vulnerabilities if v.vuln_type == 'MISSING_ISSUER']
        assert len(iss_vulns) == 1

        vuln = iss_vulns[0]
        assert vuln.severity == 'LOW'
        assert 'iss' in vuln.evidence['missing_claims']

    def test_sensitive_data_warning(self):
        """Test warning for sensitive data in payload."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': 'user123',
            'password': 'secret123',  # Sensitive!
            'api_key': 'key123'  # Sensitive!
        }
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        # Should have warnings about sensitive data
        sensitive_warnings = [w for w in result.warnings if 'sensitive' in w.lower()]
        assert len(sensitive_warnings) >= 1

    def test_long_token_lifetime_warning(self):
        """Test warning for long token lifetime."""
        analyzer = JWTAnalyzer()

        now = int(time.time())
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': 'user123',
            'iat': now,
            'exp': now + 86400  # 24 hours
        }
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        # Should have warning about long lifetime
        lifetime_warnings = [w for w in result.warnings if 'lifetime' in w.lower()]
        assert len(lifetime_warnings) >= 1

    def test_multiple_tokens_analysis(self):
        """Test analyzing multiple tokens."""
        analyzer = JWTAnalyzer()

        tokens = []
        for i in range(3):
            header = {'alg': 'HS256', 'typ': 'JWT'}
            payload = {'sub': f'user{i}'}
            token = self._create_token(header, payload, 'secret')
            tokens.append(token)

        results = [analyzer.analyze_token(token) for token in tokens]

        assert len(results) == 3
        assert len(analyzer.analyzed_tokens) == 3

        # Each should have found vulnerabilities
        for result in results:
            assert len(result.vulnerabilities) > 0

    def test_get_summary(self):
        """Test getting summary of analyzed tokens."""
        analyzer = JWTAnalyzer()

        # Analyze multiple tokens
        for i in range(3):
            header = {'alg': 'HS256', 'typ': 'JWT'}
            payload = {'sub': f'user{i}'}
            token = self._create_token(header, payload, 'secret')
            analyzer.analyze_token(token)

        summary = analyzer.get_summary()

        assert summary['tokens_analyzed'] == 3
        assert summary['total_vulnerabilities'] > 0
        assert 'vulnerabilities_by_severity' in summary
        assert 'vulnerabilities_by_type' in summary
        assert len(summary['tokens']) == 3

    def test_to_dict_conversion(self):
        """Test converting analysis result to dictionary."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert 'token' in result_dict
        assert 'header' in result_dict
        assert 'payload' in result_dict
        assert 'vulnerabilities' in result_dict
        assert 'warnings' in result_dict
        assert 'metadata' in result_dict

        # Vulnerabilities should be serializable
        assert isinstance(result_dict['vulnerabilities'], list)
        if len(result_dict['vulnerabilities']) > 0:
            assert isinstance(result_dict['vulnerabilities'][0], dict)

    def test_hs384_algorithm(self):
        """Test support for HS384 algorithm."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS384', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token_hs384(header, payload, 'secret')

        result = analyzer.analyze_token(token)
        assert result.is_valid is True
        assert result.metadata['algorithm'] == 'HS384'

    def test_hs512_algorithm(self):
        """Test support for HS512 algorithm."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS512', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token_hs512(header, payload, 'secret')

        result = analyzer.analyze_token(token)
        assert result.is_valid is True
        assert result.metadata['algorithm'] == 'HS512'

    def test_metadata_extraction(self):
        """Test metadata extraction from token."""
        analyzer = JWTAnalyzer()

        now = int(time.time())
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': 'user123',
            'iss': 'https://auth.example.com',
            'aud': 'https://api.example.com',
            'iat': now,
            'exp': now + 3600,
            'nbf': now
        }
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        assert result.metadata['algorithm'] == 'HS256'
        assert result.metadata['type'] == 'JWT'
        assert result.metadata['subject'] == 'user123'
        assert result.metadata['issuer'] == 'https://auth.example.com'
        assert result.metadata['issued_at'] == now
        assert result.metadata['expires_at'] == now + 3600
        assert result.metadata['not_before'] == now

    def test_poc_generation(self):
        """Test that POCs are generated for all vulnerabilities."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        # All vulnerabilities should have POC
        for vuln in result.vulnerabilities:
            assert vuln.poc is not None
            assert len(vuln.poc) > 0
            assert isinstance(vuln.poc, str)

    def test_remediation_provided(self):
        """Test that remediation is provided for all vulnerabilities."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        token = self._create_token(header, payload, 'secret')

        result = analyzer.analyze_token(token)

        # All vulnerabilities should have remediation
        for vuln in result.vulnerabilities:
            assert vuln.remediation is not None
            assert len(vuln.remediation) > 0
            assert isinstance(vuln.remediation, str)

    def test_cwe_mapping(self):
        """Test that vulnerabilities have CWE IDs where applicable."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        token = f"{header_b64}.{payload_b64}."

        result = analyzer.analyze_token(token)

        # Critical vulnerabilities should have CWE
        critical_vulns = [v for v in result.vulnerabilities if v.severity == 'CRITICAL']
        assert len(critical_vulns) > 0

        for vuln in critical_vulns:
            if vuln.cwe:
                assert vuln.cwe.startswith('CWE-')

    def test_cvss_scoring(self):
        """Test that critical vulnerabilities have CVSS scores."""
        analyzer = JWTAnalyzer()

        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {'sub': 'user123'}
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        token = f"{header_b64}.{payload_b64}."

        result = analyzer.analyze_token(token)

        # Check for CVSS scores
        scored_vulns = [v for v in result.vulnerabilities if v.cvss_score is not None]
        assert len(scored_vulns) > 0

        for vuln in scored_vulns:
            assert 0.0 <= vuln.cvss_score <= 10.0

    def test_error_handling(self):
        """Test error handling for malformed input."""
        analyzer = JWTAnalyzer()

        # Empty string
        result = analyzer.analyze_token('')
        assert result.is_valid is False
        assert len(result.warnings) > 0

        # Random garbage
        result = analyzer.analyze_token('totally.invalid.garbage!!!')
        assert result.is_valid is False

    # Helper methods

    def _create_token(self, header: Dict[str, Any], payload: Dict[str, Any], secret: str) -> str:
        """Create a JWT token with HS256."""
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        signing_input = f"{header_b64}.{payload_b64}"

        signature = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()

        signature_b64 = base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')

        return f"{signing_input}.{signature_b64}"

    def _create_token_hs384(self, header: Dict[str, Any], payload: Dict[str, Any], secret: str) -> str:
        """Create a JWT token with HS384."""
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        signing_input = f"{header_b64}.{payload_b64}"

        signature = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha384
        ).digest()

        signature_b64 = base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')

        return f"{signing_input}.{signature_b64}"

    def _create_token_hs512(self, header: Dict[str, Any], payload: Dict[str, Any], secret: str) -> str:
        """Create a JWT token with HS512."""
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        signing_input = f"{header_b64}.{payload_b64}"

        signature = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha512
        ).digest()

        signature_b64 = base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')

        return f"{signing_input}.{signature_b64}"

    def _encode_base64url(self, data: Dict[str, Any]) -> str:
        """Encode data as base64url."""
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.b64encode(json_str.encode()).decode()
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')


class TestJWTVulnerability:
    """Test JWTVulnerability dataclass."""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability."""
        vuln = JWTVulnerability(
            vuln_type='TEST_VULN',
            severity='HIGH',
            title='Test Vulnerability',
            description='This is a test',
            evidence={'key': 'value'},
            poc='test poc',
            remediation='fix it'
        )

        assert vuln.vuln_type == 'TEST_VULN'
        assert vuln.severity == 'HIGH'
        assert vuln.title == 'Test Vulnerability'
        assert vuln.cwe is None
        assert vuln.cvss_score is None

    def test_vulnerability_with_cwe(self):
        """Test vulnerability with CWE."""
        vuln = JWTVulnerability(
            vuln_type='TEST',
            severity='CRITICAL',
            title='Test',
            description='Test',
            evidence={},
            poc='test',
            remediation='fix',
            cwe='CWE-123'
        )

        assert vuln.cwe == 'CWE-123'


class TestJWTAnalysisResult:
    """Test JWTAnalysisResult dataclass."""

    def test_result_creation(self):
        """Test creating an analysis result."""
        result = JWTAnalysisResult(
            token='test.token.here',
            is_valid=True
        )

        assert result.token == 'test.token.here'
        assert result.is_valid is True
        assert result.header == {}
        assert result.payload == {}
        assert result.signature == ''
        assert result.vulnerabilities == []
        assert result.warnings == []
        assert result.metadata == {}

    def test_result_to_dict(self):
        """Test converting result to dict."""
        vuln = JWTVulnerability(
            vuln_type='TEST',
            severity='LOW',
            title='Test',
            description='Test',
            evidence={},
            poc='test',
            remediation='fix'
        )

        result = JWTAnalysisResult(
            token='test',
            is_valid=True,
            header={'alg': 'HS256'},
            payload={'sub': 'test'},
            signature='sig',
            vulnerabilities=[vuln],
            warnings=['warning'],
            metadata={'test': 'data'}
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict['token'] == 'test'
        assert result_dict['is_valid'] is True
        assert len(result_dict['vulnerabilities']) == 1
        assert isinstance(result_dict['vulnerabilities'][0], dict)
