"""
X-Frame-Options Security Tester Agent

Advanced X-Frame-Options header testing agent that identifies missing or misconfigured
frame protection headers and generates clickjacking POCs.

This agent tests for:
- Missing X-Frame-Options header
- DENY directive validation
- SAMEORIGIN directive validation
- Deprecated ALLOW-FROM directive
- CSP frame-ancestors alternative testing
- Conflicting header detection
- Clickjacking POC generation
- Severity-based risk assessment

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Database integration
try:
    from engine.core.database import BountyHoundDB
    from engine.core.db_hooks import DatabaseHooks
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False


class XFOSeverity(Enum):
    """X-Frame-Options vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class XFOVulnType(Enum):
    """Types of X-Frame-Options vulnerabilities."""
    MISSING_XFO = "MISSING_X_FRAME_OPTIONS"
    MISSING_BOTH = "MISSING_XFO_AND_CSP"
    DEPRECATED_ALLOW_FROM = "DEPRECATED_ALLOW_FROM"
    WEAK_PROTECTION = "WEAK_FRAME_PROTECTION"
    CONFLICTING_HEADERS = "CONFLICTING_HEADERS"
    INVALID_DIRECTIVE = "INVALID_DIRECTIVE"
    CSP_OVERRIDE = "CSP_OVERRIDES_XFO"


@dataclass
class XFOFinding:
    """Represents an X-Frame-Options security finding."""
    title: str
    severity: XFOSeverity
    vuln_type: XFOVulnType
    description: str
    endpoint: str
    url: str
    xfo_header: Optional[str] = None
    csp_header: Optional[str] = None
    frame_ancestors: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    poc_html: str = ""
    impact: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    affected_actions: List[str] = field(default_factory=list)
    bounty_estimate: Tuple[int, int] = (0, 0)
    recommendation: str = ""
    cwe_id: str = "CWE-1021"
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class XFOTestResult:
    """Result from an X-Frame-Options test."""
    endpoint: str
    url: str
    has_xfo: bool
    xfo_value: Optional[str] = None
    has_csp: bool = False
    frame_ancestors: Optional[str] = None
    is_vulnerable: bool = False
    vulnerability_type: Optional[XFOVulnType] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        if self.vulnerability_type:
            data['vulnerability_type'] = self.vulnerability_type.value
        return data


class XFrameOptionsTester:
    """
    Advanced X-Frame-Options Security Tester.

    Performs comprehensive X-Frame-Options header testing including:
    - Missing header detection
    - DENY/SAMEORIGIN/ALLOW-FROM validation
    - CSP frame-ancestors alternative testing
    - Clickjacking POC generation
    - Severity-based risk assessment

    Usage:
        tester = XFrameOptionsTester(target_url="https://example.com")
        findings = tester.run_all_tests()
    """

    # Sensitive endpoints that should have frame protection
    SENSITIVE_ENDPOINTS = [
        "/login",
        "/signin",
        "/payment",
        "/checkout",
        "/transfer",
        "/admin",
        "/settings",
        "/delete",
        "/delete-account",
        "/profile/edit",
        "/account/settings",
        "/password/change",
        "/2fa/setup",
        "/oauth/authorize",
    ]

    # Valid X-Frame-Options directives
    VALID_DIRECTIVES = ["DENY", "SAMEORIGIN", "ALLOW-FROM"]

    def __init__(self, target_url: str, timeout: int = 10,
                 custom_endpoints: Optional[List[str]] = None,
                 verify_ssl: bool = True):
        """
        Initialize the X-Frame-Options Tester.

        Args:
            target_url: Target base URL
            timeout: Request timeout in seconds
            custom_endpoints: Additional custom endpoints to test
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.findings: List[XFOFinding] = []
        self.test_results: List[XFOTestResult] = []

        # Extract domain from target URL
        self.domain = self._extract_domain(target_url)

        # Build comprehensive endpoint list
        self.test_endpoints = self._build_endpoint_list(custom_endpoints or [])

        # Database integration
        self.db = BountyHoundDB() if DATABASE_AVAILABLE else None

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]

    def _build_endpoint_list(self, custom_endpoints: List[str]) -> List[str]:
        """Build comprehensive list of endpoints to test."""
        endpoints = list(self.SENSITIVE_ENDPOINTS)
        endpoints.extend(custom_endpoints)
        return list(set(endpoints))  # Remove duplicates

    def _parse_frame_ancestors(self, csp: str) -> Optional[str]:
        """
        Parse frame-ancestors directive from CSP header.

        Args:
            csp: Content-Security-Policy header value

        Returns:
            frame-ancestors value or None
        """
        if not csp:
            return None

        match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _is_secure_xfo(self, xfo_value: str) -> bool:
        """
        Check if X-Frame-Options value is secure.

        Args:
            xfo_value: X-Frame-Options header value

        Returns:
            True if secure (DENY or SAMEORIGIN), False otherwise
        """
        xfo_upper = xfo_value.upper().strip()
        return xfo_upper in ["DENY", "SAMEORIGIN"]

    def _is_secure_csp(self, frame_ancestors: str) -> bool:
        """
        Check if CSP frame-ancestors is secure.

        Args:
            frame_ancestors: frame-ancestors directive value

        Returns:
            True if secure ('none' or 'self'), False otherwise
        """
        fa_lower = frame_ancestors.lower().strip()
        return fa_lower in ["'none'", "'self'", "none", "self"]

    def _determine_severity(self, endpoint: str, has_xfo: bool, has_csp: bool) -> XFOSeverity:
        """
        Determine severity based on endpoint type and protection status.

        Args:
            endpoint: Endpoint path
            has_xfo: Whether X-Frame-Options is present
            has_csp: Whether CSP frame-ancestors is present

        Returns:
            Severity level
        """
        endpoint_lower = endpoint.lower()

        # No protection at all
        if not has_xfo and not has_csp:
            critical_patterns = ["/payment", "/transfer", "/withdraw", "/delete"]
            high_patterns = ["/login", "/signin", "/admin", "/settings", "/oauth", "/2fa"]
            medium_patterns = ["/account", "/dashboard", "/profile", "/checkout"]

            if any(pattern in endpoint_lower for pattern in critical_patterns):
                return XFOSeverity.CRITICAL
            elif any(pattern in endpoint_lower for pattern in high_patterns):
                return XFOSeverity.HIGH
            elif any(pattern in endpoint_lower for pattern in medium_patterns):
                return XFOSeverity.MEDIUM
            else:
                return XFOSeverity.LOW

        # Has CSP but no XFO (less severe)
        elif has_csp and not has_xfo:
            return XFOSeverity.LOW

        # Has XFO but deprecated ALLOW-FROM
        else:
            return XFOSeverity.MEDIUM

    def _get_impact(self, endpoint: str) -> str:
        """
        Get impact description based on endpoint.

        Args:
            endpoint: Endpoint path

        Returns:
            Impact description
        """
        endpoint_lower = endpoint.lower()

        if "payment" in endpoint_lower or "transfer" in endpoint_lower:
            return (
                "Attacker can trick users into making unauthorized payments or transfers "
                "by framing the payment page and overlaying deceptive UI elements, "
                "potentially leading to financial loss."
            )
        elif "login" in endpoint_lower or "signin" in endpoint_lower:
            return (
                "Attacker can capture credentials by framing the login page and "
                "overlaying fake UI to steal user inputs, leading to account takeover."
            )
        elif "admin" in endpoint_lower:
            return (
                "Attacker can trick administrators into performing privileged actions "
                "such as user promotion, data deletion, or configuration changes, "
                "potentially compromising the entire system."
            )
        elif "delete" in endpoint_lower:
            return (
                "Attacker can trick users into deleting their account, data, or "
                "resources by hijacking delete confirmation buttons."
            )
        elif "oauth" in endpoint_lower or "authorize" in endpoint_lower:
            return (
                "Attacker can trick users into authorizing malicious applications "
                "by hijacking OAuth consent screens, leading to account compromise."
            )
        elif "2fa" in endpoint_lower:
            return (
                "Attacker can manipulate 2FA setup/verification flows, potentially "
                "weakening or bypassing multi-factor authentication."
            )
        else:
            return (
                "Attacker can trick users into performing unintended actions by "
                "framing the vulnerable page and overlaying deceptive UI elements."
            )

    def _get_affected_actions(self, endpoint: str) -> List[str]:
        """
        Get list of affected actions based on endpoint.

        Args:
            endpoint: Endpoint path

        Returns:
            List of affected actions
        """
        endpoint_lower = endpoint.lower()
        actions = []

        if "payment" in endpoint_lower:
            actions.extend(["Make payment", "Authorize transaction", "Confirm purchase"])
        if "transfer" in endpoint_lower:
            actions.extend(["Transfer funds", "Send money", "Wire transfer"])
        if "login" in endpoint_lower or "signin" in endpoint_lower:
            actions.extend(["Submit credentials", "Login", "Authenticate"])
        if "admin" in endpoint_lower:
            actions.extend(["Grant privileges", "Modify settings", "Delete users"])
        if "delete" in endpoint_lower:
            actions.extend(["Delete account", "Remove data", "Confirm deletion"])
        if "profile" in endpoint_lower or "settings" in endpoint_lower:
            actions.extend(["Update profile", "Change email", "Modify settings"])
        if "oauth" in endpoint_lower or "authorize" in endpoint_lower:
            actions.extend(["Authorize application", "Grant permissions", "Allow access"])
        if "2fa" in endpoint_lower:
            actions.extend(["Setup 2FA", "Verify code", "Disable 2FA"])

        if not actions:
            actions = ["Click buttons", "Submit forms", "Perform actions"]

        return actions

    def _get_bounty_range(self, severity: XFOSeverity) -> Tuple[int, int]:
        """
        Get bounty estimate based on severity.

        Args:
            severity: Severity level

        Returns:
            Tuple of (min_bounty, max_bounty)
        """
        base_ranges = {
            XFOSeverity.CRITICAL: (5000, 25000),
            XFOSeverity.HIGH: (2000, 10000),
            XFOSeverity.MEDIUM: (1000, 5000),
            XFOSeverity.LOW: (500, 2000),
            XFOSeverity.INFO: (0, 500)
        }

        return base_ranges.get(severity, (500, 2000))

    def _generate_poc_html(self, target_url: str, endpoint: str,
                          finding_type: XFOVulnType) -> str:
        """
        Generate clickjacking POC HTML.

        Args:
            target_url: Full URL of vulnerable endpoint
            endpoint: Endpoint path
            finding_type: Type of vulnerability

        Returns:
            POC HTML string
        """
        poc_title = f"Clickjacking POC - {endpoint}"

        if finding_type == XFOVulnType.MISSING_BOTH:
            vulnerability_desc = "No X-Frame-Options or CSP frame-ancestors protection"
        elif finding_type == XFOVulnType.MISSING_XFO:
            vulnerability_desc = "No X-Frame-Options header (CSP frame-ancestors present)"
        elif finding_type == XFOVulnType.DEPRECATED_ALLOW_FROM:
            vulnerability_desc = "Deprecated ALLOW-FROM directive"
        else:
            vulnerability_desc = "Weak frame protection"

        poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>{poc_title}</title>
    <meta charset="UTF-8">
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
        }}

        .container {{
            position: relative;
            width: 800px;
            height: 600px;
            margin: 50px auto;
            border: 2px solid #333;
        }}

        .decoy {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
            background: white;
            text-align: center;
            padding-top: 200px;
        }}

        .decoy h1 {{
            color: #333;
            font-size: 32px;
        }}

        .decoy button {{
            background: #28a745;
            color: white;
            padding: 20px 40px;
            font-size: 24px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 50px;
        }}

        .victim-frame {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 2;
            opacity: 0.0001; /* Nearly invisible */
            border: none;
        }}

        /* Toggle opacity for testing */
        .show-frame {{
            opacity: 0.5 !important;
        }}

        .warning {{
            background: #ff4444;
            color: white;
            padding: 10px;
            text-align: center;
            font-weight: bold;
        }}

        .info {{
            margin: 20px auto;
            width: 800px;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 5px;
        }}

        .info h3 {{
            margin-top: 0;
        }}

        .info pre {{
            background: #333;
            color: #fff;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }}

        button.debug-btn {{
            background: #333;
            color: white;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
            border-radius: 3px;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="warning">
        CLICKJACKING POC - FOR SECURITY TESTING ONLY
    </div>

    <div style="text-align: center; margin: 20px;">
        <button class="debug-btn" onclick="toggleFrame()">Toggle Frame Visibility (Testing)</button>
    </div>

    <div class="container">
        <!-- Decoy content that user sees -->
        <div class="decoy">
            <h1>🎁 Win a FREE iPhone! 🎁</h1>
            <p style="font-size: 20px;">Click the button below to claim your prize!</p>
            <button>CLAIM NOW</button>
        </div>

        <!-- Victim page loaded in invisible iframe -->
        <iframe id="victim" class="victim-frame" src="{target_url}"></iframe>
    </div>

    <div class="info">
        <h3>Vulnerability Details:</h3>
        <p><strong>Endpoint:</strong> {endpoint}</p>
        <p><strong>Issue:</strong> {vulnerability_desc}</p>

        <h3>How This Attack Works:</h3>
        <ol>
            <li>The victim page ({endpoint}) is loaded in an invisible iframe</li>
            <li>A decoy page with attractive content is shown to the user</li>
            <li>When user clicks "CLAIM NOW", they actually click a button in the hidden iframe</li>
            <li>This can trigger sensitive actions like payments, account deletion, etc.</li>
        </ol>

        <h3>Remediation:</h3>
        <pre>
# Set X-Frame-Options header
X-Frame-Options: DENY

# OR for same-origin framing
X-Frame-Options: SAMEORIGIN

# AND set CSP frame-ancestors (modern approach)
Content-Security-Policy: frame-ancestors 'none';

# OR for same-origin framing
Content-Security-Policy: frame-ancestors 'self';
        </pre>

        <h3>Notes:</h3>
        <ul>
            <li>X-Frame-Options is supported by all browsers but deprecated in favor of CSP</li>
            <li>CSP frame-ancestors provides more granular control</li>
            <li>Set both headers for defense-in-depth</li>
            <li>ALLOW-FROM is deprecated and not supported in modern browsers</li>
        </ul>
    </div>

    <script>
        function toggleFrame() {{
            var frame = document.getElementById('victim');
            frame.classList.toggle('show-frame');
        }}

        // Log iframe load for testing
        document.getElementById('victim').addEventListener('load', function() {{
            console.log('[*] Victim page loaded in iframe');
        }});

        // Log iframe errors
        document.getElementById('victim').addEventListener('error', function(e) {{
            console.error('[!] Failed to load iframe:', e);
            alert('Iframe failed to load. The target may have frame protection.');
        }});
    </script>
</body>
</html>"""

        return poc

    def test_endpoint(self, endpoint: str) -> Optional[XFOFinding]:
        """
        Test a single endpoint for X-Frame-Options issues.

        Args:
            endpoint: Endpoint path to test

        Returns:
            XFOFinding if vulnerability found, None otherwise
        """
        url = urllib.parse.urljoin(self.target_url, endpoint)

        try:
            # Make request
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )

            headers = dict(response.headers)

            # Extract relevant headers
            xfo = headers.get('X-Frame-Options', '').strip()
            csp = headers.get('Content-Security-Policy', '').strip()
            frame_ancestors = self._parse_frame_ancestors(csp) if csp else None

            # Analyze protection
            has_xfo = bool(xfo)
            has_csp = bool(frame_ancestors)

            is_vulnerable = False
            vuln_type = None
            vulnerability_details = []

            # Check for missing protection
            if not has_xfo and not has_csp:
                is_vulnerable = True
                vuln_type = XFOVulnType.MISSING_BOTH
                vulnerability_details.append("No X-Frame-Options header")
                vulnerability_details.append("No CSP frame-ancestors directive")

            # Check for deprecated ALLOW-FROM
            elif xfo.upper().startswith("ALLOW-FROM"):
                is_vulnerable = True
                vuln_type = XFOVulnType.DEPRECATED_ALLOW_FROM
                vulnerability_details.append(f"Deprecated ALLOW-FROM directive: {xfo}")
                vulnerability_details.append("ALLOW-FROM is not supported in modern browsers")

            # Check for weak protection
            elif has_xfo and not self._is_secure_xfo(xfo):
                is_vulnerable = True
                vuln_type = XFOVulnType.INVALID_DIRECTIVE
                vulnerability_details.append(f"Invalid X-Frame-Options value: {xfo}")

            # Check for conflicting headers
            elif has_xfo and has_csp:
                # CSP frame-ancestors takes precedence
                if not self._is_secure_csp(frame_ancestors):
                    is_vulnerable = True
                    vuln_type = XFOVulnType.WEAK_PROTECTION
                    vulnerability_details.append(f"Weak CSP frame-ancestors: {frame_ancestors}")

            # Check for only CSP (informational)
            elif has_csp and not has_xfo:
                # CSP is sufficient but missing XFO for defense-in-depth
                is_vulnerable = True
                vuln_type = XFOVulnType.MISSING_XFO
                vulnerability_details.append("X-Frame-Options header missing")
                vulnerability_details.append(f"Only CSP frame-ancestors present: {frame_ancestors}")

            # Store test result
            test_result = XFOTestResult(
                endpoint=endpoint,
                url=url,
                has_xfo=has_xfo,
                xfo_value=xfo if has_xfo else None,
                has_csp=has_csp,
                frame_ancestors=frame_ancestors,
                is_vulnerable=is_vulnerable,
                vulnerability_type=vuln_type,
                details={
                    'status_code': response.status_code,
                    'vulnerabilities': vulnerability_details
                }
            )
            self.test_results.append(test_result)

            # Create finding if vulnerable
            if is_vulnerable:
                severity = self._determine_severity(endpoint, has_xfo, has_csp)
                poc_html = self._generate_poc_html(url, endpoint, vuln_type)

                finding = XFOFinding(
                    title=f"Clickjacking via {vuln_type.value}: {endpoint}",
                    severity=severity,
                    vuln_type=vuln_type,
                    description=(
                        f"Endpoint {endpoint} lacks proper frame protection. "
                        f"Vulnerabilities: {', '.join(vulnerability_details)}"
                    ),
                    endpoint=endpoint,
                    url=url,
                    xfo_header=xfo if has_xfo else None,
                    csp_header=csp if csp else None,
                    frame_ancestors=frame_ancestors,
                    response_headers=headers,
                    poc_html=poc_html,
                    impact=self._get_impact(endpoint),
                    exploitation_steps=[
                        "1. Create malicious HTML page with iframe",
                        f"2. Load vulnerable page in iframe: {url}",
                        "3. Overlay transparent/opaque layer over iframe",
                        "4. Position decoy UI elements to align with target buttons",
                        "5. Trick user into clicking hijacked element",
                        "6. User performs unintended action (payment, delete, etc.)"
                    ],
                    affected_actions=self._get_affected_actions(endpoint),
                    bounty_estimate=self._get_bounty_range(severity),
                    recommendation=self._get_recommendation(vuln_type, has_csp),
                    cwe_id="CWE-1021"
                )

                return finding

        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing {url}: {e}")

        return None

    def _get_recommendation(self, vuln_type: XFOVulnType, has_csp: bool) -> str:
        """
        Get remediation recommendation based on vulnerability type.

        Args:
            vuln_type: Type of vulnerability
            has_csp: Whether CSP frame-ancestors is present

        Returns:
            Recommendation string
        """
        if vuln_type == XFOVulnType.MISSING_BOTH:
            return """Implement proper frame protection headers:

1. Set X-Frame-Options header:
   X-Frame-Options: DENY
   (or SAMEORIGIN if same-origin framing is needed)

2. Set Content-Security-Policy frame-ancestors:
   Content-Security-Policy: frame-ancestors 'none';
   (or frame-ancestors 'self' for same-origin framing)

3. Set BOTH headers for defense-in-depth and compatibility

4. For modern applications, CSP frame-ancestors is preferred

Example Apache configuration:
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'none';"

Example Nginx configuration:
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none';" always;"""

        elif vuln_type == XFOVulnType.DEPRECATED_ALLOW_FROM:
            return """Replace deprecated ALLOW-FROM directive:

1. Remove X-Frame-Options: ALLOW-FROM (not supported in modern browsers)

2. Use CSP frame-ancestors instead:
   Content-Security-Policy: frame-ancestors https://trusted-domain.com;

3. For multiple trusted domains:
   Content-Security-Policy: frame-ancestors https://domain1.com https://domain2.com;

4. Keep X-Frame-Options: SAMEORIGIN for legacy browser support:
   X-Frame-Options: SAMEORIGIN
   Content-Security-Policy: frame-ancestors 'self' https://trusted-domain.com;"""

        elif vuln_type == XFOVulnType.MISSING_XFO:
            return """Add X-Frame-Options for defense-in-depth:

Current: Only CSP frame-ancestors is set
Recommended: Add X-Frame-Options for maximum compatibility

1. Set X-Frame-Options header:
   X-Frame-Options: DENY

2. Keep existing CSP frame-ancestors

Both headers provide defense-in-depth:
- X-Frame-Options: Supported by all browsers (legacy support)
- CSP frame-ancestors: Modern standard with more granular control

Example:
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';"""

        else:
            return """Fix frame protection configuration:

1. Ensure X-Frame-Options is set to DENY or SAMEORIGIN
2. Ensure CSP frame-ancestors is set to 'none' or 'self'
3. Verify both headers are present
4. Test that headers are not being stripped by proxies/CDN"""

    def run_all_tests(self, check_database: bool = True) -> List[XFOFinding]:
        """
        Run X-Frame-Options tests on all endpoints.

        Args:
            check_database: Whether to check database before testing

        Returns:
            List of findings
        """
        print(f"[*] Starting X-Frame-Options Security Scan")
        print(f"[*] Target: {self.target_url}")

        # Database check
        if check_database and self.db:
            context = DatabaseHooks.before_test(self.domain, 'x_frame_options_tester')

            if context['should_skip']:
                print(f"[!] {context['reason']}")
                print(f"[!] Previous findings: {len(context['previous_findings'])}")
                print(f"[!] Recommendations: {', '.join(context['recommendations'])}")

                user_input = input("Continue anyway? (y/N): ").strip().lower()
                if user_input != 'y':
                    print("[*] Skipping test")
                    return []

        print(f"[*] Testing {len(self.test_endpoints)} endpoints...")

        for endpoint in self.test_endpoints:
            print(f"[*] Testing: {endpoint}")
            finding = self.test_endpoint(endpoint)

            if finding:
                self.findings.append(finding)
                print(f"    [+] VULNERABLE: {finding.severity.value} - {finding.vuln_type.value}")
            else:
                print(f"    [✓] Protected")

        # Record test in database
        if self.db:
            self.db.record_tool_run(
                domain=self.domain,
                tool_name='x_frame_options_tester',
                findings_count=len(self.findings),
                duration_seconds=0  # TODO: Track actual duration
            )

        print(f"\n[*] Scan complete. Found {len(self.findings)} vulnerabilities.")

        return self.findings

    def generate_report(self, output_file: str = "xfo_report.json") -> Dict[str, Any]:
        """
        Generate detailed vulnerability report.

        Args:
            output_file: Output file path

        Returns:
            Report dictionary
        """
        report = {
            "scan_info": {
                "target": self.target_url,
                "domain": self.domain,
                "total_findings": len(self.findings),
                "total_endpoints_tested": len(self.test_results),
                "scan_date": date.today().isoformat()
            },
            "summary": {
                "critical": sum(1 for f in self.findings if f.severity == XFOSeverity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == XFOSeverity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == XFOSeverity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == XFOSeverity.LOW),
                "info": sum(1 for f in self.findings if f.severity == XFOSeverity.INFO)
            },
            "findings": [f.to_dict() for f in self.findings],
            "test_results": [r.to_dict() for r in self.test_results]
        }

        # Save to file
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[*] Report saved to: {output_file}")
        print(f"[*] Total findings: {len(self.findings)}")
        print(f"[*] Severity breakdown: {report['summary']}")

        # Save POC files
        for i, finding in enumerate(self.findings):
            poc_filename = f"poc_xfo_{i+1}_{finding.endpoint.replace('/', '_')}.html"
            with open(poc_filename, 'w') as f:
                f.write(finding.poc_html)
            print(f"[*] POC saved: {poc_filename}")

        return report


def main():
    """Main execution function for standalone testing."""
    import argparse

    parser = argparse.ArgumentParser(description="X-Frame-Options Security Tester")
    parser.add_argument("target", help="Target base URL (e.g., https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--endpoints", nargs="+", help="Additional endpoints to test")
    parser.add_argument("--output", default="xfo_report.json", help="Output report file")
    parser.add_argument("--no-db-check", action="store_true", help="Skip database check")

    args = parser.parse_args()

    tester = XFrameOptionsTester(
        target_url=args.target,
        timeout=args.timeout,
        custom_endpoints=args.endpoints or [],
        verify_ssl=not args.no_verify
    )

    findings = tester.run_all_tests(check_database=not args.no_db_check)
    tester.generate_report(output_file=args.output)

    return 0 if not findings else 1


if __name__ == "__main__":
    exit(main())
