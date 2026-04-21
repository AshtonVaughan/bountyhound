"""
HSTS (HTTP Strict Transport Security) Analyzer Agent

Specialized agent for analyzing HSTS header configuration and identifying security
weaknesses that can lead to SSL stripping and man-in-the-middle attacks.

This agent tests for:
- Missing HSTS header
- Insufficient max-age directive (minimum 6 months recommended)
- Missing includeSubDomains directive
- Missing preload directive for critical domains
- HTTP to HTTPS redirect validation
- HSTS header on HTTP responses (ineffective)
- HSTS on non-HTTPS endpoints

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from urllib.parse import urlparse


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class HSTSSeverity(Enum):
    """HSTS vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class HSTSVulnType(Enum):
    """Types of HSTS vulnerabilities."""
    MISSING_HSTS = "HSTS_MISSING"
    WEAK_MAX_AGE = "HSTS_WEAK_MAX_AGE"
    MISSING_INCLUDE_SUBDOMAINS = "HSTS_MISSING_INCLUDE_SUBDOMAINS"
    MISSING_PRELOAD = "HSTS_MISSING_PRELOAD"
    NO_HTTPS_REDIRECT = "HSTS_NO_HTTPS_REDIRECT"
    HSTS_ON_HTTP = "HSTS_ON_HTTP"
    INVALID_SYNTAX = "HSTS_INVALID_SYNTAX"


@dataclass
class HSTSFinding:
    """Represents an HSTS security finding."""
    title: str
    severity: HSTSSeverity
    vuln_type: HSTSVulnType
    description: str
    endpoint: str
    current_value: Optional[str] = None
    expected_value: str = ""
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = "CWE-523"  # Unprotected Transport of Credentials
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class HSTSConfig:
    """Parsed HSTS configuration."""
    present: bool = False
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    raw_header: Optional[str] = None
    is_valid: bool = False
    parse_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)


class HSTSAnalyzer:
    """
    HSTS Security Analyzer.

    Performs comprehensive HSTS configuration analysis including:
    - Header presence detection
    - max-age directive validation (minimum 6 months = 15768000 seconds)
    - includeSubDomains directive checking
    - preload directive validation
    - HTTP to HTTPS redirect testing
    - HSTS header on HTTP responses detection

    Usage:
        analyzer = HSTSAnalyzer(target_url="https://example.com")
        findings = analyzer.run_all_tests()
    """

    # Minimum max-age in seconds (6 months = 15768000, but 1 year = 31536000 is recommended)
    MIN_MAX_AGE_RECOMMENDED = 31536000  # 1 year
    MIN_MAX_AGE_ACCEPTABLE = 15768000   # 6 months

    def __init__(self, target_url: str, timeout: int = 10,
                 verify_ssl: bool = True,
                 user_agent: Optional[str] = None):
        """
        Initialize HSTS Analyzer.

        Args:
            target_url: Target URL to analyze
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom user agent string
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required for HSTSAnalyzer")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.domain = self._extract_domain(target_url)
        self.findings: List[HSTSFinding] = []

        # Setup session
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })

        # Suppress SSL warnings if verification is disabled
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc

    def run_all_tests(self) -> List[HSTSFinding]:
        """
        Run all HSTS security tests.

        Returns:
            List of HSTS security findings
        """
        print(f"[*] Starting HSTS analysis for {self.target_url}")

        # Test HTTPS endpoint
        self._test_hsts_on_https()

        # Test HTTP endpoint if domain supports HTTPS
        if self.target_url.startswith('https://'):
            self._test_http_redirect()
            self._test_hsts_on_http()

        print(f"[*] HSTS analysis complete. Found {len(self.findings)} issues.")
        return self.findings

    def _test_hsts_on_https(self) -> None:
        """Test HSTS header configuration on HTTPS endpoint."""
        print(f"[*] Testing HSTS header on HTTPS endpoint...")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)

            # Parse HSTS header
            hsts_config = self._parse_hsts_header(response)

            # Store in metadata for reporting
            metadata = {
                'hsts_config': hsts_config.to_dict(),
                'status_code': response.status_code,
                'url': response.url
            }

            # Check for missing HSTS
            if not hsts_config.present:
                self._add_missing_hsts_finding(metadata)
            elif not hsts_config.is_valid:
                self._add_invalid_hsts_finding(hsts_config, metadata)
            else:
                # Check individual directives
                self._check_max_age(hsts_config, metadata)
                self._check_include_subdomains(hsts_config, metadata)
                self._check_preload(hsts_config, metadata)

        except requests.exceptions.SSLError as e:
            print(f"[!] SSL error: {e}")
            self.findings.append(HSTSFinding(
                title="SSL/TLS Error - Cannot Test HSTS",
                severity=HSTSSeverity.HIGH,
                vuln_type=HSTSVulnType.MISSING_HSTS,
                description=f"SSL/TLS error prevented HSTS testing: {str(e)}",
                endpoint=self.target_url,
                impact="Cannot verify HSTS protection due to SSL errors. Site may be vulnerable to SSL stripping attacks.",
                recommendation="Fix SSL/TLS configuration first, then implement HSTS.",
                metadata={'error': str(e)}
            ))
        except Exception as e:
            print(f"[!] Error testing HSTS on HTTPS: {e}")

    def _test_http_redirect(self) -> None:
        """Test if HTTP redirects to HTTPS."""
        print(f"[*] Testing HTTP to HTTPS redirect...")

        http_url = self.target_url.replace('https://', 'http://')

        try:
            # Don't follow redirects initially
            response = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)

            # Check if redirects to HTTPS
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')

                if not location.startswith('https://'):
                    self.findings.append(HSTSFinding(
                        title="HTTP Does Not Redirect to HTTPS",
                        severity=HSTSSeverity.HIGH,
                        vuln_type=HSTSVulnType.NO_HTTPS_REDIRECT,
                        description=f"HTTP endpoint returns {response.status_code} redirect but not to HTTPS",
                        endpoint=http_url,
                        current_value=f"Location: {location}",
                        expected_value="Location: https://... (with 301 or 308 permanent redirect)",
                        impact="Users accessing via HTTP are not automatically upgraded to HTTPS, vulnerable to SSL stripping attacks.",
                        poc=f"""
1. Visit HTTP version of site: {http_url}
2. Observe redirect to: {location}
3. Connection remains unencrypted or redirects to wrong location
4. Attacker can intercept plaintext traffic

Test command:
curl -I {http_url}
""",
                        recommendation="Configure server to redirect all HTTP requests to HTTPS with 301 or 308 status code.",
                        metadata={'status_code': response.status_code, 'location': location}
                    ))
                elif response.status_code not in [301, 308]:
                    # Temporary redirect instead of permanent
                    self.findings.append(HSTSFinding(
                        title="HTTP Uses Temporary Redirect to HTTPS",
                        severity=HSTSSeverity.MEDIUM,
                        vuln_type=HSTSVulnType.NO_HTTPS_REDIRECT,
                        description=f"HTTP endpoint uses {response.status_code} (temporary) instead of 301/308 (permanent) redirect",
                        endpoint=http_url,
                        current_value=f"HTTP {response.status_code} -> {location}",
                        expected_value="HTTP 301 or 308 -> https://...",
                        impact="Temporary redirects are not cached by browsers, requiring redirect on every visit. Less effective than permanent redirects.",
                        recommendation="Change redirect to 301 (Moved Permanently) or 308 (Permanent Redirect) for better security and performance.",
                        metadata={'status_code': response.status_code, 'location': location}
                    ))
            else:
                # No redirect at all
                self.findings.append(HSTSFinding(
                    title="HTTP Does Not Redirect to HTTPS",
                    severity=HSTSSeverity.HIGH,
                    vuln_type=HSTSVulnType.NO_HTTPS_REDIRECT,
                    description=f"HTTP endpoint returns {response.status_code} without redirecting to HTTPS",
                    endpoint=http_url,
                    current_value=f"HTTP {response.status_code} (no redirect)",
                    expected_value="HTTP 301 or 308 -> https://...",
                    impact="Site accessible via unencrypted HTTP. All traffic can be intercepted, modified, and credentials stolen.",
                    poc=f"""
1. Visit: {http_url}
2. Site loads over unencrypted HTTP
3. Attacker can:
   - View all traffic in plaintext
   - Steal credentials
   - Inject malicious content
   - Perform SSL stripping attacks

Test command:
curl -I {http_url}

Attack tool:
sslstrip -l 8080
""",
                    recommendation="Configure server to redirect all HTTP requests to HTTPS with 301 or 308 status code.",
                    cwe_id="CWE-319: Cleartext Transmission of Sensitive Information",
                    metadata={'status_code': response.status_code}
                ))

        except requests.exceptions.ConnectionError:
            # HTTP not accessible (good - server only listens on HTTPS)
            print(f"[+] HTTP endpoint not accessible (expected if server only listens on HTTPS)")
        except Exception as e:
            print(f"[!] Error testing HTTP redirect: {e}")

    def _test_hsts_on_http(self) -> None:
        """Test if HSTS header is present on HTTP endpoint (ineffective)."""
        print(f"[*] Testing for HSTS header on HTTP endpoint (should not be present)...")

        http_url = self.target_url.replace('https://', 'http://')

        try:
            response = self.session.get(http_url, timeout=self.timeout)

            hsts_header = response.headers.get('Strict-Transport-Security')
            if hsts_header:
                self.findings.append(HSTSFinding(
                    title="HSTS Header Sent Over HTTP (Ineffective)",
                    severity=HSTSSeverity.LOW,
                    vuln_type=HSTSVulnType.HSTS_ON_HTTP,
                    description="HSTS header is present on HTTP response, but browsers ignore HSTS over HTTP",
                    endpoint=http_url,
                    current_value=f"Strict-Transport-Security: {hsts_header} (over HTTP)",
                    expected_value="HSTS should only be sent over HTTPS connections",
                    impact="HSTS header is ignored by browsers when sent over HTTP. Provides false sense of security.",
                    poc=f"""
1. Request HTTP endpoint: {http_url}
2. Observe HSTS header in response
3. Browsers will ignore this header (per RFC 6797)
4. No HSTS protection is actually applied

Test command:
curl -I {http_url} | grep -i strict-transport-security
""",
                    recommendation="Remove HSTS header from HTTP responses. Only send HSTS over HTTPS. Redirect HTTP to HTTPS first.",
                    metadata={'hsts_header': hsts_header}
                ))

        except requests.exceptions.ConnectionError:
            # HTTP not accessible (good)
            pass
        except Exception as e:
            print(f"[!] Error testing HSTS on HTTP: {e}")

    def _parse_hsts_header(self, response: requests.Response) -> HSTSConfig:
        """
        Parse HSTS header from response.

        Args:
            response: HTTP response object

        Returns:
            HSTSConfig object with parsed configuration
        """
        config = HSTSConfig()

        hsts_header = response.headers.get('Strict-Transport-Security')
        if not hsts_header:
            return config

        config.present = True
        config.raw_header = hsts_header

        # Parse directives
        directives = [d.strip().lower() for d in hsts_header.split(';')]

        for directive in directives:
            if directive.startswith('max-age'):
                # Extract max-age value
                match = re.search(r'max-age\s*=\s*(\d+)', directive)
                if match:
                    try:
                        config.max_age = int(match.group(1))
                    except ValueError:
                        config.parse_errors.append(f"Invalid max-age value: {match.group(1)}")
                else:
                    config.parse_errors.append("max-age directive present but no value found")

            elif directive == 'includesubdomains':
                config.include_subdomains = True

            elif directive == 'preload':
                config.preload = True

        # Validate configuration
        if config.max_age is not None and not config.parse_errors:
            config.is_valid = True
        elif config.max_age is None:
            config.parse_errors.append("max-age directive is required but missing")

        return config

    def _add_missing_hsts_finding(self, metadata: Dict[str, Any]) -> None:
        """Add finding for missing HSTS header."""
        self.findings.append(HSTSFinding(
            title="Missing HSTS Header",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.MISSING_HSTS,
            description="The Strict-Transport-Security header is not present in the HTTPS response",
            endpoint=self.target_url,
            current_value=None,
            expected_value="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            impact="Site is vulnerable to SSL stripping attacks. Attackers can downgrade HTTPS connections to HTTP and intercept sensitive data.",
            poc=f"""
SSL Stripping Attack:
1. Victim visits site over HTTP first (or via MitM)
2. Attacker intercepts initial request
3. Attacker establishes HTTPS to real server
4. Attacker serves HTTP to victim (strips SSL)
5. Victim's browser accepts HTTP connection (no HSTS)
6. All traffic visible to attacker in plaintext

Attack tools:
- sslstrip: python sslstrip.py -l 8080
- mitmproxy: mitmproxy --mode transparent
- bettercap: set http.proxy.sslstrip true

Test command:
curl -I {self.target_url} | grep -i strict-transport-security

Prevention:
Add HSTS header to force HTTPS for specified duration.
""",
            recommendation="""
1. Add Strict-Transport-Security header to all HTTPS responses
2. Set max-age to at least 31536000 seconds (1 year)
3. Include includeSubDomains directive to protect all subdomains
4. Consider adding preload directive and submitting to HSTS preload list
5. Ensure all HTTP requests redirect to HTTPS with 301/308

Example configurations:

Apache:
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

Nginx:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

Node.js (Express + Helmet):
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))
""",
            cwe_id="CWE-523: Unprotected Transport of Credentials",
            metadata=metadata
        ))

    def _add_invalid_hsts_finding(self, config: HSTSConfig, metadata: Dict[str, Any]) -> None:
        """Add finding for invalid HSTS syntax."""
        self.findings.append(HSTSFinding(
            title="Invalid HSTS Header Syntax",
            severity=HSTSSeverity.HIGH,
            vuln_type=HSTSVulnType.INVALID_SYNTAX,
            description=f"HSTS header has invalid syntax: {'; '.join(config.parse_errors)}",
            endpoint=self.target_url,
            current_value=config.raw_header,
            expected_value="Strict-Transport-Security: max-age=<seconds>; includeSubDomains; preload",
            impact="Invalid HSTS header may be ignored by browsers, providing no protection against SSL stripping attacks.",
            poc=f"""
Current header: {config.raw_header}
Errors: {'; '.join(config.parse_errors)}

Test:
curl -I {self.target_url} | grep -i strict-transport-security
""",
            recommendation="Fix HSTS header syntax. The header must include a valid max-age directive with a numeric value in seconds.",
            metadata=metadata
        ))

    def _check_max_age(self, config: HSTSConfig, metadata: Dict[str, Any]) -> None:
        """Check max-age directive."""
        if config.max_age is None:
            return

        if config.max_age < self.MIN_MAX_AGE_ACCEPTABLE:
            # Less than 6 months - MEDIUM severity
            self.findings.append(HSTSFinding(
                title="HSTS max-age Too Short",
                severity=HSTSSeverity.MEDIUM,
                vuln_type=HSTSVulnType.WEAK_MAX_AGE,
                description=f"HSTS max-age is {config.max_age} seconds ({config.max_age / 86400:.1f} days), which is below the recommended minimum of 6 months",
                endpoint=self.target_url,
                current_value=f"max-age={config.max_age} ({config.max_age / 86400:.1f} days)",
                expected_value=f"max-age={self.MIN_MAX_AGE_RECOMMENDED} (1 year) or at least {self.MIN_MAX_AGE_ACCEPTABLE} (6 months)",
                impact=f"HSTS protection expires after {config.max_age / 86400:.1f} days. After expiration, users are vulnerable to SSL stripping attacks until they revisit the site.",
                poc=f"""
Current HSTS duration: {config.max_age / 86400:.1f} days

Attack scenario:
1. User visits site, HSTS policy cached for {config.max_age / 86400:.1f} days
2. User doesn't visit site for {config.max_age / 86400:.1f}+ days
3. HSTS policy expires from browser cache
4. User's next visit vulnerable to SSL stripping
5. Attacker intercepts first request over HTTP

Recommendation:
Increase max-age to at least 31536000 seconds (1 year)

Test current value:
curl -I {self.target_url} | grep -i strict-transport-security
""",
                recommendation=f"Increase max-age to at least {self.MIN_MAX_AGE_RECOMMENDED} seconds (1 year). Common practice is 1-2 years for production sites.",
                metadata=metadata
            ))
        elif config.max_age < self.MIN_MAX_AGE_RECOMMENDED:
            # Between 6 months and 1 year - LOW severity (acceptable but not optimal)
            self.findings.append(HSTSFinding(
                title="HSTS max-age Below Best Practice",
                severity=HSTSSeverity.LOW,
                vuln_type=HSTSVulnType.WEAK_MAX_AGE,
                description=f"HSTS max-age is {config.max_age} seconds ({config.max_age / 86400:.1f} days), which is acceptable but below the recommended 1 year",
                endpoint=self.target_url,
                current_value=f"max-age={config.max_age} ({config.max_age / 86400:.1f} days)",
                expected_value=f"max-age={self.MIN_MAX_AGE_RECOMMENDED} (1 year)",
                impact="HSTS protection is adequate but shorter than industry best practice. Consider increasing for better long-term protection.",
                recommendation=f"Increase max-age to {self.MIN_MAX_AGE_RECOMMENDED} seconds (1 year) to match industry best practices and HSTS preload requirements.",
                metadata=metadata
            ))

    def _check_include_subdomains(self, config: HSTSConfig, metadata: Dict[str, Any]) -> None:
        """Check includeSubDomains directive."""
        if not config.include_subdomains:
            self.findings.append(HSTSFinding(
                title="HSTS Missing includeSubDomains Directive",
                severity=HSTSSeverity.MEDIUM,
                vuln_type=HSTSVulnType.MISSING_INCLUDE_SUBDOMAINS,
                description="HSTS header does not include the includeSubDomains directive",
                endpoint=self.target_url,
                current_value=config.raw_header,
                expected_value=f"{config.raw_header}; includeSubDomains",
                impact="Subdomains are not protected by HSTS policy. Attackers can target subdomains with SSL stripping attacks even if main domain is protected.",
                poc=f"""
Attack scenario:
1. Main domain {self.domain} has HSTS (without includeSubDomains)
2. Subdomain api.{self.domain} does not inherit HSTS
3. Attacker targets subdomain with SSL stripping
4. Victim visits http://api.{self.domain}
5. Attacker intercepts plaintext traffic to subdomain

Example vulnerable subdomains:
- api.{self.domain}
- admin.{self.domain}
- staging.{self.domain}

Test:
# Check main domain
curl -I {self.target_url} | grep -i strict-transport-security

# Check subdomain (if exists)
curl -I https://api.{self.domain} | grep -i strict-transport-security
""",
                recommendation="""
Add includeSubDomains directive to HSTS header.

IMPORTANT: Before enabling includeSubDomains:
1. Ensure ALL subdomains support HTTPS
2. Test that all subdomains have valid SSL certificates
3. Verify no subdomains need HTTP access

Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
""",
                metadata=metadata
            ))

    def _check_preload(self, config: HSTSConfig, metadata: Dict[str, Any]) -> None:
        """Check preload directive."""
        # Only check for preload on top-level domains (not subdomains)
        domain_parts = self.domain.split('.')
        if len(domain_parts) > 2:
            # This is a subdomain, skip preload check
            return

        if not config.preload:
            self.findings.append(HSTSFinding(
                title="HSTS Missing preload Directive",
                severity=HSTSSeverity.LOW,
                vuln_type=HSTSVulnType.MISSING_PRELOAD,
                description="HSTS header does not include the preload directive (for submission to browser HSTS preload list)",
                endpoint=self.target_url,
                current_value=config.raw_header,
                expected_value=f"{config.raw_header}; preload",
                impact="Domain is not eligible for HSTS preload list. First-time visitors are vulnerable to SSL stripping attacks before HSTS header is received.",
                poc=f"""
First-visit vulnerability:
1. User has never visited {self.domain}
2. User types {self.domain} in browser (defaults to HTTP)
3. First request goes over HTTP
4. Attacker can intercept this first request (SSL stripping)
5. Only after receiving HTTPS response is HSTS cached

With HSTS preload:
1. Browser has hardcoded HSTS policy before first visit
2. Browser automatically uses HTTPS for first request
3. No SSL stripping opportunity

Check preload status:
https://hstspreload.org/?domain={self.domain}

Test:
curl -I {self.target_url} | grep -i strict-transport-security
""",
                recommendation=f"""
To enable HSTS preload:

1. Add preload directive to HSTS header:
   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

2. Ensure requirements are met:
   - Valid HTTPS certificate
   - All subdomains support HTTPS (or use includeSubDomains)
   - max-age >= 31536000 (1 year)
   - includeSubDomains directive present
   - preload directive present

3. Submit domain to HSTS preload list:
   https://hstspreload.org/

4. Wait for inclusion in browser preload lists (can take weeks)

WARNING: HSTS preload is difficult to undo. Removing from preload list can take months.
Only enable if you're certain all subdomains will permanently support HTTPS.
""",
                metadata=metadata
            ))

    def generate_report(self) -> str:
        """
        Generate comprehensive HSTS security report.

        Returns:
            Markdown formatted report
        """
        if not self.findings:
            return f"""
# HSTS Security Analysis Report

## Target: {self.target_url}
## Status: ✅ SECURE

No HSTS security issues found. The site properly implements HTTP Strict Transport Security.
"""

        # Group findings by severity
        by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }

        for finding in self.findings:
            by_severity[finding.severity.value].append(finding)

        report = f"""
# HSTS Security Analysis Report

## Target: {self.target_url}
## Domain: {self.domain}
## Analysis Date: {date.today().isoformat()}
## Total Findings: {len(self.findings)}

"""

        # Summary
        report += "## Summary\n\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = len(by_severity[severity])
            if count > 0:
                report += f"- **{severity}**: {count} issue(s)\n"

        report += "\n---\n"

        # Detailed findings
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            findings = by_severity[severity]
            if not findings:
                continue

            report += f"\n## {severity} Severity ({len(findings)})\n\n"

            for i, finding in enumerate(findings, 1):
                report += f"""
### {severity}-{i}: {finding.title}

**Vulnerability Type**: `{finding.vuln_type.value}`
**Endpoint**: `{finding.endpoint}`
**CWE**: {finding.cwe_id}

**Current Configuration**:
```
{finding.current_value or 'Not present'}
```

**Expected Configuration**:
```
{finding.expected_value}
```

**Description**:
{finding.description}

**Impact**:
{finding.impact}

**Proof of Concept**:
```
{finding.poc}
```

**Recommendation**:
{finding.recommendation}

---
"""

        # Add remediation summary
        report += self._generate_remediation_summary(by_severity)

        return report

    def _generate_remediation_summary(self, by_severity: Dict[str, List[HSTSFinding]]) -> str:
        """Generate prioritized remediation recommendations."""
        summary = "\n## Remediation Summary\n\n"

        # Immediate actions
        critical_high = by_severity['CRITICAL'] + by_severity['HIGH']
        if critical_high:
            summary += "### Immediate Action Required (Critical/High)\n\n"
            for finding in critical_high:
                summary += f"- **{finding.title}**: {finding.recommendation.split('.')[0]}.\n"

        # Short-term fixes
        if by_severity['MEDIUM']:
            summary += "\n### Short-term Fixes (Medium)\n\n"
            for finding in by_severity['MEDIUM']:
                summary += f"- **{finding.title}**: {finding.recommendation.split('.')[0]}.\n"

        # Long-term improvements
        if by_severity['LOW'] or by_severity['INFO']:
            summary += "\n### Long-term Improvements (Low/Info)\n\n"
            for finding in by_severity['LOW'] + by_severity['INFO']:
                summary += f"- **{finding.title}**: {finding.recommendation.split('.')[0]}.\n"

        # Configuration examples
        summary += """
## Recommended HSTS Configuration

### Apache (.htaccess or VirtualHost)
```apache
# Require HTTPS
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Add HSTS header
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

### Nginx
```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # HSTS header
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

### Node.js (Express + Helmet)
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Enable HSTS
app.use(helmet.hsts({
  maxAge: 31536000,      // 1 year in seconds
  includeSubDomains: true,
  preload: true
}));

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});
```

### Python (Django)
```python
# settings.py

# Redirect HTTP to HTTPS
SECURE_SSL_REDIRECT = True

# HSTS settings
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### Python (Flask)
```python
from flask import Flask, redirect, request
from flask_talisman import Talisman

app = Flask(__name__)

# Enable HSTS with Talisman
Talisman(app, force_https=True, strict_transport_security=True,
         strict_transport_security_max_age=31536000,
         strict_transport_security_include_subdomains=True,
         strict_transport_security_preload=True)

@app.before_request
def redirect_to_https():
    if not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'), code=301)
```

## Testing Your HSTS Configuration

### Command-line tests
```bash
# Check HSTS header on HTTPS
curl -I https://example.com | grep -i strict-transport-security

# Check HTTP to HTTPS redirect
curl -I http://example.com

# Detailed header inspection
curl -v https://example.com 2>&1 | grep -i strict-transport-security
```

### Online tools
- [Security Headers](https://securityheaders.com/)
- [HSTS Preload](https://hstspreload.org/)
- [SSL Labs](https://www.ssllabs.com/ssltest/)
- [Mozilla Observatory](https://observatory.mozilla.org/)

## References

- [RFC 6797 - HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)
- [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [Chrome HSTS Preload List](https://hstspreload.org/)
- [MDN Web Docs - Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [CWE-523: Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

"""

        return summary

    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get a summary of findings.

        Returns:
            Dictionary with findings statistics
        """
        summary = {
            'total_findings': len(self.findings),
            'by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            },
            'by_type': {},
            'endpoints_tested': [self.target_url]
        }

        for finding in self.findings:
            summary['by_severity'][finding.severity.value] += 1

            vuln_type = finding.vuln_type.value
            if vuln_type not in summary['by_type']:
                summary['by_type'][vuln_type] = 0
            summary['by_type'][vuln_type] += 1

        return summary


# Example usage and CLI interface
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python hsts_analyzer.py <target_url>")
        print("Example: python hsts_analyzer.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]

    # Ensure URL has scheme
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'

    print(f"\n{'='*70}")
    print(f"HSTS Security Analyzer v1.0.0")
    print(f"{'='*70}\n")

    # Run analysis
    analyzer = HSTSAnalyzer(target_url=target, verify_ssl=False)
    findings = analyzer.run_all_tests()

    # Generate and print report
    report = analyzer.generate_report()
    print(report)

    # Print summary
    summary = analyzer.get_findings_summary()
    print(f"\n{'='*70}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*70}")
    print(f"Total Issues: {summary['total_findings']}")
    print(f"Critical: {summary['by_severity']['CRITICAL']}")
    print(f"High: {summary['by_severity']['HIGH']}")
    print(f"Medium: {summary['by_severity']['MEDIUM']}")
    print(f"Low: {summary['by_severity']['LOW']}")
    print(f"{'='*70}\n")
