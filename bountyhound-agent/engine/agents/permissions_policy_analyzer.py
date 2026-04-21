"""
Permissions-Policy Security Analyzer Agent

Analyzes Permissions-Policy (formerly Feature-Policy) headers to identify
misconfigurations and security vulnerabilities that could allow abuse of
powerful browser features.

This agent tests for:
- Missing Permissions-Policy headers
- Dangerous permissions with wildcard (*) access
- Missing restrictive policies for sensitive features
- Permissive allowlists
- Feature-Policy to Permissions-Policy migration issues
- Camera, microphone, geolocation exposure
- Payment API abuse risks
- USB, Bluetooth, and other powerful feature access

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from urllib.parse import urlparse


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class PermissionsSeverity(Enum):
    """Permissions-Policy vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PermissionsVulnType(Enum):
    """Types of Permissions-Policy vulnerabilities."""
    MISSING_POLICY = "PERMISSIONS_POLICY_MISSING"
    WILDCARD_DANGEROUS = "PERMISSIONS_POLICY_WILDCARD_DANGEROUS"
    CAMERA_EXPOSED = "PERMISSIONS_POLICY_CAMERA_EXPOSED"
    MICROPHONE_EXPOSED = "PERMISSIONS_POLICY_MICROPHONE_EXPOSED"
    GEOLOCATION_EXPOSED = "PERMISSIONS_POLICY_GEOLOCATION_EXPOSED"
    PAYMENT_EXPOSED = "PERMISSIONS_POLICY_PAYMENT_EXPOSED"
    USB_EXPOSED = "PERMISSIONS_POLICY_USB_EXPOSED"
    BLUETOOTH_EXPOSED = "PERMISSIONS_POLICY_BLUETOOTH_EXPOSED"
    LEGACY_FEATURE_POLICY = "PERMISSIONS_POLICY_LEGACY_HEADER"
    PERMISSIVE_ALLOWLIST = "PERMISSIONS_POLICY_PERMISSIVE_ALLOWLIST"
    SYNC_XHR_ALLOWED = "PERMISSIONS_POLICY_SYNC_XHR"


# Dangerous permissions that should typically be restricted
DANGEROUS_PERMISSIONS = {
    'camera': {
        'severity': PermissionsSeverity.HIGH,
        'impact': 'Malicious iframes can request camera access, potentially recording users',
        'recommendation': 'camera=()'
    },
    'microphone': {
        'severity': PermissionsSeverity.HIGH,
        'impact': 'Malicious iframes can request microphone access, potentially eavesdropping',
        'recommendation': 'microphone=()'
    },
    'geolocation': {
        'severity': PermissionsSeverity.HIGH,
        'impact': 'Malicious iframes can request location data, tracking users',
        'recommendation': 'geolocation=()'
    },
    'payment': {
        'severity': PermissionsSeverity.HIGH,
        'impact': 'Malicious iframes can initiate payment requests',
        'recommendation': 'payment=()'
    },
    'usb': {
        'severity': PermissionsSeverity.MEDIUM,
        'impact': 'Malicious iframes can access USB devices',
        'recommendation': 'usb=()'
    },
    'bluetooth': {
        'severity': PermissionsSeverity.MEDIUM,
        'impact': 'Malicious iframes can access Bluetooth devices',
        'recommendation': 'bluetooth=()'
    },
    'midi': {
        'severity': PermissionsSeverity.LOW,
        'impact': 'Malicious iframes can access MIDI devices',
        'recommendation': 'midi=()'
    },
    'magnetometer': {
        'severity': PermissionsSeverity.LOW,
        'impact': 'Malicious iframes can access magnetometer data',
        'recommendation': 'magnetometer=()'
    },
    'gyroscope': {
        'severity': PermissionsSeverity.LOW,
        'impact': 'Malicious iframes can access gyroscope data (side-channel attacks)',
        'recommendation': 'gyroscope=()'
    },
    'accelerometer': {
        'severity': PermissionsSeverity.LOW,
        'impact': 'Malicious iframes can access accelerometer data (keystroke inference)',
        'recommendation': 'accelerometer=()'
    },
    'sync-xhr': {
        'severity': PermissionsSeverity.MEDIUM,
        'impact': 'Synchronous XHR can freeze the browser, enabling DoS attacks',
        'recommendation': 'sync-xhr=()'
    },
}


@dataclass
class PermissionsPolicyFinding:
    """Represents a Permissions-Policy security finding."""
    title: str
    severity: PermissionsSeverity
    vuln_type: PermissionsVulnType
    description: str
    endpoint: str
    permission_name: Optional[str] = None
    current_allowlist: Optional[str] = None
    expected_value: str = ""
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = "CWE-1021"
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    policy_header: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class PermissionsPolicyAnalysis:
    """Result from a Permissions-Policy analysis."""
    endpoint: str
    has_permissions_policy: bool
    has_feature_policy: bool
    permissions_policy_header: Optional[str] = None
    feature_policy_header: Optional[str] = None
    parsed_directives: Dict[str, List[str]] = field(default_factory=dict)
    findings: List[PermissionsPolicyFinding] = field(default_factory=list)
    dangerous_permissions_exposed: List[str] = field(default_factory=list)
    wildcard_permissions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis to dictionary."""
        data = asdict(self)
        data['findings'] = [f.to_dict() for f in self.findings]
        return data


class PermissionsPolicyAnalyzer:
    """
    Advanced Permissions-Policy Security Analyzer.

    Performs comprehensive Permissions-Policy header analysis including:
    - Detection of missing policies
    - Wildcard usage in dangerous permissions
    - Exposure of sensitive features (camera, microphone, geolocation, payment)
    - Permissive allowlist detection
    - Legacy Feature-Policy header detection
    - Synchronous XHR risks

    Usage:
        analyzer = PermissionsPolicyAnalyzer(target_url="https://example.com")
        findings = analyzer.run_all_tests()
    """

    def __init__(self, target_url: str, timeout: int = 10,
                 verify_ssl: bool = True,
                 custom_endpoints: Optional[List[str]] = None):
        """
        Initialize the Permissions-Policy analyzer.

        Args:
            target_url: Target URL to analyze
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            custom_endpoints: Additional endpoints to test
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Extract domain
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme

        # Build endpoint list
        self.endpoints = ['/']
        if custom_endpoints:
            self.endpoints.extend(custom_endpoints)

        # Storage for results
        self.findings: List[PermissionsPolicyFinding] = []
        self.analyses: List[PermissionsPolicyAnalysis] = []

        # Session for requests
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def run_all_tests(self, endpoints: Optional[List[str]] = None) -> List[PermissionsPolicyFinding]:
        """
        Execute all Permissions-Policy security tests.

        Args:
            endpoints: Optional list of endpoints to test (defaults to self.endpoints)

        Returns:
            List of PermissionsPolicyFinding objects
        """
        test_endpoints = endpoints if endpoints is not None else self.endpoints

        for endpoint in test_endpoints:
            url = f"{self.target_url}{endpoint}"
            analysis = self.analyze_endpoint(url)
            self.analyses.append(analysis)
            self.findings.extend(analysis.findings)

        return self.findings

    def analyze_endpoint(self, url: str) -> PermissionsPolicyAnalysis:
        """
        Analyze a single endpoint for Permissions-Policy issues.

        Args:
            url: URL to analyze

        Returns:
            PermissionsPolicyAnalysis object
        """
        analysis = PermissionsPolicyAnalysis(
            endpoint=url,
            has_permissions_policy=False,
            has_feature_policy=False
        )

        try:
            response = self.session.get(url, timeout=self.timeout, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            # Extract headers
            permissions_policy = response.headers.get('Permissions-Policy')
            feature_policy = response.headers.get('Feature-Policy')

            analysis.permissions_policy_header = permissions_policy
            analysis.feature_policy_header = feature_policy
            analysis.has_permissions_policy = bool(permissions_policy)
            analysis.has_feature_policy = bool(feature_policy)

            # Parse directives if present
            if permissions_policy:
                analysis.parsed_directives = self._parse_permissions_policy(permissions_policy)

            # Run tests
            if not permissions_policy and not feature_policy:
                analysis.findings.extend(self._test_missing_policy(url))

            if feature_policy and not permissions_policy:
                analysis.findings.extend(self._test_legacy_header(url, feature_policy))

            if permissions_policy:
                analysis.findings.extend(self._test_dangerous_permissions(
                    url, permissions_policy, analysis.parsed_directives
                ))
                analysis.findings.extend(self._test_wildcard_usage(
                    url, permissions_policy, analysis.parsed_directives
                ))
                analysis.findings.extend(self._test_permissive_allowlists(
                    url, permissions_policy, analysis.parsed_directives
                ))

        except requests.RequestException as e:
            # Skip this endpoint on error
            pass

        return analysis

    def _parse_permissions_policy(self, policy_header: str) -> Dict[str, List[str]]:
        """
        Parse Permissions-Policy header into directives.

        Format: permission=(allowlist)
        Example: camera=(), microphone=(self), geolocation=(self "https://example.com")

        Args:
            policy_header: Raw Permissions-Policy header value

        Returns:
            Dictionary mapping permission names to allowlist values
        """
        directives = {}

        # Split by comma, handling potential spaces
        parts = policy_header.split(',')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Match pattern: permission=(allowlist)
            match = re.match(r'([a-z-]+)\s*=\s*\(([^)]*)\)', part)
            if match:
                permission = match.group(1)
                allowlist_str = match.group(2).strip()

                # Parse allowlist (space-separated, quoted or unquoted)
                if not allowlist_str:
                    allowlist = []
                else:
                    # Handle quoted strings and bare tokens
                    allowlist = re.findall(r'"[^"]+"|[^\s]+', allowlist_str)
                    allowlist = [a.strip('"') for a in allowlist]

                directives[permission] = allowlist

        return directives

    def _test_missing_policy(self, url: str) -> List[PermissionsPolicyFinding]:
        """Test for missing Permissions-Policy header."""
        findings = []

        findings.append(PermissionsPolicyFinding(
            title="Missing Permissions-Policy Header",
            severity=PermissionsSeverity.MEDIUM,
            vuln_type=PermissionsVulnType.MISSING_POLICY,
            description=(
                "No Permissions-Policy or Feature-Policy header detected. "
                "Browser features are not restricted, allowing embedded content "
                "to request powerful permissions."
            ),
            endpoint=url,
            expected_value=(
                "Permissions-Policy: camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=(), bluetooth=()"
            ),
            poc=self._generate_missing_policy_poc(url),
            impact=(
                "Malicious iframes can request access to:\n"
                "- Camera and microphone (surveillance)\n"
                "- Geolocation (tracking)\n"
                "- Payment APIs (fraudulent transactions)\n"
                "- USB/Bluetooth devices (hardware access)\n"
                "Users may unknowingly grant permissions to untrusted origins."
            ),
            recommendation=(
                "Add Permissions-Policy header restricting dangerous features:\n"
                "Permissions-Policy: camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=(), bluetooth=(), sync-xhr=()"
            )
        ))

        return findings

    def _test_legacy_header(self, url: str, feature_policy: str) -> List[PermissionsPolicyFinding]:
        """Test for legacy Feature-Policy header usage."""
        findings = []

        findings.append(PermissionsPolicyFinding(
            title="Legacy Feature-Policy Header Detected",
            severity=PermissionsSeverity.LOW,
            vuln_type=PermissionsVulnType.LEGACY_FEATURE_POLICY,
            description=(
                f"Site uses deprecated Feature-Policy header instead of Permissions-Policy. "
                f"Feature-Policy has different syntax and is being phased out."
            ),
            endpoint=url,
            policy_header=feature_policy,
            expected_value="Migrate to Permissions-Policy header",
            poc=(
                f"# Current (deprecated):\n"
                f"Feature-Policy: {feature_policy}\n\n"
                f"# Should migrate to:\n"
                f"Permissions-Policy: <converted syntax>"
            ),
            impact=(
                "Feature-Policy may be removed from browsers in the future. "
                "The syntax differs from Permissions-Policy, causing confusion. "
                "Some features may not be properly restricted."
            ),
            recommendation=(
                "Migrate to Permissions-Policy header with updated syntax:\n"
                "Feature-Policy: camera 'none' → Permissions-Policy: camera=()\n"
                "Feature-Policy: camera 'self' → Permissions-Policy: camera=(self)"
            )
        ))

        return findings

    def _test_dangerous_permissions(self, url: str, policy_header: str,
                                   directives: Dict[str, List[str]]) -> List[PermissionsPolicyFinding]:
        """Test for dangerous permissions with permissive policies."""
        findings = []

        for permission, config in DANGEROUS_PERMISSIONS.items():
            if permission not in directives:
                # Permission not explicitly restricted
                findings.append(PermissionsPolicyFinding(
                    title=f"Missing Restriction for '{permission}' Permission",
                    severity=config['severity'],
                    vuln_type=self._get_vuln_type_for_permission(permission),
                    description=(
                        f"The '{permission}' permission is not restricted in Permissions-Policy. "
                        f"Embedded content may request access to this feature."
                    ),
                    endpoint=url,
                    permission_name=permission,
                    current_allowlist="(not set - defaults to *)",
                    expected_value=config['recommendation'],
                    poc=self._generate_permission_poc(url, permission),
                    impact=config['impact'],
                    recommendation=(
                        f"Add restriction to Permissions-Policy header: {config['recommendation']}\n"
                        f"This blocks all origins (including iframes) from accessing {permission}."
                    ),
                    policy_header=policy_header
                ))
            else:
                allowlist = directives[permission]
                if allowlist and allowlist != ['']:
                    # Permission has allowlist - check if it's too permissive
                    if '*' in allowlist or 'self' in allowlist:
                        severity_adjustment = (
                            PermissionsSeverity.HIGH if '*' in allowlist
                            else PermissionsSeverity.MEDIUM
                        )

                        findings.append(PermissionsPolicyFinding(
                            title=f"Permissive '{permission}' Permission Policy",
                            severity=severity_adjustment,
                            vuln_type=self._get_vuln_type_for_permission(permission),
                            description=(
                                f"The '{permission}' permission allows access from "
                                f"{', '.join(allowlist)}. This may be too permissive."
                            ),
                            endpoint=url,
                            permission_name=permission,
                            current_allowlist=f"({' '.join(allowlist)})",
                            expected_value=config['recommendation'],
                            poc=self._generate_permission_poc(url, permission, allowlist),
                            impact=(
                                f"{config['impact']}\n"
                                f"Current allowlist: {allowlist}"
                            ),
                            recommendation=(
                                f"Restrict '{permission}' to minimum required origins.\n"
                                f"If not needed, use: {config['recommendation']}"
                            ),
                            policy_header=policy_header
                        ))

        return findings

    def _test_wildcard_usage(self, url: str, policy_header: str,
                            directives: Dict[str, List[str]]) -> List[PermissionsPolicyFinding]:
        """Test for wildcard (*) usage in dangerous permissions."""
        findings = []

        for permission, allowlist in directives.items():
            if '*' in allowlist:
                severity = PermissionsSeverity.HIGH if permission in DANGEROUS_PERMISSIONS else PermissionsSeverity.MEDIUM

                findings.append(PermissionsPolicyFinding(
                    title=f"Wildcard (*) Allowed for '{permission}' Permission",
                    severity=severity,
                    vuln_type=PermissionsVulnType.WILDCARD_DANGEROUS,
                    description=(
                        f"The '{permission}' permission uses wildcard (*) in its allowlist, "
                        f"allowing all origins to access this feature."
                    ),
                    endpoint=url,
                    permission_name=permission,
                    current_allowlist=f"({' '.join(allowlist)})",
                    expected_value=f"{permission}=(self) or {permission}=()",
                    poc=self._generate_wildcard_poc(url, permission),
                    impact=(
                        f"Any iframe from any origin can request '{permission}' access.\n"
                        f"Malicious ads or compromised third-party content can abuse this permission."
                    ),
                    recommendation=(
                        f"Remove wildcard from '{permission}' allowlist.\n"
                        f"Use specific origins: {permission}=(self \"https://trusted.com\")\n"
                        f"Or block entirely: {permission}=()"
                    ),
                    policy_header=policy_header
                ))

        return findings

    def _test_permissive_allowlists(self, url: str, policy_header: str,
                                   directives: Dict[str, List[str]]) -> List[PermissionsPolicyFinding]:
        """Test for permissive allowlists with multiple origins."""
        findings = []

        for permission, allowlist in directives.items():
            # Check if allowlist has 3+ origins (potentially too permissive)
            if len(allowlist) >= 3 and '*' not in allowlist:
                severity = PermissionsSeverity.LOW

                findings.append(PermissionsPolicyFinding(
                    title=f"Permissive Allowlist for '{permission}' Permission",
                    severity=severity,
                    vuln_type=PermissionsVulnType.PERMISSIVE_ALLOWLIST,
                    description=(
                        f"The '{permission}' permission allows {len(allowlist)} origins. "
                        f"This may be unnecessarily permissive."
                    ),
                    endpoint=url,
                    permission_name=permission,
                    current_allowlist=f"({' '.join(allowlist)})",
                    expected_value=f"Minimize allowlist to essential origins only",
                    poc=(
                        f"# Current allowlist for {permission}:\n" +
                        "\n".join(f"  - {origin}" for origin in allowlist)
                    ),
                    impact=(
                        f"Multiple origins can access '{permission}' feature.\n"
                        f"Increases attack surface if any allowlisted origin is compromised."
                    ),
                    recommendation=(
                        f"Review allowlist for '{permission}' and remove unnecessary origins.\n"
                        f"Each allowed origin increases risk."
                    ),
                    policy_header=policy_header
                ))

        return findings

    def _get_vuln_type_for_permission(self, permission: str) -> PermissionsVulnType:
        """Map permission name to vulnerability type enum."""
        mapping = {
            'camera': PermissionsVulnType.CAMERA_EXPOSED,
            'microphone': PermissionsVulnType.MICROPHONE_EXPOSED,
            'geolocation': PermissionsVulnType.GEOLOCATION_EXPOSED,
            'payment': PermissionsVulnType.PAYMENT_EXPOSED,
            'usb': PermissionsVulnType.USB_EXPOSED,
            'bluetooth': PermissionsVulnType.BLUETOOTH_EXPOSED,
            'sync-xhr': PermissionsVulnType.SYNC_XHR_ALLOWED,
        }
        return mapping.get(permission, PermissionsVulnType.MISSING_POLICY)

    def _generate_missing_policy_poc(self, url: str) -> str:
        """Generate POC for missing Permissions-Policy."""
        return f"""# Malicious iframe can request camera access:
<iframe src="https://evil.com/spy" allow="camera; microphone; geolocation">
</iframe>

# Without Permissions-Policy, browser allows the permission request.
# User may unknowingly grant access thinking it's from {self.domain}.

# Test:
curl -I {url}
# Look for: Permissions-Policy header (should be present)
"""

    def _generate_permission_poc(self, url: str, permission: str,
                                allowlist: Optional[List[str]] = None) -> str:
        """Generate POC for specific permission exposure."""
        if allowlist:
            return f"""# Current policy allows {permission} from: {', '.join(allowlist)}
# Any iframe from these origins can request {permission}:

<iframe src="{'https://evil.com' if '*' in allowlist else allowlist[0]}"
        allow="{permission}">
</iframe>

<script>
  navigator.mediaDevices.getUserMedia({{
    {permission}: true
  }}).then(stream => {{
    // Attacker gains {permission} access
    console.log('Got {permission} access!');
  }});
</script>

# Verify:
curl -I {url} | grep -i permissions-policy
# Check: {permission}= value
"""
        else:
            return f"""# {permission} is not restricted (defaults to *)
# Test by creating malicious iframe:

<iframe src="https://evil.com/spy" allow="{permission}">
  <script>
    // Iframe can request {permission} permission
    navigator.permissions.query({{name: '{permission}'}})
      .then(result => console.log(result.state));
  </script>
</iframe>

# Verify:
curl -I {url} | grep -i permissions-policy
# Should include: {permission}=() to block
"""

    def _generate_wildcard_poc(self, url: str, permission: str) -> str:
        """Generate POC for wildcard permission abuse."""
        return f"""# Wildcard (*) allows ANY origin to access {permission}:

# Attacker serves malicious page:
<iframe src="{url}" allow="{permission}">
</iframe>

# From attacker's evil.com domain:
<script>
  // Embed target page as iframe
  const iframe = document.createElement('iframe');
  iframe.src = '{url}';
  iframe.allow = '{permission}';
  document.body.appendChild(iframe);

  // Request {permission} from within iframe context
  iframe.contentWindow.navigator.permissions.query({{name: '{permission}'}});
</script>

# Because allowlist contains *, evil.com is allowed.
# Verify with:
curl -I {url} | grep -i "permissions-policy.*{permission}"
"""

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate summary of findings.

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            'total_findings': len(self.findings),
            'by_severity': {},
            'by_vuln_type': {},
            'endpoints_tested': len(self.analyses),
            'dangerous_permissions_exposed': set(),
            'wildcard_permissions': set()
        }

        for finding in self.findings:
            # Count by severity
            severity = finding.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

            # Count by vuln type
            vuln_type = finding.vuln_type.value
            summary['by_vuln_type'][vuln_type] = summary['by_vuln_type'].get(vuln_type, 0) + 1

            # Track dangerous permissions
            if finding.permission_name in DANGEROUS_PERMISSIONS:
                summary['dangerous_permissions_exposed'].add(finding.permission_name)

            # Track wildcards
            if finding.vuln_type == PermissionsVulnType.WILDCARD_DANGEROUS:
                summary['wildcard_permissions'].add(finding.permission_name)

        # Convert sets to lists for JSON serialization
        summary['dangerous_permissions_exposed'] = list(summary['dangerous_permissions_exposed'])
        summary['wildcard_permissions'] = list(summary['wildcard_permissions'])

        return summary

    def generate_report(self) -> str:
        """
        Generate detailed security report.

        Returns:
            Formatted report string
        """
        summary = self.generate_summary()

        report = f"""
{'='*80}
PERMISSIONS-POLICY SECURITY ANALYSIS REPORT
{'='*80}

Target: {self.target_url}
Endpoints Tested: {summary['endpoints_tested']}
Total Findings: {summary['total_findings']}

SEVERITY BREAKDOWN:
"""

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = summary['by_severity'].get(severity, 0)
            if count > 0:
                report += f"  {severity}: {count}\n"

        report += f"\nDANGEROUS PERMISSIONS EXPOSED: {len(summary['dangerous_permissions_exposed'])}\n"
        for perm in summary['dangerous_permissions_exposed']:
            report += f"  - {perm}\n"

        if summary['wildcard_permissions']:
            report += f"\nWILDCARD PERMISSIONS: {len(summary['wildcard_permissions'])}\n"
            for perm in summary['wildcard_permissions']:
                report += f"  - {perm}\n"

        report += f"\n{'='*80}\nDETAILED FINDINGS\n{'='*80}\n\n"

        # Group findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_findings = [f for f in self.findings if f.severity.value == severity]

            if severity_findings:
                report += f"\n{severity} SEVERITY ({len(severity_findings)} findings)\n{'-'*80}\n\n"

                for i, finding in enumerate(severity_findings, 1):
                    report += f"""[{severity}-{i}] {finding.title}

Endpoint: {finding.endpoint}
Vulnerability Type: {finding.vuln_type.value}
CWE: {finding.cwe_id}

Description:
{finding.description}

Impact:
{finding.impact}

Proof of Concept:
{finding.poc}

Recommendation:
{finding.recommendation}

{'='*80}

"""

        return report


def main():
    """Command-line interface for permissions-policy analyzer."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python permissions_policy_analyzer.py <target_url>")
        print("\nExample: python permissions_policy_analyzer.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]

    print(f"[*] Starting Permissions-Policy analysis for {target}")
    print("[*] Analyzing headers...\n")

    analyzer = PermissionsPolicyAnalyzer(target_url=target)
    findings = analyzer.run_all_tests()

    print(analyzer.generate_report())

    # Save to file
    output_file = f"permissions_policy_analysis_{analyzer.domain.replace(':', '_')}.txt"
    with open(output_file, 'w') as f:
        f.write(analyzer.generate_report())

    print(f"\n[+] Report saved to: {output_file}")


if __name__ == "__main__":
    main()
