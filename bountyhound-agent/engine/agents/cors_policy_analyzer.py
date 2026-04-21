"""
CORS Policy Analyzer Agent

Advanced CORS policy analysis and security assessment agent that performs deep
analysis of CORS configurations, policy violations, and security implications.

This agent provides:
- Comprehensive CORS policy parsing and analysis
- Security risk assessment and scoring
- Policy violation detection
- Trust boundary analysis
- Compliance checking (OWASP, IETF standards)
- Database integration for tracking findings
- Detailed remediation recommendations

Key differences from CORSTester:
- Focuses on policy analysis vs active testing
- Provides risk scoring and compliance checks
- Tracks findings in database for historical analysis
- Generates detailed policy reports
- Analyzes policy patterns across multiple endpoints

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks


class PolicySeverity(Enum):
    """Policy violation severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyViolationType(Enum):
    """Types of CORS policy violations."""
    WILDCARD_MISCONFIGURATION = "POLICY_WILDCARD"
    ORIGIN_REFLECTION = "POLICY_ORIGIN_REFLECTION"
    NULL_ORIGIN_ALLOWED = "POLICY_NULL_ORIGIN"
    SUBDOMAIN_WILDCARD = "POLICY_SUBDOMAIN_WILDCARD"
    INSECURE_PROTOCOL = "POLICY_INSECURE_PROTOCOL"
    MISSING_VARY_HEADER = "POLICY_MISSING_VARY"
    CREDENTIAL_EXPOSURE = "POLICY_CREDENTIAL_EXPOSURE"
    OVERLY_PERMISSIVE = "POLICY_OVERLY_PERMISSIVE"
    REGEX_VULNERABILITY = "POLICY_REGEX_VULN"
    TRUST_BOUNDARY_VIOLATION = "POLICY_TRUST_BOUNDARY"
    COMPLIANCE_VIOLATION = "POLICY_COMPLIANCE"


class ComplianceStandard(Enum):
    """Compliance standards for CORS policies."""
    OWASP_ASVS = "OWASP ASVS"
    IETF_RFC6454 = "IETF RFC 6454"
    IETF_RFC7231 = "IETF RFC 7231"
    NIST_SP800_53 = "NIST SP 800-53"
    PCI_DSS = "PCI DSS"


@dataclass
class CORSPolicy:
    """Represents a parsed CORS policy."""
    endpoint: str
    allow_origin: Optional[str] = None
    allow_credentials: Optional[bool] = None
    allow_methods: List[str] = field(default_factory=list)
    allow_headers: List[str] = field(default_factory=list)
    expose_headers: List[str] = field(default_factory=list)
    max_age: Optional[int] = None
    vary_header: Optional[str] = None
    is_dynamic: bool = False  # Origin is dynamically determined
    supports_preflight: bool = False
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return asdict(self)


@dataclass
class PolicyViolation:
    """Represents a CORS policy violation."""
    title: str
    severity: PolicySeverity
    violation_type: PolicyViolationType
    description: str
    endpoint: str
    policy: CORSPolicy
    risk_score: int = 0  # 0-100
    compliance_violations: List[ComplianceStandard] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['violation_type'] = self.violation_type.value
        data['compliance_violations'] = [c.value for c in self.compliance_violations]
        data['policy'] = self.policy.to_dict()
        return data


@dataclass
class PolicyAnalysisReport:
    """Complete policy analysis report."""
    target: str
    endpoints_analyzed: int
    policies: List[CORSPolicy] = field(default_factory=list)
    violations: List[PolicyViolation] = field(default_factory=list)
    overall_risk_score: int = 0  # 0-100
    recommendations: List[str] = field(default_factory=list)
    compliance_summary: Dict[str, bool] = field(default_factory=dict)
    generated_date: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        data = asdict(self)
        data['policies'] = [p.to_dict() for p in self.policies]
        data['violations'] = [v.to_dict() for v in self.violations]
        return data


class CORSPolicyAnalyzer:
    """
    Advanced CORS Policy Analyzer.

    Performs comprehensive analysis of CORS policies including:
    - Policy parsing and normalization
    - Security risk assessment
    - Compliance checking
    - Violation detection
    - Trust boundary analysis
    - Database integration for tracking

    Usage:
        analyzer = CORSPolicyAnalyzer(target_domain="example.com")
        analyzer.analyze_endpoint("https://api.example.com/users")
        report = analyzer.generate_report()
    """

    # OWASP recommended configurations
    OWASP_RECOMMENDED = {
        'no_wildcard_with_credentials': True,
        'explicit_origin_whitelist': True,
        'https_only': True,
        'vary_header_required': True,
        'no_null_origin': True,
        'restricted_methods': ['GET', 'POST', 'OPTIONS'],
        'max_age_limit': 86400  # 24 hours
    }

    # Dangerous HTTP methods
    DANGEROUS_METHODS = {'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'}

    # Common sensitive headers
    SENSITIVE_HEADERS = {
        'authorization', 'x-api-key', 'x-auth-token',
        'cookie', 'session-id', 'x-csrf-token'
    }

    def __init__(self, target_domain: str, timeout: int = 10,
                 verify_ssl: bool = True, use_database: bool = True):
        """
        Initialize the CORS Policy Analyzer.

        Args:
            target_domain: Target domain for analysis
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            use_database: Whether to use database for tracking
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_domain = target_domain.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.use_database = use_database

        # Analysis results
        self.policies: List[CORSPolicy] = []
        self.violations: List[PolicyViolation] = []
        self.endpoints_tested: Set[str] = set()

        # Database
        if use_database:
            self.db = BountyHoundDB()
            self.db_context = DatabaseHooks.before_test(target_domain, 'cors_policy_analyzer')
        else:
            self.db = None
            self.db_context = None

    def analyze_endpoint(self, endpoint_url: str,
                        test_origins: Optional[List[str]] = None) -> CORSPolicy:
        """
        Analyze CORS policy for a specific endpoint.

        Args:
            endpoint_url: URL of the endpoint to analyze
            test_origins: Optional list of origins to test (for dynamic policies)

        Returns:
            Parsed CORSPolicy object
        """
        endpoint_url = endpoint_url.rstrip('/')
        self.endpoints_tested.add(endpoint_url)

        # Parse policy from endpoint
        policy = self._parse_policy(endpoint_url, test_origins)
        self.policies.append(policy)

        # Analyze for violations
        violations = self._analyze_policy_violations(policy)
        self.violations.extend(violations)

        return policy

    def _parse_policy(self, endpoint_url: str,
                     test_origins: Optional[List[str]] = None) -> CORSPolicy:
        """
        Parse CORS policy from endpoint response headers.

        Args:
            endpoint_url: Endpoint URL
            test_origins: Origins to test for dynamic policies

        Returns:
            CORSPolicy object
        """
        # First, get baseline policy with no Origin header
        baseline_headers = self._fetch_cors_headers(endpoint_url)

        # Test if policy is dynamic (changes based on Origin)
        is_dynamic = False
        if test_origins:
            for origin in test_origins[:3]:  # Test first 3
                test_headers = self._fetch_cors_headers(endpoint_url, origin)
                if test_headers.get('Access-Control-Allow-Origin') != baseline_headers.get('Access-Control-Allow-Origin'):
                    is_dynamic = True
                    baseline_headers = test_headers  # Use dynamic headers
                    break

        # Parse policy components
        acao = baseline_headers.get('Access-Control-Allow-Origin')
        acac = baseline_headers.get('Access-Control-Allow-Credentials')
        acam = baseline_headers.get('Access-Control-Allow-Methods', '')
        acah = baseline_headers.get('Access-Control-Allow-Headers', '')
        aceh = baseline_headers.get('Access-Control-Expose-Headers', '')
        max_age_str = baseline_headers.get('Access-Control-Max-Age')
        vary = baseline_headers.get('Vary')

        # Parse methods
        methods = [m.strip().upper() for m in acam.split(',') if m.strip()] if acam else []

        # Parse headers
        allowed_headers = [h.strip().lower() for h in acah.split(',') if h.strip()] if acah else []
        exposed_headers = [h.strip().lower() for h in aceh.split(',') if h.strip()] if aceh else []

        # Parse max-age
        max_age = None
        if max_age_str:
            try:
                max_age = int(max_age_str)
            except ValueError:
                pass

        # Check for preflight support (OPTIONS method)
        supports_preflight = 'OPTIONS' in methods or self._test_preflight_support(endpoint_url)

        return CORSPolicy(
            endpoint=endpoint_url,
            allow_origin=acao,
            allow_credentials=(acac == 'true'),
            allow_methods=methods,
            allow_headers=allowed_headers,
            expose_headers=exposed_headers,
            max_age=max_age,
            vary_header=vary,
            is_dynamic=is_dynamic,
            supports_preflight=supports_preflight,
            raw_headers=baseline_headers
        )

    def _fetch_cors_headers(self, url: str, origin: Optional[str] = None) -> Dict[str, str]:
        """
        Fetch CORS headers from an endpoint.

        Args:
            url: Endpoint URL
            origin: Optional Origin header value

        Returns:
            Dictionary of CORS-related headers
        """
        headers = {}
        if origin:
            headers['Origin'] = origin

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            # Extract CORS headers
            cors_headers = {}
            for header_name in response.headers:
                if header_name.lower().startswith('access-control-') or header_name.lower() == 'vary':
                    cors_headers[header_name] = response.headers[header_name]

            return cors_headers

        except requests.exceptions.RequestException:
            return {}

    def _test_preflight_support(self, url: str) -> bool:
        """Test if endpoint supports CORS preflight (OPTIONS)."""
        try:
            response = requests.options(
                url,
                headers={
                    'Origin': 'https://example.com',
                    'Access-Control-Request-Method': 'POST'
                },
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            return 'Access-Control-Allow-Methods' in response.headers
        except requests.exceptions.RequestException:
            return False

    def _analyze_policy_violations(self, policy: CORSPolicy) -> List[PolicyViolation]:
        """
        Analyze a CORS policy for violations.

        Args:
            policy: CORSPolicy to analyze

        Returns:
            List of PolicyViolation objects
        """
        violations = []

        # Check for wildcard misconfiguration
        if policy.allow_origin == '*' and policy.allow_credentials:
            violations.append(self._create_wildcard_violation(policy))

        # Check for origin reflection (dynamic policy)
        if policy.is_dynamic:
            violations.append(self._create_origin_reflection_violation(policy))

        # Check for null origin
        if policy.allow_origin and policy.allow_origin.lower() == 'null':
            violations.append(self._create_null_origin_violation(policy))

        # Check for subdomain wildcard patterns
        if policy.allow_origin and self._is_subdomain_wildcard(policy.allow_origin):
            violations.append(self._create_subdomain_wildcard_violation(policy))

        # Check for insecure protocol
        if policy.allow_origin and policy.allow_origin.startswith('http://'):
            violations.append(self._create_insecure_protocol_violation(policy))

        # Check for missing Vary header
        if policy.is_dynamic and not self._has_proper_vary_header(policy):
            violations.append(self._create_missing_vary_violation(policy))

        # Check for credential exposure
        if policy.allow_credentials and not self._is_origin_trusted(policy.allow_origin):
            violations.append(self._create_credential_exposure_violation(policy))

        # Check for overly permissive methods
        if self._has_dangerous_methods(policy):
            violations.append(self._create_overly_permissive_violation(policy))

        # Check for overly permissive headers
        if '*' in policy.allow_headers:
            violations.append(self._create_wildcard_headers_violation(policy))

        # Check for compliance violations
        compliance_violations = self._check_compliance(policy)
        violations.extend(compliance_violations)

        return violations

    def _create_wildcard_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for wildcard with credentials."""
        return PolicyViolation(
            title="CORS Wildcard with Credentials Misconfiguration",
            severity=PolicySeverity.HIGH,
            violation_type=PolicyViolationType.WILDCARD_MISCONFIGURATION,
            description=(
                "The endpoint uses Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true. While browsers block this per "
                "specification, it indicates a fundamental misunderstanding of CORS security."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=75,
            compliance_violations=[
                ComplianceStandard.OWASP_ASVS,
                ComplianceStandard.IETF_RFC6454
            ],
            remediation=(
                "Never use Access-Control-Allow-Origin: * with credentials. "
                "Implement an explicit whitelist of trusted origins and validate "
                "the Origin header before reflecting it."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
            ],
            cwe_id="CWE-942",
            cvss_score=6.5
        )

    def _create_origin_reflection_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for origin reflection."""
        severity = PolicySeverity.CRITICAL if policy.allow_credentials else PolicySeverity.HIGH

        return PolicyViolation(
            title=f"CORS Origin Reflection Vulnerability{'with Credentials' if policy.allow_credentials else ''}",
            severity=severity,
            violation_type=PolicyViolationType.ORIGIN_REFLECTION,
            description=(
                "The endpoint reflects arbitrary origins in the Access-Control-Allow-Origin "
                f"header. {'Credentials are allowed, enabling full account takeover attacks.' if policy.allow_credentials else 'This exposes sensitive data to unauthorized origins.'}"
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=90 if policy.allow_credentials else 70,
            compliance_violations=[
                ComplianceStandard.OWASP_ASVS,
                ComplianceStandard.IETF_RFC6454,
                ComplianceStandard.PCI_DSS
            ],
            remediation=(
                "Implement strict origin whitelisting. Validate the Origin header against "
                "a predefined list of trusted domains before reflecting it. Use exact string "
                "matching, not regex patterns that can be bypassed."
            ),
            references=[
                "https://portswigger.net/web-security/cors",
                "https://www.cobalt.io/blog/a-pentesters-guide-to-cross-origin-resource-sharing-cors"
            ],
            cwe_id="CWE-942",
            cvss_score=8.6 if policy.allow_credentials else 6.1
        )

    def _create_null_origin_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for null origin acceptance."""
        return PolicyViolation(
            title="CORS Null Origin Bypass Vulnerability",
            severity=PolicySeverity.HIGH,
            violation_type=PolicyViolationType.NULL_ORIGIN_ALLOWED,
            description=(
                "The endpoint accepts the 'null' origin, which can be triggered from "
                "sandboxed iframes, local HTML files, or certain browser contexts. "
                "This bypasses CORS protections entirely."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=80,
            compliance_violations=[ComplianceStandard.OWASP_ASVS],
            remediation=(
                "Reject requests with Origin: null. Only allow explicitly whitelisted "
                "HTTPS origins. Implement proper origin validation that excludes null."
            ),
            references=[
                "https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html#main"
            ],
            cwe_id="CWE-942",
            cvss_score=7.4
        )

    def _create_subdomain_wildcard_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for subdomain wildcard trust."""
        return PolicyViolation(
            title="CORS Subdomain Wildcard Trust Vulnerability",
            severity=PolicySeverity.HIGH,
            violation_type=PolicyViolationType.SUBDOMAIN_WILDCARD,
            description=(
                "The CORS policy trusts all subdomains indiscriminately. If an attacker "
                "can compromise any subdomain (via XSS, subdomain takeover, or registration), "
                "they can bypass CORS protections."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=75,
            compliance_violations=[ComplianceStandard.OWASP_ASVS],
            remediation=(
                "Do not trust all subdomains. Maintain an explicit whitelist of specific "
                "trusted origins. Implement subdomain takeover prevention and monitoring."
            ),
            references=[
                "https://0xpatrik.com/subdomain-takeover-basics/",
                "https://www.hackerone.com/application-security/guide-subdomain-takeovers"
            ],
            cwe_id="CWE-942",
            cvss_score=7.1
        )

    def _create_insecure_protocol_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for insecure protocol."""
        return PolicyViolation(
            title="CORS Insecure Protocol Violation",
            severity=PolicySeverity.MEDIUM,
            violation_type=PolicyViolationType.INSECURE_PROTOCOL,
            description=(
                "The CORS policy allows HTTP origins. This enables protocol downgrade "
                "attacks where an active network attacker can intercept HTTP traffic "
                "and make cross-origin requests."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=60,
            compliance_violations=[
                ComplianceStandard.OWASP_ASVS,
                ComplianceStandard.PCI_DSS
            ],
            remediation=(
                "Only allow HTTPS origins for HTTPS endpoints. Reject HTTP origins "
                "in the CORS validation logic. Implement HSTS to prevent protocol downgrades."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            ],
            cwe_id="CWE-319",
            cvss_score=5.3
        )

    def _create_missing_vary_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for missing Vary header."""
        return PolicyViolation(
            title="CORS Missing Vary Header",
            severity=PolicySeverity.MEDIUM,
            violation_type=PolicyViolationType.MISSING_VARY_HEADER,
            description=(
                "The endpoint uses dynamic CORS (reflects origins) but does not include "
                "'Vary: Origin' header. This can cause caching issues where one user's "
                "CORS response is served to another user from a shared cache."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=50,
            compliance_violations=[ComplianceStandard.IETF_RFC7231],
            remediation=(
                "Add 'Vary: Origin' header to all responses that use dynamic CORS. "
                "This ensures proper cache segmentation based on the Origin header."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"
            ],
            cwe_id="CWE-525"
        )

    def _create_credential_exposure_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for credential exposure."""
        return PolicyViolation(
            title="CORS Credential Exposure Risk",
            severity=PolicySeverity.MEDIUM,
            violation_type=PolicyViolationType.CREDENTIAL_EXPOSURE,
            description=(
                "The endpoint allows credentials in cross-origin requests. While this may "
                "be intentional, it significantly increases attack surface if combined with "
                "other CORS misconfigurations."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=60,
            compliance_violations=[],
            remediation=(
                "Only enable Access-Control-Allow-Credentials if absolutely necessary. "
                "If enabled, ensure extremely strict origin validation is in place."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials"
            ],
            cwe_id="CWE-942"
        )

    def _create_overly_permissive_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for overly permissive methods."""
        dangerous = set(policy.allow_methods) & self.DANGEROUS_METHODS

        return PolicyViolation(
            title="CORS Overly Permissive Methods",
            severity=PolicySeverity.MEDIUM,
            violation_type=PolicyViolationType.OVERLY_PERMISSIVE,
            description=(
                f"The CORS policy allows dangerous HTTP methods: {', '.join(dangerous)}. "
                "This may enable attackers to perform state-changing operations cross-origin."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=55,
            compliance_violations=[ComplianceStandard.OWASP_ASVS],
            remediation=(
                "Restrict Access-Control-Allow-Methods to only what's necessary. "
                "Typically, only GET and POST should be allowed for cross-origin requests. "
                "Dangerous methods like PUT, DELETE should require same-origin requests."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/"
            ],
            cwe_id="CWE-942"
        )

    def _create_wildcard_headers_violation(self, policy: CORSPolicy) -> PolicyViolation:
        """Create violation for wildcard headers."""
        return PolicyViolation(
            title="CORS Wildcard Headers Misconfiguration",
            severity=PolicySeverity.LOW,
            violation_type=PolicyViolationType.OVERLY_PERMISSIVE,
            description=(
                "The CORS policy allows all headers (*) in cross-origin requests. "
                "This is overly permissive and may expose sensitive header values."
            ),
            endpoint=policy.endpoint,
            policy=policy,
            risk_score=40,
            compliance_violations=[],
            remediation=(
                "Explicitly list allowed headers instead of using '*'. Only allow "
                "headers that are necessary for the application to function."
            ),
            references=[],
            cwe_id="CWE-942"
        )

    def _check_compliance(self, policy: CORSPolicy) -> List[PolicyViolation]:
        """Check policy against compliance standards."""
        violations = []

        # Check max-age compliance (shouldn't be too long)
        if policy.max_age and policy.max_age > self.OWASP_RECOMMENDED['max_age_limit']:
            violations.append(PolicyViolation(
                title="CORS Excessive Cache Duration",
                severity=PolicySeverity.LOW,
                violation_type=PolicyViolationType.COMPLIANCE_VIOLATION,
                description=(
                    f"The Access-Control-Max-Age is set to {policy.max_age} seconds, "
                    f"which exceeds the recommended maximum of {self.OWASP_RECOMMENDED['max_age_limit']} seconds (24 hours)."
                ),
                endpoint=policy.endpoint,
                policy=policy,
                risk_score=30,
                compliance_violations=[ComplianceStandard.OWASP_ASVS],
                remediation=(
                    "Reduce Access-Control-Max-Age to 24 hours (86400 seconds) or less. "
                    "This limits the window of exposure if CORS policy needs to be changed."
                ),
                references=[],
                cwe_id="CWE-525"
            ))

        return violations

    # Helper methods

    def _is_subdomain_wildcard(self, origin: Optional[str]) -> bool:
        """Check if origin uses subdomain wildcard pattern."""
        if not origin:
            return False
        # Check for patterns like *.example.com
        return '*' in origin or origin.count('.') >= 2

    def _has_proper_vary_header(self, policy: CORSPolicy) -> bool:
        """Check if Vary header includes Origin."""
        if not policy.vary_header:
            return False
        vary_values = [v.strip().lower() for v in policy.vary_header.split(',')]
        return 'origin' in vary_values

    def _is_origin_trusted(self, origin: Optional[str]) -> bool:
        """Check if origin should be trusted (basic heuristic)."""
        if not origin:
            return False
        # Wildcard and null are not trusted
        if origin == '*' or origin.lower() == 'null':
            return False
        # HTTP origins are not fully trusted
        if origin.startswith('http://'):
            return False
        return True

    def _has_dangerous_methods(self, policy: CORSPolicy) -> bool:
        """Check if policy allows dangerous HTTP methods."""
        return bool(set(policy.allow_methods) & self.DANGEROUS_METHODS)

    def generate_report(self) -> PolicyAnalysisReport:
        """
        Generate comprehensive policy analysis report.

        Returns:
            PolicyAnalysisReport object
        """
        # Calculate overall risk score (weighted average)
        if self.violations:
            risk_scores = [v.risk_score for v in self.violations]
            overall_risk = int(sum(risk_scores) / len(risk_scores))
        else:
            overall_risk = 0

        # Generate recommendations
        recommendations = self._generate_recommendations()

        # Compliance summary
        compliance_summary = self._generate_compliance_summary()

        report = PolicyAnalysisReport(
            target=self.target_domain,
            endpoints_analyzed=len(self.endpoints_tested),
            policies=self.policies,
            violations=self.violations,
            overall_risk_score=overall_risk,
            recommendations=recommendations,
            compliance_summary=compliance_summary
        )

        # Store in database if enabled
        if self.use_database and self.db:
            self._store_findings_in_database(report)

        return report

    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Group violations by type
        violation_types = {}
        for v in self.violations:
            if v.violation_type not in violation_types:
                violation_types[v.violation_type] = []
            violation_types[v.violation_type].append(v)

        # Critical recommendations first
        critical_violations = [v for v in self.violations if v.severity == PolicySeverity.CRITICAL]
        if critical_violations:
            recommendations.append(
                f"CRITICAL: Fix {len(critical_violations)} critical CORS vulnerabilities immediately. "
                "These allow full account takeover attacks."
            )

        # Origin reflection
        if PolicyViolationType.ORIGIN_REFLECTION in violation_types:
            recommendations.append(
                "Implement strict origin whitelisting. Never reflect arbitrary origins in "
                "Access-Control-Allow-Origin header."
            )

        # Credentials
        credential_violations = [v for v in self.violations
                                if v.violation_type == PolicyViolationType.CREDENTIAL_EXPOSURE]
        if credential_violations:
            recommendations.append(
                "Review credential usage in CORS. Only enable Access-Control-Allow-Credentials "
                "for trusted, explicitly whitelisted origins."
            )

        # Vary header
        if PolicyViolationType.MISSING_VARY_HEADER in violation_types:
            recommendations.append(
                "Add 'Vary: Origin' header to all dynamic CORS responses to prevent cache poisoning."
            )

        # General recommendation
        if self.violations:
            recommendations.append(
                "Conduct regular CORS policy audits. Review and update trusted origin lists quarterly."
            )

        return recommendations

    def _generate_compliance_summary(self) -> Dict[str, bool]:
        """Generate compliance summary across standards."""
        summary = {}

        for standard in ComplianceStandard:
            # Check if any violations reference this standard
            violations_for_standard = [
                v for v in self.violations
                if standard in v.compliance_violations
            ]
            summary[standard.value] = len(violations_for_standard) == 0

        return summary

    def _store_findings_in_database(self, report: PolicyAnalysisReport):
        """Store findings in database for historical tracking."""
        if not self.db:
            return

        target_id = self.db.get_or_create_target(self.target_domain)

        # Record tool run
        self.db.record_tool_run(
            domain=self.target_domain,
            tool_name='cors_policy_analyzer',
            findings_count=len(self.violations),
            success=True
        )

        # Store high severity violations as findings
        # (You can extend BountyHoundDB to have a method to store findings)
        # For now, this is a placeholder for database integration

    def get_violations_by_severity(self, severity: PolicySeverity) -> List[PolicyViolation]:
        """Get violations filtered by severity."""
        return [v for v in self.violations if v.severity == severity]

    def get_critical_violations(self) -> List[PolicyViolation]:
        """Get all critical severity violations."""
        return self.get_violations_by_severity(PolicySeverity.CRITICAL)

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of analysis results.

        Returns:
            Dictionary with analysis statistics
        """
        severity_counts = {
            'CRITICAL': len(self.get_violations_by_severity(PolicySeverity.CRITICAL)),
            'HIGH': len(self.get_violations_by_severity(PolicySeverity.HIGH)),
            'MEDIUM': len(self.get_violations_by_severity(PolicySeverity.MEDIUM)),
            'LOW': len(self.get_violations_by_severity(PolicySeverity.LOW)),
            'INFO': len(self.get_violations_by_severity(PolicySeverity.INFO))
        }

        return {
            'target': self.target_domain,
            'endpoints_analyzed': len(self.endpoints_tested),
            'policies_found': len(self.policies),
            'total_violations': len(self.violations),
            'severity_breakdown': severity_counts,
            'overall_risk_score': self.generate_report().overall_risk_score,
            'database_context': self.db_context
        }
