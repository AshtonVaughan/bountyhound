"""
API Versioning Tester Agent

Advanced API version enumeration and testing agent for discovering legacy API versions,
testing version downgrade attacks, exploiting deprecated endpoints, identifying
version-specific vulnerabilities, enumerating API versions comprehensively, and
exploiting migration gaps between API versions.

This agent tests for:
- Path-based versioning (/v1/, /v2/)
- Header-based versioning (Accept-Version, API-Version)
- Query parameter versioning (?version=1.0)
- Subdomain versioning (v1.api.example.com)
- Accept header content negotiation
- Version downgrade attacks
- Deprecated endpoint abuse
- Migration gap exploitation
- Version-specific auth bypasses
- Rate limiting differences

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import hashlib
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from enum import Enum
from collections import defaultdict


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VersioningType(Enum):
    """Types of API versioning mechanisms."""
    PATH = "path"
    HEADER = "header"
    QUERY = "query"
    SUBDOMAIN = "subdomain"
    ACCEPT = "accept_header"
    CUSTOM = "custom"


class VulnerabilityType(Enum):
    """Types of version-specific vulnerabilities."""
    AUTH_BYPASS = "authorization_bypass"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    VALIDATION_WEAKNESS = "validation_weakness"
    DEPRECATED_FEATURE = "deprecated_feature_abuse"
    MIGRATION_GAP = "migration_gap"
    VERSION_LEAK = "version_information_leak"
    DOWNGRADE_ATTACK = "version_downgrade"
    INTROSPECTION_LEAK = "introspection_leak"


@dataclass
class APIVersion:
    """Represents a discovered API version."""
    version: str
    versioning_type: VersioningType
    base_url: str
    discovered: bool = True
    endpoints: List[str] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)
    response_time: Optional[float] = None
    status_code: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with enum handling."""
        data = asdict(self)
        data['versioning_type'] = self.versioning_type.value
        return data


@dataclass
class VersionVulnerability:
    """Represents a version-specific vulnerability."""
    vuln_id: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    affected_version: str
    secure_version: Optional[str]
    endpoint: str
    proof_of_concept: str
    remediation: str
    bounty_estimate: str
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with enum handling."""
        data = asdict(self)
        data['vuln_type'] = self.vuln_type.value
        data['severity'] = self.severity.value
        return data


@dataclass
class VersionComparison:
    """Results from comparing two API versions."""
    version_a: str
    version_b: str
    status_diff: bool = False
    auth_diff: bool = False
    rate_limit_diff: bool = False
    validation_diff: bool = False
    header_diff: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class APIVersioningTester:
    """
    Advanced API versioning tester for discovering and exploiting
    vulnerabilities in API version management and legacy endpoints.

    Usage:
        tester = APIVersioningTester(target_url="https://api.example.com")
        findings = tester.run_all_tests()
    """

    # Version patterns for enumeration
    VERSION_PATTERNS = {
        'numeric': ['v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10'],
        'semantic': ['v1.0', 'v1.1', 'v2.0', 'v2.1', 'v3.0'],
        'date_based': [
            '2018-01', '2018-06', '2019-01', '2019-06',
            '2020-01', '2020-06', '2021-01', '2021-06',
            '2022-01', '2022-06', '2023-01', '2023-06',
            '2024-01', '2024-06', '2025-01', '2025-06'
        ],
        'year_month_day': [
            '2020-01-01', '2021-01-01', '2022-01-01',
            '2023-01-01', '2024-01-01', '2025-01-01'
        ]
    }

    # Common version headers
    VERSION_HEADERS = [
        'Accept-Version',
        'API-Version',
        'X-API-Version',
        'Version',
        'X-Version',
        'Stripe-Version',
        'GitHub-Version',
        'X-GitHub-Api-Version',
        'Twilio-API-Version'
    ]

    # Test endpoints for version detection
    TEST_ENDPOINTS = [
        '/',
        '/api',
        '/users',
        '/user',
        '/me',
        '/status',
        '/health',
        '/version',
        '/info'
    ]

    def __init__(self, target_url: str, timeout: int = 10,
                 verify_ssl: bool = True, max_versions: int = 20):
        """
        Initialize the API Versioning Tester.

        Args:
            target_url: Target API base URL
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            max_versions: Maximum number of versions to enumerate per method
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_versions = max_versions
        self.discovered_versions: List[APIVersion] = []
        self.vulnerabilities: List[VersionVulnerability] = []
        self.test_results: List[VersionComparison] = []

        # Extract domain info
        parsed = urllib.parse.urlparse(self.target_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        self.base_path = parsed.path or ''

        # Session for connection pooling
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def run_all_tests(self) -> List[VersionVulnerability]:
        """
        Execute comprehensive API versioning tests.

        Returns:
            List of discovered vulnerabilities
        """
        print(f"[*] Starting API versioning test for {self.target_url}")

        # Phase 1: Version Discovery
        self._discover_api_versions()

        # Phase 2: Version Comparison
        self._compare_version_behaviors()

        # Phase 3: Downgrade Attack Testing
        self._test_version_downgrades()

        # Phase 4: Deprecated Endpoint Testing
        self._test_deprecated_endpoints()

        # Phase 5: Migration Gap Analysis
        self._analyze_migration_gaps()

        # Phase 6: Version-Specific Security Testing
        self._test_version_specific_security()

        print(f"[+] Testing complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    def _discover_api_versions(self):
        """Discover all accessible API versions."""
        print("[*] Phase 1: API Version Discovery")

        # Method 1: Path-based versioning
        self._discover_path_versions()

        # Method 2: Header-based versioning
        self._discover_header_versions()

        # Method 3: Query parameter versioning
        self._discover_query_versions()

        # Method 4: Subdomain versioning
        self._discover_subdomain_versions()

        # Method 5: Accept header versioning
        self._discover_accept_versions()

        print(f"[+] Discovered {len(self.discovered_versions)} API versions")

    def _discover_path_versions(self):
        """Discover path-based API versions."""
        print("[*] Discovering path-based versions")

        for pattern_type, versions in self.VERSION_PATTERNS.items():
            for version in versions[:self.max_versions]:
                # Test multiple path formats
                test_urls = [
                    f"{self.scheme}://{self.domain}/{version}",
                    f"{self.scheme}://{self.domain}/{version}/api",
                    f"{self.scheme}://{self.domain}/api/{version}",
                ]

                for test_url in test_urls:
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                        # Consider 200, 401, 403 as existing versions (404 = not found)
                        if resp.status_code in [200, 401, 403]:
                            print(f"[+] Found path-based version: {version} at {test_url}")

                            api_version = APIVersion(
                                version=version,
                                versioning_type=VersioningType.PATH,
                                base_url=test_url,
                                status_code=resp.status_code,
                                response_time=resp.elapsed.total_seconds()
                            )
                            self.discovered_versions.append(api_version)

                            # Test some common endpoints
                            self._enumerate_version_endpoints(api_version)
                            break

                    except requests.exceptions.RequestException:
                        continue

    def _discover_header_versions(self):
        """Discover header-based API versions."""
        print("[*] Discovering header-based versions")

        for header_name in self.VERSION_HEADERS:
            for pattern_type, versions in self.VERSION_PATTERNS.items():
                for version in versions[:5]:  # Limit to avoid excessive requests
                    try:
                        headers = {header_name: version}
                        resp = self.session.get(self.target_url, headers=headers, timeout=self.timeout)

                        # Check if version header affects response
                        if resp.status_code in [200, 401, 403]:
                            # Verify it's actually using this version
                            version_confirmed = False

                            # Some APIs echo the version in response headers
                            for key, value in resp.headers.items():
                                if version in str(value):
                                    version_confirmed = True
                                    break

                            if version_confirmed or resp.status_code == 200:
                                print(f"[+] Found header-based version: {version} via {header_name}")

                                api_version = APIVersion(
                                    version=version,
                                    versioning_type=VersioningType.HEADER,
                                    base_url=self.target_url,
                                    features={'header_name': header_name},
                                    status_code=resp.status_code,
                                    response_time=resp.elapsed.total_seconds()
                                )
                                self.discovered_versions.append(api_version)
                                break

                    except requests.exceptions.RequestException:
                        continue

    def _discover_query_versions(self):
        """Discover query parameter-based versions."""
        print("[*] Discovering query parameter versions")

        query_params = ['version', 'api_version', 'v', 'ver', 'api']

        for param in query_params:
            for version in self.VERSION_PATTERNS['numeric'][:5]:
                try:
                    test_url = f"{self.target_url}?{param}={version}"
                    resp = self.session.get(test_url, timeout=self.timeout)

                    if resp.status_code in [200, 401, 403]:
                        print(f"[+] Found query-based version: {version} via ?{param}=")

                        api_version = APIVersion(
                            version=version,
                            versioning_type=VersioningType.QUERY,
                            base_url=self.target_url,
                            features={'param_name': param},
                            status_code=resp.status_code,
                            response_time=resp.elapsed.total_seconds()
                        )
                        self.discovered_versions.append(api_version)
                        break

                except requests.exceptions.RequestException:
                    continue

    def _discover_subdomain_versions(self):
        """Discover subdomain-based versions."""
        print("[*] Discovering subdomain versions")

        domain_parts = self.domain.split('.')

        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])

            for version in self.VERSION_PATTERNS['numeric'][:5]:
                try:
                    test_url = f"{self.scheme}://{version}.{base_domain}"
                    resp = self.session.get(test_url, timeout=self.timeout)

                    if resp.status_code in [200, 401, 403]:
                        print(f"[+] Found subdomain version: {version}")

                        api_version = APIVersion(
                            version=version,
                            versioning_type=VersioningType.SUBDOMAIN,
                            base_url=test_url,
                            status_code=resp.status_code,
                            response_time=resp.elapsed.total_seconds()
                        )
                        self.discovered_versions.append(api_version)

                except requests.exceptions.RequestException:
                    continue

    def _discover_accept_versions(self):
        """Discover Accept header content negotiation versions."""
        print("[*] Discovering Accept header versions")

        accept_patterns = [
            'application/vnd.api+json;version={}',
            'application/vnd.company.{}+json',
            'application/json;version={}',
        ]

        for pattern in accept_patterns:
            for version in self.VERSION_PATTERNS['numeric'][:3]:
                try:
                    accept_header = pattern.format(version)
                    headers = {'Accept': accept_header}

                    resp = self.session.get(self.target_url, headers=headers, timeout=self.timeout)

                    if resp.status_code in [200, 401, 403]:
                        print(f"[+] Found Accept header version: {version}")

                        api_version = APIVersion(
                            version=version,
                            versioning_type=VersioningType.ACCEPT,
                            base_url=self.target_url,
                            features={'accept_pattern': pattern},
                            status_code=resp.status_code,
                            response_time=resp.elapsed.total_seconds()
                        )
                        self.discovered_versions.append(api_version)
                        break

                except requests.exceptions.RequestException:
                    continue

    def _enumerate_version_endpoints(self, api_version: APIVersion):
        """Enumerate endpoints for a specific API version."""
        for endpoint in self.TEST_ENDPOINTS:
            url = urllib.parse.urljoin(api_version.base_url + '/', endpoint.lstrip('/'))

            try:
                headers = {}
                if api_version.versioning_type == VersioningType.HEADER:
                    header_name = api_version.features.get('header_name', 'Accept-Version')
                    headers[header_name] = api_version.version

                resp = self.session.get(url, headers=headers, timeout=self.timeout)

                if resp.status_code in [200, 401, 403]:
                    api_version.endpoints.append(endpoint)

            except requests.exceptions.RequestException:
                continue

    def _compare_version_behaviors(self):
        """Compare behavior across different API versions."""
        print("[*] Phase 2: Version Behavior Comparison")

        if len(self.discovered_versions) < 2:
            print("[-] Need at least 2 versions to compare")
            return

        # Group versions by type
        versions_by_type = defaultdict(list)
        for version in self.discovered_versions:
            versions_by_type[version.versioning_type].append(version)

        # Compare versions within same type
        for version_type, versions in versions_by_type.items():
            if len(versions) >= 2:
                self._compare_version_group(versions)

    def _compare_version_group(self, versions: List[APIVersion]):
        """Compare a group of API versions."""
        # Test same endpoint across all versions
        test_endpoint = '/users' if any('/users' in v.endpoints for v in versions) else (
            versions[0].endpoints[0] if versions[0].endpoints else '/'
        )

        responses = {}

        for version in versions:
            url = urllib.parse.urljoin(version.base_url + '/', test_endpoint.lstrip('/'))

            headers = {}
            if version.versioning_type == VersioningType.HEADER:
                header_name = version.features.get('header_name', 'Accept-Version')
                headers[header_name] = version.version

            try:
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
                responses[version.version] = {
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'body': resp.text[:1000]  # First 1000 chars
                }

            except requests.exceptions.RequestException:
                continue

        # Analyze differences
        if len(responses) >= 2:
            # Check for status code differences
            statuses = set(r['status'] for r in responses.values())
            if len(statuses) > 1:
                print(f"[!] Different status codes across versions: {statuses}")

                # This might indicate auth bypass
                if 200 in statuses and 401 in statuses:
                    vulnerable_version = [v for v, r in responses.items() if r['status'] == 200][0]
                    secure_version = [v for v, r in responses.items() if r['status'] == 401][0]

                    self.vulnerabilities.append(VersionVulnerability(
                        vuln_id=self._generate_vuln_id(f"auth_bypass_{vulnerable_version}"),
                        vuln_type=VulnerabilityType.AUTH_BYPASS,
                        severity=SeverityLevel.HIGH,
                        title=f"Authentication Bypass in API Version {vulnerable_version}",
                        description=f"API version {vulnerable_version} returns 200 OK without authentication while version {secure_version} properly returns 401 Unauthorized.",
                        affected_version=vulnerable_version,
                        secure_version=secure_version,
                        endpoint=test_endpoint,
                        proof_of_concept=f"Access endpoint with version {vulnerable_version} to bypass authentication.",
                        remediation=f"Backport authentication checks from {secure_version} to {vulnerable_version} or deprecate the vulnerable version.",
                        bounty_estimate="$5000-$12000",
                        cwe_id="CWE-287",
                        impact="Unauthorized access to protected resources without authentication"
                    ))

    def _test_version_downgrades(self):
        """Test version downgrade attacks."""
        print("[*] Phase 3: Version Downgrade Attack Testing")

        if len(self.discovered_versions) < 2:
            return

        # Sort versions (attempt numeric sort)
        sorted_versions = sorted(self.discovered_versions,
                                key=lambda v: self._parse_version_number(v.version))

        if len(sorted_versions) >= 2:
            oldest = sorted_versions[0]
            newest = sorted_versions[-1]

            # Test if we can downgrade from newest to oldest
            self._attempt_version_downgrade(newest, oldest)

    def _parse_version_number(self, version: str) -> float:
        """Parse version string to number for sorting."""
        # Extract first number from version string
        match = re.search(r'(\d+)\.?(\d*)', version)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2)) if match.group(2) else 0
            return float(f"{major}.{minor}")
        return 0.0

    def _attempt_version_downgrade(self, from_version: APIVersion, to_version: APIVersion):
        """Attempt to downgrade from one version to another."""
        print(f"[*] Testing downgrade: {from_version.version} -> {to_version.version}")

        # Test if we can force old version while using new version URL
        if from_version.versioning_type == VersioningType.PATH and to_version.versioning_type == VersioningType.HEADER:
            # Try to access new path with old version header
            url = from_version.base_url

            header_name = to_version.features.get('header_name', 'Accept-Version')
            headers = {header_name: to_version.version}

            try:
                resp = self.session.get(url, headers=headers, timeout=self.timeout)

                if resp.status_code == 200:
                    print(f"[!] Successfully downgraded to {to_version.version} via header")

                    self.vulnerabilities.append(VersionVulnerability(
                        vuln_id=self._generate_vuln_id(f"downgrade_{to_version.version}"),
                        vuln_type=VulnerabilityType.DOWNGRADE_ATTACK,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Version Downgrade Possible to {to_version.version}",
                        description=f"Can force API to use legacy version {to_version.version} while accessing newer endpoints.",
                        affected_version=to_version.version,
                        secure_version=from_version.version,
                        endpoint=from_version.base_url,
                        proof_of_concept=f"Add header '{header_name}: {to_version.version}' to force legacy version.",
                        remediation="Enforce minimum API version and reject requests for deprecated versions.",
                        bounty_estimate="$2000-$6000",
                        cwe_id="CWE-330",
                        impact="Access to deprecated API features with potentially weaker security controls"
                    ))

            except requests.exceptions.RequestException:
                pass

    def _test_deprecated_endpoints(self):
        """Test for deprecated endpoints in old versions."""
        print("[*] Phase 4: Deprecated Endpoint Testing")

        # Common deprecated endpoints
        deprecated_endpoints = [
            '/v1/admin',
            '/v1/internal',
            '/v1/debug',
            '/v1/test',
            '/v1/legacy',
            '/admin',
            '/internal',
            '/debug'
        ]

        for version in self.discovered_versions:
            for endpoint in deprecated_endpoints:
                url = urllib.parse.urljoin(version.base_url + '/', endpoint.lstrip('/'))

                headers = {}
                if version.versioning_type == VersioningType.HEADER:
                    header_name = version.features.get('header_name', 'Accept-Version')
                    headers[header_name] = version.version

                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout)

                    if resp.status_code in [200, 403]:  # 403 means it exists but forbidden
                        print(f"[!] Found deprecated endpoint: {endpoint} in {version.version}")

                        self.vulnerabilities.append(VersionVulnerability(
                            vuln_id=self._generate_vuln_id(f"deprecated_{version.version}_{endpoint}"),
                            vuln_type=VulnerabilityType.DEPRECATED_FEATURE,
                            severity=SeverityLevel.MEDIUM,
                            title=f"Deprecated Endpoint Accessible: {endpoint}",
                            description=f"Deprecated endpoint {endpoint} is still accessible in API version {version.version}.",
                            affected_version=version.version,
                            secure_version=None,
                            endpoint=endpoint,
                            proof_of_concept=f"Access {url} to reach deprecated endpoint.",
                            remediation="Remove or properly secure deprecated endpoints. Return 410 Gone for sunset endpoints.",
                            bounty_estimate="$1000-$4000",
                            cwe_id="CWE-1059",
                            impact="Potential access to deprecated features with known security issues"
                        ))

                except requests.exceptions.RequestException:
                    continue

    def _analyze_migration_gaps(self):
        """Analyze gaps in security controls between versions."""
        print("[*] Phase 5: Migration Gap Analysis")

        if len(self.discovered_versions) < 2:
            return

        # Test common security controls across versions
        security_tests = [
            ('rate_limiting', self._test_rate_limiting),
            ('input_validation', self._test_input_validation),
            ('authentication', self._test_authentication),
        ]

        for test_name, test_func in security_tests:
            results = {}

            for version in self.discovered_versions:
                result = test_func(version)
                results[version.version] = result

            # Look for inconsistencies
            if len(set(results.values())) > 1:
                # Different security controls across versions
                vulnerable_versions = [v for v, r in results.items() if not r]
                secure_versions = [v for v, r in results.items() if r]

                if vulnerable_versions and secure_versions:
                    self.vulnerabilities.append(VersionVulnerability(
                        vuln_id=self._generate_vuln_id(f"migration_gap_{test_name}"),
                        vuln_type=VulnerabilityType.MIGRATION_GAP,
                        severity=SeverityLevel.HIGH,
                        title=f"Migration Gap: {test_name.replace('_', ' ').title()}",
                        description=f"Security control '{test_name}' implemented in {secure_versions} but missing in {vulnerable_versions}.",
                        affected_version=', '.join(vulnerable_versions),
                        secure_version=', '.join(secure_versions),
                        endpoint="Multiple endpoints",
                        proof_of_concept=f"Use version {vulnerable_versions[0]} to bypass {test_name}.",
                        remediation=f"Implement {test_name} consistently across all API versions.",
                        bounty_estimate="$3000-$10000",
                        cwe_id="CWE-693",
                        impact=f"Bypass of {test_name} security control via version downgrade"
                    ))

    def _test_rate_limiting(self, version: APIVersion) -> bool:
        """Test if rate limiting is implemented."""
        url = version.base_url

        headers = {}
        if version.versioning_type == VersioningType.HEADER:
            header_name = version.features.get('header_name', 'Accept-Version')
            headers[header_name] = version.version

        # Make 20 rapid requests
        rate_limited = False
        for i in range(20):
            try:
                resp = self.session.get(url, headers=headers, timeout=2)
                if resp.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    break
            except requests.exceptions.RequestException:
                break

        return rate_limited

    def _test_input_validation(self, version: APIVersion) -> bool:
        """Test input validation strength."""
        # Test with malicious input
        test_payload = {"input": "<script>alert(1)</script>"}

        url = version.base_url

        headers = {'Content-Type': 'application/json'}
        if version.versioning_type == VersioningType.HEADER:
            header_name = version.features.get('header_name', 'Accept-Version')
            headers[header_name] = version.version

        try:
            resp = self.session.post(url, json=test_payload, headers=headers, timeout=self.timeout)
            # 400 = validation working, 200 = no validation
            return resp.status_code == 400
        except requests.exceptions.RequestException:
            return True  # Assume validation if error

    def _test_authentication(self, version: APIVersion) -> bool:
        """Test if authentication is required."""
        url = urllib.parse.urljoin(version.base_url + '/', 'users')

        headers = {}
        if version.versioning_type == VersioningType.HEADER:
            header_name = version.features.get('header_name', 'Accept-Version')
            headers[header_name] = version.version

        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            # 401 = auth required (good), 200 = no auth (bad)
            return resp.status_code == 401
        except requests.exceptions.RequestException:
            return True

    def _test_version_specific_security(self):
        """Test for version-specific security issues."""
        print("[*] Phase 6: Version-Specific Security Testing")

        # Test for version info leaks
        for version in self.discovered_versions:
            url = urllib.parse.urljoin(version.base_url + '/', 'version')

            headers = {}
            if version.versioning_type == VersioningType.HEADER:
                header_name = version.features.get('header_name', 'Accept-Version')
                headers[header_name] = version.version

            try:
                resp = self.session.get(url, headers=headers, timeout=self.timeout)

                if resp.status_code == 200:
                    body = resp.text.lower()

                    # Check for version info in response
                    if any(keyword in body for keyword in ['version', 'build', 'commit', 'git']):
                        self.vulnerabilities.append(VersionVulnerability(
                            vuln_id=self._generate_vuln_id(f"version_leak_{version.version}"),
                            vuln_type=VulnerabilityType.VERSION_LEAK,
                            severity=SeverityLevel.LOW,
                            title=f"Version Information Disclosure: {version.version}",
                            description=f"API version {version.version} exposes version information at /version endpoint.",
                            affected_version=version.version,
                            secure_version=None,
                            endpoint='/version',
                            proof_of_concept=f"Access {url} to retrieve version information.",
                            remediation="Remove version endpoint or require authentication.",
                            bounty_estimate="$500-$1500",
                            cwe_id="CWE-200",
                            impact="Information disclosure that aids reconnaissance"
                        ))

            except requests.exceptions.RequestException:
                continue

    def _generate_vuln_id(self, base: str) -> str:
        """Generate unique vulnerability ID."""
        hash_input = f"{base}_{self.target_url}".encode()
        return f"APIVER-{hashlib.md5(hash_input).hexdigest()[:8].upper()}"

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive testing report."""
        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'versions_discovered': len(self.discovered_versions),
                'total_vulnerabilities': len(self.vulnerabilities),
                'by_severity': {
                    'critical': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
                    'high': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH]),
                    'medium': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                    'low': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.LOW]),
                    'info': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.INFO])
                },
                'by_type': {
                    vtype.value: len([v for v in self.vulnerabilities if v.vuln_type == vtype])
                    for vtype in VulnerabilityType
                }
            },
            'discovered_versions': [v.to_dict() for v in self.discovered_versions],
            'vulnerabilities': [
                v.to_dict()
                for v in sorted(
                    self.vulnerabilities,
                    key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x.severity.value)
                )
            ]
        }

    def save_to_database(self, db_path: Optional[str] = None):
        """
        Save findings to BountyHound database.

        Args:
            db_path: Optional path to database file
        """
        try:
            from engine.core.database import BountyHoundDB

            db = BountyHoundDB(db_path=db_path)

            # Extract domain from target URL
            parsed = urllib.parse.urlparse(self.target_url)
            domain = parsed.netloc

            # Ensure target exists
            target_id = db.add_target(
                domain=domain,
                platform="unknown",
                platform_handle=None
            )

            # Save each vulnerability as a finding
            for vuln in self.vulnerabilities:
                db.add_finding(
                    target_id=target_id,
                    title=vuln.title,
                    severity=vuln.severity.value,
                    vuln_type=vuln.vuln_type.value,
                    description=vuln.description,
                    poc=vuln.proof_of_concept,
                    endpoints=[vuln.endpoint]
                )

            print(f"[+] Saved {len(self.vulnerabilities)} findings to database")

        except ImportError:
            print("[-] Database module not available, skipping database save")
        except Exception as e:
            print(f"[-] Error saving to database: {e}")


# Main entry point
def run_versioning_test(target_url: str, **kwargs) -> Dict[str, Any]:
    """
    Main entry point for API versioning testing.

    Args:
        target_url: Target API URL
        **kwargs: Additional arguments for APIVersioningTester

    Returns:
        Testing report with discovered vulnerabilities
    """
    tester = APIVersioningTester(target_url, **kwargs)
    tester.run_all_tests()
    return tester.generate_report()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_versioning_tester.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    report = run_versioning_test(target)

    print("\n" + "="*80)
    print("API VERSIONING TEST REPORT")
    print("="*80)
    print(json.dumps(report, indent=2))
