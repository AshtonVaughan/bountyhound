"""
API Response Analyzer Agent

Comprehensive API response analysis agent that identifies vulnerabilities in
API responses including:
- Error pattern analysis with information disclosure detection
- Security header audit (CSP, HSTS, X-Frame-Options, etc.)
- Data consistency checks for IDOR and missing authorization
- Response timing analysis for user enumeration
- Information leakage (stack traces, database errors, internal paths, API keys)
- Response manipulation testing (cache poisoning, response splitting)

This agent performs deep analysis of HTTP responses to uncover security issues
that may not be apparent from simple endpoint testing.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import requests
import json
import time
import re
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from urllib.parse import urlparse
from collections import defaultdict
import statistics
from datetime import datetime
from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks



class ResponseSeverity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InformationType(Enum):
    """Types of information leakage."""
    VERSION_NUMBER = "version_number"
    STACK_TRACE = "stack_trace"
    FILE_PATH = "file_path"
    DATABASE_ERROR = "database_error"
    API_KEY = "api_key"
    EMAIL_ADDRESS = "email_address"
    IP_ADDRESS = "ip_address"
    USERNAME = "username"
    ERROR_CODE = "error_code"
    INTERNAL_URL = "internal_url"


@dataclass
class ResponsePattern:
    """API response pattern."""
    status_code: int
    response_time_ms: float
    content_length: int
    content_hash: str
    headers: Dict[str, str]
    body_sample: str = ""


@dataclass
class ResponseVulnerability:
    """Response vulnerability finding."""
    vuln_id: str
    severity: ResponseSeverity
    title: str
    description: str
    endpoint: str
    evidence: Dict[str, Any]
    remediation: str
    cwe: str = ""
    cvss_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vuln_id': self.vuln_id,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'endpoint': self.endpoint,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe': self.cwe,
            'cvss_score': self.cvss_score
        }


class APIResponseAnalyzer:
    """
    Advanced API response analysis agent.

    Analyzes responses for:
    - Information disclosure
    - Security header issues
    - Error pattern leaks
    - Timing variations
    - Data inconsistencies
    - Response manipulation vulnerabilities
    """

    def __init__(self, base_url: str, endpoints: Optional[List[str]] = None,
                 session: Optional[requests.Session] = None, db_path: Optional[str] = None):
        """
        Initialize API response analyzer.

        Args:
            base_url: Base URL of the API
            endpoints: List of endpoints to test (optional, will discover if not provided)
            session: Existing requests session (optional)
            db_path: Path to database file (optional)
        """
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.endpoints = endpoints or self.discover_endpoints()
        self.vulnerabilities: List[ResponseVulnerability] = []
        self.response_patterns: Dict[str, List[ResponsePattern]] = defaultdict(list)

        # Database integration
        self.db = BountyHoundDB(db_path) if db_path else BountyHoundDB()

        # Request session
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.verify = False
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

    def discover_endpoints(self) -> List[str]:
        """Discover common API endpoints."""
        common_endpoints = [
            "/api/v1/users",
            "/api/v1/auth/login",
            "/api/v1/products",
            "/api/v1/search",
            "/api/v1/config",
            "/api/health",
            "/api/status",
            "/graphql",
            "/v1/user",
            "/v1/data",
        ]
        return common_endpoints

    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Execute full response analysis.

        Returns:
            Dictionary with analysis results and vulnerabilities
        """
        results = {
            "target": self.base_url,
            "domain": self.domain,
            "endpoints_analyzed": 0,
            "timestamp": datetime.now().isoformat(),
            "tests_run": [],
            "vulnerabilities": []
        }

        print(f"[*] Starting API Response Analysis for {self.base_url}")

        # Database check
        context = DatabaseHooks.before_test(self.domain, 'api_response_analyzer')
        if context['should_skip']:
            print(f"[!] {context['reason']}")
            print(f"[!] {', '.join(context['recommendations'])}")
            results['skipped'] = True
            results['skip_reason'] = context['reason']
            return results

        # Phase 1: Error Pattern Analysis
        print("\n[*] Phase 1: Error Pattern Detection")
        error_vulns = self.analyze_error_patterns()
        results["tests_run"].append("error_patterns")
        self.vulnerabilities.extend(error_vulns)

        # Phase 2: Security Headers
        print("\n[*] Phase 2: Security Header Audit")
        header_vulns = self.audit_security_headers()
        results["tests_run"].append("security_headers")
        self.vulnerabilities.extend(header_vulns)

        # Phase 3: Information Disclosure
        print("\n[*] Phase 3: Information Leakage Detection")
        info_vulns = self.detect_information_leakage()
        results["tests_run"].append("information_disclosure")
        self.vulnerabilities.extend(info_vulns)

        # Phase 4: Timing Analysis
        print("\n[*] Phase 4: Response Timing Analysis")
        timing_vulns = self.analyze_timing()
        results["tests_run"].append("timing_analysis")
        self.vulnerabilities.extend(timing_vulns)

        # Phase 5: Data Consistency
        print("\n[*] Phase 5: Data Consistency Checks")
        consistency_vulns = self.check_data_consistency()
        results["tests_run"].append("data_consistency")
        self.vulnerabilities.extend(consistency_vulns)

        # Phase 6: Response Manipulation
        print("\n[*] Phase 6: Response Manipulation Tests")
        manipulation_vulns = self.test_response_manipulation()
        results["tests_run"].append("response_manipulation")
        self.vulnerabilities.extend(manipulation_vulns)

        results["endpoints_analyzed"] = len(self.endpoints)
        results["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]

        # Record tool run in database
        self.db.record_tool_run(
            domain=self.domain,
            tool_name='api_response_analyzer',
            findings_count=len(self.vulnerabilities),
            duration_seconds=int(time.time() - datetime.fromisoformat(results["timestamp"]).timestamp())
        )

        return results

    def analyze_error_patterns(self) -> List[ResponseVulnerability]:
        """Analyze error responses for information disclosure."""
        vulnerabilities = []

        # Error-triggering payloads
        error_payloads = [
            ("", "Empty request"),
            ("null", "Null value"),
            ("undefined", "Undefined"),
            ("[]", "Empty array"),
            ("{}", "Empty object"),
            ('{"id": "\'OR\'1\'=\'1"}', "SQL injection"),
            ('{"id": "../../../etc/passwd"}', "Path traversal"),
            ('{"id": "<script>alert(1)</script>"}', "XSS"),
            ('{"id": -1}', "Negative ID"),
            ('{"id": 999999999}', "Large ID"),
            ('{"id": "' + 'a' * 1000 + '"}', "Oversized input"),
        ]

        for endpoint in self.endpoints[:10]:  # Test first 10 endpoints
            for payload, payload_type in error_payloads:
                try:
                    url = self.base_url + endpoint
                    response = self.session.post(
                        url,
                        data=payload if payload else None,
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )

                    if response.status_code >= 400:
                        # Analyze error response
                        error_vulns = self.analyze_error_response(
                            endpoint, payload_type, response
                        )
                        vulnerabilities.extend(error_vulns)

                except Exception:
                    continue

        return vulnerabilities

    def analyze_error_response(self, endpoint: str, payload_type: str,
                               response: requests.Response) -> List[ResponseVulnerability]:
        """Analyze individual error response."""
        vulnerabilities = []
        error_body = response.text

        # Check for stack traces
        if self.contains_stack_trace(error_body):
            stack_trace = self.extract_stack_trace(error_body)

            vulnerabilities.append(ResponseVulnerability(
                vuln_id="RESP-STACK-001",
                severity=ResponseSeverity.MEDIUM,
                title="Stack Trace Disclosed in Error Response",
                description=f"Endpoint returns detailed stack trace when triggered with {payload_type}, exposing internal application structure and file paths.",
                endpoint=endpoint,
                evidence={
                    "trigger": payload_type,
                    "status_code": response.status_code,
                    "stack_trace_sample": stack_trace[:300]
                },
                remediation="Implement generic error messages for production. Log detailed errors server-side only.",
                cwe="CWE-209",
                cvss_score=5.3
            ))

        # Check for database errors
        db_patterns = [
            (r'SQL.*error', 'SQL syntax error'),
            (r'ORA-\d+', 'Oracle error'),
            (r'MySQL.*error', 'MySQL error'),
            (r'PostgreSQL.*error', 'PostgreSQL error'),
            (r'MongoDB.*error', 'MongoDB error'),
            (r'redis.*error', 'Redis error'),
        ]

        for pattern, db_type in db_patterns:
            if re.search(pattern, error_body, re.IGNORECASE):
                vulnerabilities.append(ResponseVulnerability(
                    vuln_id=f"RESP-DB-{db_type.upper().replace(' ', '_')}",
                    severity=ResponseSeverity.HIGH,
                    title=f"Database Error Disclosure: {db_type}",
                    description=f"Response exposes {db_type} error messages when triggered with {payload_type}, revealing database structure and query details.",
                    endpoint=endpoint,
                    evidence={
                        "trigger": payload_type,
                        "error_sample": error_body[:200],
                        "database_type": db_type
                    },
                    remediation="Catch database exceptions and return generic error messages.",
                    cwe="CWE-209",
                    cvss_score=6.5
                ))
                break

        # Check for file paths
        path_patterns = [
            r'/home/\w+/[^\s]+',
            r'C:\\Users\\[^\s]+',
            r'/var/www/[^\s]+',
            r'/usr/local/[^\s]+',
            r'\\app\\[^\s]+',
        ]

        for pattern in path_patterns:
            match = re.search(pattern, error_body)
            if match:
                file_path = match.group(0)

                vulnerabilities.append(ResponseVulnerability(
                    vuln_id="RESP-PATH-001",
                    severity=ResponseSeverity.LOW,
                    title="Internal File Path Disclosed",
                    description=f"Error response contains internal server file paths when triggered with {payload_type}.",
                    endpoint=endpoint,
                    evidence={
                        "trigger": payload_type,
                        "file_path": file_path
                    },
                    remediation="Remove file paths from error messages.",
                    cwe="CWE-209",
                    cvss_score=3.7
                ))
                break

        # Check for internal IP addresses
        ip_pattern = r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b'
        ip_match = re.search(ip_pattern, error_body)

        if ip_match:
            internal_ip = ip_match.group(0)

            vulnerabilities.append(ResponseVulnerability(
                vuln_id="RESP-IP-001",
                severity=ResponseSeverity.LOW,
                title="Internal IP Address Disclosed",
                description=f"Error response exposes internal network IP address when triggered with {payload_type}.",
                endpoint=endpoint,
                evidence={
                    "trigger": payload_type,
                    "internal_ip": internal_ip
                },
                remediation="Sanitize error messages to remove internal IP addresses.",
                cwe="CWE-200",
                cvss_score=3.7
            ))

        return vulnerabilities

    def contains_stack_trace(self, text: str) -> bool:
        """Check if text contains stack trace."""
        indicators = [
            'traceback',
            'stack trace',
            'at line',
            r'at \w+\.\w+\(',
            r'\.java:\d+',
            r'\.py:\d+',
            r'\.js:\d+',
            'caused by:',
        ]

        return any(re.search(indicator, text, re.IGNORECASE) for indicator in indicators)

    def extract_stack_trace(self, text: str) -> str:
        """Extract stack trace from response."""
        lines = text.split('\n')

        stack_lines = []
        in_stack = False

        for line in lines:
            if any(indicator in line.lower() for indicator in ['traceback', 'stack trace', 'at line']):
                in_stack = True

            if in_stack:
                stack_lines.append(line)

                if len(stack_lines) >= 10:
                    break

        return '\n'.join(stack_lines)

    def audit_security_headers(self) -> List[ResponseVulnerability]:
        """Audit HTTP security headers."""
        vulnerabilities = []

        # Test main endpoint
        test_url = self.base_url + (self.endpoints[0] if self.endpoints else "/")

        try:
            response = self.session.get(test_url, timeout=10)
            headers = response.headers

            # Check for missing security headers
            security_headers = {
                "Strict-Transport-Security": {
                    "severity": ResponseSeverity.HIGH,
                    "description": "HSTS header missing, allowing downgrade attacks",
                    "cvss": 6.5,
                    "cwe": "CWE-319"
                },
                "Content-Security-Policy": {
                    "severity": ResponseSeverity.MEDIUM,
                    "description": "CSP header missing, allowing XSS attacks",
                    "cvss": 5.3,
                    "cwe": "CWE-1021"
                },
                "X-Frame-Options": {
                    "severity": ResponseSeverity.MEDIUM,
                    "description": "X-Frame-Options missing, allowing clickjacking",
                    "cvss": 4.3,
                    "cwe": "CWE-1021"
                },
                "X-Content-Type-Options": {
                    "severity": ResponseSeverity.LOW,
                    "description": "X-Content-Type-Options missing, allowing MIME sniffing",
                    "cvss": 3.7,
                    "cwe": "CWE-16"
                },
                "Referrer-Policy": {
                    "severity": ResponseSeverity.LOW,
                    "description": "Referrer-Policy missing, potentially leaking URLs",
                    "cvss": 3.7,
                    "cwe": "CWE-200"
                },
                "Permissions-Policy": {
                    "severity": ResponseSeverity.INFO,
                    "description": "Permissions-Policy missing, not restricting browser features",
                    "cvss": 2.0,
                    "cwe": "CWE-16"
                }
            }

            for header_name, header_info in security_headers.items():
                if header_name not in headers:
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id=f"RESP-HDR-{header_name.upper().replace('-', '_')}",
                        severity=header_info["severity"],
                        title=f"Missing Security Header: {header_name}",
                        description=header_info["description"],
                        endpoint=test_url,
                        evidence={
                            "headers_present": list(headers.keys())
                        },
                        remediation=f"Add {header_name} header to all responses.",
                        cwe=header_info["cwe"],
                        cvss_score=header_info["cvss"]
                    ))

            # Check for weak CSP
            if "Content-Security-Policy" in headers:
                csp = headers["Content-Security-Policy"]

                if "unsafe-inline" in csp:
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id="RESP-CSP-WEAK",
                        severity=ResponseSeverity.MEDIUM,
                        title="Weak Content-Security-Policy with unsafe-inline",
                        description="CSP allows unsafe-inline, significantly weakening XSS protection.",
                        endpoint=test_url,
                        evidence={
                            "csp": csp
                        },
                        remediation="Remove unsafe-inline from CSP. Use nonces or hashes for inline scripts.",
                        cwe="CWE-1021",
                        cvss_score=5.3
                    ))

            # Check for exposed server version
            if "Server" in headers:
                server_header = headers["Server"]

                # Check if version number is present
                if re.search(r'\d+\.\d+', server_header):
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id="RESP-SERVER-VERSION",
                        severity=ResponseSeverity.LOW,
                        title="Server Version Disclosed in Headers",
                        description=f"Server header exposes version: {server_header}",
                        endpoint=test_url,
                        evidence={
                            "server_header": server_header
                        },
                        remediation="Remove version information from Server header.",
                        cwe="CWE-200",
                        cvss_score=3.7
                    ))

            # Check for X-Powered-By
            if "X-Powered-By" in headers:
                powered_by = headers["X-Powered-By"]

                vulnerabilities.append(ResponseVulnerability(
                    vuln_id="RESP-POWERED-BY",
                    severity=ResponseSeverity.LOW,
                    title="Technology Stack Disclosed in X-Powered-By Header",
                    description=f"X-Powered-By header reveals: {powered_by}",
                    endpoint=test_url,
                    evidence={
                        "x_powered_by": powered_by
                    },
                    remediation="Remove X-Powered-By header.",
                    cwe="CWE-200",
                    cvss_score=3.7
                ))

        except Exception as e:
            print(f"[!] Error auditing headers: {e}")

        return vulnerabilities

    def detect_information_leakage(self) -> List[ResponseVulnerability]:
        """Detect various types of information leakage."""
        vulnerabilities = []

        for endpoint in self.endpoints[:10]:
            try:
                url = self.base_url + endpoint
                response = self.session.get(url, timeout=10)

                body = response.text

                # Check for email addresses
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, body)

                if emails and not endpoint.endswith('/users'):  # Exclude user list endpoints
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id="RESP-INFO-EMAIL",
                        severity=ResponseSeverity.LOW,
                        title="Email Addresses Exposed in Response",
                        description=f"Response contains {len(emails)} email address(es).",
                        endpoint=endpoint,
                        evidence={
                            "email_count": len(emails),
                            "sample": emails[:3]
                        },
                        remediation="Mask or remove unnecessary email addresses from responses.",
                        cwe="CWE-200",
                        cvss_score=3.7
                    ))

                # Check for API keys/tokens
                api_key_patterns = [
                    (r'["\']api[_-]?key["\']:\s*["\']([a-zA-Z0-9_-]{20,})["\']', "API Key"),
                    (r'["\']token["\']:\s*["\']([a-zA-Z0-9_-]{20,})["\']', "Token"),
                    (r'["\']secret["\']:\s*["\']([a-zA-Z0-9_-]{20,})["\']', "Secret"),
                ]

                for pattern, key_type in api_key_patterns:
                    matches = re.findall(pattern, body, re.IGNORECASE)

                    if matches:
                        vulnerabilities.append(ResponseVulnerability(
                            vuln_id=f"RESP-INFO-{key_type.upper().replace(' ', '_')}",
                            severity=ResponseSeverity.CRITICAL,
                            title=f"{key_type} Exposed in Response",
                            description=f"API response contains {key_type} value.",
                            endpoint=endpoint,
                            evidence={
                                "key_type": key_type,
                                "value_preview": matches[0][:10] + "..."
                            },
                            remediation=f"Never expose {key_type} values in API responses.",
                            cwe="CWE-200",
                            cvss_score=9.1
                        ))
                        break

                # Check for version numbers
                version_patterns = [
                    r'["\']version["\']:\s*["\']([0-9.]+)["\']',
                    r'v\d+\.\d+\.\d+',
                    r'["\']build["\']:\s*["\']([a-zA-Z0-9]+)["\']',
                ]

                for pattern in version_patterns:
                    match = re.search(pattern, body, re.IGNORECASE)

                    if match:
                        version = match.group(0)

                        vulnerabilities.append(ResponseVulnerability(
                            vuln_id="RESP-INFO-VERSION",
                            severity=ResponseSeverity.INFO,
                            title="Version Information Disclosed",
                            description=f"Response contains version information: {version}",
                            endpoint=endpoint,
                            evidence={
                                "version": version
                            },
                            remediation="Remove version numbers from public responses.",
                            cwe="CWE-200",
                            cvss_score=2.0
                        ))
                        break

            except Exception:
                continue

        return vulnerabilities

    def analyze_timing(self) -> List[ResponseVulnerability]:
        """Analyze response timing for information leaks."""
        vulnerabilities = []

        # Test user enumeration via timing
        timing_tests = [
            ("existing_user", "admin"),
            ("existing_user", "user@example.com"),
            ("nonexistent", "nonexistent_user_12345"),
            ("nonexistent", "random_98765@example.com"),
        ]

        auth_endpoints = [ep for ep in self.endpoints if 'auth' in ep or 'login' in ep]

        for endpoint in auth_endpoints[:2]:
            timings = defaultdict(list)

            print(f"[*] Timing analysis: {endpoint}")

            for test_type, username in timing_tests:
                for i in range(5):
                    try:
                        url = self.base_url + endpoint
                        payload = {"username": username, "password": "invalid_password"}

                        start = time.time()
                        response = self.session.post(url, json=payload, timeout=10)
                        elapsed = (time.time() - start) * 1000  # ms

                        timings[test_type].append(elapsed)

                    except Exception:
                        continue

            # Analyze timing differences
            if timings["existing_user"] and timings["nonexistent"]:
                avg_existing = statistics.mean(timings["existing_user"])
                avg_nonexistent = statistics.mean(timings["nonexistent"])

                difference = abs(avg_existing - avg_nonexistent)

                # If timing difference > 100ms, user enumeration possible
                if difference > 100:
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id="RESP-TIMING-001",
                        severity=ResponseSeverity.MEDIUM,
                        title="User Enumeration via Response Timing",
                        description=f"Response time differs by {difference:.0f}ms for existing vs non-existing users, allowing enumeration.",
                        endpoint=endpoint,
                        evidence={
                            "avg_existing_ms": round(avg_existing, 2),
                            "avg_nonexistent_ms": round(avg_nonexistent, 2),
                            "difference_ms": round(difference, 2)
                        },
                        remediation="Implement constant-time responses for authentication. Use same code path regardless of user existence.",
                        cwe="CWE-208",
                        cvss_score=5.3
                    ))

        return vulnerabilities

    def check_data_consistency(self) -> List[ResponseVulnerability]:
        """Check for data consistency issues."""
        vulnerabilities = []

        # Test for IDOR via response comparison
        for endpoint in self.endpoints[:5]:
            if '{id}' in endpoint or 'id=' in endpoint:
                try:
                    # Test multiple IDs
                    test_ids = [1, 2, 100, 999999]
                    responses = []

                    for test_id in test_ids:
                        url = self.base_url + endpoint.replace('{id}', str(test_id))
                        if 'id=' in url:
                            url = url.replace('id=', f'id={test_id}')

                        response = self.session.get(url, timeout=10)
                        responses.append({
                            "id": test_id,
                            "status": response.status_code,
                            "length": len(response.text)
                        })

                    # Check for inconsistent responses
                    status_codes = [r["status"] for r in responses]

                    # If 200 for some IDs and 403/404 for others = proper auth
                    # If all 200 or all 404 = potential issue
                    if all(s == 200 for s in status_codes):
                        vulnerabilities.append(ResponseVulnerability(
                            vuln_id="RESP-IDOR-001",
                            severity=ResponseSeverity.HIGH,
                            title="Potential IDOR: All Test IDs Return 200",
                            description="Endpoint returns 200 for all tested IDs, suggesting missing authorization checks.",
                            endpoint=endpoint,
                            evidence={
                                "test_ids": test_ids,
                                "all_successful": True
                            },
                            remediation="Implement proper authorization checks. Verify user owns/can access the resource.",
                            cwe="CWE-639",
                            cvss_score=7.5
                        ))

                except Exception:
                    continue

        return vulnerabilities

    def test_response_manipulation(self) -> List[ResponseVulnerability]:
        """Test for response manipulation vulnerabilities."""
        vulnerabilities = []

        # Test for response splitting
        splitting_payloads = [
            "%0d%0aSet-Cookie:%20malicious=true",
            "\r\nSet-Cookie: malicious=true",
            "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK",
        ]

        test_endpoint = self.endpoints[0] if self.endpoints else "/"

        for payload in splitting_payloads:
            try:
                url = self.base_url + test_endpoint + "?param=" + payload
                response = self.session.get(url, timeout=10, allow_redirects=False)

                # Check if payload reflected in headers
                if "malicious=true" in response.headers.get("Set-Cookie", ""):
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id="RESP-SPLIT-001",
                        severity=ResponseSeverity.HIGH,
                        title="HTTP Response Splitting Vulnerability",
                        description="Application vulnerable to HTTP response splitting via CRLF injection.",
                        endpoint=test_endpoint,
                        evidence={
                            "payload": payload,
                            "set_cookie_header": response.headers.get("Set-Cookie")
                        },
                        remediation="Sanitize all user input. Remove CRLF characters before setting headers.",
                        cwe="CWE-113",
                        cvss_score=7.5
                    ))
                    break

            except Exception:
                continue

        # Test for cache poisoning
        cache_headers = ["X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL"]

        for header in cache_headers:
            try:
                response = self.session.get(
                    self.base_url + test_endpoint,
                    headers={header: "evil.com"},
                    timeout=10
                )

                # Check if poisoned value reflected
                if "evil.com" in response.text or "evil.com" in str(response.headers):
                    vulnerabilities.append(ResponseVulnerability(
                        vuln_id=f"RESP-CACHE-{header.upper().replace('-', '_')}",
                        severity=ResponseSeverity.HIGH,
                        title=f"Cache Poisoning via {header}",
                        description=f"Application reflects {header} header value, potentially allowing cache poisoning.",
                        endpoint=test_endpoint,
                        evidence={
                            "header": header,
                            "poisoned_value": "evil.com",
                            "reflected": True
                        },
                        remediation=f"Don't trust {header} header. Implement proper input validation.",
                        cwe="CWE-444",
                        cvss_score=7.5
                    ))

            except Exception:
                continue

        return vulnerabilities

    def generate_report(self, output_file: str):
        """
        Generate comprehensive response analysis report.

        Args:
            output_file: Path to output JSON file
        """
        report = {
            "target": self.base_url,
            "domain": self.domain,
            "endpoints_analyzed": len(self.endpoints),
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": {
                "critical": len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.CRITICAL]),
                "high": len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.HIGH]),
                "medium": len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.MEDIUM]),
                "low": len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.LOW]),
                "info": len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.INFO]),
            },
            "findings": [v.to_dict() for v in sorted(self.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to: {output_file}")

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of analysis results.

        Returns:
            Summary dictionary with vulnerability counts and statistics
        """
        return {
            'target': self.base_url,
            'domain': self.domain,
            'endpoints_analyzed': len(self.endpoints),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_severity': {
                'critical': len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.CRITICAL]),
                'high': len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.HIGH]),
                'medium': len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.MEDIUM]),
                'low': len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.LOW]),
                'info': len([v for v in self.vulnerabilities if v.severity == ResponseSeverity.INFO]),
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }


# Example usage
if __name__ == "__main__":
    analyzer = APIResponseAnalyzer(
        base_url="https://api.example.com",
        endpoints=["/api/v1/users", "/api/v1/auth/login", "/api/v1/products"]
    )

    results = analyzer.run_comprehensive_analysis()
    analyzer.generate_report("api-response-analysis.json")

    print(f"\n{'='*60}")
    print(f"API Response Analysis Complete")
    print(f"{'='*60}")
    print(f"Endpoints analyzed: {results['endpoints_analyzed']}")
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
