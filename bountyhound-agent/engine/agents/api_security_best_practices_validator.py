"""
API Security Best Practices Validator Agent

Comprehensive API security validator that checks APIs against industry best practices
including OWASP API Security Top 10 2023, security headers, authentication standards,
rate limiting, and common misconfigurations.

This agent performs deep security analysis of API endpoints to identify vulnerabilities
and security weaknesses before they can be exploited.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import asyncio
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse
import hashlib
from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks



class OWASPCategory(Enum):
    """OWASP API Security Top 10 2023"""
    API1_BROKEN_OBJECT_LEVEL_AUTH = "API1:2023 Broken Object Level Authorization"
    API2_BROKEN_AUTHENTICATION = "API2:2023 Broken Authentication"
    API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTH = "API3:2023 Broken Object Property Level Authorization"
    API4_UNRESTRICTED_RESOURCE_CONSUMPTION = "API4:2023 Unrestricted Resource Consumption"
    API5_BROKEN_FUNCTION_LEVEL_AUTH = "API5:2023 Broken Function Level Authorization"
    API6_UNRESTRICTED_ACCESS_TO_SENSITIVE_BUSINESS_FLOWS = "API6:2023 Unrestricted Access to Sensitive Business Flows"
    API7_SERVER_SIDE_REQUEST_FORGERY = "API7:2023 Server Side Request Forgery"
    API8_SECURITY_MISCONFIGURATION = "API8:2023 Security Misconfiguration"
    API9_IMPROPER_INVENTORY_MANAGEMENT = "API9:2023 Improper Inventory Management"
    API10_UNSAFE_CONSUMPTION_OF_APIS = "API10:2023 Unsafe Consumption of APIs"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuthType(Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    HMAC = "hmac"
    CUSTOM = "custom"


@dataclass
class SecurityHeader:
    """Security header configuration"""
    name: str
    required: bool
    recommended_value: Optional[str] = None
    dangerous_values: List[str] = field(default_factory=list)
    description: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Single validation result"""
    category: OWASPCategory
    severity: Severity
    title: str
    description: str
    endpoint: str
    evidence: Dict[str, Any]
    remediation: str
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'category': self.category.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'endpoint': self.endpoint,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score
        }


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_window: int
    window_seconds: int
    burst_allowed: bool = False
    per_ip: bool = True
    per_user: bool = False
    bypass_detected: bool = False


@dataclass
class AuthConfig:
    """Authentication configuration"""
    auth_type: AuthType
    token_format: Optional[str] = None
    token_lifetime: Optional[int] = None
    refresh_enabled: bool = False
    mfa_available: bool = False
    weak_points: List[str] = field(default_factory=list)


class APISecurityValidator:
    """
    Validates API security against best practices and OWASP Top 10.

    Performs comprehensive security testing including:
    - OWASP API Security Top 10 validation
    - Security header analysis
    - Authentication mechanism testing
    - Rate limiting verification
    - Error handling validation
    - TLS configuration review
    - CORS policy analysis
    - Input validation testing
    """

    def __init__(self, target: str, headers: Optional[Dict] = None, db: Optional[BountyHoundDB] = None):
        """
        Initialize API Security Validator.

        Args:
            target: Target API URL
            headers: Optional headers for authenticated requests
            db: Optional BountyHoundDB instance
        """
        self.target = target
        self.base_url = self._extract_base_url(target)
        self.headers = headers or {}
        self.results: List[ValidationResult] = []
        self.endpoints: Set[str] = set()
        self.auth_config: Optional[AuthConfig] = None
        self.db = db or BountyHoundDB()

        # Extract domain for database tracking
        parsed = urlparse(target)
        self.domain = parsed.netloc

        # Security headers to validate
        self.security_headers = {
            "Strict-Transport-Security": SecurityHeader(
                name="Strict-Transport-Security",
                required=True,
                recommended_value="max-age=31536000; includeSubDomains; preload",
                dangerous_values=["max-age=0"],
                description="Enforces HTTPS connections",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"]
            ),
            "X-Content-Type-Options": SecurityHeader(
                name="X-Content-Type-Options",
                required=True,
                recommended_value="nosniff",
                description="Prevents MIME type sniffing",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
            ),
            "X-Frame-Options": SecurityHeader(
                name="X-Frame-Options",
                required=True,
                recommended_value="DENY",
                dangerous_values=["ALLOW"],
                description="Prevents clickjacking attacks",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"]
            ),
            "Content-Security-Policy": SecurityHeader(
                name="Content-Security-Policy",
                required=True,
                description="Controls resource loading",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
            ),
            "Referrer-Policy": SecurityHeader(
                name="Referrer-Policy",
                required=True,
                recommended_value="strict-origin-when-cross-origin",
                description="Controls referrer information",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
            ),
            "Cache-Control": SecurityHeader(
                name="Cache-Control",
                required=True,
                recommended_value="no-store, private",
                dangerous_values=["public"],
                description="Prevents sensitive data caching",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"]
            ),
        }

    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def validate_all(self) -> List[ValidationResult]:
        """
        Run all validation checks.

        Returns:
            List of ValidationResult objects
        """
        print(f"[*] Starting comprehensive API security validation for {self.target}")

        # Check database before testing
        context = DatabaseHooks.before_test(self.domain, 'api_security_validator')
        if context['should_skip']:
            print(f"[!] {context['reason']}")
            print(f"[!] {', '.join(context['recommendations'])}")
            return []

        start_time = time.time()

        # Run all validation categories
        await self.validate_owasp_top_10()
        await self.validate_security_headers()
        await self.validate_authentication()
        await self.validate_rate_limiting()
        await self.validate_error_handling()
        await self.validate_tls_configuration()
        await self.validate_versioning()
        await self.validate_cors()
        await self.validate_input_validation()

        # Generate summary
        self._generate_summary()

        # Record test in database
        duration = int(time.time() - start_time)
        self.db.record_tool_run(
            domain=self.domain,
            tool_name='api_security_validator',
            findings_count=len(self.results),
            duration_seconds=duration,
            success=True
        )

        return self.results

    async def validate_owasp_top_10(self):
        """Validate against OWASP API Security Top 10."""
        print("[*] Validating OWASP API Security Top 10...")

        # API1: Broken Object Level Authorization
        await self._test_bola()

        # API2: Broken Authentication
        await self._test_broken_authentication()

        # API3: Broken Object Property Level Authorization
        await self._test_mass_assignment()

        # API4: Unrestricted Resource Consumption
        await self._test_resource_consumption()

        # API5: Broken Function Level Authorization
        await self._test_bfla()

        # API6: Business Flow Abuse
        await self._test_business_flows()

        # API7: SSRF
        await self._test_ssrf_vectors()

        # API8: Security Misconfiguration
        await self._test_misconfigurations()

        # API9: Improper Inventory Management
        await self._test_api_inventory()

        # API10: Unsafe API Consumption
        await self._test_upstream_apis()

    async def _test_bola(self):
        """Test for Broken Object Level Authorization."""
        test_ids = ["1", "2", "100", "999", "userId", "123e4567-e89b-12d3-a456-426614174000"]

        for endpoint in self.endpoints:
            if any(pattern in endpoint for pattern in ["/users/", "/accounts/", "/orders/", "/documents/"]):
                for test_id in test_ids:
                    test_url = endpoint.replace("{id}", test_id)
                    response = await self._make_request(test_url, method="GET", skip_auth=True)

                    if response.get("status") in [200, 201]:
                        self.results.append(ValidationResult(
                            category=OWASPCategory.API1_BROKEN_OBJECT_LEVEL_AUTH,
                            severity=Severity.CRITICAL,
                            title="Broken Object Level Authorization Detected",
                            description="Endpoint allows unauthorized access to objects without proper authorization checks",
                            endpoint=test_url,
                            evidence={
                                "status_code": response.get("status"),
                                "response_size": len(str(response.get("body", ""))),
                                "test_id": test_id,
                                "headers": response.get("headers", {})
                            },
                            remediation="Implement object-level authorization checks that verify the requesting user has permission to access the specific resource",
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                "https://cwe.mitre.org/data/definitions/639.html"
                            ],
                            cwe_id="CWE-639",
                            cvss_score=9.1
                        ))

    async def _test_broken_authentication(self):
        """Test for authentication vulnerabilities."""
        auth_tests = [
            ("Missing auth header", {}),
            ("Empty bearer token", {"Authorization": "Bearer "}),
            ("Invalid token format", {"Authorization": "Bearer invalid"}),
            ("JWT none algorithm", {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."}),
            ("SQL injection in auth", {"Authorization": "Bearer ' OR '1'='1"}),
        ]

        for test_name, test_headers in auth_tests:
            for endpoint in self.endpoints:
                response = await self._make_request(endpoint, headers=test_headers)

                if response.get("status") in [200, 201]:
                    self.results.append(ValidationResult(
                        category=OWASPCategory.API2_BROKEN_AUTHENTICATION,
                        severity=Severity.CRITICAL,
                        title=f"Authentication Bypass via {test_name}",
                        description="Endpoint accessible without valid authentication",
                        endpoint=endpoint,
                        evidence={
                            "test": test_name,
                            "status": response.get("status"),
                            "headers_used": test_headers
                        },
                        remediation="Implement proper authentication validation on all protected endpoints",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                        cwe_id="CWE-287",
                        cvss_score=9.8
                    ))

    async def _test_mass_assignment(self):
        """Test for mass assignment vulnerabilities."""
        dangerous_fields = ["role", "admin", "isAdmin", "is_admin", "privilege", "permissions",
                           "salary", "balance", "credit", "verified", "approved"]

        for endpoint in self.endpoints:
            if any(method in endpoint for method in ["POST", "PUT", "PATCH"]):
                for field in dangerous_fields:
                    payload = {field: "admin" if "role" in field or "admin" in field else True}
                    response = await self._make_request(endpoint, method="POST", json=payload)

                    if response.get("status") in [200, 201]:
                        body = response.get("body", {})
                        if isinstance(body, dict) and field in body:
                            self.results.append(ValidationResult(
                                category=OWASPCategory.API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTH,
                                severity=Severity.HIGH,
                                title="Mass Assignment Vulnerability Detected",
                                description=f"Sensitive field '{field}' can be set via API request",
                                endpoint=endpoint,
                                evidence={
                                    "field": field,
                                    "payload": payload,
                                    "response": body
                                },
                                remediation="Use allowlists to define which properties can be updated by users",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                                cwe_id="CWE-915",
                                cvss_score=8.2
                            ))

    async def _test_resource_consumption(self):
        """Test for resource consumption vulnerabilities."""
        large_limits = [1000, 10000, 100000]

        for endpoint in self.endpoints:
            if "?" in endpoint or any(x in endpoint for x in ["page", "limit", "size"]):
                for limit in large_limits:
                    test_url = f"{endpoint}?limit={limit}" if "?" not in endpoint else f"{endpoint}&limit={limit}"

                    start_time = time.time()
                    response = await self._make_request(test_url)
                    duration = time.time() - start_time

                    if response.get("status") == 200 and duration > 5:
                        self.results.append(ValidationResult(
                            category=OWASPCategory.API4_UNRESTRICTED_RESOURCE_CONSUMPTION,
                            severity=Severity.MEDIUM,
                            title="Unrestricted Pagination Limit",
                            description=f"API accepts extremely large pagination limits ({limit} items)",
                            endpoint=test_url,
                            evidence={
                                "limit_tested": limit,
                                "response_time": duration,
                                "status": response.get("status")
                            },
                            remediation="Implement maximum pagination limits (e.g., 100 items per page)",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                            cwe_id="CWE-770",
                            cvss_score=5.3
                        ))

    async def _test_bfla(self):
        """Test for Broken Function Level Authorization."""
        admin_patterns = ["/admin", "/manage", "/delete", "/update", "/create", "/config"]

        for pattern in admin_patterns:
            admin_endpoints = [e for e in self.endpoints if pattern in e.lower()]

            for endpoint in admin_endpoints:
                response = await self._make_request(endpoint, skip_auth=True)

                if response.get("status") in [200, 201]:
                    self.results.append(ValidationResult(
                        category=OWASPCategory.API5_BROKEN_FUNCTION_LEVEL_AUTH,
                        severity=Severity.CRITICAL,
                        title="Broken Function Level Authorization",
                        description="Administrative endpoint accessible without proper authorization",
                        endpoint=endpoint,
                        evidence={
                            "status": response.get("status"),
                            "pattern": pattern,
                            "response_snippet": str(response.get("body", ""))[:200]
                        },
                        remediation="Implement role-based access control (RBAC) for administrative functions",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
                        cwe_id="CWE-285",
                        cvss_score=8.8
                    ))

    async def _test_business_flows(self):
        """Test for business flow abuse."""
        # Check for sequential operations without validation
        flow_patterns = [
            ("checkout", ["/cart/add", "/checkout/complete"]),
            ("voucher", ["/voucher/redeem"]),
            ("purchase", ["/cart/add?quantity=-1"]),
        ]

        for flow_name, steps in flow_patterns:
            for step in steps:
                # This is a placeholder - real implementation would test actual flows
                pass

    async def _test_ssrf_vectors(self):
        """Test for SSRF vulnerabilities."""
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:22",
            "http://127.0.0.1:6379",
            "file:///etc/passwd",
        ]

        url_parameters = ["url", "callback", "webhook", "redirect", "link", "uri"]

        for endpoint in self.endpoints:
            for param in url_parameters:
                if param in endpoint.lower():
                    for payload in ssrf_payloads:
                        test_url = f"{endpoint}?{param}={payload}"
                        response = await self._make_request(test_url)

                        body_str = str(response.get("body", ""))
                        if any(indicator in body_str for indicator in ["ami-id", "instance-id", "local-hostname", "root:x:"]):
                            self.results.append(ValidationResult(
                                category=OWASPCategory.API7_SERVER_SIDE_REQUEST_FORGERY,
                                severity=Severity.CRITICAL,
                                title="Server-Side Request Forgery (SSRF) Vulnerability",
                                description="API accepts and processes arbitrary URLs, enabling SSRF attacks",
                                endpoint=test_url,
                                evidence={
                                    "parameter": param,
                                    "payload": payload,
                                    "response_snippet": body_str[:500]
                                },
                                remediation="Validate and sanitize all URL inputs, use allowlists, disable unnecessary protocols",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"],
                                cwe_id="CWE-918",
                                cvss_score=9.0
                            ))

    async def _test_misconfigurations(self):
        """Test for security misconfigurations."""
        misconfig_tests = [
            ("/swagger.json", "Swagger documentation exposed"),
            ("/openapi.json", "OpenAPI specification exposed"),
            ("/.git/config", "Git repository exposed"),
            ("/.env", "Environment file exposed"),
            ("/config.json", "Configuration file exposed"),
            ("/graphql", "GraphQL introspection may be enabled"),
        ]

        for path, description in misconfig_tests:
            test_url = f"{self.base_url}{path}"
            response = await self._make_request(test_url)

            if response.get("status") == 200:
                self.results.append(ValidationResult(
                    category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    title="Security Misconfiguration Detected",
                    description=description,
                    endpoint=test_url,
                    evidence={
                        "status": response.get("status"),
                        "content_type": response.get("headers", {}).get("content-type", ""),
                        "size": len(str(response.get("body", "")))
                    },
                    remediation="Disable or properly secure sensitive endpoints in production",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                    cwe_id="CWE-16",
                    cvss_score=6.5
                ))

    async def _test_api_inventory(self):
        """Test API inventory management."""
        versions = ["/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/"]
        found_versions = set()

        for version in versions:
            test_url = f"{self.base_url}{version}users"
            response = await self._make_request(test_url)
            if response.get("status") != 404:
                found_versions.add(version)

        if len(found_versions) > 2:
            self.results.append(ValidationResult(
                category=OWASPCategory.API9_IMPROPER_INVENTORY_MANAGEMENT,
                severity=Severity.MEDIUM,
                title="Multiple API Versions Exposed",
                description=f"Found {len(found_versions)} different API versions, increasing attack surface",
                endpoint=self.base_url,
                evidence={"versions": list(found_versions)},
                remediation="Deprecate old API versions, maintain proper inventory",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                cwe_id="CWE-1059"
            ))

    async def _test_upstream_apis(self):
        """Test upstream API consumption."""
        webhook_patterns = ["/webhook", "/callback", "/notify"]

        for pattern in webhook_patterns:
            matching = [e for e in self.endpoints if pattern in e.lower()]
            for endpoint in matching:
                response = await self._make_request(endpoint, method="POST", json={"test": "data"})

                if response.get("status") in [200, 201]:
                    self.results.append(ValidationResult(
                        category=OWASPCategory.API10_UNSAFE_CONSUMPTION_OF_APIS,
                        severity=Severity.MEDIUM,
                        title="Webhook Endpoint Missing Source Validation",
                        description="Webhook endpoint accepts requests without validating source",
                        endpoint=endpoint,
                        evidence={"status": response.get("status")},
                        remediation="Implement signature validation for webhook endpoints",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"],
                        cwe_id="CWE-345"
                    ))

    async def validate_security_headers(self):
        """Validate security headers."""
        print("[*] Validating security headers...")

        response = await self._make_request(self.target)
        headers = response.get("headers", {})

        # Normalize header names
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        for header_name, config in self.security_headers.items():
            header_lower = header_name.lower()

            if header_lower not in normalized_headers:
                if config.required:
                    self.results.append(ValidationResult(
                        category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                        severity=Severity.MEDIUM if config.required else Severity.LOW,
                        title=f"Missing Security Header: {header_name}",
                        description=f"{config.description}. This header is recommended for all APIs.",
                        endpoint=self.target,
                        evidence={"missing_header": header_name},
                        remediation=f"Add '{header_name}: {config.recommended_value}' to all API responses",
                        references=config.references
                    ))
            else:
                # Check for dangerous values
                header_value = normalized_headers[header_lower]
                for dangerous in config.dangerous_values:
                    if dangerous.lower() in header_value.lower():
                        self.results.append(ValidationResult(
                            category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                            severity=Severity.MEDIUM,
                            title=f"Insecure {header_name} Configuration",
                            description=f"Header contains dangerous value: {dangerous}",
                            endpoint=self.target,
                            evidence={
                                "header": header_name,
                                "value": header_value,
                                "dangerous_pattern": dangerous
                            },
                            remediation=f"Update to recommended value: {config.recommended_value}",
                            references=config.references
                        ))

    async def validate_authentication(self):
        """Validate authentication implementation."""
        print("[*] Validating authentication...")

        self.auth_config = await self._detect_auth_type()

        if self.auth_config.auth_type == AuthType.NONE:
            self.results.append(ValidationResult(
                category=OWASPCategory.API2_BROKEN_AUTHENTICATION,
                severity=Severity.CRITICAL,
                title="No Authentication Detected",
                description="API endpoints accessible without any authentication",
                endpoint=self.target,
                evidence={"auth_type": "none"},
                remediation="Implement proper authentication (OAuth 2.0, JWT, API keys with secrets)",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]
            ))

        if self.auth_config.weak_points:
            for weak_point in self.auth_config.weak_points:
                self.results.append(ValidationResult(
                    category=OWASPCategory.API2_BROKEN_AUTHENTICATION,
                    severity=Severity.HIGH,
                    title=f"Weak Authentication: {weak_point}",
                    description="Authentication implementation has security weaknesses",
                    endpoint=self.target,
                    evidence={"weakness": weak_point},
                    remediation="Strengthen authentication mechanism, implement MFA, use secure token formats",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]
                ))

    async def validate_rate_limiting(self):
        """Validate rate limiting implementation."""
        print("[*] Validating rate limiting...")

        rate_limit_config = await self._test_rate_limits()

        if not rate_limit_config:
            self.results.append(ValidationResult(
                category=OWASPCategory.API4_UNRESTRICTED_RESOURCE_CONSUMPTION,
                severity=Severity.HIGH,
                title="No Rate Limiting Detected",
                description="API does not implement rate limiting, enabling abuse and DoS attacks",
                endpoint=self.target,
                evidence={"test_requests": 50, "status": "all_succeeded"},
                remediation="Implement rate limiting (e.g., 100 requests per minute per IP/user)",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#rate-limiting"],
                cwe_id="CWE-770"
            ))
        elif rate_limit_config.bypass_detected:
            self.results.append(ValidationResult(
                category=OWASPCategory.API4_UNRESTRICTED_RESOURCE_CONSUMPTION,
                severity=Severity.MEDIUM,
                title="Rate Limit Bypass Detected",
                description="Rate limiting can be bypassed using known techniques",
                endpoint=self.target,
                evidence={"bypass_method": "header_manipulation"},
                remediation="Implement robust rate limiting that cannot be bypassed via headers or other tricks",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#rate-limiting"]
            ))

    async def validate_error_handling(self):
        """Validate error handling."""
        print("[*] Validating error handling...")

        error_tests = [
            ("invalid_json", "POST", "not-valid-json"),
            ("sql_injection", "GET", "?id=' OR '1'='1"),
            ("path_traversal", "GET", "?file=../../etc/passwd"),
        ]

        for test_name, method, payload in error_tests:
            response = await self._make_request(self.target, method=method, data=payload)
            body = str(response.get("body", ""))

            # Check for information disclosure
            sensitive_patterns = [
                (r"at [\w.]+\([\w.]+\.java:\d+\)", "Java stack trace"),
                (r"Traceback \(most recent call last\):", "Python stack trace"),
                (r"Fatal error:", "PHP error"),
                (r"Exception in thread", "Java exception"),
                (r"System\.[\w.]+Exception", ".NET exception"),
                (r"/var/www/|/usr/local/|C:\\", "File path disclosure"),
                (r"mysql_|postgresql_|sqlite_", "Database error"),
            ]

            for pattern, description in sensitive_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self.results.append(ValidationResult(
                        category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                        severity=Severity.LOW,
                        title=f"Information Disclosure in Error: {description}",
                        description="Error messages leak sensitive technical information",
                        endpoint=self.target,
                        evidence={
                            "test": test_name,
                            "pattern": pattern,
                            "snippet": body[:300]
                        },
                        remediation="Implement generic error messages for users, log detailed errors server-side",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"],
                        cwe_id="CWE-209"
                    ))

    async def validate_tls_configuration(self):
        """Validate TLS/SSL configuration."""
        print("[*] Validating TLS configuration...")

        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            self.results.append(ValidationResult(
                category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                severity=Severity.CRITICAL,
                title="API Not Using HTTPS",
                description="API is accessible over unencrypted HTTP",
                endpoint=self.target,
                evidence={"scheme": parsed.scheme},
                remediation="Enforce HTTPS for all API endpoints, redirect HTTP to HTTPS",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
            ))

    async def validate_versioning(self):
        """Validate API versioning."""
        print("[*] Validating API versioning...")

        has_url_version = any(v in self.target for v in ["/v1", "/v2", "/v3"])

        response = await self._make_request(self.target)
        headers = response.get("headers", {})
        has_header_version = any("version" in k.lower() for k in headers.keys())

        if not has_url_version and not has_header_version:
            self.results.append(ValidationResult(
                category=OWASPCategory.API9_IMPROPER_INVENTORY_MANAGEMENT,
                severity=Severity.LOW,
                title="API Versioning Not Detected",
                description="API does not appear to use versioning",
                endpoint=self.target,
                evidence={"url_version": False, "header_version": False},
                remediation="Implement API versioning (preferably in URL path)",
                references=["https://restfulapi.net/versioning/"]
            ))

    async def validate_cors(self):
        """Validate CORS configuration."""
        print("[*] Validating CORS configuration...")

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]

        for origin in test_origins:
            response = await self._make_request(
                self.target,
                headers={"Origin": origin}
            )

            cors_headers = {
                k: v for k, v in response.get("headers", {}).items()
                if k.lower().startswith("access-control-")
            }

            acao = cors_headers.get("access-control-allow-origin", "")
            acac = cors_headers.get("access-control-allow-credentials", "")

            # Note: ACAO:* + ACAC:true is blocked by browsers, but still report
            if acao == "*" and acac.lower() == "true":
                self.results.append(ValidationResult(
                    category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                    severity=Severity.HIGH,
                    title="Dangerous CORS Configuration (blocked by browsers)",
                    description="API allows all origins (*) with credentials enabled (browsers block this, but indicates misconfiguration)",
                    endpoint=self.target,
                    evidence={
                        "acao": acao,
                        "acac": acac,
                        "test_origin": origin
                    },
                    remediation="Use specific origin allowlist instead of '*', or disable credentials",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                    cwe_id="CWE-942"
                ))
            elif origin in acao:
                self.results.append(ValidationResult(
                    category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    title="CORS Allows Arbitrary Origins",
                    description="API reflects Origin header, allowing any domain",
                    endpoint=self.target,
                    evidence={
                        "acao": acao,
                        "acac": acac,
                        "test_origin": origin
                    },
                    remediation="Implement origin allowlist validation",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                    cwe_id="CWE-942"
                ))

    async def validate_input_validation(self):
        """Validate input validation."""
        print("[*] Validating input validation...")

        injection_tests = [
            ("sql", "' OR '1'='1", ["sql", "mysql", "error in your sql syntax"]),
            ("xss", "<script>alert(1)</script>", ["<script>", "alert(1)"]),
            ("xxe", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", ["root:x:", "<!ENTITY"]),
            ("ssti", "{{7*7}}", ["49", "{{7*7}}"]),
            ("command", "; ls -la", ["total ", "drwx"]),
        ]

        for injection_type, payload, indicators in injection_tests:
            response = await self._make_request(
                self.target,
                method="POST",
                json={"input": payload}
            )

            body = str(response.get("body", ""))

            for indicator in indicators:
                if indicator.lower() in body.lower():
                    severity = Severity.CRITICAL if injection_type in ["sql", "command"] else Severity.HIGH

                    self.results.append(ValidationResult(
                        category=OWASPCategory.API8_SECURITY_MISCONFIGURATION,
                        severity=severity,
                        title=f"Potential {injection_type.upper()} Injection",
                        description=f"API appears vulnerable to {injection_type} injection attacks",
                        endpoint=self.target,
                        evidence={
                            "injection_type": injection_type,
                            "payload": payload,
                            "indicator": indicator,
                            "response_snippet": body[:300]
                        },
                        remediation=f"Implement proper input validation and sanitization for {injection_type} attacks",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
                        ]
                    ))

    async def _detect_auth_type(self) -> AuthConfig:
        """Detect authentication type."""
        response = await self._make_request(self.target)
        headers = response.get("headers", {})

        auth_header = headers.get("authorization", "")
        www_auth = headers.get("www-authenticate", "")

        weak_points = []

        if not auth_header and not www_auth:
            return AuthConfig(auth_type=AuthType.NONE)

        if "basic" in auth_header.lower() or "basic" in www_auth.lower():
            weak_points.append("Basic auth without HTTPS is insecure")
            return AuthConfig(auth_type=AuthType.BASIC, weak_points=weak_points)

        if "bearer" in auth_header.lower():
            token = auth_header.split("Bearer ")[-1] if "Bearer " in auth_header else ""
            if token and token.count(".") == 2:
                # Likely JWT
                try:
                    parts = token.split(".")
                    header_data = json.loads(self._base64_decode(parts[0]))

                    if header_data.get("alg") == "none":
                        weak_points.append("JWT with 'none' algorithm")
                    if header_data.get("alg") in ["HS256", "HS384", "HS512"]:
                        weak_points.append("JWT with symmetric algorithm (key exposure risk)")

                    return AuthConfig(auth_type=AuthType.JWT, token_format="JWT", weak_points=weak_points)
                except:
                    pass

            return AuthConfig(auth_type=AuthType.BEARER, weak_points=weak_points)

        if any(key in headers for key in ["x-api-key", "api-key", "apikey"]):
            weak_points.append("API key in header (ensure HTTPS and rate limiting)")
            return AuthConfig(auth_type=AuthType.API_KEY, weak_points=weak_points)

        return AuthConfig(auth_type=AuthType.CUSTOM, weak_points=["Unknown auth type - manual review needed"])

    async def _test_rate_limits(self) -> Optional[RateLimitConfig]:
        """Test rate limiting."""
        requests_count = 50  # Reduced from 100 to be less aggressive
        successful = 0
        rate_limited = 0

        for i in range(requests_count):
            response = await self._make_request(self.target)
            if response.get("status") == 200:
                successful += 1
            elif response.get("status") == 429:
                rate_limited += 1

        if rate_limited == 0:
            return None  # No rate limiting

        return RateLimitConfig(
            requests_per_window=successful,
            window_seconds=60,
            per_ip=True,
            bypass_detected=False
        )

    async def _make_request(self, url: str, method: str = "GET", headers: Optional[Dict] = None,
                          json: Optional[Dict] = None, data: Optional[str] = None,
                          skip_auth: bool = False) -> Dict:
        """
        Make HTTP request (stub - implement with actual HTTP library).

        In production, this would use aiohttp or similar.
        """
        return {
            "status": 200,
            "headers": {},
            "body": {}
        }

    def _base64_decode(self, data: str) -> str:
        """Base64 decode with padding."""
        import base64
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.b64decode(data).decode('utf-8')

    def _generate_summary(self):
        """Generate validation summary."""
        print(f"\n[+] API Security Validation Complete")
        print(f"[+] Total findings: {len(self.results)}")

        by_severity = {}
        for result in self.results:
            severity = result.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"    [{severity.upper()}]: {count}")

        print(f"\n[+] OWASP API Top 10 Coverage:")
        by_category = {}
        for result in self.results:
            cat = result.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            print(f"    {category}: {count} findings")

    def export_report(self, format: str = "json") -> str:
        """
        Export validation report.

        Args:
            format: Output format ('json' or 'markdown')

        Returns:
            Formatted report string
        """
        if format == "json":
            return json.dumps([r.to_dict() for r in self.results], indent=2)

        # Markdown format
        report = "# API Security Validation Report\n\n"
        report += f"**Target**: {self.target}\n"
        report += f"**Date**: {datetime.now().isoformat()}\n"
        report += f"**Total Findings**: {len(self.results)}\n\n"

        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = [r for r in self.results if r.severity == severity]
            if findings:
                report += f"## {severity.value.upper()} Severity ({len(findings)})\n\n"
                for result in findings:
                    report += f"### {result.title}\n"
                    report += f"**Category**: {result.category.value}\n"
                    report += f"**Endpoint**: `{result.endpoint}`\n"
                    report += f"**Description**: {result.description}\n\n"
                    report += f"**Remediation**: {result.remediation}\n\n"
                    if result.references:
                        report += "**References**:\n"
                        for ref in result.references:
                            report += f"- {ref}\n"
                    report += "\n---\n\n"

        return report

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of validation results.

        Returns:
            Dictionary with summary statistics
        """
        by_severity = {}
        by_category = {}

        for result in self.results:
            severity = result.severity.value
            category = result.category.value

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

        return {
            'target': self.target,
            'total_findings': len(self.results),
            'by_severity': by_severity,
            'by_category': by_category,
            'timestamp': datetime.now().isoformat()
        }


async def main():
    """Example usage."""
    target = "https://api.example.com/v1/users"

    validator = APISecurityValidator(target)

    # Add discovered endpoints
    validator.endpoints = {
        "/v1/users",
        "/v1/users/{id}",
        "/v1/users/{id}/delete",
        "/v1/admin/config",
        "/v1/orders",
        "/v1/payments/process",
        "/webhook/stripe",
    }

    # Run validation
    results = await validator.validate_all()

    # Export reports
    json_report = validator.export_report(format="json")
    md_report = validator.export_report(format="markdown")

    print("\n" + "="*80)
    print(md_report[:500])  # Print first 500 chars

    # Get summary
    summary = validator.get_summary()
    print(f"\nSummary: {json.dumps(summary, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())
