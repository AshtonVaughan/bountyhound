"""
API Schema Analyzer Agent

Advanced API schema analysis agent for OpenAPI/Swagger specification parsing,
GraphQL schema introspection, REST API endpoint discovery, parameter type analysis,
and hidden endpoint detection. Identifies schema validation bypasses, required vs
optional field misconfigurations, and discovers undocumented endpoints through
multiple enumeration techniques.

Average bounty: $2K-$15K per schema vulnerability
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import time
import json
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse
import requests
from requests.exceptions import Timeout, RequestException


try:
    import yaml
except ImportError:
    yaml = None


class SchemaType(Enum):
    """Enumeration of supported schema types."""
    OPENAPI_2 = "openapi_2.0"
    OPENAPI_3 = "openapi_3.0"
    OPENAPI_31 = "openapi_3.1"
    GRAPHQL = "graphql"
    REST_UNDOCUMENTED = "rest_undocumented"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SchemaEndpoint:
    """Represents a discovered API endpoint."""
    path: str
    method: str
    parameters: List[Dict[str, Any]]
    required_params: List[str]
    optional_params: List[str]
    security_schemes: List[str]
    response_schemas: Dict[int, Dict]
    deprecated: bool = False
    hidden: bool = False
    version: Optional[str] = None


@dataclass
class GraphQLField:
    """Represents a GraphQL field."""
    name: str
    type: str
    args: List[Dict[str, Any]]
    description: Optional[str]
    is_deprecated: bool
    deprecation_reason: Optional[str]


@dataclass
class SchemaVulnerability:
    """Represents a schema vulnerability finding."""
    vuln_id: str
    severity: SeverityLevel
    title: str
    description: str
    endpoint: str
    payload: str
    evidence: Dict[str, Any]
    remediation: str
    bounty_estimate: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vuln_id': self.vuln_id,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'endpoint': self.endpoint,
            'payload': self.payload,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'bounty_estimate': self.bounty_estimate
        }


class APISchemaAnalyzer:
    """
    Advanced API schema analyzer for discovering vulnerabilities in API specifications
    and implementations across OpenAPI, Swagger, and GraphQL formats.
    """

    def __init__(self, target_url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None):
        """
        Initialize API Schema Analyzer.

        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
            headers: Optional HTTP headers
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.headers = headers or {
            'User-Agent': 'BountyHound/5.0',
            'Accept': 'application/json, text/yaml, */*'
        }
        self.vulnerabilities: List[SchemaVulnerability] = []
        self.discovered_endpoints: List[SchemaEndpoint] = []
        self.graphql_schema: Optional[Dict] = None
        self.openapi_spec: Optional[Dict] = None
        self.schema_type: SchemaType = SchemaType.UNKNOWN

        # Common OpenAPI/Swagger paths
        self.spec_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api/openapi.json',
            '/api/openapi.yaml',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/v3/swagger.json',
            '/api-docs',
            '/api/docs',
            '/docs/swagger.json',
            '/swagger/v1/swagger.json',
            '/swagger/v2/swagger.json',
            '/api/v1/openapi.json',
            '/api/v2/openapi.json',
            '/redoc.json',
            '/api.json',
            '/api.yaml',
            '/docs.json',
            '/docs.yaml'
        ]

        # Common GraphQL paths
        self.graphql_paths = [
            '/graphql',
            '/api/graphql',
            '/v1/graphql',
            '/v2/graphql',
            '/query',
            '/api/query',
            '/gql',
            '/api/gql'
        ]

        # GraphQL introspection query (simplified for testing)
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  name
                  description
                  type { name kind }
                }
                type { name kind }
                isDeprecated
                deprecationReason
              }
            }
          }
        }
        """

    def analyze(self) -> List[SchemaVulnerability]:
        """
        Main analysis entry point.

        Returns:
            List of discovered schema vulnerabilities
        """
        print(f"[*] Starting API schema analysis for {self.target_url}")

        # Phase 1: Schema Discovery
        self.discover_schemas()

        # Phase 2: Schema-specific analysis
        if self.schema_type in [SchemaType.OPENAPI_2, SchemaType.OPENAPI_3, SchemaType.OPENAPI_31]:
            self.analyze_openapi_schema()
        elif self.schema_type == SchemaType.GRAPHQL:
            self.analyze_graphql_schema()

        # Phase 3: Hidden endpoint discovery
        self.discover_hidden_endpoints()

        # Phase 4: Validation bypass testing
        self.test_validation_bypasses()

        # Phase 5: Type confusion testing
        self.test_type_confusion()

        # Phase 6: Version enumeration
        self.enumerate_api_versions()

        return self.vulnerabilities

    def discover_schemas(self) -> bool:
        """
        Discover API schema specifications.

        Returns:
            True if schema found, False otherwise
        """
        print("[*] Phase 1: Schema Discovery")

        # Try OpenAPI/Swagger paths
        for path in self.spec_paths:
            url = urljoin(self.target_url, path)
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout)

                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')

                    if 'json' in content_type or path.endswith('.json'):
                        try:
                            self.openapi_spec = response.json()
                        except ValueError:
                            continue
                    elif yaml and ('yaml' in content_type or path.endswith('.yaml')):
                        try:
                            self.openapi_spec = yaml.safe_load(response.text)
                        except Exception:
                            continue

                    if self.openapi_spec:
                        self.detect_openapi_version()
                        print(f"[+] Found OpenAPI spec at {url} (Type: {self.schema_type.value})")
                        return True
            except Exception:
                continue

        # Try GraphQL paths if no OpenAPI found
        for path in self.graphql_paths:
            url = urljoin(self.target_url, path)
            if self.test_graphql_introspection(url):
                self.schema_type = SchemaType.GRAPHQL
                print(f"[+] Found GraphQL endpoint at {url}")
                return True

        return False

    def detect_openapi_version(self) -> None:
        """Detect OpenAPI specification version."""
        if not self.openapi_spec:
            return

        if 'swagger' in self.openapi_spec:
            version = self.openapi_spec['swagger']
            if version.startswith('2.'):
                self.schema_type = SchemaType.OPENAPI_2
        elif 'openapi' in self.openapi_spec:
            version = self.openapi_spec['openapi']
            if version.startswith('3.0'):
                self.schema_type = SchemaType.OPENAPI_3
            elif version.startswith('3.1'):
                self.schema_type = SchemaType.OPENAPI_31

    def test_graphql_introspection(self, url: str) -> bool:
        """
        Test if GraphQL introspection is enabled.

        Args:
            url: GraphQL endpoint URL

        Returns:
            True if introspection enabled, False otherwise
        """
        try:
            response = requests.post(
                url,
                json={'query': self.introspection_query},
                headers={**self.headers, 'Content-Type': 'application/json'},
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                if data and 'data' in data and '__schema' in data['data']:
                    self.graphql_schema = data['data']['__schema']

                    # Record vulnerability: Introspection enabled
                    type_count = len(self.graphql_schema.get('types', []))
                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id("graphql_introspection_enabled"),
                        severity=SeverityLevel.MEDIUM,
                        title="GraphQL Introspection Enabled",
                        description=f"GraphQL introspection is enabled at {url}, exposing full schema structure including all queries, mutations, and types.",
                        endpoint=url,
                        payload=self.introspection_query,
                        evidence={
                            'query_type': self.graphql_schema.get('queryType', {}).get('name'),
                            'mutation_type': self.graphql_schema.get('mutationType', {}).get('name'),
                            'type_count': type_count
                        },
                        remediation="Disable GraphQL introspection in production environments unless required for public APIs. Implement query complexity limits and depth restrictions.",
                        bounty_estimate="$500-$3000"
                    ))

                    return True
        except Exception:
            pass

        return False

    def analyze_openapi_schema(self) -> None:
        """Analyze OpenAPI/Swagger schema for vulnerabilities."""
        print("[*] Phase 2: OpenAPI Schema Analysis")

        if not self.openapi_spec:
            return

        paths = self.openapi_spec.get('paths', {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    continue

                endpoint = SchemaEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=[],
                    required_params=[],
                    optional_params=[],
                    security_schemes=[],
                    response_schemas={},
                    deprecated=details.get('deprecated', False)
                )

                # Extract parameters
                parameters = details.get('parameters', [])
                # Also check requestBody for OpenAPI 3.x
                if 'requestBody' in details:
                    request_body = details['requestBody']
                    content = request_body.get('content', {})
                    for content_type, schema_info in content.items():
                        if 'schema' in schema_info:
                            # Add request body parameters
                            endpoint.parameters.append({
                                'name': 'requestBody',
                                'in': 'body',
                                'required': request_body.get('required', False),
                                'schema': schema_info['schema']
                            })

                for param in parameters:
                    endpoint.parameters.append(param)
                    if param.get('required', False):
                        endpoint.required_params.append(param['name'])
                    else:
                        endpoint.optional_params.append(param['name'])

                # Extract security requirements
                security = details.get('security', [])
                for sec in security:
                    endpoint.security_schemes.extend(sec.keys())

                # Extract response schemas
                responses = details.get('responses', {})
                for status_code, response in responses.items():
                    try:
                        code = int(status_code)
                        endpoint.response_schemas[code] = response
                    except ValueError:
                        continue

                self.discovered_endpoints.append(endpoint)

                # Check for missing authentication on write operations
                if not endpoint.security_schemes and method.upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id(f"missing_auth_{path}_{method}"),
                        severity=SeverityLevel.HIGH,
                        title=f"Missing Authentication on {method.upper()} {path}",
                        description=f"Endpoint {method.upper()} {path} has no security schemes defined in OpenAPI spec, indicating potential missing authentication.",
                        endpoint=f"{method.upper()} {path}",
                        payload="N/A",
                        evidence={
                            'method': method.upper(),
                            'path': path,
                            'security_schemes': endpoint.security_schemes,
                            'parameters': [p['name'] for p in endpoint.parameters]
                        },
                        remediation="Add appropriate security schemes (OAuth2, API Key, JWT) to the endpoint definition.",
                        bounty_estimate="$2000-$8000"
                    ))

        print(f"[+] Analyzed {len(self.discovered_endpoints)} endpoints from OpenAPI spec")

    def analyze_graphql_schema(self) -> None:
        """Analyze GraphQL schema for vulnerabilities."""
        print("[*] Phase 2: GraphQL Schema Analysis")

        if not self.graphql_schema:
            return

        types = self.graphql_schema.get('types', [])

        # Analyze mutations
        mutation_type = self.graphql_schema.get('mutationType', {})
        if mutation_type:
            mutation_type_name = mutation_type.get('name')
            mutation_fields = []

            for type_def in types:
                if type_def.get('name') == mutation_type_name:
                    mutation_fields = type_def.get('fields', [])
                    break

            print(f"[+] Found {len(mutation_fields)} mutations")

            # Check for dangerous mutations without proper field documentation
            for field in mutation_fields:
                field_name = field['name']
                field_args = field.get('args', [])

                # Check for mutations with ID parameters (potential IDOR)
                id_params = [arg for arg in field_args if 'id' in arg['name'].lower()]

                if id_params and not field.get('isDeprecated'):
                    # Build payload string without nested f-strings
                    param_str = ', '.join([f'{arg["name"]}: "test"' for arg in id_params])
                    payload = f"mutation {{ {field_name}({param_str}) }}"

                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id(f"graphql_idor_risk_{field_name}"),
                        severity=SeverityLevel.MEDIUM,
                        title=f"GraphQL Mutation with ID Parameter: {field_name}",
                        description=f"Mutation '{field_name}' accepts ID parameters which may be vulnerable to IDOR attacks if authorization is not properly implemented.",
                        endpoint=f"mutation.{field_name}",
                        payload=payload,
                        evidence={
                            'mutation_name': field_name,
                            'id_parameters': [arg['name'] for arg in id_params],
                            'all_parameters': [arg['name'] for arg in field_args]
                        },
                        remediation="Implement proper authorization checks that verify the authenticated user has permission to access/modify the specified ID.",
                        bounty_estimate="$1000-$5000"
                    ))

        # Test for field suggestions
        self.test_field_suggestions()

    def test_field_suggestions(self) -> None:
        """Test GraphQL field suggestions to discover hidden fields."""
        print("[*] Testing GraphQL field suggestions")

        if not self.graphql_schema:
            return

        # Try invalid field names to trigger suggestions
        test_queries = [
            "query { __typename invalidField }",
            "query { user(id: 1) { invalidField } }",
            "mutation { invalidMutation(input: {}) { id } }"
        ]

        for graphql_path in self.graphql_paths:
            url = urljoin(self.target_url, graphql_path)

            for query in test_queries:
                try:
                    response = requests.post(
                        url,
                        json={'query': query},
                        headers={**self.headers, 'Content-Type': 'application/json'},
                        timeout=self.timeout
                    )

                    if response.status_code == 200:
                        data = response.json()

                        # Check for field suggestions in error messages
                        errors = data.get('errors', [])
                        for error in errors:
                            message = error.get('message', '')
                            if 'did you mean' in message.lower() or 'suggestion' in message.lower():
                                self.vulnerabilities.append(SchemaVulnerability(
                                    vuln_id=self.generate_vuln_id("graphql_field_suggestions"),
                                    severity=SeverityLevel.LOW,
                                    title="GraphQL Field Suggestions Enabled",
                                    description=f"GraphQL endpoint returns field suggestions in error messages, potentially exposing hidden field names.",
                                    endpoint=url,
                                    payload=query,
                                    evidence={
                                        'error_message': message,
                                        'query': query
                                    },
                                    remediation="Disable field suggestions in production or implement generic error messages.",
                                    bounty_estimate="$300-$1500"
                                ))
                                return  # Only report once
                except Exception:
                    continue

    def discover_hidden_endpoints(self) -> None:
        """Discover hidden/undocumented API endpoints."""
        print("[*] Phase 3: Hidden Endpoint Discovery")

        documented_paths = set()
        if self.openapi_spec:
            documented_paths = set(self.openapi_spec.get('paths', {}).keys())

        # Common REST patterns to fuzz
        resource_names = ['users', 'accounts', 'profiles', 'orders', 'products', 'admin', 'api', 'internal']
        actions = ['list', 'create', 'update', 'delete', 'search', 'export', 'import', 'merge', 'batch']
        versions = ['v1', 'v2', 'v3', 'v4', 'v1.0', 'v2.0']

        test_paths = []

        # Generate potential paths
        for version in versions:
            for resource in resource_names:
                test_paths.extend([
                    f'/{version}/{resource}',
                    f'/api/{version}/{resource}',
                    f'/{resource}/{version}',
                    f'/api/{resource}'
                ])

                for action in actions:
                    test_paths.extend([
                        f'/{version}/{resource}/{action}',
                        f'/api/{version}/{resource}/{action}',
                        f'/{version}/{resource}/1/{action}'  # With ID
                    ])

        # Test for hidden endpoints (limited to avoid excessive requests)
        hidden_count = 0
        for path in test_paths[:50]:  # Limit to 50 to avoid excessive requests
            if path in documented_paths:
                continue

            url = urljoin(self.target_url, path)

            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)

                # Consider 200, 401, 403, 405 as existing endpoints
                if response.status_code in [200, 401, 403, 405]:
                    hidden_count += 1

                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id(f"hidden_endpoint_{path}"),
                        severity=SeverityLevel.MEDIUM,
                        title=f"Undocumented API Endpoint: {path}",
                        description=f"Discovered undocumented endpoint at {path} (HTTP {response.status_code}). This endpoint is not listed in API documentation but is accessible.",
                        endpoint=path,
                        payload=f"GET {url}",
                        evidence={
                            'status_code': response.status_code,
                            'headers': dict(response.headers),
                            'documented': False
                        },
                        remediation="Document all API endpoints or restrict access to internal endpoints. Remove unused endpoints.",
                        bounty_estimate="$1000-$5000"
                    ))
            except Exception:
                continue

        print(f"[+] Discovered {hidden_count} hidden/undocumented endpoints")

    def test_validation_bypasses(self) -> None:
        """Test for schema validation bypass vulnerabilities."""
        print("[*] Phase 4: Validation Bypass Testing")

        # Test subset to avoid excessive requests
        for endpoint in self.discovered_endpoints[:10]:
            if endpoint.method not in ['POST', 'PUT', 'PATCH']:
                continue

            url = urljoin(self.target_url, endpoint.path)

            # Test 1: Additional properties injection
            test_payload = {
                '_internal': True,
                '_admin': True,
                '_bypass_validation': True,
                '_discount_override': 100.0
            }

            # Add required parameters with dummy values
            for param in endpoint.required_params:
                test_payload[param] = "test_value"

            try:
                response = requests.request(
                    endpoint.method,
                    url,
                    json=test_payload,
                    headers={**self.headers, 'Content-Type': 'application/json'},
                    timeout=self.timeout
                )

                # If we get 200 instead of 400, validation might be weak
                if response.status_code == 200:
                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id(f"validation_bypass_{endpoint.path}"),
                        severity=SeverityLevel.HIGH,
                        title=f"Schema Validation Bypass: {endpoint.method} {endpoint.path}",
                        description=f"Endpoint accepts additional properties not defined in schema, potentially allowing injection of internal fields.",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        payload=json.dumps(test_payload, indent=2),
                        evidence={
                            'status_code': response.status_code,
                            'injected_fields': list(test_payload.keys())
                        },
                        remediation="Enable strict schema validation with 'additionalProperties: false'. Whitelist allowed fields explicitly.",
                        bounty_estimate="$3000-$12000"
                    ))
            except Exception:
                continue

            # Test 2: Required field bypass
            minimal_payload = {}

            try:
                response = requests.request(
                    endpoint.method,
                    url,
                    json=minimal_payload,
                    headers={**self.headers, 'Content-Type': 'application/json'},
                    timeout=self.timeout
                )

                # Should return 400 if validation is working
                if response.status_code not in [400, 422]:
                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id(f"required_field_bypass_{endpoint.path}"),
                        severity=SeverityLevel.MEDIUM,
                        title=f"Required Field Validation Missing: {endpoint.method} {endpoint.path}",
                        description=f"Endpoint does not properly validate required fields, accepting requests with missing parameters.",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        payload=json.dumps(minimal_payload, indent=2),
                        evidence={
                            'status_code': response.status_code,
                            'required_params': endpoint.required_params,
                            'provided_params': []
                        },
                        remediation="Implement proper input validation that enforces required fields.",
                        bounty_estimate="$800-$3000"
                    ))
            except Exception:
                continue

    def test_type_confusion(self) -> None:
        """Test for type confusion vulnerabilities."""
        print("[*] Phase 5: Type Confusion Testing")

        for endpoint in self.discovered_endpoints[:10]:
            if endpoint.method not in ['POST', 'PUT', 'PATCH']:
                continue

            url = urljoin(self.target_url, endpoint.path)

            # Find parameters with numeric types
            numeric_params = []
            for param in endpoint.parameters:
                param_type = param.get('type') or param.get('schema', {}).get('type')
                if param_type in ['integer', 'number']:
                    numeric_params.append(param['name'])

            if not numeric_params:
                continue

            # Test type coercion
            test_payload = {}
            for param in endpoint.required_params:
                if param in numeric_params:
                    test_payload[param] = "-999999999"  # String instead of number
                else:
                    test_payload[param] = "test"

            try:
                response = requests.request(
                    endpoint.method,
                    url,
                    json=test_payload,
                    headers={**self.headers, 'Content-Type': 'application/json'},
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    self.vulnerabilities.append(SchemaVulnerability(
                        vuln_id=self.generate_vuln_id(f"type_confusion_{endpoint.path}"),
                        severity=SeverityLevel.MEDIUM,
                        title=f"Type Confusion Vulnerability: {endpoint.method} {endpoint.path}",
                        description=f"Endpoint accepts string values for numeric parameters, indicating weak type validation. This may allow bypassing range checks or causing unexpected behavior.",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        payload=json.dumps(test_payload, indent=2),
                        evidence={
                            'status_code': response.status_code,
                            'numeric_params': numeric_params,
                            'provided_values': {k: v for k, v in test_payload.items() if k in numeric_params}
                        },
                        remediation="Implement strict type checking and reject requests with incorrect parameter types.",
                        bounty_estimate="$1500-$6000"
                    ))
            except Exception:
                continue

    def enumerate_api_versions(self) -> None:
        """Enumerate different API versions to find deprecated endpoints."""
        print("[*] Phase 6: API Version Enumeration")

        versions = ['v1', 'v2', 'v3', 'v4', 'v5', 'v1.0', 'v1.1', 'v2.0', 'v2.1', '2019-01', '2020-01', '2021-01']

        discovered_versions = set()

        for version in versions:
            test_paths = [
                f'/{version}',
                f'/api/{version}',
                f'/{version}/users',
                f'/api/{version}/users'
            ]

            for path in test_paths:
                url = urljoin(self.target_url, path)

                try:
                    response = requests.get(url, headers=self.headers, timeout=self.timeout)

                    if response.status_code in [200, 401, 403]:
                        discovered_versions.add(version)
                        print(f"[+] Found API version: {version}")
                        break
                except Exception:
                    continue

        if len(discovered_versions) > 1:
            self.vulnerabilities.append(SchemaVulnerability(
                vuln_id=self.generate_vuln_id("multiple_api_versions"),
                severity=SeverityLevel.LOW,
                title="Multiple API Versions Accessible",
                description=f"Discovered {len(discovered_versions)} different API versions: {', '.join(sorted(discovered_versions))}. Older versions may have weaker security controls.",
                endpoint="/api/*",
                payload="N/A",
                evidence={
                    'versions': sorted(discovered_versions),
                    'count': len(discovered_versions)
                },
                remediation="Deprecate and remove old API versions. Implement version sunset policies with clear migration paths.",
                bounty_estimate="$500-$2000"
            ))

    def generate_vuln_id(self, base: str) -> str:
        """
        Generate unique vulnerability ID.

        Args:
            base: Base identifier string

        Returns:
            Unique vulnerability ID
        """
        hash_input = f"{base}_{self.target_url}".encode()
        return f"SCHEMA-{hashlib.md5(hash_input).hexdigest()[:8].upper()}"

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report.

        Returns:
            Analysis report dictionary
        """
        return {
            'target': self.target_url,
            'schema_type': self.schema_type.value,
            'timestamp': int(time.time()),
            'statistics': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'by_severity': {
                    'critical': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
                    'high': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH]),
                    'medium': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                    'low': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.LOW]),
                    'info': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.INFO])
                },
                'endpoints_analyzed': len(self.discovered_endpoints),
                'schema_found': self.openapi_spec is not None or self.graphql_schema is not None
            },
            'vulnerabilities': [
                v.to_dict()
                for v in sorted(
                    self.vulnerabilities,
                    key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.severity.value)
                )
            ]
        }

    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get summary of findings.

        Returns:
            Summary dictionary
        """
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value.upper()] += 1

        return {
            'total_findings': len(self.vulnerabilities),
            'severity_counts': severity_counts,
            'findings': [v.to_dict() for v in self.vulnerabilities]
        }


# Integration with BountyHound
def run_schema_analysis(target_url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Main entry point for schema analysis.

    Args:
        target_url: Target API base URL
        timeout: Request timeout in seconds
        headers: Optional HTTP headers

    Returns:
        Analysis report with discovered vulnerabilities
    """
    analyzer = APISchemaAnalyzer(target_url, timeout=timeout, headers=headers)
    analyzer.analyze()
    return analyzer.generate_report()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_schema_analyzer.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    report = run_schema_analysis(target)

    print("\n" + "="*80)
    print("API SCHEMA ANALYSIS REPORT")
    print("="*80)
    print(json.dumps(report, indent=2))
