"""
API Documentation Scanner Agent

Advanced API documentation discovery and analysis agent that identifies exposed
API documentation endpoints and extracts sensitive information.

This agent discovers:
- Swagger/OpenAPI specifications (JSON/YAML)
- GraphQL introspection and playgrounds
- Postman collections
- API Blueprint documents
- RAML specifications
- AsyncAPI documentation
- Credentials and API keys
- Internal endpoints and schemas

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class DocSeverity(Enum):
    """Documentation exposure severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DocType(Enum):
    """Types of documentation."""
    SWAGGER = "swagger"
    OPENAPI = "openapi"
    GRAPHQL = "graphql"
    POSTMAN = "postman"
    RAML = "raml"
    BLUEPRINT = "blueprint"
    ASYNCAPI = "asyncapi"
    UNKNOWN = "unknown"


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""
    path: str
    method: str
    description: Optional[str] = None
    parameters: List[Dict] = field(default_factory=list)
    authentication_required: bool = False
    authentication_type: Optional[str] = None
    request_schema: Optional[Dict] = None
    response_schema: Optional[Dict] = None
    deprecated: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert endpoint to dictionary."""
        return asdict(self)


@dataclass
class Credential:
    """Represents a discovered credential."""
    type: str  # api_key, bearer_token, basic_auth, etc.
    value: str
    context: str  # where it was found
    confidence: float  # 0.0 to 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert credential to dictionary."""
        return asdict(self)


@dataclass
class DocumentationSource:
    """Information about discovered documentation."""
    url: str
    doc_type: DocType
    version: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    base_url: Optional[str] = None
    endpoints: List[APIEndpoint] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    security_schemes: List[Dict] = field(default_factory=list)
    servers: List[str] = field(default_factory=list)
    raw_content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert documentation source to dictionary."""
        data = asdict(self)
        data['doc_type'] = self.doc_type.value
        data['endpoints'] = [e.to_dict() for e in self.endpoints]
        data['credentials'] = [c.to_dict() for c in self.credentials]
        return data


@dataclass
class DocFinding:
    """Represents a documentation exposure finding."""
    title: str
    severity: DocSeverity
    doc_type: DocType
    description: str
    endpoint: str
    endpoints_count: int = 0
    credentials_count: int = 0
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = "CWE-200"
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['doc_type'] = self.doc_type.value
        return data


class APIDocumentationScanner:
    """
    Advanced API Documentation Scanner.

    Performs comprehensive documentation discovery including:
    - Swagger/OpenAPI specification scanning
    - GraphQL schema introspection
    - Postman collection discovery
    - API Blueprint detection
    - RAML file discovery
    - AsyncAPI documentation
    - Credential extraction
    - Internal endpoint enumeration

    Usage:
        scanner = APIDocumentationScanner(target="https://api.example.com")
        findings = scanner.scan_all()
    """

    # Common documentation paths
    SWAGGER_PATHS = [
        '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
        '/swagger/index.html', '/swagger-ui/index.html',
        '/api-docs', '/api-docs.json', '/api-docs.yaml',
        '/v2/api-docs', '/v3/api-docs',
        '/api/swagger.json', '/api/swagger.yaml',
        '/docs/swagger.json', '/docs/swagger.yaml',
        '/openapi.json', '/openapi.yaml',
        '/api/openapi.json', '/api/v1/openapi.json',
        '/swagger/v1/swagger.json',
        '/api/v1/swagger.json', '/api/v2/swagger.json',
        '/redoc', '/rapidoc', '/scalar',
        '/api/docs', '/api/documentation',
        '/docs', '/documentation',
        '/.well-known/openapi.json'
    ]

    GRAPHQL_PATHS = [
        '/graphql', '/graphiql', '/playground',
        '/graphql/playground', '/graphql-playground',
        '/api/graphql', '/v1/graphql',
        '/console', '/graphql/console',
        '/___graphql', '/altair',
        '/voyager', '/graphql/voyager'
    ]

    POSTMAN_PATHS = [
        '/postman_collection.json', '/postman.json',
        '/collection.json', '/api/postman',
        '/postman_collection', '/postman',
        '/docs/postman.json', '/api/collection.json'
    ]

    RAML_PATHS = [
        '/api.raml', '/raml/api.raml',
        '/docs/api.raml', '/v1/api.raml',
        '/api/v1/raml', '/raml'
    ]

    BLUEPRINT_PATHS = [
        '/api.md', '/apiary.apib', '/api-blueprint.md',
        '/blueprint/api.md', '/docs/api.md',
        '/api.apib', '/blueprint.apib'
    ]

    ASYNCAPI_PATHS = [
        '/asyncapi.json', '/asyncapi.yaml',
        '/asyncapi/asyncapi.json',
        '/docs/asyncapi.json'
    ]

    # Credential patterns
    CREDENTIAL_PATTERNS = {
        'api_key': [
            r'api[_-]?key["\s:=]+([a-zA-Z0-9_\-]{20,})',
            r'apikey["\s:=]+([a-zA-Z0-9_\-]{20,})',
            r'key["\s:=]+([a-zA-Z0-9_\-]{32,})'
        ],
        'bearer_token': [
            r'bearer["\s:=]+([a-zA-Z0-9_\-\.]{20,})',
            r'token["\s:=]+([a-zA-Z0-9_\-\.]{20,})'
        ],
        'basic_auth': [
            r'basic["\s:=]+([a-zA-Z0-9+/=]{20,})',
            r'authorization["\s:=]+basic\s+([a-zA-Z0-9+/=]+)'
        ],
        'oauth_secret': [
            r'client[_-]?secret["\s:=]+([a-zA-Z0-9_\-]{20,})',
            r'oauth[_-]?secret["\s:=]+([a-zA-Z0-9_\-]{20,})'
        ],
        'aws_key': [
            r'AKIA[0-9A-Z]{16}',
            r'aws[_-]?access[_-]?key["\s:=]+([A-Z0-9]{20})'
        ],
        'jwt': [
            r'eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*'
        ]
    }

    def __init__(self, target: str, timeout: int = 30, threads: int = 10,
                 verify_ssl: bool = True):
        """
        Initialize the API Documentation Scanner.

        Args:
            target: Target URL (e.g., https://api.example.com)
            timeout: Request timeout in seconds
            threads: Number of concurrent threads
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.verify_ssl = verify_ssl

        # Parse target URL
        self.parsed_url = urllib.parse.urlparse(
            target if '://' in target else f'https://{target}'
        )
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.domain = self.parsed_url.netloc

        # Storage
        self.discovered_docs: List[DocumentationSource] = []
        self.all_endpoints: List[APIEndpoint] = []
        self.all_credentials: List[Credential] = []
        self.findings: List[DocFinding] = []

    def scan_all(self) -> List[DocFinding]:
        """
        Scan for all types of API documentation.

        Returns:
            List of findings
        """
        # Scan for different documentation types
        self._scan_swagger_docs()
        self._scan_graphql_docs()
        self._scan_postman_collections()
        self._scan_raml_docs()
        self._scan_blueprint_docs()
        self._scan_asyncapi_docs()

        # Generate findings from discovered documentation
        self._generate_findings()

        return self.findings

    def _test_url(self, path: str) -> Optional[Tuple[int, str, Dict]]:
        """
        Test if a URL path exists and return response.

        Args:
            path: URL path to test

        Returns:
            Tuple of (status_code, content, headers) or None
        """
        url = urllib.parse.urljoin(self.base_url, path)

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
                headers={'User-Agent': 'Mozilla/5.0 BountyHound API Scanner'}
            )
            return (response.status_code, response.text, dict(response.headers))

        except requests.exceptions.RequestException:
            return None

    def _scan_swagger_docs(self):
        """Scan for Swagger/OpenAPI documentation."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, path): path
                      for path in self.SWAGGER_PATHS}

            for future in as_completed(futures):
                path = futures[future]
                result = future.result()

                if result and result[0] == 200:
                    status_code, content, headers = result
                    url = urllib.parse.urljoin(self.base_url, path)

                    doc = self._parse_swagger_content(content, url)
                    if doc:
                        self.discovered_docs.append(doc)

    def _parse_swagger_content(self, content: str, url: str) -> Optional[DocumentationSource]:
        """Parse Swagger/OpenAPI content."""
        try:
            # Try JSON first
            try:
                spec = json.loads(content)
            except json.JSONDecodeError:
                # Try YAML
                if not YAML_AVAILABLE:
                    return None
                spec = yaml.safe_load(content)

            # Determine version
            if 'swagger' in spec:
                version = spec['swagger']
                doc_type = DocType.SWAGGER
            elif 'openapi' in spec:
                version = spec['openapi']
                doc_type = DocType.OPENAPI
            else:
                return None

            # Extract metadata
            info = spec.get('info', {})
            title = info.get('title', 'Unknown API')
            description = info.get('description', '')

            # Extract base URL
            base_url = None
            servers = []
            if 'servers' in spec:
                # OpenAPI 3.x
                servers = [s.get('url') for s in spec.get('servers', [])]
                if servers:
                    base_url = servers[0]
            elif 'host' in spec:
                # Swagger 2.0
                scheme = spec.get('schemes', ['https'])[0]
                base_path = spec.get('basePath', '')
                base_url = f"{scheme}://{spec['host']}{base_path}"
                servers = [base_url]

            # Extract endpoints
            endpoints = self._parse_swagger_paths(spec)
            self.all_endpoints.extend(endpoints)

            # Extract security schemes
            security_schemes = []
            if 'securityDefinitions' in spec:
                security_schemes = spec['securityDefinitions']
            elif 'components' in spec and 'securitySchemes' in spec['components']:
                security_schemes = spec['components']['securitySchemes']

            # Extract credentials
            credentials = self._extract_credentials(content, f"swagger:{url}")
            self.all_credentials.extend(credentials)

            doc = DocumentationSource(
                url=url,
                doc_type=doc_type,
                version=version,
                title=title,
                description=description,
                base_url=base_url,
                endpoints=endpoints,
                credentials=credentials,
                security_schemes=security_schemes,
                servers=servers,
                raw_content=content
            )

            return doc

        except Exception:
            return None

    def _parse_swagger_paths(self, spec: Dict) -> List[APIEndpoint]:
        """Parse endpoints from Swagger/OpenAPI paths."""
        endpoints = []
        paths = spec.get('paths', {})

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    continue

                # Check authentication
                auth_required = False
                auth_type = None

                if 'security' in operation:
                    auth_required = True
                    security = operation['security']
                    if security:
                        auth_type = list(security[0].keys())[0]
                elif 'security' in spec:
                    auth_required = True
                    security = spec['security']
                    if security:
                        auth_type = list(security[0].keys())[0]

                # Extract parameters
                parameters = operation.get('parameters', [])

                # Extract schemas
                request_schema = None
                response_schema = None

                if 'requestBody' in operation:
                    request_schema = operation['requestBody']

                if 'responses' in operation:
                    response_schema = operation['responses']

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    description=operation.get('description') or operation.get('summary'),
                    parameters=parameters,
                    authentication_required=auth_required,
                    authentication_type=auth_type,
                    request_schema=request_schema,
                    response_schema=response_schema,
                    deprecated=operation.get('deprecated', False),
                    tags=operation.get('tags', [])
                )

                endpoints.append(endpoint)

        return endpoints

    def _scan_graphql_docs(self):
        """Scan for GraphQL documentation and introspection."""
        introspection_query = {
            "query": """
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
                                    type { kind name ofType { kind name } }
                                }
                                type { kind name ofType { kind name } }
                                isDeprecated
                                deprecationReason
                            }
                        }
                    }
                }
            """
        }

        for path in self.GRAPHQL_PATHS:
            url = urllib.parse.urljoin(self.base_url, path)

            try:
                response = requests.post(
                    url,
                    json=introspection_query,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0'
                    }
                )

                if response.status_code == 200:
                    data = response.json()

                    if 'data' in data and '__schema' in data['data']:
                        doc = self._parse_graphql_schema(data, url)
                        if doc:
                            self.discovered_docs.append(doc)

            except Exception:
                continue

    def _parse_graphql_schema(self, schema_data: Dict, url: str) -> Optional[DocumentationSource]:
        """Parse GraphQL introspection schema."""
        try:
            schema = schema_data['data']['__schema']

            query_type = schema.get('queryType', {}).get('name')
            mutation_type = schema.get('mutationType', {}).get('name')
            subscription_type = schema.get('subscriptionType', {}).get('name')

            # Extract endpoints (queries, mutations, subscriptions)
            endpoints = []

            for type_def in schema.get('types', []):
                type_name = type_def.get('name')

                # Skip internal types
                if type_name and type_name.startswith('__'):
                    continue

                # Process queries
                if type_name == query_type:
                    for field in type_def.get('fields', []):
                        endpoint = APIEndpoint(
                            path=field['name'],
                            method='QUERY',
                            description=field.get('description'),
                            parameters=field.get('args', []),
                            authentication_required=False,
                            authentication_type=None,
                            request_schema=None,
                            response_schema=field.get('type'),
                            deprecated=field.get('isDeprecated', False)
                        )
                        endpoints.append(endpoint)

                # Process mutations
                elif type_name == mutation_type:
                    for field in type_def.get('fields', []):
                        endpoint = APIEndpoint(
                            path=field['name'],
                            method='MUTATION',
                            description=field.get('description'),
                            parameters=field.get('args', []),
                            authentication_required=False,
                            authentication_type=None,
                            request_schema=None,
                            response_schema=field.get('type'),
                            deprecated=field.get('isDeprecated', False)
                        )
                        endpoints.append(endpoint)

                # Process subscriptions
                elif type_name == subscription_type:
                    for field in type_def.get('fields', []):
                        endpoint = APIEndpoint(
                            path=field['name'],
                            method='SUBSCRIPTION',
                            description=field.get('description'),
                            parameters=field.get('args', []),
                            authentication_required=False,
                            authentication_type=None,
                            request_schema=None,
                            response_schema=field.get('type'),
                            deprecated=field.get('isDeprecated', False)
                        )
                        endpoints.append(endpoint)

            self.all_endpoints.extend(endpoints)

            # Extract credentials
            raw_content = json.dumps(schema_data, indent=2)
            credentials = self._extract_credentials(raw_content, f"graphql:{url}")
            self.all_credentials.extend(credentials)

            doc = DocumentationSource(
                url=url,
                doc_type=DocType.GRAPHQL,
                version='introspection',
                title='GraphQL API',
                description=f'Queries: {query_type}, Mutations: {mutation_type}, Subscriptions: {subscription_type}',
                base_url=url,
                endpoints=endpoints,
                credentials=credentials,
                security_schemes=[],
                servers=[url],
                raw_content=raw_content
            )

            return doc

        except Exception:
            return None

    def _scan_postman_collections(self):
        """Scan for Postman collections."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, path): path
                      for path in self.POSTMAN_PATHS}

            for future in as_completed(futures):
                path = futures[future]
                result = future.result()

                if result and result[0] == 200:
                    status_code, content, headers = result
                    url = urllib.parse.urljoin(self.base_url, path)

                    doc = self._parse_postman_collection(content, url)
                    if doc:
                        self.discovered_docs.append(doc)

    def _parse_postman_collection(self, content: str, url: str) -> Optional[DocumentationSource]:
        """Parse Postman collection."""
        try:
            collection = json.loads(content)

            info = collection.get('info', {})
            title = info.get('name', 'Unknown Collection')
            description = info.get('description', '')

            # Extract endpoints from items
            endpoints = []
            self._parse_postman_items(collection.get('item', []), endpoints, '')

            self.all_endpoints.extend(endpoints)

            # Extract credentials
            credentials = []

            # Check collection-level auth
            if 'auth' in collection:
                auth_creds = self._extract_postman_auth(collection['auth'], f"collection:{url}")
                credentials.extend(auth_creds)

            # Check variables
            for var in collection.get('variable', []):
                var_name = var.get('key', '')
                var_value = var.get('value', '')

                if any(keyword in var_name.lower() for keyword in ['key', 'token', 'secret', 'password']):
                    if var_value and len(var_value) > 5:
                        cred = Credential(
                            type='postman_variable',
                            value=var_value,
                            context=f"variable:{var_name} in {url}",
                            confidence=0.7
                        )
                        credentials.append(cred)

            # Extract from content
            content_creds = self._extract_credentials(content, f"postman:{url}")
            credentials.extend(content_creds)

            self.all_credentials.extend(credentials)

            # Get base URL
            base_url = None
            if endpoints and endpoints[0].request_schema:
                url_obj = endpoints[0].request_schema.get('url', {})
                if isinstance(url_obj, dict):
                    base_url = url_obj.get('raw', '').split('?')[0]

            doc = DocumentationSource(
                url=url,
                doc_type=DocType.POSTMAN,
                version=info.get('schema', 'unknown'),
                title=title,
                description=description,
                base_url=base_url,
                endpoints=endpoints,
                credentials=credentials,
                security_schemes=[],
                servers=[base_url] if base_url else [],
                raw_content=content
            )

            return doc

        except Exception:
            return None

    def _parse_postman_items(self, items: List[Dict], endpoints: List[APIEndpoint], prefix: str):
        """Recursively parse Postman collection items."""
        for item in items:
            # Check if folder or request
            if 'item' in item:
                # It's a folder, recurse
                folder_name = item.get('name', '')
                new_prefix = f"{prefix}/{folder_name}" if prefix else folder_name
                self._parse_postman_items(item['item'], endpoints, new_prefix)

            elif 'request' in item:
                # It's a request
                request = item['request']
                name = item.get('name', 'Unknown')

                # Extract method
                method = request.get('method', 'GET')

                # Extract URL
                url_obj = request.get('url', {})
                if isinstance(url_obj, str):
                    path = url_obj
                else:
                    path = url_obj.get('raw', '')

                # Extract auth
                auth = request.get('auth', {})
                auth_type = auth.get('type')

                # Extract headers
                headers = request.get('header', [])

                # Extract body
                body = request.get('body', {})

                endpoint = APIEndpoint(
                    path=f"{prefix}/{name}" if prefix else name,
                    method=method,
                    description=item.get('description'),
                    parameters=headers,
                    authentication_required=bool(auth_type),
                    authentication_type=auth_type,
                    request_schema={'url': url_obj, 'body': body, 'headers': headers},
                    response_schema=None
                )

                endpoints.append(endpoint)

    def _extract_postman_auth(self, auth: Dict, context: str) -> List[Credential]:
        """Extract credentials from Postman auth configuration."""
        credentials = []
        auth_type = auth.get('type', '')

        if auth_type == 'apikey':
            for item in auth.get('apikey', []):
                if item.get('key') == 'value':
                    value = item.get('value', '')
                    if value:
                        cred = Credential(
                            type='api_key',
                            value=value,
                            context=f"apikey in {context}",
                            confidence=0.9
                        )
                        credentials.append(cred)

        elif auth_type == 'bearer':
            for item in auth.get('bearer', []):
                if item.get('key') == 'token':
                    value = item.get('value', '')
                    if value:
                        cred = Credential(
                            type='bearer_token',
                            value=value,
                            context=f"bearer token in {context}",
                            confidence=0.9
                        )
                        credentials.append(cred)

        elif auth_type == 'basic':
            username = ''
            password = ''
            for item in auth.get('basic', []):
                if item.get('key') == 'username':
                    username = item.get('value', '')
                elif item.get('key') == 'password':
                    password = item.get('value', '')

            if username and password:
                cred = Credential(
                    type='basic_auth',
                    value=f"{username}:{password}",
                    context=f"basic auth in {context}",
                    confidence=0.9
                )
                credentials.append(cred)

        return credentials

    def _scan_raml_docs(self):
        """Scan for RAML documentation."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, path): path
                      for path in self.RAML_PATHS}

            for future in as_completed(futures):
                path = futures[future]
                result = future.result()

                if result and result[0] == 200:
                    status_code, content, headers = result

                    # Check if it's RAML
                    if content.strip().startswith('#%RAML'):
                        url = urllib.parse.urljoin(self.base_url, path)
                        doc = self._parse_raml_content(content, url)
                        if doc:
                            self.discovered_docs.append(doc)

    def _parse_raml_content(self, content: str, url: str) -> Optional[DocumentationSource]:
        """Parse RAML content."""
        try:
            if not YAML_AVAILABLE:
                return None

            # Parse YAML
            raml = yaml.safe_load(content)

            title = raml.get('title', 'Unknown API')
            description = raml.get('description', '')
            version = raml.get('version', 'unknown')
            base_url = raml.get('baseUri', '')

            # Extract credentials
            credentials = self._extract_credentials(content, f"raml:{url}")
            self.all_credentials.extend(credentials)

            doc = DocumentationSource(
                url=url,
                doc_type=DocType.RAML,
                version=version,
                title=title,
                description=description,
                base_url=base_url,
                endpoints=[],
                credentials=credentials,
                security_schemes=raml.get('securitySchemes', []),
                servers=[base_url] if base_url else [],
                raw_content=content
            )

            return doc

        except Exception:
            return None

    def _scan_blueprint_docs(self):
        """Scan for API Blueprint documentation."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, path): path
                      for path in self.BLUEPRINT_PATHS}

            for future in as_completed(futures):
                path = futures[future]
                result = future.result()

                if result and result[0] == 200:
                    status_code, content, headers = result

                    # Check if it's API Blueprint
                    if 'FORMAT: 1A' in content or '# Group' in content or '## ' in content[:200]:
                        url = urllib.parse.urljoin(self.base_url, path)

                        # Extract credentials
                        credentials = self._extract_credentials(content, f"blueprint:{url}")
                        self.all_credentials.extend(credentials)

                        doc = DocumentationSource(
                            url=url,
                            doc_type=DocType.BLUEPRINT,
                            version='1A',
                            title='API Blueprint Documentation',
                            description='',
                            base_url=None,
                            endpoints=[],
                            credentials=credentials,
                            security_schemes=[],
                            servers=[],
                            raw_content=content
                        )

                        self.discovered_docs.append(doc)

    def _scan_asyncapi_docs(self):
        """Scan for AsyncAPI documentation."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, path): path
                      for path in self.ASYNCAPI_PATHS}

            for future in as_completed(futures):
                path = futures[future]
                result = future.result()

                if result and result[0] == 200:
                    status_code, content, headers = result
                    url = urllib.parse.urljoin(self.base_url, path)

                    try:
                        # Try JSON
                        try:
                            spec = json.loads(content)
                        except:
                            if not YAML_AVAILABLE:
                                continue
                            spec = yaml.safe_load(content)

                        # Check if AsyncAPI
                        if 'asyncapi' in spec:
                            # Extract credentials
                            credentials = self._extract_credentials(content, f"asyncapi:{url}")
                            self.all_credentials.extend(credentials)

                            info = spec.get('info', {})

                            doc = DocumentationSource(
                                url=url,
                                doc_type=DocType.ASYNCAPI,
                                version=spec['asyncapi'],
                                title=info.get('title', 'AsyncAPI'),
                                description=info.get('description', ''),
                                base_url=None,
                                endpoints=[],
                                credentials=credentials,
                                security_schemes=[],
                                servers=list(spec.get('servers', {}).keys()),
                                raw_content=content
                            )

                            self.discovered_docs.append(doc)

                    except:
                        continue

    def _extract_credentials(self, content: str, context: str) -> List[Credential]:
        """Extract credentials from content using regex patterns."""
        credentials = []

        for cred_type, patterns in self.CREDENTIAL_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)

                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)

                    # Skip common false positives
                    if value.lower() in ['example', 'your_key_here', 'replace_me', 'xxx', '***']:
                        continue

                    # Calculate confidence based on entropy
                    entropy = len(set(value)) / len(value) if value else 0
                    confidence = min(entropy, 0.95)

                    cred = Credential(
                        type=cred_type,
                        value=value,
                        context=context,
                        confidence=confidence
                    )

                    # Avoid duplicates
                    if not any(c.value == value for c in credentials):
                        credentials.append(cred)

        return credentials

    def _generate_findings(self):
        """Generate findings from discovered documentation."""
        for doc in self.discovered_docs:
            # Determine severity
            severity = DocSeverity.MEDIUM

            if len(doc.credentials) > 0:
                severity = DocSeverity.HIGH
            elif len(doc.endpoints) > 50:
                severity = DocSeverity.MEDIUM
            else:
                severity = DocSeverity.LOW

            # Build description
            description = f"Exposed {doc.doc_type.value} documentation at {doc.url}. "
            description += f"Contains {len(doc.endpoints)} endpoints"
            if doc.credentials:
                description += f" and {len(doc.credentials)} potential credentials"
            description += "."

            # Build POC
            poc = f"# Access the documentation\ncurl '{doc.url}'\n\n"
            if doc.endpoints:
                poc += f"# Documentation reveals {len(doc.endpoints)} endpoints\n"
                poc += "# Sample endpoints:\n"
                for endpoint in doc.endpoints[:5]:
                    poc += f"# {endpoint.method} {endpoint.path}\n"

            # Build impact
            impact = "An attacker can:\n"
            impact += "- Enumerate all API endpoints\n"
            impact += "- Understand authentication mechanisms\n"
            impact += "- Identify internal/deprecated endpoints\n"
            impact += "- Extract request/response schemas\n"
            if doc.credentials:
                impact += "- Access exposed credentials\n"

            # Build recommendation
            recommendation = "1. Remove or restrict access to API documentation in production\n"
            recommendation += "2. Require authentication to view documentation\n"
            recommendation += "3. Remove all credentials and secrets from documentation\n"
            recommendation += "4. Use environment variables for sensitive values"

            finding = DocFinding(
                title=f"Exposed {doc.doc_type.value.upper()} Documentation",
                severity=severity,
                doc_type=doc.doc_type,
                description=description,
                endpoint=doc.url,
                endpoints_count=len(doc.endpoints),
                credentials_count=len(doc.credentials),
                poc=poc,
                impact=impact,
                recommendation=recommendation,
                raw_data=doc.to_dict()
            )

            self.findings.append(finding)

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report."""
        return {
            'target': self.base_url,
            'domain': self.domain,
            'scan_date': date.today().isoformat(),
            'documentation_sources': len(self.discovered_docs),
            'total_endpoints': len(self.all_endpoints),
            'total_credentials': len(self.all_credentials),
            'findings': [f.to_dict() for f in self.findings],
            'documentation_details': [d.to_dict() for d in self.discovered_docs]
        }


def main():
    """Main execution function."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_documentation_scanner.py <target-url>")
        sys.exit(1)

    target = sys.argv[1]

    scanner = APIDocumentationScanner(target)
    findings = scanner.scan_all()

    report = scanner.generate_report()

    # Print summary
    print(f"\nAPI Documentation Scanner Results")
    print(f"{'='*60}")
    print(f"Target: {scanner.base_url}")
    print(f"Documentation Sources: {len(scanner.discovered_docs)}")
    print(f"Total Endpoints: {len(scanner.all_endpoints)}")
    print(f"Credentials Found: {len(scanner.all_credentials)}")
    print(f"Findings: {len(findings)}")

    # Save report
    output_file = f"api_docs_{scanner.domain.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to {output_file}")


if __name__ == '__main__':
    main()
