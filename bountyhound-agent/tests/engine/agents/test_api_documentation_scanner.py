"""
Comprehensive tests for API Documentation Scanner Agent.

Tests cover:
- Initialization and configuration
- Swagger/OpenAPI detection and parsing
- GraphQL introspection testing
- Postman collection parsing
- RAML documentation discovery
- API Blueprint detection
- AsyncAPI documentation
- Credential extraction
- Finding generation
- Report generation
- Edge cases and error handling
- All parsing methods
- URL testing

Target: 95%+ code coverage with 30+ tests
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.api_documentation_scanner import (
        APIDocumentationScanner,
        APIEndpoint,
        Credential,
        DocumentationSource,
        DocFinding,
        DocSeverity,
        DocType,
        REQUESTS_AVAILABLE
    )
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="API Documentation Scanner not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, content="", headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = content
        response.headers = headers or {}

        # Add json method for GraphQL responses
        def json_method():
            return json.loads(content) if content else {}
        response.json = json_method

        return response

    return _create_response


@pytest.fixture
def scanner():
    """Create a scanner instance for testing."""
    if not SCANNER_AVAILABLE:
        pytest.skip("Scanner not available")

    return APIDocumentationScanner(
        target="https://api.example.com",
        timeout=5,
        threads=5,
        verify_ssl=False
    )


@pytest.fixture
def swagger_spec():
    """Sample Swagger 2.0 specification."""
    return {
        "swagger": "2.0",
        "info": {
            "title": "Test API",
            "description": "A test API",
            "version": "1.0.0"
        },
        "host": "api.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "description": "Retrieve all users",
                    "parameters": [],
                    "responses": {
                        "200": {"description": "Success"}
                    },
                    "security": [{"apiKey": []}]
                },
                "post": {
                    "summary": "Create user",
                    "parameters": [],
                    "responses": {
                        "201": {"description": "Created"}
                    }
                }
            },
            "/users/{id}": {
                "delete": {
                    "summary": "Delete user",
                    "deprecated": True,
                    "parameters": [],
                    "responses": {
                        "204": {"description": "Deleted"}
                    }
                }
            }
        },
        "securityDefinitions": {
            "apiKey": {
                "type": "apiKey",
                "name": "X-API-Key",
                "in": "header"
            }
        }
    }


@pytest.fixture
def openapi_spec():
    """Sample OpenAPI 3.0 specification."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API v3",
            "description": "OpenAPI 3.0 test",
            "version": "3.0.0"
        },
        "servers": [
            {"url": "https://api.example.com/v3"}
        ],
        "paths": {
            "/products": {
                "get": {
                    "summary": "List products",
                    "operationId": "listProducts",
                    "tags": ["products"],
                    "responses": {
                        "200": {"description": "Success"}
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        }
    }


@pytest.fixture
def graphql_schema():
    """Sample GraphQL introspection response."""
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": {"name": "Subscription"},
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "user",
                                "description": "Get user by ID",
                                "args": [
                                    {
                                        "name": "id",
                                        "description": "User ID",
                                        "type": {"kind": "SCALAR", "name": "ID", "ofType": None}
                                    }
                                ],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None
                            }
                        ]
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "createUser",
                                "description": "Create new user",
                                "args": [],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None
                            }
                        ]
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Subscription",
                        "fields": [
                            {
                                "name": "userUpdated",
                                "description": "Subscribe to user updates",
                                "args": [],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None
                            }
                        ]
                    }
                ]
            }
        }
    }


@pytest.fixture
def postman_collection():
    """Sample Postman collection."""
    return {
        "info": {
            "name": "Test Collection",
            "description": "Test API collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "auth": {
            "type": "bearer",
            "bearer": [
                {"key": "token", "value": "test_bearer_token_12345"}
            ]
        },
        "variable": [
            {"key": "api_key", "value": "sk_test_abcd1234efgh5678"},
            {"key": "base_url", "value": "https://api.example.com"}
        ],
        "item": [
            {
                "name": "Users",
                "item": [
                    {
                        "name": "Get User",
                        "request": {
                            "method": "GET",
                            "url": {
                                "raw": "{{base_url}}/users/{{user_id}}",
                                "host": ["api", "example", "com"],
                                "path": ["users", "{{user_id}}"]
                            },
                            "auth": {"type": "apikey"},
                            "header": [
                                {"key": "X-API-Key", "value": "{{api_key}}"}
                            ],
                            "body": {}
                        }
                    }
                ]
            },
            {
                "name": "Create Order",
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/orders",
                    "auth": {
                        "type": "basic",
                        "basic": [
                            {"key": "username", "value": "admin"},
                            {"key": "password", "value": "secret123"}
                        ]
                    },
                    "body": {"mode": "raw"}
                }
            }
        ]
    }


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestInitialization:
    """Test scanner initialization."""

    def test_init_with_basic_url(self):
        """Test initialization with basic URL."""
        scanner = APIDocumentationScanner(target="https://api.example.com")

        assert scanner.target == "https://api.example.com"
        assert scanner.base_url == "https://api.example.com"
        assert scanner.domain == "api.example.com"
        assert scanner.timeout == 30
        assert scanner.threads == 10
        assert scanner.verify_ssl is True

    def test_init_with_custom_settings(self):
        """Test initialization with custom settings."""
        scanner = APIDocumentationScanner(
            target="https://test.com",
            timeout=15,
            threads=5,
            verify_ssl=False
        )

        assert scanner.timeout == 15
        assert scanner.threads == 5
        assert scanner.verify_ssl is False

    def test_init_without_scheme(self):
        """Test initialization with URL without scheme."""
        scanner = APIDocumentationScanner(target="api.example.com")

        assert scanner.base_url == "https://api.example.com"
        assert scanner.domain == "api.example.com"

    def test_init_requires_requests(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            APIDocumentationScanner(target="https://example.com")

    def test_init_with_path(self):
        """Test initialization with URL containing path."""
        scanner = APIDocumentationScanner(target="https://api.example.com/v1/test")

        assert scanner.base_url == "https://api.example.com"
        assert scanner.domain == "api.example.com"

    def test_init_with_port(self):
        """Test initialization with URL containing port."""
        scanner = APIDocumentationScanner(target="https://api.example.com:8443")

        assert scanner.base_url == "https://api.example.com:8443"
        assert scanner.domain == "api.example.com:8443"


# ============================================================================
# URL Testing Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestURLTesting:
    """Test URL testing functionality."""

    @patch('requests.get')
    def test_test_url_success(self, mock_get, scanner, mock_response):
        """Test successful URL testing."""
        mock_get.return_value = mock_response(
            status_code=200,
            content="test content",
            headers={"Content-Type": "application/json"}
        )

        result = scanner._test_url('/swagger.json')

        assert result is not None
        assert result[0] == 200
        assert result[1] == "test content"
        assert result[2]["Content-Type"] == "application/json"

    @patch('requests.get')
    def test_test_url_not_found(self, mock_get, scanner, mock_response):
        """Test URL that returns 404."""
        mock_get.return_value = mock_response(status_code=404)

        result = scanner._test_url('/nonexistent')

        assert result is not None
        assert result[0] == 404

    @patch('requests.get')
    def test_test_url_timeout(self, mock_get, scanner):
        """Test URL that times out."""
        mock_get.side_effect = Exception("Timeout")

        result = scanner._test_url('/slow')

        assert result is None

    @patch('requests.get')
    def test_test_url_with_redirects(self, mock_get, scanner, mock_response):
        """Test URL with redirects."""
        mock_get.return_value = mock_response(
            status_code=200,
            content="redirected content"
        )

        result = scanner._test_url('/redirect')

        assert result is not None
        assert result[0] == 200


# ============================================================================
# Swagger/OpenAPI Parsing Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestSwaggerParsing:
    """Test Swagger/OpenAPI parsing."""

    def test_parse_swagger_spec(self, scanner, swagger_spec):
        """Test parsing Swagger 2.0 specification."""
        content = json.dumps(swagger_spec)
        doc = scanner._parse_swagger_content(content, "https://api.example.com/swagger.json")

        assert doc is not None
        assert doc.doc_type == DocType.SWAGGER
        assert doc.version == "2.0"
        assert doc.title == "Test API"
        assert doc.description == "A test API"
        assert doc.base_url == "https://api.example.com/v1"
        assert len(doc.endpoints) == 3

    def test_parse_openapi_spec(self, scanner, openapi_spec):
        """Test parsing OpenAPI 3.0 specification."""
        content = json.dumps(openapi_spec)
        doc = scanner._parse_swagger_content(content, "https://api.example.com/openapi.json")

        assert doc is not None
        assert doc.doc_type == DocType.OPENAPI
        assert doc.version == "3.0.0"
        assert doc.title == "Test API v3"
        assert len(doc.endpoints) == 1
        assert doc.base_url == "https://api.example.com/v3"

    def test_parse_swagger_endpoints(self, scanner, swagger_spec):
        """Test parsing endpoints from Swagger spec."""
        endpoints = scanner._parse_swagger_paths(swagger_spec)

        assert len(endpoints) == 3

        # Check GET /users
        get_users = next(e for e in endpoints if e.method == "GET" and e.path == "/users")
        assert get_users.description == "Retrieve all users"
        assert get_users.authentication_required is True
        assert get_users.authentication_type == "apiKey"
        assert get_users.deprecated is False

        # Check DELETE /users/{id}
        delete_user = next(e for e in endpoints if e.method == "DELETE")
        assert delete_user.deprecated is True

    def test_parse_invalid_swagger(self, scanner):
        """Test parsing invalid Swagger content."""
        doc = scanner._parse_swagger_content("invalid json", "test.json")

        assert doc is None

    def test_parse_swagger_yaml(self, scanner):
        """Test parsing YAML Swagger spec."""
        yaml_content = """
swagger: "2.0"
info:
  title: YAML API
  version: "1.0"
paths:
  /test:
    get:
      summary: Test endpoint
      responses:
        200:
          description: Success
"""
        doc = scanner._parse_swagger_content(yaml_content, "test.yaml")

        # Should handle YAML if available
        if doc:
            assert doc.doc_type == DocType.SWAGGER
            assert doc.title == "YAML API"


# ============================================================================
# GraphQL Parsing Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestGraphQLParsing:
    """Test GraphQL introspection parsing."""

    def test_parse_graphql_schema(self, scanner, graphql_schema):
        """Test parsing GraphQL schema."""
        doc = scanner._parse_graphql_schema(
            graphql_schema,
            "https://api.example.com/graphql"
        )

        assert doc is not None
        assert doc.doc_type == DocType.GRAPHQL
        assert doc.version == "introspection"
        assert len(doc.endpoints) == 3

        # Check query
        query = next(e for e in doc.endpoints if e.method == "QUERY")
        assert query.path == "user"
        assert query.description == "Get user by ID"

        # Check mutation
        mutation = next(e for e in doc.endpoints if e.method == "MUTATION")
        assert mutation.path == "createUser"

        # Check subscription
        subscription = next(e for e in doc.endpoints if e.method == "SUBSCRIPTION")
        assert subscription.path == "userUpdated"

    def test_parse_graphql_with_deprecated_fields(self, scanner):
        """Test parsing GraphQL with deprecated fields."""
        schema_data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "subscriptionType": None,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "oldField",
                                    "description": "Deprecated field",
                                    "args": [],
                                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                                    "isDeprecated": True,
                                    "deprecationReason": "Use newField instead"
                                }
                            ]
                        }
                    ]
                }
            }
        }

        doc = scanner._parse_graphql_schema(schema_data, "https://test.com/graphql")

        assert doc is not None
        assert len(doc.endpoints) == 1
        assert doc.endpoints[0].deprecated is True

    def test_parse_graphql_skips_internal_types(self, scanner):
        """Test that GraphQL parsing skips internal types."""
        schema_data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "subscriptionType": None,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "__Schema",
                            "fields": []
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": []
                        }
                    ]
                }
            }
        }

        doc = scanner._parse_graphql_schema(schema_data, "test.com")

        # Should only process Query, not __Schema
        assert doc is not None

    def test_parse_invalid_graphql_schema(self, scanner):
        """Test parsing invalid GraphQL schema."""
        doc = scanner._parse_graphql_schema({"invalid": "data"}, "test.com")

        assert doc is None


# ============================================================================
# Postman Collection Parsing Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestPostmanParsing:
    """Test Postman collection parsing."""

    def test_parse_postman_collection(self, scanner, postman_collection):
        """Test parsing Postman collection."""
        content = json.dumps(postman_collection)
        doc = scanner._parse_postman_collection(content, "https://api.example.com/collection.json")

        assert doc is not None
        assert doc.doc_type == DocType.POSTMAN
        assert doc.title == "Test Collection"
        assert len(doc.endpoints) == 2
        assert len(doc.credentials) > 0

    def test_parse_postman_nested_folders(self, scanner):
        """Test parsing Postman collection with nested folders."""
        collection = {
            "info": {"name": "Nested Test"},
            "item": [
                {
                    "name": "Folder1",
                    "item": [
                        {
                            "name": "Request1",
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/test"
                            }
                        }
                    ]
                }
            ]
        }

        content = json.dumps(collection)
        doc = scanner._parse_postman_collection(content, "test.json")

        assert doc is not None
        assert len(doc.endpoints) == 1
        assert "Folder1/Request1" in doc.endpoints[0].path

    def test_extract_postman_auth_apikey(self, scanner):
        """Test extracting API key from Postman auth."""
        auth = {
            "type": "apikey",
            "apikey": [
                {"key": "value", "value": "test_api_key_12345"},
                {"key": "in", "value": "header"}
            ]
        }

        creds = scanner._extract_postman_auth(auth, "test context")

        assert len(creds) == 1
        assert creds[0].type == "api_key"
        assert creds[0].value == "test_api_key_12345"
        assert creds[0].confidence == 0.9

    def test_extract_postman_auth_bearer(self, scanner):
        """Test extracting bearer token from Postman auth."""
        auth = {
            "type": "bearer",
            "bearer": [
                {"key": "token", "value": "bearer_token_xyz"}
            ]
        }

        creds = scanner._extract_postman_auth(auth, "test")

        assert len(creds) == 1
        assert creds[0].type == "bearer_token"
        assert creds[0].value == "bearer_token_xyz"

    def test_extract_postman_auth_basic(self, scanner):
        """Test extracting basic auth from Postman auth."""
        auth = {
            "type": "basic",
            "basic": [
                {"key": "username", "value": "user123"},
                {"key": "password", "value": "pass456"}
            ]
        }

        creds = scanner._extract_postman_auth(auth, "test")

        assert len(creds) == 1
        assert creds[0].type == "basic_auth"
        assert creds[0].value == "user123:pass456"

    def test_parse_postman_with_string_url(self, scanner):
        """Test parsing Postman request with string URL."""
        collection = {
            "info": {"name": "Test"},
            "item": [
                {
                    "name": "Request",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/endpoint"
                    }
                }
            ]
        }

        content = json.dumps(collection)
        doc = scanner._parse_postman_collection(content, "test.json")

        assert doc is not None
        assert len(doc.endpoints) == 1
        assert doc.endpoints[0].method == "POST"


# ============================================================================
# Credential Extraction Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestCredentialExtraction:
    """Test credential extraction."""

    def test_extract_api_key(self, scanner):
        """Test extracting API key."""
        content = 'api_key: "sk_live_abcdefghijklmnop12345"'
        creds = scanner._extract_credentials(content, "test")

        assert len(creds) > 0
        assert any(c.type == "api_key" for c in creds)

    def test_extract_bearer_token(self, scanner):
        """Test extracting bearer token."""
        content = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        creds = scanner._extract_credentials(content, "test")

        assert len(creds) > 0

    def test_extract_aws_key(self, scanner):
        """Test extracting AWS access key."""
        content = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
        creds = scanner._extract_credentials(content, "test")

        assert len(creds) > 0
        assert any(c.type == "aws_key" for c in creds)

    def test_extract_jwt(self, scanner):
        """Test extracting JWT token."""
        content = 'token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        creds = scanner._extract_credentials(content, "test")

        assert len(creds) > 0
        assert any(c.type == "jwt" for c in creds)

    def test_skip_false_positives(self, scanner):
        """Test skipping common false positives."""
        content = 'api_key: "example"\ntoken: "your_key_here"\nsecret: "xxx"'
        creds = scanner._extract_credentials(content, "test")

        # Should not extract example values
        assert not any(c.value.lower() in ["example", "your_key_here", "xxx"] for c in creds)

    def test_avoid_duplicate_credentials(self, scanner):
        """Test that duplicate credentials are not added."""
        content = 'key1: "duplicate_key_12345"\nkey2: "duplicate_key_12345"'
        creds = scanner._extract_credentials(content, "test")

        # Should only have one credential
        duplicate_values = [c.value for c in creds if c.value == "duplicate_key_12345"]
        assert len(duplicate_values) <= 1

    def test_credential_confidence_calculation(self, scanner):
        """Test credential confidence calculation."""
        content = 'api_key: "aaaaaaaaaaaaaaaaaaaaaa"'  # Low entropy
        creds = scanner._extract_credentials(content, "test")

        if creds:
            # Low entropy should have lower confidence
            assert all(c.confidence < 1.0 for c in creds)


# ============================================================================
# RAML and Blueprint Parsing Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestRAMLBlueprintParsing:
    """Test RAML and API Blueprint parsing."""

    def test_parse_raml_content(self, scanner):
        """Test parsing RAML content."""
        raml_content = """#%RAML 1.0
title: Test API
version: v1
baseUri: https://api.example.com/{version}
description: Test RAML API
"""
        doc = scanner._parse_raml_content(raml_content, "https://api.example.com/api.raml")

        if doc:  # Only if YAML is available
            assert doc.doc_type == DocType.RAML
            assert doc.title == "Test API"
            assert doc.version == "v1"

    def test_parse_invalid_raml(self, scanner):
        """Test parsing invalid RAML."""
        doc = scanner._parse_raml_content("not raml content", "test.raml")

        assert doc is None


# ============================================================================
# Finding Generation Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestFindingGeneration:
    """Test finding generation."""

    def test_generate_findings_with_credentials(self, scanner, swagger_spec):
        """Test generating findings with credentials."""
        # Add a doc with credentials
        doc = DocumentationSource(
            url="https://api.example.com/swagger.json",
            doc_type=DocType.SWAGGER,
            version="2.0",
            title="Test API",
            endpoints=[APIEndpoint(path="/test", method="GET")],
            credentials=[
                Credential(type="api_key", value="test_key", context="test", confidence=0.9)
            ]
        )

        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        assert len(scanner.findings) == 1
        finding = scanner.findings[0]
        assert finding.severity == DocSeverity.HIGH
        assert finding.credentials_count == 1
        assert "credential" in finding.description.lower()

    def test_generate_findings_many_endpoints(self, scanner):
        """Test generating findings with many endpoints."""
        endpoints = [APIEndpoint(path=f"/endpoint{i}", method="GET") for i in range(60)]

        doc = DocumentationSource(
            url="https://api.example.com/docs",
            doc_type=DocType.OPENAPI,
            version="3.0",
            title="Large API",
            endpoints=endpoints
        )

        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        assert len(scanner.findings) == 1
        finding = scanner.findings[0]
        assert finding.severity == DocSeverity.MEDIUM
        assert finding.endpoints_count == 60

    def test_generate_findings_few_endpoints(self, scanner):
        """Test generating findings with few endpoints."""
        doc = DocumentationSource(
            url="https://api.example.com/docs",
            doc_type=DocType.SWAGGER,
            version="2.0",
            title="Small API",
            endpoints=[APIEndpoint(path="/test", method="GET")]
        )

        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        assert len(scanner.findings) == 1
        finding = scanner.findings[0]
        assert finding.severity == DocSeverity.LOW

    def test_finding_contains_poc(self, scanner):
        """Test that findings contain POC."""
        doc = DocumentationSource(
            url="https://api.example.com/swagger.json",
            doc_type=DocType.SWAGGER,
            endpoints=[APIEndpoint(path="/test", method="GET")]
        )

        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        finding = scanner.findings[0]
        assert "curl" in finding.poc
        assert doc.url in finding.poc

    def test_finding_contains_impact(self, scanner):
        """Test that findings contain impact description."""
        doc = DocumentationSource(
            url="https://api.example.com/docs",
            doc_type=DocType.OPENAPI,
            endpoints=[]
        )

        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        finding = scanner.findings[0]
        assert len(finding.impact) > 0
        assert "attacker" in finding.impact.lower()

    def test_finding_contains_recommendation(self, scanner):
        """Test that findings contain recommendations."""
        doc = DocumentationSource(
            url="https://api.example.com/docs",
            doc_type=DocType.SWAGGER,
            endpoints=[]
        )

        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        finding = scanner.findings[0]
        assert len(finding.recommendation) > 0


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestReportGeneration:
    """Test report generation."""

    def test_generate_report(self, scanner):
        """Test generating comprehensive report."""
        # Add some test data
        scanner.discovered_docs.append(
            DocumentationSource(
                url="https://api.example.com/swagger.json",
                doc_type=DocType.SWAGGER,
                endpoints=[APIEndpoint(path="/test", method="GET")]
            )
        )
        scanner.all_endpoints.append(APIEndpoint(path="/test", method="GET"))
        scanner.all_credentials.append(
            Credential(type="api_key", value="test", context="test", confidence=0.9)
        )
        scanner._generate_findings()

        report = scanner.generate_report()

        assert report['target'] == scanner.base_url
        assert report['domain'] == scanner.domain
        assert report['scan_date'] == date.today().isoformat()
        assert report['documentation_sources'] == 1
        assert report['total_endpoints'] == 1
        assert report['total_credentials'] == 1
        assert len(report['findings']) == 1
        assert len(report['documentation_details']) == 1

    def test_report_contains_finding_details(self, scanner):
        """Test that report contains finding details."""
        doc = DocumentationSource(
            url="https://api.example.com/docs",
            doc_type=DocType.OPENAPI,
            endpoints=[]
        )
        scanner.discovered_docs.append(doc)
        scanner._generate_findings()

        report = scanner.generate_report()

        assert 'findings' in report
        assert len(report['findings']) > 0
        finding = report['findings'][0]
        assert 'title' in finding
        assert 'severity' in finding
        assert 'description' in finding


# ============================================================================
# Data Class Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestDataClasses:
    """Test data class functionality."""

    def test_api_endpoint_to_dict(self):
        """Test APIEndpoint to_dict method."""
        endpoint = APIEndpoint(
            path="/users",
            method="GET",
            description="Get users"
        )

        data = endpoint.to_dict()

        assert data['path'] == "/users"
        assert data['method'] == "GET"
        assert data['description'] == "Get users"

    def test_credential_to_dict(self):
        """Test Credential to_dict method."""
        cred = Credential(
            type="api_key",
            value="test_key",
            context="test",
            confidence=0.9
        )

        data = cred.to_dict()

        assert data['type'] == "api_key"
        assert data['value'] == "test_key"
        assert data['confidence'] == 0.9

    def test_documentation_source_to_dict(self):
        """Test DocumentationSource to_dict method."""
        doc = DocumentationSource(
            url="https://api.example.com/docs",
            doc_type=DocType.SWAGGER,
            version="2.0",
            endpoints=[APIEndpoint(path="/test", method="GET")],
            credentials=[Credential(type="api_key", value="test", context="test", confidence=0.9)]
        )

        data = doc.to_dict()

        assert data['url'] == "https://api.example.com/docs"
        assert data['doc_type'] == "swagger"
        assert data['version'] == "2.0"
        assert len(data['endpoints']) == 1
        assert len(data['credentials']) == 1

    def test_doc_finding_to_dict(self):
        """Test DocFinding to_dict method."""
        finding = DocFinding(
            title="Test Finding",
            severity=DocSeverity.HIGH,
            doc_type=DocType.SWAGGER,
            description="Test description",
            endpoint="https://api.example.com/docs"
        )

        data = finding.to_dict()

        assert data['title'] == "Test Finding"
        assert data['severity'] == "HIGH"
        assert data['doc_type'] == "swagger"


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestIntegration:
    """Integration tests."""

    @patch('requests.get')
    @patch('requests.post')
    def test_full_scan_workflow(self, mock_post, mock_get, scanner, mock_response, swagger_spec):
        """Test complete scanning workflow."""
        # Mock Swagger endpoint
        swagger_response = mock_response(
            status_code=200,
            content=json.dumps(swagger_spec)
        )

        # Mock GraphQL endpoint (not found)
        graphql_404 = mock_response(status_code=404)

        # Setup mock returns
        def get_side_effect(url, *args, **kwargs):
            if 'swagger.json' in url:
                return swagger_response
            return mock_response(status_code=404)

        mock_get.side_effect = get_side_effect
        mock_post.return_value = graphql_404

        # Run scan
        findings = scanner.scan_all()

        # Verify results
        assert len(scanner.discovered_docs) > 0
        assert len(scanner.findings) > 0


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_swagger_spec(self, scanner):
        """Test parsing empty Swagger spec."""
        doc = scanner._parse_swagger_content(json.dumps({}), "test.json")

        assert doc is None

    def test_malformed_json(self, scanner):
        """Test parsing malformed JSON."""
        doc = scanner._parse_swagger_content("{invalid json", "test.json")

        assert doc is None

    def test_swagger_without_paths(self, scanner):
        """Test Swagger spec without paths."""
        spec = {
            "swagger": "2.0",
            "info": {"title": "Test"}
        }

        content = json.dumps(spec)
        doc = scanner._parse_swagger_content(content, "test.json")

        assert doc is not None
        assert len(doc.endpoints) == 0

    def test_scan_with_no_results(self, scanner):
        """Test scanning with no documentation found."""
        with patch('requests.get', side_effect=Exception("No connection")):
            findings = scanner.scan_all()

            assert len(findings) == 0
            assert len(scanner.discovered_docs) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
