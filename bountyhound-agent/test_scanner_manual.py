"""Manual test script for API Documentation Scanner."""
import json
from engine.agents.api_documentation_scanner import (
    APIDocumentationScanner,
    APIEndpoint,
    Credential,
    DocumentationSource,
    DocType,
    DocSeverity
)

def test_initialization():
    """Test scanner initialization."""
    print("Testing initialization...")
    scanner = APIDocumentationScanner("https://api.example.com")
    assert scanner.base_url == "https://api.example.com"
    assert scanner.domain == "api.example.com"
    print("  [PASS] Initialization")

def test_swagger_parsing():
    """Test Swagger parsing."""
    print("Testing Swagger parsing...")
    scanner = APIDocumentationScanner("https://api.example.com")

    swagger_spec = {
        "swagger": "2.0",
        "info": {"title": "Test API", "version": "1.0"},
        "host": "api.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {"200": {"description": "OK"}},
                    "security": [{"apiKey": []}]
                },
                "post": {
                    "summary": "Create user",
                    "responses": {"201": {"description": "Created"}}
                }
            }
        },
        "securityDefinitions": {
            "apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
        }
    }

    doc = scanner._parse_swagger_content(json.dumps(swagger_spec), "test.json")
    assert doc is not None
    assert doc.doc_type == DocType.SWAGGER
    assert doc.version == "2.0"
    assert doc.title == "Test API"
    assert len(doc.endpoints) == 2
    assert doc.base_url == "https://api.example.com/v1"
    print("  [PASS] Swagger parsing")

def test_openapi_parsing():
    """Test OpenAPI 3.0 parsing."""
    print("Testing OpenAPI parsing...")
    scanner = APIDocumentationScanner("https://api.example.com")

    openapi_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "3.0.0"},
        "servers": [{"url": "https://api.example.com/v3"}],
        "paths": {
            "/products": {
                "get": {
                    "summary": "List products",
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }

    doc = scanner._parse_swagger_content(json.dumps(openapi_spec), "test.json")
    assert doc is not None
    assert doc.doc_type == DocType.OPENAPI
    assert doc.version == "3.0.0"
    assert len(doc.endpoints) == 1
    print("  [PASS] OpenAPI parsing")

def test_graphql_parsing():
    """Test GraphQL schema parsing."""
    print("Testing GraphQL parsing...")
    scanner = APIDocumentationScanner("https://api.example.com")

    schema_data = {
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
                                "description": "Get user",
                                "args": [],
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
                                "description": "Create user",
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

    doc = scanner._parse_graphql_schema(schema_data, "https://api.example.com/graphql")
    assert doc is not None, "GraphQL schema parsing returned None"
    assert doc.doc_type == DocType.GRAPHQL, f"Expected GRAPHQL, got {doc.doc_type}"
    assert len(doc.endpoints) == 3, f"Expected 3 endpoints, got {len(doc.endpoints)}"
    queries = [e for e in doc.endpoints if e.method == "QUERY"]
    mutations = [e for e in doc.endpoints if e.method == "MUTATION"]
    subscriptions = [e for e in doc.endpoints if e.method == "SUBSCRIPTION"]
    assert len(queries) == 1, f"Expected 1 query, got {len(queries)}"
    assert len(mutations) == 1, f"Expected 1 mutation, got {len(mutations)}"
    assert len(subscriptions) == 1, f"Expected 1 subscription, got {len(subscriptions)}"
    print("  [PASS] GraphQL parsing")

def test_postman_parsing():
    """Test Postman collection parsing."""
    print("Testing Postman parsing...")
    scanner = APIDocumentationScanner("https://api.example.com")

    collection = {
        "info": {
            "name": "Test Collection",
            "description": "Test collection"
        },
        "item": [
            {
                "name": "Get User",
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/users"
                }
            }
        ]
    }

    doc = scanner._parse_postman_collection(json.dumps(collection), "test.json")
    assert doc is not None
    assert doc.doc_type == DocType.POSTMAN
    assert doc.title == "Test Collection"
    assert len(doc.endpoints) == 1
    print("  [PASS] Postman parsing")

def test_credential_extraction():
    """Test credential extraction."""
    print("Testing credential extraction...")
    scanner = APIDocumentationScanner("https://api.example.com")

    # Test API key extraction
    content1 = 'api_key: "sk_live_abcdefghijklmnopqrstuvwxyz12345"'
    creds1 = scanner._extract_credentials(content1, "test1")
    assert len(creds1) > 0
    assert any(c.type == "api_key" for c in creds1)

    # Test JWT extraction
    content2 = 'token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    creds2 = scanner._extract_credentials(content2, "test2")
    assert len(creds2) > 0

    # Test AWS key extraction
    content3 = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
    creds3 = scanner._extract_credentials(content3, "test3")
    assert len(creds3) > 0
    assert any(c.type == "aws_key" for c in creds3)

    print("  [PASS] Credential extraction")

def test_finding_generation():
    """Test finding generation."""
    print("Testing finding generation...")
    scanner = APIDocumentationScanner("https://api.example.com")

    # Add a doc with credentials
    doc = DocumentationSource(
        url="https://api.example.com/swagger.json",
        doc_type=DocType.SWAGGER,
        version="2.0",
        title="Test API",
        endpoints=[
            APIEndpoint(path="/users", method="GET"),
            APIEndpoint(path="/products", method="POST")
        ],
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
    assert finding.endpoints_count == 2
    assert len(finding.poc) > 0
    assert len(finding.impact) > 0
    assert len(finding.recommendation) > 0
    print("  [PASS] Finding generation")

def test_report_generation():
    """Test report generation."""
    print("Testing report generation...")
    scanner = APIDocumentationScanner("https://api.example.com")

    # Add test data
    doc = DocumentationSource(
        url="https://api.example.com/docs",
        doc_type=DocType.OPENAPI,
        endpoints=[APIEndpoint(path="/test", method="GET")]
    )
    scanner.discovered_docs.append(doc)
    scanner.all_endpoints.append(APIEndpoint(path="/test", method="GET"))
    scanner._generate_findings()

    report = scanner.generate_report()

    assert "target" in report
    assert "domain" in report
    assert "scan_date" in report
    assert report["documentation_sources"] == 1
    assert report["total_endpoints"] == 1
    assert len(report["findings"]) > 0
    print("  [PASS] Report generation")

def test_data_classes():
    """Test data class conversions."""
    print("Testing data classes...")

    # Test APIEndpoint
    endpoint = APIEndpoint(path="/users", method="GET", description="Get users")
    data = endpoint.to_dict()
    assert data["path"] == "/users"
    assert data["method"] == "GET"

    # Test Credential
    cred = Credential(type="api_key", value="test", context="test", confidence=0.9)
    data = cred.to_dict()
    assert data["type"] == "api_key"
    assert data["confidence"] == 0.9

    # Test DocumentationSource
    doc = DocumentationSource(
        url="test.com",
        doc_type=DocType.SWAGGER,
        endpoints=[endpoint],
        credentials=[cred]
    )
    data = doc.to_dict()
    assert data["doc_type"] == "swagger"
    assert len(data["endpoints"]) == 1
    assert len(data["credentials"]) == 1

    print("  [PASS] Data classes")

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("API Documentation Scanner - Manual Tests")
    print("="*60 + "\n")

    tests = [
        test_initialization,
        test_swagger_parsing,
        test_openapi_parsing,
        test_graphql_parsing,
        test_postman_parsing,
        test_credential_extraction,
        test_finding_generation,
        test_report_generation,
        test_data_classes
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1

    print("\n" + "="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")

    return failed == 0

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
