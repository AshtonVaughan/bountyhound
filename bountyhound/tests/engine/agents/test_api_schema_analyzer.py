"""
Tests for API Schema Analyzer Agent

Comprehensive tests covering all API schema attack vectors:
- OpenAPI/Swagger schema analysis
- GraphQL schema introspection
- Hidden endpoint discovery
- Validation bypass testing
- Type confusion attacks
- API version enumeration
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import Timeout, RequestException

from engine.agents.api_schema_analyzer import (
    APISchemaAnalyzer,
    SchemaVulnerability,
    SchemaEndpoint,
    GraphQLField,
    SchemaType,
    SeverityLevel,
    run_schema_analysis
)


# ===== Fixtures =====

@pytest.fixture
def schema_analyzer():
    """Create schema analyzer instance."""
    return APISchemaAnalyzer(
        target_url='https://api.example.com',
        timeout=10
    )


@pytest.fixture
def mock_response():
    """Create mock response."""
    response = Mock()
    response.status_code = 200
    response.headers = {'Content-Type': 'application/json'}
    response.json.return_value = {}
    response.text = ''
    return response


@pytest.fixture
def openapi_spec():
    """Sample OpenAPI specification."""
    return {
        'openapi': '3.0.0',
        'info': {'title': 'Test API', 'version': '1.0.0'},
        'paths': {
            '/users': {
                'get': {
                    'security': [{'bearerAuth': []}],
                    'parameters': [
                        {'name': 'limit', 'in': 'query', 'required': False, 'schema': {'type': 'integer'}}
                    ],
                    'responses': {'200': {'description': 'Success'}}
                },
                'post': {
                    'parameters': [
                        {'name': 'email', 'in': 'body', 'required': True, 'schema': {'type': 'string'}}
                    ],
                    'responses': {'201': {'description': 'Created'}}
                }
            },
            '/admin': {
                'delete': {
                    'security': [{'apiKey': []}],
                    'responses': {'204': {'description': 'Deleted'}}
                }
            }
        }
    }


@pytest.fixture
def graphql_schema():
    """Sample GraphQL schema."""
    return {
        '__schema': {
            'queryType': {'name': 'Query'},
            'mutationType': {'name': 'Mutation'},
            'subscriptionType': None,
            'types': [
                {
                    'kind': 'OBJECT',
                    'name': 'Query',
                    'fields': [
                        {'name': 'user', 'args': [{'name': 'id', 'type': {'name': 'ID'}}]}
                    ]
                },
                {
                    'kind': 'OBJECT',
                    'name': 'Mutation',
                    'fields': [
                        {
                            'name': 'deleteUser',
                            'args': [{'name': 'userId', 'type': {'name': 'ID'}}],
                            'isDeprecated': False
                        },
                        {
                            'name': 'updateProfile',
                            'args': [{'name': 'profileId', 'type': {'name': 'ID'}}],
                            'isDeprecated': False
                        }
                    ]
                }
            ]
        }
    }


# ===== Initialization Tests =====

def test_schema_analyzer_initialization():
    """Test schema analyzer initializes correctly."""
    analyzer = APISchemaAnalyzer(
        target_url='https://api.example.com/',
        timeout=15,
        headers={'Authorization': 'Bearer token'}
    )

    assert analyzer.target_url == 'https://api.example.com'  # Trailing slash removed
    assert analyzer.timeout == 15
    assert 'Authorization' in analyzer.headers
    assert analyzer.vulnerabilities == []
    assert analyzer.discovered_endpoints == []
    assert analyzer.schema_type == SchemaType.UNKNOWN


def test_schema_analyzer_default_headers():
    """Test default headers are set correctly."""
    analyzer = APISchemaAnalyzer('https://api.example.com')

    assert 'User-Agent' in analyzer.headers
    assert analyzer.headers['User-Agent'] == 'BountyHound/5.0'
    assert 'Accept' in analyzer.headers


def test_schema_analyzer_url_normalization():
    """Test URL normalization removes trailing slash."""
    analyzer = APISchemaAnalyzer('https://api.example.com///')

    assert analyzer.target_url == 'https://api.example.com'


# ===== OpenAPI Discovery Tests =====

def test_discover_openapi_json(schema_analyzer, mock_response, openapi_spec):
    """Test discovering OpenAPI JSON specification."""
    mock_response.json.return_value = openapi_spec

    with patch('requests.get') as mock_get:
        mock_get.return_value = mock_response

        result = schema_analyzer.discover_schemas()

        assert result is True
        assert schema_analyzer.schema_type == SchemaType.OPENAPI_3
        assert schema_analyzer.openapi_spec is not None


def test_discover_openapi_yaml(schema_analyzer, mock_response, openapi_spec):
    """Test discovering OpenAPI YAML specification."""
    mock_response.headers = {'Content-Type': 'text/yaml'}
    mock_response.text = 'openapi: 3.0.0'

    with patch('requests.get') as mock_get:
        with patch('yaml.safe_load') as mock_yaml:
            mock_yaml.return_value = openapi_spec
            mock_get.return_value = mock_response

            result = schema_analyzer.discover_schemas()

            assert result is True
            assert schema_analyzer.openapi_spec is not None


def test_discover_schemas_not_found(schema_analyzer):
    """Test schema discovery when no schemas found."""
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = schema_analyzer.discover_schemas()

        assert result is False
        assert schema_analyzer.schema_type == SchemaType.UNKNOWN


def test_discover_schemas_connection_error(schema_analyzer):
    """Test schema discovery with connection error."""
    with patch('requests.get') as mock_get:
        mock_get.side_effect = RequestException('Connection failed')

        result = schema_analyzer.discover_schemas()

        assert result is False


# ===== OpenAPI Version Detection Tests =====

def test_detect_openapi_2(schema_analyzer):
    """Test detecting OpenAPI 2.0 (Swagger)."""
    schema_analyzer.openapi_spec = {'swagger': '2.0'}
    schema_analyzer.detect_openapi_version()

    assert schema_analyzer.schema_type == SchemaType.OPENAPI_2


def test_detect_openapi_3_0(schema_analyzer):
    """Test detecting OpenAPI 3.0."""
    schema_analyzer.openapi_spec = {'openapi': '3.0.1'}
    schema_analyzer.detect_openapi_version()

    assert schema_analyzer.schema_type == SchemaType.OPENAPI_3


def test_detect_openapi_3_1(schema_analyzer):
    """Test detecting OpenAPI 3.1."""
    schema_analyzer.openapi_spec = {'openapi': '3.1.0'}
    schema_analyzer.detect_openapi_version()

    assert schema_analyzer.schema_type == SchemaType.OPENAPI_31


def test_detect_openapi_version_none(schema_analyzer):
    """Test version detection with no spec."""
    schema_analyzer.openapi_spec = None
    schema_analyzer.detect_openapi_version()

    assert schema_analyzer.schema_type == SchemaType.UNKNOWN


# ===== GraphQL Discovery Tests =====

def test_graphql_introspection_enabled(schema_analyzer, graphql_schema):
    """Test GraphQL introspection detection when enabled."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': graphql_schema}
        mock_post.return_value = mock_response

        result = schema_analyzer.test_graphql_introspection('https://api.example.com/graphql')

        assert result is True
        assert schema_analyzer.graphql_schema is not None
        assert len(schema_analyzer.vulnerabilities) == 1
        assert schema_analyzer.vulnerabilities[0].title == "GraphQL Introspection Enabled"


def test_graphql_introspection_disabled(schema_analyzer):
    """Test GraphQL introspection when disabled."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'errors': [{'message': 'Introspection disabled'}]}
        mock_post.return_value = mock_response

        result = schema_analyzer.test_graphql_introspection('https://api.example.com/graphql')

        assert result is False
        assert schema_analyzer.graphql_schema is None


def test_graphql_introspection_error(schema_analyzer):
    """Test GraphQL introspection with connection error."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = RequestException('Connection failed')

        result = schema_analyzer.test_graphql_introspection('https://api.example.com/graphql')

        assert result is False


# ===== OpenAPI Schema Analysis Tests =====

def test_analyze_openapi_schema(schema_analyzer, openapi_spec):
    """Test analyzing OpenAPI schema."""
    schema_analyzer.openapi_spec = openapi_spec
    schema_analyzer.analyze_openapi_schema()

    assert len(schema_analyzer.discovered_endpoints) > 0

    # Find the POST /users endpoint (no security)
    post_users = [e for e in schema_analyzer.discovered_endpoints if e.method == 'POST' and e.path == '/users']
    assert len(post_users) == 1

    # Should have generated missing auth finding
    missing_auth = [v for v in schema_analyzer.vulnerabilities if 'Missing Authentication' in v.title]
    assert len(missing_auth) == 1


def test_analyze_openapi_no_spec(schema_analyzer):
    """Test analyzing OpenAPI when no spec available."""
    schema_analyzer.openapi_spec = None
    schema_analyzer.analyze_openapi_schema()

    assert len(schema_analyzer.discovered_endpoints) == 0


def test_analyze_openapi_with_request_body(schema_analyzer):
    """Test analyzing OpenAPI 3.x with requestBody."""
    spec = {
        'openapi': '3.0.0',
        'paths': {
            '/users': {
                'post': {
                    'requestBody': {
                        'required': True,
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'email': {'type': 'string'}
                                    }
                                }
                            }
                        }
                    },
                    'responses': {'201': {'description': 'Created'}}
                }
            }
        }
    }

    schema_analyzer.openapi_spec = spec
    schema_analyzer.analyze_openapi_schema()

    # Should find requestBody parameter
    endpoint = schema_analyzer.discovered_endpoints[0]
    assert len(endpoint.parameters) == 1
    assert endpoint.parameters[0]['name'] == 'requestBody'


# ===== GraphQL Schema Analysis Tests =====

def test_analyze_graphql_schema(schema_analyzer, graphql_schema):
    """Test analyzing GraphQL schema."""
    schema_analyzer.graphql_schema = graphql_schema['__schema']
    schema_analyzer.analyze_graphql_schema()

    # Should find IDOR risks for mutations with ID parameters
    idor_findings = [v for v in schema_analyzer.vulnerabilities if 'IDOR' in v.vuln_id]
    assert len(idor_findings) >= 1


def test_analyze_graphql_no_schema(schema_analyzer):
    """Test analyzing GraphQL when no schema available."""
    schema_analyzer.graphql_schema = None
    schema_analyzer.analyze_graphql_schema()

    # Should not crash
    assert True


def test_analyze_graphql_no_mutations(schema_analyzer):
    """Test analyzing GraphQL schema with no mutations."""
    schema = {
        'queryType': {'name': 'Query'},
        'mutationType': None,
        'types': []
    }

    schema_analyzer.graphql_schema = schema
    schema_analyzer.analyze_graphql_schema()

    # Should not crash or find IDOR issues
    idor_findings = [v for v in schema_analyzer.vulnerabilities if 'IDOR' in v.title]
    assert len(idor_findings) == 0


# ===== Field Suggestions Tests =====

def test_field_suggestions_enabled(schema_analyzer, graphql_schema):
    """Test GraphQL field suggestions detection."""
    schema_analyzer.graphql_schema = graphql_schema['__schema']

    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': 'Cannot query field "invalidField". Did you mean "id", "email"?'
            }]
        }
        mock_post.return_value = mock_response

        schema_analyzer.test_field_suggestions()

        # Should find field suggestion vulnerability
        suggestions = [v for v in schema_analyzer.vulnerabilities if 'Field Suggestions' in v.title]
        assert len(suggestions) == 1


def test_field_suggestions_disabled(schema_analyzer, graphql_schema):
    """Test GraphQL field suggestions when disabled."""
    schema_analyzer.graphql_schema = graphql_schema['__schema']

    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': 'Cannot query field "invalidField".'
            }]
        }
        mock_post.return_value = mock_response

        schema_analyzer.test_field_suggestions()

        # Should not find vulnerability
        suggestions = [v for v in schema_analyzer.vulnerabilities if 'Field Suggestions' in v.title]
        assert len(suggestions) == 0


# ===== Hidden Endpoint Discovery Tests =====

def test_discover_hidden_endpoints_found(schema_analyzer):
    """Test discovering hidden endpoints."""
    schema_analyzer.openapi_spec = {'paths': {'/api/v1/users': {}}}

    with patch('requests.get') as mock_get:
        def response_side_effect(url, *args, **kwargs):
            response = Mock()
            if '/api/v2/users' in url:
                response.status_code = 200
            else:
                response.status_code = 404
            response.headers = {}
            return response

        mock_get.side_effect = response_side_effect

        schema_analyzer.discover_hidden_endpoints()

        # Should find undocumented endpoints
        hidden = [v for v in schema_analyzer.vulnerabilities if 'Undocumented' in v.title]
        assert len(hidden) >= 1


def test_discover_hidden_endpoints_none_found(schema_analyzer):
    """Test hidden endpoint discovery when none found."""
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        schema_analyzer.discover_hidden_endpoints()

        hidden = [v for v in schema_analyzer.vulnerabilities if 'Undocumented' in v.title]
        assert len(hidden) == 0


def test_discover_hidden_endpoints_401_403_405(schema_analyzer):
    """Test hidden endpoints return 401/403/405."""
    with patch('requests.get') as mock_get:
        responses = []
        for status in [401, 403, 405]:
            response = Mock()
            response.status_code = status
            response.headers = {}
            responses.append(response)

        mock_get.side_effect = responses + [Mock(status_code=404)] * 100

        schema_analyzer.discover_hidden_endpoints()

        # Should find endpoints returning 401/403/405
        hidden = [v for v in schema_analyzer.vulnerabilities if 'Undocumented' in v.title]
        assert len(hidden) == 3


# ===== Validation Bypass Tests =====

def test_validation_bypass_additional_properties(schema_analyzer):
    """Test validation bypass with additional properties."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[{'name': 'email', 'required': True}],
        required_params=['email'],
        optional_params=[],
        security_schemes=[],
        response_schemas={}
    )
    schema_analyzer.discovered_endpoints.append(endpoint)

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        schema_analyzer.test_validation_bypasses()

        # Should find validation bypass
        bypass = [v for v in schema_analyzer.vulnerabilities if 'Validation Bypass' in v.title]
        assert len(bypass) == 1


def test_validation_bypass_protected(schema_analyzer):
    """Test validation bypass when protected."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[],
        required_params=[],
        optional_params=[],
        security_schemes=[],
        response_schemas={}
    )
    schema_analyzer.discovered_endpoints.append(endpoint)

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 400  # Properly rejects bad request
        mock_request.return_value = mock_response

        schema_analyzer.test_validation_bypasses()

        bypass = [v for v in schema_analyzer.vulnerabilities if 'Validation Bypass' in v.title]
        assert len(bypass) == 0


def test_required_field_bypass(schema_analyzer):
    """Test required field validation bypass."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[{'name': 'email', 'required': True}],
        required_params=['email'],
        optional_params=[],
        security_schemes=[],
        response_schemas={}
    )
    schema_analyzer.discovered_endpoints.append(endpoint)

    with patch('requests.request') as mock_request:
        # First call (additional properties) returns 400
        # Second call (missing required) returns 200 (vulnerable)
        responses = [
            Mock(status_code=400),
            Mock(status_code=200)
        ]
        mock_request.side_effect = responses

        schema_analyzer.test_validation_bypasses()

        # Should find required field bypass
        bypass = [v for v in schema_analyzer.vulnerabilities if 'Required Field' in v.title]
        assert len(bypass) == 1


# ===== Type Confusion Tests =====

def test_type_confusion_vulnerable(schema_analyzer):
    """Test type confusion detection."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[
            {'name': 'age', 'required': True, 'type': 'integer'},
            {'name': 'email', 'required': True, 'type': 'string'}
        ],
        required_params=['age', 'email'],
        optional_params=[],
        security_schemes=[],
        response_schemas={}
    )
    schema_analyzer.discovered_endpoints.append(endpoint)

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        schema_analyzer.test_type_confusion()

        # Should find type confusion
        confusion = [v for v in schema_analyzer.vulnerabilities if 'Type Confusion' in v.title]
        assert len(confusion) == 1


def test_type_confusion_no_numeric_params(schema_analyzer):
    """Test type confusion when no numeric params."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[
            {'name': 'email', 'required': True, 'type': 'string'}
        ],
        required_params=['email'],
        optional_params=[],
        security_schemes=[],
        response_schemas={}
    )
    schema_analyzer.discovered_endpoints.append(endpoint)

    schema_analyzer.test_type_confusion()

    # Should not find type confusion (no numeric params to test)
    confusion = [v for v in schema_analyzer.vulnerabilities if 'Type Confusion' in v.title]
    assert len(confusion) == 0


def test_type_confusion_with_schema_notation(schema_analyzer):
    """Test type confusion with OpenAPI 3.x schema notation."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[
            {'name': 'count', 'required': True, 'schema': {'type': 'number'}}
        ],
        required_params=['count'],
        optional_params=[],
        security_schemes=[],
        response_schemas={}
    )
    schema_analyzer.discovered_endpoints.append(endpoint)

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        schema_analyzer.test_type_confusion()

        # Should find type confusion
        confusion = [v for v in schema_analyzer.vulnerabilities if 'Type Confusion' in v.title]
        assert len(confusion) == 1


# ===== API Version Enumeration Tests =====

def test_enumerate_api_versions_multiple(schema_analyzer):
    """Test enumerating multiple API versions."""
    with patch('requests.get') as mock_get:
        def response_side_effect(url, *args, **kwargs):
            response = Mock()
            if '/v1' in url or '/v2' in url:
                response.status_code = 200
            else:
                response.status_code = 404
            return response

        mock_get.side_effect = response_side_effect

        schema_analyzer.enumerate_api_versions()

        # Should find multiple versions vulnerability
        versions = [v for v in schema_analyzer.vulnerabilities if 'Multiple API Versions' in v.title]
        assert len(versions) == 1


def test_enumerate_api_versions_single(schema_analyzer):
    """Test enumerating single API version."""
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        schema_analyzer.enumerate_api_versions()

        # Should not find vulnerability with only one version
        versions = [v for v in schema_analyzer.vulnerabilities if 'Multiple API Versions' in v.title]
        assert len(versions) == 0


# ===== Utility Functions Tests =====

def test_generate_vuln_id(schema_analyzer):
    """Test vulnerability ID generation."""
    vuln_id_1 = schema_analyzer.generate_vuln_id("test_vuln")
    vuln_id_2 = schema_analyzer.generate_vuln_id("test_vuln")
    vuln_id_3 = schema_analyzer.generate_vuln_id("different_vuln")

    # Same input should generate same ID
    assert vuln_id_1 == vuln_id_2

    # Different input should generate different ID
    assert vuln_id_1 != vuln_id_3

    # Should have correct format
    assert vuln_id_1.startswith("SCHEMA-")
    assert len(vuln_id_1) == 15  # SCHEMA- + 8 hex chars


def test_generate_report(schema_analyzer):
    """Test report generation."""
    # Add some test vulnerabilities
    schema_analyzer.vulnerabilities.append(SchemaVulnerability(
        vuln_id='SCHEMA-TEST001',
        severity=SeverityLevel.HIGH,
        title='Test Vulnerability',
        description='Test',
        endpoint='/api/test',
        payload='test',
        evidence={},
        remediation='Fix it',
        bounty_estimate='$1000'
    ))

    report = schema_analyzer.generate_report()

    assert report['target'] == schema_analyzer.target_url
    assert report['schema_type'] == SchemaType.UNKNOWN.value
    assert 'statistics' in report
    assert report['statistics']['total_vulnerabilities'] == 1
    assert report['statistics']['by_severity']['high'] == 1
    assert len(report['vulnerabilities']) == 1


def test_get_findings_summary(schema_analyzer):
    """Test getting findings summary."""
    schema_analyzer.vulnerabilities.extend([
        SchemaVulnerability(
            vuln_id='V1', severity=SeverityLevel.HIGH, title='T1',
            description='', endpoint='', payload='', evidence={},
            remediation='', bounty_estimate=''
        ),
        SchemaVulnerability(
            vuln_id='V2', severity=SeverityLevel.MEDIUM, title='T2',
            description='', endpoint='', payload='', evidence={},
            remediation='', bounty_estimate=''
        ),
        SchemaVulnerability(
            vuln_id='V3', severity=SeverityLevel.HIGH, title='T3',
            description='', endpoint='', payload='', evidence={},
            remediation='', bounty_estimate=''
        )
    ])

    summary = schema_analyzer.get_findings_summary()

    assert summary['total_findings'] == 3
    assert summary['severity_counts']['HIGH'] == 2
    assert summary['severity_counts']['MEDIUM'] == 1
    assert len(summary['findings']) == 3


# ===== Schema Vulnerability Model Tests =====

def test_schema_vulnerability_creation():
    """Test SchemaVulnerability dataclass."""
    vuln = SchemaVulnerability(
        vuln_id='SCHEMA-TEST',
        severity=SeverityLevel.CRITICAL,
        title='Test Vuln',
        description='Test description',
        endpoint='/api/test',
        payload='{"test": true}',
        evidence={'key': 'value'},
        remediation='Fix this',
        bounty_estimate='$5000-$10000'
    )

    assert vuln.vuln_id == 'SCHEMA-TEST'
    assert vuln.severity == SeverityLevel.CRITICAL
    assert vuln.evidence['key'] == 'value'


def test_schema_vulnerability_to_dict():
    """Test converting vulnerability to dictionary."""
    vuln = SchemaVulnerability(
        vuln_id='SCHEMA-TEST',
        severity=SeverityLevel.HIGH,
        title='Test',
        description='Desc',
        endpoint='/api',
        payload='payload',
        evidence={'test': 123},
        remediation='Fix',
        bounty_estimate='$1000'
    )

    vuln_dict = vuln.to_dict()

    assert isinstance(vuln_dict, dict)
    assert vuln_dict['vuln_id'] == 'SCHEMA-TEST'
    assert vuln_dict['severity'] == 'high'
    assert vuln_dict['evidence']['test'] == 123


# ===== Schema Endpoint Model Tests =====

def test_schema_endpoint_creation():
    """Test SchemaEndpoint dataclass."""
    endpoint = SchemaEndpoint(
        path='/api/users',
        method='POST',
        parameters=[{'name': 'email'}],
        required_params=['email'],
        optional_params=['name'],
        security_schemes=['bearerAuth'],
        response_schemas={200: {'description': 'Success'}},
        deprecated=True,
        hidden=False,
        version='v1'
    )

    assert endpoint.path == '/api/users'
    assert endpoint.method == 'POST'
    assert endpoint.deprecated is True
    assert endpoint.hidden is False
    assert endpoint.version == 'v1'


# ===== Integration Tests =====

def test_full_analysis_workflow(schema_analyzer, openapi_spec):
    """Test complete analysis workflow."""
    with patch('requests.get') as mock_get:
        with patch('requests.post') as mock_post:
            # Mock OpenAPI discovery
            mock_response_get = Mock()
            mock_response_get.status_code = 200
            mock_response_get.headers = {'Content-Type': 'application/json'}
            mock_response_get.json.return_value = openapi_spec
            mock_get.return_value = mock_response_get

            # Mock POST requests for validation tests
            mock_response_post = Mock()
            mock_response_post.status_code = 400
            mock_post.return_value = mock_response_post

            vulnerabilities = schema_analyzer.analyze()

            # Should complete without errors
            assert isinstance(vulnerabilities, list)
            # Should have at least one vulnerability (missing auth on POST /users)
            assert len(vulnerabilities) >= 1


def test_run_schema_analysis_function(openapi_spec):
    """Test the run_schema_analysis helper function."""
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.json.return_value = openapi_spec
        mock_get.return_value = mock_response

        report = run_schema_analysis('https://api.example.com')

        assert isinstance(report, dict)
        assert 'target' in report
        assert 'statistics' in report
        assert 'vulnerabilities' in report


def test_analyze_with_custom_headers():
    """Test analysis with custom headers."""
    custom_headers = {
        'Authorization': 'Bearer token123',
        'X-Custom-Header': 'value'
    }

    analyzer = APISchemaAnalyzer(
        'https://api.example.com',
        headers=custom_headers
    )

    assert 'Authorization' in analyzer.headers
    assert analyzer.headers['X-Custom-Header'] == 'value'


# ===== Edge Cases =====

def test_request_exception_handling(schema_analyzer):
    """Test handling of request exceptions."""
    with patch('requests.get') as mock_get:
        mock_get.side_effect = Exception('Network error')

        # Should not crash
        result = schema_analyzer.discover_schemas()

        assert result is False


def test_malformed_json_response(schema_analyzer):
    """Test handling of malformed JSON responses."""
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_get.return_value = mock_response

        result = schema_analyzer.discover_schemas()

        # Should handle gracefully
        assert result is False


def test_empty_openapi_spec(schema_analyzer):
    """Test handling of empty OpenAPI spec."""
    schema_analyzer.openapi_spec = {'paths': {}}
    schema_analyzer.analyze_openapi_schema()

    # Should not crash
    assert len(schema_analyzer.discovered_endpoints) == 0


def test_timeout_handling(schema_analyzer):
    """Test handling of request timeouts."""
    with patch('requests.get') as mock_get:
        mock_get.side_effect = Timeout('Request timed out')

        result = schema_analyzer.discover_schemas()

        assert result is False


def test_yaml_not_available(schema_analyzer):
    """Test behavior when yaml module not available."""
    import engine.agents.api_schema_analyzer as module

    original_yaml = module.yaml
    module.yaml = None

    try:
        analyzer = APISchemaAnalyzer('https://api.example.com')

        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {'Content-Type': 'text/yaml'}
            mock_response.text = 'openapi: 3.0.0'
            mock_get.return_value = mock_response

            result = analyzer.discover_schemas()

            # Should skip YAML files when yaml not available
            assert result is False
    finally:
        module.yaml = original_yaml


# ===== Severity Level Tests =====

def test_severity_levels():
    """Test all severity levels are defined."""
    assert SeverityLevel.CRITICAL.value == 'critical'
    assert SeverityLevel.HIGH.value == 'high'
    assert SeverityLevel.MEDIUM.value == 'medium'
    assert SeverityLevel.LOW.value == 'low'
    assert SeverityLevel.INFO.value == 'info'


# ===== Schema Type Tests =====

def test_schema_types():
    """Test all schema types are defined."""
    assert SchemaType.OPENAPI_2.value == 'openapi_2.0'
    assert SchemaType.OPENAPI_3.value == 'openapi_3.0'
    assert SchemaType.OPENAPI_31.value == 'openapi_3.1'
    assert SchemaType.GRAPHQL.value == 'graphql'
    assert SchemaType.UNKNOWN.value == 'unknown'


# ===== Output Format Tests =====

def test_report_sorting_by_severity(schema_analyzer):
    """Test vulnerabilities are sorted by severity in report."""
    schema_analyzer.vulnerabilities = [
        SchemaVulnerability('V1', SeverityLevel.LOW, 'T1', '', '', '', {}, '', ''),
        SchemaVulnerability('V2', SeverityLevel.CRITICAL, 'T2', '', '', '', {}, '', ''),
        SchemaVulnerability('V3', SeverityLevel.MEDIUM, 'T3', '', '', '', {}, '', ''),
        SchemaVulnerability('V4', SeverityLevel.HIGH, 'T4', '', '', '', {}, '', '')
    ]

    report = schema_analyzer.generate_report()
    severities = [v['severity'] for v in report['vulnerabilities']]

    # Should be sorted: critical, high, medium, low
    assert severities == ['critical', 'high', 'medium', 'low']


def test_statistics_accuracy(schema_analyzer):
    """Test statistics are calculated accurately."""
    schema_analyzer.vulnerabilities = [
        SchemaVulnerability('V1', SeverityLevel.CRITICAL, '', '', '', '', {}, '', ''),
        SchemaVulnerability('V2', SeverityLevel.CRITICAL, '', '', '', '', {}, '', ''),
        SchemaVulnerability('V3', SeverityLevel.HIGH, '', '', '', '', {}, '', ''),
        SchemaVulnerability('V4', SeverityLevel.MEDIUM, '', '', '', '', {}, '', ''),
        SchemaVulnerability('V5', SeverityLevel.LOW, '', '', '', '', {}, '', ''),
        SchemaVulnerability('V6', SeverityLevel.INFO, '', '', '', '', {}, '', '')
    ]

    report = schema_analyzer.generate_report()
    stats = report['statistics']['by_severity']

    assert stats['critical'] == 2
    assert stats['high'] == 1
    assert stats['medium'] == 1
    assert stats['low'] == 1
    assert stats['info'] == 1
    assert report['statistics']['total_vulnerabilities'] == 6
