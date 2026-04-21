"""
Tests for GraphQL Advanced Tester Agent

Comprehensive tests covering all GraphQL attack vectors:
- DoS attacks (circular queries, field duplication, fragment recursion)
- Batch query abuse
- Directive injection
- Subscription flooding
- Introspection bypass
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import Timeout

from engine.agents.graphql_advanced_tester import (
    GraphQLAdvancedTester,
    GraphQLFinding
)


# ===== Fixtures =====

@pytest.fixture
def graphql_tester():
    """Create GraphQL tester instance."""
    return GraphQLAdvancedTester(
        url='https://api.example.com/graphql',
        timeout=10
    )


@pytest.fixture
def mock_response():
    """Create mock response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {'data': {}}
    return response


# ===== Initialization Tests =====

def test_graphql_tester_initialization():
    """Test GraphQL tester initializes correctly."""
    tester = GraphQLAdvancedTester(
        url='https://api.example.com/graphql',
        timeout=15,
        headers={'Authorization': 'Bearer token'}
    )

    assert tester.url == 'https://api.example.com/graphql'
    assert tester.timeout == 15
    assert 'Authorization' in tester.headers
    assert tester.findings == []
    assert tester.schema == {}


def test_graphql_tester_default_headers():
    """Test default headers are set correctly."""
    tester = GraphQLAdvancedTester('https://api.example.com/graphql')

    assert 'Content-Type' in tester.headers
    assert tester.headers['Content-Type'] == 'application/json'
    assert 'User-Agent' in tester.headers


# ===== DoS Attack Tests =====

def test_circular_query_dos_vulnerable(graphql_tester):
    """Test circular query DoS detection when vulnerable."""
    with patch('requests.post') as mock_post:
        # Simulate slow response (> 5 seconds)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}

        # Mock time to simulate 6 second response
        with patch('time.time', side_effect=[0, 6]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_circular_query_dos()

            assert result is True
            assert len(graphql_tester.findings) == 1
            finding = graphql_tester.findings[0]
            assert finding.severity == 'HIGH'
            assert finding.vuln_type == 'DOS'
            assert 'Circular Query' in finding.title


def test_circular_query_dos_timeout(graphql_tester):
    """Test circular query DoS when request times out."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = Timeout()

        result = graphql_tester.test_circular_query_dos()

        assert result is True
        assert len(graphql_tester.findings) == 1
        finding = graphql_tester.findings[0]
        assert 'Timeout' in finding.title


def test_circular_query_dos_protected(graphql_tester):
    """Test circular query DoS when protected."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}

        # Mock time to simulate 2 second response (< 5 seconds)
        with patch('time.time', side_effect=[0, 2]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_circular_query_dos()

            assert result is False
            assert len(graphql_tester.findings) == 0


def test_circular_query_dos_server_error(graphql_tester):
    """Test circular query DoS when server returns 500."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 500

        with patch('time.time', side_effect=[0, 2]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_circular_query_dos()

            assert result is True
            assert len(graphql_tester.findings) == 1


def test_field_duplication_dos_vulnerable(graphql_tester):
    """Test field duplication DoS detection."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}

        # Simulate slow response
        with patch('time.time', side_effect=[0, 7]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_field_duplication_dos()

            assert result is True
            assert len(graphql_tester.findings) == 1
            finding = graphql_tester.findings[0]
            assert 'Field Duplication' in finding.title
            assert finding.severity == 'MEDIUM'


def test_field_duplication_dos_protected(graphql_tester):
    """Test field duplication DoS when protected."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200

        with patch('time.time', side_effect=[0, 1]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_field_duplication_dos()

            assert result is False


def test_fragment_recursion_vulnerable(graphql_tester):
    """Test fragment recursion DoS detection."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 500

        with patch('time.time', side_effect=[0, 6]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_fragment_recursion()

            assert result is True
            assert len(graphql_tester.findings) == 1
            finding = graphql_tester.findings[0]
            assert 'Fragment Recursion' in finding.title


def test_fragment_recursion_protected(graphql_tester):
    """Test fragment recursion when protected."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200

        with patch('time.time', side_effect=[0, 2]):
            mock_post.return_value = mock_response

            result = graphql_tester.test_fragment_recursion()

            assert result is False


# ===== Batch Query Abuse Tests =====

def test_batch_query_abuse_vulnerable(graphql_tester):
    """Test batch query abuse detection."""
    with patch('requests.post') as mock_post:
        # Simulate successful batch processing
        batch_response = [{'data': {'user': {'email': f'user{i}@example.com'}}} for i in range(100)]
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = batch_response
        mock_post.return_value = mock_response

        result = graphql_tester.test_batch_query_abuse()

        assert result is True
        assert len(graphql_tester.findings) == 1
        finding = graphql_tester.findings[0]
        assert finding.severity == 'HIGH'
        assert finding.vuln_type == 'RATE_LIMIT_BYPASS'
        assert 'Batch Query' in finding.title


def test_batch_query_abuse_protected(graphql_tester):
    """Test batch query abuse when protected."""
    with patch('requests.post') as mock_post:
        # Simulate limited batch processing (< 50 queries)
        batch_response = [{'data': {'user': {'email': f'user{i}@example.com'}}} for i in range(10)]
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = batch_response
        mock_post.return_value = mock_response

        result = graphql_tester.test_batch_query_abuse()

        assert result is False


def test_batch_query_abuse_rejected(graphql_tester):
    """Test batch query when server rejects batching."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = graphql_tester.test_batch_query_abuse()

        assert result is False


def test_mutation_batching_vulnerable(graphql_tester):
    """Test mutation batching abuse detection."""
    with patch('requests.post') as mock_post:
        # Simulate 30 successful mutations
        batch_response = [
            {'data': {'createUser': {'id': i, 'email': f'test{i}@example.com'}}}
            for i in range(30)
        ]
        batch_response.extend([{'errors': [{'message': 'Failed'}]} for _ in range(20)])

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = batch_response
        mock_post.return_value = mock_response

        result = graphql_tester.test_mutation_batching()

        assert result is True
        assert len(graphql_tester.findings) == 1
        finding = graphql_tester.findings[0]
        assert 'Mutation Batching' in finding.title


def test_mutation_batching_protected(graphql_tester):
    """Test mutation batching when protected."""
    with patch('requests.post') as mock_post:
        # Simulate only 5 successful mutations
        batch_response = [
            {'data': {'createUser': {'id': i, 'email': f'test{i}@example.com'}}}
            for i in range(5)
        ]

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = batch_response
        mock_post.return_value = mock_response

        result = graphql_tester.test_mutation_batching()

        assert result is False


# ===== Directive Abuse Tests =====

def test_directive_abuse_vulnerable(graphql_tester):
    """Test directive abuse detection."""
    with patch('requests.post') as mock_post:
        # Simulate response with sensitive data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'user': {
                    'email': 'user@example.com',
                    'password': 'hashed_password',
                    'secretToken': 'secret123'
                }
            }
        }
        mock_post.return_value = mock_response

        result = graphql_tester.test_directive_abuse()

        assert result is True
        assert len(graphql_tester.findings) == 1
        finding = graphql_tester.findings[0]
        assert 'Directive' in finding.title
        assert finding.severity == 'MEDIUM'


def test_directive_abuse_protected(graphql_tester):
    """Test directive abuse when protected."""
    with patch('requests.post') as mock_post:
        # Simulate response without sensitive data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'user': {
                    'email': 'user@example.com',
                    'id': '123'
                }
            }
        }
        mock_post.return_value = mock_response

        result = graphql_tester.test_directive_abuse()

        assert result is False


# ===== Introspection Bypass Tests =====

def test_introspection_bypass_vulnerable(graphql_tester):
    """Test introspection bypass via field suggestions."""
    with patch('requests.post') as mock_post:
        # Simulate field suggestion error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': 'Cannot query field "invalidFieldNamezzz123". Did you mean "id", "email", "username"?'
            }]
        }
        mock_post.return_value = mock_response

        result = graphql_tester.test_introspection_bypass()

        assert result is True
        assert len(graphql_tester.findings) == 1
        finding = graphql_tester.findings[0]
        assert 'Schema Discovery' in finding.title
        assert finding.severity == 'LOW'


def test_introspection_bypass_protected(graphql_tester):
    """Test introspection bypass when protected."""
    with patch('requests.post') as mock_post:
        # Simulate generic error without suggestions
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': 'Cannot query field "invalidFieldNamezzz123".'
            }]
        }
        mock_post.return_value = mock_response

        result = graphql_tester.test_introspection_bypass()

        assert result is False


# ===== Schema Extraction Tests =====

def test_extract_schema_via_introspection(graphql_tester):
    """Test schema extraction via introspection."""
    with patch('requests.post') as mock_post:
        # Simulate successful introspection
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                '__schema': {
                    'queryType': {'name': 'Query'},
                    'mutationType': {'name': 'Mutation'},
                    'types': [
                        {
                            'name': 'User',
                            'kind': 'OBJECT',
                            'fields': [
                                {'name': 'id', 'type': {'name': 'ID', 'kind': 'SCALAR'}},
                                {'name': 'email', 'type': {'name': 'String', 'kind': 'SCALAR'}}
                            ]
                        }
                    ]
                }
            }
        }
        mock_post.return_value = mock_response

        schema = graphql_tester.extract_schema('https://api.example.com/graphql')

        assert schema is not None
        assert 'queryType' in schema
        assert schema['queryType']['name'] == 'Query'
        assert len(schema['types']) == 1


def test_extract_schema_via_suggestions(graphql_tester):
    """Test schema extraction via field suggestions fallback."""
    with patch('requests.post') as mock_post:
        # First call (introspection) fails, second call (suggestions) succeeds
        mock_response_1 = Mock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = {'errors': [{'message': 'Introspection disabled'}]}

        mock_response_2 = Mock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = {
            'errors': [{
                'message': 'Cannot query field "invalidFieldNamezzz123". Did you mean "id", "email"?'
            }]
        }

        mock_post.side_effect = [mock_response_1, mock_response_2]

        schema = graphql_tester.extract_schema('https://api.example.com/graphql')

        assert 'fields' in schema
        assert len(schema['fields']) > 0


def test_parse_suggestions():
    """Test parsing field suggestions from error message."""
    tester = GraphQLAdvancedTester('https://api.example.com/graphql')

    message = 'Cannot query field "invalid". Did you mean "id", "email", "username"?'
    suggestions = tester._parse_suggestions(message)

    assert len(suggestions) == 3
    assert 'id' in suggestions
    assert 'email' in suggestions
    assert 'username' in suggestions


# ===== Mutation Testing =====

def test_mutations_missing_auth(graphql_tester):
    """Test mutations with missing authorization."""
    mutations = ['createUser', 'deleteUser', 'updateUser']

    with patch('requests.post') as mock_post:
        # Simulate successful mutation without auth
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'createUser': {'id': '123'}
            }
        }
        mock_post.return_value = mock_response

        findings = graphql_tester.test_mutations(
            'https://api.example.com/graphql',
            mutations
        )

        assert len(findings) == 3  # All 3 mutations vulnerable
        for finding in findings:
            assert finding.severity == 'HIGH'
            assert finding.vuln_type == 'BROKEN_ACCESS_CONTROL'


def test_mutations_with_auth(graphql_tester):
    """Test mutations with proper authorization."""
    mutations = ['createUser']

    with patch('requests.post') as mock_post:
        # Simulate auth error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{'message': 'Unauthorized'}]
        }
        mock_post.return_value = mock_response

        findings = graphql_tester.test_mutations(
            'https://api.example.com/graphql',
            mutations
        )

        assert len(findings) == 0  # No vulnerabilities


# ===== Sensitive Field Detection =====

def test_find_sensitive_fields():
    """Test finding sensitive fields in schema."""
    tester = GraphQLAdvancedTester('https://api.example.com/graphql')

    schema = {
        'types': [
            {
                'name': 'User',
                'fields': [
                    {'name': 'id'},
                    {'name': 'email'},
                    {'name': 'password'},
                    {'name': 'apiKey'},
                    {'name': 'accessToken'},
                    {'name': 'creditCard'}
                ]
            }
        ]
    }

    sensitive = tester.find_sensitive_fields(schema)

    assert len(sensitive) == 4  # password, apiKey, accessToken, creditCard
    assert 'password' in sensitive
    assert 'apiKey' in sensitive
    assert 'accessToken' in sensitive
    assert 'creditCard' in sensitive


# ===== Full Scan Tests =====

def test_full_graphql_scan(graphql_tester):
    """Test complete GraphQL security scan."""
    with patch('requests.post') as mock_post:
        # Mock all responses to return protected state
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}

        with patch('time.time', side_effect=[0, 1] * 10):
            mock_post.return_value = mock_response

            findings = graphql_tester.test_graphql_endpoint(full_scan=True)

            # Should have attempted all tests
            assert mock_post.call_count >= 5


def test_quick_graphql_scan(graphql_tester):
    """Test quick GraphQL scan (not full)."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        findings = graphql_tester.test_graphql_endpoint(full_scan=False)

        # Should only run quick tests (introspection, batching)
        assert mock_post.call_count == 2


# ===== Finding Model Tests =====

def test_graphql_finding_creation():
    """Test GraphQL finding dataclass."""
    finding = GraphQLFinding(
        title='Test Finding',
        severity='HIGH',
        vuln_type='DOS',
        description='Test description',
        poc='query { test }',
        impact='Server crash',
        endpoint='https://api.example.com/graphql',
        evidence={'response_time': 10.5}
    )

    assert finding.title == 'Test Finding'
    assert finding.severity == 'HIGH'
    assert finding.vuln_type == 'DOS'
    assert finding.evidence['response_time'] == 10.5


def test_graphql_finding_to_dict():
    """Test converting finding to dictionary."""
    finding = GraphQLFinding(
        title='Test',
        severity='HIGH',
        vuln_type='DOS',
        description='Desc',
        poc='POC',
        impact='Impact',
        endpoint='https://api.example.com/graphql'
    )

    finding_dict = finding.to_dict()

    assert isinstance(finding_dict, dict)
    assert finding_dict['title'] == 'Test'
    assert finding_dict['severity'] == 'HIGH'
    assert 'evidence' in finding_dict


# ===== Summary Tests =====

def test_get_findings_summary(graphql_tester):
    """Test getting findings summary."""
    # Add some test findings
    graphql_tester.findings.append(GraphQLFinding(
        title='Test 1',
        severity='HIGH',
        vuln_type='DOS',
        description='',
        poc='',
        impact='',
        endpoint=''
    ))
    graphql_tester.findings.append(GraphQLFinding(
        title='Test 2',
        severity='MEDIUM',
        vuln_type='INFO_DISCLOSURE',
        description='',
        poc='',
        impact='',
        endpoint=''
    ))
    graphql_tester.findings.append(GraphQLFinding(
        title='Test 3',
        severity='HIGH',
        vuln_type='RATE_LIMIT_BYPASS',
        description='',
        poc='',
        impact='',
        endpoint=''
    ))

    summary = graphql_tester.get_findings_summary()

    assert summary['total_findings'] == 3
    assert summary['severity_counts']['HIGH'] == 2
    assert summary['severity_counts']['MEDIUM'] == 1
    assert len(summary['findings']) == 3


def test_print_summary_no_findings(graphql_tester, capsys):
    """Test printing summary with no findings."""
    graphql_tester._print_summary()

    captured = capsys.readouterr()
    assert '0 GraphQL vulnerabilities found' in captured.out


def test_print_summary_with_findings(graphql_tester, capsys):
    """Test printing summary with findings."""
    graphql_tester.findings.append(GraphQLFinding(
        title='Test Finding',
        severity='HIGH',
        vuln_type='DOS',
        description='Test',
        poc='',
        impact='Server crash',
        endpoint=''
    ))

    graphql_tester._print_summary()

    captured = capsys.readouterr()
    assert '1 GraphQL vulnerabilities found' in captured.out
    assert 'Test Finding' in captured.out
    assert 'HIGH: 1' in captured.out


# ===== Edge Cases =====

def test_request_exception_handling(graphql_tester):
    """Test handling of request exceptions."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = Exception('Connection error')

        # Should not crash, should return False
        result = graphql_tester.test_batch_query_abuse()

        assert result is False


def test_malformed_json_response(graphql_tester):
    """Test handling of malformed JSON responses."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_post.return_value = mock_response

        # Should not crash
        result = graphql_tester.test_introspection_bypass()

        assert result is False


def test_empty_schema(graphql_tester):
    """Test handling of empty schema."""
    sensitive = graphql_tester.find_sensitive_fields({})

    assert sensitive == []


# ===== Integration Tests =====

def test_multiple_vulnerabilities_detected(graphql_tester):
    """Test detecting multiple vulnerabilities in one scan."""
    with patch('requests.post') as mock_post:
        # Mock responses to trigger multiple vulnerabilities
        def response_side_effect(*args, **kwargs):
            query = kwargs.get('json', {}).get('query', '')

            # Circular query - slow response
            if 'CircularDoS' in query:
                response = Mock()
                response.status_code = 500
                return response

            # Batch query - vulnerable
            if isinstance(kwargs.get('json'), list):
                response = Mock()
                response.status_code = 200
                response.json.return_value = [{'data': {}}] * 100
                return response

            # Field suggestions - vulnerable
            if 'invalidFieldNamezzz123' in query:
                response = Mock()
                response.status_code = 200
                response.json.return_value = {
                    'errors': [{'message': 'Did you mean "id"?'}]
                }
                return response

            # Default response
            response = Mock()
            response.status_code = 200
            response.json.return_value = {'data': {}}
            return response

        mock_post.side_effect = response_side_effect

        with patch('time.time', side_effect=[0, 6] + [0, 1] * 10):
            findings = graphql_tester.test_graphql_endpoint(full_scan=True)

            # Should detect multiple vulnerabilities
            assert len(findings) >= 2


def test_test_depth_limit_alias(graphql_tester):
    """Test depth_limit is alias for circular_query_dos."""
    with patch.object(graphql_tester, 'test_circular_query_dos') as mock_circular:
        mock_circular.return_value = []

        result = graphql_tester.test_depth_limit('https://api.example.com/graphql')

        mock_circular.assert_called_once()


def test_test_batching_alias(graphql_tester):
    """Test batching is alias for batch_query_abuse."""
    with patch.object(graphql_tester, 'test_batch_query_abuse') as mock_batch:
        mock_batch.return_value = []

        result = graphql_tester.test_batching('https://api.example.com/graphql')

        mock_batch.assert_called_once()
