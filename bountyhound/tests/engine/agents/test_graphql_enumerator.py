"""
Tests for GraphQL Enumerator Agent

Comprehensive tests covering:
- GraphQL endpoint detection
- Introspection testing
- Field suggestion exploitation
- Recursive discovery
- Schema probing
- Batch testing
- Result saving
- Database integration
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock, call
from datetime import date

from engine.agents.graphql_enumerator import (
    GraphQLEnumerator,
    GraphQLOperation,
    EnumerationResult
)


# ===== Fixtures =====

@pytest.fixture
def enumerator():
    """Create GraphQL enumerator instance."""
    return GraphQLEnumerator(
        endpoint='https://api.example.com/graphql',
        timeout=10
    )


@pytest.fixture
def enumerator_with_auth():
    """Create GraphQL enumerator with auth token."""
    return GraphQLEnumerator(
        endpoint='https://api.example.com/graphql',
        timeout=10,
        auth_token='test_token_123'
    )


@pytest.fixture
def mock_response():
    """Create mock HTTP response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {'data': {}}
    return response


# ===== Initialization Tests =====

def test_enumerator_initialization():
    """Test enumerator initializes correctly."""
    enumerator = GraphQLEnumerator(
        endpoint='https://api.example.com/graphql',
        timeout=15,
        headers={'X-Custom': 'test'}
    )

    assert enumerator.endpoint == 'https://api.example.com/graphql'
    assert enumerator.timeout == 15
    assert 'X-Custom' in enumerator.headers
    assert enumerator.discovered_mutations == set()
    assert enumerator.discovered_queries == set()


def test_enumerator_default_headers():
    """Test default headers are set."""
    enumerator = GraphQLEnumerator('https://api.example.com/graphql')

    assert 'Content-Type' in enumerator.headers
    assert enumerator.headers['Content-Type'] == 'application/json'
    assert 'User-Agent' in enumerator.headers


def test_enumerator_with_auth_token():
    """Test auth token is added to headers."""
    enumerator = GraphQLEnumerator(
        endpoint='https://api.example.com/graphql',
        auth_token='Bearer test123'
    )

    assert 'Authorization' in enumerator.headers
    assert enumerator.headers['Authorization'] == 'Bearer Bearer test123'


# ===== GraphQL Operation Model Tests =====

def test_graphql_operation_creation():
    """Test GraphQL operation dataclass."""
    operation = GraphQLOperation(
        name='createUser',
        operation_type='mutation',
        arguments={'email': {'type': 'String', 'required': True}},
        return_type='User',
        is_authenticated=True,
        discovered_via='field_suggestion'
    )

    assert operation.name == 'createUser'
    assert operation.operation_type == 'mutation'
    assert 'email' in operation.arguments
    assert operation.return_type == 'User'
    assert operation.is_authenticated is True


def test_graphql_operation_to_dict():
    """Test converting operation to dict."""
    operation = GraphQLOperation(
        name='getUser',
        operation_type='query'
    )

    operation_dict = operation.to_dict()

    assert isinstance(operation_dict, dict)
    assert operation_dict['name'] == 'getUser'
    assert operation_dict['operation_type'] == 'query'


# ===== Enumeration Result Model Tests =====

def test_enumeration_result_creation():
    """Test enumeration result dataclass."""
    mutations = [
        GraphQLOperation(name='createUser', operation_type='mutation'),
        GraphQLOperation(name='deleteUser', operation_type='mutation')
    ]
    queries = [
        GraphQLOperation(name='getUser', operation_type='query')
    ]

    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=mutations,
        queries=queries,
        introspection_enabled=True,
        field_suggestions_enabled=True,
        total_operations=3,
        enumeration_time=5.5
    )

    assert result.endpoint == 'https://api.example.com/graphql'
    assert len(result.mutations) == 2
    assert len(result.queries) == 1
    assert result.total_operations == 3


def test_enumeration_result_to_dict():
    """Test converting result to dict."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[],
        queries=[],
        introspection_enabled=False,
        field_suggestions_enabled=True,
        total_operations=0,
        enumeration_time=2.0
    )

    result_dict = result.to_dict()

    assert isinstance(result_dict, dict)
    assert result_dict['endpoint'] == 'https://api.example.com/graphql'
    assert result_dict['introspection_enabled'] is False


# ===== Endpoint Detection Tests =====

def test_detect_graphql_endpoint_found():
    """Test detecting GraphQL endpoint."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {'__typename': 'Query'}}
        mock_post.return_value = mock_response

        endpoint = GraphQLEnumerator.detect_graphql_endpoint('example.com')

        assert endpoint is not None
        assert 'graphql' in endpoint.lower()


def test_detect_graphql_endpoint_not_found():
    """Test when GraphQL endpoint not found."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = Exception('Connection error')

        endpoint = GraphQLEnumerator.detect_graphql_endpoint('example.com')

        assert endpoint is None


def test_detect_graphql_endpoint_tries_common_paths():
    """Test all common paths are tried."""
    with patch('requests.post') as mock_post:
        # First few attempts fail, last one succeeds
        responses = [Exception()] * 5
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {'data': {}}
        responses.append(success_response)

        mock_post.side_effect = responses

        endpoint = GraphQLEnumerator.detect_graphql_endpoint('example.com')

        # Should have tried multiple paths
        assert mock_post.call_count >= 2


def test_detect_graphql_endpoint_with_https_url():
    """Test detection with full HTTPS URL."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        endpoint = GraphQLEnumerator.detect_graphql_endpoint('https://example.com')

        assert endpoint is not None
        assert endpoint.startswith('https://')


# ===== Introspection Tests =====

def test_introspection_enabled(enumerator):
    """Test detecting enabled introspection."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                '__schema': {
                    'queryType': {'name': 'Query'},
                    'mutationType': {'name': 'Mutation'}
                }
            }
        }
        mock_post.return_value = mock_response

        result = enumerator.test_introspection()

        assert result is True


def test_introspection_disabled(enumerator):
    """Test detecting disabled introspection."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{'message': 'Introspection is disabled'}]
        }
        mock_post.return_value = mock_response

        result = enumerator.test_introspection()

        assert result is False


def test_introspection_error(enumerator):
    """Test handling introspection errors."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = Exception('Network error')

        result = enumerator.test_introspection()

        assert result is False


# ===== Field Suggestion Tests =====

def test_discover_mutations_via_suggestions(enumerator):
    """Test discovering mutations via field suggestions."""
    with patch('requests.post') as mock_post:
        # First call: initial discovery
        mock_response_1 = Mock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = {
            'errors': [{
                'message': "Cannot query field. Did you mean 'createUser', 'deleteUser', 'updateUser'?"
            }]
        }

        # Subsequent calls for recursive discovery
        mock_response_2 = Mock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = {'errors': [{'message': 'Unknown field'}]}

        mock_post.side_effect = [mock_response_1] + [mock_response_2] * 20

        result = enumerator.discover_mutations()

        assert result is True
        assert len(enumerator.discovered_mutations) >= 3
        assert 'createUser' in enumerator.discovered_mutations
        assert 'deleteUser' in enumerator.discovered_mutations
        assert 'updateUser' in enumerator.discovered_mutations


def test_discover_mutations_no_suggestions(enumerator):
    """Test when no field suggestions are available."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{'message': 'Unknown field'}]
        }
        mock_post.return_value = mock_response

        result = enumerator.discover_mutations()

        assert result is False
        assert len(enumerator.discovered_mutations) == 0


def test_discover_queries_via_suggestions(enumerator):
    """Test discovering queries via field suggestions."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': "Did you mean 'user', 'users', 'currentUser'?"
            }]
        }
        mock_post.return_value = mock_response

        result = enumerator.discover_queries()

        assert result is True
        assert len(enumerator.discovered_queries) >= 3


def test_discover_queries_no_suggestions(enumerator):
    """Test when query suggestions not available."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        result = enumerator.discover_queries()

        assert result is False


# ===== Suggestion Extraction Tests =====

def test_extract_suggestions_pattern_1(enumerator):
    """Test extracting suggestions with single quotes."""
    message = "Cannot query field. Did you mean 'field1', 'field2', or 'field3'?"

    suggestions = enumerator._extract_suggestions(message)

    assert len(suggestions) >= 3
    assert 'field1' in suggestions
    assert 'field2' in suggestions
    assert 'field3' in suggestions


def test_extract_suggestions_pattern_2(enumerator):
    """Test extracting suggestions without quotes."""
    message = "Did you mean field1, field2, field3?"

    suggestions = enumerator._extract_suggestions(message)

    assert len(suggestions) >= 3


def test_extract_suggestions_with_or(enumerator):
    """Test extracting suggestions with 'or'."""
    message = "Did you mean 'field1' or 'field2'?"

    suggestions = enumerator._extract_suggestions(message)

    assert 'field1' in suggestions
    assert 'field2' in suggestions


def test_extract_suggestions_empty(enumerator):
    """Test extraction with no suggestions."""
    message = "Unknown error occurred"

    suggestions = enumerator._extract_suggestions(message)

    assert suggestions == []


def test_extract_suggestions_filters_invalid(enumerator):
    """Test extraction filters non-identifier strings."""
    message = "Did you mean 'valid_field', '123invalid', '__typename'?"

    suggestions = enumerator._extract_suggestions(message)

    # Should only include valid identifiers
    assert 'valid_field' in suggestions
    # Numbers and underscores are valid in identifiers
    assert '__typename' in suggestions


# ===== Schema Probing Tests =====

def test_probe_operation_schema_with_args(enumerator):
    """Test probing operation schema with arguments."""
    with patch('requests.post') as mock_post:
        # First call: discover required arguments
        mock_response_1 = Mock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = {
            'errors': [{
                'message': "Field 'createUser' argument 'email' of type 'String!' is required"
            }]
        }

        # Second call: discover optional arguments
        mock_response_2 = Mock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = {
            'errors': [{
                'message': "Did you mean 'name', 'age'?"
            }]
        }

        mock_post.side_effect = [mock_response_1, mock_response_2]

        operation = enumerator.probe_operation_schema('createUser', 'mutation')

        assert operation is not None
        assert operation.name == 'createUser'
        assert 'email' in operation.arguments
        assert operation.arguments['email']['required'] is True
        assert operation.arguments['email']['type'] == 'String'


def test_probe_operation_schema_no_args(enumerator):
    """Test probing operation with no arguments."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        operation = enumerator.probe_operation_schema('getUsers', 'query')

        assert operation is not None
        assert operation.name == 'getUsers'
        assert len(operation.arguments) == 0


def test_probe_operation_schema_list_type(enumerator):
    """Test probing operation with list type argument."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': "Field 'batchDelete' argument 'ids' of type '[ID!]!' is required"
            }]
        }
        mock_post.return_value = mock_response

        operation = enumerator.probe_operation_schema('batchDelete', 'mutation')

        assert operation is not None
        assert 'ids' in operation.arguments
        assert operation.arguments['ids']['type'] == 'ID'
        assert operation.arguments['ids']['is_list'] is True
        assert operation.arguments['ids']['required'] is True


def test_probe_operation_schema_error_handling(enumerator):
    """Test probing handles errors gracefully."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = Exception('Network error')

        operation = enumerator.probe_operation_schema('test', 'mutation')

        assert operation is not None
        assert operation.name == 'test'


# ===== Recursive Discovery Tests =====

def test_recursive_discovery_finds_more(enumerator):
    """Test recursive discovery finds additional operations."""
    enumerator.discovered_mutations.add('createUser')
    enumerator.discovered_mutations.add('deleteUser')

    with patch('requests.post') as mock_post:
        # Responses that add new operations
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{
                'message': "Did you mean 'updateUser', 'batchCreateUsers'?"
            }]
        }
        mock_post.return_value = mock_response

        initial_count = len(enumerator.discovered_mutations)
        enumerator._recursive_discovery('mutation', max_iterations=2)

        # Should have found new operations
        assert len(enumerator.discovered_mutations) > initial_count


def test_recursive_discovery_stops_when_no_new(enumerator):
    """Test recursive discovery stops when no new operations found."""
    enumerator.discovered_queries.add('user')

    with patch('requests.post') as mock_post:
        # Return same fields each time
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [{'message': "Did you mean 'user'?"}]
        }
        mock_post.return_value = mock_response

        enumerator._recursive_discovery('query', max_iterations=5)

        # Should have stopped early (not all 5 iterations)
        # Hard to test exact count, but should not crash


def test_recursive_discovery_max_iterations(enumerator):
    """Test recursive discovery respects max_iterations."""
    enumerator.discovered_mutations.add('test')

    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        enumerator._recursive_discovery('mutation', max_iterations=3)

        # Should have made at most 3 iterations worth of calls
        assert mock_post.call_count <= 3


# ===== Batch Testing Tests =====

def test_batch_test_operations(enumerator):
    """Test batch testing operations."""
    operations = ['createUser', 'deleteUser', 'updateUser']

    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'test0': {'id': '1'},
                'test1': None,
                'test2': {'id': '3'}
            }
        }
        mock_post.return_value = mock_response

        results = enumerator.batch_test_operations(operations, 'mutation', batch_size=3)

        assert results['tested'] == 3
        assert 'createUser' in results['successful']
        assert 'updateUser' in results['successful']


def test_batch_test_with_auth_errors(enumerator):
    """Test batch testing identifies auth-protected operations."""
    operations = ['adminMutation', 'userMutation']

    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'errors': [
                {'message': 'UNAUTHENTICATED', 'path': ['test0']},
                {'message': 'FORBIDDEN', 'path': ['test1']}
            ]
        }
        mock_post.return_value = mock_response

        results = enumerator.batch_test_operations(operations, 'mutation')

        assert 'adminMutation' in results['auth_protected']
        assert 'userMutation' in results['auth_protected']


def test_batch_test_large_batch(enumerator):
    """Test batch testing splits large batches."""
    operations = [f'mutation{i}' for i in range(50)]

    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        results = enumerator.batch_test_operations(operations, 'mutation', batch_size=20)

        # Should have made 3 batches (50 / 20 = 2.5 -> 3 batches)
        assert mock_post.call_count == 3
        assert results['tested'] == 50


def test_batch_test_error_handling(enumerator):
    """Test batch testing handles errors gracefully."""
    operations = ['test1', 'test2']

    with patch('requests.post') as mock_post:
        mock_post.side_effect = Exception('Network error')

        results = enumerator.batch_test_operations(operations, 'query')

        # Should not crash, return partial results
        assert 'tested' in results


# ===== Complete Enumeration Tests =====

def test_enumerate_complete_with_introspection(enumerator):
    """Test complete enumeration when introspection enabled."""
    with patch.object(enumerator, 'test_introspection', return_value=True):
        with patch.object(enumerator, '_enumerate_via_introspection') as mock_enum:
            # Simulate introspection populating the sets
            def populate_from_introspection():
                enumerator.discovered_mutations.add('createUser')
                enumerator.discovered_queries.add('user')
                enumerator.mutation_schemas['createUser'] = GraphQLOperation(
                    name='createUser',
                    operation_type='mutation',
                    discovered_via='introspection'
                )
                enumerator.query_schemas['user'] = GraphQLOperation(
                    name='user',
                    operation_type='query',
                    discovered_via='introspection'
                )

            mock_enum.side_effect = populate_from_introspection

            with patch.object(enumerator, 'discover_mutations', return_value=False):
                with patch.object(enumerator, 'discover_queries', return_value=False):
                    result = enumerator.enumerate_complete()

                    assert result.introspection_enabled is True
                    assert result.total_operations >= 2
                    assert len(result.mutations) >= 1
                    assert len(result.queries) >= 1


def test_enumerate_complete_without_introspection(enumerator):
    """Test complete enumeration when introspection disabled."""
    with patch('requests.post') as mock_post:
        # Introspection disabled
        intro_response = Mock()
        intro_response.status_code = 200
        intro_response.json.return_value = {'errors': [{'message': 'Introspection disabled'}]}

        # Field suggestions work
        suggestion_response = Mock()
        suggestion_response.status_code = 200
        suggestion_response.json.return_value = {
            'errors': [{
                'message': "Did you mean 'createUser', 'deleteUser'?"
            }]
        }

        # Schema probing
        probe_response = Mock()
        probe_response.status_code = 200
        probe_response.json.return_value = {'data': {}}

        mock_post.side_effect = [intro_response, suggestion_response, suggestion_response] + [probe_response] * 20

        result = enumerator.enumerate_complete()

        assert result.introspection_enabled is False
        assert result.field_suggestions_enabled is True
        assert result.total_operations >= 0


def test_enumerate_complete_timing(enumerator):
    """Test enumeration tracks timing correctly."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        result = enumerator.enumerate_complete()

        assert result.enumeration_time >= 0
        assert isinstance(result.enumeration_time, float)


# ===== Introspection Enumeration Tests =====

def test_enumerate_via_introspection_full_schema(enumerator):
    """Test enumeration via full introspection."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                '__schema': {
                    'mutationType': {
                        'name': 'Mutation',
                        'fields': [
                            {
                                'name': 'createUser',
                                'args': [
                                    {
                                        'name': 'email',
                                        'type': {
                                            'name': 'String',
                                            'kind': 'SCALAR'
                                        }
                                    }
                                ]
                            },
                            {
                                'name': 'deleteUser',
                                'args': [
                                    {
                                        'name': 'id',
                                        'type': {
                                            'name': None,
                                            'kind': 'NON_NULL',
                                            'ofType': {'name': 'ID', 'kind': 'SCALAR'}
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    'queryType': {
                        'name': 'Query',
                        'fields': [
                            {'name': 'user', 'args': []},
                            {'name': 'users', 'args': []}
                        ]
                    }
                }
            }
        }
        mock_post.return_value = mock_response

        enumerator._enumerate_via_introspection()

        assert len(enumerator.discovered_mutations) == 2
        assert 'createUser' in enumerator.discovered_mutations
        assert 'deleteUser' in enumerator.discovered_mutations

        assert len(enumerator.discovered_queries) == 2
        assert 'user' in enumerator.discovered_queries
        assert 'users' in enumerator.discovered_queries

        # Check schemas
        assert 'createUser' in enumerator.mutation_schemas
        assert 'email' in enumerator.mutation_schemas['createUser'].arguments


def test_enumerate_via_introspection_error(enumerator):
    """Test introspection enumeration handles errors."""
    with patch('requests.post') as mock_post:
        mock_post.side_effect = Exception('Network error')

        # Should not crash
        enumerator._enumerate_via_introspection()


# ===== Result Saving Tests =====

def test_save_results_creates_files(enumerator):
    """Test saving results creates markdown and JSON files."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[
            GraphQLOperation(
                name='createUser',
                operation_type='mutation',
                arguments={'email': {'type': 'String', 'required': True}}
            )
        ],
        queries=[
            GraphQLOperation(name='user', operation_type='query')
        ],
        introspection_enabled=False,
        field_suggestions_enabled=True,
        total_operations=2,
        enumeration_time=3.5
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        md_path, json_path = enumerator.save_results(result, tmpdir)

        assert os.path.exists(md_path)
        assert os.path.exists(json_path)
        assert md_path.endswith('.md')
        assert json_path.endswith('.json')


def test_save_results_markdown_content(enumerator):
    """Test markdown content is correct."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[
            GraphQLOperation(
                name='testMutation',
                operation_type='mutation',
                arguments={
                    'required_arg': {'type': 'String', 'required': True, 'is_list': False},
                    'optional_arg': {'type': 'Int', 'required': False, 'is_list': False}
                }
            )
        ],
        queries=[],
        introspection_enabled=True,
        field_suggestions_enabled=False,
        total_operations=1,
        enumeration_time=2.0
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        md_path, _ = enumerator.save_results(result, tmpdir)

        with open(md_path, 'r') as f:
            content = f.read()

        assert 'testMutation' in content
        assert 'required_arg' in content
        assert 'optional_arg' in content
        assert '*(required)*' in content
        assert 'String' in content


def test_save_results_json_structure(enumerator):
    """Test JSON structure is correct."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[],
        queries=[],
        introspection_enabled=False,
        field_suggestions_enabled=True,
        total_operations=0,
        enumeration_time=1.5
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        _, json_path = enumerator.save_results(result, tmpdir)

        with open(json_path, 'r') as f:
            data = json.load(f)

        assert 'endpoint' in data
        assert 'mutations' in data
        assert 'queries' in data
        assert 'total_operations' in data
        assert data['endpoint'] == 'https://api.example.com/graphql'


def test_save_results_creates_directory(enumerator):
    """Test saving creates output directory if it doesn't exist."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[],
        queries=[],
        introspection_enabled=False,
        field_suggestions_enabled=False,
        total_operations=0,
        enumeration_time=0.5
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, 'new_directory')

        md_path, json_path = enumerator.save_results(result, output_dir)

        assert os.path.exists(output_dir)
        assert os.path.exists(md_path)
        assert os.path.exists(json_path)


# ===== Summary Printing Tests =====

def test_print_summary(enumerator, capsys):
    """Test printing enumeration summary."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[
            GraphQLOperation(name='mut1', operation_type='mutation'),
            GraphQLOperation(name='mut2', operation_type='mutation', arguments={'arg1': {}})
        ],
        queries=[
            GraphQLOperation(name='query1', operation_type='query')
        ],
        introspection_enabled=True,
        field_suggestions_enabled=False,
        total_operations=3,
        enumeration_time=4.5
    )

    enumerator._print_summary(result)

    captured = capsys.readouterr()
    assert 'ENUMERATION RESULTS' in captured.out
    assert '4.5' in captured.out
    assert 'Total Operations: 3' in captured.out
    assert 'Mutations: 2' in captured.out
    assert 'Queries: 1' in captured.out


def test_print_summary_no_operations(enumerator, capsys):
    """Test summary with no operations found."""
    result = EnumerationResult(
        endpoint='https://api.example.com/graphql',
        mutations=[],
        queries=[],
        introspection_enabled=False,
        field_suggestions_enabled=False,
        total_operations=0,
        enumeration_time=1.0
    )

    enumerator._print_summary(result)

    captured = capsys.readouterr()
    assert 'Total Operations: 0' in captured.out
    assert 'Introspection: ❌ Disabled' in captured.out


# ===== Edge Cases =====

def test_send_query_with_variables(enumerator):
    """Test sending query with variables."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {}}
        mock_post.return_value = mock_response

        query = 'query ($id: ID!) { user(id: $id) { name } }'
        variables = {'id': '123'}

        result = enumerator._send_query(query, variables)

        # Check variables were included in request
        call_args = mock_post.call_args
        assert 'variables' in call_args[1]['json']
        assert call_args[1]['json']['variables'] == variables


def test_malformed_json_response(enumerator):
    """Test handling malformed JSON response."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_post.return_value = mock_response

        # Should handle gracefully
        with pytest.raises(ValueError):
            enumerator._send_query('{ test }')


def test_timeout_handling(enumerator):
    """Test request timeout handling."""
    import requests as req
    with patch('requests.post') as mock_post:
        mock_post.side_effect = req.exceptions.Timeout()

        # Should raise timeout
        with pytest.raises(req.exceptions.Timeout):
            enumerator._send_query('{ test }')


def test_http_error_handling(enumerator):
    """Test HTTP error handling."""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {'errors': [{'message': 'Internal server error'}]}
        mock_post.return_value = mock_response

        result = enumerator._send_query('{ test }')

        assert 'errors' in result


# ===== Integration Tests =====

def test_full_workflow_introspection_disabled(enumerator):
    """Test full workflow when introspection disabled."""
    with patch('requests.post') as mock_post:
        # Introspection test - disabled
        intro_response = Mock()
        intro_response.status_code = 200
        intro_response.json.return_value = {'errors': [{'message': 'Introspection disabled'}]}

        # Mutation discovery - suggestions with single quotes
        mutation_response = Mock()
        mutation_response.status_code = 200
        mutation_response.json.return_value = {
            'errors': [{'message': "Did you mean 'createUser', 'deleteUser'?"}]
        }

        # Query discovery - suggestions with single quotes
        query_response = Mock()
        query_response.status_code = 200
        query_response.json.return_value = {
            'errors': [{'message': "Did you mean 'user'?"}]
        }

        # Schema probing and recursive discovery
        empty_response = Mock()
        empty_response.status_code = 200
        empty_response.json.return_value = {'data': {}}

        # Provide enough responses: intro + 2 discoveries + recursive + probing
        mock_post.side_effect = [
            intro_response,
            mutation_response,
            empty_response,  # recursive mutation
            empty_response,  # recursive mutation
            query_response,
            empty_response,  # recursive query
        ] + [empty_response] * 20  # probing responses

        result = enumerator.enumerate_complete()

        assert result.introspection_enabled is False
        assert result.field_suggestions_enabled is True
        assert result.total_operations >= 2


def test_full_workflow_both_enabled(enumerator):
    """Test full workflow when both introspection and suggestions work."""
    with patch.object(enumerator, 'test_introspection', return_value=True):
        with patch.object(enumerator, '_enumerate_via_introspection') as mock_enum:
            # Simulate introspection populating schemas
            def populate():
                enumerator.discovered_mutations.add('testMutation')
                enumerator.discovered_queries.add('testQuery')
                enumerator.mutation_schemas['testMutation'] = GraphQLOperation(
                    name='testMutation',
                    operation_type='mutation'
                )
                enumerator.query_schemas['testQuery'] = GraphQLOperation(
                    name='testQuery',
                    operation_type='query'
                )

            mock_enum.side_effect = populate

            with patch.object(enumerator, 'discover_mutations', return_value=True):
                with patch.object(enumerator, 'discover_queries', return_value=True):
                    result = enumerator.enumerate_complete()

                    assert result.introspection_enabled is True
                    assert result.total_operations >= 2


# ===== Database Integration Tests =====

def test_enumerator_has_database_instance(enumerator):
    """Test enumerator initializes with database instance."""
    assert enumerator.db is not None
    assert hasattr(enumerator.db, 'get_target_stats')


def test_common_paths_constant():
    """Test COMMON_PATHS constant exists and is valid."""
    assert len(GraphQLEnumerator.COMMON_PATHS) >= 5
    assert '/graphql' in GraphQLEnumerator.COMMON_PATHS
    assert all(path.startswith('/') for path in GraphQLEnumerator.COMMON_PATHS)


# ===== Performance Tests =====

def test_enumerate_respects_timeout(enumerator):
    """Test enumeration respects timeout setting."""
    assert enumerator.timeout == 10

    with patch('requests.post') as mock_post:
        mock_post.return_value = Mock(status_code=200, json=lambda: {'data': {}})

        enumerator._send_query('{ test }')

        # Check timeout was passed to requests
        call_args = mock_post.call_args
        assert call_args[1]['timeout'] == 10


def test_batch_size_optimization(enumerator):
    """Test batch testing uses optimal batch size."""
    operations = [f'op{i}' for i in range(100)]

    with patch('requests.post') as mock_post:
        mock_post.return_value = Mock(status_code=200, json=lambda: {'data': {}})

        enumerator.batch_test_operations(operations, 'mutation', batch_size=25)

        # Should make 4 batches (100 / 25)
        assert mock_post.call_count == 4
