"""
Tests for Cloud Functions Tester
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError

from engine.cloud.gcp.functions_tester import CloudFunctionsTester


class TestCloudFunctionsTester:
    """Test suite for Cloud Functions Tester"""

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    def test_init_with_credentials(self, mock_client, mock_default):
        """Test initialization with valid credentials"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = CloudFunctionsTester(rate_limit=0.1, project_id='test-project')

        assert tester.rate_limit == 0.1
        assert tester.project_id == 'test-project'
        assert tester.findings == []

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.DatabaseHooks')
    @patch('engine.cloud.gcp.functions_tester.BountyHoundDB')
    def test_enumerate_functions_skip(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test enumeration when database says to skip"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': []
        }

        tester = CloudFunctionsTester()
        results = tester.enumerate_functions()

        assert results == []

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.DatabaseHooks')
    @patch('engine.cloud.gcp.functions_tester.BountyHoundDB')
    def test_enumerate_functions_proceed(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test enumeration when database check passes"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test'
        }

        mock_function = Mock()
        mock_function.name = 'projects/test/locations/us-central1/functions/test-func'
        mock_function.runtime = 'python39'
        mock_function.status.name = 'ACTIVE'
        mock_function.entry_point = 'main'
        mock_function.https_trigger = Mock()
        mock_function.https_trigger.url = 'https://test.cloudfunctions.net/test-func'
        mock_function.https_trigger.security_level.name = 'SECURE_ALWAYS'
        mock_function.service_account_email = None
        mock_function.environment_variables = {}

        mock_functions_client = Mock()
        mock_functions_client.list_functions.return_value = [mock_function]
        mock_client.return_value = mock_functions_client

        tester = CloudFunctionsTester(rate_limit=0)
        functions = tester.enumerate_functions()

        assert len(functions) == 1
        assert functions[0]['name'] == mock_function.name

    def test_extract_function_info_https(self):
        """Test extracting information from HTTP-triggered function"""
        tester = Mock()
        tester.extract_function_info = CloudFunctionsTester.extract_function_info.__get__(tester, CloudFunctionsTester)
        tester.check_env_variables = Mock()

        mock_function = Mock()
        mock_function.name = 'test-func'
        mock_function.runtime = 'nodejs18'
        mock_function.status.name = 'ACTIVE'
        mock_function.entry_point = 'helloWorld'
        mock_function.https_trigger = Mock()
        mock_function.https_trigger.url = 'https://test.com/func'
        mock_function.https_trigger.security_level.name = 'SECURE_OPTIONAL'
        mock_function.event_trigger = None
        mock_function.service_account_email = 'test@test.iam.gserviceaccount.com'
        mock_function.environment_variables = {}

        info = tester.extract_function_info(mock_function)

        assert info['trigger_type'] == 'https'
        assert info['url'] == 'https://test.com/func'
        assert info['security_level'] == 'SECURE_OPTIONAL'
        assert info['service_account'] == 'test@test.iam.gserviceaccount.com'

    def test_extract_function_info_event(self):
        """Test extracting information from event-triggered function"""
        tester = Mock()
        tester.extract_function_info = CloudFunctionsTester.extract_function_info.__get__(tester, CloudFunctionsTester)
        tester.check_env_variables = Mock()

        mock_function = Mock()
        mock_function.name = 'test-func'
        mock_function.runtime = 'python39'
        mock_function.status.name = 'ACTIVE'
        mock_function.entry_point = 'process_event'
        mock_function.https_trigger = None
        mock_function.event_trigger = Mock()
        mock_function.event_trigger.event_type = 'google.storage.object.finalize'
        mock_function.event_trigger.resource = 'projects/test/buckets/test-bucket'
        mock_function.service_account_email = None
        mock_function.environment_variables = {}

        info = tester.extract_function_info(mock_function)

        assert info['trigger_type'] == 'event'
        assert info['event_type'] == 'google.storage.object.finalize'

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.requests.get')
    def test_test_http_function_unauthenticated(self, mock_get, mock_client, mock_default):
        """Test detecting unauthenticated HTTP function"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        tester = CloudFunctionsTester(rate_limit=0)
        tester.test_cors = Mock()

        func_info = {
            'name': 'test-func',
            'url': 'https://test.com/func'
        }

        tester.test_http_function(func_info)

        assert len(tester.findings) > 0
        assert any(f['severity'] == 'HIGH' for f in tester.findings)

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.requests.get')
    def test_test_http_function_authenticated(self, mock_get, mock_client, mock_default):
        """Test function requiring authentication"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        tester = CloudFunctionsTester(rate_limit=0)
        tester.test_cors = Mock()

        func_info = {
            'name': 'test-func',
            'url': 'https://test.com/func'
        }

        initial_findings = len(tester.findings)
        tester.test_http_function(func_info)

        # No high-severity findings for authenticated function
        new_findings = tester.findings[initial_findings:]
        assert not any(f['severity'] == 'HIGH' for f in new_findings)

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.requests.options')
    def test_test_cors_wildcard(self, mock_options, mock_client, mock_default):
        """Test detecting CORS wildcard"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*'
        }
        mock_options.return_value = mock_response

        tester = CloudFunctionsTester(rate_limit=0)
        tester.test_cors('https://test.com/func')

        assert len(tester.findings) > 0
        assert any('CORS' in f['title'] for f in tester.findings)

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.requests.options')
    def test_test_cors_reflection_with_credentials(self, mock_options, mock_client, mock_default):
        """Test detecting CORS origin reflection with credentials"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true'
        }
        mock_options.return_value = mock_response

        tester = CloudFunctionsTester(rate_limit=0)
        tester.test_cors('https://test.com/func')

        assert len(tester.findings) > 0
        high_cors = [f for f in tester.findings if f['severity'] == 'HIGH' and 'CORS' in f['title']]
        assert len(high_cors) > 0

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    def test_check_env_variables_secrets(self, mock_client, mock_default):
        """Test detecting secrets in environment variables"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = CloudFunctionsTester(rate_limit=0)

        env_vars = {
            'API_KEY': 'abc123',
            'DATABASE_PASSWORD': 'secret',
            'STRIPE_SECRET': 'sk_test_123'
        }

        tester.check_env_variables('test-func', env_vars)

        assert len(tester.findings) >= 3

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    @patch('engine.cloud.gcp.functions_tester.requests.post')
    def test_test_function_invocation_error_leak(self, mock_post, mock_client, mock_default):
        """Test detecting information disclosure in error messages"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = 'Traceback (most recent call last): File "main.py", line 10...'
        mock_post.return_value = mock_response

        tester = CloudFunctionsTester(rate_limit=0)

        func_info = {
            'name': 'test-func',
            'url': 'https://test.com/func'
        }

        tester.test_function_invocation(func_info)

        assert any('Information Disclosure' in f['title'] for f in tester.findings)

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    def test_check_function_iam_public(self, mock_client, mock_default):
        """Test detecting public IAM policy on function"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_binding = Mock()
        mock_binding.role = 'roles/cloudfunctions.invoker'
        mock_binding.members = ['allUsers']

        mock_policy = Mock()
        mock_policy.bindings = [mock_binding]

        mock_functions_client = Mock()
        mock_functions_client.get_iam_policy.return_value = mock_policy
        mock_client.return_value = mock_functions_client

        tester = CloudFunctionsTester(rate_limit=0)
        result = tester.check_function_iam('projects/test/functions/test-func')

        assert result is not None
        assert len(result) > 0
        assert result[0]['severity'] == 'CRITICAL'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
