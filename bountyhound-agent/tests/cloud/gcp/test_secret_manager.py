"""
Tests for Secret Manager Tester
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError

from engine.cloud.gcp.secret_manager import SecretManagerTester


class TestSecretManagerTester:
    """Test suite for Secret Manager Tester"""

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_init_with_credentials(self, mock_client, mock_default):
        """Test initialization with valid credentials"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = SecretManagerTester(rate_limit=0.1, project_id='test-project')

        assert tester.rate_limit == 0.1
        assert tester.project_id == 'test-project'
        assert tester.findings == []

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    @patch('engine.cloud.gcp.secret_manager.DatabaseHooks')
    @patch('engine.cloud.gcp.secret_manager.BountyHoundDB')
    def test_enumerate_secrets_skip(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test when database says to skip"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': []
        }

        tester = SecretManagerTester()
        results = tester.enumerate_secrets()

        assert results == []

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    @patch('engine.cloud.gcp.secret_manager.DatabaseHooks')
    @patch('engine.cloud.gcp.secret_manager.BountyHoundDB')
    def test_enumerate_secrets_proceed(self, mock_db, mock_hooks, mock_sm_client, mock_default):
        """Test when database check passes"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test'
        }

        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/api-key'
        mock_secret.create_time = '2024-01-01'
        mock_secret.replication.automatic = True
        mock_secret.replication.user_managed = False
        mock_secret.labels = {}

        mock_client = Mock()
        mock_client.list_secrets.return_value = [mock_secret]
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        tester.test_secret_access = Mock()

        secrets = tester.enumerate_secrets()

        assert len(secrets) == 1
        assert secrets[0]['name'] == 'api-key'

    def test_extract_secret_info(self):
        """Test extracting secret information"""
        tester = Mock()
        tester.extract_secret_info = SecretManagerTester.extract_secret_info.__get__(tester, SecretManagerTester)

        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/db-password'
        mock_secret.create_time = '2024-01-01T00:00:00Z'
        mock_secret.replication.automatic = True
        mock_secret.replication.user_managed = False
        mock_secret.labels = {'env': 'prod'}

        info = tester.extract_secret_info(mock_secret)

        assert info['name'] == 'db-password'
        assert info['full_name'] == mock_secret.name
        assert info['replication'] == 'automatic'
        assert 'labels' in info

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_test_secret_access_allowed(self, mock_sm_client, mock_default):
        """Test detecting unauthorized secret access"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_payload = Mock()
        mock_payload.data = b'secret-value-12345'

        mock_result = Mock()
        mock_result.payload = mock_payload

        mock_client = Mock()
        mock_client.access_secret_version.return_value = mock_result
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        result = tester.test_secret_access('projects/test/secrets/api-key')

        assert result is not None
        assert result['severity'] == 'CRITICAL'
        assert result['issue'] == 'unauthorized_access'
        assert result['payload_length'] == 18

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_test_secret_access_forbidden(self, mock_sm_client, mock_default):
        """Test secret access blocked by permissions"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_client = Mock()
        mock_client.access_secret_version.side_effect = gcp_exceptions.PermissionDenied('Access denied')
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        result = tester.test_secret_access('projects/test/secrets/api-key')

        assert result is None

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_test_secret_iam_public(self, mock_sm_client, mock_default):
        """Test detecting public IAM policy on secret"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_binding = Mock()
        mock_binding.role = 'roles/secretmanager.secretAccessor'
        mock_binding.members = ['allUsers']

        mock_policy = Mock()
        mock_policy.bindings = [mock_binding]

        mock_client = Mock()
        mock_client.get_iam_policy.return_value = mock_policy
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        result = tester.test_secret_iam('projects/test/secrets/api-key')

        assert result is not None
        assert len(result) > 0
        assert result[0]['severity'] == 'CRITICAL'

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_test_secret_iam_authenticated_users(self, mock_sm_client, mock_default):
        """Test detecting overly permissive IAM policy"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_binding = Mock()
        mock_binding.role = 'roles/secretmanager.secretAccessor'
        mock_binding.members = ['allAuthenticatedUsers']

        mock_policy = Mock()
        mock_policy.bindings = [mock_binding]

        mock_client = Mock()
        mock_client.get_iam_policy.return_value = mock_policy
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        result = tester.test_secret_iam('projects/test/secrets/api-key')

        assert result is not None
        assert len(result) > 0
        assert result[0]['severity'] == 'HIGH'

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_test_secret_versions(self, mock_sm_client, mock_default):
        """Test listing secret versions"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_version1 = Mock()
        mock_version1.name = 'projects/test/secrets/api-key/versions/1'
        mock_version1.state.name = 'ENABLED'
        mock_version1.create_time = '2024-01-01'

        mock_version2 = Mock()
        mock_version2.name = 'projects/test/secrets/api-key/versions/2'
        mock_version2.state.name = 'ENABLED'
        mock_version2.create_time = '2024-02-01'

        mock_client = Mock()
        mock_client.list_secret_versions.return_value = [mock_version1, mock_version2]
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        versions = tester.test_secret_versions('projects/test/secrets/api-key')

        assert len(versions) == 2
        # Should create finding for multiple enabled versions
        assert any('Multiple Secret Versions' in f['title'] for f in tester.findings)

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_test_common_secret_names(self, mock_sm_client, mock_default):
        """Test finding common secret names"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/api-key'

        mock_client = Mock()

        def get_secret_side_effect(name):
            if 'api-key' in name or 'database-password' in name:
                return mock_secret
            raise gcp_exceptions.NotFound('Secret not found')

        mock_client.get_secret.side_effect = get_secret_side_effect
        mock_sm_client.return_value = mock_client

        tester = SecretManagerTester(rate_limit=0)
        tester.test_secret_access = Mock(return_value={'severity': 'CRITICAL'})

        findings = tester.test_common_secret_names()

        # Should find at least the api-key and database-password
        assert len(findings) >= 2

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_add_finding(self, mock_client, mock_default):
        """Test adding a security finding"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = SecretManagerTester()
        tester.add_finding('CRITICAL', 'Test Finding', 'Test description')

        assert len(tester.findings) == 1
        assert tester.findings[0]['severity'] == 'CRITICAL'
        assert tester.findings[0]['title'] == 'Test Finding'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
