"""
Tests for GCP IAM Tester
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys

# Mock GCP modules before importing
sys.modules['google.cloud.iam_credentials_v1'] = Mock()
sys.modules['google.cloud.resourcemanager_v3'] = Mock()
sys.modules['google.cloud.iam_admin_v1'] = Mock()

from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError

from engine.cloud.gcp.iam_tester import GCPIAMTester


class TestGCPIAMTester:
    """Test suite for GCP IAM Tester"""

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1')
    def test_init_with_credentials(self, mock_iam_creds, mock_default):
        """Test initialization with valid credentials"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')
        mock_iam_creds.IAMCredentialsClient.return_value = Mock()

        tester = GCPIAMTester(rate_limit=0.1, project_id='test-project')

        assert tester.rate_limit == 0.1
        assert tester.project_id == 'test-project'
        assert tester.findings == []

    @patch('engine.cloud.gcp.iam_tester.default')
    def test_init_no_credentials(self, mock_default):
        """Test initialization fails without credentials"""
        mock_default.side_effect = DefaultCredentialsError()

        with pytest.raises(DefaultCredentialsError):
            GCPIAMTester()

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_get_service_account_info(self, mock_client, mock_default):
        """Test getting service account information"""
        mock_creds = Mock()
        mock_creds.service_account_email = 'test@test.iam.gserviceaccount.com'
        mock_default.return_value = (mock_creds, 'test-project')

        tester = GCPIAMTester()
        info = tester.get_service_account_info()

        assert info['type'] == 'service_account'
        assert info['email'] == 'test@test.iam.gserviceaccount.com'

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_get_user_credentials_info(self, mock_client, mock_default):
        """Test getting user credentials information"""
        mock_creds = Mock(spec=[])  # No service_account_email attribute
        mock_default.return_value = (mock_creds, 'test-project')

        tester = GCPIAMTester()
        info = tester.get_service_account_info()

        assert info['type'] == 'user'

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    @patch('engine.cloud.gcp.iam_tester.DatabaseHooks')
    @patch('engine.cloud.gcp.iam_tester.BountyHoundDB')
    def test_enumerate_permissions_skip(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test enumeration when database says to skip"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': []
        }

        tester = GCPIAMTester()
        results = tester.enumerate_permissions()

        assert results['skipped'] is True
        assert 'reason' in results

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    @patch('engine.cloud.gcp.iam_tester.DatabaseHooks')
    @patch('engine.cloud.gcp.iam_tester.BountyHoundDB')
    def test_enumerate_permissions_proceed(self, mock_db, mock_hooks, mock_client, mock_default):
        """Test enumeration when database check passes"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test'
        }

        tester = GCPIAMTester(rate_limit=0)
        tester.get_service_account_info = Mock(return_value={'type': 'service_account'})
        tester.test_permissions = Mock(return_value=['storage.buckets.list'])

        results = tester.enumerate_permissions()

        assert 'permissions' in results
        assert isinstance(results['permissions'], list)

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    @patch('engine.cloud.gcp.iam_tester.storage')
    def test_test_permissions_storage(self, mock_storage, mock_client, mock_default):
        """Test checking storage permissions"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_storage_client = Mock()
        mock_storage_client.list_buckets.return_value = []
        mock_storage.Client.return_value = mock_storage_client

        tester = GCPIAMTester(rate_limit=0)
        tester.test_single_permission = Mock(return_value=False)

        permissions = tester.test_permissions()

        assert 'storage.buckets.list' in permissions

    def test_check_privilege_escalation_create_keys(self):
        """Test detecting CreateServiceAccountKeys escalation path"""
        tester = Mock()
        tester.check_privilege_escalation_paths = GCPIAMTester.check_privilege_escalation_paths.__get__(tester, GCPIAMTester)

        permissions = ['iam.serviceAccountKeys.create']
        paths = tester.check_privilege_escalation_paths(permissions)

        assert len(paths) > 0
        assert any(p['technique'] == 'CreateServiceAccountKeys' for p in paths)
        assert any(p['severity'] == 'CRITICAL' for p in paths)

    def test_check_privilege_escalation_act_as(self):
        """Test detecting ActAsServiceAccount escalation path"""
        tester = Mock()
        tester.check_privilege_escalation_paths = GCPIAMTester.check_privilege_escalation_paths.__get__(tester, GCPIAMTester)

        permissions = ['iam.serviceAccounts.actAs']
        paths = tester.check_privilege_escalation_paths(permissions)

        assert len(paths) > 0
        assert any(p['technique'] == 'ActAsServiceAccount' for p in paths)

    def test_check_privilege_escalation_modify_iam(self):
        """Test detecting ModifyProjectIAM escalation path"""
        tester = Mock()
        tester.check_privilege_escalation_paths = GCPIAMTester.check_privilege_escalation_paths.__get__(tester, GCPIAMTester)

        permissions = ['resourcemanager.projects.setIamPolicy']
        paths = tester.check_privilege_escalation_paths(permissions)

        assert len(paths) > 0
        assert any(p['technique'] == 'ModifyProjectIAM' for p in paths)
        assert any(p['severity'] == 'CRITICAL' for p in paths)

    def test_check_privilege_escalation_cloud_functions(self):
        """Test detecting Cloud Functions escalation path"""
        tester = Mock()
        tester.check_privilege_escalation_paths = GCPIAMTester.check_privilege_escalation_paths.__get__(tester, GCPIAMTester)

        permissions = ['cloudfunctions.functions.create']
        paths = tester.check_privilege_escalation_paths(permissions)

        assert len(paths) > 0
        assert any(p['technique'] == 'MaliciousCloudFunction' for p in paths)

    def test_check_privilege_escalation_compute_metadata(self):
        """Test detecting Compute metadata escalation path"""
        tester = Mock()
        tester.check_privilege_escalation_paths = GCPIAMTester.check_privilege_escalation_paths.__get__(tester, GCPIAMTester)

        permissions = ['compute.instances.setMetadata']
        paths = tester.check_privilege_escalation_paths(permissions)

        assert len(paths) > 0
        assert any(p['technique'] == 'ComputeMetadataEscalation' for p in paths)

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    @patch('engine.cloud.gcp.iam_tester.iam_admin_v1.IAMClient')
    def test_enumerate_service_accounts(self, mock_iam, mock_creds_client, mock_default):
        """Test enumerating service accounts"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_account = Mock()
        mock_account.email = 'test@test.iam.gserviceaccount.com'
        mock_account.display_name = 'Test Account'
        mock_account.unique_id = '123456'

        mock_response = Mock()
        mock_response.accounts = [mock_account]

        mock_iam_client = Mock()
        mock_iam_client.list_service_accounts.return_value = mock_response
        mock_iam.return_value = mock_iam_client

        tester = GCPIAMTester(rate_limit=0)
        accounts = tester.enumerate_service_accounts()

        assert len(accounts) == 1
        assert accounts[0]['email'] == 'test@test.iam.gserviceaccount.com'

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    @patch('engine.cloud.gcp.iam_tester.iam_admin_v1.IAMClient')
    def test_check_service_account_keys(self, mock_iam, mock_creds_client, mock_default):
        """Test listing service account keys"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        mock_key = Mock()
        mock_key.name = 'projects/test/serviceAccounts/test@test.iam.gserviceaccount.com/keys/key1'
        mock_key.key_type.name = 'USER_MANAGED'
        mock_key.valid_after_time = '2024-01-01'
        mock_key.valid_before_time = '2025-01-01'

        mock_response = Mock()
        mock_response.keys = [mock_key]

        mock_iam_client = Mock()
        mock_iam_client.list_service_account_keys.return_value = mock_response
        mock_iam.return_value = mock_iam_client

        tester = GCPIAMTester(rate_limit=0)
        keys = tester.check_service_account_keys('test@test.iam.gserviceaccount.com')

        assert len(keys) == 1
        assert keys[0]['key_type'] == 'USER_MANAGED'

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_add_finding(self, mock_client, mock_default):
        """Test adding a security finding"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = GCPIAMTester()
        tester.add_finding('HIGH', 'Test Finding', 'Test description')

        assert len(tester.findings) == 1
        assert tester.findings[0]['severity'] == 'HIGH'
        assert tester.findings[0]['title'] == 'Test Finding'

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_rate_limiting(self, mock_client, mock_default):
        """Test rate limiting functionality"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = GCPIAMTester(rate_limit=0.1)

        mock_func = Mock(return_value='result')

        import time
        start = time.time()

        # First call
        result1 = tester._rate_limited_call(mock_func)

        # Second call should be delayed
        result2 = tester._rate_limited_call(mock_func)

        elapsed = time.time() - start

        assert result1 == 'result'
        assert result2 == 'result'
        assert elapsed >= 0.1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
