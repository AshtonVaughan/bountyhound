"""
Integration Tests for GCP Security Module
"""

import pytest
from unittest.mock import Mock, patch

from engine.cloud.gcp import (
    GCSScanner,
    GCPIAMTester,
    CloudFunctionsTester,
    FirestoreTester,
    SecretManagerTester
)


class TestGCPIntegration:
    """Integration tests for GCP security testing module"""

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_gcs_scanner_import(self, mock_client):
        """Test GCS Scanner can be imported and initialized"""
        scanner = GCSScanner(rate_limit=0)
        assert scanner is not None
        assert hasattr(scanner, 'enumerate_buckets')
        assert hasattr(scanner, 'check_bucket')

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_iam_tester_import(self, mock_client, mock_default):
        """Test IAM Tester can be imported and initialized"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = GCPIAMTester(rate_limit=0)
        assert tester is not None
        assert hasattr(tester, 'enumerate_permissions')
        assert hasattr(tester, 'check_privilege_escalation_paths')

    @patch('engine.cloud.gcp.functions_tester.default')
    @patch('engine.cloud.gcp.functions_tester.functions_v1.CloudFunctionsServiceClient')
    def test_functions_tester_import(self, mock_client, mock_default):
        """Test Cloud Functions Tester can be imported and initialized"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = CloudFunctionsTester(rate_limit=0)
        assert tester is not None
        assert hasattr(tester, 'enumerate_functions')
        assert hasattr(tester, 'test_http_function')

    @patch('engine.cloud.gcp.firestore_tester.default')
    @patch('engine.cloud.gcp.firestore_tester.firestore.Client')
    def test_firestore_tester_import(self, mock_client, mock_default):
        """Test Firestore Tester can be imported and initialized"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = FirestoreTester(rate_limit=0)
        assert tester is not None
        assert hasattr(tester, 'test_collections')
        assert hasattr(tester, 'test_collection_access')

    @patch('engine.cloud.gcp.secret_manager.default')
    @patch('engine.cloud.gcp.secret_manager.secretmanager.SecretManagerServiceClient')
    def test_secret_manager_import(self, mock_client, mock_default):
        """Test Secret Manager Tester can be imported and initialized"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        tester = SecretManagerTester(rate_limit=0)
        assert tester is not None
        assert hasattr(tester, 'enumerate_secrets')
        assert hasattr(tester, 'test_secret_access')

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_multiple_testers_concurrent(self, mock_iam_client, mock_default, mock_storage):
        """Test multiple testers can be initialized concurrently"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, 'test-project')

        scanner = GCSScanner(rate_limit=0)
        tester = GCPIAMTester(rate_limit=0)

        assert scanner is not None
        assert tester is not None
        assert scanner.rate_limit == 0
        assert tester.rate_limit == 0

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_gcs_scanner_workflow(self, mock_client):
        """Test complete GCS scanner workflow"""
        mock_bucket = Mock()
        mock_bucket.exists.return_value = True
        mock_bucket.list_blobs.return_value = []

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)

        # Test bucket name generation
        names = scanner.generate_bucket_names('example.com')
        assert len(names) > 0

        # Test bucket check
        result = scanner.check_bucket('test-bucket')
        assert result is not None

    @patch('engine.cloud.gcp.iam_tester.default')
    @patch('engine.cloud.gcp.iam_tester.iam_credentials_v1.IAMCredentialsClient')
    def test_iam_tester_workflow(self, mock_client, mock_default):
        """Test complete IAM tester workflow"""
        mock_creds = Mock()
        mock_creds.service_account_email = 'test@test.iam.gserviceaccount.com'
        mock_default.return_value = (mock_creds, 'test-project')

        tester = GCPIAMTester(rate_limit=0)

        # Test service account info
        info = tester.get_service_account_info()
        assert info['type'] == 'service_account'

        # Test escalation path detection
        permissions = ['iam.serviceAccountKeys.create']
        paths = tester.check_privilege_escalation_paths(permissions)
        assert len(paths) > 0

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    @patch('engine.cloud.gcp.gcs_scanner.DatabaseHooks')
    def test_database_integration(self, mock_hooks, mock_client):
        """Test database hooks integration"""
        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test',
            'recommendations': []
        }

        scanner = GCSScanner(rate_limit=0)
        scanner.check_bucket = Mock(return_value=None)

        # Should call database hooks
        scanner.enumerate_buckets('example.com')

        mock_hooks.before_test.assert_called()

    def test_all_exports(self):
        """Test all expected exports are available"""
        from engine.cloud.gcp import __all__

        expected = [
            'GCSScanner',
            'GCPIAMTester',
            'CloudFunctionsTester',
            'FirestoreTester',
            'SecretManagerTester'
        ]

        for export in expected:
            assert export in __all__

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_error_handling_no_credentials(self, mock_client):
        """Test graceful error handling without credentials"""
        from google.auth.exceptions import DefaultCredentialsError

        mock_client.side_effect = DefaultCredentialsError()
        mock_client.create_anonymous_client.return_value = Mock()

        # Should fall back to anonymous client
        scanner = GCSScanner(rate_limit=0)
        assert scanner.storage_client is not None

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_rate_limiting_across_modules(self, mock_client):
        """Test rate limiting is enforced across all modules"""
        import time

        scanner = GCSScanner(rate_limit=0.1)

        mock_func = Mock(return_value='result')

        start = time.time()
        scanner._rate_limited_call(mock_func)
        scanner._rate_limited_call(mock_func)
        elapsed = time.time() - start

        # Should enforce rate limit
        assert elapsed >= 0.1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
