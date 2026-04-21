"""
Tests for GCS Scanner
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError

from engine.cloud.gcp.gcs_scanner import GCSScanner


class TestGCSScanner:
    """Test suite for GCS Scanner"""

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_init_with_credentials(self, mock_client):
        """Test initialization with valid credentials"""
        scanner = GCSScanner(rate_limit=0.1, project_id='test-project')

        assert scanner.rate_limit == 0.1
        assert scanner.project_id == 'test-project'
        assert scanner.findings == []
        mock_client.assert_called_once()

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_init_anonymous(self, mock_client):
        """Test initialization in anonymous mode"""
        mock_client.side_effect = DefaultCredentialsError()
        mock_client.create_anonymous_client.return_value = Mock()

        scanner = GCSScanner()

        mock_client.create_anonymous_client.assert_called_once()

    def test_generate_bucket_names(self):
        """Test bucket name generation"""
        scanner = Mock()
        scanner.generate_bucket_names = GCSScanner.generate_bucket_names.__get__(scanner, GCSScanner)

        names = scanner.generate_bucket_names('example.com')

        assert 'example.com' in names
        assert 'example-backup' in names
        assert 'example-prod' in names
        assert 'example-dev' in names
        assert 'example-assets' in names
        assert 'example-terraform-state' in names
        assert len(names) > 20

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    @patch('engine.cloud.gcp.gcs_scanner.DatabaseHooks')
    @patch('engine.cloud.gcp.gcs_scanner.BountyHoundDB')
    def test_enumerate_buckets_skip(self, mock_db, mock_hooks, mock_client):
        """Test enumeration when database says to skip"""
        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'recommendations': ['Wait 7 days'],
            'previous_findings': []
        }

        scanner = GCSScanner()
        results = scanner.enumerate_buckets('example.com')

        assert results == []
        mock_hooks.before_test.assert_called_once()

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    @patch('engine.cloud.gcp.gcs_scanner.DatabaseHooks')
    @patch('engine.cloud.gcp.gcs_scanner.BountyHoundDB')
    def test_enumerate_buckets_proceed(self, mock_db, mock_hooks, mock_client):
        """Test enumeration when database check passes"""
        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test',
            'recommendations': ['Focus on backup buckets']
        }

        scanner = GCSScanner(rate_limit=0)
        scanner.check_bucket = Mock(return_value=None)

        results = scanner.enumerate_buckets('example.com')

        assert isinstance(results, list)
        # Should call check_bucket for each generated name
        assert scanner.check_bucket.call_count > 0

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_not_found(self, mock_client):
        """Test checking a bucket that doesn't exist"""
        mock_bucket = Mock()
        mock_bucket.exists.return_value = False

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket('nonexistent-bucket')

        assert result is None

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_publicly_listable(self, mock_client):
        """Test detecting a publicly listable bucket"""
        mock_blob = Mock()
        mock_blob.name = 'test-file.txt'

        mock_bucket = Mock()
        mock_bucket.exists.return_value = True
        mock_bucket.list_blobs.return_value = [mock_blob]

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket('public-bucket')

        assert result is not None
        assert result['severity'] == 'CRITICAL'
        assert result['status'] == 'publicly_listable'
        assert 'sample_objects' in result

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_private(self, mock_client):
        """Test checking a private bucket"""
        mock_bucket = Mock()
        mock_bucket.exists.return_value = True
        mock_bucket.list_blobs.side_effect = gcp_exceptions.Forbidden('Access denied')

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket('private-bucket')

        assert result is not None
        assert result['severity'] == 'INFO'
        assert result['status'] == 'exists_private'

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_iam_public(self, mock_client):
        """Test detecting public IAM policy"""
        mock_binding = {
            'role': 'roles/storage.objectViewer',
            'members': ['allUsers']
        }
        mock_policy = Mock()
        mock_policy.bindings = [Mock(role='roles/storage.objectViewer', get=lambda x, default=[]: ['allUsers'])]

        mock_bucket = Mock()
        mock_bucket.get_iam_policy.return_value = mock_policy

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket_iam('test-bucket')

        assert result is not None
        assert len(result) > 0
        assert result[0]['severity'] == 'CRITICAL'

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_lifecycle(self, mock_client):
        """Test checking bucket lifecycle configuration"""
        mock_bucket = Mock()
        mock_bucket.lifecycle_rules = []

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket_lifecycle('test-bucket')

        assert result is not None
        assert result['severity'] == 'LOW'
        assert 'lifecycle' in result['issue'].lower()

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_versioning_disabled(self, mock_client):
        """Test detecting disabled versioning"""
        mock_bucket = Mock()
        mock_bucket.versioning_enabled = False

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket_versioning('test-bucket')

        assert result is not None
        assert result['severity'] == 'MEDIUM'
        assert 'versioning' in result['issue'].lower()

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_check_bucket_encryption(self, mock_client):
        """Test checking encryption configuration"""
        mock_bucket = Mock()
        mock_bucket.default_kms_key_name = None

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.check_bucket_encryption('test-bucket')

        assert result is not None
        assert result['severity'] == 'LOW'
        assert 'encryption' in result['issue'].lower()

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_test_object_upload_allowed(self, mock_client):
        """Test detecting unauthorized upload access"""
        mock_blob = Mock()
        mock_blob.upload_from_string.return_value = None
        mock_blob.delete.return_value = None

        mock_bucket = Mock()
        mock_bucket.blob.return_value = mock_blob

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.test_object_upload('writable-bucket')

        assert result is not None
        assert result['severity'] == 'CRITICAL'
        assert 'upload' in result['issue'].lower()

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_test_object_upload_forbidden(self, mock_client):
        """Test upload blocked by permissions"""
        mock_blob = Mock()
        mock_blob.upload_from_string.side_effect = gcp_exceptions.Forbidden('Access denied')

        mock_bucket = Mock()
        mock_bucket.blob.return_value = mock_blob

        mock_storage = Mock()
        mock_storage.bucket.return_value = mock_bucket
        mock_client.return_value = mock_storage

        scanner = GCSScanner(rate_limit=0)
        result = scanner.test_object_upload('protected-bucket')

        assert result is None

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_rate_limiting(self, mock_client):
        """Test rate limiting functionality"""
        scanner = GCSScanner(rate_limit=0.1)

        mock_func = Mock(return_value='result')

        import time
        start = time.time()

        # First call
        result1 = scanner._rate_limited_call(mock_func)

        # Second call should be delayed
        result2 = scanner._rate_limited_call(mock_func)

        elapsed = time.time() - start

        assert result1 == 'result'
        assert result2 == 'result'
        assert elapsed >= 0.1  # Rate limit was enforced

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_rate_limit_retry(self, mock_client):
        """Test retry on rate limit errors"""
        mock_func = Mock(side_effect=[
            gcp_exceptions.TooManyRequests('Rate limited'),
            'success'
        ])

        scanner = GCSScanner(rate_limit=0, max_retries=3)
        result = scanner._rate_limited_call(mock_func)

        assert result == 'success'
        assert mock_func.call_count == 2

    @patch('engine.cloud.gcp.gcs_scanner.storage.Client')
    def test_rate_limit_max_retries(self, mock_client):
        """Test max retries exhausted"""
        mock_func = Mock(side_effect=gcp_exceptions.TooManyRequests('Rate limited'))

        scanner = GCSScanner(rate_limit=0, max_retries=2)
        result = scanner._rate_limited_call(mock_func)

        assert result is None
        assert mock_func.call_count == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
