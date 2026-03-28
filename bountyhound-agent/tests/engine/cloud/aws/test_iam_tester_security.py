"""
Security tests for IAM Tester - ensure no hardcoded credentials
"""

import pytest
import os
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../'))

from engine.cloud.aws.iam_tester import IAMTester


def test_uses_environment_credentials():
    """Test that IAMTester uses boto3's default credential chain"""
    with patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'test_key',
        'AWS_SECRET_ACCESS_KEY': 'test_secret'
    }):
        with patch('boto3.client') as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client

            tester = IAMTester()

            # Should have called boto3.client without explicit credentials
            # Check that boto3.client was called for both iam and sts
            assert mock_boto.call_count == 2
            calls = [str(call) for call in mock_boto.call_args_list]
            assert "call('iam')" in str(calls)
            assert "call('sts')" in str(calls)


def test_no_hardcoded_credentials_in_source():
    """Test that source code contains no hardcoded AWS keys"""
    import inspect
    source = inspect.getsource(IAMTester)

    # Should not contain any hardcoded access keys (AWS keys start with AKIA)
    assert 'AKIA' not in source, "Hardcoded AWS access key found in source"

    # Get just the __init__ method to check for credential parameters
    init_source = inspect.getsource(IAMTester.__init__)

    # Should not accept credentials as constructor parameters
    assert 'access_key' not in init_source, \
        "IAMTester.__init__ should not accept credential parameters"
    assert 'secret_key' not in init_source, \
        "IAMTester.__init__ should not accept credential parameters"


def test_no_credential_parameters_in_init():
    """Test that __init__ does not accept credential parameters"""
    import inspect
    sig = inspect.signature(IAMTester.__init__)
    params = list(sig.parameters.keys())

    # Should have self + rate limiting params (added in Task #25), but NO credential params
    assert 'self' in params, "Should have 'self' parameter"
    assert 'rate_limit' in params, "Should have 'rate_limit' parameter (Task #25)"
    assert 'max_retries' in params, "Should have 'max_retries' parameter (Task #25)"

    # CRITICAL: Should NOT have credential parameters
    assert 'access_key' not in params, "Should NOT have 'access_key' parameter"
    assert 'secret_key' not in params, "Should NOT have 'secret_key' parameter"
    assert 'aws_access_key_id' not in params, "Should NOT have 'aws_access_key_id' parameter"
    assert 'aws_secret_access_key' not in params, "Should NOT have 'aws_secret_access_key' parameter"


def test_helpful_error_when_no_credentials():
    """Test that helpful error is shown when credentials are missing"""
    with patch.dict(os.environ, {}, clear=True):
        # Remove AWS environment variables if they exist
        for key in list(os.environ.keys()):
            if key.startswith('AWS_'):
                del os.environ[key]

        with patch('boto3.client') as mock_boto:
            from botocore.exceptions import NoCredentialsError
            mock_boto.side_effect = NoCredentialsError()

            with pytest.raises(NoCredentialsError):
                tester = IAMTester()


def test_creates_iam_and_sts_clients():
    """Test that both IAM and STS clients are created"""
    with patch('boto3.client') as mock_boto:
        mock_client = MagicMock()
        mock_boto.return_value = mock_client

        tester = IAMTester()

        # Should have created both clients
        assert hasattr(tester, 'iam')
        assert hasattr(tester, 'sts')
        assert tester.iam is not None
        assert tester.sts is not None
