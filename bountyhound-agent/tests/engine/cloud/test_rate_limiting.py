import pytest
import time
from unittest.mock import patch, MagicMock
from engine.cloud.aws.s3_enumerator import S3Enumerator
from engine.cloud.aws.iam_tester import IAMTester

def test_s3_enumerator_respects_rate_limit():
    """Test that S3 enumerator enforces rate limiting between requests"""

    with patch('boto3.client') as mock_boto:
        mock_s3 = MagicMock()
        mock_boto.return_value = mock_s3

        # Mock successful responses
        mock_s3.list_objects_v2.return_value = {'Contents': [], 'KeyCount': 0}

        enumerator = S3Enumerator(rate_limit=0.5)

        # Time the enumeration (will check 5 buckets)
        start_time = time.time()
        enumerator.enumerate_buckets(domain="example.com")
        elapsed = time.time() - start_time

        # Should have made multiple calls with delays
        # With rate_limit=0.5, if we made N calls, should take at least (N-1) * 0.5 seconds
        call_count = mock_s3.list_objects_v2.call_count
        if call_count > 1:
            expected_min_time = (call_count - 1) * 0.5
            assert elapsed >= expected_min_time * 0.9, \
                f"Rate limiting not enforced: {elapsed}s < {expected_min_time}s (made {call_count} calls)"

def test_iam_tester_respects_rate_limit():
    """Test that IAM tester enforces rate limiting"""

    with patch('boto3.client') as mock_boto:
        mock_iam = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service):
            return mock_iam if service == 'iam' else mock_sts

        mock_boto.side_effect = client_factory

        # Mock responses - must match boto3 response format
        mock_sts.get_caller_identity.return_value = {
            'UserId': 'AIDAI23HXW2HQ',
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/test'
        }

        # Mock list_users to trigger rate limiting
        mock_iam.list_users.return_value = {'Users': []}
        mock_iam.list_roles.return_value = {'Roles': []}
        mock_iam.list_policies.return_value = {'Policies': []}

        tester = IAMTester(rate_limit=0.3)

        start_time = time.time()
        tester.enumerate_permissions()
        elapsed = time.time() - start_time

        # Should have delays between permission checks
        # Count total API calls (sts + iam calls)
        total_calls = mock_sts.get_caller_identity.call_count + mock_iam.call_count
        if total_calls > 1:
            expected_min_time = (total_calls - 1) * 0.3
            assert elapsed >= expected_min_time * 0.9, \
                f"Rate limiting not enforced in IAM tester: {elapsed}s < {expected_min_time}s (made {total_calls} calls)"

def test_exponential_backoff_on_throttle():
    """Test that tools implement exponential backoff on rate limit errors"""

    with patch('boto3.client') as mock_boto:
        mock_s3 = MagicMock()
        mock_boto.return_value = mock_s3

        # Simulate throttling errors followed by success
        from botocore.exceptions import ClientError
        mock_s3.list_objects_v2.side_effect = [
            ClientError({'Error': {'Code': '429'}}, 'list_objects_v2'),
            ClientError({'Error': {'Code': 'ThrottlingException'}}, 'list_objects_v2'),
            {'Contents': [], 'KeyCount': 0}  # Success on 3rd try
        ]

        enumerator = S3Enumerator(max_retries=3)

        start_time = time.time()
        result = enumerator._check_bucket_exists("test-bucket")
        elapsed = time.time() - start_time

        # Should have exponential backoff delays
        # 1st retry: ~1s, 2nd retry: ~2s = ~3s total minimum
        assert elapsed >= 2.5, \
            f"Exponential backoff not working: {elapsed}s < 2.5s"

        # Should eventually succeed
        assert result is not None, "Should succeed after retries"
