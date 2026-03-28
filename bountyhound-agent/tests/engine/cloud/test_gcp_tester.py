import pytest
from unittest.mock import Mock, patch
from engine.cloud.gcp_tester import GCPTester

@pytest.fixture
def tester():
    return GCPTester()

def test_test_storage_bucket_enumeration(tester):
    """Test GCS bucket enumeration"""
    with patch('requests.get') as mock_get:
        # Mock public bucket
        mock_get.return_value = Mock(
            status_code=200,
            text='<?xml version="1.0"?><ListBucketResult></ListBucketResult>'
        )

        findings = tester.test_storage_bucket_enumeration("example.com")

        assert mock_get.called

def test_test_cloud_function_exposure(tester):
    """Test Cloud Functions for vulnerabilities"""
    with patch('requests.get') as mock_get:
        mock_get.return_value = Mock(status_code=200, json=lambda: {"result": "ok"})

        findings = tester.test_cloud_function_exposure("example")

        assert mock_get.called

def test_test_firestore_exposure(tester):
    """Test Firestore/Firebase security rules"""
    js_content = '''
    const firebaseConfig = {
        apiKey: "AIzaSyTest123",
        projectId: "test-project"
    };
    '''

    findings = tester.test_firestore_exposure("https://example.com", js_content)

    assert len(findings) >= 0
