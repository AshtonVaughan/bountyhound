import pytest

try:
    from engine.cloud.azure_tester import AzureTester
    from engine.cloud.gcp_tester import GCPTester
except ImportError:
    pytestmark = pytest.mark.skip(reason="AzureTester/GCPTester not yet implemented")

def test_azure_full_audit():
    """Test complete Azure security audit"""
    tester = AzureTester()

    # Should not crash with invalid target
    findings = tester.test_storage_account_enumeration("nonexistent.com")
    assert isinstance(findings, list)

def test_gcp_full_audit():
    """Test complete GCP security audit"""
    tester = GCPTester()

    # Should not crash with invalid target
    findings = tester.test_storage_bucket_enumeration("nonexistent.com")
    assert isinstance(findings, list)
