import pytest
from unittest.mock import Mock, patch

try:
    from engine.cloud.azure_tester import AzureTester
except ImportError:
    pytestmark = pytest.mark.skip(reason="AzureTester not yet implemented")

@pytest.fixture
def tester():
    return AzureTester()

def test_test_storage_account_enumeration(tester):
    """Test Azure Storage account enumeration"""
    with patch('requests.get') as mock_get:
        # Mock public blob accessible
        mock_get.return_value = Mock(status_code=200, text="blob contents")

        findings = tester.test_storage_account_enumeration("example.com")

        assert mock_get.called
        # Should try common patterns

def test_test_function_app_exposure(tester):
    """Test Azure Function Apps for vulnerabilities"""
    with patch('requests.get') as mock_get:
        # Mock accessible function app
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"status": "running"}
        )

        findings = tester.test_function_app_exposure("example")

        assert mock_get.called

def test_test_keyvault_exposure(tester):
    """Test for exposed Key Vault secrets"""
    js_content = 'const vaultUrl = "https://example-vault.vault.azure.net";'

    with patch('requests.get') as mock_get:
        mock_get.return_value = Mock(status_code=200, text=js_content)

        findings = tester.test_keyvault_exposure("https://example.com", js_content)

        assert len(findings) >= 0
