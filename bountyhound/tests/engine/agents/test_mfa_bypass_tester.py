import pytest
from unittest.mock import Mock, patch
from engine.agents.mfa_bypass_tester import MFABypassTester

@pytest.fixture
def tester():
    return MFABypassTester()

def test_test_response_manipulation(tester):
    """Test response manipulation bypass"""
    with patch('engine.agents.mfa_bypass_tester.requests.post') as mock_post:
        # Mock MFA challenge response
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"mfa_required": True, "session": "abc123"}
        )

        findings = tester.test_response_manipulation("https://example.com/login")

        assert mock_post.called

def test_test_direct_endpoint_access(tester):
    """Test direct access to post-MFA endpoints"""
    with patch('engine.agents.mfa_bypass_tester.requests.get') as mock_get:
        # Mock successful access without MFA
        mock_get.return_value = Mock(status_code=200, text="Dashboard")

        findings = tester.test_direct_endpoint_access("https://example.com/dashboard", session_token="abc123")

        assert mock_get.called

def test_test_code_reuse(tester):
    """Test if MFA codes can be reused"""
    with patch('engine.agents.mfa_bypass_tester.requests.post') as mock_post:
        # Mock successful login with same code
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"status": "success"}
        )

        findings = tester.test_code_reuse("https://example.com/verify-mfa", "123456")

        assert mock_post.call_count >= 2  # Should try code multiple times

def test_test_rate_limiting(tester):
    """Test MFA code rate limiting"""
    with patch('engine.agents.mfa_bypass_tester.requests.post') as mock_post:
        # Mock no rate limiting
        mock_post.return_value = Mock(
            status_code=400,
            text="invalid code"
        )

        findings = tester.test_rate_limiting("https://example.com/verify-mfa", attempts=50)

        # Should make many attempts
        assert mock_post.call_count >= 40

def test_test_backup_code_weaknesses(tester):
    """Test backup code security"""
    with patch('engine.agents.mfa_bypass_tester.requests.post') as mock_post:
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"status": "invalid_code"}
        )

        findings = tester.test_backup_code_weaknesses("https://example.com/verify-backup")

        assert mock_post.called

def test_generate_totp_code(tester):
    """Test TOTP code generation"""
    secret = "JBSWY3DPEHPK3PXP"
    code = tester._generate_totp_code(secret)

    assert len(code) == 6
    assert code.isdigit()
