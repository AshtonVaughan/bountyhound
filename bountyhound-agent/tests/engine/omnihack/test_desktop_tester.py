import pytest
from unittest.mock import Mock, patch
from engine.omnihack.desktop_tester import DesktopTester

@pytest.fixture
def tester():
    return DesktopTester()

def test_test_update_mechanism(tester):
    """Test update mechanism security"""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(
            stdout="http://updates.example.com/latest.exe\nSome other text",
            returncode=0
        )

        findings = tester.test_update_mechanism("C:/Program Files/App/app.exe")

        assert isinstance(findings, list)

def test_scan_for_secrets(tester):
    """Test hardcoded secret scanning"""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(
            stdout="API_KEY=abc123\nPASSWORD=secret\n",
            returncode=0
        )

        findings = tester.scan_for_secrets("C:/Program Files/App/app.exe")

        assert isinstance(findings, list)

def test_test_privilege_escalation(tester):
    """Test privilege escalation vectors"""
    findings = tester.test_privilege_escalation("C:/Program Files/App/service.exe")

    assert isinstance(findings, list)

def test_unquoted_service_path_detected(tester):
    """Test detection of unquoted service path with spaces"""
    findings = tester.test_privilege_escalation("C:/Program Files/App/My Service.exe")

    assert isinstance(findings, list)
    assert len(findings) > 0
    assert findings[0].severity == "MEDIUM"
    assert "Unquoted" in findings[0].title
