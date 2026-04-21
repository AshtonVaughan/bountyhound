import pytest
from unittest.mock import Mock, patch, MagicMock
from engine.mobile.ios.frida_hooker import iOSFridaHooker

@pytest.fixture
def hooker():
    """Create Frida hooker with mocked device"""
    with patch('frida.get_usb_device') as mock_device:
        mock_device.return_value = Mock()
        return iOSFridaHooker()

def test_hook_ssl_pinning(hooker):
    """Test SSL pinning bypass"""
    with patch.object(hooker.device, 'attach') as mock_attach:
        mock_session = Mock()
        mock_attach.return_value = mock_session

        result = hooker.hook_ssl_pinning("com.example.app")

        assert mock_attach.called
        # Should attach to app process

def test_hook_jailbreak_detection(hooker):
    """Test jailbreak detection bypass"""
    with patch.object(hooker.device, 'attach') as mock_attach:
        mock_session = Mock()
        mock_attach.return_value = mock_session

        result = hooker.hook_jailbreak_detection("com.example.app")

        assert mock_attach.called

def test_hook_biometric_auth(hooker):
    """Test biometric auth hooking"""
    with patch.object(hooker.device, 'attach') as mock_attach:
        mock_session = Mock()
        mock_session.create_script = Mock(return_value=Mock())
        mock_attach.return_value = mock_session

        hooker.hook_biometric_auth("com.example.app")

        assert mock_attach.called

def test_dump_keychain(hooker):
    """Test keychain dumping"""
    with patch.object(hooker.device, 'attach') as mock_attach:
        mock_session = Mock()
        mock_script = Mock()
        mock_script.exports = Mock(dumpKeychain=Mock(return_value={"items": []}))
        mock_session.create_script = Mock(return_value=mock_script)
        mock_attach.return_value = mock_session

        keychain = hooker.dump_keychain("com.example.app")

        assert isinstance(keychain, dict)

def test_monitor_api_calls(hooker):
    """Test API call monitoring"""
    with patch.object(hooker.device, 'attach') as mock_attach:
        mock_session = Mock()
        mock_attach.return_value = mock_session

        calls = hooker.monitor_api_calls("com.example.app", duration=1)

        assert isinstance(calls, list)

def test_inject_custom_hook(hooker):
    """Test custom hook injection"""
    hook_script = "console.log('test');"

    with patch.object(hooker.device, 'attach') as mock_attach:
        mock_session = Mock()
        mock_attach.return_value = mock_session

        hooker.inject_custom_hook("com.example.app", hook_script)

        assert mock_attach.called
