import pytest
from unittest.mock import Mock, patch
from engine.hardware.iot_tester import IoTTester

@pytest.fixture
def tester():
    return IoTTester()

def test_scan_network_devices(tester):
    """Test IoT device discovery on network"""
    with patch('subprocess.run') as mock_run:
        # Mock nmap output
        mock_run.return_value = Mock(
            stdout="Host: 192.168.1.100\nPort 1883/tcp open mqtt\n",
            returncode=0
        )

        devices = tester.scan_network_devices("192.168.1.0/24")

        assert isinstance(devices, list)

def test_test_mqtt_security(tester):
    """Test MQTT broker security"""
    with patch('paho.mqtt.client.Client') as mock_client:
        mock_mqtt = Mock()
        mock_client.return_value = mock_mqtt

        findings = tester.test_mqtt_security("192.168.1.100:1883")

        assert isinstance(findings, list)

def test_test_upnp_vulnerabilities(tester):
    """Test UPnP security"""
    with patch('requests.get') as mock_get:
        mock_get.return_value = Mock(
            status_code=200,
            text='<?xml version="1.0"?><root></root>'
        )

        findings = tester.test_upnp_vulnerabilities("192.168.1.100")

        assert isinstance(findings, list)

def test_test_firmware_extraction(tester):
    """Test firmware extraction attempts"""
    with patch('requests.get') as mock_get:
        mock_get.return_value = Mock(status_code=404)

        result = tester.test_firmware_extraction("192.168.1.100")

        assert isinstance(result, dict)

def test_test_default_credentials(tester):
    """Test for default credentials"""
    with patch('requests.post') as mock_post:
        mock_post.return_value = Mock(status_code=401)

        findings = tester.test_default_credentials("192.168.1.100")

        assert isinstance(findings, list)
