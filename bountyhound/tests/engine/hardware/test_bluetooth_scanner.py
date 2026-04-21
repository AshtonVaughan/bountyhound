"""
Tests for Bluetooth Scanner Module
Comprehensive tests for BLE device security testing
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from engine.hardware.bluetooth_scanner import BluetoothScanner, BLEDevice, BLEService, BLEFinding


class TestBluetoothScanner:
    """Test suite for BluetoothScanner"""

    def test_scanner_initialization(self):
        """Test scanner initializes with correct defaults"""
        scanner = BluetoothScanner()
        assert scanner.scan_duration == 10.0
        assert scanner.findings == []

    def test_scanner_custom_duration(self):
        """Test scanner with custom scan duration"""
        scanner = BluetoothScanner(scan_duration=20.0)
        assert scanner.scan_duration == 20.0

    def test_interesting_services_defined(self):
        """Test INTERESTING_SERVICES dictionary is properly defined"""
        assert isinstance(BluetoothScanner.INTERESTING_SERVICES, dict)
        assert len(BluetoothScanner.INTERESTING_SERVICES) > 5

    def test_insecure_properties_defined(self):
        """Test INSECURE_PROPERTIES dictionary is properly defined"""
        assert isinstance(BluetoothScanner.INSECURE_PROPERTIES, dict)
        assert 'read' in BluetoothScanner.INSECURE_PROPERTIES
        assert 'write' in BluetoothScanner.INSECURE_PROPERTIES

    @pytest.mark.asyncio
    @patch('bleak.BleakScanner.discover')
    async def test_scan_devices_empty(self, mock_discover):
        """Test device scanning when no devices found"""
        mock_discover.return_value = []

        scanner = BluetoothScanner()
        devices = await scanner.scan_devices()

        assert devices == []

    @pytest.mark.asyncio
    @patch('bleak.BleakScanner.discover')
    async def test_scan_devices_single(self, mock_discover):
        """Test device scanning with single device"""
        mock_device = Mock()
        mock_device.address = 'AA:BB:CC:DD:EE:FF'
        mock_device.name = 'Test Device'
        mock_device.rssi = -50
        mock_device.metadata = {}

        mock_discover.return_value = [mock_device]

        scanner = BluetoothScanner()
        devices = await scanner.scan_devices()

        assert len(devices) == 1
        assert devices[0].address == 'AA:BB:CC:DD:EE:FF'
        assert devices[0].name == 'Test Device'

    @pytest.mark.asyncio
    @patch('bleak.BleakScanner.discover')
    async def test_scan_devices_multiple(self, mock_discover):
        """Test device scanning with multiple devices"""
        mock_devices = []
        for i in range(3):
            mock_device = Mock()
            mock_device.address = f'AA:BB:CC:DD:EE:{i:02X}'
            mock_device.name = f'Device {i}'
            mock_device.rssi = -50 - i * 10
            mock_device.metadata = {}
            mock_devices.append(mock_device)

        mock_discover.return_value = mock_devices

        scanner = BluetoothScanner()
        devices = await scanner.scan_devices()

        assert len(devices) == 3

    @pytest.mark.asyncio
    @patch('bleak.BleakClient')
    async def test_enumerate_services(self, mock_client_class):
        """Test service enumeration"""
        mock_client = AsyncMock()
        mock_client.is_connected = True

        mock_service = Mock()
        mock_service.uuid = '0000180f-0000-1000-8000-00805f9b34fb'

        mock_char = Mock()
        mock_char.uuid = 'char-uuid-1'

        mock_service.characteristics = [mock_char]
        mock_client.services = [mock_service]

        mock_client_class.return_value.__aenter__.return_value = mock_client

        scanner = BluetoothScanner()
        services = await scanner.enumerate_services('AA:BB:CC:DD:EE:FF')

        assert len(services) == 1
        assert len(services[0].characteristics) == 1

    @pytest.mark.asyncio
    @patch('bleak.BleakClient')
    async def test_enumerate_services_connection_failed(self, mock_client_class):
        """Test service enumeration when connection fails"""
        mock_client = AsyncMock()
        mock_client.is_connected = False

        mock_client_class.return_value.__aenter__.return_value = mock_client

        scanner = BluetoothScanner()
        services = await scanner.enumerate_services('AA:BB:CC:DD:EE:FF')

        assert services == []

    @pytest.mark.asyncio
    @patch('bleak.BleakClient')
    async def test_test_authentication(self, mock_client_class):
        """Test authentication testing"""
        mock_client = AsyncMock()
        mock_client.is_connected = True

        mock_char = Mock()
        mock_char.uuid = 'test-char'
        mock_char.properties = ['read']

        mock_service = Mock()
        mock_service.characteristics = [mock_char]
        mock_client.services = [mock_service]
        mock_client.read_gatt_char = AsyncMock(return_value=b'test data')

        mock_client_class.return_value.__aenter__.return_value = mock_client

        scanner = BluetoothScanner()
        findings = await scanner.test_authentication('AA:BB:CC:DD:EE:FF')

        # Should find unprotected characteristic
        assert len(findings) > 0

    @pytest.mark.asyncio
    @patch('bleak.BleakClient')
    async def test_test_write_access(self, mock_client_class):
        """Test write access testing"""
        mock_client = AsyncMock()
        mock_client.is_connected = True

        mock_char = Mock()
        mock_char.uuid = 'writable-char'
        mock_char.properties = ['write']

        mock_service = Mock()
        mock_service.uuid = 'service-uuid'
        mock_service.characteristics = [mock_char]
        mock_client.services = [mock_service]

        mock_client_class.return_value.__aenter__.return_value = mock_client

        scanner = BluetoothScanner()
        findings = await scanner.test_write_access('AA:BB:CC:DD:EE:FF')

        # Should find writable characteristics
        assert len(findings) > 0
        assert findings[0].severity == 'HIGH'

    @pytest.mark.asyncio
    @patch('bleak.BleakClient')
    async def test_check_information_disclosure(self, mock_client_class):
        """Test information disclosure checking"""
        mock_client = AsyncMock()
        mock_client.is_connected = True

        mock_char = Mock()
        mock_char.uuid = 'info-char'
        mock_char.properties = ['read']

        mock_service = Mock()
        mock_service.uuid = '0000180a-0000-1000-8000-00805f9b34fb'  # Device Info
        mock_service.characteristics = [mock_char]
        mock_client.services = [mock_service]
        mock_client.read_gatt_char = AsyncMock(return_value=b'Manufacturer Name')

        mock_client_class.return_value.__aenter__.return_value = mock_client

        scanner = BluetoothScanner()
        findings = await scanner.check_information_disclosure('AA:BB:CC:DD:EE:FF')

        assert len(findings) > 0

    def test_run_scan_synchronous(self):
        """Test synchronous scan wrapper"""
        scanner = BluetoothScanner(scan_duration=0.1)

        with patch.object(scanner, 'scan_and_analyze', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = {'test': 'result'}

            result = scanner.run_scan()

            assert result == {'test': 'result'}
            mock_scan.assert_called_once()

    def test_get_findings_summary_empty(self):
        """Test findings summary when empty"""
        scanner = BluetoothScanner()
        summary = scanner.get_findings_summary()

        assert summary['total'] == 0
        assert summary['critical'] == 0

    def test_get_findings_summary_with_findings(self):
        """Test findings summary with various findings"""
        scanner = BluetoothScanner()
        scanner.findings = [
            BLEFinding('device1', 'CRITICAL', 'Test1', 'Desc1', 'Evidence1', 0.0),
            BLEFinding('device2', 'HIGH', 'Test2', 'Desc2', 'Evidence2', 0.0),
            BLEFinding('device3', 'MEDIUM', 'Test3', 'Desc3', 'Evidence3', 0.0),
        ]

        summary = scanner.get_findings_summary()
        assert summary['total'] == 3
        assert summary['critical'] == 1
        assert summary['high'] == 1


class TestBLEDevice:
    """Test suite for BLEDevice dataclass"""

    def test_ble_device_creation(self):
        """Test BLEDevice object creation"""
        device = BLEDevice(
            address='AA:BB:CC:DD:EE:FF',
            name='Test Device',
            rssi=-50,
            metadata={'key': 'value'}
        )

        assert device.address == 'AA:BB:CC:DD:EE:FF'
        assert device.name == 'Test Device'
        assert device.rssi == -50


class TestBLEService:
    """Test suite for BLEService dataclass"""

    def test_ble_service_creation(self):
        """Test BLEService object creation"""
        service = BLEService(
            uuid='service-uuid',
            description='Test Service',
            characteristics=['char1', 'char2']
        )

        assert service.uuid == 'service-uuid'
        assert len(service.characteristics) == 2


class TestBLEFinding:
    """Test suite for BLEFinding dataclass"""

    def test_ble_finding_creation(self):
        """Test BLEFinding object creation"""
        finding = BLEFinding(
            device_address='AA:BB:CC:DD:EE:FF',
            severity='HIGH',
            title='Test Finding',
            description='Test Description',
            evidence='Test Evidence',
            timestamp=1234567890.0
        )

        assert finding.device_address == 'AA:BB:CC:DD:EE:FF'
        assert finding.severity == 'HIGH'
