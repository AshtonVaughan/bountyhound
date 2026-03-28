"""
Tests for USB Analyzer Module
Comprehensive tests for USB device security testing
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from engine.hardware.usb_analyzer import USBAnalyzer, USBDevice, USBEndpoint, USBFinding
import usb.core


class TestUSBAnalyzer:
    """Test suite for USBAnalyzer"""

    def test_analyzer_initialization(self):
        """Test analyzer initializes with correct defaults"""
        analyzer = USBAnalyzer()
        assert analyzer.rate_limit == 0.5
        assert analyzer.findings == []

    def test_analyzer_custom_rate_limit(self):
        """Test analyzer with custom rate limit"""
        analyzer = USBAnalyzer(rate_limit=1.0)
        assert analyzer.rate_limit == 1.0

    def test_usb_classes_defined(self):
        """Test USB_CLASSES dictionary is properly defined"""
        assert isinstance(USBAnalyzer.USB_CLASSES, dict)
        assert 0x03 in USBAnalyzer.USB_CLASSES  # HID
        assert 0x08 in USBAnalyzer.USB_CLASSES  # Mass Storage

    def test_transfer_types_defined(self):
        """Test TRANSFER_TYPES dictionary is properly defined"""
        assert isinstance(USBAnalyzer.TRANSFER_TYPES, dict)
        assert len(USBAnalyzer.TRANSFER_TYPES) == 4

    @patch('usb.core.find')
    def test_enumerate_devices_empty(self, mock_find):
        """Test device enumeration when no devices found"""
        mock_find.return_value = []

        analyzer = USBAnalyzer()
        devices = analyzer.enumerate_devices()

        assert devices == []

    @patch('usb.core.find')
    @patch('usb.util.get_string')
    def test_enumerate_devices_single(self, mock_get_string, mock_find):
        """Test device enumeration with single device"""
        mock_device = Mock()
        mock_device.idVendor = 0x1234
        mock_device.idProduct = 0x5678
        mock_device.iManufacturer = 1
        mock_device.iProduct = 2
        mock_device.iSerialNumber = 3
        mock_device.bDeviceClass = 0x03  # HID
        mock_device.bDeviceSubClass = 0
        mock_device.bDeviceProtocol = 0
        mock_device.bus = 1
        mock_device.address = 5
        mock_device.speed = 2  # Full Speed
        mock_device.bNumConfigurations = 1

        mock_get_string.side_effect = ['Test Manufacturer', 'Test Product', '123456']
        mock_find.return_value = [mock_device]

        analyzer = USBAnalyzer()
        devices = analyzer.enumerate_devices()

        assert len(devices) == 1
        assert devices[0].vendor_id == 0x1234
        assert devices[0].product_id == 0x5678

    @patch('usb.core.find')
    def test_enumerate_devices_error_handling(self, mock_find):
        """Test device enumeration handles errors gracefully"""
        mock_device = Mock()
        mock_device.idVendor = 0x1234
        mock_device.idProduct = 0x5678
        mock_device.iManufacturer = 0
        mock_device.iProduct = 0
        mock_device.iSerialNumber = 0
        mock_device.bDeviceClass = 0xFF
        mock_device.bDeviceSubClass = 0
        mock_device.bDeviceProtocol = 0
        mock_device.bus = 1
        mock_device.address = 5
        mock_device.speed = 3
        mock_device.bNumConfigurations = 1

        mock_find.return_value = [mock_device]

        analyzer = USBAnalyzer()
        devices = analyzer.enumerate_devices()

        assert len(devices) == 1

    def test_get_speed_string(self):
        """Test speed code to string conversion"""
        analyzer = USBAnalyzer()
        assert 'Low Speed' in analyzer._get_speed_string(1)
        assert 'Full Speed' in analyzer._get_speed_string(2)
        assert 'High Speed' in analyzer._get_speed_string(3)
        assert 'Unknown' in analyzer._get_speed_string(99)

    @patch('usb.core.find')
    def test_analyze_device_not_found(self, mock_find):
        """Test device analysis when device not found"""
        mock_find.return_value = None

        analyzer = USBAnalyzer()
        result = analyzer.analyze_device(0x1234, 0x5678)

        assert result == {}

    @patch('usb.core.find')
    @patch('usb.util.get_string')
    def test_analyze_device_success(self, mock_get_string, mock_find):
        """Test successful device analysis"""
        mock_device = Mock()
        mock_device.idVendor = 0x1234
        mock_device.idProduct = 0x5678
        mock_device.iManufacturer = 1
        mock_device.iProduct = 2
        mock_device.iSerialNumber = 3
        mock_device.bDeviceClass = 0x03
        mock_device.speed = 2

        # Mock configurations
        mock_config = Mock()
        mock_config.bConfigurationValue = 1
        mock_config.bNumInterfaces = 1
        mock_config.bmAttributes = 0x80
        mock_config.bMaxPower = 50

        mock_interface = Mock()
        mock_endpoint = Mock()
        mock_endpoint.bEndpointAddress = 0x81
        mock_endpoint.bmAttributes = 0x03
        mock_endpoint.wMaxPacketSize = 64
        mock_endpoint.bInterval = 10

        mock_interface.__iter__ = Mock(return_value=iter([mock_endpoint]))
        mock_config.__iter__ = Mock(return_value=iter([mock_interface]))
        mock_device.__iter__ = Mock(return_value=iter([mock_config]))

        mock_get_string.side_effect = ['Manufacturer', 'Product', 'Serial']
        mock_find.return_value = mock_device

        analyzer = USBAnalyzer()
        result = analyzer.analyze_device(0x1234, 0x5678)

        assert 'device_info' in result
        assert 'configurations' in result
        assert 'endpoints' in result
        assert 'security_issues' in result

    def test_parse_endpoint(self):
        """Test endpoint parsing"""
        mock_ep = Mock()
        mock_ep.bEndpointAddress = 0x81  # IN endpoint
        mock_ep.bmAttributes = 0x03      # Interrupt
        mock_ep.wMaxPacketSize = 64
        mock_ep.bInterval = 10

        analyzer = USBAnalyzer()
        endpoint = analyzer._parse_endpoint(mock_ep)

        assert endpoint.address == 0x81
        assert endpoint.direction == 'IN'
        assert endpoint.transfer_type == 'Interrupt'
        assert endpoint.max_packet_size == 64

    def test_parse_endpoint_out(self):
        """Test OUT endpoint parsing"""
        mock_ep = Mock()
        mock_ep.bEndpointAddress = 0x02  # OUT endpoint
        mock_ep.bmAttributes = 0x02      # Bulk
        mock_ep.wMaxPacketSize = 512
        mock_ep.bInterval = 0

        analyzer = USBAnalyzer()
        endpoint = analyzer._parse_endpoint(mock_ep)

        assert endpoint.direction == 'OUT'
        assert endpoint.transfer_type == 'Bulk'

    @patch('usb.core.find')
    def test_enumerate_endpoints(self, mock_find):
        """Test endpoint enumeration"""
        mock_device = Mock()
        mock_config = Mock()
        mock_interface = Mock()

        mock_ep1 = Mock()
        mock_ep1.bEndpointAddress = 0x81
        mock_ep1.bmAttributes = 0x03
        mock_ep1.wMaxPacketSize = 64
        mock_ep1.bInterval = 10

        mock_interface.__iter__ = Mock(return_value=iter([mock_ep1]))
        mock_config.__iter__ = Mock(return_value=iter([mock_interface]))
        mock_device.__iter__ = Mock(return_value=iter([mock_config]))

        mock_find.return_value = mock_device

        analyzer = USBAnalyzer()
        endpoints = analyzer.enumerate_endpoints(0x1234, 0x5678)

        assert len(endpoints) == 1

    def test_check_vendor_vulnerabilities(self):
        """Test vendor vulnerability checking"""
        analyzer = USBAnalyzer()
        findings = analyzer.check_vendor_vulnerabilities(0x0403)  # FTDI

        assert len(findings) > 0
        assert findings[0].severity == 'MEDIUM'

    def test_check_vendor_vulnerabilities_safe(self):
        """Test vendor vulnerability checking for safe vendor"""
        analyzer = USBAnalyzer()
        findings = analyzer.check_vendor_vulnerabilities(0x9999)  # Unknown vendor

        assert len(findings) == 0

    def test_check_security_issues_vendor_specific(self):
        """Test security issue detection for vendor-specific class"""
        mock_device = Mock()
        mock_device.idVendor = 0x1234
        mock_device.idProduct = 0x5678
        mock_device.bDeviceClass = 0xFF  # Vendor-specific

        analysis = {
            'endpoints': [],
            'security_issues': []
        }

        analyzer = USBAnalyzer()
        analyzer._check_security_issues(mock_device, analysis)

        assert len(analysis['security_issues']) > 0
        assert any('Vendor-Specific' in f.title for f in analysis['security_issues'])

    def test_check_security_issues_excessive_endpoints(self):
        """Test detection of excessive endpoints"""
        mock_device = Mock()
        mock_device.idVendor = 0x1234
        mock_device.idProduct = 0x5678
        mock_device.bDeviceClass = 0x00

        # Create 10 mock endpoints
        endpoints = [Mock() for _ in range(10)]

        analysis = {
            'endpoints': endpoints,
            'security_issues': []
        }

        analyzer = USBAnalyzer()
        analyzer._check_security_issues(mock_device, analysis)

        assert any('Large Number of Endpoints' in f.title for f in analysis['security_issues'])

    @patch('usb.core.find')
    def test_fuzz_device_no_device(self, mock_find):
        """Test fuzzing when device not found"""
        mock_find.return_value = None

        analyzer = USBAnalyzer()
        findings = analyzer.fuzz_device(0x1234, 0x5678)

        assert findings == []

    def test_get_findings_summary_empty(self):
        """Test findings summary when empty"""
        analyzer = USBAnalyzer()
        summary = analyzer.get_findings_summary()

        assert summary['total'] == 0
        assert summary['critical'] == 0

    def test_get_findings_summary_with_findings(self):
        """Test findings summary with various findings"""
        analyzer = USBAnalyzer()
        analyzer.findings = [
            USBFinding('device1', 'CRITICAL', 'Test1', 'Desc1', 'Evidence1', 0.0),
            USBFinding('device2', 'HIGH', 'Test2', 'Desc2', 'Evidence2', 0.0),
            USBFinding('device3', 'MEDIUM', 'Test3', 'Desc3', 'Evidence3', 0.0),
        ]

        summary = analyzer.get_findings_summary()
        assert summary['total'] == 3
        assert summary['critical'] == 1
        assert summary['high'] == 1
        assert summary['medium'] == 1


class TestUSBDevice:
    """Test suite for USBDevice dataclass"""

    def test_usb_device_creation(self):
        """Test USBDevice object creation"""
        device = USBDevice(
            vendor_id=0x1234,
            product_id=0x5678,
            manufacturer='Test Mfr',
            product='Test Product',
            serial_number='123456',
            device_class=0x03,
            device_subclass=0,
            device_protocol=0,
            bus=1,
            address=5,
            speed='Full Speed',
            configurations=1
        )

        assert device.vendor_id == 0x1234
        assert device.product_id == 0x5678
        assert device.manufacturer == 'Test Mfr'


class TestUSBEndpoint:
    """Test suite for USBEndpoint dataclass"""

    def test_usb_endpoint_creation(self):
        """Test USBEndpoint object creation"""
        endpoint = USBEndpoint(
            address=0x81,
            attributes=0x03,
            max_packet_size=64,
            interval=10,
            direction='IN',
            transfer_type='Interrupt'
        )

        assert endpoint.address == 0x81
        assert endpoint.direction == 'IN'
        assert endpoint.transfer_type == 'Interrupt'


class TestUSBFinding:
    """Test suite for USBFinding dataclass"""

    def test_usb_finding_creation(self):
        """Test USBFinding object creation"""
        finding = USBFinding(
            device_id='1234:5678',
            severity='HIGH',
            title='Test Finding',
            description='Test Description',
            evidence='Test Evidence',
            timestamp=1234567890.0
        )

        assert finding.device_id == '1234:5678'
        assert finding.severity == 'HIGH'
