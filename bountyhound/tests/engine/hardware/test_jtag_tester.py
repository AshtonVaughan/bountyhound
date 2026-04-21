"""
Tests for JTAG Tester Module
Comprehensive tests for JTAG/SWD interface security testing
"""

import pytest
from unittest.mock import Mock, patch
from engine.hardware.jtag_tester import JTAGTester, JTAGPin, JTAGFinding


class TestJTAGTester:
    """Test suite for JTAGTester"""

    def test_tester_initialization(self):
        """Test tester initializes with correct defaults"""
        tester = JTAGTester()
        assert tester.rate_limit == 0.5
        assert tester.findings == []
        assert tester.detected_pins == {}

    def test_tester_custom_rate_limit(self):
        """Test tester with custom rate limit"""
        tester = JTAGTester(rate_limit=1.0)
        assert tester.rate_limit == 1.0

    def test_jtag_pins_defined(self):
        """Test JTAG_PINS dictionary is properly defined"""
        assert isinstance(JTAGTester.JTAG_PINS, dict)
        assert 'TDI' in JTAGTester.JTAG_PINS
        assert 'TDO' in JTAGTester.JTAG_PINS
        assert 'TCK' in JTAGTester.JTAG_PINS
        assert 'TMS' in JTAGTester.JTAG_PINS

    def test_swd_pins_defined(self):
        """Test SWD_PINS dictionary is properly defined"""
        assert isinstance(JTAGTester.SWD_PINS, dict)
        assert 'SWDIO' in JTAGTester.SWD_PINS
        assert 'SWCLK' in JTAGTester.SWD_PINS

    def test_common_frequencies_defined(self):
        """Test COMMON_FREQUENCIES list is properly defined"""
        assert isinstance(JTAGTester.COMMON_FREQUENCIES, list)
        assert 1000000 in JTAGTester.COMMON_FREQUENCIES  # 1 MHz

    def test_detect_jtag_pins(self):
        """Test JTAG pin detection (simulated)"""
        tester = JTAGTester()
        detected = tester.detect_jtag_pins(pin_count=20)

        # Returns empty dict as it requires hardware
        assert isinstance(detected, dict)

    @patch('subprocess.run')
    def test_check_debug_enabled_openocd_found(self, mock_run):
        """Test debug check when OpenOCD is installed"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'Open On-Chip Debugger 0.11.0'
        mock_run.return_value = mock_result

        tester = JTAGTester()
        findings = tester.check_debug_enabled()

        assert len(findings) > 0
        assert findings[0].severity == 'INFO'

    @patch('subprocess.run')
    def test_check_debug_enabled_openocd_not_found(self, mock_run):
        """Test debug check when OpenOCD is not installed"""
        mock_run.side_effect = FileNotFoundError()

        tester = JTAGTester()
        findings = tester.check_debug_enabled()

        assert findings == []

    def test_test_readout_protection(self):
        """Test readout protection testing"""
        tester = JTAGTester()
        findings = tester.test_readout_protection()

        # Returns empty list as it requires hardware
        assert isinstance(findings, list)

    def test_test_boundary_scan(self):
        """Test boundary scan testing"""
        tester = JTAGTester()
        findings = tester.test_boundary_scan()

        # Returns empty list as it requires hardware
        assert isinstance(findings, list)

    def test_enumerate_tap_devices(self):
        """Test TAP device enumeration"""
        tester = JTAGTester()
        devices = tester.enumerate_tap_devices()

        # Returns empty list as it requires hardware
        assert isinstance(devices, list)

    def test_test_debug_authentication(self):
        """Test debug authentication testing"""
        tester = JTAGTester()
        findings = tester.test_debug_authentication()

        # Returns empty list as it requires hardware
        assert isinstance(findings, list)

    def test_test_flash_extraction(self):
        """Test flash extraction testing"""
        tester = JTAGTester()
        findings = tester.test_flash_extraction()

        # Returns empty list as it requires hardware
        assert isinstance(findings, list)

    def test_scan_for_swd(self):
        """Test SWD scanning"""
        tester = JTAGTester()
        results = tester.scan_for_swd()

        assert isinstance(results, dict)
        assert 'swd_detected' in results
        assert 'swdio_pin' in results
        assert 'swclk_pin' in results
        assert results['swd_detected'] is False

    def test_test_voltage_glitching(self):
        """Test voltage glitching analysis"""
        tester = JTAGTester()
        findings = tester.test_voltage_glitching()

        # Should create medium severity finding
        assert len(findings) > 0
        assert findings[0].severity == 'MEDIUM'
        assert 'glitching' in findings[0].title.lower()

    def test_comprehensive_analysis(self):
        """Test comprehensive JTAG analysis"""
        tester = JTAGTester()
        results = tester.comprehensive_analysis()

        assert isinstance(results, dict)
        assert 'jtag_pins' in results
        assert 'swd_detection' in results
        assert 'debug_enabled' in results
        assert 'tap_devices' in results
        assert 'readout_protection' in results
        assert 'boundary_scan' in results
        assert 'debug_auth' in results
        assert 'flash_extraction' in results
        assert 'voltage_glitching' in results
        assert 'findings' in results

    def test_generate_openocd_config_default(self):
        """Test OpenOCD config generation with default chip"""
        tester = JTAGTester()
        config = tester.generate_openocd_config()

        assert isinstance(config, str)
        assert 'OpenOCD Configuration' in config
        assert 'stm32f4x' in config
        assert 'init' in config
        assert 'dump_image' in config

    def test_generate_openocd_config_custom_chip(self):
        """Test OpenOCD config generation with custom chip"""
        tester = JTAGTester()
        config = tester.generate_openocd_config(chip_type='nrf52')

        assert 'nrf52' in config

    def test_get_testing_guide(self):
        """Test testing guide generation"""
        tester = JTAGTester()
        guide = tester.get_testing_guide()

        assert isinstance(guide, str)
        assert 'JTAG/SWD' in guide
        assert 'HARDWARE REQUIREMENTS' in guide
        assert 'PIN IDENTIFICATION' in guide
        assert 'TESTING WORKFLOW' in guide

    def test_get_findings_summary_empty(self):
        """Test findings summary when empty"""
        tester = JTAGTester()
        summary = tester.get_findings_summary()

        assert summary['total'] == 0
        assert summary['critical'] == 0
        assert summary['high'] == 0

    def test_get_findings_summary_with_findings(self):
        """Test findings summary with various findings"""
        tester = JTAGTester()
        tester.findings = [
            JTAGFinding('CRITICAL', 'Test1', 'Desc1', 'Evidence1', 0.0),
            JTAGFinding('HIGH', 'Test2', 'Desc2', 'Evidence2', 0.0),
            JTAGFinding('MEDIUM', 'Test3', 'Desc3', 'Evidence3', 0.0),
            JTAGFinding('INFO', 'Test4', 'Desc4', 'Evidence4', 0.0),
        ]

        summary = tester.get_findings_summary()
        assert summary['total'] == 4
        assert summary['critical'] == 1
        assert summary['high'] == 1
        assert summary['medium'] == 1
        assert summary['info'] == 1


class TestJTAGPin:
    """Test suite for JTAGPin dataclass"""

    def test_jtag_pin_creation(self):
        """Test JTAGPin object creation"""
        pin = JTAGPin(
            number=1,
            name='TDI',
            detected=True,
            voltage=3.3
        )

        assert pin.number == 1
        assert pin.name == 'TDI'
        assert pin.detected is True
        assert pin.voltage == 3.3

    def test_jtag_pin_optional_voltage(self):
        """Test JTAGPin with optional voltage field"""
        pin = JTAGPin(
            number=2,
            name='TDO',
            detected=False
        )

        assert pin.voltage is None


class TestJTAGFinding:
    """Test suite for JTAGFinding dataclass"""

    def test_jtag_finding_creation(self):
        """Test JTAGFinding object creation"""
        finding = JTAGFinding(
            severity='HIGH',
            title='Test Finding',
            description='Test Description',
            evidence='Test Evidence',
            timestamp=1234567890.0
        )

        assert finding.severity == 'HIGH'
        assert finding.title == 'Test Finding'
        assert finding.timestamp == 1234567890.0
