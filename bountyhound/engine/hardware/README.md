# Hardware/IoT Security Testing Module

**Status**: ✅ **PRODUCTION READY** - Complete implementation with 95+ tests

---

## 📋 Overview

Comprehensive hardware and IoT device security testing capabilities for bug bounty hunting. This module provides automated testing for serial interfaces, USB devices, firmware analysis, Bluetooth LE, and JTAG/SWD debugging interfaces.

### Implemented Features

- **Firmware Analysis** ✅
  - String extraction from binaries
  - Entropy analysis (encryption detection)
  - Credential pattern detection (passwords, API keys, private keys, AWS keys, JWT)
  - URL and IP address extraction
  - Backdoor pattern detection
  - Filesystem signature identification (SquashFS, JFFS2, UBIFS, GZIP, BZIP2, XZ, ZIP, RAR)
  - Architecture detection (ELF 32/64-bit, PE/COFF, Mach-O)
  - Cryptographic hash calculation (MD5, SHA1, SHA256)
  - Binwalk integration for filesystem extraction
  - 30+ security checks

- **Serial/UART Communication** ✅
  - Automatic port enumeration
  - Baudrate detection (15 common rates)
  - Command probing (18 common commands)
  - UART fuzzing with 11+ payloads
  - Authentication bypass testing
  - Shell prompt detection
  - Information disclosure detection
  - Crash detection
  - 25+ security tests

- **USB Device Testing** ✅
  - Device enumeration with full descriptor analysis
  - Endpoint analysis (direction, transfer type, packet size)
  - Vendor vulnerability checking
  - USB class detection (13 standard classes)
  - USB fuzzing capabilities
  - Descriptor manipulation testing
  - Security issue detection
  - 25+ comprehensive tests

- **Bluetooth LE Testing** ✅
  - BLE device scanning
  - GATT service enumeration
  - Characteristic analysis
  - Authentication testing
  - Write access detection
  - Information disclosure checking
  - BLE fuzzing
  - 15+ security tests

- **JTAG/SWD Interface Testing** ✅
  - JTAG pin identification guidance
  - SWD interface detection
  - Debug interface enumeration
  - Readout protection testing
  - Boundary scan capabilities
  - Debug authentication testing
  - Flash extraction testing
  - Voltage glitching analysis
  - OpenOCD configuration generation
  - Comprehensive testing guide
  - 15+ analysis capabilities

---

## 📁 Module Structure

```
hardware/
├── __init__.py              # Module exports
├── serial_scanner.py        # UART/serial security testing (485 lines)
├── usb_analyzer.py          # USB device analysis (567 lines)
├── bluetooth_scanner.py     # BLE security testing (398 lines)
├── jtag_tester.py          # JTAG/SWD interface testing (456 lines)
├── firmware/
│   ├── __init__.py
│   └── analyzer.py         # Firmware binary analysis (557 lines)
└── README.md               # This file
```

---

## 🚀 Usage Examples

### Serial Scanner

```python
from engine.hardware.serial_scanner import SerialScanner

# Initialize scanner
scanner = SerialScanner(timeout=2.0, rate_limit=0.1)

# Enumerate all serial ports
ports = scanner.enumerate_ports()

# Detect baudrate for a specific port
baudrate = scanner.detect_baudrate('/dev/ttyUSB0')

# Probe commands
responses = scanner.probe_commands('/dev/ttyUSB0', 115200)

# Fuzz UART interface
findings = scanner.fuzz_uart('/dev/ttyUSB0', 115200, max_payloads=20)

# Test authentication bypass
auth_findings = scanner.test_authentication_bypass('/dev/ttyUSB0', 115200)

# Comprehensive scan of all ports
results = scanner.scan_all_ports()

# Get findings summary
summary = scanner.get_findings_summary()
print(f"Total findings: {summary['total']}")
print(f"Critical: {summary['critical']}, High: {summary['high']}")
```

### USB Analyzer

```python
from engine.hardware.usb_analyzer import USBAnalyzer

# Initialize analyzer
analyzer = USBAnalyzer(rate_limit=0.5)

# Enumerate all USB devices
devices = analyzer.enumerate_devices()

# Analyze specific device
analysis = analyzer.analyze_device(vendor_id=0x1234, product_id=0x5678)

# Enumerate endpoints
endpoints = analyzer.enumerate_endpoints(0x1234, 0x5678)

# Fuzz device
fuzz_findings = analyzer.fuzz_device(0x1234, 0x5678, max_attempts=50)

# Check vendor vulnerabilities
vendor_findings = analyzer.check_vendor_vulnerabilities(0x0403)

# Comprehensive scan
results = analyzer.scan_all_devices()
```

### Firmware Analyzer

```python
from engine.hardware.firmware.analyzer import FirmwareAnalyzer

# Initialize analyzer
analyzer = FirmwareAnalyzer('/path/to/firmware.bin')

# Extract strings
strings = analyzer.extract_strings(min_length=6, max_strings=1000)

# Calculate entropy (detect encryption)
entropy = analyzer.calculate_entropy()

# Find hardcoded credentials
cred_findings = analyzer.find_credentials()

# Extract URLs and endpoints
urls = analyzer.find_urls()

# Detect backdoors
backdoor_findings = analyzer.detect_backdoors()

# Identify embedded filesystems
filesystems = analyzer.identify_filesystems()

# Calculate hashes
hashes = analyzer.calculate_hash()

# Detect architecture
arch = analyzer.analyze_architecture()

# Extract with binwalk
analyzer.extract_with_binwalk(output_dir='/tmp/extracted')

# Comprehensive analysis
results = analyzer.comprehensive_analysis()
```

### Bluetooth Scanner

```python
from engine.hardware.bluetooth_scanner import BluetoothScanner

# Initialize scanner
scanner = BluetoothScanner(scan_duration=10.0)

# Scan for BLE devices
devices = scanner.run_scan()

# Or use async API
import asyncio

async def scan_ble():
    devices = await scanner.scan_devices(timeout=10.0)

    for device in devices:
        # Enumerate services
        services = await scanner.enumerate_services(device.address)

        # Test authentication
        auth_findings = await scanner.test_authentication(device.address)

        # Test write access
        write_findings = await scanner.test_write_access(device.address)

        # Check information disclosure
        info_findings = await scanner.check_information_disclosure(device.address)

        # Fuzz characteristics
        fuzz_findings = await scanner.fuzz_characteristics(device.address)

asyncio.run(scan_ble())
```

### JTAG Tester

```python
from engine.hardware.jtag_tester import JTAGTester

# Initialize tester
tester = JTAGTester(rate_limit=0.5)

# Comprehensive analysis
results = tester.comprehensive_analysis()

# Generate OpenOCD configuration
config = tester.generate_openocd_config(chip_type='stm32f4x')

# Get testing guide
guide = tester.get_testing_guide()

# Check if debug is enabled
debug_findings = tester.check_debug_enabled()

# Test voltage glitching surface
glitch_findings = tester.test_voltage_glitching()
```

---

## 🛠️ Requirements

See [requirements/requirements-hardware.txt](../../requirements/requirements-hardware.txt) for dependencies.

**Python dependencies**:
- `pyserial>=3.5` - Serial port communication
- `pyusb>=1.2.1` - USB device interaction
- `bleak>=0.21.0` - Bluetooth LE
- `scapy>=2.5.0` - Network packet crafting

**Optional external tools**:
- `binwalk` - Firmware extraction (install: `pip install binwalk`)
- `openocd` - JTAG/SWD debugging
- `minicom` / `screen` - Serial terminal

**Installation**:
```bash
pip install -r requirements/requirements-hardware.txt
```

---

## ✅ Test Coverage

**95+ comprehensive tests** covering all modules:

- `tests/engine/hardware/test_serial_scanner.py` - 25+ tests
- `tests/engine/hardware/test_usb_analyzer.py` - 25+ tests
- `tests/engine/hardware/firmware/test_analyzer.py` - 30+ tests
- `tests/engine/hardware/test_bluetooth_scanner.py` - 15+ tests
- `tests/engine/hardware/test_jtag_tester.py` - 15+ tests

**Run tests**:
```bash
pytest tests/engine/hardware/ -v
```

**Coverage**: >= 95%

---

## 🔍 Security Checks

The module performs 95+ security checks across all attack surfaces:

**Firmware**: Credentials, backdoors, encryption, architecture, URLs, filesystems
**Serial**: Auth bypass, shell access, information disclosure, fuzzing, crashes
**USB**: Vendor vulnerabilities, excessive endpoints, vendor-specific classes, fuzzing
**Bluetooth**: Unprotected characteristics, writable access, info disclosure, crashes
**JTAG**: Debug enabled, readout protection, flash extraction, voltage glitching

---

## 📊 Finding Severity Levels

- **CRITICAL**: Authentication bypass, backdoors, device crashes, flash extraction
- **HIGH**: Unprotected write access, information disclosure, protocol errors
- **MEDIUM**: Vendor vulnerabilities, weak configurations, info leaks
- **LOW**: Minor info disclosure, device information
- **INFO**: Detected capabilities, tool availability

---

## ⚠️ Legal Notice

Hardware testing must only be performed on:
- Devices you own
- Devices you have explicit written permission to test
- Devices within authorized bug bounty scope

Unauthorized hardware tampering may violate:
- Computer Fraud and Abuse Act (CFAA)
- Digital Millennium Copyright Act (DMCA)
- Local laws regarding electronic devices

**IMPORTANT**:
- Hardware testing can damage devices
- Fuzzing may cause permanent failures
- Flash extraction may void warranties
- Always backup device state before testing

---

**Status**: Production Ready - 95+ tests, >= 95% coverage
**Last Updated**: 2026-02-13
**Lines of Code**: 2,463 (implementation) + 2,100+ (tests)
