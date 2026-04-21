"""
USB Device Analyzer and Fuzzer
Comprehensive USB device enumeration, analysis, and security testing
"""

import usb.core
import usb.util
from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style
import time
from dataclasses import dataclass
from engine.core.proxy_config import ProxyConfig
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


@dataclass
class USBDevice:
    """Represents a USB device"""
    vendor_id: int
    product_id: int
    manufacturer: Optional[str]
    product: Optional[str]
    serial_number: Optional[str]
    device_class: int
    device_subclass: int
    device_protocol: int
    bus: int
    address: int
    speed: str
    configurations: int


@dataclass
class USBEndpoint:
    """Represents a USB endpoint"""
    address: int
    attributes: int
    max_packet_size: int
    interval: int
    direction: str
    transfer_type: str


@dataclass
class USBFinding:
    """Represents a USB security finding"""
    device_id: str
    severity: str
    title: str
    description: str
    evidence: str
    timestamp: float


class USBAnalyzer:
    """USB device enumeration and security analysis"""

    # Known vulnerable USB vendor IDs (examples)
    KNOWN_VULNERABLE_VIDS = {
        0x0403: 'FTDI (check for clones)',
        0x067b: 'Prolific (known vulnerabilities)',
        0x10c4: 'Silicon Labs (check firmware version)',
    }

    # USB class codes
    USB_CLASSES = {
        0x00: 'Device',
        0x01: 'Audio',
        0x02: 'Communications',
        0x03: 'HID',
        0x05: 'Physical',
        0x06: 'Image',
        0x07: 'Printer',
        0x08: 'Mass Storage',
        0x09: 'Hub',
        0x0A: 'CDC-Data',
        0x0B: 'Smart Card',
        0x0D: 'Content Security',
        0x0E: 'Video',
        0x0F: 'Personal Healthcare',
        0xDC: 'Diagnostic',
        0xE0: 'Wireless Controller',
        0xEF: 'Miscellaneous',
        0xFE: 'Application Specific',
        0xFF: 'Vendor Specific',
    }

    # Transfer types
    TRANSFER_TYPES = {
        0: 'Control',
        1: 'Isochronous',
        2: 'Bulk',
        3: 'Interrupt',
    }

    def __init__(self, rate_limit: float = 0.5, proxy_config: ProxyConfig = None):
        """
        Initialize USB analyzer with rate limiting.

        Args:
            rate_limit: Seconds between USB operations (default: 0.5)
            proxy_config: Proxy configuration (not used for USB, kept for API consistency)
        """
        self.rate_limit = rate_limit
        self.findings = []
        print(f"{Fore.GREEN}[+] USB analyzer initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s{Style.RESET_ALL}")

    def enumerate_devices(self) -> List[USBDevice]:
        """
        Enumerate all connected USB devices.

        Returns:
            List of USBDevice objects
        """
        print(f"\n{Fore.YELLOW}[*] Enumerating USB devices...{Style.RESET_ALL}")
        devices = []

        for dev in usb.core.find(find_all=True):
            try:
                device = USBDevice(
                    vendor_id=dev.idVendor,
                    product_id=dev.idProduct,
                    manufacturer=usb.util.get_string(dev, dev.iManufacturer) if dev.iManufacturer else None,
                    product=usb.util.get_string(dev, dev.iProduct) if dev.iProduct else None,
                    serial_number=usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else None,
                    device_class=dev.bDeviceClass,
                    device_subclass=dev.bDeviceSubClass,
                    device_protocol=dev.bDeviceProtocol,
                    bus=dev.bus,
                    address=dev.address,
                    speed=self._get_speed_string(dev.speed),
                    configurations=dev.bNumConfigurations
                )
                devices.append(device)

                print(f"{Fore.GREEN}[+] Found: {hex(dev.idVendor)}:{hex(dev.idProduct)}{Style.RESET_ALL}")
                if device.manufacturer:
                    print(f"    Manufacturer: {device.manufacturer}")
                if device.product:
                    print(f"    Product: {device.product}")
                print(f"    Class: {self.USB_CLASSES.get(device.device_class, 'Unknown')}")
                print(f"    Bus/Address: {device.bus}/{device.address}")

            except (usb.core.USBError, ValueError) as e:
                print(f"{Fore.YELLOW}[!] Could not read device info: {e}{Style.RESET_ALL}")

            time.sleep(self.rate_limit)

        print(f"\n{Fore.CYAN}[*] Total devices found: {len(devices)}{Style.RESET_ALL}")
        return devices

    def analyze_device(self, vendor_id: int, product_id: int) -> Dict:
        """
        Perform detailed analysis of a specific USB device.

        Args:
            vendor_id: USB vendor ID
            product_id: USB product ID

        Returns:
            Dictionary containing device analysis results
        """
        print(f"\n{Fore.YELLOW}[*] Analyzing device {hex(vendor_id)}:{hex(product_id)}...{Style.RESET_ALL}")

        dev = usb.core.find(idVendor=vendor_id, idProduct=product_id)
        if dev is None:
            print(f"{Fore.RED}[!] Device not found{Style.RESET_ALL}")
            return {}

        analysis = {
            'device_info': self._get_device_info(dev),
            'configurations': [],
            'endpoints': [],
            'security_issues': [],
        }

        # Analyze configurations
        for cfg in dev:
            config_info = {
                'value': cfg.bConfigurationValue,
                'interfaces': cfg.bNumInterfaces,
                'attributes': cfg.bmAttributes,
                'max_power': cfg.bMaxPower * 2,  # In mA
            }
            analysis['configurations'].append(config_info)

            # Analyze interfaces and endpoints
            for intf in cfg:
                for ep in intf:
                    endpoint = self._parse_endpoint(ep)
                    analysis['endpoints'].append(endpoint)
                    print(f"{Fore.CYAN}[*] Endpoint: {hex(endpoint.address)} ({endpoint.direction}, {endpoint.transfer_type}){Style.RESET_ALL}")

        # Security analysis
        self._check_security_issues(dev, analysis)

        return analysis

    def enumerate_endpoints(self, vendor_id: int, product_id: int) -> List[USBEndpoint]:
        """
        Enumerate all endpoints for a specific device.

        Args:
            vendor_id: USB vendor ID
            product_id: USB product ID

        Returns:
            List of USBEndpoint objects
        """
        print(f"\n{Fore.YELLOW}[*] Enumerating endpoints for {hex(vendor_id)}:{hex(product_id)}...{Style.RESET_ALL}")
        endpoints = []

        dev = usb.core.find(idVendor=vendor_id, idProduct=product_id)
        if dev is None:
            print(f"{Fore.RED}[!] Device not found{Style.RESET_ALL}")
            return endpoints

        try:
            for cfg in dev:
                for intf in cfg:
                    for ep in intf:
                        endpoint = self._parse_endpoint(ep)
                        endpoints.append(endpoint)
                        print(f"{Fore.GREEN}[+] {hex(endpoint.address)}: {endpoint.direction} {endpoint.transfer_type}{Style.RESET_ALL}")

        except usb.core.USBError as e:
            print(f"{Fore.RED}[!] Error enumerating endpoints: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Total endpoints: {len(endpoints)}{Style.RESET_ALL}")
        return endpoints

    def fuzz_device(self, vendor_id: int, product_id: int, max_attempts: int = 50) -> List[USBFinding]:
        """
        Fuzz USB device with various payloads to detect vulnerabilities.

        Args:
            vendor_id: USB vendor ID
            product_id: USB product ID
            max_attempts: Maximum fuzzing attempts

        Returns:
            List of findings from fuzzing
        """
        print(f"\n{Fore.YELLOW}[*] Fuzzing device {hex(vendor_id)}:{hex(product_id)}...{Style.RESET_ALL}")
        findings = []
        device_id = f"{hex(vendor_id)}:{hex(product_id)}"

        dev = usb.core.find(idVendor=vendor_id, idProduct=product_id)
        if dev is None:
            print(f"{Fore.RED}[!] Device not found{Style.RESET_ALL}")
            return findings

        # Fuzzing payloads
        payloads = [
            bytes([0xFF] * 64),      # Max bytes
            bytes([0x00] * 64),      # Null bytes
            bytes(range(256)),       # All byte values
            b'A' * 1024,             # Large buffer
            b'\x00' * 1024,          # Large null buffer
            bytes([0x41, 0x41] * 512),  # Alternating pattern
        ]

        endpoints = self.enumerate_endpoints(vendor_id, product_id)
        out_endpoints = [ep for ep in endpoints if ep.direction == 'OUT']

        if not out_endpoints:
            print(f"{Fore.YELLOW}[!] No OUT endpoints found for fuzzing{Style.RESET_ALL}")
            return findings

        attempts = 0
        for endpoint in out_endpoints[:2]:  # Limit to first 2 OUT endpoints
            for payload in payloads:
                if attempts >= max_attempts:
                    break

                try:
                    # Try to write payload
                    dev.write(endpoint.address, payload, timeout=1000)
                    attempts += 1
                    time.sleep(self.rate_limit)

                    # Check if device still responds
                    try:
                        usb.util.get_string(dev, 1)
                    except usb.core.USBError:
                        finding = USBFinding(
                            device_id=device_id,
                            severity='HIGH',
                            title='USB Device Unresponsive After Fuzzing',
                            description=f'Device stopped responding after payload to endpoint {hex(endpoint.address)}',
                            evidence=f'Payload size: {len(payload)} bytes',
                            timestamp=time.time()
                        )
                        findings.append(finding)
                        self.findings.append(finding)
                        print(f"{Fore.RED}[!] Device became unresponsive!{Style.RESET_ALL}")
                        return findings

                except usb.core.USBError as e:
                    if 'timeout' not in str(e).lower():
                        finding = USBFinding(
                            device_id=device_id,
                            severity='MEDIUM',
                            title='USB Protocol Error',
                            description=f'Payload triggered USB error: {e}',
                            evidence=f'Endpoint: {hex(endpoint.address)}, Payload size: {len(payload)}',
                            timestamp=time.time()
                        )
                        findings.append(finding)
                        self.findings.append(finding)
                        print(f"{Fore.YELLOW}[!] USB error: {e}{Style.RESET_ALL}")

                time.sleep(self.rate_limit)

        print(f"{Fore.CYAN}[*] Fuzzing complete: {attempts} attempts, {len(findings)} findings{Style.RESET_ALL}")
        return findings

    def check_vendor_vulnerabilities(self, vendor_id: int) -> List[USBFinding]:
        """
        Check if vendor ID is associated with known vulnerabilities.

        Args:
            vendor_id: USB vendor ID

        Returns:
            List of findings for known vulnerable vendors
        """
        findings = []

        if vendor_id in self.KNOWN_VULNERABLE_VIDS:
            description = self.KNOWN_VULNERABLE_VIDS[vendor_id]
            finding = USBFinding(
                device_id=hex(vendor_id),
                severity='MEDIUM',
                title='Known Vulnerable USB Vendor',
                description=description,
                evidence=f'Vendor ID {hex(vendor_id)} has known security issues',
                timestamp=time.time()
            )
            findings.append(finding)
            self.findings.append(finding)
            print(f"{Fore.YELLOW}[!] Known vulnerable vendor: {description}{Style.RESET_ALL}")

        return findings

    def test_descriptor_manipulation(self, vendor_id: int, product_id: int) -> List[USBFinding]:
        """
        Test for descriptor manipulation vulnerabilities.

        Args:
            vendor_id: USB vendor ID
            product_id: USB product ID

        Returns:
            List of descriptor-related findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing descriptor manipulation...{Style.RESET_ALL}")
        findings = []
        device_id = f"{hex(vendor_id)}:{hex(product_id)}"

        dev = usb.core.find(idVendor=vendor_id, idProduct=product_id)
        if dev is None:
            return findings

        try:
            # Try to read various descriptor types
            descriptor_types = [
                (0x01, 'Device'),
                (0x02, 'Configuration'),
                (0x03, 'String'),
                (0x06, 'Device Qualifier'),
                (0x0A, 'Debug'),
                (0x0F, 'BOS'),
            ]

            for dtype, name in descriptor_types:
                try:
                    # Request descriptor
                    result = dev.ctrl_transfer(
                        0x80,  # bmRequestType: Device-to-host
                        0x06,  # bRequest: GET_DESCRIPTOR
                        (dtype << 8) | 0,  # wValue
                        0,     # wIndex
                        255,   # wLength
                        timeout=1000
                    )

                    if result and len(result) > 0:
                        print(f"{Fore.GREEN}[+] {name} descriptor: {len(result)} bytes{Style.RESET_ALL}")

                except usb.core.USBError:
                    pass

                time.sleep(self.rate_limit)

        except usb.core.USBError as e:
            print(f"{Fore.RED}[!] Error testing descriptors: {e}{Style.RESET_ALL}")

        return findings

    def scan_all_devices(self) -> Dict[str, Dict]:
        """
        Comprehensive scan of all connected USB devices.

        Returns:
            Dictionary mapping device IDs to scan results
        """
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting comprehensive USB device scan{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        results = {}
        devices = self.enumerate_devices()

        for device in devices:
            device_id = f"{hex(device.vendor_id)}:{hex(device.product_id)}"
            print(f"\n{Fore.CYAN}[*] Scanning {device_id}...{Style.RESET_ALL}")

            # Analyze device
            analysis = self.analyze_device(device.vendor_id, device.product_id)

            # Check vendor vulnerabilities
            vendor_findings = self.check_vendor_vulnerabilities(device.vendor_id)

            # Test descriptor manipulation
            descriptor_findings = self.test_descriptor_manipulation(device.vendor_id, device.product_id)

            # Fuzz device (limited)
            fuzz_findings = self.fuzz_device(device.vendor_id, device.product_id, max_attempts=10)

            results[device_id] = {
                'device_info': device,
                'analysis': analysis,
                'vendor_findings': vendor_findings,
                'descriptor_findings': descriptor_findings,
                'fuzz_findings': fuzz_findings,
                'total_findings': len(vendor_findings) + len(descriptor_findings) + len(fuzz_findings)
            }

        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total findings: {len(self.findings)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        return results

    def _get_speed_string(self, speed: int) -> str:
        """Convert speed code to human-readable string"""
        speeds = {
            0: 'Unknown',
            1: 'Low Speed (1.5 Mbps)',
            2: 'Full Speed (12 Mbps)',
            3: 'High Speed (480 Mbps)',
            4: 'Super Speed (5 Gbps)',
            5: 'Super Speed+ (10 Gbps)',
        }
        return speeds.get(speed, f'Unknown ({speed})')

    def _parse_endpoint(self, ep) -> USBEndpoint:
        """Parse endpoint descriptor into USBEndpoint object"""
        direction = 'IN' if ep.bEndpointAddress & 0x80 else 'OUT'
        transfer_type = self.TRANSFER_TYPES.get(ep.bmAttributes & 0x03, 'Unknown')

        return USBEndpoint(
            address=ep.bEndpointAddress,
            attributes=ep.bmAttributes,
            max_packet_size=ep.wMaxPacketSize,
            interval=ep.bInterval,
            direction=direction,
            transfer_type=transfer_type
        )

    def _get_device_info(self, dev) -> Dict:
        """Extract detailed device information"""
        try:
            return {
                'vendor_id': hex(dev.idVendor),
                'product_id': hex(dev.idProduct),
                'manufacturer': usb.util.get_string(dev, dev.iManufacturer) if dev.iManufacturer else None,
                'product': usb.util.get_string(dev, dev.iProduct) if dev.iProduct else None,
                'serial': usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else None,
                'class': self.USB_CLASSES.get(dev.bDeviceClass, 'Unknown'),
                'speed': self._get_speed_string(dev.speed),
            }
        except (usb.core.USBError, ValueError):
            return {}

    def _check_security_issues(self, dev, analysis: Dict):
        """Check for common USB security issues"""
        device_id = f"{hex(dev.idVendor)}:{hex(dev.idProduct)}"

        # Check for vendor-specific class (potential custom protocol)
        if dev.bDeviceClass == 0xFF:
            finding = USBFinding(
                device_id=device_id,
                severity='LOW',
                title='Vendor-Specific USB Class',
                description='Device uses vendor-specific class which may have undocumented protocol',
                evidence=f'Device class: 0xFF',
                timestamp=time.time()
            )
            analysis['security_issues'].append(finding)
            self.findings.append(finding)

        # Check for excessive endpoints (possible attack surface)
        if len(analysis['endpoints']) > 8:
            finding = USBFinding(
                device_id=device_id,
                severity='LOW',
                title='Large Number of Endpoints',
                description=f'Device has {len(analysis["endpoints"])} endpoints (increased attack surface)',
                evidence=f'Endpoint count: {len(analysis["endpoints"])}',
                timestamp=time.time()
            )
            analysis['security_issues'].append(finding)
            self.findings.append(finding)

    def get_findings_summary(self) -> Dict:
        """
        Get summary of all findings.

        Returns:
            Dictionary with findings statistics
        """
        critical = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high = sum(1 for f in self.findings if f.severity == 'HIGH')
        medium = sum(1 for f in self.findings if f.severity == 'MEDIUM')
        low = sum(1 for f in self.findings if f.severity == 'LOW')

        return {
            'total': len(self.findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'findings': self.findings
        }
