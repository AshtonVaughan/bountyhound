"""
Bluetooth LE Scanner and Security Tester
BLE device enumeration, service discovery, and security testing
"""

import asyncio
from bleak import BleakScanner, BleakClient
from typing import List, Dict, Optional, Set
from colorama import Fore, Style
import time
from dataclasses import dataclass
from engine.core.proxy_config import ProxyConfig


@dataclass
class BLEDevice:
    """Represents a Bluetooth LE device"""
    address: str
    name: Optional[str]
    rssi: int
    metadata: Dict


@dataclass
class BLEService:
    """Represents a BLE GATT service"""
    uuid: str
    description: str
    characteristics: List[str]


@dataclass
class BLEFinding:
    """Represents a BLE security finding"""
    device_address: str
    severity: str
    title: str
    description: str
    evidence: str
    timestamp: float


class BluetoothScanner:
    """Bluetooth LE device enumeration and security testing"""

    # Known vulnerable/interesting service UUIDs
    INTERESTING_SERVICES = {
        '0000180f-0000-1000-8000-00805f9b34fb': 'Battery Service',
        '0000180a-0000-1000-8000-00805f9b34fb': 'Device Information',
        '00001800-0000-1000-8000-00805f9b34fb': 'Generic Access',
        '00001801-0000-1000-8000-00805f9b34fb': 'Generic Attribute',
        '0000180d-0000-1000-8000-00805f9b34fb': 'Heart Rate',
        '00001812-0000-1000-8000-00805f9b34fb': 'HID Service',
        '0000fee0-0000-1000-8000-00805f9b34fb': 'Xiaomi Service',
        '0000fee1-0000-1000-8000-00805f9b34fb': 'Nordic UART',
    }

    # Characteristic properties that indicate security issues
    INSECURE_PROPERTIES = {
        'read': 'Unprotected read access',
        'write': 'Unprotected write access',
        'write-without-response': 'Unprotected write without response',
        'notify': 'Unprotected notifications',
        'indicate': 'Unprotected indications',
    }

    def __init__(self, scan_duration: float = 10.0, proxy_config: ProxyConfig = None):
        """
        Initialize Bluetooth scanner.

        Args:
            scan_duration: Duration of BLE scan in seconds (default: 10.0)
            proxy_config: Proxy configuration (not used for BLE, kept for API consistency)
        """
        self.scan_duration = scan_duration
        self.findings = []
        print(f"{Fore.GREEN}[+] Bluetooth scanner initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan duration: {scan_duration}s{Style.RESET_ALL}")

    async def scan_devices(self, timeout: Optional[float] = None) -> List[BLEDevice]:
        """
        Scan for nearby BLE devices.

        Args:
            timeout: Scan timeout in seconds (uses scan_duration if None)

        Returns:
            List of discovered BLEDevice objects
        """
        timeout = timeout or self.scan_duration
        print(f"\n{Fore.YELLOW}[*] Scanning for BLE devices ({timeout}s)...{Style.RESET_ALL}")

        devices = []
        try:
            discovered = await BleakScanner.discover(timeout=timeout)

            for device in discovered:
                ble_device = BLEDevice(
                    address=device.address,
                    name=device.name,
                    rssi=device.rssi,
                    metadata=device.metadata
                )
                devices.append(ble_device)

                print(f"{Fore.GREEN}[+] Found: {device.address}{Style.RESET_ALL}")
                if device.name:
                    print(f"    Name: {device.name}")
                print(f"    RSSI: {device.rssi} dBm")

        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning devices: {e}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[*] Total devices found: {len(devices)}{Style.RESET_ALL}")
        return devices

    async def enumerate_services(self, address: str) -> List[BLEService]:
        """
        Enumerate GATT services for a specific device.

        Args:
            address: BLE device address

        Returns:
            List of BLEService objects
        """
        print(f"\n{Fore.YELLOW}[*] Enumerating services for {address}...{Style.RESET_ALL}")
        services = []

        try:
            async with BleakClient(address) as client:
                if not client.is_connected:
                    print(f"{Fore.RED}[!] Failed to connect to device{Style.RESET_ALL}")
                    return services

                for service in client.services:
                    characteristics = []

                    for char in service.characteristics:
                        characteristics.append(str(char.uuid))

                    ble_service = BLEService(
                        uuid=str(service.uuid),
                        description=self.INTERESTING_SERVICES.get(str(service.uuid).lower(), 'Unknown'),
                        characteristics=characteristics
                    )
                    services.append(ble_service)

                    service_name = self.INTERESTING_SERVICES.get(str(service.uuid).lower(), 'Unknown')
                    print(f"{Fore.GREEN}[+] Service: {service.uuid} ({service_name}){Style.RESET_ALL}")
                    print(f"    Characteristics: {len(characteristics)}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error enumerating services: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Total services: {len(services)}{Style.RESET_ALL}")
        return services

    async def test_authentication(self, address: str) -> List[BLEFinding]:
        """
        Test if device requires authentication/pairing.

        Args:
            address: BLE device address

        Returns:
            List of authentication-related findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing authentication for {address}...{Style.RESET_ALL}")
        findings = []

        try:
            async with BleakClient(address) as client:
                if not client.is_connected:
                    return findings

                # Attempt to read characteristics without pairing
                accessible_chars = 0

                for service in client.services:
                    for char in service.characteristics:
                        if 'read' in char.properties:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                accessible_chars += 1

                                print(f"{Fore.YELLOW}[!] Unprotected read: {char.uuid}{Style.RESET_ALL}")

                            except Exception:
                                # Read failed - likely protected
                                pass

                if accessible_chars > 0:
                    finding = BLEFinding(
                        device_address=address,
                        severity='MEDIUM',
                        title='Unprotected GATT Characteristics',
                        description=f'{accessible_chars} characteristics readable without authentication',
                        evidence=f'Accessible characteristics: {accessible_chars}',
                        timestamp=time.time()
                    )
                    findings.append(finding)
                    self.findings.append(finding)
                    print(f"{Fore.YELLOW}[!] {accessible_chars} unprotected characteristics found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] All characteristics appear protected{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error testing authentication: {e}{Style.RESET_ALL}")

        return findings

    async def test_write_access(self, address: str) -> List[BLEFinding]:
        """
        Test for writable characteristics without authentication.

        Args:
            address: BLE device address

        Returns:
            List of write access findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing write access for {address}...{Style.RESET_ALL}")
        findings = []

        try:
            async with BleakClient(address) as client:
                if not client.is_connected:
                    return findings

                writable_chars = []

                for service in client.services:
                    for char in service.characteristics:
                        if 'write' in char.properties or 'write-without-response' in char.properties:
                            writable_chars.append((service.uuid, char.uuid, char.properties))

                            print(f"{Fore.YELLOW}[!] Writable: {char.uuid}{Style.RESET_ALL}")
                            print(f"    Properties: {char.properties}")

                if writable_chars:
                    finding = BLEFinding(
                        device_address=address,
                        severity='HIGH',
                        title='Writable GATT Characteristics',
                        description=f'{len(writable_chars)} characteristics are writable',
                        evidence=f'Writable characteristics: {len(writable_chars)}',
                        timestamp=time.time()
                    )
                    findings.append(finding)
                    self.findings.append(finding)
                    print(f"{Fore.RED}[!] {len(writable_chars)} writable characteristics found{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error testing write access: {e}{Style.RESET_ALL}")

        return findings

    async def fuzz_characteristics(self, address: str, max_attempts: int = 10) -> List[BLEFinding]:
        """
        Fuzz writable characteristics with test payloads.

        Args:
            address: BLE device address
            max_attempts: Maximum fuzzing attempts per characteristic

        Returns:
            List of fuzzing findings
        """
        print(f"\n{Fore.YELLOW}[*] Fuzzing characteristics for {address}...{Style.RESET_ALL}")
        findings = []

        # Test payloads
        payloads = [
            b'\x00' * 20,          # Null bytes
            b'\xff' * 20,          # Max bytes
            b'A' * 100,            # Large buffer
            b'\x00\xff' * 10,      # Alternating pattern
            bytes(range(256)),     # All byte values (truncated to MTU)
        ]

        try:
            async with BleakClient(address) as client:
                if not client.is_connected:
                    return findings

                attempts = 0

                for service in client.services:
                    for char in service.characteristics:
                        if 'write' in char.properties or 'write-without-response' in char.properties:
                            for payload in payloads[:max_attempts]:
                                try:
                                    # Attempt write
                                    await client.write_gatt_char(char.uuid, payload[:20], response=True)
                                    attempts += 1

                                    # Check if device still responds
                                    await asyncio.sleep(0.5)
                                    if not client.is_connected:
                                        finding = BLEFinding(
                                            device_address=address,
                                            severity='HIGH',
                                            title='BLE Device Crashed During Fuzzing',
                                            description=f'Device disconnected after writing to {char.uuid}',
                                            evidence=f'Payload size: {len(payload)} bytes',
                                            timestamp=time.time()
                                        )
                                        findings.append(finding)
                                        self.findings.append(finding)
                                        print(f"{Fore.RED}[!] Device crashed!{Style.RESET_ALL}")
                                        return findings

                                except Exception as e:
                                    if 'disconnect' in str(e).lower():
                                        finding = BLEFinding(
                                            device_address=address,
                                            severity='MEDIUM',
                                            title='BLE Write Error',
                                            description=f'Write to {char.uuid} caused error: {e}',
                                            evidence=f'Error type: {type(e).__name__}',
                                            timestamp=time.time()
                                        )
                                        findings.append(finding)
                                        self.findings.append(finding)

                                await asyncio.sleep(0.1)

        except Exception as e:
            print(f"{Fore.RED}[!] Error during fuzzing: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Fuzzing complete: {len(findings)} findings{Style.RESET_ALL}")
        return findings

    async def check_information_disclosure(self, address: str) -> List[BLEFinding]:
        """
        Check for information disclosure in device name, services, and characteristics.

        Args:
            address: BLE device address

        Returns:
            List of information disclosure findings
        """
        print(f"\n{Fore.YELLOW}[*] Checking information disclosure for {address}...{Style.RESET_ALL}")
        findings = []

        try:
            async with BleakClient(address) as client:
                if not client.is_connected:
                    return findings

                # Check Device Information Service
                device_info_service = '0000180a-0000-1000-8000-00805f9b34fb'

                for service in client.services:
                    if str(service.uuid).lower() == device_info_service:
                        for char in service.characteristics:
                            if 'read' in char.properties:
                                try:
                                    value = await client.read_gatt_char(char.uuid)
                                    decoded = value.decode('utf-8', errors='replace')

                                    if decoded:
                                        finding = BLEFinding(
                                            device_address=address,
                                            severity='LOW',
                                            title='Device Information Disclosure',
                                            description=f'Device info readable: {char.uuid}',
                                            evidence=f'Value: {decoded[:50]}',
                                            timestamp=time.time()
                                        )
                                        findings.append(finding)
                                        self.findings.append(finding)
                                        print(f"{Fore.CYAN}[*] Device info: {decoded[:50]}{Style.RESET_ALL}")

                                except Exception:
                                    pass

        except Exception as e:
            print(f"{Fore.RED}[!] Error checking information disclosure: {e}{Style.RESET_ALL}")

        return findings

    async def scan_and_analyze(self, target_address: Optional[str] = None) -> Dict:
        """
        Comprehensive BLE scan and security analysis.

        Args:
            target_address: Specific device address to analyze (scans all if None)

        Returns:
            Dictionary containing scan and analysis results
        """
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting comprehensive BLE scan{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        results = {}

        # Scan for devices
        if target_address:
            devices = [BLEDevice(address=target_address, name=None, rssi=0, metadata={})]
        else:
            devices = await self.scan_devices()

        # Analyze each device
        for device in devices[:5]:  # Limit to 5 devices
            print(f"\n{Fore.CYAN}[*] Analyzing {device.address}...{Style.RESET_ALL}")

            services = await self.enumerate_services(device.address)
            auth_findings = await self.test_authentication(device.address)
            write_findings = await self.test_write_access(device.address)
            info_findings = await self.check_information_disclosure(device.address)
            fuzz_findings = await self.fuzz_characteristics(device.address, max_attempts=5)

            results[device.address] = {
                'device_info': device,
                'services': services,
                'auth_findings': auth_findings,
                'write_findings': write_findings,
                'info_findings': info_findings,
                'fuzz_findings': fuzz_findings,
                'total_findings': len(auth_findings) + len(write_findings) + len(info_findings) + len(fuzz_findings)
            }

        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total findings: {len(self.findings)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        return results

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

    def run_scan(self, target_address: Optional[str] = None) -> Dict:
        """
        Synchronous wrapper for scan_and_analyze.

        Args:
            target_address: Specific device address to analyze (scans all if None)

        Returns:
            Dictionary containing scan and analysis results
        """
        return asyncio.run(self.scan_and_analyze(target_address))
