"""
JTAG/SWD Interface Tester
Hardware debugging interface detection and security testing
"""

from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style
import time
from dataclasses import dataclass
from scapy.all import *
import subprocess
import re


@dataclass
class JTAGPin:
    """Represents a JTAG pin"""
    number: int
    name: str
    detected: bool
    voltage: Optional[float] = None


@dataclass
class JTAGFinding:
    """Represents a JTAG security finding"""
    severity: str
    title: str
    description: str
    evidence: str
    timestamp: float


class JTAGTester:
    """JTAG/SWD interface detection and security testing"""

    # Standard JTAG pin configurations
    JTAG_PINS = {
        'TDI': 'Test Data In',
        'TDO': 'Test Data Out',
        'TCK': 'Test Clock',
        'TMS': 'Test Mode Select',
        'TRST': 'Test Reset (optional)',
    }

    # SWD pin configurations
    SWD_PINS = {
        'SWDIO': 'Serial Wire Debug I/O',
        'SWCLK': 'Serial Wire Clock',
        'SWO': 'Serial Wire Output (optional)',
    }

    # Common JTAG frequencies (Hz)
    COMMON_FREQUENCIES = [
        100000,    # 100 KHz
        1000000,   # 1 MHz
        4000000,   # 4 MHz
        8000000,   # 8 MHz
        10000000,  # 10 MHz
    ]

    def __init__(self, rate_limit: float = 0.5):
        """
        Initialize JTAG tester.

        Args:
            rate_limit: Seconds between operations (default: 0.5)
        """
        self.rate_limit = rate_limit
        self.findings = []
        self.detected_pins = {}
        print(f"{Fore.GREEN}[+] JTAG tester initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s{Style.RESET_ALL}")

    def detect_jtag_pins(self, pin_count: int = 20) -> Dict[str, JTAGPin]:
        """
        Simulate JTAG pin detection (requires hardware probe in practice).

        Args:
            pin_count: Number of pins to scan

        Returns:
            Dictionary mapping pin names to JTAGPin objects
        """
        print(f"\n{Fore.YELLOW}[*] Scanning for JTAG pins (1-{pin_count})...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Note: This is a simulated scan - requires hardware probe{Style.RESET_ALL}")

        detected = {}

        # Simulate pin scanning
        print(f"{Fore.YELLOW}[!] Hardware probe required for actual pin detection{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Common JTAG pin patterns:{Style.RESET_ALL}")

        for pin_name, description in self.JTAG_PINS.items():
            print(f"    {pin_name}: {description}")

        return detected

    def check_debug_enabled(self) -> List[JTAGFinding]:
        """
        Check if hardware debugging is enabled (requires OpenOCD or similar).

        Returns:
            List of findings related to debug access
        """
        print(f"\n{Fore.YELLOW}[*] Checking if debug interface is enabled...{Style.RESET_ALL}")
        findings = []

        try:
            # Try to detect OpenOCD
            result = subprocess.run(
                ['openocd', '--version'],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] OpenOCD detected: {result.stdout.split()[2] if len(result.stdout.split()) > 2 else 'Unknown version'}{Style.RESET_ALL}")

                finding = JTAGFinding(
                    severity='INFO',
                    title='OpenOCD Available',
                    description='OpenOCD is installed and can be used for JTAG testing',
                    evidence=result.stdout.strip(),
                    timestamp=time.time()
                )
                findings.append(finding)
                self.findings.append(finding)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"{Fore.YELLOW}[!] OpenOCD not found - install for JTAG testing{Style.RESET_ALL}")

        return findings

    def test_readout_protection(self) -> List[JTAGFinding]:
        """
        Test for firmware readout protection (RDP).

        Returns:
            List of readout protection findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing readout protection...{Style.RESET_ALL}")
        findings = []

        print(f"{Fore.CYAN}[*] Readout protection tests require:{Style.RESET_ALL}")
        print(f"    1. Physical JTAG/SWD connection")
        print(f"    2. OpenOCD or J-Link")
        print(f"    3. Appropriate target configuration")

        # Simulate common RDP scenarios
        rdp_levels = {
            'Level 0': 'No protection - full debug access',
            'Level 1': 'Memory read protected',
            'Level 2': 'Debug disabled (permanent)',
        }

        print(f"\n{Fore.CYAN}[*] Common RDP levels:{Style.RESET_ALL}")
        for level, description in rdp_levels.items():
            print(f"    {level}: {description}")

        return findings

    def test_boundary_scan(self) -> List[JTAGFinding]:
        """
        Test JTAG boundary scan capabilities.

        Returns:
            List of boundary scan findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing boundary scan...{Style.RESET_ALL}")
        findings = []

        print(f"{Fore.CYAN}[*] Boundary scan capabilities:{Style.RESET_ALL}")
        print(f"    - Pin state observation")
        print(f"    - Signal injection")
        print(f"    - Circuit testing")
        print(f"    - Device identification")

        print(f"\n{Fore.YELLOW}[!] Requires physical JTAG connection{Style.RESET_ALL}")

        return findings

    def enumerate_tap_devices(self) -> List[Dict]:
        """
        Enumerate devices in JTAG chain (Test Access Points).

        Returns:
            List of detected TAP devices
        """
        print(f"\n{Fore.YELLOW}[*] Enumerating TAP devices...{Style.RESET_ALL}")
        devices = []

        print(f"{Fore.CYAN}[*] TAP enumeration requires:{Style.RESET_ALL}")
        print(f"    - OpenOCD with: openocd -f interface.cfg -f target.cfg")
        print(f"    - Or JTAGEnum tool for hardware probing")

        return devices

    def test_debug_authentication(self) -> List[JTAGFinding]:
        """
        Test if debug interface requires authentication.

        Returns:
            List of authentication findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing debug authentication...{Style.RESET_ALL}")
        findings = []

        print(f"{Fore.CYAN}[*] Debug authentication mechanisms:{Style.RESET_ALL}")
        print(f"    - Password/key required")
        print(f"    - Certificate-based auth")
        print(f"    - Secure debug unlock")
        print(f"    - No authentication (CRITICAL)")

        # If no authentication is found, it's a critical finding
        # This would be determined by actual hardware testing

        return findings

    def test_flash_extraction(self) -> List[JTAGFinding]:
        """
        Test if flash memory can be extracted via JTAG.

        Returns:
            List of flash extraction findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing flash extraction...{Style.RESET_ALL}")
        findings = []

        print(f"{Fore.CYAN}[*] Flash extraction via JTAG:{Style.RESET_ALL}")
        print(f"    Command: openocd -f interface.cfg -f target.cfg \\")
        print(f"             -c 'init' -c 'halt' -c 'dump_image firmware.bin 0x08000000 0x100000'")

        print(f"\n{Fore.RED}[!] If flash is extractable without auth = CRITICAL{Style.RESET_ALL}")

        return findings

    def scan_for_swd(self) -> Dict[str, bool]:
        """
        Scan for Serial Wire Debug (SWD) interface.

        Returns:
            Dictionary with SWD detection results
        """
        print(f"\n{Fore.YELLOW}[*] Scanning for SWD interface...{Style.RESET_ALL}")

        results = {
            'swd_detected': False,
            'swdio_pin': None,
            'swclk_pin': None,
        }

        print(f"{Fore.CYAN}[*] SWD is a 2-pin alternative to JTAG{Style.RESET_ALL}")
        print(f"    - SWDIO: Bidirectional data")
        print(f"    - SWCLK: Clock signal")
        print(f"    - Common on ARM Cortex devices")

        print(f"\n{Fore.YELLOW}[!] Hardware probe required for detection{Style.RESET_ALL}")

        return results

    def test_voltage_glitching(self) -> List[JTAGFinding]:
        """
        Test for voltage glitching attack surface.

        Returns:
            List of voltage glitching findings
        """
        print(f"\n{Fore.YELLOW}[*] Analyzing voltage glitching attack surface...{Style.RESET_ALL}")
        findings = []

        print(f"{Fore.CYAN}[*] Voltage glitching can bypass:{Style.RESET_ALL}")
        print(f"    - Secure boot")
        print(f"    - Readout protection")
        print(f"    - Debug authentication")

        print(f"\n{Fore.YELLOW}[!] Requires specialized hardware (ChipWhisperer, etc.){Style.RESET_ALL}")

        # Check if power pins are accessible
        finding = JTAGFinding(
            severity='MEDIUM',
            title='Voltage Glitching Attack Surface',
            description='Device may be vulnerable to voltage glitching if power pins are accessible',
            evidence='Requires hardware fault injection equipment',
            timestamp=time.time()
        )
        findings.append(finding)
        self.findings.append(finding)

        return findings

    def comprehensive_analysis(self) -> Dict:
        """
        Comprehensive JTAG/SWD security analysis.

        Returns:
            Dictionary containing all analysis results
        """
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting comprehensive JTAG/SWD analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        results = {
            'jtag_pins': self.detect_jtag_pins(),
            'swd_detection': self.scan_for_swd(),
            'debug_enabled': self.check_debug_enabled(),
            'tap_devices': self.enumerate_tap_devices(),
            'readout_protection': self.test_readout_protection(),
            'boundary_scan': self.test_boundary_scan(),
            'debug_auth': self.test_debug_authentication(),
            'flash_extraction': self.test_flash_extraction(),
            'voltage_glitching': self.test_voltage_glitching(),
            'findings': self.findings,
        }

        # Print summary
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Analysis Summary:{Style.RESET_ALL}")
        print(f"    Total findings: {len(self.findings)}")
        print(f"\n{Fore.YELLOW}[!] IMPORTANT: Most JTAG/SWD tests require:{Style.RESET_ALL}")
        print(f"    1. Physical hardware access")
        print(f"    2. JTAG/SWD debugger (J-Link, ST-Link, etc.)")
        print(f"    3. OpenOCD or vendor-specific tools")
        print(f"    4. Target configuration files")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        return results

    def generate_openocd_config(self, chip_type: str = 'stm32f4x') -> str:
        """
        Generate sample OpenOCD configuration for testing.

        Args:
            chip_type: Target chip type

        Returns:
            OpenOCD configuration string
        """
        config = f"""# OpenOCD Configuration for {chip_type}
# Generated by BountyHound JTAG Tester

# Interface configuration (choose your adapter)
# source [find interface/jlink.cfg]
# source [find interface/stlink-v2.cfg]

# Target configuration
source [find target/{chip_type}.cfg]

# Connection settings
adapter speed 1000

# Commands to dump flash
init
halt
dump_image firmware.bin 0x08000000 0x100000
reset
shutdown
"""
        print(f"\n{Fore.GREEN}[+] Sample OpenOCD config generated{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{config}{Style.RESET_ALL}")

        return config

    def get_testing_guide(self) -> str:
        """
        Get comprehensive JTAG testing guide.

        Returns:
            Testing guide as string
        """
        guide = """
╔════════════════════════════════════════════════════════════════╗
║              JTAG/SWD SECURITY TESTING GUIDE                   ║
╚════════════════════════════════════════════════════════════════╝

1. HARDWARE REQUIREMENTS
   - JTAG/SWD debugger (J-Link, ST-Link, FTDI, etc.)
   - Target device with exposed debug pins
   - Multimeter for pin identification
   - Logic analyzer (optional)

2. PIN IDENTIFICATION
   JTAG (5 pins minimum):
   - TDI, TDO, TCK, TMS, (TRST optional)

   SWD (2 pins minimum):
   - SWDIO, SWCLK

   Use JTAGEnum or manual probing to identify pins

3. TESTING WORKFLOW
   a) Identify debug pins
   b) Connect debugger
   c) Run OpenOCD: openocd -f interface.cfg -f target.cfg
   d) Test readout protection
   e) Attempt flash dump
   f) Check for authentication

4. COMMON VULNERABILITIES
   ✗ Debug interface enabled in production
   ✗ No readout protection (RDP Level 0)
   ✗ Weak or no debug authentication
   ✗ Flash memory extractable
   ✗ Firmware contains secrets

5. TOOLS
   - OpenOCD (open-source debug)
   - J-Link Commander (Segger)
   - PyOCD (Python)
   - JTAGEnum (pin discovery)
   - ChipWhisperer (fault injection)

6. LEGAL NOTICE
   ⚠ Only test devices you own or have permission to test
   ⚠ Hardware modification may void warranty
   ⚠ Some techniques may damage device

╚════════════════════════════════════════════════════════════════╝
"""
        print(guide)
        return guide

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
        info = sum(1 for f in self.findings if f.severity == 'INFO')

        return {
            'total': len(self.findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info,
            'findings': self.findings
        }
