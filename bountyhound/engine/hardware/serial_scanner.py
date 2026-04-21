"""
Serial Port Scanner and UART Security Tester
Automated serial port enumeration, baudrate detection, and UART fuzzing
"""

import serial
import serial.tools.list_ports
from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style
import time
import threading
from dataclasses import dataclass
from engine.core.proxy_config import ProxyConfig
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


@dataclass
class SerialPort:
    """Represents a detected serial port"""
    device: str
    description: str
    hwid: str
    vid: Optional[int] = None
    pid: Optional[int] = None
    manufacturer: Optional[str] = None


@dataclass
class SerialFinding:
    """Represents a security finding from serial testing"""
    port: str
    baudrate: int
    severity: str
    title: str
    description: str
    evidence: str
    timestamp: float


class SerialScanner:
    """Serial port enumeration and UART security testing"""

    # Common baudrates ordered by likelihood
    COMMON_BAUDRATES = [
        115200, 9600, 57600, 38400, 19200, 14400, 4800, 2400,
        1200, 230400, 460800, 921600, 1000000, 1500000, 2000000
    ]

    # Common test commands for embedded systems
    TEST_COMMANDS = [
        b'\r\n',           # Line feed
        b'help\r\n',       # Help command
        b'?\r\n',          # Question mark
        b'AT\r\n',         # AT command (modems)
        b'ATI\r\n',        # AT info
        b'info\r\n',       # Info
        b'version\r\n',    # Version
        b'status\r\n',     # Status
        b'ls\r\n',         # List (Unix-like)
        b'dir\r\n',        # Directory (DOS-like)
        b'cat /etc/passwd\r\n',  # Unix password file
        b'ps\r\n',         # Process list
        b'uname -a\r\n',   # System info
        b'id\r\n',         # User ID
        b'whoami\r\n',     # Current user
        b'\x03',           # Ctrl+C
        b'\x04',           # Ctrl+D
        b'\x1b',           # ESC
    ]

    # Payloads for UART fuzzing
    FUZZ_PAYLOADS = [
        b'A' * 256,        # Buffer overflow
        b'%s' * 100,       # Format string
        b'\x00' * 100,     # Null bytes
        b'\xff' * 100,     # Max bytes
        b'../' * 50,       # Directory traversal
        b'; ls\r\n',       # Command injection
        b'| id\r\n',       # Pipe injection
        b'`whoami`\r\n',   # Command substitution
        b'$(id)\r\n',      # Command substitution
        b"'; DROP TABLE--", # SQL injection
        b'<script>alert(1)</script>', # XSS
    ]

    def __init__(self, timeout: float = 2.0, rate_limit: float = 0.1, proxy_config: ProxyConfig = None):
        """
        Initialize serial scanner with timeout and rate limiting.

        Args:
            timeout: Serial read timeout in seconds (default: 2.0)
            rate_limit: Seconds between operations (default: 0.1)
            proxy_config: Proxy configuration (not used for serial, kept for API consistency)
        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.findings = []
        self._stop_event = threading.Event()
        print(f"{Fore.GREEN}[+] Serial scanner initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Timeout: {timeout}s, Rate limit: {rate_limit}s{Style.RESET_ALL}")

    def enumerate_ports(self) -> List[SerialPort]:
        """
        Enumerate all available serial ports on the system.

        Returns:
            List of SerialPort objects
        """
        print(f"\n{Fore.YELLOW}[*] Enumerating serial ports...{Style.RESET_ALL}")
        ports = []

        for port in serial.tools.list_ports.comports():
            serial_port = SerialPort(
                device=port.device,
                description=port.description,
                hwid=port.hwid,
                vid=port.vid,
                pid=port.pid,
                manufacturer=port.manufacturer
            )
            ports.append(serial_port)

            print(f"{Fore.GREEN}[+] Found: {port.device}{Style.RESET_ALL}")
            print(f"    Description: {port.description}")
            print(f"    HWID: {port.hwid}")
            if port.vid and port.pid:
                print(f"    VID:PID: {hex(port.vid)}:{hex(port.pid)}")
            if port.manufacturer:
                print(f"    Manufacturer: {port.manufacturer}")

        print(f"\n{Fore.CYAN}[*] Total ports found: {len(ports)}{Style.RESET_ALL}")
        return ports

    def detect_baudrate(self, port: str, baudrates: Optional[List[int]] = None) -> Optional[int]:
        """
        Detect the correct baudrate for a serial port by testing common rates.

        Args:
            port: Serial port device path
            baudrates: List of baudrates to test (uses COMMON_BAUDRATES if None)

        Returns:
            Detected baudrate or None if detection failed
        """
        baudrates = baudrates or self.COMMON_BAUDRATES
        print(f"\n{Fore.YELLOW}[*] Detecting baudrate for {port}...{Style.RESET_ALL}")

        for baudrate in baudrates:
            try:
                with serial.Serial(port, baudrate, timeout=self.timeout) as ser:
                    # Clear buffer
                    ser.reset_input_buffer()

                    # Send newline and check for response
                    ser.write(b'\r\n')
                    time.sleep(self.rate_limit)

                    if ser.in_waiting > 0:
                        response = ser.read(ser.in_waiting)
                        # Check if response looks like valid ASCII
                        if self._is_valid_response(response):
                            print(f"{Fore.GREEN}[+] Baudrate detected: {baudrate}{Style.RESET_ALL}")
                            return baudrate

            except (serial.SerialException, OSError) as e:
                continue

            time.sleep(self.rate_limit)

        print(f"{Fore.RED}[-] Baudrate detection failed{Style.RESET_ALL}")
        return None

    def probe_commands(self, port: str, baudrate: int) -> Dict[str, bytes]:
        """
        Test common commands on the serial port to identify the interface type.

        Args:
            port: Serial port device path
            baudrate: Baudrate to use

        Returns:
            Dictionary mapping commands to their responses
        """
        print(f"\n{Fore.YELLOW}[*] Probing commands on {port} @ {baudrate}...{Style.RESET_ALL}")
        responses = {}

        try:
            with serial.Serial(port, baudrate, timeout=self.timeout) as ser:
                for cmd in self.TEST_COMMANDS:
                    ser.reset_input_buffer()
                    ser.write(cmd)
                    time.sleep(self.rate_limit)

                    if ser.in_waiting > 0:
                        response = ser.read(ser.in_waiting)
                        if len(response) > 0:
                            responses[cmd.decode('utf-8', errors='replace').strip()] = response
                            print(f"{Fore.GREEN}[+] Command responded: {cmd[:20]}{Style.RESET_ALL}")

                            # Check for security issues
                            self._analyze_response(port, baudrate, cmd, response)

                    time.sleep(self.rate_limit)

        except (serial.SerialException, OSError) as e:
            print(f"{Fore.RED}[!] Error probing commands: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Commands responded: {len(responses)}/{len(self.TEST_COMMANDS)}{Style.RESET_ALL}")
        return responses

    def fuzz_uart(self, port: str, baudrate: int, max_payloads: int = 20) -> List[SerialFinding]:
        """
        Fuzz UART interface with various payloads to detect vulnerabilities.

        Args:
            port: Serial port device path
            baudrate: Baudrate to use
            max_payloads: Maximum number of payloads to test

        Returns:
            List of findings from fuzzing
        """
        print(f"\n{Fore.YELLOW}[*] Fuzzing UART on {port} @ {baudrate}...{Style.RESET_ALL}")
        findings = []
        payloads_tested = 0

        try:
            with serial.Serial(port, baudrate, timeout=self.timeout) as ser:
                for payload in self.FUZZ_PAYLOADS[:max_payloads]:
                    if self._stop_event.is_set():
                        break

                    ser.reset_input_buffer()
                    ser.write(payload)
                    time.sleep(self.rate_limit * 2)  # Longer wait for crash detection

                    payloads_tested += 1

                    # Check if device still responds
                    try:
                        ser.write(b'\r\n')
                        time.sleep(self.rate_limit)

                        if ser.in_waiting > 0:
                            response = ser.read(ser.in_waiting)

                            # Check for interesting responses
                            if self._is_vulnerability_response(response):
                                finding = SerialFinding(
                                    port=port,
                                    baudrate=baudrate,
                                    severity='HIGH',
                                    title='UART Fuzzing Anomaly Detected',
                                    description=f'Payload triggered unexpected response',
                                    evidence=f'Payload: {payload[:50]}\nResponse: {response[:200]}',
                                    timestamp=time.time()
                                )
                                findings.append(finding)
                                self.findings.append(finding)
                                print(f"{Fore.RED}[!] Vulnerability found!{Style.RESET_ALL}")

                    except (serial.SerialException, OSError):
                        # Device may have crashed
                        finding = SerialFinding(
                            port=port,
                            baudrate=baudrate,
                            severity='CRITICAL',
                            title='UART Device Crash Detected',
                            description='Fuzzing payload caused device to stop responding',
                            evidence=f'Crash payload: {payload[:100]}',
                            timestamp=time.time()
                        )
                        findings.append(finding)
                        self.findings.append(finding)
                        print(f"{Fore.RED}[!!!] CRITICAL: Device crashed!{Style.RESET_ALL}")
                        break

                    time.sleep(self.rate_limit)

        except (serial.SerialException, OSError) as e:
            print(f"{Fore.RED}[!] Error during fuzzing: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Fuzzing complete: {payloads_tested} payloads tested, {len(findings)} findings{Style.RESET_ALL}")
        return findings

    def test_authentication_bypass(self, port: str, baudrate: int) -> List[SerialFinding]:
        """
        Test for authentication bypass vulnerabilities on UART interface.

        Args:
            port: Serial port device path
            baudrate: Baudrate to use

        Returns:
            List of authentication bypass findings
        """
        print(f"\n{Fore.YELLOW}[*] Testing authentication bypass on {port}...{Style.RESET_ALL}")
        findings = []

        bypass_attempts = [
            (b'\x03\r\n', 'Ctrl+C interrupt'),
            (b'\x04\r\n', 'Ctrl+D EOF'),
            (b'\x1b\r\n', 'ESC escape'),
            (b'root\r\n', 'Root login attempt'),
            (b'admin\r\n', 'Admin login attempt'),
            (b'\r\n' * 10, 'Multiple newlines'),
            (b' \r\n', 'Space bypass'),
            (b'\t\r\n', 'Tab bypass'),
        ]

        try:
            with serial.Serial(port, baudrate, timeout=self.timeout) as ser:
                for payload, description in bypass_attempts:
                    ser.reset_input_buffer()
                    ser.write(payload)
                    time.sleep(self.rate_limit)

                    if ser.in_waiting > 0:
                        response = ser.read(ser.in_waiting)

                        # Check for shell prompt or command execution
                        if self._is_shell_prompt(response):
                            finding = SerialFinding(
                                port=port,
                                baudrate=baudrate,
                                severity='CRITICAL',
                                title='UART Authentication Bypass',
                                description=f'Authentication bypassed using: {description}',
                                evidence=f'Payload: {payload}\nResponse: {response[:200]}',
                                timestamp=time.time()
                            )
                            findings.append(finding)
                            self.findings.append(finding)
                            print(f"{Fore.RED}[!!!] CRITICAL: Auth bypass found!{Style.RESET_ALL}")

                    time.sleep(self.rate_limit)

        except (serial.SerialException, OSError) as e:
            print(f"{Fore.RED}[!] Error testing auth bypass: {e}{Style.RESET_ALL}")

        return findings

    def scan_all_ports(self) -> Dict[str, Dict]:
        """
        Comprehensive scan of all available serial ports.

        Returns:
            Dictionary mapping port names to scan results
        """
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting comprehensive serial port scan{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        results = {}
        ports = self.enumerate_ports()

        for port_info in ports:
            port = port_info.device
            print(f"\n{Fore.CYAN}[*] Scanning {port}...{Style.RESET_ALL}")

            # Detect baudrate
            baudrate = self.detect_baudrate(port)
            if not baudrate:
                print(f"{Fore.YELLOW}[!] Skipping {port} - could not detect baudrate{Style.RESET_ALL}")
                continue

            # Probe commands
            responses = self.probe_commands(port, baudrate)

            # Test authentication bypass
            auth_findings = self.test_authentication_bypass(port, baudrate)

            # Fuzz UART
            fuzz_findings = self.fuzz_uart(port, baudrate, max_payloads=10)

            results[port] = {
                'port_info': port_info,
                'baudrate': baudrate,
                'responses': responses,
                'auth_findings': auth_findings,
                'fuzz_findings': fuzz_findings,
                'total_findings': len(auth_findings) + len(fuzz_findings)
            }

        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total findings: {len(self.findings)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        return results

    def _is_valid_response(self, data: bytes) -> bool:
        """Check if response looks like valid ASCII text"""
        try:
            decoded = data.decode('utf-8', errors='ignore')
            # Check for printable characters
            printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1)
            return printable_ratio > 0.7
        except:
            return False

    def _is_vulnerability_response(self, data: bytes) -> bool:
        """Check if response indicates a vulnerability"""
        vuln_indicators = [
            b'error', b'Error', b'ERROR',
            b'exception', b'Exception',
            b'segmentation fault',
            b'stack trace',
            b'debug',
            b'root@', b'#',
            b'/etc/passwd',
            b'uid=', b'gid=',
        ]
        return any(indicator in data for indicator in vuln_indicators)

    def _is_shell_prompt(self, data: bytes) -> bool:
        """Check if response looks like a shell prompt"""
        shell_prompts = [
            b'# ', b'$ ', b'> ',
            b'root@', b'admin@',
            b'bash-', b'sh-',
            b'login:', b'Password:',
        ]
        return any(prompt in data for prompt in shell_prompts)

    def _analyze_response(self, port: str, baudrate: int, command: bytes, response: bytes):
        """Analyze command response for security issues"""
        # Check for information disclosure
        sensitive_patterns = [
            (b'password', 'Password disclosure'),
            (b'secret', 'Secret disclosure'),
            (b'key', 'Key disclosure'),
            (b'token', 'Token disclosure'),
            (b'/etc/passwd', 'Password file access'),
            (b'root:', 'Root account information'),
            (b'uid=0', 'Root privilege detection'),
        ]

        for pattern, description in sensitive_patterns:
            if pattern in response.lower():
                finding = SerialFinding(
                    port=port,
                    baudrate=baudrate,
                    severity='HIGH',
                    title=f'Information Disclosure: {description}',
                    description=f'Command "{command[:50]}" revealed sensitive information',
                    evidence=f'Response: {response[:200]}',
                    timestamp=time.time()
                )
                self.findings.append(finding)
                print(f"{Fore.RED}[!] {description} detected!{Style.RESET_ALL}")

    def stop(self):
        """Stop ongoing scan operations"""
        self._stop_event.set()
        print(f"{Fore.YELLOW}[*] Stopping scan...{Style.RESET_ALL}")

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
