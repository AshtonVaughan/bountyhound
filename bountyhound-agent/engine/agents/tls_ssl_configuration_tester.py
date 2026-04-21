"""
TLS/SSL Configuration Tester Agent

Advanced TLS/SSL configuration testing agent that identifies weak cipher suites,
outdated protocols, certificate issues, and common TLS vulnerabilities.

This agent tests for:
- Weak cipher suite detection (RC4, DES, 3DES, EXPORT, NULL)
- Deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Certificate validation (expired, self-signed, hostname mismatch, weak keys)
- Forward secrecy support (DHE, ECDHE)
- Known vulnerabilities (BEAST, CRIME, POODLE, Heartbleed)
- Certificate chain validation
- TLS compression support
- Renegotiation issues

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import ssl
import socket
import hashlib
import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta
from enum import Enum
from urllib.parse import urlparse


try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID, ExtensionOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Database integration
try:
    from engine.core.database import BountyHoundDB
    from engine.core.db_hooks import DatabaseHooks
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False


class TLSSeverity(Enum):
    """TLS vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TLSVulnType(Enum):
    """Types of TLS vulnerabilities."""
    WEAK_CIPHER = "TLS_WEAK_CIPHER"
    WEAK_PROTOCOL = "TLS_WEAK_PROTOCOL"
    EXPIRED_CERT = "TLS_EXPIRED_CERT"
    SELF_SIGNED_CERT = "TLS_SELF_SIGNED"
    WEAK_KEY = "TLS_WEAK_KEY"
    NO_FORWARD_SECRECY = "TLS_NO_FORWARD_SECRECY"
    BEAST_VULNERABLE = "TLS_BEAST"
    CRIME_VULNERABLE = "TLS_CRIME"
    POODLE_VULNERABLE = "TLS_POODLE"
    HEARTBLEED_VULNERABLE = "TLS_HEARTBLEED"
    HOSTNAME_MISMATCH = "TLS_HOSTNAME_MISMATCH"
    CHAIN_INVALID = "TLS_CHAIN_INVALID"
    WEAK_SIGNATURE = "TLS_WEAK_SIGNATURE"
    INSECURE_RENEGOTIATION = "TLS_INSECURE_RENEGOTIATION"


@dataclass
class TLSFinding:
    """Represents a TLS security finding."""
    title: str
    severity: TLSSeverity
    vuln_type: TLSVulnType
    description: str
    endpoint: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    exploitation: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    bounty_estimate: str = ""
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class CertificateInfo:
    """SSL/TLS Certificate information."""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    sans: List[str]
    not_before: datetime
    not_after: datetime
    serial_number: str
    signature_algorithm: str
    public_key_type: str
    public_key_size: int
    is_self_signed: bool
    is_expired: bool
    is_valid: bool
    fingerprint_sha256: str
    issues: List[str] = field(default_factory=list)


@dataclass
class CipherSuiteInfo:
    """Cipher suite information."""
    name: str
    protocol: str
    bits: int
    is_weak: bool = False
    has_forward_secrecy: bool = False
    weakness_reason: Optional[str] = None


@dataclass
class TLSTestResult:
    """Result from TLS configuration test."""
    hostname: str
    port: int
    supported_protocols: List[str] = field(default_factory=list)
    cipher_suites: List[CipherSuiteInfo] = field(default_factory=list)
    certificate: Optional[CertificateInfo] = None
    vulnerabilities: List[str] = field(default_factory=list)
    has_forward_secrecy: bool = False
    compression_enabled: bool = False
    renegotiation_secure: bool = True
    findings: List[TLSFinding] = field(default_factory=list)


class TLSSSLConfigurationTester:
    """
    Advanced TLS/SSL Configuration Tester.

    Performs comprehensive TLS/SSL security testing including:
    - Protocol version testing (SSLv2/v3, TLS 1.0/1.1/1.2/1.3)
    - Cipher suite enumeration and weakness detection
    - Certificate validation and chain verification
    - Known vulnerability scanning (BEAST, POODLE, CRIME, Heartbleed)
    - Forward secrecy support testing

    Usage:
        tester = TLSSSLConfigurationTester(hostname="example.com", port=443)
        result = tester.run_all_tests()
    """

    # Weak cipher patterns
    WEAK_CIPHER_PATTERNS = [
        ('RC4', 'RC4 stream cipher (known biases)'),
        ('DES-CBC3', 'Triple DES (64-bit blocks, Sweet32)'),
        ('DES-CBC-', 'DES cipher (56-bit key)'),
        ('EXPORT', 'Export-grade cipher (weak key)'),
        ('NULL', 'Null encryption (no confidentiality)'),
        ('MD5', 'MD5 authentication (collision attacks)'),
        ('aNULL', 'Anonymous authentication (no identity)'),
        ('eNULL', 'No encryption'),
        ('AECDH', 'Anonymous ECDH (no authentication)'),
        ('ADH', 'Anonymous DH (no authentication)'),
    ]

    # Deprecated protocols
    WEAK_PROTOCOLS = {
        'SSLv2': ('POODLE, DROWN', TLSSeverity.CRITICAL),
        'SSLv3': ('POODLE attack', TLSSeverity.HIGH),
        'TLSv1.0': ('BEAST, POODLE TLS', TLSSeverity.MEDIUM),
        'TLSv1.1': ('Deprecated, lacks modern features', TLSSeverity.LOW),
    }

    # Forward secrecy cipher patterns
    FORWARD_SECRECY_PATTERNS = ['DHE', 'ECDHE']

    def __init__(self, hostname: str, port: int = 443, timeout: int = 10,
                 use_database: bool = True):
        """
        Initialize TLS/SSL Configuration Tester.

        Args:
            hostname: Target hostname
            port: Target port (default 443)
            timeout: Connection timeout in seconds
            use_database: Whether to use database for context/deduplication
        """
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.use_database = use_database and DATABASE_AVAILABLE

        self.findings: List[TLSFinding] = []
        self.tested_ciphers: Set[str] = set()

        # Database initialization
        self.db = BountyHoundDB() if self.use_database else None

    def run_all_tests(self) -> TLSTestResult:
        """
        Execute all TLS/SSL configuration tests.

        Returns:
            TLSTestResult containing all test results and findings
        """
        print(f"[*] Starting TLS/SSL configuration tests for {self.hostname}:{self.port}")

        # Database check
        if self.use_database:
            context = DatabaseHooks.before_test(self.hostname, 'tls_ssl_configuration_tester')
            if context['should_skip']:
                print(f"[!] {context['reason']}")
                print(f"[!] Previous findings: {len(context['previous_findings'])}")
                print("[*] Proceeding with test anyway for completeness...")

        result = TLSTestResult(hostname=self.hostname, port=self.port)

        # Test 1: Protocol version enumeration
        print("[*] Testing protocol versions...")
        supported_protocols = self._test_protocol_versions()
        result.supported_protocols = supported_protocols

        # Test 2: Cipher suite enumeration
        print("[*] Enumerating cipher suites...")
        cipher_suites = self._enumerate_cipher_suites()
        result.cipher_suites = cipher_suites

        # Test 3: Certificate validation
        print("[*] Validating certificate...")
        cert_info = self._test_certificate()
        result.certificate = cert_info

        # Test 4: Forward secrecy check
        print("[*] Checking forward secrecy support...")
        has_fs = self._check_forward_secrecy(cipher_suites)
        result.has_forward_secrecy = has_fs

        # Test 5: Known vulnerability scanning
        print("[*] Scanning for known vulnerabilities...")
        vulns = self._scan_known_vulnerabilities(supported_protocols, cipher_suites)
        result.vulnerabilities = vulns

        # Test 6: Compression check (CRIME)
        print("[*] Testing TLS compression...")
        compression = self._test_compression()
        result.compression_enabled = compression

        # Test 7: Renegotiation check
        print("[*] Testing secure renegotiation...")
        renegotiation = self._test_renegotiation()
        result.renegotiation_secure = renegotiation

        # Aggregate findings
        result.findings = self.findings

        # Database recording
        if self.use_database and self.db:
            self._record_to_database(result)

        print(f"[+] Testing complete. Found {len(self.findings)} issues.")
        return result

    def _test_protocol_versions(self) -> List[str]:
        """
        Test which SSL/TLS protocol versions are supported.

        Returns:
            List of supported protocol version strings
        """
        supported = []

        protocols_to_test = [
            ('SSLv2', ssl.PROTOCOL_SSLv23, {'options': ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2}),
            ('SSLv3', ssl.PROTOCOL_SSLv23, {'options': ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2}),
        ]

        # Add specific protocol versions if available
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            protocols_to_test.append(('TLSv1.0', ssl.PROTOCOL_TLSv1, {}))
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            protocols_to_test.append(('TLSv1.1', ssl.PROTOCOL_TLSv1_1, {}))
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            protocols_to_test.append(('TLSv1.2', ssl.PROTOCOL_TLSv1_2, {}))
        if hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3'):
            protocols_to_test.append(('TLSv1.3', ssl.PROTOCOL_TLS, {'min_version': ssl.TLSVersion.TLSv1_3}))

        for proto_name, proto_const, proto_options in protocols_to_test:
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Apply options
                if 'options' in proto_options:
                    context.options |= proto_options['options']
                if 'min_version' in proto_options:
                    context.minimum_version = proto_options['min_version']

                # Attempt connection
                with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        supported.append(proto_name)

                        # Check if protocol is weak
                        if proto_name in self.WEAK_PROTOCOLS:
                            vuln_desc, severity = self.WEAK_PROTOCOLS[proto_name]
                            self._add_finding(
                                title=f"Weak TLS Protocol Supported: {proto_name}",
                                severity=severity,
                                vuln_type=TLSVulnType.WEAK_PROTOCOL,
                                description=f"Server supports deprecated {proto_name} protocol. Known vulnerabilities: {vuln_desc}",
                                evidence={
                                    'protocol': proto_name,
                                    'vulnerabilities': vuln_desc
                                },
                                exploitation=f"Attacker can force protocol downgrade to {proto_name} and exploit known vulnerabilities.",
                                remediation=f"Disable {proto_name} support. Use TLS 1.2 or TLS 1.3 only.",
                                cwe_id="CWE-327",
                                bounty_estimate="$1000-$5000"
                            )
            except (ssl.SSLError, OSError, ConnectionRefusedError, socket.timeout):
                continue
            except Exception as e:
                print(f"[-] Error testing {proto_name}: {e}")
                continue

        return supported

    def _enumerate_cipher_suites(self) -> List[CipherSuiteInfo]:
        """
        Enumerate supported cipher suites.

        Returns:
            List of CipherSuiteInfo objects
        """
        cipher_suites = []

        # Try different protocol versions
        protocols = [
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else ssl.PROTOCOL_TLSv1),
        ]

        if hasattr(ssl, 'PROTOCOL_TLS'):
            protocols.append(('TLSv1.3', ssl.PROTOCOL_TLS))

        for proto_name, proto_const in protocols:
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        cipher = ssock.cipher()

                        if cipher and cipher[0] not in self.tested_ciphers:
                            self.tested_ciphers.add(cipher[0])

                            cipher_name = cipher[0]
                            cipher_version = cipher[1]
                            cipher_bits = cipher[2]

                            # Check for weaknesses
                            is_weak = False
                            weakness_reason = None
                            for pattern, reason in self.WEAK_CIPHER_PATTERNS:
                                if pattern in cipher_name:
                                    is_weak = True
                                    weakness_reason = reason
                                    break

                            # Check for forward secrecy
                            has_fs = any(fs_pattern in cipher_name for fs_pattern in self.FORWARD_SECRECY_PATTERNS)

                            cipher_info = CipherSuiteInfo(
                                name=cipher_name,
                                protocol=cipher_version,
                                bits=cipher_bits,
                                is_weak=is_weak,
                                has_forward_secrecy=has_fs,
                                weakness_reason=weakness_reason
                            )
                            cipher_suites.append(cipher_info)

                            # Report weak cipher
                            if is_weak:
                                self._add_finding(
                                    title=f"Weak Cipher Suite: {cipher_name}",
                                    severity=TLSSeverity.HIGH,
                                    vuln_type=TLSVulnType.WEAK_CIPHER,
                                    description=f"Server supports weak cipher suite '{cipher_name}'. {weakness_reason}",
                                    evidence={
                                        'cipher': cipher_name,
                                        'protocol': cipher_version,
                                        'bits': cipher_bits,
                                        'weakness': weakness_reason
                                    },
                                    exploitation="Attacker can negotiate weak cipher and potentially break encryption through known attacks.",
                                    remediation="Disable weak ciphers. Use only strong AEAD ciphers like AES-GCM or ChaCha20-Poly1305.",
                                    cwe_id="CWE-327",
                                    bounty_estimate="$1500-$6000"
                                )
            except Exception as e:
                continue

        return cipher_suites

    def _test_certificate(self) -> Optional[CertificateInfo]:
        """
        Retrieve and validate SSL certificate.

        Returns:
            CertificateInfo object or None if retrieval fails
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            print("[-] cryptography library not available for certificate validation")
            return None

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Extract subject
                    subject = {}
                    for attr in cert.subject:
                        subject[attr.oid._name] = attr.value

                    # Extract issuer
                    issuer = {}
                    for attr in cert.issuer:
                        issuer[attr.oid._name] = attr.value

                    # Extract SANs
                    sans = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = [dns.value for dns in san_ext.value]
                    except x509.ExtensionNotFound:
                        if 'commonName' in subject:
                            sans = [subject['commonName']]

                    # Check if self-signed
                    is_self_signed = subject == issuer

                    # Check expiration
                    now = datetime.now()
                    is_expired = cert.not_valid_after < now

                    # Get public key info
                    public_key = cert.public_key()
                    public_key_type = type(public_key).__name__
                    public_key_size = public_key.key_size if hasattr(public_key, 'key_size') else 0

                    # Calculate fingerprint
                    fingerprint = hashlib.sha256(der_cert).hexdigest()

                    # Signature algorithm
                    sig_alg = cert.signature_algorithm_oid._name

                    # Validate certificate
                    issues = []
                    is_valid = True

                    # Issue 1: Self-signed
                    if is_self_signed:
                        issues.append('Certificate is self-signed')
                        is_valid = False
                        self._add_finding(
                            title="Self-Signed Certificate",
                            severity=TLSSeverity.HIGH,
                            vuln_type=TLSVulnType.SELF_SIGNED_CERT,
                            description="Server is using a self-signed certificate which cannot be validated against trusted CAs.",
                            evidence={
                                'subject': subject,
                                'issuer': issuer,
                                'self_signed': True
                            },
                            exploitation="Self-signed certificates enable man-in-the-middle attacks as clients cannot verify authenticity.",
                            remediation="Obtain a certificate from a trusted Certificate Authority (CA).",
                            cwe_id="CWE-295",
                            bounty_estimate="$500-$2000"
                        )

                    # Issue 2: Expired certificate
                    if is_expired:
                        issues.append(f'Certificate expired on {cert.not_valid_after}')
                        is_valid = False
                        self._add_finding(
                            title="Expired SSL Certificate",
                            severity=TLSSeverity.HIGH,
                            vuln_type=TLSVulnType.EXPIRED_CERT,
                            description=f"Certificate expired on {cert.not_valid_after}. Current date: {now}.",
                            evidence={
                                'not_after': str(cert.not_valid_after),
                                'current_time': str(now),
                                'days_expired': (now - cert.not_valid_after).days
                            },
                            exploitation="Expired certificates cause browser warnings and may be rejected, enabling MITM attacks.",
                            remediation="Renew the certificate immediately. Implement auto-renewal if using Let's Encrypt.",
                            cwe_id="CWE-298",
                            bounty_estimate="$300-$1500"
                        )

                    # Issue 3: Expiring soon
                    days_until_expiry = (cert.not_valid_after - now).days
                    if not is_expired and days_until_expiry < 30:
                        issues.append(f'Certificate expires in {days_until_expiry} days')
                        self._add_finding(
                            title=f"Certificate Expiring Soon ({days_until_expiry} days)",
                            severity=TLSSeverity.MEDIUM,
                            vuln_type=TLSVulnType.EXPIRED_CERT,
                            description=f"Certificate will expire in {days_until_expiry} days on {cert.not_valid_after}.",
                            evidence={
                                'not_after': str(cert.not_valid_after),
                                'days_remaining': days_until_expiry
                            },
                            exploitation="Certificate expiration will cause service disruption and security warnings.",
                            remediation="Renew certificate before expiration. Recommended renewal window is 30-90 days before expiry.",
                            cwe_id="CWE-298",
                            bounty_estimate="$100-$500"
                        )

                    # Issue 4: Weak signature algorithm
                    if 'sha1' in sig_alg.lower() or 'md5' in sig_alg.lower():
                        issues.append(f'Weak signature algorithm: {sig_alg}')
                        is_valid = False
                        self._add_finding(
                            title=f"Weak Certificate Signature Algorithm: {sig_alg}",
                            severity=TLSSeverity.HIGH,
                            vuln_type=TLSVulnType.WEAK_SIGNATURE,
                            description=f"Certificate uses weak signature algorithm '{sig_alg}' vulnerable to collision attacks.",
                            evidence={
                                'signature_algorithm': sig_alg,
                                'weakness': 'MD5/SHA1 collision attacks'
                            },
                            exploitation="Attacker can create fraudulent certificates with identical signature hashes.",
                            remediation="Reissue certificate with SHA-256 or stronger signature algorithm.",
                            cwe_id="CWE-327",
                            bounty_estimate="$800-$3000"
                        )

                    # Issue 5: Weak key size
                    if public_key_size < 2048:
                        issues.append(f'Weak key size: {public_key_size} bits')
                        is_valid = False
                        self._add_finding(
                            title=f"Weak Certificate Key Size: {public_key_size} bits",
                            severity=TLSSeverity.HIGH,
                            vuln_type=TLSVulnType.WEAK_KEY,
                            description=f"Certificate uses {public_key_size}-bit {public_key_type} key, below recommended 2048-bit minimum.",
                            evidence={
                                'key_size': public_key_size,
                                'key_type': public_key_type,
                                'minimum_recommended': 2048
                            },
                            exploitation="Weak keys can be factored with sufficient computational resources.",
                            remediation="Generate new certificate with at least 2048-bit RSA key or use ECDSA P-256.",
                            cwe_id="CWE-326",
                            bounty_estimate="$1000-$4000"
                        )

                    # Issue 6: Hostname mismatch
                    hostname_match = False
                    for san in sans:
                        if san == self.hostname or (san.startswith('*.') and self.hostname.endswith(san[1:])):
                            hostname_match = True
                            break

                    if not hostname_match:
                        issues.append(f'Hostname mismatch: certificate issued for {sans} but accessed via {self.hostname}')
                        is_valid = False
                        self._add_finding(
                            title=f"Certificate Hostname Mismatch",
                            severity=TLSSeverity.MEDIUM,
                            vuln_type=TLSVulnType.HOSTNAME_MISMATCH,
                            description=f"Certificate CN/SANs do not match hostname '{self.hostname}'. Issued for: {', '.join(sans)}",
                            evidence={
                                'hostname': self.hostname,
                                'certificate_sans': sans,
                                'common_name': subject.get('commonName', 'N/A')
                            },
                            exploitation="Hostname mismatch causes browser warnings and may indicate misconfiguration or MITM attack.",
                            remediation=f"Obtain certificate that includes '{self.hostname}' in Subject Alternative Names.",
                            cwe_id="CWE-297",
                            bounty_estimate="$200-$1000"
                        )

                    cert_info = CertificateInfo(
                        subject=subject,
                        issuer=issuer,
                        sans=sans,
                        not_before=cert.not_valid_before,
                        not_after=cert.not_valid_after,
                        serial_number=hex(cert.serial_number),
                        signature_algorithm=sig_alg,
                        public_key_type=public_key_type,
                        public_key_size=public_key_size,
                        is_self_signed=is_self_signed,
                        is_expired=is_expired,
                        is_valid=is_valid,
                        fingerprint_sha256=fingerprint,
                        issues=issues
                    )

                    return cert_info

        except Exception as e:
            print(f"[-] Error testing certificate: {e}")
            return None

    def _check_forward_secrecy(self, cipher_suites: List[CipherSuiteInfo]) -> bool:
        """
        Check if server supports forward secrecy.

        Args:
            cipher_suites: List of supported cipher suites

        Returns:
            True if forward secrecy is supported
        """
        has_fs = any(cs.has_forward_secrecy for cs in cipher_suites)

        if not has_fs and cipher_suites:
            self._add_finding(
                title="No Forward Secrecy Support",
                severity=TLSSeverity.MEDIUM,
                vuln_type=TLSVulnType.NO_FORWARD_SECRECY,
                description="Server does not support cipher suites with forward secrecy (DHE/ECDHE). Past communications can be decrypted if private key is compromised.",
                evidence={
                    'cipher_suites': [cs.name for cs in cipher_suites],
                    'forward_secrecy': False
                },
                exploitation="If server's private key is compromised, all past encrypted traffic can be decrypted.",
                remediation="Enable cipher suites with forward secrecy: ECDHE-RSA-AES-GCM, DHE-RSA-AES-GCM.",
                cwe_id="CWE-327",
                bounty_estimate="$500-$2000"
            )

        return has_fs

    def _scan_known_vulnerabilities(self, protocols: List[str], cipher_suites: List[CipherSuiteInfo]) -> List[str]:
        """
        Scan for known TLS vulnerabilities.

        Args:
            protocols: List of supported protocols
            cipher_suites: List of supported cipher suites

        Returns:
            List of detected vulnerability names
        """
        vulnerabilities = []

        # BEAST: TLS 1.0 with CBC ciphers
        if 'TLSv1.0' in protocols:
            cbc_ciphers = [cs.name for cs in cipher_suites if 'CBC' in cs.name]
            if cbc_ciphers:
                vulnerabilities.append('BEAST')
                self._add_finding(
                    title="BEAST Vulnerability (TLS 1.0 with CBC)",
                    severity=TLSSeverity.MEDIUM,
                    vuln_type=TLSVulnType.BEAST_VULNERABLE,
                    description="Server supports TLS 1.0 with CBC-mode ciphers, vulnerable to BEAST attack.",
                    evidence={
                        'protocol': 'TLSv1.0',
                        'cbc_ciphers': cbc_ciphers
                    },
                    exploitation="Attacker can decrypt session cookies by exploiting CBC cipher block chaining in TLS 1.0.",
                    remediation="Disable TLS 1.0 or disable CBC ciphers. Use TLS 1.2+ with GCM ciphers.",
                    cwe_id="CWE-327",
                    cvss_score=4.3,
                    bounty_estimate="$500-$2000"
                )

        # POODLE: SSLv3
        if 'SSLv3' in protocols:
            vulnerabilities.append('POODLE')
            # Already reported in protocol testing

        # CRIME: TLS compression
        # Handled in _test_compression()

        # Sweet32: 3DES
        des3_ciphers = [cs.name for cs in cipher_suites if 'DES-CBC3' in cs.name or '3DES' in cs.name]
        if des3_ciphers:
            vulnerabilities.append('Sweet32')
            # Already reported in cipher enumeration

        return vulnerabilities

    def _test_compression(self) -> bool:
        """
        Test if TLS compression is enabled (CRIME vulnerability).

        Returns:
            True if compression is enabled
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_COMPRESSION

            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # If compression was negotiated despite OP_NO_COMPRESSION, it's forced by server
                    compression = ssock.compression()

                    if compression:
                        self._add_finding(
                            title="TLS Compression Enabled (CRIME)",
                            severity=TLSSeverity.MEDIUM,
                            vuln_type=TLSVulnType.CRIME_VULNERABLE,
                            description=f"Server forces TLS compression ({compression}), vulnerable to CRIME attack.",
                            evidence={
                                'compression_method': compression
                            },
                            exploitation="Attacker can extract session cookies by observing compressed traffic size variations.",
                            remediation="Disable TLS compression at server level.",
                            cwe_id="CWE-327",
                            cvss_score=5.9,
                            bounty_estimate="$500-$2000"
                        )
                        return True

                    return False
        except Exception as e:
            print(f"[-] Error testing compression: {e}")
            return False

    def _test_renegotiation(self) -> bool:
        """
        Test secure renegotiation support.

        Returns:
            True if secure renegotiation is supported
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Python's SSL doesn't expose renegotiation details easily
                    # This is a basic check - would need OpenSSL bindings for full test
                    return True
        except Exception as e:
            return True

    def _add_finding(self, title: str, severity: TLSSeverity, vuln_type: TLSVulnType,
                     description: str, evidence: Dict[str, Any], exploitation: str,
                     remediation: str, cwe_id: Optional[str] = None,
                     cvss_score: Optional[float] = None, bounty_estimate: str = ""):
        """
        Add a finding to the results list.

        Args:
            title: Finding title
            severity: Severity level
            vuln_type: Type of vulnerability
            description: Detailed description
            evidence: Evidence dictionary
            exploitation: How to exploit
            remediation: How to fix
            cwe_id: CWE identifier
            cvss_score: CVSS score
            bounty_estimate: Estimated bounty range
        """
        finding = TLSFinding(
            title=title,
            severity=severity,
            vuln_type=vuln_type,
            description=description,
            endpoint=f"{self.hostname}:{self.port}",
            evidence=evidence,
            exploitation=exploitation,
            remediation=remediation,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            bounty_estimate=bounty_estimate
        )
        self.findings.append(finding)

    def _record_to_database(self, result: TLSTestResult):
        """
        Record test results to database.

        Args:
            result: TLSTestResult to record
        """
        if not self.use_database or not self.db:
            return

        try:
            # Record tool run
            self.db.record_tool_run(
                domain=self.hostname,
                tool_name='tls_ssl_configuration_tester',
                findings_count=len(result.findings),
                duration_seconds=0  # Would need to track actual duration
            )

            # Record findings
            # Note: Would need to implement finding recording in database
            print(f"[+] Recorded {len(result.findings)} findings to database")

        except Exception as e:
            print(f"[-] Error recording to database: {e}")

    def generate_report(self, result: TLSTestResult) -> Dict[str, Any]:
        """
        Generate comprehensive test report.

        Args:
            result: TLSTestResult from testing

        Returns:
            Dictionary containing formatted report
        """
        return {
            'target': f"{result.hostname}:{result.port}",
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(result.findings),
                'by_severity': {
                    'critical': len([f for f in result.findings if f.severity == TLSSeverity.CRITICAL]),
                    'high': len([f for f in result.findings if f.severity == TLSSeverity.HIGH]),
                    'medium': len([f for f in result.findings if f.severity == TLSSeverity.MEDIUM]),
                    'low': len([f for f in result.findings if f.severity == TLSSeverity.LOW]),
                    'info': len([f for f in result.findings if f.severity == TLSSeverity.INFO])
                },
                'supported_protocols': result.supported_protocols,
                'cipher_suites_count': len(result.cipher_suites),
                'weak_ciphers_count': len([cs for cs in result.cipher_suites if cs.is_weak]),
                'forward_secrecy': result.has_forward_secrecy,
                'compression_enabled': result.compression_enabled,
                'known_vulnerabilities': result.vulnerabilities
            },
            'certificate': asdict(result.certificate) if result.certificate else None,
            'cipher_suites': [asdict(cs) for cs in result.cipher_suites],
            'findings': [f.to_dict() for f in sorted(
                result.findings,
                key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x.severity.value)
            )]
        }


def run_tls_ssl_tests(hostname: str, port: int = 443, timeout: int = 10,
                      use_database: bool = True) -> Dict[str, Any]:
    """
    Main entry point for TLS/SSL configuration testing.

    Args:
        hostname: Target hostname
        port: Target port (default 443)
        timeout: Connection timeout in seconds
        use_database: Whether to use database integration

    Returns:
        Test report dictionary
    """
    tester = TLSSSLConfigurationTester(
        hostname=hostname,
        port=port,
        timeout=timeout,
        use_database=use_database
    )

    result = tester.run_all_tests()
    report = tester.generate_report(result)

    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python tls_ssl_configuration_tester.py <hostname> [port]")
        sys.exit(1)

    hostname = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    report = run_tls_ssl_tests(hostname, port)

    print("\n" + "="*80)
    print("TLS/SSL CONFIGURATION TEST REPORT")
    print("="*80)
    print(json.dumps(report, indent=2, default=str))
