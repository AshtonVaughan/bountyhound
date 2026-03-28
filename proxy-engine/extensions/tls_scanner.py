"""TLS Scanner — test protocol versions, weak ciphers, certificate validity, and hostname matching."""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.tls-scanner")

NAME = "tls-scanner"
DESCRIPTION = "Test TLS protocol versions, weak ciphers, certificate expiry, self-signed, hostname mismatch"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10.0,
}

# Weak cipher suites to flag
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "RC2", "IDEA", "SEED",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Run TLS security checks against the target."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    timeout = _config.get("timeout", 10.0)

    if not hostname:
        return findings

    # Only test HTTPS targets
    if parsed.scheme != "https" and port != 443:
        return findings

    # Test deprecated protocol versions
    findings.extend(_test_protocol_versions(hostname, port, timeout))

    # Test certificate
    findings.extend(_test_certificate(hostname, port, timeout))

    # Test for weak ciphers
    findings.extend(_test_weak_ciphers(hostname, port, timeout))

    return findings


def _test_protocol_versions(
    hostname: str, port: int, timeout: float
) -> list[ScanFinding]:
    """Test for deprecated TLS/SSL protocol support."""
    findings: list[ScanFinding] = []

    deprecated_protocols = [
        ("SSLv3", ssl.PROTOCOL_TLS_CLIENT, "SSLv3"),
        ("TLS 1.0", ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
        ("TLS 1.1", ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1"),
    ]

    for proto_name, proto_const, version_str in deprecated_protocols:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Try to set maximum version to the deprecated protocol
            if version_str == "SSLv3":
                ctx.maximum_version = ssl.TLSVersion.SSLv3
                ctx.minimum_version = ssl.TLSVersion.SSLv3
            elif version_str == "TLSv1":
                ctx.maximum_version = ssl.TLSVersion.TLSv1
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            elif version_str == "TLSv1.1":
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    actual_version = ssock.version()
                    findings.append(ScanFinding(
                        template_id=f"tls_deprecated_{version_str.lower().replace('.', '')}",
                        name=f"TLS: Deprecated Protocol {proto_name} Supported",
                        severity="high" if "SSL" in proto_name else "medium",
                        url=f"https://{hostname}:{port}",
                        matched_at=f"https://{hostname}:{port}",
                        description=(
                            f"Server supports deprecated protocol {proto_name} ({actual_version}). "
                            "Deprecated protocols have known vulnerabilities (POODLE, BEAST, etc.)."
                        ),
                        extracted=[
                            f"Protocol: {proto_name}",
                            f"Negotiated: {actual_version}",
                        ],
                        source="extension",
                        confidence="confirmed",
                        remediation=f"Disable {proto_name} support. Require TLS 1.2 or higher.",
                    ))

        except (ssl.SSLError, socket.error, OSError, ValueError):
            # Protocol not supported — good
            pass
        except Exception as e:
            log.debug(f"Protocol test error ({proto_name}): {e}")

    # Check if TLS 1.2 and 1.3 are supported
    for version_name, min_ver, max_ver in [
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    pass  # Supported
        except (ssl.SSLError, socket.error, OSError, ValueError):
            if version_name == "TLS 1.3":
                findings.append(ScanFinding(
                    template_id="tls_no_13",
                    name="TLS: TLS 1.3 Not Supported",
                    severity="info",
                    url=f"https://{hostname}:{port}",
                    matched_at=f"https://{hostname}:{port}",
                    description="Server does not support TLS 1.3. Consider enabling for improved security and performance.",
                    extracted=[f"Host: {hostname}:{port}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Enable TLS 1.3 support on the server.",
                ))
        except Exception:
            pass

    return findings


def _test_certificate(hostname: str, port: int, timeout: float) -> list[ScanFinding]:
    """Test certificate validity, expiry, and hostname matching."""
    findings: list[ScanFinding] = []

    try:
        # First, get cert without verification
        ctx_noverify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx_noverify.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()

        if not cert:
            findings.append(ScanFinding(
                template_id="tls_no_cert",
                name="TLS: No Certificate Presented",
                severity="high",
                url=f"https://{hostname}:{port}",
                matched_at=f"https://{hostname}:{port}",
                description="Server did not present a certificate during TLS handshake.",
                extracted=[],
                source="extension",
                confidence="confirmed",
                remediation="Configure the server to present a valid TLS certificate.",
            ))
            return findings

        # Check expiry
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")

        if not_after:
            try:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (expiry - now).days

                if days_left < 0:
                    findings.append(ScanFinding(
                        template_id="tls_cert_expired",
                        name="TLS: Certificate Expired",
                        severity="high",
                        url=f"https://{hostname}:{port}",
                        matched_at=f"https://{hostname}:{port}",
                        description=(
                            f"Certificate expired {abs(days_left)} days ago "
                            f"(expiry: {not_after})."
                        ),
                        extracted=[f"Expiry: {not_after}", f"Days expired: {abs(days_left)}"],
                        source="extension",
                        confidence="confirmed",
                        remediation="Renew the TLS certificate immediately.",
                    ))
                elif days_left < 30:
                    findings.append(ScanFinding(
                        template_id="tls_cert_expiring_soon",
                        name="TLS: Certificate Expiring Soon",
                        severity="low",
                        url=f"https://{hostname}:{port}",
                        matched_at=f"https://{hostname}:{port}",
                        description=f"Certificate expires in {days_left} days ({not_after}).",
                        extracted=[f"Expiry: {not_after}", f"Days remaining: {days_left}"],
                        source="extension",
                        confidence="confirmed",
                        remediation="Renew the certificate before expiry.",
                    ))
            except (ValueError, TypeError) as e:
                log.debug(f"Date parse error: {e}")

        # Check hostname match
        try:
            ctx_verify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_verify.check_hostname = True
            ctx_verify.verify_mode = ssl.CERT_REQUIRED
            ctx_verify.load_default_certs()

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx_verify.wrap_socket(sock, server_hostname=hostname):
                    pass
        except ssl.CertificateError as e:
            findings.append(ScanFinding(
                template_id="tls_hostname_mismatch",
                name="TLS: Certificate Hostname Mismatch",
                severity="high",
                url=f"https://{hostname}:{port}",
                matched_at=f"https://{hostname}:{port}",
                description=f"Certificate hostname does not match '{hostname}': {e}",
                extracted=[
                    f"Hostname: {hostname}",
                    f"Error: {str(e)[:200]}",
                    f"Subject: {cert.get('subject', '')}",
                ],
                source="extension",
                confidence="confirmed",
                remediation="Ensure certificate covers the correct hostnames (SAN/CN).",
            ))
        except ssl.SSLCertVerificationError as e:
            error_msg = str(e).lower()
            if "self signed" in error_msg or "self-signed" in error_msg:
                findings.append(ScanFinding(
                    template_id="tls_self_signed",
                    name="TLS: Self-Signed Certificate",
                    severity="medium",
                    url=f"https://{hostname}:{port}",
                    matched_at=f"https://{hostname}:{port}",
                    description=(
                        "Server uses a self-signed certificate that is not trusted by default CA stores."
                    ),
                    extracted=[
                        f"Issuer: {cert.get('issuer', '')}",
                        f"Subject: {cert.get('subject', '')}",
                    ],
                    source="extension",
                    confidence="confirmed",
                    remediation="Use a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
                ))
            else:
                findings.append(ScanFinding(
                    template_id="tls_cert_untrusted",
                    name="TLS: Certificate Verification Failed",
                    severity="medium",
                    url=f"https://{hostname}:{port}",
                    matched_at=f"https://{hostname}:{port}",
                    description=f"Certificate verification failed: {e}",
                    extracted=[str(e)[:200]],
                    source="extension",
                    confidence="confirmed",
                    remediation="Use a certificate signed by a trusted CA with a valid chain.",
                ))
        except (socket.error, OSError):
            pass

    except Exception as e:
        log.debug(f"Certificate test error: {e}")

    return findings


def _test_weak_ciphers(hostname: str, port: int, timeout: float) -> list[ScanFinding]:
    """Test for weak cipher suite support."""
    findings: list[ScanFinding] = []

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name, protocol, bits = cipher

                    # Check for weak ciphers
                    is_weak = any(wc.lower() in cipher_name.lower() for wc in WEAK_CIPHERS)

                    if is_weak:
                        findings.append(ScanFinding(
                            template_id="tls_weak_cipher",
                            name=f"TLS: Weak Cipher Negotiated",
                            severity="medium",
                            url=f"https://{hostname}:{port}",
                            matched_at=f"https://{hostname}:{port}",
                            description=(
                                f"Server negotiated a weak cipher suite: {cipher_name} "
                                f"({bits} bits, {protocol})."
                            ),
                            extracted=[
                                f"Cipher: {cipher_name}",
                                f"Protocol: {protocol}",
                                f"Bits: {bits}",
                            ],
                            source="extension",
                            confidence="confirmed",
                            remediation="Disable weak cipher suites. Use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                        ))

                    if bits and bits < 128:
                        findings.append(ScanFinding(
                            template_id="tls_short_key",
                            name="TLS: Short Cipher Key Length",
                            severity="high",
                            url=f"https://{hostname}:{port}",
                            matched_at=f"https://{hostname}:{port}",
                            description=(
                                f"Negotiated cipher uses only {bits}-bit key: {cipher_name}. "
                                "Keys shorter than 128 bits are considered insecure."
                            ),
                            extracted=[f"Cipher: {cipher_name}", f"Bits: {bits}"],
                            source="extension",
                            confidence="confirmed",
                            remediation="Require minimum 128-bit cipher key length. Prefer 256-bit.",
                        ))

    except Exception as e:
        log.debug(f"Weak cipher test error: {e}")

    return findings
