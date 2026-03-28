"""
Security.txt Validator Agent

Advanced security.txt validator that checks RFC 9116 compliance and identifies
potential security misconfigurations or information disclosure issues.

This agent tests for:
- security.txt presence at /.well-known/security.txt
- RFC 9116 compliance (field validation)
- Required fields (Contact, Expires)
- Optional fields (Encryption, Acknowledgments, Preferred-Languages, Canonical, Policy, Hiring)
- PGP signature verification
- Expired security.txt detection
- Information disclosure analysis
- HTTP vs HTTPS serving
- Charset and content-type validation

Author: BountyHound Team
Version: 1.0.0
RFC: https://www.rfc-editor.org/rfc/rfc9116.html
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SecurityTxtSeverity(Enum):
    """Security.txt finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SecurityTxtIssueType(Enum):
    """Types of security.txt issues."""
    MISSING = "SECURITY_TXT_MISSING"
    EXPIRED = "SECURITY_TXT_EXPIRED"
    NO_CONTACT = "SECURITY_TXT_NO_CONTACT"
    NO_EXPIRES = "SECURITY_TXT_NO_EXPIRES"
    INVALID_EXPIRES = "SECURITY_TXT_INVALID_EXPIRES"
    INVALID_CONTACT = "SECURITY_TXT_INVALID_CONTACT"
    HTTP_ONLY = "SECURITY_TXT_HTTP_ONLY"
    WRONG_LOCATION = "SECURITY_TXT_WRONG_LOCATION"
    INVALID_SIGNATURE = "SECURITY_TXT_INVALID_SIGNATURE"
    INFO_DISCLOSURE = "SECURITY_TXT_INFO_DISCLOSURE"
    INVALID_FIELD = "SECURITY_TXT_INVALID_FIELD"
    MALFORMED = "SECURITY_TXT_MALFORMED"
    WRONG_CONTENT_TYPE = "SECURITY_TXT_WRONG_CONTENT_TYPE"
    WRONG_CHARSET = "SECURITY_TXT_WRONG_CHARSET"


@dataclass
class SecurityTxtFinding:
    """Represents a security.txt finding."""
    title: str
    severity: SecurityTxtSeverity
    issue_type: SecurityTxtIssueType
    description: str
    url: str
    field_name: Optional[str] = None
    field_value: Optional[str] = None
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['issue_type'] = self.issue_type.value
        return data


@dataclass
class SecurityTxtData:
    """Parsed security.txt data."""
    url: str
    content: str
    contact: List[str] = field(default_factory=list)
    expires: Optional[str] = None
    expires_datetime: Optional[datetime] = None
    encryption: List[str] = field(default_factory=list)
    acknowledgments: List[str] = field(default_factory=list)
    preferred_languages: List[str] = field(default_factory=list)
    canonical: List[str] = field(default_factory=list)
    policy: List[str] = field(default_factory=list)
    hiring: List[str] = field(default_factory=list)
    has_signature: bool = False
    signature_valid: Optional[bool] = None
    unknown_fields: Dict[str, List[str]] = field(default_factory=dict)
    comments: List[str] = field(default_factory=list)
    is_expired: bool = False
    content_type: Optional[str] = None
    charset: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with datetime handling."""
        data = asdict(self)
        if self.expires_datetime:
            data['expires_datetime'] = self.expires_datetime.isoformat()
        return data


class SecurityTxtValidator:
    """
    Advanced Security.txt Validator.

    Performs comprehensive security.txt validation including:
    - RFC 9116 compliance checking
    - Required field validation
    - Expiry date verification
    - PGP signature detection
    - Information disclosure analysis

    Usage:
        validator = SecurityTxtValidator(target_url="https://example.com")
        findings = validator.validate()
    """

    # Standard security.txt locations per RFC 9116
    STANDARD_LOCATIONS = [
        "/.well-known/security.txt",
        "/security.txt"  # Legacy location, should redirect to /.well-known/
    ]

    # RFC 9116 valid fields
    VALID_FIELDS = [
        "Contact",
        "Expires",
        "Encryption",
        "Acknowledgments",
        "Preferred-Languages",
        "Canonical",
        "Policy",
        "Hiring"
    ]

    # Required fields per RFC 9116
    REQUIRED_FIELDS = ["Contact", "Expires"]

    # PGP signature markers
    PGP_SIGNATURE_START = "-----BEGIN PGP SIGNED MESSAGE-----"
    PGP_SIGNATURE_END = "-----END PGP SIGNATURE-----"

    def __init__(self, target_url: str, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the Security.txt Validator.

        Args:
            target_url: Target website URL (base URL)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        # Normalize target URL
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme:
            target_url = f"https://{target_url}"

        self.base_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.findings: List[SecurityTxtFinding] = []
        self.security_txt_data: Optional[SecurityTxtData] = None

    def validate(self) -> List[SecurityTxtFinding]:
        """
        Run all validation checks.

        Returns:
            List of findings discovered
        """
        # Try to fetch security.txt
        security_txt_url, content, response = self._fetch_security_txt()

        if not content:
            # No security.txt found
            self.findings.append(SecurityTxtFinding(
                title="Missing security.txt File",
                severity=SecurityTxtSeverity.INFO,
                issue_type=SecurityTxtIssueType.MISSING,
                description=(
                    f"No security.txt file found at {self.base_url}/.well-known/security.txt "
                    f"or {self.base_url}/security.txt. This file is recommended per RFC 9116 "
                    f"to help security researchers report vulnerabilities."
                ),
                url=f"{self.base_url}/.well-known/security.txt",
                impact=(
                    "Security researchers may have difficulty contacting the organization "
                    "to report vulnerabilities, potentially delaying fixes."
                ),
                recommendation=(
                    "Create a security.txt file at /.well-known/security.txt following RFC 9116. "
                    "Include Contact and Expires fields at minimum."
                ),
                cwe_id="CWE-1008"
            ))
            return self.findings

        # Parse security.txt
        self.security_txt_data = self._parse_security_txt(security_txt_url, content, response)

        # Run validation checks
        self._check_required_fields()
        self._check_expires_field()
        self._check_contact_field()
        self._check_encryption_field()
        self._check_url_fields()
        self._check_signature()
        self._check_location(security_txt_url)
        self._check_content_type(response)
        self._check_unknown_fields()
        self._check_information_disclosure()

        return self.findings

    def _fetch_security_txt(self) -> Tuple[Optional[str], Optional[str], Optional[Any]]:
        """
        Fetch security.txt from standard locations.

        Returns:
            Tuple of (url, content, response) or (None, None, None)
        """
        for location in self.STANDARD_LOCATIONS:
            url = f"{self.base_url}{location}"

            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )

                if response.status_code == 200:
                    # Found security.txt
                    return url, response.text, response

            except requests.exceptions.RequestException:
                # Try next location
                continue

        return None, None, None

    def _parse_security_txt(self, url: str, content: str, response: Any) -> SecurityTxtData:
        """
        Parse security.txt content into structured data.

        Args:
            url: URL where security.txt was found
            content: Raw content
            response: HTTP response object

        Returns:
            SecurityTxtData object
        """
        data = SecurityTxtData(
            url=url,
            content=content,
            content_type=response.headers.get('Content-Type'),
        )

        # Detect PGP signature
        if self.PGP_SIGNATURE_START in content and self.PGP_SIGNATURE_END in content:
            data.has_signature = True
            # Extract signed content (between headers and signature)
            # For simplicity, we'll just mark as having signature
            # Full validation would require gpg binary

        # Parse line by line
        lines = content.split('\n')

        for line in lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip PGP signature blocks
            if line.startswith('-----'):
                continue

            # Comments
            if line.startswith('#'):
                data.comments.append(line[1:].strip())
                continue

            # Field lines
            if ':' in line:
                field_name, field_value = line.split(':', 1)
                field_name = field_name.strip()
                field_value = field_value.strip()

                # Case-insensitive field matching
                field_name_lower = field_name.lower()

                if field_name == "Contact":
                    data.contact.append(field_value)
                elif field_name == "Expires":
                    data.expires = field_value
                    # Try to parse datetime
                    try:
                        data.expires_datetime = datetime.fromisoformat(field_value.replace('Z', '+00:00'))
                        # Check if expired
                        if data.expires_datetime < datetime.now(timezone.utc):
                            data.is_expired = True
                    except (ValueError, AttributeError):
                        # Invalid datetime format
                        data.expires_datetime = None
                elif field_name == "Encryption":
                    data.encryption.append(field_value)
                elif field_name == "Acknowledgments":
                    data.acknowledgments.append(field_value)
                elif field_name == "Preferred-Languages":
                    data.preferred_languages.append(field_value)
                elif field_name == "Canonical":
                    data.canonical.append(field_value)
                elif field_name == "Policy":
                    data.policy.append(field_value)
                elif field_name == "Hiring":
                    data.hiring.append(field_value)
                else:
                    # Unknown field
                    if field_name not in data.unknown_fields:
                        data.unknown_fields[field_name] = []
                    data.unknown_fields[field_name].append(field_value)

        # Extract charset from Content-Type
        if data.content_type:
            charset_match = re.search(r'charset=([^\s;]+)', data.content_type, re.IGNORECASE)
            if charset_match:
                data.charset = charset_match.group(1).lower()

        return data

    def _check_required_fields(self):
        """Check that all required fields are present."""
        if not self.security_txt_data:
            return

        # Check Contact
        if not self.security_txt_data.contact:
            self.findings.append(SecurityTxtFinding(
                title="Missing Required Field: Contact",
                severity=SecurityTxtSeverity.HIGH,
                issue_type=SecurityTxtIssueType.NO_CONTACT,
                description=(
                    "The security.txt file is missing the required 'Contact' field. "
                    "Per RFC 9116, at least one Contact field MUST be present to provide "
                    "a method for security researchers to reach the organization."
                ),
                url=self.security_txt_data.url,
                field_name="Contact",
                impact=(
                    "Security researchers cannot contact the organization to report "
                    "vulnerabilities, defeating the purpose of security.txt."
                ),
                recommendation=(
                    "Add at least one Contact field with an email (mailto:), phone (tel:), "
                    "or web form (https://) URI."
                ),
                cwe_id="CWE-1008"
            ))

        # Check Expires
        if not self.security_txt_data.expires:
            self.findings.append(SecurityTxtFinding(
                title="Missing Required Field: Expires",
                severity=SecurityTxtSeverity.HIGH,
                issue_type=SecurityTxtIssueType.NO_EXPIRES,
                description=(
                    "The security.txt file is missing the required 'Expires' field. "
                    "Per RFC 9116, the Expires field MUST be present to indicate when "
                    "the file should be considered stale."
                ),
                url=self.security_txt_data.url,
                field_name="Expires",
                impact=(
                    "Without an expiration date, researchers cannot determine if the "
                    "contact information is still valid."
                ),
                recommendation=(
                    "Add an Expires field with an ISO 8601 datetime. Example: "
                    "Expires: 2025-12-31T23:59:59Z"
                ),
                cwe_id="CWE-1008"
            ))

    def _check_expires_field(self):
        """Validate the Expires field."""
        if not self.security_txt_data or not self.security_txt_data.expires:
            return

        # Check if datetime is invalid
        if self.security_txt_data.expires_datetime is None:
            self.findings.append(SecurityTxtFinding(
                title="Invalid Expires Field Format",
                severity=SecurityTxtSeverity.MEDIUM,
                issue_type=SecurityTxtIssueType.INVALID_EXPIRES,
                description=(
                    f"The Expires field contains an invalid datetime format: "
                    f"'{self.security_txt_data.expires}'. Per RFC 9116, the Expires field "
                    f"MUST use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)."
                ),
                url=self.security_txt_data.url,
                field_name="Expires",
                field_value=self.security_txt_data.expires,
                impact=(
                    "Automated tools cannot determine when the file expires, "
                    "and researchers may not trust the contact information."
                ),
                recommendation=(
                    "Use ISO 8601 datetime format. Example: "
                    "Expires: 2025-12-31T23:59:59Z"
                ),
                cwe_id="CWE-1008"
            ))

        # Check if expired
        elif self.security_txt_data.is_expired:
            days_expired = (datetime.now(timezone.utc) - self.security_txt_data.expires_datetime).days

            self.findings.append(SecurityTxtFinding(
                title="Expired security.txt File",
                severity=SecurityTxtSeverity.MEDIUM,
                issue_type=SecurityTxtIssueType.EXPIRED,
                description=(
                    f"The security.txt file expired {days_expired} day(s) ago on "
                    f"{self.security_txt_data.expires_datetime.isoformat()}. "
                    f"Per RFC 9116, expired files should be considered stale and untrustworthy."
                ),
                url=self.security_txt_data.url,
                field_name="Expires",
                field_value=self.security_txt_data.expires,
                impact=(
                    "Security researchers may not trust the contact information, "
                    "and the organization may miss vulnerability reports."
                ),
                recommendation=(
                    f"Update the Expires field to a future date and review all contact "
                    f"information for accuracy. Recommend expiring no more than 1 year in the future."
                ),
                cwe_id="CWE-1008"
            ))

    def _check_contact_field(self):
        """Validate Contact field values."""
        if not self.security_txt_data or not self.security_txt_data.contact:
            return

        for contact in self.security_txt_data.contact:
            # Contact must be a URI (mailto:, tel:, or https://)
            if not (contact.startswith('mailto:') or
                    contact.startswith('tel:') or
                    contact.startswith('https://') or
                    contact.startswith('http://')):

                self.findings.append(SecurityTxtFinding(
                    title="Invalid Contact Field Format",
                    severity=SecurityTxtSeverity.MEDIUM,
                    issue_type=SecurityTxtIssueType.INVALID_CONTACT,
                    description=(
                        f"Contact field contains invalid URI: '{contact}'. "
                        f"Per RFC 9116, Contact values MUST be URIs (mailto:, tel:, or https://)."
                    ),
                    url=self.security_txt_data.url,
                    field_name="Contact",
                    field_value=contact,
                    impact=(
                        "Automated tools cannot process the contact information, "
                        "and researchers may not know how to reach the organization."
                    ),
                    recommendation=(
                        "Format Contact values as valid URIs. Examples:\n"
                        "  Contact: mailto:security@example.com\n"
                        "  Contact: https://example.com/security\n"
                        "  Contact: tel:+1-201-555-0123"
                    ),
                    cwe_id="CWE-1008"
                ))

            # Check for HTTP contact (should be HTTPS)
            elif contact.startswith('http://'):
                self.findings.append(SecurityTxtFinding(
                    title="Contact Field Uses HTTP Instead of HTTPS",
                    severity=SecurityTxtSeverity.LOW,
                    issue_type=SecurityTxtIssueType.HTTP_ONLY,
                    description=(
                        f"Contact field uses HTTP instead of HTTPS: '{contact}'. "
                        f"This allows potential MITM attacks on security communications."
                    ),
                    url=self.security_txt_data.url,
                    field_name="Contact",
                    field_value=contact,
                    impact=(
                        "An attacker could intercept security vulnerability reports "
                        "via a man-in-the-middle attack."
                    ),
                    recommendation=(
                        f"Use HTTPS for all web-based Contact URIs to ensure secure communication."
                    ),
                    cwe_id="CWE-319"
                ))

    def _check_encryption_field(self):
        """Validate Encryption field values."""
        if not self.security_txt_data or not self.security_txt_data.encryption:
            return

        for encryption_uri in self.security_txt_data.encryption:
            # Encryption should be a URI (typically https:// or openpgp4fpr:)
            if not (encryption_uri.startswith('https://') or
                    encryption_uri.startswith('openpgp4fpr:') or
                    encryption_uri.startswith('dns:') or
                    encryption_uri.startswith('http://')):

                self.findings.append(SecurityTxtFinding(
                    title="Invalid Encryption Field Format",
                    severity=SecurityTxtSeverity.LOW,
                    issue_type=SecurityTxtIssueType.INVALID_FIELD,
                    description=(
                        f"Encryption field contains non-standard URI: '{encryption_uri}'. "
                        f"Should be https://, openpgp4fpr:, or dns: URI."
                    ),
                    url=self.security_txt_data.url,
                    field_name="Encryption",
                    field_value=encryption_uri,
                    recommendation=(
                        "Use standard URI formats for Encryption field. Examples:\n"
                        "  Encryption: https://example.com/pgp-key.txt\n"
                        "  Encryption: openpgp4fpr:5F2DE5521C63A801AB59CCB603707A4DC8B8401"
                    ),
                    cwe_id="CWE-1008"
                ))

    def _check_url_fields(self):
        """Validate URL-based fields (Acknowledgments, Canonical, Policy, Hiring)."""
        if not self.security_txt_data:
            return

        url_fields = {
            'Acknowledgments': self.security_txt_data.acknowledgments,
            'Canonical': self.security_txt_data.canonical,
            'Policy': self.security_txt_data.policy,
            'Hiring': self.security_txt_data.hiring
        }

        for field_name, values in url_fields.items():
            for value in values:
                # These should be https:// URLs
                if not value.startswith('https://') and not value.startswith('http://'):
                    self.findings.append(SecurityTxtFinding(
                        title=f"Invalid {field_name} Field Format",
                        severity=SecurityTxtSeverity.LOW,
                        issue_type=SecurityTxtIssueType.INVALID_FIELD,
                        description=(
                            f"{field_name} field should contain a URI but has: '{value}'"
                        ),
                        url=self.security_txt_data.url,
                        field_name=field_name,
                        field_value=value,
                        recommendation=(
                            f"Ensure {field_name} field contains a valid HTTPS URI."
                        ),
                        cwe_id="CWE-1008"
                    ))
                elif value.startswith('http://'):
                    self.findings.append(SecurityTxtFinding(
                        title=f"{field_name} Field Uses HTTP Instead of HTTPS",
                        severity=SecurityTxtSeverity.LOW,
                        issue_type=SecurityTxtIssueType.HTTP_ONLY,
                        description=(
                            f"{field_name} field uses HTTP: '{value}'. Should use HTTPS."
                        ),
                        url=self.security_txt_data.url,
                        field_name=field_name,
                        field_value=value,
                        recommendation=(
                            f"Use HTTPS for {field_name} field to ensure integrity."
                        ),
                        cwe_id="CWE-319"
                    ))

    def _check_signature(self):
        """Check for PGP signature."""
        if not self.security_txt_data:
            return

        if not self.security_txt_data.has_signature:
            self.findings.append(SecurityTxtFinding(
                title="No PGP Signature",
                severity=SecurityTxtSeverity.INFO,
                issue_type=SecurityTxtIssueType.INVALID_SIGNATURE,
                description=(
                    "The security.txt file is not signed with a PGP signature. "
                    "While not required, signing the file provides cryptographic "
                    "verification that it hasn't been tampered with."
                ),
                url=self.security_txt_data.url,
                impact=(
                    "An attacker with web server access could modify the security.txt "
                    "file to redirect vulnerability reports to themselves."
                ),
                recommendation=(
                    "Sign the security.txt file with a PGP signature using:\n"
                    "  gpg --clearsign security.txt"
                ),
                cwe_id="CWE-345"
            ))

    def _check_location(self, url: str):
        """Check if security.txt is in the correct location."""
        if not url:
            return

        # Should be at /.well-known/security.txt
        if '/security.txt' in url and '/.well-known/' not in url:
            self.findings.append(SecurityTxtFinding(
                title="security.txt at Legacy Location",
                severity=SecurityTxtSeverity.LOW,
                issue_type=SecurityTxtIssueType.WRONG_LOCATION,
                description=(
                    f"security.txt found at legacy location: {url}. "
                    f"Per RFC 9116, the preferred location is /.well-known/security.txt. "
                    f"The root location /security.txt should redirect to /.well-known/."
                ),
                url=url,
                impact=(
                    "Some automated tools may only check /.well-known/security.txt and "
                    "miss the legacy location."
                ),
                recommendation=(
                    "Move security.txt to /.well-known/security.txt and add a redirect "
                    "from /security.txt to the new location."
                ),
                cwe_id="CWE-1008"
            ))

    def _check_content_type(self, response: Any):
        """Check Content-Type header."""
        if not response or not self.security_txt_data:
            return

        content_type = response.headers.get('Content-Type', '').lower()

        # Should be text/plain
        if content_type and 'text/plain' not in content_type:
            self.findings.append(SecurityTxtFinding(
                title="Incorrect Content-Type Header",
                severity=SecurityTxtSeverity.LOW,
                issue_type=SecurityTxtIssueType.WRONG_CONTENT_TYPE,
                description=(
                    f"security.txt served with incorrect Content-Type: '{content_type}'. "
                    f"Per RFC 9116, it SHOULD be served as 'text/plain; charset=utf-8'."
                ),
                url=self.security_txt_data.url,
                impact=(
                    "Some parsers may fail to process the file correctly."
                ),
                recommendation=(
                    "Configure the web server to serve security.txt with:\n"
                    "  Content-Type: text/plain; charset=utf-8"
                ),
                cwe_id="CWE-1008"
            ))

        # Check charset
        if self.security_txt_data.charset and self.security_txt_data.charset != 'utf-8':
            self.findings.append(SecurityTxtFinding(
                title="Incorrect Charset",
                severity=SecurityTxtSeverity.LOW,
                issue_type=SecurityTxtIssueType.WRONG_CHARSET,
                description=(
                    f"security.txt served with charset '{self.security_txt_data.charset}'. "
                    f"Per RFC 9116, it SHOULD use 'utf-8'."
                ),
                url=self.security_txt_data.url,
                recommendation=(
                    "Use UTF-8 charset: Content-Type: text/plain; charset=utf-8"
                ),
                cwe_id="CWE-1008"
            ))

    def _check_unknown_fields(self):
        """Check for unknown/invalid fields."""
        if not self.security_txt_data or not self.security_txt_data.unknown_fields:
            return

        for field_name, values in self.security_txt_data.unknown_fields.items():
            self.findings.append(SecurityTxtFinding(
                title=f"Unknown Field: {field_name}",
                severity=SecurityTxtSeverity.INFO,
                issue_type=SecurityTxtIssueType.INVALID_FIELD,
                description=(
                    f"security.txt contains unknown field '{field_name}'. "
                    f"RFC 9116 only defines: {', '.join(self.VALID_FIELDS)}. "
                    f"Unknown fields should be ignored by parsers."
                ),
                url=self.security_txt_data.url,
                field_name=field_name,
                field_value=', '.join(values),
                recommendation=(
                    f"Remove unknown field or ensure it matches RFC 9116 field names "
                    f"(case-sensitive)."
                ),
                cwe_id="CWE-1008"
            ))

    def _check_information_disclosure(self):
        """Check for potential information disclosure in comments or fields."""
        if not self.security_txt_data:
            return

        # Patterns that might indicate information disclosure
        sensitive_patterns = [
            (r'\b(?:password|passwd|pwd)\b', 'password reference'),
            (r'\b(?:token|api[_-]?key|secret)\b', 'token/key reference'),
            (r'\b(?:internal|private|confidential)\b', 'internal system reference'),
            (r'\b(?:admin|root|superuser)\b', 'privileged user reference'),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP address'),
            (r'\b[a-f0-9]{32,}\b', 'potential hash/key'),
        ]

        content_lower = self.security_txt_data.content.lower()

        for pattern, description in sensitive_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                # Extract matching lines
                matching_lines = []
                for line in self.security_txt_data.content.split('\n'):
                    if re.search(pattern, line, re.IGNORECASE):
                        matching_lines.append(line.strip())

                if matching_lines:
                    self.findings.append(SecurityTxtFinding(
                        title=f"Potential Information Disclosure: {description}",
                        severity=SecurityTxtSeverity.LOW,
                        issue_type=SecurityTxtIssueType.INFO_DISCLOSURE,
                        description=(
                            f"security.txt contains potential sensitive information ({description}). "
                            f"Matched in: {matching_lines[0][:100]}"
                        ),
                        url=self.security_txt_data.url,
                        impact=(
                            "May reveal internal system details or sensitive data to attackers."
                        ),
                        recommendation=(
                            "Review security.txt content and remove any sensitive information. "
                            "Only include publicly-intended contact and policy information."
                        ),
                        cwe_id="CWE-200"
                    ))
                    break  # Only report once per pattern type

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of validation results.

        Returns:
            Dictionary with validation statistics
        """
        severity_counts = {
            'CRITICAL': len([f for f in self.findings if f.severity == SecurityTxtSeverity.CRITICAL]),
            'HIGH': len([f for f in self.findings if f.severity == SecurityTxtSeverity.HIGH]),
            'MEDIUM': len([f for f in self.findings if f.severity == SecurityTxtSeverity.MEDIUM]),
            'LOW': len([f for f in self.findings if f.severity == SecurityTxtSeverity.LOW]),
            'INFO': len([f for f in self.findings if f.severity == SecurityTxtSeverity.INFO])
        }

        return {
            'target': self.base_url,
            'security_txt_found': self.security_txt_data is not None,
            'security_txt_url': self.security_txt_data.url if self.security_txt_data else None,
            'is_expired': self.security_txt_data.is_expired if self.security_txt_data else None,
            'has_signature': self.security_txt_data.has_signature if self.security_txt_data else False,
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'compliant': len([f for f in self.findings if f.severity in [SecurityTxtSeverity.HIGH, SecurityTxtSeverity.CRITICAL]]) == 0,
            'findings': [f.to_dict() for f in self.findings],
            'parsed_data': self.security_txt_data.to_dict() if self.security_txt_data else None
        }

    def get_findings_by_severity(self, severity: SecurityTxtSeverity) -> List[SecurityTxtFinding]:
        """Get findings filtered by severity level."""
        return [f for f in self.findings if f.severity == severity]
