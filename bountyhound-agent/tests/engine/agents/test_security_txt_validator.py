"""
Comprehensive tests for Security.txt Validator Agent.

Tests cover:
- Initialization and configuration
- security.txt presence detection
- RFC 9116 field validation
- Required fields (Contact, Expires)
- Optional fields validation
- Expires datetime parsing and expiry detection
- Contact URI format validation
- Encryption field validation
- PGP signature detection
- Location validation (/.well-known/ vs root)
- Content-Type and charset validation
- Unknown field detection
- Information disclosure analysis
- Edge cases and error handling
- Summary generation

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta

# Test imports with fallback
try:
    from engine.agents.security_txt_validator import (
        SecurityTxtValidator,
        SecurityTxtFinding,
        SecurityTxtData,
        SecurityTxtSeverity,
        SecurityTxtIssueType,
        REQUESTS_AVAILABLE
    )
    VALIDATOR_AVAILABLE = True
except ImportError:
    VALIDATOR_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Security.txt validator not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, text="", headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.headers = headers or {'Content-Type': 'text/plain; charset=utf-8'}
        return response
    return _create_response


@pytest.fixture
def valid_security_txt():
    """Create a valid security.txt content."""
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return f"""# Example security.txt
Contact: mailto:security@example.com
Expires: {expires}
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/hall-of-fame
Preferred-Languages: en, es
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
Hiring: https://example.com/jobs
"""


@pytest.fixture
def expired_security_txt():
    """Create an expired security.txt content."""
    return """Contact: mailto:security@example.com
Expires: 2020-01-01T00:00:00Z
"""


@pytest.fixture
def validator():
    """Create a SecurityTxtValidator instance."""
    if not VALIDATOR_AVAILABLE:
        pytest.skip("Security.txt validator not available")
    return SecurityTxtValidator(target_url="https://example.com", verify_ssl=False)


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestInitialization:
    """Test SecurityTxtValidator initialization."""

    def test_init_with_https_url(self):
        """Test initialization with HTTPS URL."""
        validator = SecurityTxtValidator(target_url="https://example.com")

        assert validator.base_url == "https://example.com"
        assert validator.timeout == 10
        assert validator.verify_ssl is True
        assert len(validator.findings) == 0
        assert validator.security_txt_data is None

    def test_init_with_http_url(self):
        """Test initialization with HTTP URL."""
        validator = SecurityTxtValidator(target_url="http://example.com")

        assert validator.base_url == "http://example.com"

    def test_init_without_scheme(self):
        """Test initialization without URL scheme."""
        validator = SecurityTxtValidator(target_url="example.com")

        # Should default to https
        assert validator.base_url == "https://example.com"

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        validator = SecurityTxtValidator(target_url="https://example.com", timeout=30)

        assert validator.timeout == 30

    def test_init_without_ssl_verification(self):
        """Test initialization with SSL verification disabled."""
        validator = SecurityTxtValidator(target_url="https://example.com", verify_ssl=False)

        assert validator.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed."""
        validator = SecurityTxtValidator(target_url="https://example.com/")

        assert validator.base_url == "https://example.com"

    def test_init_requires_requests_library(self):
        """Test that initialization fails without requests library."""
        if REQUESTS_AVAILABLE:
            pytest.skip("requests is available")

        with pytest.raises(ImportError, match="requests library is required"):
            SecurityTxtValidator(target_url="https://example.com")


# ============================================================================
# Fetch Security.txt Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestFetchSecurityTxt:
    """Test security.txt fetching logic."""

    @patch('requests.get')
    def test_fetch_from_well_known(self, mock_get, validator, mock_response, valid_security_txt):
        """Test fetching security.txt from /.well-known/."""
        mock_get.return_value = mock_response(text=valid_security_txt)

        url, content, response = validator._fetch_security_txt()

        assert url == "https://example.com/.well-known/security.txt"
        assert content == valid_security_txt
        assert response is not None

    @patch('requests.get')
    def test_fetch_from_root_location(self, mock_get, validator, mock_response, valid_security_txt):
        """Test fetching security.txt from root when /.well-known/ fails."""
        def side_effect(url, **kwargs):
            if '/.well-known/' in url:
                return mock_response(status_code=404)
            return mock_response(text=valid_security_txt)

        mock_get.side_effect = side_effect

        url, content, response = validator._fetch_security_txt()

        assert url == "https://example.com/security.txt"
        assert content == valid_security_txt

    @patch('requests.get')
    def test_fetch_not_found(self, mock_get, validator, mock_response):
        """Test when security.txt is not found."""
        mock_get.return_value = mock_response(status_code=404)

        url, content, response = validator._fetch_security_txt()

        assert url is None
        assert content is None
        assert response is None

    @patch('requests.get')
    def test_fetch_handles_request_exception(self, mock_get, validator):
        """Test handling of request exceptions."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        url, content, response = validator._fetch_security_txt()

        assert url is None
        assert content is None

    @patch('requests.get')
    def test_fetch_follows_redirects(self, mock_get, validator, mock_response, valid_security_txt):
        """Test that redirects are followed."""
        mock_get.return_value = mock_response(text=valid_security_txt)

        validator._fetch_security_txt()

        # Should call with allow_redirects=True
        mock_get.assert_called_with(
            "https://example.com/.well-known/security.txt",
            timeout=10,
            verify=False,
            allow_redirects=True
        )


# ============================================================================
# Parsing Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestParsing:
    """Test security.txt parsing."""

    def test_parse_valid_security_txt(self, validator, mock_response, valid_security_txt):
        """Test parsing valid security.txt."""
        response = mock_response(text=valid_security_txt)
        data = validator._parse_security_txt(
            "https://example.com/.well-known/security.txt",
            valid_security_txt,
            response
        )

        assert data.url == "https://example.com/.well-known/security.txt"
        assert "mailto:security@example.com" in data.contact
        assert data.expires is not None
        assert data.expires_datetime is not None
        assert not data.is_expired
        assert "https://example.com/pgp-key.txt" in data.encryption
        assert data.content_type == 'text/plain; charset=utf-8'

    def test_parse_multiple_contacts(self, validator, mock_response):
        """Test parsing multiple Contact fields."""
        content = """Contact: mailto:security@example.com
Contact: https://example.com/security
Contact: tel:+1-555-0123
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert len(data.contact) == 3
        assert "mailto:security@example.com" in data.contact
        assert "https://example.com/security" in data.contact
        assert "tel:+1-555-0123" in data.contact

    def test_parse_comments(self, validator, mock_response):
        """Test parsing comments."""
        content = """# This is a comment
# Another comment
Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert len(data.comments) == 2
        assert "This is a comment" in data.comments

    def test_parse_pgp_signature(self, validator, mock_response):
        """Test detection of PGP signature."""
        content = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE...
-----END PGP SIGNATURE-----
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert data.has_signature is True

    def test_parse_unknown_fields(self, validator, mock_response):
        """Test parsing unknown fields."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Custom-Field: custom value
Another-Field: another value
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert "Custom-Field" in data.unknown_fields
        assert "Another-Field" in data.unknown_fields

    def test_parse_expired_datetime(self, validator, mock_response):
        """Test parsing and detecting expired datetime."""
        content = """Contact: mailto:security@example.com
Expires: 2020-01-01T00:00:00Z
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert data.is_expired is True
        assert data.expires_datetime is not None

    def test_parse_invalid_datetime(self, validator, mock_response):
        """Test parsing invalid datetime format."""
        content = """Contact: mailto:security@example.com
Expires: not-a-valid-date
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert data.expires == "not-a-valid-date"
        assert data.expires_datetime is None

    def test_parse_charset_from_content_type(self, validator, mock_response):
        """Test extracting charset from Content-Type header."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content, headers={'Content-Type': 'text/plain; charset=iso-8859-1'})
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert data.charset == "iso-8859-1"

    def test_parse_empty_lines(self, validator, mock_response):
        """Test that empty lines are skipped."""
        content = """Contact: mailto:security@example.com

Expires: 2025-12-31T23:59:59Z

"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        assert len(data.contact) == 1
        assert data.expires is not None


# ============================================================================
# Required Fields Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestRequiredFields:
    """Test required field validation."""

    @patch('requests.get')
    def test_missing_contact_field(self, mock_get, validator, mock_response):
        """Test detection of missing Contact field."""
        content = """Expires: 2025-12-31T23:59:59Z
Encryption: https://example.com/pgp-key.txt
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.NO_CONTACT for f in findings)
        assert any(f.severity == SecurityTxtSeverity.HIGH for f in findings)

    @patch('requests.get')
    def test_missing_expires_field(self, mock_get, validator, mock_response):
        """Test detection of missing Expires field."""
        content = """Contact: mailto:security@example.com
Encryption: https://example.com/pgp-key.txt
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.NO_EXPIRES for f in findings)
        assert any(f.severity == SecurityTxtSeverity.HIGH for f in findings)

    @patch('requests.get')
    def test_valid_required_fields(self, mock_get, validator, mock_response, valid_security_txt):
        """Test that valid required fields don't generate findings."""
        mock_get.return_value = mock_response(text=valid_security_txt)

        findings = validator.validate()

        # Should not have NO_CONTACT or NO_EXPIRES findings
        assert not any(f.issue_type == SecurityTxtIssueType.NO_CONTACT for f in findings)
        assert not any(f.issue_type == SecurityTxtIssueType.NO_EXPIRES for f in findings)


# ============================================================================
# Expires Field Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestExpiresField:
    """Test Expires field validation."""

    @patch('requests.get')
    def test_expired_security_txt(self, mock_get, validator, mock_response):
        """Test detection of expired security.txt."""
        content = """Contact: mailto:security@example.com
Expires: 2020-01-01T00:00:00Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.EXPIRED for f in findings)
        assert any(f.severity == SecurityTxtSeverity.MEDIUM for f in findings)

    @patch('requests.get')
    def test_invalid_expires_format(self, mock_get, validator, mock_response):
        """Test detection of invalid Expires format."""
        content = """Contact: mailto:security@example.com
Expires: December 31, 2025
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INVALID_EXPIRES for f in findings)
        assert any(f.severity == SecurityTxtSeverity.MEDIUM for f in findings)

    @patch('requests.get')
    def test_valid_expires_field(self, mock_get, validator, mock_response):
        """Test valid Expires field."""
        expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')
        content = f"""Contact: mailto:security@example.com
Expires: {expires}
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        # Should not have EXPIRED or INVALID_EXPIRES findings
        assert not any(f.issue_type == SecurityTxtIssueType.EXPIRED for f in findings)
        assert not any(f.issue_type == SecurityTxtIssueType.INVALID_EXPIRES for f in findings)


# ============================================================================
# Contact Field Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestContactField:
    """Test Contact field validation."""

    @patch('requests.get')
    def test_invalid_contact_format(self, mock_get, validator, mock_response):
        """Test detection of invalid Contact format."""
        content = """Contact: security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INVALID_CONTACT for f in findings)
        assert any(f.severity == SecurityTxtSeverity.MEDIUM for f in findings)

    @patch('requests.get')
    def test_contact_with_http(self, mock_get, validator, mock_response):
        """Test detection of HTTP Contact URI."""
        content = """Contact: http://example.com/security
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.HTTP_ONLY for f in findings)
        assert any("HTTP" in f.title for f in findings)

    @patch('requests.get')
    def test_valid_contact_mailto(self, mock_get, validator, mock_response):
        """Test valid mailto Contact."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        # Should not have INVALID_CONTACT findings for this contact
        contact_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_CONTACT]
        assert len(contact_findings) == 0

    @patch('requests.get')
    def test_valid_contact_https(self, mock_get, validator, mock_response):
        """Test valid HTTPS Contact."""
        content = """Contact: https://example.com/security
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        contact_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_CONTACT]
        assert len(contact_findings) == 0

    @patch('requests.get')
    def test_valid_contact_tel(self, mock_get, validator, mock_response):
        """Test valid tel Contact."""
        content = """Contact: tel:+1-555-0123
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        contact_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_CONTACT]
        assert len(contact_findings) == 0


# ============================================================================
# Encryption Field Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestEncryptionField:
    """Test Encryption field validation."""

    @patch('requests.get')
    def test_invalid_encryption_format(self, mock_get, validator, mock_response):
        """Test detection of invalid Encryption format."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Encryption: invalid-format
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INVALID_FIELD and f.field_name == "Encryption" for f in findings)

    @patch('requests.get')
    def test_valid_encryption_https(self, mock_get, validator, mock_response):
        """Test valid HTTPS Encryption."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Encryption: https://example.com/pgp-key.txt
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        encryption_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_FIELD and f.field_name == "Encryption"]
        assert len(encryption_findings) == 0

    @patch('requests.get')
    def test_valid_encryption_openpgp(self, mock_get, validator, mock_response):
        """Test valid openpgp4fpr Encryption."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Encryption: openpgp4fpr:5F2DE5521C63A801AB59CCB603707A4DC8B8401
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        encryption_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_FIELD and f.field_name == "Encryption"]
        assert len(encryption_findings) == 0


# ============================================================================
# URL Fields Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestURLFields:
    """Test URL-based field validation."""

    @patch('requests.get')
    def test_invalid_acknowledgments_format(self, mock_get, validator, mock_response):
        """Test detection of invalid Acknowledgments format."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Acknowledgments: not-a-url
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.field_name == "Acknowledgments" and f.issue_type == SecurityTxtIssueType.INVALID_FIELD for f in findings)

    @patch('requests.get')
    def test_acknowledgments_with_http(self, mock_get, validator, mock_response):
        """Test detection of HTTP Acknowledgments."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Acknowledgments: http://example.com/hall-of-fame
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.field_name == "Acknowledgments" and f.issue_type == SecurityTxtIssueType.HTTP_ONLY for f in findings)

    @patch('requests.get')
    def test_policy_with_http(self, mock_get, validator, mock_response):
        """Test detection of HTTP Policy."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Policy: http://example.com/security-policy
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.field_name == "Policy" and f.issue_type == SecurityTxtIssueType.HTTP_ONLY for f in findings)

    @patch('requests.get')
    def test_hiring_with_http(self, mock_get, validator, mock_response):
        """Test detection of HTTP Hiring."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Hiring: http://example.com/jobs
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.field_name == "Hiring" and f.issue_type == SecurityTxtIssueType.HTTP_ONLY for f in findings)

    @patch('requests.get')
    def test_canonical_with_http(self, mock_get, validator, mock_response):
        """Test detection of HTTP Canonical."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Canonical: http://example.com/.well-known/security.txt
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.field_name == "Canonical" and f.issue_type == SecurityTxtIssueType.HTTP_ONLY for f in findings)


# ============================================================================
# Signature Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestSignature:
    """Test PGP signature detection."""

    @patch('requests.get')
    def test_no_signature_info_finding(self, mock_get, validator, mock_response):
        """Test that missing signature generates INFO finding."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INVALID_SIGNATURE for f in findings)
        assert any(f.severity == SecurityTxtSeverity.INFO for f in findings)

    @patch('requests.get')
    def test_signed_security_txt_no_finding(self, mock_get, validator, mock_response):
        """Test that signed security.txt doesn't generate signature finding."""
        content = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE...
-----END PGP SIGNATURE-----
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        signature_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_SIGNATURE]
        # Signed files should not have the "No PGP Signature" finding
        assert not any("No PGP Signature" in f.title for f in signature_findings)


# ============================================================================
# Location Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestLocation:
    """Test location validation."""

    @patch('requests.get')
    def test_legacy_location_warning(self, mock_get, validator, mock_response):
        """Test warning for legacy /security.txt location."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""

        def side_effect(url, **kwargs):
            if '/.well-known/' in url:
                return mock_response(status_code=404)
            return mock_response(text=content)

        mock_get.side_effect = side_effect

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.WRONG_LOCATION for f in findings)
        assert any("legacy" in f.description.lower() for f in findings)

    @patch('requests.get')
    def test_well_known_location_no_warning(self, mock_get, validator, mock_response):
        """Test that /.well-known/ location doesn't generate warning."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        location_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.WRONG_LOCATION]
        assert len(location_findings) == 0


# ============================================================================
# Content-Type Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestContentType:
    """Test Content-Type validation."""

    @patch('requests.get')
    def test_wrong_content_type(self, mock_get, validator, mock_response):
        """Test detection of wrong Content-Type."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content, headers={'Content-Type': 'text/html'})
        mock_get.return_value = response

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.WRONG_CONTENT_TYPE for f in findings)

    @patch('requests.get')
    def test_wrong_charset(self, mock_get, validator, mock_response):
        """Test detection of wrong charset."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content, headers={'Content-Type': 'text/plain; charset=iso-8859-1'})
        mock_get.return_value = response

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.WRONG_CHARSET for f in findings)

    @patch('requests.get')
    def test_correct_content_type(self, mock_get, validator, mock_response):
        """Test that correct Content-Type doesn't generate findings."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content, headers={'Content-Type': 'text/plain; charset=utf-8'})
        mock_get.return_value = response

        findings = validator.validate()

        ct_findings = [f for f in findings if f.issue_type in [SecurityTxtIssueType.WRONG_CONTENT_TYPE, SecurityTxtIssueType.WRONG_CHARSET]]
        assert len(ct_findings) == 0


# ============================================================================
# Unknown Fields Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestUnknownFields:
    """Test unknown field detection."""

    @patch('requests.get')
    def test_unknown_field_detection(self, mock_get, validator, mock_response):
        """Test detection of unknown fields."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Custom-Field: custom value
Unknown-Field: unknown value
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        unknown_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INVALID_FIELD and f.title.startswith("Unknown Field")]
        assert len(unknown_findings) == 2


# ============================================================================
# Information Disclosure Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestInformationDisclosure:
    """Test information disclosure detection."""

    @patch('requests.get')
    def test_password_reference_detection(self, mock_get, validator, mock_response):
        """Test detection of password references."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
# Internal password: secret123
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INFO_DISCLOSURE for f in findings)

    @patch('requests.get')
    def test_token_reference_detection(self, mock_get, validator, mock_response):
        """Test detection of token references."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
# API token: abc123
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INFO_DISCLOSURE for f in findings)

    @patch('requests.get')
    def test_ip_address_detection(self, mock_get, validator, mock_response):
        """Test detection of IP addresses."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
# Internal server: 192.168.1.100
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        assert any(f.issue_type == SecurityTxtIssueType.INFO_DISCLOSURE for f in findings)

    @patch('requests.get')
    def test_clean_security_txt_no_disclosure(self, mock_get, validator, mock_response, valid_security_txt):
        """Test that clean security.txt doesn't generate disclosure findings."""
        mock_get.return_value = mock_response(text=valid_security_txt)

        findings = validator.validate()

        disclosure_findings = [f for f in findings if f.issue_type == SecurityTxtIssueType.INFO_DISCLOSURE]
        assert len(disclosure_findings) == 0


# ============================================================================
# Missing Security.txt Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestMissingSecurityTxt:
    """Test missing security.txt detection."""

    @patch('requests.get')
    def test_missing_security_txt_finding(self, mock_get, validator, mock_response):
        """Test that missing security.txt generates INFO finding."""
        mock_get.return_value = mock_response(status_code=404)

        findings = validator.validate()

        assert len(findings) == 1
        assert findings[0].issue_type == SecurityTxtIssueType.MISSING
        assert findings[0].severity == SecurityTxtSeverity.INFO


# ============================================================================
# Summary Generation Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestSummaryGeneration:
    """Test summary report generation."""

    @patch('requests.get')
    def test_summary_structure(self, mock_get, validator, mock_response, valid_security_txt):
        """Test summary report structure."""
        mock_get.return_value = mock_response(text=valid_security_txt)
        validator.validate()

        summary = validator.get_summary()

        assert 'target' in summary
        assert 'security_txt_found' in summary
        assert 'security_txt_url' in summary
        assert 'is_expired' in summary
        assert 'has_signature' in summary
        assert 'total_findings' in summary
        assert 'severity_breakdown' in summary
        assert 'compliant' in summary
        assert 'findings' in summary
        assert 'parsed_data' in summary

    @patch('requests.get')
    def test_summary_severity_breakdown(self, mock_get, validator, mock_response, valid_security_txt):
        """Test severity breakdown in summary."""
        mock_get.return_value = mock_response(text=valid_security_txt)
        validator.validate()

        summary = validator.get_summary()
        breakdown = summary['severity_breakdown']

        assert 'CRITICAL' in breakdown
        assert 'HIGH' in breakdown
        assert 'MEDIUM' in breakdown
        assert 'LOW' in breakdown
        assert 'INFO' in breakdown

    @patch('requests.get')
    def test_summary_compliant_flag(self, mock_get, validator, mock_response, valid_security_txt):
        """Test compliant flag for valid security.txt."""
        mock_get.return_value = mock_response(text=valid_security_txt)
        validator.validate()

        summary = validator.get_summary()

        # Valid security.txt with no CRITICAL/HIGH findings should be compliant
        assert summary['compliant'] is True

    @patch('requests.get')
    def test_summary_not_found(self, mock_get, validator, mock_response):
        """Test summary when security.txt not found."""
        mock_get.return_value = mock_response(status_code=404)
        validator.validate()

        summary = validator.get_summary()

        assert summary['security_txt_found'] is False
        assert summary['security_txt_url'] is None


# ============================================================================
# Finding Management Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestFindingManagement:
    """Test finding management methods."""

    @patch('requests.get')
    def test_get_findings_by_severity(self, mock_get, validator, mock_response):
        """Test filtering findings by severity."""
        content = """Contact: security@example.com
Expires: not-a-date
"""
        mock_get.return_value = mock_response(text=content)
        validator.validate()

        high_findings = validator.get_findings_by_severity(SecurityTxtSeverity.HIGH)
        medium_findings = validator.get_findings_by_severity(SecurityTxtSeverity.MEDIUM)

        assert len(high_findings) > 0
        assert len(medium_findings) > 0


# ============================================================================
# Data Conversion Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestDataConversion:
    """Test data conversion methods."""

    def test_finding_to_dict(self):
        """Test SecurityTxtFinding to dict conversion."""
        finding = SecurityTxtFinding(
            title="Test Finding",
            severity=SecurityTxtSeverity.HIGH,
            issue_type=SecurityTxtIssueType.EXPIRED,
            description="Test description",
            url="https://example.com/.well-known/security.txt"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['title'] == "Test Finding"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['issue_type'] == "SECURITY_TXT_EXPIRED"

    def test_data_to_dict(self, validator, mock_response):
        """Test SecurityTxtData to dict conversion."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
"""
        response = mock_response(text=content)
        data = validator._parse_security_txt("https://example.com/.well-known/security.txt", content, response)

        data_dict = data.to_dict()

        assert 'url' in data_dict
        assert 'contact' in data_dict
        assert 'expires' in data_dict
        assert 'expires_datetime' in data_dict


# ============================================================================
# Edge Cases Tests
# ============================================================================

@pytest.mark.skipif(not VALIDATOR_AVAILABLE, reason="Validator not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch('requests.get')
    def test_empty_security_txt(self, mock_get, validator, mock_response):
        """Test handling of empty security.txt."""
        mock_get.return_value = mock_response(text="")

        findings = validator.validate()

        # Should have findings for missing required fields
        assert any(f.issue_type == SecurityTxtIssueType.NO_CONTACT for f in findings)
        assert any(f.issue_type == SecurityTxtIssueType.NO_EXPIRES for f in findings)

    @patch('requests.get')
    def test_malformed_field_lines(self, mock_get, validator, mock_response):
        """Test handling of malformed field lines."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
MalformedLineWithoutColon
AnotherBadLine
"""
        mock_get.return_value = mock_response(text=content)

        # Should not crash
        findings = validator.validate()

        assert len(findings) >= 0

    @patch('requests.get')
    def test_multiple_expires_fields(self, mock_get, validator, mock_response):
        """Test handling of multiple Expires fields (only first is used)."""
        content = """Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Expires: 2026-12-31T23:59:59Z
"""
        mock_get.return_value = mock_response(text=content)

        findings = validator.validate()

        # Should parse the first Expires field
        assert validator.security_txt_data.expires == "2025-12-31T23:59:59Z"

    def test_finding_default_date(self):
        """Test that finding gets default discovered_date."""
        finding = SecurityTxtFinding(
            title="Test",
            severity=SecurityTxtSeverity.HIGH,
            issue_type=SecurityTxtIssueType.EXPIRED,
            description="Test",
            url="https://example.com/.well-known/security.txt"
        )

        # Should have a datetime string
        assert finding.discovered_date is not None
        assert 'T' in finding.discovered_date
