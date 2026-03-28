"""
Extended metadata SSRF tests for improved coverage.
"""
import pytest
from engine.cloud.aws.metadata_ssrf import MetadataSSRF


def test_metadata_ssrf_init():
    """Test MetadataSSRF initialization."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    assert ssrf is not None
    assert ssrf.target_url == "http://example.com?url=INJECT"
    assert ssrf.findings == []


def test_metadata_ssrf_init_with_target():
    """Test MetadataSSRF initialization with explicit target."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT", target="example.com")
    assert ssrf.target == "example.com"


def test_metadata_ssrf_init_extracts_domain():
    """Test MetadataSSRF extracts domain from URL."""
    ssrf = MetadataSSRF("http://test.example.com/fetch?url=INJECT")
    assert ssrf.target == "test.example.com"


def test_generate_payloads_returns_list():
    """Test payload generation returns list."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()
    assert isinstance(payloads, list)
    assert len(payloads) > 0


def test_generate_payloads_returns_tuples():
    """Test payload generation returns tuples of (name, payload)."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    for item in payloads:
        assert isinstance(item, tuple)
        assert len(item) == 2
        name, payload = item
        assert isinstance(name, str)
        assert isinstance(payload, str)


def test_payload_format_valid():
    """Test generated payloads have valid format."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    for name, payload in payloads:
        assert 'http' in payload.lower() or '169.254' in payload


def test_aws_metadata_endpoint_included():
    """Test AWS metadata endpoint is in payloads."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    metadata_endpoints = [p for name, p in payloads if '169.254.169.254' in p]
    assert len(metadata_endpoints) > 0


def test_metadata_root_endpoint():
    """Test metadata root endpoint is included."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    payloads_dict = {name: payload for name, payload in payloads}
    assert "Metadata root" in payloads_dict
    assert "169.254.169.254/latest/meta-data/" in payloads_dict["Metadata root"]


def test_iam_credentials_endpoint():
    """Test IAM credentials endpoint is included."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    payloads_dict = {name: payload for name, payload in payloads}
    assert "IAM credentials" in payloads_dict
    assert "iam/security-credentials" in payloads_dict["IAM credentials"]


def test_dns_bypass_payloads():
    """Test DNS bypass techniques are included."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    dns_bypasses = [name for name, p in payloads if "DNS bypass" in name]
    assert len(dns_bypasses) >= 2


def test_decimal_ip_bypass():
    """Test decimal IP bypass is included."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    payloads_dict = {name: payload for name, payload in payloads}
    assert "Decimal IP" in payloads_dict
    assert "2852039166" in payloads_dict["Decimal IP"]


def test_hex_ip_bypass():
    """Test hex IP bypass is included."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")
    payloads = ssrf.generate_payloads()

    payloads_dict = {name: payload for name, payload in payloads}
    assert "Hex IP" in payloads_dict
    assert "0xa9fea9fe" in payloads_dict["Hex IP"]


def test_is_metadata_response():
    """Test metadata response detection."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")

    # Mock response object
    class MockResponse:
        def __init__(self, text):
            self.text = text

    # Test positive cases
    assert ssrf.is_metadata_response(MockResponse("ami-id: ami-12345"))
    assert ssrf.is_metadata_response(MockResponse("instance-id: i-12345"))
    assert ssrf.is_metadata_response(MockResponse("AccessKeyId: AKIAIOSFODNN7EXAMPLE"))
    assert ssrf.is_metadata_response(MockResponse("SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))

    # Test negative case
    assert not ssrf.is_metadata_response(MockResponse("Hello World"))


def test_is_metadata_response_case_insensitive():
    """Test metadata response detection is case insensitive."""
    ssrf = MetadataSSRF("http://example.com?url=INJECT")

    class MockResponse:
        def __init__(self, text):
            self.text = text

    assert ssrf.is_metadata_response(MockResponse("AMI-ID: ami-12345"))
    assert ssrf.is_metadata_response(MockResponse("INSTANCE-ID: i-12345"))
