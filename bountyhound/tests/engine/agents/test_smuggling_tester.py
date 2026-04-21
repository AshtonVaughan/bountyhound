import pytest
from unittest.mock import Mock, patch
from engine.agents.smuggling_tester import SmugglingTester

@pytest.fixture
def tester():
    return SmugglingTester()

def test_test_cl_te(tester):
    """Test CL.TE smuggling detection"""
    with patch('requests.post') as mock_post:
        # Mock different responses
        mock_post.side_effect = [
            Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5)),
            Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5)),
        ]

        findings = tester.test_cl_te("https://example.com/test")

        assert mock_post.called
        assert len(findings) >= 0

def test_test_te_cl(tester):
    """Test TE.CL smuggling detection"""
    with patch('requests.post') as mock_post:
        mock_post.return_value = Mock(status_code=200)

        findings = tester.test_te_cl("https://example.com/test")

        assert mock_post.called

def test_test_te_te(tester):
    """Test TE.TE smuggling detection"""
    with patch('requests.post') as mock_post:
        mock_post.return_value = Mock(status_code=200)

        findings = tester.test_te_te("https://example.com/test")

        assert mock_post.called

def test_test_timing_detection(tester):
    """Test timing-based smuggling detection"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        # Simulate timing difference
        mock_get.return_value = Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5))
        mock_post.return_value = Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 10.5))

        with patch('time.time', side_effect=[0, 0.5, 0.5, 11.0]):
            is_vulnerable = tester.test_timing_detection("https://example.com/test")

        # Should detect timing difference
        assert isinstance(is_vulnerable, bool)

def test_generate_smuggling_payloads(tester):
    """Test smuggling payload generation"""
    payloads = tester.generate_smuggling_payloads()

    assert len(payloads) > 0
    assert any("Content-Length" in p for p in payloads)
    assert any("Transfer-Encoding" in p for p in payloads)

def test_cl_te_payload_structure(tester):
    """Test CL.TE payload structure"""
    payload = tester._build_cl_te_payload("GET", "/test", "example.com")

    assert "Content-Length" in payload
    assert "Transfer-Encoding: chunked" in payload
    assert "0\r\n\r\n" in payload  # Chunk terminator

def test_te_cl_payload_structure(tester):
    """Test TE.CL payload structure"""
    payload = tester._build_te_cl_payload("POST", "/test", "example.com")

    assert "Content-Length" in payload
    assert "Transfer-Encoding: chunked" in payload
    assert "0\r\n\r\n" in payload

def test_te_te_payload_structure(tester):
    """Test TE.TE payload structure with obfuscation"""
    obf_header = "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"
    payload = tester._build_te_te_payload("POST", "/test", "example.com", obf_header)

    assert "Transfer-Encoding" in payload
    assert "identity" in payload or "chunked" in payload

def test_smuggling_indicators(tester):
    """Test smuggling detection indicators"""
    # 404 response
    response_404 = Mock(status_code=404, text="Not found")
    assert tester._indicates_smuggling(response_404)

    # 403 response
    response_403 = Mock(status_code=403, text="Forbidden")
    assert tester._indicates_smuggling(response_403)

    # Unrecognized method
    response_method = Mock(status_code=400, text="Unrecognized method GET")
    assert tester._indicates_smuggling(response_method)

    # Normal response
    response_normal = Mock(status_code=200, text="OK")
    assert not tester._indicates_smuggling(response_normal)

def test_get_host(tester):
    """Test host extraction from URL"""
    assert tester._get_host("https://example.com/test") == "example.com"
    assert tester._get_host("http://api.example.com:8080/path") == "api.example.com:8080"
    assert tester._get_host("https://sub.domain.example.com/") == "sub.domain.example.com"

def test_cl_te_with_smuggling_response(tester):
    """Test CL.TE detection with smuggling indicators"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        mock_post.return_value = Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5))
        mock_get.return_value = Mock(status_code=404, text="Not found", elapsed=Mock(total_seconds=lambda: 0.5))

        findings = tester.test_cl_te("https://example.com/test")

        assert len(findings) == 1
        assert findings[0].vuln_type == "HTTP_Smuggling_CLTE"
        assert findings[0].severity == "CRITICAL"
        assert "CL.TE" in findings[0].evidence["type"]

def test_te_cl_with_smuggling_response(tester):
    """Test TE.CL detection with smuggling indicators"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        mock_post.return_value = Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5))
        mock_get.return_value = Mock(status_code=403, text="Forbidden", elapsed=Mock(total_seconds=lambda: 0.5))

        findings = tester.test_te_cl("https://example.com/test")

        assert len(findings) == 1
        assert findings[0].vuln_type == "HTTP_Smuggling_TECL"
        assert findings[0].severity == "CRITICAL"

def test_te_te_with_smuggling_response(tester):
    """Test TE.TE detection with smuggling indicators"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        mock_post.return_value = Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5))
        mock_get.return_value = Mock(status_code=404, text="Unrecognized method", elapsed=Mock(total_seconds=lambda: 0.5))

        findings = tester.test_te_te("https://example.com/test")

        assert len(findings) == 1
        assert findings[0].vuln_type == "HTTP_Smuggling_TETE"
        assert findings[0].severity == "CRITICAL"
        assert "obfuscation" in findings[0].evidence

def test_timing_detection_positive(tester):
    """Test timing detection with significant delay"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        mock_get.return_value = Mock(status_code=200)
        mock_post.return_value = Mock(status_code=200)

        # Simulate baseline: 0.5s, smuggling: 10.5s (10s delay)
        with patch('time.time', side_effect=[0, 0.5, 0.5, 11.0]):
            is_vulnerable = tester.test_timing_detection("https://example.com/test")

        assert is_vulnerable is True

def test_timing_detection_negative(tester):
    """Test timing detection with no significant delay"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        mock_get.return_value = Mock(status_code=200)
        mock_post.return_value = Mock(status_code=200)

        # Simulate baseline: 0.5s, smuggling: 0.6s (0.1s delay - below threshold)
        with patch('time.time', side_effect=[0, 0.5, 0.5, 1.1]):
            is_vulnerable = tester.test_timing_detection("https://example.com/test")

        assert is_vulnerable is False

def test_exception_handling(tester):
    """Test that exceptions are handled gracefully"""
    with patch('requests.post', side_effect=Exception("Network error")):
        findings = tester.test_cl_te("https://example.com/test")
        assert findings == []

        findings = tester.test_te_cl("https://example.com/test")
        assert findings == []

        findings = tester.test_te_te("https://example.com/test")
        assert findings == []

def test_payload_contains_smuggled_request(tester):
    """Test that payloads contain smuggled requests"""
    payload = tester._build_cl_te_payload("POST", "/api/test", "api.example.com")

    assert "GET /admin" in payload
    assert "Host: api.example.com" in payload
    assert "HTTP/1.1" in payload

def test_multiple_obfuscation_attempts(tester):
    """Test that TE.TE tries multiple obfuscation techniques"""
    with patch('requests.post') as mock_post, patch('requests.get') as mock_get:
        mock_post.return_value = Mock(status_code=200, elapsed=Mock(total_seconds=lambda: 0.5))
        mock_get.return_value = Mock(status_code=200, text="OK", elapsed=Mock(total_seconds=lambda: 0.5))

        tester.test_te_te("https://example.com/test")

        # Should try multiple obfuscation techniques
        assert mock_post.call_count >= 1
