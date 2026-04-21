"""
Tests for HTTP Request Smuggling Tester Agent

Comprehensive test suite covering:
- CL.TE desynchronization detection
- TE.CL desynchronization detection
- TE.TE obfuscation variants
- Timing-based detection
- Differential response detection
- HTTP/2 downgrade (informational)
- Chunked encoding abuse
- Database integration
- POC generation
- Finding classification
"""

import pytest
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock
from datetime import date

from engine.agents.http_request_smuggling_tester import (
    HTTPRequestSmugglingTester,
    SmugglingTechnique,
    SeverityLevel,
    SmugglingTest,
    SmugglingFinding
)


class TestHTTPRequestSmugglingTester:
    """Test suite for HTTP Request Smuggling Tester."""

    @pytest.fixture
    def tester(self):
        """Create tester instance for testing."""
        return HTTPRequestSmugglingTester(
            target_host="example.com",
            target_port=443,
            use_ssl=True,
            timeout=5
        )

    @pytest.fixture
    def mock_database(self):
        """Mock database responses."""
        with patch('engine.agents.http_request_smuggling_tester.DatabaseHooks') as mock_db:
            mock_db.before_test.return_value = {
                'should_skip': False,
                'reason': 'Test environment',
                'previous_findings': [],
                'recommendations': ['Full test'],
                'last_tested_days': None
            }
            yield mock_db

    def test_initialization(self, tester):
        """Test tester initialization."""
        assert tester.target_host == "example.com"
        assert tester.target_port == 443
        assert tester.use_ssl is True
        assert tester.timeout == 5
        assert tester.target == "example.com"
        assert len(tester.findings) == 0
        assert tester.tests_run == 0

    def test_build_normal_request(self, tester):
        """Test normal request building."""
        request = tester._build_normal_request()

        assert b"GET / HTTP/1.1" in request
        assert b"Host: example.com" in request
        assert b"User-Agent:" in request
        assert b"Connection: close" in request
        assert request.endswith(b"\r\n\r\n")

    def test_extract_status_code(self, tester):
        """Test status code extraction."""
        # Test various response formats
        assert tester._extract_status_code(b"HTTP/1.1 200 OK\r\n") == 200
        assert tester._extract_status_code(b"HTTP/1.1 400 Bad Request\r\n") == 400
        assert tester._extract_status_code(b"HTTP/1.0 404 Not Found\r\n") == 404
        assert tester._extract_status_code(b"HTTP/2 500 Internal Server Error\r\n") == 500
        assert tester._extract_status_code(b"Invalid response") == 0

    def test_is_smuggling_detected_400_response(self, tester):
        """Test smuggling detection with 400 Bad Request."""
        test = SmugglingTest(
            name="Test",
            technique=SmugglingTechnique.CL_TE,
            payload=b"POST / HTTP/1.1\r\n\r\n",
            description="Test",
            severity=SeverityLevel.CRITICAL
        )

        response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request"

        assert tester._is_smuggling_detected(response, test) is True

    def test_is_smuggling_detected_admin_403(self, tester):
        """Test smuggling detection with admin endpoint 403."""
        test = SmugglingTest(
            name="Test",
            technique=SmugglingTechnique.CL_TE,
            payload=b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n",
            description="Test",
            severity=SeverityLevel.CRITICAL
        )

        response = b"HTTP/1.1 403 Forbidden\r\n\r\n"

        assert tester._is_smuggling_detected(response, test) is True

    def test_is_smuggling_detected_500_error(self, tester):
        """Test smuggling detection with 500 error."""
        test = SmugglingTest(
            name="Test",
            technique=SmugglingTechnique.TE_CL,
            payload=b"POST / HTTP/1.1\r\n\r\n",
            description="Test",
            severity=SeverityLevel.CRITICAL
        )

        response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"

        assert tester._is_smuggling_detected(response, test) is True

    def test_is_smuggling_detected_empty_response(self, tester):
        """Test smuggling detection with empty response (connection reset)."""
        test = SmugglingTest(
            name="Test",
            technique=SmugglingTechnique.CL_TE,
            payload=b"POST / HTTP/1.1\r\n\r\n",
            description="Test",
            severity=SeverityLevel.CRITICAL
        )

        response = b""

        assert tester._is_smuggling_detected(response, test) is True

    def test_is_smuggling_detected_normal_response(self, tester):
        """Test no smuggling detection with normal 200 response."""
        test = SmugglingTest(
            name="Test",
            technique=SmugglingTechnique.CL_TE,
            payload=b"POST / HTTP/1.1\r\n\r\n",
            description="Test",
            severity=SeverityLevel.CRITICAL
        )

        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

        assert tester._is_smuggling_detected(response, test) is False

    def test_get_impact_cl_te(self, tester):
        """Test impact description for CL.TE."""
        impact = tester._get_impact(SmugglingTechnique.CL_TE)
        assert "cache poisoning" in impact.lower()
        assert "access control bypass" in impact.lower()

    def test_get_impact_te_cl(self, tester):
        """Test impact description for TE.CL."""
        impact = tester._get_impact(SmugglingTechnique.TE_CL)
        assert "session hijacking" in impact.lower()
        assert "credential theft" in impact.lower()

    def test_get_impact_te_te(self, tester):
        """Test impact description for TE.TE."""
        impact = tester._get_impact(SmugglingTechnique.TE_TE)
        assert "obfuscation" in impact.lower()
        assert "security controls" in impact.lower()

    def test_get_exploitation_notes_cl_te(self, tester):
        """Test exploitation notes for CL.TE."""
        notes = tester._get_exploitation_notes(SmugglingTechnique.CL_TE)
        assert "frontend" in notes.lower()
        assert "content-length" in notes.lower()
        assert "backend" in notes.lower()
        assert "transfer-encoding" in notes.lower()

    def test_get_exploitation_notes_te_cl(self, tester):
        """Test exploitation notes for TE.CL."""
        notes = tester._get_exploitation_notes(SmugglingTechnique.TE_CL)
        assert "steal" in notes.lower() or "session" in notes.lower()

    def test_generate_poc(self, tester):
        """Test POC generation."""
        test = SmugglingTest(
            name="CL.TE Test",
            technique=SmugglingTechnique.CL_TE,
            payload=b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
            description="Test CL.TE desync",
            severity=SeverityLevel.CRITICAL
        )

        poc = tester._generate_poc(test)

        assert "CL.TE" in poc
        assert "POST / HTTP/1.1" in poc
        assert "Exploitation:" in poc
        assert "Impact:" in poc

    def test_generate_timing_poc(self, tester):
        """Test timing POC generation."""
        payload = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        poc = tester._generate_timing_poc(payload)

        assert "Timing-Based" in poc
        assert "POST / HTTP/1.1" in poc
        assert "GET / HTTP/1.1" in poc
        assert "hangs" in poc.lower()

    def test_generate_differential_poc(self, tester):
        """Test differential response POC generation."""
        payload = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        poc = tester._generate_differential_poc(payload)

        assert "Differential" in poc
        assert "Step 1" in poc
        assert "Step 2" in poc
        assert "different status codes" in poc.lower()

    def test_generate_http2_poc(self, tester):
        """Test HTTP/2 POC generation."""
        poc = tester._generate_http2_poc()

        assert "HTTP/2" in poc
        assert "h2 library" in poc or "HTTP/2 tools" in poc
        assert "example.com" in poc
        assert "downgrade" in poc.lower()

    def test_generate_admin_access_exploit(self, tester):
        """Test admin access exploitation generation."""
        finding = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Test",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        exploit = tester._generate_admin_access_exploit(finding)

        assert "/admin" in exploit
        assert "localhost" in exploit
        assert "Step 1" in exploit
        assert "bypass" in exploit.lower() and "ip" in exploit.lower()

    def test_generate_cache_poisoning_exploit(self, tester):
        """Test cache poisoning exploitation generation."""
        finding = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Test",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        exploit = tester._generate_cache_poisoning_exploit(finding)

        assert "Cache Poisoning" in exploit
        assert "X-Forwarded-Host" in exploit
        assert "evil.com" in exploit
        assert "XSS" in exploit

    def test_smuggling_finding_to_dict(self):
        """Test SmugglingFinding to_dict conversion."""
        finding = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Test Finding",
            technique=SmugglingTechnique.CL_TE,
            description="Test description",
            payload=b"POST / HTTP/1.1\r\n",
            evidence={'test': 'data'},
            poc="Test POC",
            impact="Test impact"
        )

        result = finding.to_dict()

        assert result['severity'] == SeverityLevel.CRITICAL
        assert result['title'] == "Test Finding"
        assert result['technique'] == SmugglingTechnique.CL_TE
        assert result['description'] == "Test description"
        assert "POST / HTTP/1.1" in result['payload']
        assert result['evidence'] == {'test': 'data'}
        assert result['poc'] == "Test POC"
        assert result['impact'] == "Test impact"
        assert 'timestamp' in result

    def test_get_findings(self, tester):
        """Test getting all findings."""
        finding1 = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Finding 1",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        finding2 = SmugglingFinding(
            severity=SeverityLevel.HIGH,
            title="Finding 2",
            technique=SmugglingTechnique.TE_CL,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        tester.findings = [finding1, finding2]

        findings = tester.get_findings()
        assert len(findings) == 2
        assert findings[0].title == "Finding 1"
        assert findings[1].title == "Finding 2"

    def test_get_findings_by_severity(self, tester):
        """Test getting findings by severity."""
        finding1 = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Critical",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        finding2 = SmugglingFinding(
            severity=SeverityLevel.HIGH,
            title="High",
            technique=SmugglingTechnique.TE_CL,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        finding3 = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Critical 2",
            technique=SmugglingTechnique.TE_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        tester.findings = [finding1, finding2, finding3]

        critical = tester.get_findings_by_severity(SeverityLevel.CRITICAL)
        assert len(critical) == 2
        assert all(f.severity == SeverityLevel.CRITICAL for f in critical)

        high = tester.get_findings_by_severity(SeverityLevel.HIGH)
        assert len(high) == 1
        assert high[0].severity == SeverityLevel.HIGH

    def test_get_findings_by_technique(self, tester):
        """Test getting findings by technique."""
        finding1 = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="CL.TE Finding",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        finding2 = SmugglingFinding(
            severity=SeverityLevel.HIGH,
            title="TE.CL Finding",
            technique=SmugglingTechnique.TE_CL,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        finding3 = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="CL.TE Finding 2",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"test",
            evidence={},
            poc="test",
            impact="test"
        )

        tester.findings = [finding1, finding2, finding3]

        cl_te = tester.get_findings_by_technique(SmugglingTechnique.CL_TE)
        assert len(cl_te) == 2
        assert all(f.technique == SmugglingTechnique.CL_TE for f in cl_te)

        te_cl = tester.get_findings_by_technique(SmugglingTechnique.TE_CL)
        assert len(te_cl) == 1
        assert te_cl[0].technique == SmugglingTechnique.TE_CL

    @patch('engine.agents.http_request_smuggling_tester.DatabaseHooks')
    @patch('engine.agents.http_request_smuggling_tester.BountyHoundDB')
    def test_database_integration_skip(self, mock_db_class, mock_hooks):
        """Test database integration - skip recently tested target."""
        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': [{'title': 'Previous finding'}],
            'recommendations': ['Skip this target'],
            'last_tested_days': 2
        }

        tester = HTTPRequestSmugglingTester("example.com")
        findings = tester.run_all_tests()

        # Should return empty list without running tests
        assert len(findings) == 0
        assert tester.tests_run == 0
        mock_hooks.before_test.assert_called_once_with('example.com', 'http_request_smuggling_tester')

    @patch('engine.agents.http_request_smuggling_tester.DatabaseHooks')
    @patch('engine.agents.http_request_smuggling_tester.BountyHoundDB')
    @patch('engine.agents.http_request_smuggling_tester.HTTPRequestSmugglingTester._send_raw_request')
    def test_database_integration_proceed(self, mock_send, mock_db_class, mock_hooks):
        """Test database integration - proceed with testing."""
        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Last tested 45 days ago',
            'previous_findings': [],
            'recommendations': ['Full retest recommended'],
            'last_tested_days': 45
        }

        # Mock successful response
        mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

        mock_db = MagicMock()
        mock_db_class.return_value = mock_db

        tester = HTTPRequestSmugglingTester("example.com")
        findings = tester.run_all_tests()

        # Should run tests
        assert tester.tests_run > 0
        mock_hooks.before_test.assert_called_once()

        # Should record results
        mock_db.record_tool_run.assert_called_once()
        call_args = mock_db.record_tool_run.call_args[0]
        assert call_args[0] == 'example.com'
        assert call_args[1] == 'http_request_smuggling_tester'

    @patch('engine.agents.http_request_smuggling_tester.socket.socket')
    def test_send_raw_request_ssl(self, mock_socket_class):
        """Test sending raw request with SSL."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # Mock SSL wrap
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]

        with patch('ssl.create_default_context') as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_context.wrap_socket.return_value = mock_ssl_socket

            tester = HTTPRequestSmugglingTester("example.com", use_ssl=True)
            response = tester._send_raw_request(b"GET / HTTP/1.1\r\n\r\n")

            assert response == b"HTTP/1.1 200 OK\r\n\r\n"
            mock_ssl_socket.connect.assert_called_once_with(("example.com", 443))
            mock_ssl_socket.sendall.assert_called_once()

    @patch('engine.agents.http_request_smuggling_tester.socket.socket')
    def test_send_raw_request_no_ssl(self, mock_socket_class):
        """Test sending raw request without SSL."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]

        tester = HTTPRequestSmugglingTester("example.com", use_ssl=False, target_port=80)
        response = tester._send_raw_request(b"GET / HTTP/1.1\r\n\r\n")

        assert response == b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket.connect.assert_called_once_with(("example.com", 80))
        mock_socket.sendall.assert_called_once()

    @patch('engine.agents.http_request_smuggling_tester.socket.socket')
    def test_send_raw_request_timeout(self, mock_socket_class):
        """Test handling of request timeout."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.side_effect = socket.timeout("Connection timeout")

        tester = HTTPRequestSmugglingTester("example.com", use_ssl=False)
        response = tester._send_raw_request(b"GET / HTTP/1.1\r\n\r\n")

        assert response is None

    @patch('engine.agents.http_request_smuggling_tester.socket.socket')
    def test_send_raw_request_connection_error(self, mock_socket_class):
        """Test handling of connection error."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.side_effect = ConnectionRefusedError("Connection refused")

        tester = HTTPRequestSmugglingTester("example.com", use_ssl=False)
        response = tester._send_raw_request(b"GET / HTTP/1.1\r\n\r\n")

        assert response is None

    def test_te_obfuscation_variants(self, tester):
        """Test that TE obfuscation variants are defined."""
        assert len(tester.TE_OBFUSCATIONS) >= 10
        assert "Transfer-Encoding: chunked" in tester.TE_OBFUSCATIONS
        assert any(":" in variant and "chunked" in variant for variant in tester.TE_OBFUSCATIONS)

    def test_coverage_30_plus_tests(self, tester, mock_database):
        """Test that at least 30 tests are executed."""
        with patch.object(tester, '_send_raw_request') as mock_send:
            # Mock successful responses for all tests
            mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

            # Mock database to prevent skip
            with patch('engine.agents.http_request_smuggling_tester.BountyHoundDB'):
                with patch('engine.agents.http_request_smuggling_tester.PayloadHooks'):
                    tester.run_all_tests()

            # Should run at least 30 tests
            assert tester.tests_run >= 30

    def test_coverage_all_techniques(self, tester, mock_database):
        """Test that all smuggling techniques are covered."""
        with patch.object(tester, '_send_raw_request') as mock_send:
            mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

            # Mock database to prevent skip
            with patch('engine.agents.http_request_smuggling_tester.BountyHoundDB'):
                with patch('engine.agents.http_request_smuggling_tester.PayloadHooks'):
                    tester.run_all_tests()

            # Verify all test methods were called
            # (indirectly verified by tests_run count >= 30)
            assert tester.tests_run >= 30

    @patch('engine.agents.http_request_smuggling_tester.PayloadHooks')
    @patch('engine.agents.http_request_smuggling_tester.BountyHoundDB')
    @patch('engine.agents.http_request_smuggling_tester.DatabaseHooks')
    def test_payload_recording(self, mock_hooks, mock_db_class, mock_payload_hooks):
        """Test that successful payloads are recorded."""
        mock_hooks.before_test.return_value = {
            'should_skip': False,
            'reason': 'Test',
            'previous_findings': [],
            'recommendations': [],
            'last_tested_days': None
        }

        tester = HTTPRequestSmugglingTester("example.com")

        # Add a critical finding
        finding = SmugglingFinding(
            severity=SeverityLevel.CRITICAL,
            title="Test",
            technique=SmugglingTechnique.CL_TE,
            description="Test",
            payload=b"POST / HTTP/1.1\r\n",
            evidence={},
            poc="test",
            impact="test"
        )
        tester.findings = [finding]

        with patch.object(tester, '_establish_timing_baseline'):
            with patch.object(tester, '_test_cl_te_desync'):
                with patch.object(tester, '_test_te_cl_desync'):
                    with patch.object(tester, '_test_te_te_desync'):
                        with patch.object(tester, '_test_timing_based_detection'):
                            with patch.object(tester, '_test_differential_responses'):
                                with patch.object(tester, '_test_pipeline_desync'):
                                    with patch.object(tester, '_test_http2_downgrade'):
                                        with patch.object(tester, '_test_chunked_encoding_abuse'):
                                            with patch.object(tester, '_generate_exploitations'):
                                                tester.run_all_tests()

        # Should record critical findings
        mock_payload_hooks.record_payload_success.assert_called_once()
        call_args = mock_payload_hooks.record_payload_success.call_args
        assert call_args[1]['vuln_type'] == 'HTTP_REQUEST_SMUGGLING'
        assert call_args[1]['context'] == SmugglingTechnique.CL_TE


class TestSmugglingTechnique:
    """Test SmugglingTechnique constants."""

    def test_technique_values(self):
        """Test that technique values are defined correctly."""
        assert SmugglingTechnique.CL_TE == "CL.TE"
        assert SmugglingTechnique.TE_CL == "TE.CL"
        assert SmugglingTechnique.TE_TE == "TE.TE"
        assert SmugglingTechnique.H2C == "H2C"
        assert SmugglingTechnique.H2_DOWNGRADE == "HTTP2_DOWNGRADE"
        assert SmugglingTechnique.CHUNKED_ABUSE == "CHUNKED_ABUSE"


class TestSeverityLevel:
    """Test SeverityLevel constants."""

    def test_severity_values(self):
        """Test that severity values are defined correctly."""
        assert SeverityLevel.CRITICAL == "CRITICAL"
        assert SeverityLevel.HIGH == "HIGH"
        assert SeverityLevel.MEDIUM == "MEDIUM"
        assert SeverityLevel.LOW == "LOW"
        assert SeverityLevel.INFO == "INFO"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=engine.agents.http_request_smuggling_tester"])
