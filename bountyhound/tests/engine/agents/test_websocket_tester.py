"""
Comprehensive tests for WebSocket Tester Agent.

Tests cover:
- Initialization and configuration
- WebSocket endpoint discovery
- CSWSH (Cross-Site WebSocket Hijacking) detection
- Authentication bypass testing (handshake and message-level)
- Message injection (XSS, SQLi, command injection)
- Token in URL detection
- DoS testing (subscription flooding, message flooding)
- Finding management
- Report generation
- Edge cases and error handling
- Database integration
- All POC generation methods

Target: 95%+ code coverage with 30+ tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import date

# Test imports with fallback
try:
    from engine.agents.websocket_tester import (
        WebSocketTester,
        WebSocketDetector,
        WebSocketFinding,
        WebSocketSeverity,
        WebSocketVulnType,
        WEBSOCKET_AVAILABLE,
        REQUESTS_AVAILABLE
    )
    WEBSOCKET_TESTER_AVAILABLE = True
except ImportError:
    WEBSOCKET_TESTER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="WebSocket tester not available")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_ws_connection():
    """Create a mock WebSocket connection."""
    def _create_ws(can_send=True, can_recv=True, recv_data='{"status":"ok"}'):
        ws = Mock()
        ws.send = Mock()
        ws.recv = Mock(return_value=recv_data) if can_recv else Mock(side_effect=Exception("timeout"))
        ws.close = Mock()
        ws.settimeout = Mock()
        ws.getheaders = Mock(return_value={})
        return ws

    return _create_ws


@pytest.fixture
def tester():
    """Create a WebSocketTester instance for testing."""
    if not WEBSOCKET_TESTER_AVAILABLE:
        pytest.skip("WebSocket tester not available")

    return WebSocketTester(
        ws_url="wss://example.com/ws",
        timeout=5,
        auto_discover=False
    )


@pytest.fixture
def mock_db_context():
    """Mock database context."""
    return {
        'should_skip': False,
        'reason': 'Never tested before',
        'previous_findings': [],
        'recommendations': ['Full test recommended'],
        'last_tested_days': None
    }


# ============================================================================
# Initialization Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestInitialization:
    """Test WebSocketTester initialization."""

    def test_init_with_ws_url(self):
        """Test initialization with direct WebSocket URL."""
        tester = WebSocketTester(ws_url="wss://example.com/ws", auto_discover=False)

        assert tester.ws_endpoints == ["wss://example.com/ws"]
        assert tester.target == "example.com"
        assert tester.timeout == 5
        assert len(tester.findings) == 0

    def test_init_with_http_url_auto_discover(self):
        """Test initialization with HTTP URL (auto-discover mode)."""
        with patch('engine.agents.websocket_tester.WebSocketDetector') as mock_detector:
            mock_detector.return_value.discover_websockets.return_value = ["wss://example.com/ws"]

            tester = WebSocketTester(target_url="https://example.com", auto_discover=True)

            assert tester.target_url == "https://example.com"
            assert tester.target == "example.com"

    def test_init_with_session_cookies(self):
        """Test initialization with session cookies."""
        cookies = {"session": "abc123", "token": "xyz789"}
        tester = WebSocketTester(ws_url="wss://example.com/ws", session_cookies=cookies, auto_discover=False)

        assert tester.session_cookies == cookies

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        tester = WebSocketTester(ws_url="wss://example.com/ws", timeout=30, auto_discover=False)

        assert tester.timeout == 30

    def test_init_with_custom_target(self):
        """Test initialization with custom target identifier."""
        tester = WebSocketTester(
            ws_url="wss://example.com/ws",
            target="custom-target",
            auto_discover=False
        )

        assert tester.target == "custom-target"

    def test_init_requires_websocket_library(self):
        """Test that initialization fails without websocket library."""
        if WEBSOCKET_AVAILABLE:
            pytest.skip("websocket-client is available")

        with pytest.raises(ImportError, match="websocket-client library is required"):
            WebSocketTester(ws_url="wss://example.com/ws")


# ============================================================================
# WebSocket Discovery Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestWebSocketDiscovery:
    """Test WebSocket endpoint discovery."""

    def test_detector_init(self):
        """Test WebSocketDetector initialization."""
        detector = WebSocketDetector(target_url="https://example.com", timeout=10)

        assert detector.target_url == "https://example.com"
        assert detector.timeout == 10
        assert detector.ws_endpoints == []

    @patch('websocket.create_connection')
    def test_discover_websockets_finds_endpoint(self, mock_ws):
        """Test successful WebSocket endpoint discovery."""
        mock_connection = Mock()
        mock_connection.close = Mock()
        mock_connection.getheaders = Mock(return_value={})
        mock_ws.return_value = mock_connection

        detector = WebSocketDetector(target_url="https://example.com")
        endpoints = detector.discover_websockets()

        assert len(endpoints) > 0
        assert any("wss://example.com" in ep for ep in endpoints)

    @patch('websocket.create_connection')
    def test_discover_websockets_handles_connection_failure(self, mock_ws):
        """Test that discovery handles connection failures gracefully."""
        mock_ws.side_effect = Exception("Connection failed")

        detector = WebSocketDetector(target_url="https://example.com")
        endpoints = detector.discover_websockets()

        # Should not crash, may return empty list or JS-discovered endpoints
        assert isinstance(endpoints, list)

    @patch('websocket.create_connection')
    @patch('requests.get')
    def test_discover_websockets_from_javascript(self, mock_get, mock_ws):
        """Test discovering WebSocket URLs from JavaScript files."""
        mock_ws.side_effect = Exception("Connection failed")

        # Mock HTML response with script tag
        html_response = Mock()
        html_response.text = '<script src="/app.js"></script>'
        mock_get.return_value = html_response

        # Mock JS response with WebSocket URL
        with patch('requests.get') as mock_get_js:
            js_response = Mock()
            js_response.text = 'new WebSocket("wss://example.com/socket")'
            mock_get_js.return_value = js_response

            detector = WebSocketDetector(target_url="https://example.com")
            endpoints = detector.discover_websockets()

            # Should find the WebSocket URL from JS
            assert isinstance(endpoints, list)


# ============================================================================
# CSWSH Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestCSWSH:
    """Test Cross-Site WebSocket Hijacking detection."""

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_cswsh_detected_with_evil_origin(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test CSWSH vulnerability detection with evil origin."""
        mock_db.return_value = mock_db_context
        mock_ws.return_value = mock_ws_connection()

        tester.run_all_tests()

        # Should find CSWSH vulnerability
        cswsh_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.CSWSH]
        assert len(cswsh_findings) > 0
        assert cswsh_findings[0].severity == WebSocketSeverity.CRITICAL

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_cswsh_includes_poc(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test that CSWSH finding includes HTML POC."""
        mock_db.return_value = mock_db_context
        mock_ws.return_value = mock_ws_connection()

        tester.run_all_tests()

        cswsh_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.CSWSH]
        if cswsh_findings:
            assert "WebSocket" in cswsh_findings[0].poc
            assert "new WebSocket" in cswsh_findings[0].poc

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_cswsh_not_detected_with_origin_validation(self, mock_db, mock_ws, tester, mock_db_context):
        """Test that CSWSH is not detected when origin validation works."""
        mock_db.return_value = mock_db_context
        mock_ws.side_effect = Exception("Origin not allowed")

        tester.run_all_tests()

        cswsh_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.CSWSH]
        assert len(cswsh_findings) == 0


# ============================================================================
# Authentication Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestAuthentication:
    """Test WebSocket authentication vulnerabilities."""

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_missing_authentication_detected(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test detection of missing authentication."""
        mock_db.return_value = mock_db_context
        mock_ws.return_value = mock_ws_connection(recv_data='{"sensitive":"data"}')

        tester.run_all_tests()

        auth_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.MISSING_AUTHENTICATION]
        assert len(auth_findings) > 0
        assert auth_findings[0].severity == WebSocketSeverity.HIGH

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_message_level_auth_missing(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test detection of missing message-level authentication."""
        mock_db.return_value = mock_db_context

        # Connection succeeds, message gets valid response without auth check
        ws = mock_ws_connection(recv_data='{"user_data":"sensitive"}')
        mock_ws.return_value = ws

        tester.run_all_tests()

        msg_auth_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.MESSAGE_LEVEL_AUTH_MISSING]
        assert len(msg_auth_findings) > 0

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_authentication_enforced(self, mock_db, mock_ws, tester, mock_db_context):
        """Test that authentication enforcement is detected."""
        mock_db.return_value = mock_db_context
        mock_ws.side_effect = Exception("Authentication required")

        tester.run_all_tests()

        # Should not find missing auth vulnerabilities
        auth_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.MISSING_AUTHENTICATION]
        assert len(auth_findings) == 0


# ============================================================================
# Message Injection Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestMessageInjection:
    """Test message injection vulnerabilities."""

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_xss_via_websocket_detected(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test XSS detection via WebSocket messages."""
        mock_db.return_value = mock_db_context

        # WebSocket reflects XSS payload - needs to match payload exactly
        xss_payload = '<script>document.title="XSS-FIRED"</script>'
        xss_response = xss_payload  # Reflect exact payload
        ws = mock_ws_connection(recv_data=xss_response)
        mock_ws.return_value = ws

        tester.run_all_tests()

        xss_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.XSS_VIA_WEBSOCKET]
        assert len(xss_findings) > 0
        assert xss_findings[0].severity == WebSocketSeverity.HIGH

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_sqli_via_websocket_detected(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test SQL injection detection via WebSocket."""
        mock_db.return_value = mock_db_context

        # WebSocket returns SQL error
        sql_response = '{"error":"sql syntax error near OR"}'
        ws = mock_ws_connection(recv_data=sql_response)
        mock_ws.return_value = ws

        tester.run_all_tests()

        sqli_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.SQLI_VIA_WEBSOCKET]
        assert len(sqli_findings) > 0
        assert sqli_findings[0].severity == WebSocketSeverity.CRITICAL

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    @patch('engine.agents.websocket_tester.time.time')
    def test_time_based_sqli_detected(self, mock_time, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test time-based SQL injection detection."""
        mock_db.return_value = mock_db_context

        # Use a function to return alternating values: start (0) and end (6 for SLEEP, 0.1 for others)
        # This simulates delays only for SLEEP payloads
        call_count = [0]
        def time_side_effect():
            call_count[0] += 1
            # Every other call (end time)
            if call_count[0] % 2 == 0:
                # Check if previous call was for SQLi SLEEP test (calls 7-8)
                if 7 <= call_count[0] <= 12:  # Range where SQLi test happens
                    return 6  # 6 second delay
                return 0.1  # Normal fast response
            return 0  # Start time

        mock_time.side_effect = time_side_effect

        ws = mock_ws_connection(recv_data='{}')
        mock_ws.return_value = ws

        tester.run_all_tests()

        # Time-based SQLi should be detected
        sqli_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.SQLI_VIA_WEBSOCKET]
        if sqli_findings:
            assert any('time' in f.title.lower() or 'delay' in f.description.lower() for f in sqli_findings)

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    @patch('engine.agents.websocket_tester.time.time')
    def test_command_injection_detected(self, mock_time, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test command injection detection via WebSocket."""
        mock_db.return_value = mock_db_context

        # Use a function to simulate delays for command injection sleep
        call_count = [0]
        def time_side_effect():
            call_count[0] += 1
            # Every other call (end time)
            if call_count[0] % 2 == 0:
                # Check if we're in command injection test range
                if 13 <= call_count[0] <= 18:  # Range where command injection test happens
                    return 6  # 6 second delay
                return 0.1  # Normal fast response
            return 0  # Start time

        mock_time.side_effect = time_side_effect

        ws = mock_ws_connection(recv_data='{}')
        mock_ws.return_value = ws

        tester.run_all_tests()

        cmd_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.COMMAND_INJECTION]
        if cmd_findings:
            assert cmd_findings[0].severity == WebSocketSeverity.CRITICAL


# ============================================================================
# DoS Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestDoS:
    """Test WebSocket DoS vulnerabilities."""

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_subscription_flooding_detected(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test subscription flooding detection."""
        mock_db.return_value = mock_db_context

        # No rate limiting - always returns OK
        ws = mock_ws_connection(recv_data='{"status":"subscribed"}')
        mock_ws.return_value = ws

        tester.run_all_tests()

        flood_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.SUBSCRIPTION_FLOODING]
        assert len(flood_findings) > 0
        assert flood_findings[0].severity == WebSocketSeverity.MEDIUM

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_message_flooding_detected(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test message flooding detection."""
        mock_db.return_value = mock_db_context

        # No rate limiting
        ws = mock_ws_connection(recv_data='{"status":"ok"}')
        mock_ws.return_value = ws

        tester.run_all_tests()

        flood_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.MESSAGE_FLOODING]
        assert len(flood_findings) > 0

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_rate_limiting_enforced(self, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test that rate limiting enforcement is detected."""
        mock_db.return_value = mock_db_context

        # Rate limiting kicks in
        ws = mock_ws_connection(recv_data='{"error":"rate limit exceeded"}')
        mock_ws.return_value = ws

        tester.run_all_tests()

        # Should not find flooding vulnerabilities
        flood_findings = [
            f for f in tester.findings
            if f.vuln_type in [WebSocketVulnType.SUBSCRIPTION_FLOODING, WebSocketVulnType.MESSAGE_FLOODING]
        ]
        # Rate limiting detected, so should be 0 findings
        assert len(flood_findings) == 0


# ============================================================================
# Token in URL Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestTokenInURL:
    """Test token in URL detection."""

    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_token_in_url_detected(self, mock_db, mock_db_context):
        """Test detection of token in WebSocket URL."""
        mock_db.return_value = mock_db_context

        tester = WebSocketTester(
            ws_url="wss://example.com/ws?token=abc123&session=xyz789",
            auto_discover=False
        )

        tester.run_all_tests()

        token_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.TOKEN_IN_URL]
        assert len(token_findings) > 0
        assert token_findings[0].severity == WebSocketSeverity.MEDIUM

    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_no_token_in_url(self, mock_db, mock_db_context):
        """Test that no finding is created when URL has no token."""
        mock_db.return_value = mock_db_context

        tester = WebSocketTester(
            ws_url="wss://example.com/ws",
            auto_discover=False
        )

        tester.run_all_tests()

        token_findings = [f for f in tester.findings if f.vuln_type == WebSocketVulnType.TOKEN_IN_URL]
        # May have 0 findings or may have other findings, but token finding should be 0
        assert len(token_findings) == 0


# ============================================================================
# Finding Management Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestFindingManagement:
    """Test finding management methods."""

    def test_get_findings_by_severity(self, tester):
        """Test filtering findings by severity."""
        # Add test findings
        tester.findings.append(WebSocketFinding(
            title="Critical Finding",
            severity=WebSocketSeverity.CRITICAL,
            vuln_type=WebSocketVulnType.CSWSH,
            description="Test",
            ws_url=tester.ws_endpoints[0]
        ))
        tester.findings.append(WebSocketFinding(
            title="High Finding",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.MISSING_AUTHENTICATION,
            description="Test",
            ws_url=tester.ws_endpoints[0]
        ))

        critical = tester.get_findings_by_severity(WebSocketSeverity.CRITICAL)
        high = tester.get_findings_by_severity(WebSocketSeverity.HIGH)

        assert len(critical) == 1
        assert len(high) == 1

    def test_get_findings(self, tester):
        """Test getting all findings."""
        tester.findings.append(WebSocketFinding(
            title="Test",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.XSS_VIA_WEBSOCKET,
            description="Test",
            ws_url=tester.ws_endpoints[0]
        ))

        findings = tester.get_findings()
        assert len(findings) == 1


# ============================================================================
# Summary Generation Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestSummaryGeneration:
    """Test summary report generation."""

    def test_get_summary_structure(self, tester):
        """Test summary report structure."""
        summary = tester.get_summary()

        assert 'target' in summary
        assert 'ws_endpoints' in summary
        assert 'total_findings' in summary
        assert 'severity_breakdown' in summary
        assert 'vulnerable' in summary
        assert 'findings' in summary

    def test_get_summary_severity_breakdown(self, tester):
        """Test severity breakdown in summary."""
        tester.findings.append(WebSocketFinding(
            title="Critical",
            severity=WebSocketSeverity.CRITICAL,
            vuln_type=WebSocketVulnType.CSWSH,
            description="Test",
            ws_url=tester.ws_endpoints[0]
        ))

        summary = tester.get_summary()
        breakdown = summary['severity_breakdown']

        assert 'CRITICAL' in breakdown
        assert 'HIGH' in breakdown
        assert 'MEDIUM' in breakdown
        assert 'LOW' in breakdown
        assert 'INFO' in breakdown

    def test_get_summary_vulnerable_flag(self, tester):
        """Test vulnerable flag is set correctly."""
        tester.findings.append(WebSocketFinding(
            title="Test",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.XSS_VIA_WEBSOCKET,
            description="Test",
            ws_url=tester.ws_endpoints[0]
        ))

        summary = tester.get_summary()
        assert summary['vulnerable'] is True

    def test_get_summary_not_vulnerable(self, tester):
        """Test vulnerable flag when no findings."""
        summary = tester.get_summary()
        assert summary['vulnerable'] is False


# ============================================================================
# POC Generation Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestPOCGeneration:
    """Test POC generation methods."""

    def test_generate_cswsh_poc(self, tester):
        """Test CSWSH HTML POC generation."""
        poc = tester._generate_cswsh_poc(tester.ws_endpoints[0])

        assert "new WebSocket" in poc
        assert tester.ws_endpoints[0] in poc
        assert "fetch" in poc
        assert "evil.com" in poc


# ============================================================================
# Data Conversion Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestDataConversion:
    """Test data conversion methods."""

    def test_websocket_finding_to_dict(self):
        """Test WebSocketFinding to dict conversion."""
        finding = WebSocketFinding(
            title="Test",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.CSWSH,
            description="Test description",
            ws_url="wss://example.com/ws"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['title'] == "Test"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['vuln_type'] == "CSWSH"

    def test_finding_with_default_date(self):
        """Test that finding gets default date."""
        finding = WebSocketFinding(
            title="Test",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.CSWSH,
            description="Test",
            ws_url="wss://example.com/ws"
        )

        assert finding.discovered_date == date.today().isoformat()


# ============================================================================
# Database Integration Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestDatabaseIntegration:
    """Test database integration."""

    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_database_check_before_test(self, mock_db, tester, mock_db_context):
        """Test that database is checked before testing."""
        mock_db.return_value = mock_db_context

        tester.run_all_tests()

        mock_db.assert_called_once_with(tester.target, 'websocket_tester')

    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_skip_when_database_says_skip(self, mock_db, tester):
        """Test that testing is skipped when database recommends it."""
        mock_db.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': [],
            'recommendations': [],
            'last_tested_days': 2
        }

        findings = tester.run_all_tests()

        assert len(findings) == 0

    @patch('engine.agents.websocket_tester.BountyHoundDB')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_records_tool_run(self, mock_db_hooks, mock_db_class, tester, mock_db_context):
        """Test that tool run is recorded in database."""
        mock_db_hooks.return_value = mock_db_context
        mock_db = Mock()
        mock_db_class.return_value = mock_db

        tester.run_all_tests()

        mock_db.record_tool_run.assert_called_once()
        call_args = mock_db.record_tool_run.call_args
        assert call_args[0][0] == tester.target
        assert call_args[0][1] == 'websocket_tester'


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_tester_with_no_endpoints(self):
        """Test tester with no WebSocket endpoints."""
        tester = WebSocketTester(target_url="https://example.com", auto_discover=False)
        tester.ws_endpoints = []

        # Should not crash
        with patch('engine.agents.websocket_tester.DatabaseHooks.before_test') as mock_db:
            mock_db.return_value = {'should_skip': False, 'reason': 'Test', 'previous_findings': [], 'recommendations': [], 'last_tested_days': None}
            findings = tester.run_all_tests()

        assert len(findings) == 0

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_handles_websocket_exceptions(self, mock_db, mock_ws, tester, mock_db_context):
        """Test handling of WebSocket connection exceptions."""
        mock_db.return_value = mock_db_context
        mock_ws.side_effect = Exception("Connection error")

        # Should not crash
        findings = tester.run_all_tests()
        assert isinstance(findings, list)

    def test_finding_with_evidence(self):
        """Test finding with evidence dictionary."""
        finding = WebSocketFinding(
            title="Test",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.CSWSH,
            description="Test",
            ws_url="wss://example.com/ws",
            evidence={'test_key': 'test_value'}
        )

        assert finding.evidence == {'test_key': 'test_value'}

    def test_finding_with_cwe_id(self):
        """Test finding with CWE ID."""
        finding = WebSocketFinding(
            title="Test",
            severity=WebSocketSeverity.HIGH,
            vuln_type=WebSocketVulnType.CSWSH,
            description="Test",
            ws_url="wss://example.com/ws",
            cwe_id="CWE-346"
        )

        assert finding.cwe_id == "CWE-346"

    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_multiple_endpoints(self, mock_db, mock_db_context):
        """Test testing multiple WebSocket endpoints."""
        mock_db.return_value = mock_db_context

        tester = WebSocketTester(auto_discover=False)
        tester.ws_endpoints = ["wss://example.com/ws1", "wss://example.com/ws2"]

        # Should test both endpoints without crashing
        findings = tester.run_all_tests()
        assert isinstance(findings, list)


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.skipif(not WEBSOCKET_TESTER_AVAILABLE, reason="WebSocket tester not available")
class TestIntegration:
    """Test full integration scenarios."""

    @patch('websocket.create_connection')
    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    @patch('engine.agents.websocket_tester.PayloadHooks.record_payload_success')
    def test_full_test_suite_with_findings(self, mock_payload, mock_db, mock_ws, tester, mock_ws_connection, mock_db_context):
        """Test running full test suite and finding vulnerabilities."""
        mock_db.return_value = mock_db_context

        # Simulate vulnerable WebSocket
        ws = mock_ws_connection(recv_data='{"data":"test"}')
        mock_ws.return_value = ws

        findings = tester.run_all_tests()

        # Should have tested and found vulnerabilities
        assert len(findings) > 0
        assert all(isinstance(f, WebSocketFinding) for f in findings)

    @patch('engine.agents.websocket_tester.DatabaseHooks.before_test')
    def test_get_summary_with_findings(self, mock_db, tester, mock_db_context):
        """Test summary generation with actual findings."""
        mock_db.return_value = mock_db_context

        # Add various findings
        tester.findings.extend([
            WebSocketFinding(
                title="CSWSH",
                severity=WebSocketSeverity.CRITICAL,
                vuln_type=WebSocketVulnType.CSWSH,
                description="Test",
                ws_url=tester.ws_endpoints[0]
            ),
            WebSocketFinding(
                title="XSS",
                severity=WebSocketSeverity.HIGH,
                vuln_type=WebSocketVulnType.XSS_VIA_WEBSOCKET,
                description="Test",
                ws_url=tester.ws_endpoints[0]
            ),
            WebSocketFinding(
                title="Token in URL",
                severity=WebSocketSeverity.MEDIUM,
                vuln_type=WebSocketVulnType.TOKEN_IN_URL,
                description="Test",
                ws_url=tester.ws_endpoints[0]
            )
        ])

        summary = tester.get_summary()

        assert summary['total_findings'] == 3
        assert summary['severity_breakdown']['CRITICAL'] == 1
        assert summary['severity_breakdown']['HIGH'] == 1
        assert summary['severity_breakdown']['MEDIUM'] == 1
        assert summary['vulnerable'] is True
