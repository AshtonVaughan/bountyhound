"""
Comprehensive tests for API Response Analyzer Agent

Tests cover:
- Error pattern analysis (stack traces, database errors, file paths, IPs)
- Security header auditing (HSTS, CSP, X-Frame-Options, etc.)
- Information leakage detection (API keys, emails, versions)
- Response timing analysis (user enumeration)
- Data consistency checks (IDOR detection)
- Response manipulation (cache poisoning, response splitting)
- Database integration
- Edge cases and error handling
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, date

from engine.agents.api_response_analyzer import (
    APIResponseAnalyzer,
    ResponseVulnerability,
    ResponseSeverity,
    ResponsePattern,
    InformationType
)


class TestAPIResponseAnalyzer:
    """Test API Response Analyzer functionality."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/users"]
        )

        assert analyzer.base_url == "https://api.example.com"
        assert analyzer.domain == "api.example.com"
        assert len(analyzer.endpoints) == 1
        assert analyzer.endpoints[0] == "/api/v1/users"
        assert len(analyzer.vulnerabilities) == 0

    def test_initialization_with_trailing_slash(self):
        """Test that trailing slash is removed from base_url."""
        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com/",
            endpoints=["/api/test"]
        )

        assert analyzer.base_url == "https://api.example.com"

    def test_discover_endpoints(self):
        """Test endpoint discovery."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        endpoints = analyzer.discover_endpoints()

        assert len(endpoints) > 0
        assert "/api/v1/users" in endpoints
        assert "/api/v1/auth/login" in endpoints
        assert "/graphql" in endpoints

    def test_contains_stack_trace(self):
        """Test stack trace detection."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        # Positive cases
        assert analyzer.contains_stack_trace("Traceback (most recent call last)")
        assert analyzer.contains_stack_trace("Stack trace:\n  at line 42")
        assert analyzer.contains_stack_trace("at Controller.handleRequest (server.js:123)")
        assert analyzer.contains_stack_trace("  File app.py:45 in view_function")
        assert analyzer.contains_stack_trace("Caused by: NullPointerException")

        # Negative cases
        assert not analyzer.contains_stack_trace("Normal error message")
        assert not analyzer.contains_stack_trace("Invalid request")

    def test_extract_stack_trace(self):
        """Test stack trace extraction."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        error_text = """
        Some error occurred.
        Traceback (most recent call last):
          File "/app/views.py", line 42, in get_user
            user = User.objects.get(id=user_id)
          File "/app/models.py", line 15, in get
            return self.filter(**kwargs).first()
        AttributeError: 'NoneType' object has no attribute 'first'
        """

        stack_trace = analyzer.extract_stack_trace(error_text)

        assert "Traceback" in stack_trace
        assert "/app/views.py" in stack_trace
        assert len(stack_trace) > 0

    def test_analyze_error_response_with_stack_trace(self):
        """Test analysis of error response with stack trace."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = """
        Traceback (most recent call last):
          File "/home/app/api/user.py", line 42, in get_user
            user = User.query.get(id)
        TypeError: 'NoneType' object is not subscriptable
        """

        vulns = analyzer.analyze_error_response("/api/v1/user", "Null value", mock_response)

        assert len(vulns) >= 1
        stack_vuln = [v for v in vulns if v.vuln_id == "RESP-STACK-001"]
        assert len(stack_vuln) == 1

        vuln = stack_vuln[0]
        assert vuln.severity == ResponseSeverity.MEDIUM
        assert "Stack Trace" in vuln.title
        assert vuln.cwe == "CWE-209"
        assert vuln.cvss_score == 5.3

    def test_analyze_error_response_with_database_error(self):
        """Test analysis of database error disclosure."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        db_errors = [
            ("SQL syntax error near 'SELECT'", "SQL syntax error"),
            ("ORA-00942: table or view does not exist", "Oracle error"),
            ("MySQL error: Unknown column 'id'", "MySQL error"),
            ("PostgreSQL error: relation does not exist", "PostgreSQL error"),
            ("MongoDB error: collection not found", "MongoDB error"),
        ]

        for error_text, expected_type in db_errors:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = error_text

            vulns = analyzer.analyze_error_response("/api/v1/query", "SQL injection", mock_response)

            db_vulns = [v for v in vulns if "Database Error" in v.title]
            assert len(db_vulns) >= 1, f"Failed to detect: {expected_type}"

            vuln = db_vulns[0]
            assert vuln.severity == ResponseSeverity.HIGH
            assert vuln.cwe == "CWE-209"
            assert vuln.cvss_score == 6.5

    def test_analyze_error_response_with_file_path(self):
        """Test detection of file path disclosure."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        file_paths = [
            "/home/ubuntu/app/server.py",
            "C:\\Users\\Admin\\Projects\\api\\handler.js",
            "/var/www/html/index.php",
            "/usr/local/app/config.py",
        ]

        for file_path in file_paths:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = f"Error in file {file_path}"

            vulns = analyzer.analyze_error_response("/api/v1/test", "Empty request", mock_response)

            path_vulns = [v for v in vulns if v.vuln_id == "RESP-PATH-001"]
            assert len(path_vulns) == 1, f"Failed to detect path: {file_path}"

            vuln = path_vulns[0]
            assert vuln.severity == ResponseSeverity.LOW
            assert file_path in vuln.evidence["file_path"]

    def test_analyze_error_response_with_internal_ip(self):
        """Test detection of internal IP address disclosure."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        internal_ips = [
            "10.0.0.5",
            "172.16.0.10",
            "192.168.1.100",
            "172.31.255.255",
        ]

        for ip in internal_ips:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = f"Failed to connect to database at {ip}"

            vulns = analyzer.analyze_error_response("/api/v1/db", "Large ID", mock_response)

            ip_vulns = [v for v in vulns if v.vuln_id == "RESP-IP-001"]
            assert len(ip_vulns) == 1, f"Failed to detect IP: {ip}"

            vuln = ip_vulns[0]
            assert vuln.severity == ResponseSeverity.LOW
            assert ip in vuln.evidence["internal_ip"]

    @patch('requests.Session.get')
    def test_audit_security_headers_all_missing(self, mock_get):
        """Test security header audit when all headers are missing."""
        mock_response = Mock()
        mock_response.headers = {
            "Content-Type": "application/json"
        }
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        vulns = analyzer.audit_security_headers()

        # Should detect missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
        assert len(vulns) >= 6

        # Check HSTS
        hsts_vulns = [v for v in vulns if "Strict-Transport-Security" in v.title]
        assert len(hsts_vulns) == 1
        assert hsts_vulns[0].severity == ResponseSeverity.HIGH

        # Check CSP
        csp_vulns = [v for v in vulns if "Content-Security-Policy" in v.title and "Missing" in v.title]
        assert len(csp_vulns) == 1
        assert csp_vulns[0].severity == ResponseSeverity.MEDIUM

    @patch('requests.Session.get')
    def test_audit_security_headers_weak_csp(self, mock_get):
        """Test detection of weak CSP with unsafe-inline."""
        mock_response = Mock()
        mock_response.headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
        }
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        vulns = analyzer.audit_security_headers()

        weak_csp_vulns = [v for v in vulns if v.vuln_id == "RESP-CSP-WEAK"]
        assert len(weak_csp_vulns) == 1

        vuln = weak_csp_vulns[0]
        assert vuln.severity == ResponseSeverity.MEDIUM
        assert "unsafe-inline" in vuln.description

    @patch('requests.Session.get')
    def test_audit_security_headers_server_version(self, mock_get):
        """Test detection of server version disclosure."""
        mock_response = Mock()
        mock_response.headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3"
        }
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        vulns = analyzer.audit_security_headers()

        # Check server version
        server_vulns = [v for v in vulns if v.vuln_id == "RESP-SERVER-VERSION"]
        assert len(server_vulns) == 1
        assert "Apache/2.4.41" in server_vulns[0].evidence["server_header"]

        # Check X-Powered-By
        powered_vulns = [v for v in vulns if v.vuln_id == "RESP-POWERED-BY"]
        assert len(powered_vulns) == 1
        assert "PHP/7.4.3" in powered_vulns[0].evidence["x_powered_by"]

    @patch('requests.Session.get')
    def test_detect_information_leakage_emails(self, mock_get):
        """Test detection of email address exposure."""
        mock_response = Mock()
        mock_response.text = """
        {
            "error": "Contact admin@example.com or support@test.com for help"
        }
        """
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/error"]
        )

        vulns = analyzer.detect_information_leakage()

        email_vulns = [v for v in vulns if v.vuln_id == "RESP-INFO-EMAIL"]
        assert len(email_vulns) == 1

        vuln = email_vulns[0]
        assert vuln.severity == ResponseSeverity.LOW
        assert vuln.evidence["email_count"] == 2

    @patch('requests.Session.get')
    def test_detect_information_leakage_api_key(self, mock_get):
        """Test detection of API key exposure."""
        mock_response = Mock()
        mock_response.text = """
        {
            "config": {
                "api_key": "sk_live_1234567890abcdefghijklmnop"
            }
        }
        """
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/config"]
        )

        vulns = analyzer.detect_information_leakage()

        api_key_vulns = [v for v in vulns if "API_KEY" in v.vuln_id]
        assert len(api_key_vulns) == 1

        vuln = api_key_vulns[0]
        assert vuln.severity == ResponseSeverity.CRITICAL
        assert vuln.cvss_score == 9.1
        assert "sk_live_12" in vuln.evidence["value_preview"]

    @patch('requests.Session.get')
    def test_detect_information_leakage_version(self, mock_get):
        """Test detection of version information."""
        mock_response = Mock()
        mock_response.text = """
        {
            "version": "1.2.3",
            "build": "a1b2c3d4"
        }
        """
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/health"]
        )

        vulns = analyzer.detect_information_leakage()

        version_vulns = [v for v in vulns if v.vuln_id == "RESP-INFO-VERSION"]
        assert len(version_vulns) == 1

        vuln = version_vulns[0]
        assert vuln.severity == ResponseSeverity.INFO
        assert vuln.cvss_score == 2.0

    @patch('requests.Session.post')
    def test_analyze_timing_user_enumeration(self, mock_post):
        """Test detection of timing-based user enumeration."""
        # Simulate timing difference: existing user = 500ms, nonexistent = 100ms
        call_count = [0]

        def mock_post_timing(*args, **kwargs):
            call_count[0] += 1
            mock_resp = Mock()
            mock_resp.status_code = 401

            # Simulate timing difference
            if "admin" in str(kwargs.get('json', {})) or "user@example.com" in str(kwargs.get('json', {})):
                time.sleep(0.15)  # 150ms for existing users
            else:
                time.sleep(0.01)  # 10ms for nonexistent users

            return mock_resp

        mock_post.side_effect = mock_post_timing

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/auth/login"]
        )

        vulns = analyzer.analyze_timing()

        timing_vulns = [v for v in vulns if v.vuln_id == "RESP-TIMING-001"]
        assert len(timing_vulns) == 1

        vuln = timing_vulns[0]
        assert vuln.severity == ResponseSeverity.MEDIUM
        assert vuln.evidence["difference_ms"] > 100
        assert "User Enumeration" in vuln.title

    @patch('requests.Session.get')
    def test_check_data_consistency_idor(self, mock_get):
        """Test detection of potential IDOR via response consistency."""
        # All IDs return 200 = potential IDOR
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"user": "data"}'
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/user/{id}"]
        )

        vulns = analyzer.check_data_consistency()

        idor_vulns = [v for v in vulns if v.vuln_id == "RESP-IDOR-001"]
        assert len(idor_vulns) == 1

        vuln = idor_vulns[0]
        assert vuln.severity == ResponseSeverity.HIGH
        assert vuln.evidence["all_successful"] is True
        assert vuln.cwe == "CWE-639"
        assert vuln.cvss_score == 7.5

    @patch('requests.Session.get')
    def test_test_response_manipulation_splitting(self, mock_get):
        """Test detection of HTTP response splitting."""
        mock_response = Mock()
        mock_response.headers = {
            "Set-Cookie": "session=abc123; malicious=true"
        }
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        vulns = analyzer.test_response_manipulation()

        split_vulns = [v for v in vulns if v.vuln_id == "RESP-SPLIT-001"]
        assert len(split_vulns) == 1

        vuln = split_vulns[0]
        assert vuln.severity == ResponseSeverity.HIGH
        assert "Response Splitting" in vuln.title
        assert vuln.cwe == "CWE-113"

    @patch('requests.Session.get')
    def test_test_response_manipulation_cache_poisoning(self, mock_get):
        """Test detection of cache poisoning."""
        mock_response = Mock()
        mock_response.text = '<a href="https://evil.com">Click here</a>'
        mock_response.headers = {}
        mock_get.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        vulns = analyzer.test_response_manipulation()

        cache_vulns = [v for v in vulns if "RESP-CACHE" in v.vuln_id]
        assert len(cache_vulns) >= 1

        vuln = cache_vulns[0]
        assert vuln.severity == ResponseSeverity.HIGH
        assert "Cache Poisoning" in vuln.title
        assert vuln.cwe == "CWE-444"

    def test_response_vulnerability_to_dict(self):
        """Test converting ResponseVulnerability to dictionary."""
        vuln = ResponseVulnerability(
            vuln_id="TEST-001",
            severity=ResponseSeverity.HIGH,
            title="Test Vulnerability",
            description="This is a test",
            endpoint="/api/v1/test",
            evidence={"key": "value"},
            remediation="Fix it",
            cwe="CWE-123",
            cvss_score=7.5
        )

        vuln_dict = vuln.to_dict()

        assert isinstance(vuln_dict, dict)
        assert vuln_dict["vuln_id"] == "TEST-001"
        assert vuln_dict["severity"] == "high"
        assert vuln_dict["title"] == "Test Vulnerability"
        assert vuln_dict["cvss_score"] == 7.5

    @patch('requests.Session.get')
    @patch('requests.Session.post')
    def test_run_comprehensive_analysis(self, mock_post, mock_get):
        """Test full comprehensive analysis."""
        # Mock responses
        mock_get_resp = Mock()
        mock_get_resp.headers = {"Content-Type": "application/json"}
        mock_get_resp.text = '{"status": "ok"}'
        mock_get_resp.status_code = 200
        mock_get.return_value = mock_get_resp

        mock_post_resp = Mock()
        mock_post_resp.status_code = 400
        mock_post_resp.text = "Bad request"
        mock_post.return_value = mock_post_resp

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        results = analyzer.run_comprehensive_analysis()

        assert "target" in results
        assert "domain" in results
        assert results["target"] == "https://api.example.com"
        assert results["domain"] == "api.example.com"
        assert "tests_run" in results
        assert len(results["tests_run"]) == 6  # 6 phases

        # Check phases
        assert "error_patterns" in results["tests_run"]
        assert "security_headers" in results["tests_run"]
        assert "information_disclosure" in results["tests_run"]
        assert "timing_analysis" in results["tests_run"]
        assert "data_consistency" in results["tests_run"]
        assert "response_manipulation" in results["tests_run"]

    def test_get_summary(self):
        """Test getting analysis summary."""
        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        # Add some test vulnerabilities
        analyzer.vulnerabilities.append(ResponseVulnerability(
            vuln_id="TEST-001",
            severity=ResponseSeverity.CRITICAL,
            title="Critical Test",
            description="Test",
            endpoint="/test",
            evidence={},
            remediation="Fix"
        ))

        analyzer.vulnerabilities.append(ResponseVulnerability(
            vuln_id="TEST-002",
            severity=ResponseSeverity.HIGH,
            title="High Test",
            description="Test",
            endpoint="/test",
            evidence={},
            remediation="Fix"
        ))

        summary = analyzer.get_summary()

        assert summary["target"] == "https://api.example.com"
        assert summary["total_vulnerabilities"] == 2
        assert summary["vulnerabilities_by_severity"]["critical"] == 1
        assert summary["vulnerabilities_by_severity"]["high"] == 1

    @patch('builtins.open', create=True)
    def test_generate_report(self, mock_open):
        """Test report generation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        analyzer.vulnerabilities.append(ResponseVulnerability(
            vuln_id="TEST-001",
            severity=ResponseSeverity.HIGH,
            title="Test",
            description="Test",
            endpoint="/test",
            evidence={},
            remediation="Fix"
        ))

        analyzer.generate_report("test-report.json")

        mock_open.assert_called_once_with("test-report.json", 'w')
        mock_file.write.assert_called()

    def test_custom_session(self):
        """Test using custom session."""
        custom_session = Mock()
        custom_session.headers = {}

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            session=custom_session
        )

        assert analyzer.session == custom_session

    def test_custom_db_path(self):
        """Test using custom database path."""
        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            db_path=":memory:"
        )

        assert analyzer.db is not None

    @patch('requests.Session.get')
    def test_error_handling_in_header_audit(self, mock_get):
        """Test error handling during header audit."""
        mock_get.side_effect = Exception("Network error")

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        # Should not raise exception
        vulns = analyzer.audit_security_headers()
        assert isinstance(vulns, list)

    @patch('requests.Session.get')
    def test_error_handling_in_info_leakage(self, mock_get):
        """Test error handling during information leakage detection."""
        mock_get.side_effect = Exception("Timeout")

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        # Should not raise exception
        vulns = analyzer.detect_information_leakage()
        assert isinstance(vulns, list)

    @patch('requests.Session.post')
    def test_error_handling_in_timing_analysis(self, mock_post):
        """Test error handling during timing analysis."""
        mock_post.side_effect = Exception("Connection refused")

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/auth/login"]
        )

        # Should not raise exception
        vulns = analyzer.analyze_timing()
        assert isinstance(vulns, list)


class TestResponseSeverity:
    """Test ResponseSeverity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert ResponseSeverity.CRITICAL.value == "critical"
        assert ResponseSeverity.HIGH.value == "high"
        assert ResponseSeverity.MEDIUM.value == "medium"
        assert ResponseSeverity.LOW.value == "low"
        assert ResponseSeverity.INFO.value == "info"


class TestInformationType:
    """Test InformationType enum."""

    def test_information_types(self):
        """Test information type enum values."""
        assert InformationType.VERSION_NUMBER.value == "version_number"
        assert InformationType.STACK_TRACE.value == "stack_trace"
        assert InformationType.DATABASE_ERROR.value == "database_error"
        assert InformationType.API_KEY.value == "api_key"


class TestResponsePattern:
    """Test ResponsePattern dataclass."""

    def test_response_pattern_creation(self):
        """Test creating a response pattern."""
        pattern = ResponsePattern(
            status_code=200,
            response_time_ms=150.5,
            content_length=1024,
            content_hash="abc123",
            headers={"Content-Type": "application/json"}
        )

        assert pattern.status_code == 200
        assert pattern.response_time_ms == 150.5
        assert pattern.content_length == 1024


class TestDatabaseIntegration:
    """Test database integration."""

    @patch('engine.core.db_hooks.DatabaseHooks.before_test')
    @patch('engine.core.database.BountyHoundDB.record_tool_run')
    @patch('requests.Session.get')
    @patch('requests.Session.post')
    def test_database_before_test_check(self, mock_post, mock_get, mock_record, mock_before):
        """Test that database is checked before testing."""
        # Mock database response
        mock_before.return_value = {
            'should_skip': False,
            'reason': 'Last tested 30 days ago',
            'previous_findings': [],
            'recommendations': ['Full retest recommended'],
            'last_tested_days': 30
        }

        mock_get_resp = Mock()
        mock_get_resp.headers = {}
        mock_get_resp.text = '{"status": "ok"}'
        mock_get_resp.status_code = 200
        mock_get.return_value = mock_get_resp

        mock_post_resp = Mock()
        mock_post_resp.status_code = 400
        mock_post_resp.text = "Error"
        mock_post.return_value = mock_post_resp

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        results = analyzer.run_comprehensive_analysis()

        # Verify database hook was called
        mock_before.assert_called_once_with("api.example.com", "api_response_analyzer")

        # Verify tool run was recorded
        assert mock_record.called

    @patch('engine.core.db_hooks.DatabaseHooks.before_test')
    def test_database_skip_recent_test(self, mock_before):
        """Test skipping recently tested target."""
        # Mock database response indicating recent test
        mock_before.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': [],
            'recommendations': ['Skip this target'],
            'last_tested_days': 2
        }

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        results = analyzer.run_comprehensive_analysis()

        # Should skip testing
        assert results.get('skipped') is True
        assert 'Tested 2 days ago' in results['skip_reason']


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_endpoints_list(self):
        """Test with empty endpoints list."""
        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=[]
        )

        # Should discover default endpoints
        assert len(analyzer.endpoints) == 0

    def test_none_endpoints(self):
        """Test with None endpoints (should discover)."""
        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=None
        )

        # Should discover default endpoints
        assert len(analyzer.endpoints) > 0

    @patch('requests.Session.post')
    def test_analyze_error_patterns_no_errors(self, mock_post):
        """Test error pattern analysis when no errors occur."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_post.return_value = mock_response

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/test"]
        )

        vulns = analyzer.analyze_error_patterns()

        # No vulnerabilities should be found
        assert len(vulns) == 0

    def test_extract_stack_trace_no_trace(self):
        """Test stack trace extraction when there is no trace."""
        analyzer = APIResponseAnalyzer(base_url="https://api.example.com")

        result = analyzer.extract_stack_trace("Just a normal error message")

        assert result == ""

    @patch('requests.Session.get')
    def test_timing_analysis_no_auth_endpoints(self, mock_get):
        """Test timing analysis when no auth endpoints exist."""
        mock_get.return_value = Mock()

        analyzer = APIResponseAnalyzer(
            base_url="https://api.example.com",
            endpoints=["/api/v1/products", "/api/v1/search"]  # No auth endpoints
        )

        vulns = analyzer.analyze_timing()

        # Should not crash, may return empty list
        assert isinstance(vulns, list)
