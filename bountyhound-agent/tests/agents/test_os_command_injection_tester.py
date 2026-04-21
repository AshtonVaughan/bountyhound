"""
Unit tests for OS Command Injection Tester Agent

Tests for:
- Payload generation (inline, blind, OOB, encoded)
- Platform detection
- Time-based analysis
- Response analysis
- Finding generation
- Database integration
- Encoding techniques
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from engine.agents.os_command_injection_tester import (
    CommandInjectionTester,
    PayloadGenerator,
    ShellEncoder,
    TimeAnalyzer,
    ResponseAnalyzer,
    Platform,
    InjectionType,
    Context,
    SeverityLevel,
    CommandPayload,
    InjectionFinding
)


class TestShellEncoder:
    """Test shell encoding and obfuscation techniques"""

    def test_bash_variable_expansion(self):
        """Test bash variable expansion encoding"""
        encoder = ShellEncoder()
        variants = encoder.bash_variable_expansion("whoami")

        assert len(variants) >= 3
        # Check that variants use IFS or other variable expansion
        assert any('IFS' in v or '$@' in v or 'PATH' in v for v in variants)

    def test_quote_evasion(self):
        """Test quote-based evasion"""
        encoder = ShellEncoder()
        variants = encoder.quote_evasion("whoami")

        assert len(variants) >= 3
        assert any("'" in v for v in variants)
        assert any('"' in v for v in variants)
        assert any('\\' in v for v in variants)

    def test_hex_encoding(self):
        """Test hex encoding techniques"""
        encoder = ShellEncoder()
        variants = encoder.hex_encoding("whoami")

        assert len(variants) >= 2
        assert any('xxd' in v for v in variants)
        assert any('printf' in v for v in variants)
        assert any('\\x' in v for v in variants)

    def test_base64_encoding(self):
        """Test base64 encoding"""
        encoder = ShellEncoder()
        variants = encoder.base64_encoding("whoami")

        assert len(variants) >= 2
        assert all('base64' in v for v in variants)
        assert any('echo' in v for v in variants)

    def test_wildcard_abuse(self):
        """Test wildcard-based obfuscation"""
        encoder = ShellEncoder()
        variants = encoder.wildcard_abuse("whoami")

        assert len(variants) >= 2
        assert any('?' in v for v in variants)
        assert any('*' in v for v in variants)

    def test_windows_encoding(self):
        """Test Windows-specific encoding"""
        encoder = ShellEncoder()
        variants = encoder.windows_encoding("whoami")

        assert len(variants) >= 1
        assert any('^' in v for v in variants)


class TestPayloadGenerator:
    """Test payload generation"""

    def test_generate_inline_payloads_unix(self):
        """Test Unix inline payload generation"""
        gen = PayloadGenerator()
        payloads = gen.generate_inline_payloads(Platform.UNIX)

        assert len(payloads) > 0
        assert all(isinstance(p, CommandPayload) for p in payloads)
        assert all(p.injection_type == InjectionType.INLINE for p in payloads)
        assert all(p.platform == Platform.UNIX for p in payloads)

        # Check operators
        operators = {p.operator for p in payloads}
        assert ';' in operators
        assert '|' in operators
        assert '&&' in operators

    def test_generate_inline_payloads_windows(self):
        """Test Windows inline payload generation"""
        gen = PayloadGenerator()
        payloads = gen.generate_inline_payloads(Platform.WINDOWS)

        assert len(payloads) > 0
        assert all(p.platform == Platform.WINDOWS for p in payloads)

        # Check for Windows commands
        commands = {p.command for p in payloads}
        assert any('whoami' in c for c in commands)
        assert any('ipconfig' in c or 'systeminfo' in c for c in commands)

    def test_generate_blind_time_payloads(self):
        """Test blind time-based payload generation"""
        gen = PayloadGenerator()
        payloads = gen.generate_blind_time_payloads(Platform.UNIX, delay=5)

        assert len(payloads) > 0
        assert all(p.injection_type == InjectionType.BLIND_TIME for p in payloads)
        assert any('sleep' in p.command for p in payloads)
        assert any('5' in p.command for p in payloads)  # Check delay replacement

    def test_generate_oob_payloads_unix(self):
        """Test OOB payload generation for Unix"""
        gen = PayloadGenerator()
        payloads = gen.generate_oob_payloads("burpcollaborator.net", Platform.UNIX)

        assert len(payloads) > 0
        assert all(p.injection_type == InjectionType.BLIND_OOB for p in payloads)
        assert any('curl' in p.command for p in payloads)
        assert any('wget' in p.command for p in payloads)
        assert any('nslookup' in p.command for p in payloads)
        assert all('burpcollaborator.net' in p.command for p in payloads)

    def test_generate_oob_payloads_windows(self):
        """Test OOB payload generation for Windows"""
        gen = PayloadGenerator()
        payloads = gen.generate_oob_payloads("burpcollaborator.net", Platform.WINDOWS)

        assert len(payloads) > 0
        assert any('nslookup' in p.command for p in payloads)
        assert any('certutil' in p.command for p in payloads)

    def test_generate_encoded_payloads_unix(self):
        """Test encoded payload generation for Unix"""
        gen = PayloadGenerator()
        payloads = gen.generate_encoded_payloads("whoami", Platform.UNIX)

        assert len(payloads) > 10  # Should have many variants
        assert all(p.encoded for p in payloads)
        assert any('IFS' in p.command for p in payloads)
        assert any('base64' in p.command for p in payloads)

    def test_generate_encoded_payloads_windows(self):
        """Test encoded payload generation for Windows"""
        gen = PayloadGenerator()
        payloads = gen.generate_encoded_payloads("whoami", Platform.WINDOWS)

        assert len(payloads) > 0
        assert all(p.platform == Platform.WINDOWS for p in payloads)
        assert all(p.encoded for p in payloads)

    def test_generate_context_specific_shell_arg(self):
        """Test shell argument context payloads"""
        gen = PayloadGenerator()
        payloads = gen.generate_context_specific(Context.SHELL_ARG, Platform.UNIX)

        assert len(payloads) > 0
        assert all(p.context == Context.SHELL_ARG for p in payloads)
        assert any('-option' in p.payload for p in payloads)
        assert any('--flag' in p.payload for p in payloads)

    def test_generate_context_specific_url(self):
        """Test URL context payloads"""
        gen = PayloadGenerator()
        payloads = gen.generate_context_specific(Context.URL, Platform.UNIX)

        assert len(payloads) > 0
        assert all(p.context == Context.URL for p in payloads)
        assert any('http://' in p.payload for p in payloads)
        assert any('ftp://' in p.payload for p in payloads)

    def test_generate_context_specific_json(self):
        """Test JSON context payloads"""
        gen = PayloadGenerator()
        payloads = gen.generate_context_specific(Context.JSON, Platform.UNIX)

        assert len(payloads) > 0
        assert all(p.context == Context.JSON for p in payloads)
        assert any('{"cmd"' in p.payload for p in payloads)
        assert any('{"exec"' in p.payload for p in payloads)

    def test_generate_all_payloads(self):
        """Test comprehensive payload generation"""
        gen = PayloadGenerator()
        payloads = gen.generate_all_payloads(Platform.UNIX, "attacker.com")

        assert len(payloads) >= 30  # Should generate 30+ payloads
        assert any(p.injection_type == InjectionType.INLINE for p in payloads)
        assert any(p.injection_type == InjectionType.BLIND_TIME for p in payloads)
        assert any(p.injection_type == InjectionType.BLIND_OOB for p in payloads)
        assert any(p.encoded for p in payloads)


class TestTimeAnalyzer:
    """Test time-based analysis"""

    def test_establish_baseline(self):
        """Test baseline establishment"""
        analyzer = TimeAnalyzer()
        times = [0.5, 0.6, 0.55]
        baseline = analyzer.establish_baseline(times)

        assert baseline > 0
        assert 0.5 <= baseline <= 0.6
        assert analyzer.baseline_time is not None

    def test_is_delayed_positive(self):
        """Test delayed response detection (positive)"""
        analyzer = TimeAnalyzer()
        analyzer.baseline_time = 0.5

        # Response took 10.5s, baseline 0.5s = 10s delay
        assert analyzer.is_delayed(10.5, expected_delay=10)

    def test_is_delayed_negative(self):
        """Test delayed response detection (negative)"""
        analyzer = TimeAnalyzer()
        analyzer.baseline_time = 0.5

        # Response took 1.5s, baseline 0.5s = 1s delay (not 10s)
        assert not analyzer.is_delayed(1.5, expected_delay=10)

    def test_calculate_confidence_high(self):
        """Test confidence calculation (high confidence)"""
        analyzer = TimeAnalyzer()
        analyzer.baseline_time = 0.5

        # Exact 10s delay
        confidence = analyzer.calculate_confidence(10.5, expected_delay=10)
        assert confidence >= 0.9

    def test_calculate_confidence_medium(self):
        """Test confidence calculation (medium confidence)"""
        analyzer = TimeAnalyzer()
        analyzer.baseline_time = 0.5

        # 12s delay (1.2x the expected 10s) = 85% confidence
        confidence = analyzer.calculate_confidence(12.5, expected_delay=10)
        assert confidence == 0.85

    def test_calculate_confidence_low(self):
        """Test confidence calculation (low confidence)"""
        analyzer = TimeAnalyzer()
        analyzer.baseline_time = 0.5

        # 5s delay (not enough)
        confidence = analyzer.calculate_confidence(5.5, expected_delay=10)
        assert confidence == 0.0


class TestResponseAnalyzer:
    """Test response analysis"""

    def test_analyze_inline_whoami(self):
        """Test inline analysis with whoami output"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; whoami",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='whoami',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 200,
            'headers': {},
            'body': 'www-data'
        }

        finding = analyzer.analyze_inline(response, payload)

        assert finding is not None
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.injection_type == InjectionType.INLINE
        assert 'www-data' in finding.evidence

    def test_analyze_inline_id_command(self):
        """Test inline analysis with id command output"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; id",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='id',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 200,
            'headers': {},
            'body': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
        }

        finding = analyzer.analyze_inline(response, payload)

        assert finding is not None
        assert finding.severity == SeverityLevel.CRITICAL
        assert 'uid=' in finding.command_output

    def test_analyze_inline_no_match(self):
        """Test inline analysis with no command output"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; whoami",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='whoami',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 200,
            'headers': {},
            'body': 'Invalid command'
        }

        finding = analyzer.analyze_inline(response, payload)

        assert finding is None

    def test_analyze_inline_error_status(self):
        """Test inline analysis skips 4xx errors"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; whoami",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='whoami',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 403,
            'headers': {},
            'body': 'www-data'
        }

        finding = analyzer.analyze_inline(response, payload)

        assert finding is None

    def test_analyze_inline_500_error(self):
        """Test inline analysis checks 500 errors"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; id",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='id',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 500,
            'headers': {},
            'body': 'Error: uid=33(www-data) gid=33(www-data)'
        }

        finding = analyzer.analyze_inline(response, payload)

        assert finding is not None  # 500 errors are checked with command output

    def test_analyze_blind_time_positive(self):
        """Test blind time-based detection (positive)"""
        analyzer = ResponseAnalyzer()
        analyzer.time_analyzer.baseline_time = 0.5

        payload = CommandPayload(
            payload="; sleep 10",
            injection_type=InjectionType.BLIND_TIME,
            platform=Platform.UNIX,
            operator=';',
            command='sleep 10',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 200,
            'headers': {},
            'body': '',
            'response_time': 10.5
        }

        finding = analyzer.analyze_blind_time(response, payload, expected_delay=10)

        assert finding is not None
        assert finding.injection_type == InjectionType.BLIND_TIME
        assert finding.severity == SeverityLevel.HIGH
        assert 'delayed' in finding.evidence.lower()

    def test_analyze_blind_time_negative(self):
        """Test blind time-based detection (negative)"""
        analyzer = ResponseAnalyzer()
        analyzer.time_analyzer.baseline_time = 0.5

        payload = CommandPayload(
            payload="; sleep 10",
            injection_type=InjectionType.BLIND_TIME,
            platform=Platform.UNIX,
            operator=';',
            command='sleep 10',
            context=Context.UNKNOWN
        )
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 200,
            'headers': {},
            'body': '',
            'response_time': 1.5
        }

        finding = analyzer.analyze_blind_time(response, payload, expected_delay=10)

        assert finding is None

    def test_has_command_output_indicators(self):
        """Test command output indicator detection"""
        analyzer = ResponseAnalyzer()

        # Test positive cases
        assert analyzer._has_command_output_indicators('uid=1000')
        assert analyzer._has_command_output_indicators('root:x:0:0:')
        assert analyzer._has_command_output_indicators('/bin/bash')
        assert analyzer._has_command_output_indicators('C:\\Windows\\System32')
        assert analyzer._has_command_output_indicators('Linux version 5.4')

        # Test negative case
        assert not analyzer._has_command_output_indicators('Hello World')

    def test_calculate_severity_critical(self):
        """Test critical severity calculation"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; whoami",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='whoami',
            context=Context.UNKNOWN
        )

        severity = analyzer._calculate_severity(payload, 'www-data')
        assert severity == SeverityLevel.CRITICAL

    def test_calculate_severity_sensitive_data(self):
        """Test critical severity for sensitive data"""
        analyzer = ResponseAnalyzer()
        payload = CommandPayload(
            payload="; cat config",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='cat config',
            context=Context.UNKNOWN
        )

        severity = analyzer._calculate_severity(payload, 'password=secret123')
        assert severity == SeverityLevel.CRITICAL

    def test_generate_impact(self):
        """Test impact generation"""
        analyzer = ResponseAnalyzer()

        payload_whoami = CommandPayload(
            payload="; whoami",
            injection_type=InjectionType.INLINE,
            platform=Platform.UNIX,
            operator=';',
            command='whoami',
            context=Context.UNKNOWN
        )

        impact = analyzer._generate_impact(payload_whoami)
        assert 'arbitrary command execution' in impact.lower()

    def test_generate_remediation(self):
        """Test remediation generation"""
        analyzer = ResponseAnalyzer()
        remediation = analyzer._generate_remediation()

        assert 'never pass user input' in remediation.lower()
        assert 'parameterized' in remediation.lower()
        assert 'validation' in remediation.lower()

    def test_calculate_cvss(self):
        """Test CVSS score calculation"""
        analyzer = ResponseAnalyzer()

        assert analyzer._calculate_cvss(SeverityLevel.CRITICAL) == 9.8
        assert analyzer._calculate_cvss(SeverityLevel.HIGH) == 8.5
        assert analyzer._calculate_cvss(SeverityLevel.MEDIUM) == 6.5
        assert analyzer._calculate_cvss(SeverityLevel.LOW) == 4.0
        assert analyzer._calculate_cvss(SeverityLevel.INFO) == 0.0


class TestCommandInjectionTester:
    """Test main testing engine"""

    def test_init(self):
        """Test tester initialization"""
        tester = CommandInjectionTester(target="example.com")

        assert tester.target == "example.com"
        assert tester.payload_gen is not None
        assert tester.analyzer is not None
        assert len(tester.findings) == 0

    def test_detect_platform_windows(self):
        """Test Windows platform detection"""
        tester = CommandInjectionTester()
        response = {
            'headers': {'Server': 'Microsoft-IIS/10.0'}
        }

        platform = tester.detect_platform(response)
        assert platform == Platform.WINDOWS

    def test_detect_platform_unix(self):
        """Test Unix platform detection"""
        tester = CommandInjectionTester()
        response = {
            'headers': {'Server': 'nginx/1.18.0'}
        }

        platform = tester.detect_platform(response)
        assert platform == Platform.UNIX

    def test_detect_platform_unknown(self):
        """Test unknown platform detection"""
        tester = CommandInjectionTester()
        response = {
            'headers': {'Server': 'CustomServer/1.0'}
        }

        platform = tester.detect_platform(response)
        assert platform == Platform.UNKNOWN

    @patch('engine.agents.os_command_injection_tester.requests.get')
    @patch('engine.agents.os_command_injection_tester.DatabaseHooks.before_test')
    def test_test_endpoint_basic(self, mock_db_check, mock_get):
        """Test basic endpoint testing"""
        # Mock database check to not skip
        mock_db_check.return_value = {
            'should_skip': False,
            'reason': 'Never tested before',
            'previous_findings': [],
            'recommendations': []
        }

        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = 'www-data'
        mock_get.return_value = mock_response

        tester = CommandInjectionTester(target="example.com")

        # Test with limited payloads for speed
        with patch.object(tester.payload_gen, 'generate_inline_payloads') as mock_inline:
            mock_inline.return_value = [
                CommandPayload(
                    payload="; whoami",
                    injection_type=InjectionType.INLINE,
                    platform=Platform.UNIX,
                    operator=';',
                    command='whoami',
                    context=Context.UNKNOWN
                )
            ]

            findings = tester.test_endpoint(
                url="https://example.com/api",
                parameter="cmd",
                platform=Platform.UNIX,
                test_inline=True,
                test_blind=False,
                test_oob=False
            )

        assert tester.tests_run > 0

    @patch('engine.agents.os_command_injection_tester.DatabaseHooks.before_test')
    def test_test_endpoint_skip(self, mock_db_check):
        """Test endpoint testing with database skip"""
        # Mock database check to skip
        mock_db_check.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': [],
            'recommendations': []
        }

        tester = CommandInjectionTester(target="example.com")
        findings = tester.test_endpoint(
            url="https://example.com/api",
            parameter="cmd",
            platform=Platform.UNIX
        )

        assert len(findings) == 0

    def test_generate_report_no_findings(self):
        """Test report generation with no findings"""
        tester = CommandInjectionTester()
        tester.tests_run = 50

        report = tester.generate_report()

        assert report['status'] == 'no_findings'
        assert report['total_tests'] == 50
        assert len(report['findings']) == 0

    def test_generate_report_with_findings(self):
        """Test report generation with findings"""
        tester = CommandInjectionTester()
        tester.tests_run = 50

        # Add mock findings
        tester.findings = [
            InjectionFinding(
                endpoint="https://example.com/api",
                parameter="cmd",
                payload="; whoami",
                injection_type=InjectionType.INLINE,
                platform=Platform.UNIX,
                context=Context.UNKNOWN,
                severity=SeverityLevel.CRITICAL,
                evidence="www-data",
                command_output="www-data",
                impact="RCE",
                remediation="Fix it",
                cvss_score=9.8
            ),
            InjectionFinding(
                endpoint="https://example.com/api",
                parameter="cmd",
                payload="; sleep 10",
                injection_type=InjectionType.BLIND_TIME,
                platform=Platform.UNIX,
                context=Context.UNKNOWN,
                severity=SeverityLevel.HIGH,
                evidence="Delayed",
                command_output="",
                impact="Blind RCE",
                remediation="Fix it",
                cvss_score=8.5
            )
        ]

        report = tester.generate_report()

        assert report['status'] == 'vulnerable'
        assert report['total_tests'] == 50
        assert report['total_findings'] == 2
        assert report['critical'] == 1
        assert report['high'] == 1
        assert len(report['findings']) == 2


class TestIntegration:
    """Integration tests"""

    def test_full_payload_generation_unix(self):
        """Test full payload generation for Unix"""
        gen = PayloadGenerator()
        payloads = gen.generate_all_payloads(Platform.UNIX, "burpcollaborator.net")

        # Verify we have at least 30 payloads
        assert len(payloads) >= 30

        # Verify payload diversity
        types = {p.injection_type for p in payloads}
        assert InjectionType.INLINE in types
        assert InjectionType.BLIND_TIME in types
        assert InjectionType.BLIND_OOB in types

        # Verify encoding diversity
        assert any(p.encoded for p in payloads)

        # Verify context diversity
        contexts = {p.context for p in payloads}
        assert len(contexts) >= 2

    def test_full_payload_generation_windows(self):
        """Test full payload generation for Windows"""
        gen = PayloadGenerator()
        payloads = gen.generate_all_payloads(Platform.WINDOWS, "burpcollaborator.net")

        assert len(payloads) >= 30
        assert all(p.platform == Platform.WINDOWS for p in payloads)

    def test_end_to_end_analysis(self):
        """Test end-to-end analysis flow"""
        # Generate payload
        gen = PayloadGenerator()
        payloads = gen.generate_inline_payloads(Platform.UNIX)
        payload = payloads[0]

        # Create response
        response = {
            'url': 'https://example.com/api',
            'parameter': 'cmd',
            'status_code': 200,
            'headers': {},
            'body': 'uid=33(www-data) gid=33(www-data)',
            'response_time': 0.5
        }

        # Analyze
        analyzer = ResponseAnalyzer()
        finding = analyzer.analyze_inline(response, payload)

        # Verify finding
        assert finding is not None
        assert finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        assert finding.cvss_score >= 8.0
        assert 'uid=' in finding.command_output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
