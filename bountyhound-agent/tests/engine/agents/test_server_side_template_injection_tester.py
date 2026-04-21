"""
Comprehensive tests for Server-Side Template Injection (SSTI) Tester Agent.

35+ test cases covering all SSTI testing capabilities.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from engine.agents.server_side_template_injection_tester import (
    SSTITester, SSTIPayload, SSTIFinding, TemplateEngine,
    SSTITestType, TemplateDetector, PayloadGenerator
)


# === Initialization Tests ===

def test_ssti_tester_init():
    """Test SSTITester initialization."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    assert tester is not None
    assert tester.target_url == "http://example.com/render"
    assert tester.parameters == {"template": "test"}
    assert tester.findings == []
    assert tester.timeout == 10


def test_ssti_tester_init_with_method():
    """Test SSTITester initialization with POST method."""
    tester = SSTITester("http://example.com/render", {"template": "test"}, method="POST")
    assert tester.method == "POST"


def test_ssti_tester_init_extracts_domain():
    """Test SSTITester extracts domain from URL."""
    tester = SSTITester("http://test.example.com/render", {"template": "test"})
    assert tester.target == "test.example.com"


def test_ssti_tester_init_with_explicit_target():
    """Test SSTITester initialization with explicit target."""
    tester = SSTITester("http://example.com/render", {"template": "test"}, target="example.com")
    assert tester.target == "example.com"


def test_ssti_tester_init_with_timeout():
    """Test SSTITester initialization with custom timeout."""
    tester = SSTITester("http://example.com/render", {"template": "test"}, timeout=15)
    assert tester.timeout == 15


# === Template Engine Enum Tests ===

def test_template_engine_enum_values():
    """Test TemplateEngine enum has all expected values."""
    assert TemplateEngine.JINJA2.value == "jinja2"
    assert TemplateEngine.FREEMARKER.value == "freemarker"
    assert TemplateEngine.TWIG.value == "twig"
    assert TemplateEngine.VELOCITY.value == "velocity"
    assert TemplateEngine.ERB.value == "erb"
    assert TemplateEngine.UNKNOWN.value == "unknown"


def test_ssti_test_type_enum_values():
    """Test SSTITestType enum has all expected values."""
    assert SSTITestType.DETECTION.value == "detection"
    assert SSTITestType.CONTEXT_ESCAPE.value == "context_escape"
    assert SSTITestType.CODE_EXECUTION.value == "code_execution"
    assert SSTITestType.FILE_READ.value == "file_read"
    assert SSTITestType.FILE_WRITE.value == "file_write"
    assert SSTITestType.RCE.value == "rce"


# === SSTIPayload Dataclass Tests ===

def test_ssti_payload_creation():
    """Test SSTIPayload dataclass creation."""
    payload = SSTIPayload(
        payload="{{7*7}}",
        engine=TemplateEngine.JINJA2,
        test_type=SSTITestType.DETECTION,
        expected_output="49",
        description="Test payload"
    )
    assert payload.payload == "{{7*7}}"
    assert payload.engine == TemplateEngine.JINJA2
    assert payload.expected_output == "49"


def test_ssti_payload_with_pattern():
    """Test SSTIPayload with expected pattern."""
    payload = SSTIPayload(
        payload="{{config}}",
        engine=TemplateEngine.JINJA2,
        test_type=SSTITestType.CONTEXT_ESCAPE,
        expected_pattern=r"SECRET_KEY",
        description="Config access"
    )
    assert payload.expected_pattern == r"SECRET_KEY"


# === SSTIFinding Dataclass Tests ===

def test_ssti_finding_creation():
    """Test SSTIFinding dataclass creation."""
    finding = SSTIFinding(
        url="http://example.com/render",
        parameter="template",
        method="GET",
        engine=TemplateEngine.JINJA2,
        test_type=SSTITestType.RCE,
        payload="{{7*7}}",
        evidence="49 found in response",
        context="test context",
        severity="critical",
        impact="RCE possible",
        exploitation_path=["step1", "step2"],
        poc="curl ..."
    )
    assert finding.severity == "critical"
    assert finding.engine == TemplateEngine.JINJA2


def test_ssti_finding_to_dict():
    """Test SSTIFinding to_dict conversion."""
    finding = SSTIFinding(
        url="http://example.com/render",
        parameter="template",
        method="GET",
        engine=TemplateEngine.JINJA2,
        test_type=SSTITestType.DETECTION,
        payload="test",
        evidence="test",
        context="test",
        severity="high",
        impact="test",
        exploitation_path=[],
        poc="test"
    )
    result = finding.to_dict()
    assert isinstance(result, dict)
    assert result['engine'] == 'jinja2'
    assert result['test_type'] == 'detection'
    assert 'timestamp' in result


# === TemplateDetector Tests ===

def test_template_detector_signatures_jinja2():
    """Test TemplateDetector has Jinja2 signatures."""
    assert TemplateEngine.JINJA2 in TemplateDetector.SIGNATURES
    sigs = TemplateDetector.SIGNATURES[TemplateEngine.JINJA2]
    assert 'error_patterns' in sigs
    assert 'behavior_markers' in sigs


def test_template_detector_signatures_freemarker():
    """Test TemplateDetector has Freemarker signatures."""
    assert TemplateEngine.FREEMARKER in TemplateDetector.SIGNATURES
    sigs = TemplateDetector.SIGNATURES[TemplateEngine.FREEMARKER]
    assert any('freemarker' in p for p in sigs['error_patterns'])


def test_template_detector_signatures_twig():
    """Test TemplateDetector has Twig signatures."""
    assert TemplateEngine.TWIG in TemplateDetector.SIGNATURES
    sigs = TemplateDetector.SIGNATURES[TemplateEngine.TWIG]
    assert any('Twig' in p for p in sigs['error_patterns'])


def test_template_detector_signatures_velocity():
    """Test TemplateDetector has Velocity signatures."""
    assert TemplateEngine.VELOCITY in TemplateDetector.SIGNATURES
    sigs = TemplateDetector.SIGNATURES[TemplateEngine.VELOCITY]
    assert any('velocity' in p for p in sigs['error_patterns'])


def test_template_detector_signatures_erb():
    """Test TemplateDetector has ERB signatures."""
    assert TemplateEngine.ERB in TemplateDetector.SIGNATURES
    sigs = TemplateDetector.SIGNATURES[TemplateEngine.ERB]
    assert any('erb' in p.lower() for p in sigs['error_patterns'])


def test_template_detector_detect_engine_by_error():
    """Test engine detection by error patterns."""
    detector = TemplateDetector()
    responses = [
        {
            'body': 'jinja2.exceptions.TemplateSyntaxError',
            'headers': {},
            'payload': ''
        }
    ]
    engine = detector.detect_engine(responses)
    assert engine == TemplateEngine.JINJA2


def test_template_detector_detect_engine_by_behavior():
    """Test engine detection by behavior markers."""
    detector = TemplateDetector()
    responses = [
        {
            'body': '49',
            'headers': {},
            'payload': '{{7*7}}'
        }
    ]
    engine = detector.detect_engine(responses)
    # Could be Jinja2 or Twig (both use same syntax)
    assert engine in [TemplateEngine.JINJA2, TemplateEngine.TWIG]


def test_template_detector_detect_engine_by_server_header():
    """Test engine detection by server headers."""
    detector = TemplateDetector()
    responses = [
        {
            'body': '',
            'headers': {'server': 'Werkzeug/2.0.1 Python/3.9.0'},
            'payload': ''
        }
    ]
    engine = detector.detect_engine(responses)
    assert engine == TemplateEngine.JINJA2


def test_template_detector_unknown_engine():
    """Test detection returns UNKNOWN for unrecognized engines."""
    detector = TemplateDetector()
    responses = [
        {
            'body': 'random text',
            'headers': {},
            'payload': ''
        }
    ]
    engine = detector.detect_engine(responses)
    assert engine == TemplateEngine.UNKNOWN


# === PayloadGenerator Tests ===

def test_payload_generator_init():
    """Test PayloadGenerator initialization."""
    gen = PayloadGenerator()
    assert gen is not None
    assert gen.random_marker.startswith("SSTI")


def test_payload_generator_detection_payloads():
    """Test detection payloads generation."""
    gen = PayloadGenerator()
    payloads = gen.get_detection_payloads()
    assert len(payloads) > 0
    assert any(p.engine == TemplateEngine.JINJA2 for p in payloads)
    assert any(p.engine == TemplateEngine.FREEMARKER for p in payloads)
    assert any(p.engine == TemplateEngine.TWIG for p in payloads)


def test_payload_generator_jinja2_detection():
    """Test Jinja2 detection payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_detection_payloads()
    jinja2_payloads = [p for p in payloads if p.engine == TemplateEngine.JINJA2]
    assert len(jinja2_payloads) > 0
    assert any('{{7*7}}' in p.payload for p in jinja2_payloads)


def test_payload_generator_freemarker_detection():
    """Test Freemarker detection payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_detection_payloads()
    fm_payloads = [p for p in payloads if p.engine == TemplateEngine.FREEMARKER]
    assert len(fm_payloads) > 0
    assert any('${7*7}' in p.payload for p in fm_payloads)


def test_payload_generator_erb_detection():
    """Test ERB detection payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_detection_payloads()
    erb_payloads = [p for p in payloads if p.engine == TemplateEngine.ERB]
    assert len(erb_payloads) > 0
    assert any('<%= 7*7 %>' in p.payload for p in erb_payloads)


def test_payload_generator_polyglot_payloads():
    """Test polyglot payloads generation."""
    gen = PayloadGenerator()
    payloads = gen.get_detection_payloads()
    polyglot = [p for p in payloads if p.engine == TemplateEngine.UNKNOWN]
    assert len(polyglot) > 0


def test_payload_generator_context_escape_jinja2():
    """Test Jinja2 context escape payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_context_escape_payloads(TemplateEngine.JINJA2)
    assert len(payloads) > 0
    assert any('config' in p.payload for p in payloads)
    assert any('__subclasses__' in p.payload for p in payloads)


def test_payload_generator_context_escape_twig():
    """Test Twig context escape payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_context_escape_payloads(TemplateEngine.TWIG)
    assert len(payloads) > 0
    assert any('_self.env' in p.payload for p in payloads)


def test_payload_generator_rce_jinja2():
    """Test Jinja2 RCE payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_rce_payloads(TemplateEngine.JINJA2, "id")
    assert len(payloads) > 0
    assert any('popen' in p.payload for p in payloads)
    assert any('id' in p.payload for p in payloads)


def test_payload_generator_rce_freemarker():
    """Test Freemarker RCE payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_rce_payloads(TemplateEngine.FREEMARKER, "whoami")
    assert len(payloads) > 0
    assert any('Execute' in p.payload for p in payloads)


def test_payload_generator_rce_erb():
    """Test ERB RCE payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_rce_payloads(TemplateEngine.ERB, "pwd")
    assert len(payloads) > 0
    assert any('system' in p.payload for p in payloads)
    assert any('IO.popen' in p.payload for p in payloads)


def test_payload_generator_file_read_jinja2():
    """Test Jinja2 file read payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_file_read_payloads(TemplateEngine.JINJA2, "/etc/passwd")
    assert len(payloads) > 0
    assert any('/etc/passwd' in p.payload for p in payloads)


def test_payload_generator_file_read_twig():
    """Test Twig file read payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_file_read_payloads(TemplateEngine.TWIG, "/etc/hosts")
    assert len(payloads) > 0
    assert any('source' in p.payload for p in payloads)


# === Request Handling Tests ===

@patch('engine.agents.server_side_template_injection_tester.requests.get')
def test_send_request_get_method(mock_get):
    """Test sending GET request."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "test response"
    mock_response.headers = {'content-type': 'text/html'}
    mock_get.return_value = mock_response

    tester = SSTITester("http://example.com/render", {"template": "test"})
    response = tester._send_request({"template": "{{7*7}}"})

    assert response is not None
    assert response['status'] == 200
    assert response['body'] == "test response"


@patch('engine.agents.server_side_template_injection_tester.requests.post')
def test_send_request_post_method(mock_post):
    """Test sending POST request."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "test response"
    mock_response.headers = {}
    mock_post.return_value = mock_response

    tester = SSTITester("http://example.com/render", {"template": "test"}, method="POST")
    response = tester._send_request({"template": "{{7*7}}"})

    assert response is not None
    assert mock_post.called


@patch('engine.agents.server_side_template_injection_tester.requests.get')
def test_send_request_handles_exception(mock_get):
    """Test request exception handling."""
    mock_get.side_effect = Exception("Network error")

    tester = SSTITester("http://example.com/render", {"template": "test"})
    response = tester._send_request({"template": "test"})

    assert response is None


# === File Detection Tests ===

def test_detect_file_content_etc_passwd():
    """Test detection of /etc/passwd content."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    body = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin"
    assert tester._detect_file_content(body, "/etc/passwd") is True


def test_detect_file_content_etc_hosts():
    """Test detection of /etc/hosts content."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    body = "127.0.0.1 localhost\n::1 localhost"
    assert tester._detect_file_content(body, "/etc/hosts") is True


def test_detect_file_content_windows_ini():
    """Test detection of Windows ini file content."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    body = "[fonts]\nMS Sans Serif=SSERIFE.FON\n[extensions]"
    assert tester._detect_file_content(body, "c:\\windows\\win.ini") is True


def test_detect_file_content_no_match():
    """Test file content detection returns False for no match."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    body = "random text that doesn't match"
    assert tester._detect_file_content(body, "/etc/passwd") is False


# === POC Generation Tests ===

def test_generate_poc_get_method():
    """Test POC generation for GET method."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    poc = tester._generate_poc("template", "{{7*7}}")
    assert "curl" in poc
    assert "example.com" in poc
    assert "template=" in poc


def test_generate_poc_post_method():
    """Test POC generation for POST method."""
    tester = SSTITester("http://example.com/render", {"template": "test"}, method="POST")
    poc = tester._generate_poc("template", "{{7*7}}")
    assert "curl" in poc
    assert "-X POST" in poc


def test_generate_rce_poc_jinja2():
    """Test RCE POC generation for Jinja2."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    poc = tester._generate_rce_poc("template", TemplateEngine.JINJA2)
    assert "config.__class__" in poc or "popen" in poc


def test_generate_rce_poc_erb():
    """Test RCE POC generation for ERB."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    poc = tester._generate_rce_poc("template", TemplateEngine.ERB)
    assert "system" in poc


# === Finding Management Tests ===

def test_get_findings():
    """Test get_findings returns all findings."""
    tester = SSTITester("http://example.com/render", {"template": "test"})
    finding = SSTIFinding(
        url="http://example.com/render",
        parameter="template",
        method="GET",
        engine=TemplateEngine.JINJA2,
        test_type=SSTITestType.DETECTION,
        payload="test",
        evidence="test",
        context="test",
        severity="high",
        impact="test",
        exploitation_path=[],
        poc="test"
    )
    tester.findings.append(finding)

    findings = tester.get_findings()
    assert len(findings) == 1


def test_get_findings_by_severity():
    """Test get_findings_by_severity filters correctly."""
    tester = SSTITester("http://example.com/render", {"template": "test"})

    tester.findings.append(SSTIFinding(
        url="test", parameter="test", method="GET",
        engine=TemplateEngine.JINJA2, test_type=SSTITestType.RCE,
        payload="test", evidence="test", context="test",
        severity="critical", impact="test", exploitation_path=[], poc="test"
    ))

    tester.findings.append(SSTIFinding(
        url="test", parameter="test", method="GET",
        engine=TemplateEngine.JINJA2, test_type=SSTITestType.DETECTION,
        payload="test", evidence="test", context="test",
        severity="high", impact="test", exploitation_path=[], poc="test"
    ))

    critical = tester.get_findings_by_severity("critical")
    assert len(critical) == 1
    assert critical[0].severity == "critical"


# === Database Integration Tests ===

@patch('engine.agents.server_side_template_injection_tester.DatabaseHooks.before_test')
@patch('engine.agents.server_side_template_injection_tester.BountyHoundDB')
def test_run_all_tests_skips_when_database_says_skip(mock_db, mock_before_test):
    """Test run_all_tests skips when database recommends."""
    mock_before_test.return_value = {
        'should_skip': True,
        'reason': 'Tested recently',
        'previous_findings': []
    }

    tester = SSTITester("http://example.com/render", {"template": "test"})
    findings = tester.run_all_tests()

    assert findings == []


# === Integration Function Tests ===

@patch('engine.agents.server_side_template_injection_tester.SSTITester.run_all_tests')
def test_run_ssti_tests_integration(mock_run_tests):
    """Test run_ssti_tests integration function."""
    from engine.agents.server_side_template_injection_tester import run_ssti_tests

    mock_finding = SSTIFinding(
        url="http://example.com/render",
        parameter="template",
        method="GET",
        engine=TemplateEngine.JINJA2,
        test_type=SSTITestType.RCE,
        payload="{{7*7}}",
        evidence="test",
        context="test",
        severity="critical",
        impact="RCE",
        exploitation_path=[],
        poc="curl ..."
    )
    mock_run_tests.return_value = [mock_finding]

    result = run_ssti_tests("http://example.com/render", {"template": "test"})

    assert 'findings' in result
    assert 'stats' in result
    assert result['stats']['total_findings'] == 1
    assert result['stats']['critical'] == 1


# === Coverage Meta-Test ===

def test_comprehensive_coverage():
    """Meta-test: Verify we have 35+ test cases."""
    import inspect
    import sys

    current_module = sys.modules[__name__]
    test_functions = [
        name for name, obj in inspect.getmembers(current_module)
        if inspect.isfunction(obj) and name.startswith('test_')
    ]

    assert len(test_functions) >= 35, f"Expected 35+ tests, found {len(test_functions)}"


def test_all_template_engines_covered():
    """Test all template engines have detection payloads."""
    gen = PayloadGenerator()
    payloads = gen.get_detection_payloads()

    engines = set(p.engine for p in payloads)
    assert TemplateEngine.JINJA2 in engines
    assert TemplateEngine.FREEMARKER in engines
    assert TemplateEngine.TWIG in engines
    assert TemplateEngine.VELOCITY in engines
    assert TemplateEngine.ERB in engines


def test_all_test_types_supported():
    """Test all SSTI test types are represented."""
    test_types = [
        SSTITestType.DETECTION,
        SSTITestType.CONTEXT_ESCAPE,
        SSTITestType.CODE_EXECUTION,
        SSTITestType.FILE_READ,
        SSTITestType.FILE_WRITE,
        SSTITestType.RCE
    ]

    for test_type in test_types:
        payload = SSTIPayload(
            payload="test",
            engine=TemplateEngine.JINJA2,
            test_type=test_type,
            description="test"
        )
        assert payload.test_type == test_type
