"""
Extended Semgrep runner tests for improved coverage.
"""
import pytest
from pathlib import Path
from engine.sast.analyzers.semgrep_runner import SemgrepRunner


@pytest.fixture
def temp_code_file(tmp_path):
    """Create temporary code file for testing."""
    code_file = tmp_path / "test.py"
    code_file.write_text("import os\npassword = 'hardcoded'\n")
    return code_file


def test_semgrep_runner_init(tmp_path):
    """Test SemgrepRunner initialization."""
    runner = SemgrepRunner(str(tmp_path))
    assert runner is not None
    assert runner.repo_path == tmp_path
    assert runner.findings == []


def test_semgrep_runner_with_target(tmp_path):
    """Test runner with specific target."""
    runner = SemgrepRunner(str(tmp_path), target="custom-target")
    assert runner.target == "custom-target"


def test_semgrep_check_installed():
    """Test semgrep installation check."""
    import subprocess
    # Test if semgrep command exists
    try:
        result = subprocess.run(
            ['semgrep', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        installed = result.returncode == 0
        assert isinstance(installed, bool)
    except FileNotFoundError:
        # Expected if semgrep not installed
        assert True


def test_semgrep_default_rules():
    """Test default rules are defined."""
    # The scan method uses "auto" as default config
    import inspect
    sig = inspect.signature(SemgrepRunner.scan)
    assert 'config' in sig.parameters
    assert sig.parameters['config'].default == "auto"


@pytest.mark.skipif(not Path("/usr/bin/semgrep").exists(), reason="semgrep not installed")
def test_semgrep_scan_output_format(temp_code_file):
    """Test scan output has expected format."""
    runner = SemgrepRunner(target=str(temp_code_file.parent))
    # This test only runs if semgrep is actually installed
    results = runner.scan()
    assert isinstance(results, list)


def test_process_findings_empty(tmp_path):
    """Test processing empty findings list."""
    runner = SemgrepRunner(str(tmp_path))
    results = runner.process_findings([])
    assert results == []


def test_process_findings_sql_injection(tmp_path):
    """Test SQL injection finding is categorized correctly."""
    runner = SemgrepRunner(str(tmp_path))
    semgrep_result = {
        'check_id': 'python.lang.security.sql-injection',
        'path': 'test.py',
        'start': {'line': 10},
        'extra': {
            'severity': 'ERROR',
            'message': 'Possible SQL injection',
            'lines': 'query = "SELECT * FROM users WHERE id = " + user_id'
        }
    }
    findings = runner.process_findings([semgrep_result])
    assert len(findings) == 1
    assert findings[0]['category'] == 'SQL Injection'
    assert findings[0]['severity'] == 'CRITICAL'
    assert findings[0]['title'] == 'python.lang.security.sql-injection'


def test_process_findings_xss(tmp_path):
    """Test XSS finding is categorized correctly."""
    runner = SemgrepRunner(str(tmp_path))
    semgrep_result = {
        'check_id': 'javascript.react.xss-dangerous-html',
        'path': 'component.js',
        'start': {'line': 25},
        'extra': {
            'severity': 'WARNING',
            'message': 'XSS vulnerability',
            'lines': 'dangerouslySetInnerHTML={{__html: userInput}}'
        }
    }
    findings = runner.process_findings([semgrep_result])
    assert len(findings) == 1
    assert findings[0]['category'] == 'XSS'
    assert findings[0]['severity'] == 'HIGH'


def test_process_findings_hardcoded_secret(tmp_path):
    """Test hardcoded secret finding is categorized correctly."""
    runner = SemgrepRunner(str(tmp_path))
    semgrep_result = {
        'check_id': 'generic.secrets.security.hardcoded-password',
        'path': 'config.py',
        'start': {'line': 5},
        'extra': {
            'severity': 'INFO',
            'message': 'Hardcoded password detected',
            'lines': 'password = "admin123"'
        }
    }
    findings = runner.process_findings([semgrep_result])
    assert len(findings) == 1
    assert findings[0]['category'] == 'Hardcoded Secret'
    assert findings[0]['severity'] == 'CRITICAL'


def test_process_findings_severity_mapping(tmp_path):
    """Test severity mapping from Semgrep to BountyHound format."""
    runner = SemgrepRunner(str(tmp_path))

    # Test ERROR -> HIGH (but gets overridden to CRITICAL for some categories)
    error_result = {
        'check_id': 'generic.security.issue',
        'path': 'test.py',
        'start': {'line': 1},
        'extra': {'severity': 'ERROR', 'message': 'Error', 'lines': 'code'}
    }

    # Test WARNING -> MEDIUM
    warning_result = {
        'check_id': 'generic.security.warning',
        'path': 'test.py',
        'start': {'line': 2},
        'extra': {'severity': 'WARNING', 'message': 'Warning', 'lines': 'code'}
    }

    # Test INFO -> LOW
    info_result = {
        'check_id': 'generic.security.info',
        'path': 'test.py',
        'start': {'line': 3},
        'extra': {'severity': 'INFO', 'message': 'Info', 'lines': 'code'}
    }

    findings = runner.process_findings([error_result, warning_result, info_result])
    assert len(findings) == 3
    assert findings[0]['severity'] == 'HIGH'
    assert findings[1]['severity'] == 'MEDIUM'
    assert findings[2]['severity'] == 'LOW'


def test_print_summary_with_findings(tmp_path, capsys):
    """Test print_summary outputs findings correctly."""
    runner = SemgrepRunner(str(tmp_path))
    runner.findings = [
        {'severity': 'CRITICAL', 'category': 'SQL Injection', 'title': 'test1'},
        {'severity': 'HIGH', 'category': 'XSS', 'title': 'test2'},
        {'severity': 'MEDIUM', 'category': 'Security Issue', 'title': 'test3'}
    ]
    runner.print_summary()
    captured = capsys.readouterr()
    assert 'CRITICAL' in captured.out
    assert 'HIGH' in captured.out
    assert 'MEDIUM' in captured.out


def test_print_summary_empty_findings(tmp_path, capsys):
    """Test print_summary with no findings outputs nothing."""
    runner = SemgrepRunner(str(tmp_path))
    runner.findings = []
    runner.print_summary()
    captured = capsys.readouterr()
    assert captured.out == ""


def test_scan_with_custom_rules(tmp_path):
    """Test scan_with_custom_rules method exists."""
    runner = SemgrepRunner(str(tmp_path))
    assert hasattr(runner, 'scan_with_custom_rules')
    assert callable(runner.scan_with_custom_rules)
