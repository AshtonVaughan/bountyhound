"""
Tests for Mobile API Tester Agent

Comprehensive tests covering all mobile security attack vectors:
- APK static analysis (hardcoded secrets, manifest issues)
- Certificate pinning bypass
- Deep link vulnerabilities
- Mobile API security issues
- Root/jailbreak detection
"""

import os
import pytest
import json
import tempfile
import zipfile
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path

from engine.agents.mobile_api_tester import (
    MobileAPKAnalyzer,
    CertificatePinningBypass,
    DeepLinkTester,
    MobileAPISecurityTester,
    MobileFinding,
    MobileSeverity,
    MobileVulnType,
    test_mobile_security
)


# ===== Fixtures =====

@pytest.fixture
def temp_apk():
    """Create temporary APK file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.apk', delete=False) as f:
        apk_path = f.name

    # Create a valid ZIP structure (APK is a ZIP)
    with zipfile.ZipFile(apk_path, 'w') as zf:
        # Add AndroidManifest.xml
        manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">
    <application android:debuggable="true" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <data android:scheme="testapp" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
        zf.writestr('AndroidManifest.xml', manifest_content)

        # Add file with hardcoded secrets
        secrets_content = '''
api_key = "sk_live_1234567890abcdefghijklmn"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
google_api_key = "AIzaSyD1234567890abcdefghijklmnopqr"
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
'''
        zf.writestr('res/values/secrets.xml', secrets_content)

        # Add file with certificate pinning
        pinning_content = '''
import okhttp3.CertificatePinner;
certificatePinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();
'''
        zf.writestr('smali/MainActivity.smali', pinning_content)

        # Add file with API endpoint
        api_content = '''
private static final String API_BASE = "https://api.example.com/v1/";
private static final String API_ENDPOINT = "https://api.example.com/api/users";
'''
        zf.writestr('smali/ApiClient.smali', api_content)

        # Add file with insecure storage
        storage_content = '''
openFileOutput("sensitive.txt", MODE_WORLD_READABLE);
getSharedPreferences("prefs", MODE_PRIVATE);
'''
        zf.writestr('smali/Storage.smali', storage_content)

    yield apk_path

    # Cleanup
    try:
        os.unlink(apk_path)
    except:
        pass


@pytest.fixture
def mock_apk_analyzer():
    """Create mock APK analyzer."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()
    return analyzer


@pytest.fixture
def mock_requests_response():
    """Create mock requests response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {'data': {}}
    response.headers = {}
    return response


# ===== APK Analyzer Tests =====

def test_apk_analyzer_initialization():
    """Test APK analyzer initializes correctly."""
    analyzer = MobileAPKAnalyzer('/path/to/app.apk')

    assert analyzer.apk_path == '/path/to/app.apk'
    assert analyzer.findings == []
    assert analyzer.extracted_dir is None
    assert analyzer.api_endpoints == []


def test_apk_analyzer_with_real_apk(temp_apk):
    """Test APK analyzer with real APK file."""
    analyzer = MobileAPKAnalyzer(temp_apk)
    findings = analyzer.analyze_all()

    assert len(findings) > 0
    assert analyzer.extracted_dir is not None

    # Check for expected findings
    finding_types = [f.vuln_type for f in findings]

    # Should find debuggable app
    assert MobileVulnType.DEBUGGABLE_APP in finding_types

    # Should find backup enabled
    assert MobileVulnType.BACKUP_ENABLED in finding_types

    # Should find exported component
    assert MobileVulnType.EXPORTED_COMPONENT in finding_types

    # Should find hardcoded secrets
    secret_findings = [f for f in findings if f.vuln_type == MobileVulnType.HARDCODED_SECRET]
    assert len(secret_findings) >= 3  # At least AWS, Stripe, Google API


def test_apk_analyzer_nonexistent_file():
    """Test APK analyzer with non-existent file."""
    analyzer = MobileAPKAnalyzer('/nonexistent/app.apk')
    findings = analyzer.analyze_all()

    assert findings == []


def test_find_hardcoded_secrets_aws():
    """Test finding AWS credentials."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    # Create file with AWS credentials
    test_file = os.path.join(analyzer.extracted_dir, 'config.xml')
    with open(test_file, 'w') as f:
        f.write('aws_access_key = "AKIAIOSFODNN7EXAMPLE"')

    analyzer.find_hardcoded_secrets()

    assert len(analyzer.findings) == 1
    finding = analyzer.findings[0]
    assert finding.vuln_type == MobileVulnType.HARDCODED_SECRET
    assert finding.severity == MobileSeverity.CRITICAL
    assert 'AKIA' in finding.value

    # Cleanup
    os.unlink(test_file)
    os.rmdir(analyzer.extracted_dir)


def test_find_hardcoded_secrets_stripe():
    """Test finding Stripe API keys."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    test_file = os.path.join(analyzer.extracted_dir, 'payment.properties')
    with open(test_file, 'w') as f:
        f.write('stripe_key = "sk_live_1234567890abcdefghijklmn"')

    analyzer.find_hardcoded_secrets()

    assert len(analyzer.findings) == 1
    finding = analyzer.findings[0]
    assert 'stripe' in finding.title.lower()
    assert finding.severity == MobileSeverity.CRITICAL

    os.unlink(test_file)
    os.rmdir(analyzer.extracted_dir)


def test_find_hardcoded_secrets_jwt():
    """Test finding JWT tokens."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    test_file = os.path.join(analyzer.extracted_dir, 'auth.json')
    with open(test_file, 'w') as f:
        f.write('{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"}')

    analyzer.find_hardcoded_secrets()

    assert len(analyzer.findings) == 1
    finding = analyzer.findings[0]
    assert 'jwt' in finding.title.lower()

    os.unlink(test_file)
    os.rmdir(analyzer.extracted_dir)


def test_find_hardcoded_secrets_deduplication():
    """Test that duplicate secrets are not reported multiple times."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    # Create multiple files with same secret
    for i in range(3):
        test_file = os.path.join(analyzer.extracted_dir, f'config{i}.xml')
        with open(test_file, 'w') as f:
            f.write('api_key = "sk_live_1234567890abcdefghijklmn"')

    analyzer.find_hardcoded_secrets()

    # Should only report once due to deduplication
    assert len(analyzer.findings) == 1

    # Cleanup
    for i in range(3):
        os.unlink(os.path.join(analyzer.extracted_dir, f'config{i}.xml'))
    os.rmdir(analyzer.extracted_dir)


def test_analyze_manifest_debuggable():
    """Test detection of debuggable flag."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    manifest_path = os.path.join(analyzer.extracted_dir, 'AndroidManifest.xml')
    with open(manifest_path, 'w') as f:
        f.write('<application android:debuggable="true"></application>')

    analyzer.analyze_manifest()

    debuggable_findings = [f for f in analyzer.findings if f.vuln_type == MobileVulnType.DEBUGGABLE_APP]
    assert len(debuggable_findings) == 1
    assert debuggable_findings[0].severity == MobileSeverity.HIGH

    os.unlink(manifest_path)
    os.rmdir(analyzer.extracted_dir)


def test_analyze_manifest_backup_enabled():
    """Test detection of backup enabled."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    manifest_path = os.path.join(analyzer.extracted_dir, 'AndroidManifest.xml')
    with open(manifest_path, 'w') as f:
        f.write('<application android:allowBackup="true"></application>')

    analyzer.analyze_manifest()

    backup_findings = [f for f in analyzer.findings if f.vuln_type == MobileVulnType.BACKUP_ENABLED]
    assert len(backup_findings) == 1
    assert backup_findings[0].severity == MobileSeverity.MEDIUM

    os.unlink(manifest_path)
    os.rmdir(analyzer.extracted_dir)


def test_analyze_manifest_exported_components():
    """Test detection of exported components."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    manifest_path = os.path.join(analyzer.extracted_dir, 'AndroidManifest.xml')
    with open(manifest_path, 'w') as f:
        f.write('''
            <activity android:name="com.example.MainActivity" android:exported="true" />
            <service android:name="com.example.MyService" android:exported="true" />
            <receiver android:name="com.example.MyReceiver" android:exported="true" />
        ''')

    analyzer.analyze_manifest()

    exported_findings = [f for f in analyzer.findings if f.vuln_type == MobileVulnType.EXPORTED_COMPONENT]
    assert len(exported_findings) == 3

    os.unlink(manifest_path)
    os.rmdir(analyzer.extracted_dir)


def test_check_certificate_pinning_present():
    """Test detection of certificate pinning implementation."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    smali_file = os.path.join(analyzer.extracted_dir, 'NetworkClient.smali')
    with open(smali_file, 'w') as f:
        f.write('import okhttp3.CertificatePinner;')

    analyzer.check_certificate_pinning()

    # Should NOT create finding if pinning is present
    pinning_findings = [f for f in analyzer.findings if f.vuln_type == MobileVulnType.MISSING_CERTIFICATE_PINNING]
    assert len(pinning_findings) == 0

    os.unlink(smali_file)
    os.rmdir(analyzer.extracted_dir)


def test_check_certificate_pinning_missing():
    """Test detection when certificate pinning is missing."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    # Create file without pinning indicators
    smali_file = os.path.join(analyzer.extracted_dir, 'NetworkClient.smali')
    with open(smali_file, 'w') as f:
        f.write('// No pinning here')

    analyzer.check_certificate_pinning()

    pinning_findings = [f for f in analyzer.findings if f.vuln_type == MobileVulnType.MISSING_CERTIFICATE_PINNING]
    assert len(pinning_findings) == 1
    assert pinning_findings[0].severity == MobileSeverity.MEDIUM

    os.unlink(smali_file)
    os.rmdir(analyzer.extracted_dir)


def test_find_api_endpoints():
    """Test API endpoint extraction."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    smali_file = os.path.join(analyzer.extracted_dir, 'ApiClient.smali')
    with open(smali_file, 'w') as f:
        f.write('''
            const-string v0, "https://api.example.com/v1/users"
            const-string v1, "https://api.example.com/api/auth"
        ''')

    analyzer.find_api_endpoints()

    assert len(analyzer.api_endpoints) == 2
    assert any('users' in endpoint for endpoint in analyzer.api_endpoints)
    assert any('auth' in endpoint for endpoint in analyzer.api_endpoints)

    os.unlink(smali_file)
    os.rmdir(analyzer.extracted_dir)


def test_find_api_endpoints_excludes_common_urls():
    """Test that common third-party URLs are excluded."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    smali_file = os.path.join(analyzer.extracted_dir, 'Config.smali')
    with open(smali_file, 'w') as f:
        f.write('''
            "https://googleapis.com/api/v1"
            "https://facebook.com/api"
            "https://api.myapp.com/v1/users"
        ''')

    analyzer.find_api_endpoints()

    # Should only find myapp.com, not googleapis or facebook
    assert len(analyzer.api_endpoints) == 1
    assert 'myapp.com' in analyzer.api_endpoints[0]

    os.unlink(smali_file)
    os.rmdir(analyzer.extracted_dir)


def test_check_insecure_storage():
    """Test detection of insecure storage patterns."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    smali_file = os.path.join(analyzer.extracted_dir, 'Storage.smali')
    with open(smali_file, 'w') as f:
        f.write('openFileOutput("data.txt", MODE_WORLD_READABLE);')

    analyzer.check_insecure_storage()

    storage_findings = [f for f in analyzer.findings if f.vuln_type == MobileVulnType.INSECURE_STORAGE]
    assert len(storage_findings) == 1
    assert storage_findings[0].severity == MobileSeverity.HIGH

    os.unlink(smali_file)
    os.rmdir(analyzer.extracted_dir)


# ===== Certificate Pinning Bypass Tests =====

def test_pinning_bypass_initialization():
    """Test certificate pinning bypass initializes correctly."""
    tester = CertificatePinningBypass('com.example.app', device_id='device123')

    assert tester.package_name == 'com.example.app'
    assert tester.device_id == 'device123'
    assert tester.findings == []


def test_pinning_bypass_test():
    """Test certificate pinning bypass generates findings."""
    tester = CertificatePinningBypass('com.example.app')

    with patch('subprocess.run') as mock_run:
        # Simulate Frida installed
        mock_run.return_value = Mock(returncode=0, stdout='15.1.0\n')

        findings = tester.test_pinning_bypass()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.vuln_type == MobileVulnType.CERTIFICATE_PINNING_BYPASS
        assert finding.severity == MobileSeverity.HIGH
        assert 'Frida' in finding.poc


def test_pinning_bypass_frida_not_installed():
    """Test pinning bypass when Frida is not installed."""
    tester = CertificatePinningBypass('com.example.app')

    with patch('subprocess.run', side_effect=FileNotFoundError):
        findings = tester.test_pinning_bypass()

        # Should still generate finding with manual instructions
        assert len(findings) == 1


def test_pinning_bypass_frida_script_saved():
    """Test that Frida script is saved to file."""
    tester = CertificatePinningBypass('com.example.app')

    script_path = tester._save_frida_script()

    assert os.path.exists(script_path)
    assert script_path.endswith('.js')

    with open(script_path, 'r') as f:
        content = f.read()
        assert 'CertificatePinner' in content
        assert 'TrustManager' in content
        assert 'ObjC.available' in content  # iOS support

    os.unlink(script_path)


def test_pinning_bypass_poc_format():
    """Test POC format is correct."""
    tester = CertificatePinningBypass('com.example.testapp')
    script_path = '/tmp/ssl_bypass.js'

    poc = tester._generate_poc(script_path, frida_available=True)

    assert 'frida-server' in poc
    assert 'com.example.testapp' in poc
    assert script_path in poc
    assert 'Objection' in poc  # Alternative tool mentioned


# ===== Deep Link Tester Tests =====

def test_deeplink_tester_initialization():
    """Test deep link tester initializes correctly."""
    tester = DeepLinkTester('myapp', host='example.com', package_name='com.example.app')

    assert tester.app_scheme == 'myapp'
    assert tester.host == 'example.com'
    assert tester.package_name == 'com.example.app'
    assert tester.findings == []


def test_deeplink_test_open_redirect():
    """Test open redirect detection."""
    tester = DeepLinkTester('myapp')
    tester.test_open_redirect()

    assert len(tester.findings) >= 5  # Multiple redirect payloads
    finding = tester.findings[0]
    assert finding.vuln_type == MobileVulnType.DEEP_LINK_OPEN_REDIRECT
    assert finding.severity == MobileSeverity.MEDIUM
    assert 'evil.com' in finding.poc


def test_deeplink_test_intent_hijacking():
    """Test intent hijacking detection."""
    tester = DeepLinkTester('myapp')
    tester.test_intent_hijacking()

    assert len(tester.findings) == 1
    finding = tester.findings[0]
    assert finding.vuln_type == MobileVulnType.INTENT_HIJACKING
    assert finding.severity == MobileSeverity.MEDIUM
    assert 'intent-filter' in finding.poc
    assert 'myapp' in finding.poc


def test_deeplink_test_token_leakage():
    """Test token leakage detection."""
    tester = DeepLinkTester('myapp')
    tester.test_token_leakage()

    token_findings = [f for f in tester.findings if f.vuln_type == MobileVulnType.TOKEN_LEAKAGE]
    assert len(token_findings) >= 5  # Multiple token parameters

    # Check for common token parameters
    params_tested = [f.evidence['parameter'] for f in token_findings]
    assert 'token' in params_tested
    assert 'access_token' in params_tested
    assert 'jwt' in params_tested


def test_deeplink_test_parameter_injection():
    """Test parameter injection testing."""
    tester = DeepLinkTester('myapp')
    tester.test_parameter_injection()

    # This test just prints, doesn't create findings
    # Just verify it doesn't crash
    assert True


def test_deeplink_all_tests():
    """Test running all deep link tests."""
    tester = DeepLinkTester('myapp', host='example.com')
    findings = tester.test_all_deeplink_vulns()

    assert len(findings) > 0
    # Should have findings from open redirect, hijacking, and token leakage
    vuln_types = set(f.vuln_type for f in findings)
    assert MobileVulnType.DEEP_LINK_OPEN_REDIRECT in vuln_types
    assert MobileVulnType.INTENT_HIJACKING in vuln_types
    assert MobileVulnType.TOKEN_LEAKAGE in vuln_types


# ===== Mobile API Security Tester Tests =====

def test_mobile_api_tester_initialization():
    """Test mobile API tester initializes correctly."""
    tester = MobileAPISecurityTester('https://api.example.com')

    assert tester.api_base_url == 'https://api.example.com'
    assert tester.findings == []


@patch('engine.agents.mobile_api_tester.REQUESTS_AVAILABLE', True)
def test_mobile_api_platform_validation_vulnerable(mock_requests_response):
    """Test detection of missing platform validation."""
    tester = MobileAPISecurityTester('https://api.example.com')

    with patch('requests.get', return_value=mock_requests_response):
        tester.test_missing_platform_validation()

        platform_findings = [f for f in tester.findings if f.vuln_type == MobileVulnType.MISSING_PLATFORM_VALIDATION]
        assert len(platform_findings) == 1
        assert platform_findings[0].severity == MobileSeverity.MEDIUM


@patch('engine.agents.mobile_api_tester.REQUESTS_AVAILABLE', True)
def test_mobile_api_platform_validation_protected():
    """Test when platform validation is present."""
    tester = MobileAPISecurityTester('https://api.example.com')

    mock_response = Mock()
    mock_response.status_code = 403

    with patch('requests.get', return_value=mock_response):
        tester.test_missing_platform_validation()

        platform_findings = [f for f in tester.findings if f.vuln_type == MobileVulnType.MISSING_PLATFORM_VALIDATION]
        assert len(platform_findings) == 0


@patch('engine.agents.mobile_api_tester.REQUESTS_AVAILABLE', True)
def test_mobile_api_version_enforcement_vulnerable(mock_requests_response):
    """Test detection of missing version enforcement."""
    tester = MobileAPISecurityTester('https://api.example.com')

    with patch('requests.get', return_value=mock_requests_response):
        tester.test_version_enforcement()

        version_findings = [f for f in tester.findings if f.vuln_type == MobileVulnType.MISSING_VERSION_ENFORCEMENT]
        assert len(version_findings) == 1
        assert version_findings[0].severity == MobileSeverity.MEDIUM


@patch('engine.agents.mobile_api_tester.REQUESTS_AVAILABLE', True)
def test_mobile_api_device_binding():
    """Test device binding testing."""
    tester = MobileAPISecurityTester('https://api.example.com')

    with patch('requests.get', return_value=Mock(status_code=200)):
        tester.test_device_binding()
        # Just verify it doesn't crash


def test_mobile_api_root_detection():
    """Test root/jailbreak detection testing."""
    tester = MobileAPISecurityTester('https://api.example.com')
    tester.test_root_jailbreak_detection()

    root_findings = [f for f in tester.findings if f.vuln_type == MobileVulnType.MISSING_ROOT_DETECTION]
    assert len(root_findings) == 1
    assert 'Magisk' in root_findings[0].poc
    assert 'Cydia' in root_findings[0].poc


def test_mobile_api_all_tests():
    """Test running all mobile API tests."""
    tester = MobileAPISecurityTester('https://api.example.com')

    with patch('engine.agents.mobile_api_tester.REQUESTS_AVAILABLE', False):
        findings = tester.test_all_api_security()

        # Should at least have root detection finding
        assert len(findings) >= 1


@patch('engine.agents.mobile_api_tester.REQUESTS_AVAILABLE', False)
def test_mobile_api_requests_not_available():
    """Test when requests library is not available."""
    tester = MobileAPISecurityTester('https://api.example.com')
    tester.test_missing_platform_validation()

    # Should not create findings if requests unavailable
    platform_findings = [f for f in tester.findings if f.vuln_type == MobileVulnType.MISSING_PLATFORM_VALIDATION]
    assert len(platform_findings) == 0


# ===== MobileFinding Tests =====

def test_mobile_finding_creation():
    """Test mobile finding creation."""
    finding = MobileFinding(
        title='Test Finding',
        severity=MobileSeverity.HIGH,
        vuln_type=MobileVulnType.HARDCODED_SECRET,
        description='Test description',
        poc='Test POC',
        impact='Test impact',
        recommendation='Test recommendation',
        cwe_id='CWE-798'
    )

    assert finding.title == 'Test Finding'
    assert finding.severity == MobileSeverity.HIGH
    assert finding.vuln_type == MobileVulnType.HARDCODED_SECRET
    assert finding.cwe_id == 'CWE-798'


def test_mobile_finding_to_dict():
    """Test mobile finding conversion to dictionary."""
    finding = MobileFinding(
        title='Test Finding',
        severity=MobileSeverity.CRITICAL,
        vuln_type=MobileVulnType.DEBUGGABLE_APP,
        description='Test',
        poc='Test',
        impact='Test',
        evidence={'key': 'value'}
    )

    finding_dict = finding.to_dict()

    assert finding_dict['title'] == 'Test Finding'
    assert finding_dict['severity'] == 'CRITICAL'
    assert finding_dict['vuln_type'] == 'MOBILE_DEBUGGABLE'
    assert finding_dict['evidence'] == {'key': 'value'}


# ===== Integration Tests =====

def test_mobile_security_full_scan(temp_apk):
    """Test complete mobile security scan."""
    result = test_mobile_security(
        apk_path=temp_apk,
        api_base_url='https://api.example.com',
        package_name='com.example.testapp',
        app_scheme='testapp',
        full_scan=True
    )

    assert result['total_findings'] > 0
    assert 'severity_counts' in result
    assert result['tested_components']['apk_analysis'] is True
    assert result['tested_components']['pinning_bypass'] is True
    assert result['tested_components']['deeplink_testing'] is True
    assert result['tested_components']['api_testing'] is True

    # Check severity counts
    assert isinstance(result['severity_counts'], dict)
    assert all(severity in result['severity_counts'] for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])


def test_mobile_security_apk_only(temp_apk):
    """Test scan with APK only."""
    result = test_mobile_security(apk_path=temp_apk)

    assert result['total_findings'] > 0
    assert result['tested_components']['apk_analysis'] is True
    assert result['tested_components']['pinning_bypass'] is False
    assert result['tested_components']['deeplink_testing'] is False
    assert result['tested_components']['api_testing'] is False


def test_mobile_security_no_inputs():
    """Test scan with no inputs."""
    result = test_mobile_security()

    assert result['total_findings'] == 0
    assert all(not tested for tested in result['tested_components'].values())


def test_mobile_security_quick_scan(temp_apk):
    """Test quick scan mode."""
    result = test_mobile_security(
        apk_path=temp_apk,
        full_scan=False
    )

    assert result['total_findings'] > 0


# ===== Edge Cases and Error Handling =====

def test_apk_analyzer_invalid_zip():
    """Test APK analyzer with invalid ZIP file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.apk', delete=False) as f:
        f.write('This is not a valid ZIP file')
        invalid_apk = f.name

    analyzer = MobileAPKAnalyzer(invalid_apk)
    findings = analyzer.analyze_all()

    # Should handle gracefully
    assert analyzer.extracted_dir is None

    os.unlink(invalid_apk)


def test_apk_analyzer_empty_apk():
    """Test APK analyzer with empty APK."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.apk', delete=False) as f:
        empty_apk = f.name

    # Create empty ZIP
    with zipfile.ZipFile(empty_apk, 'w'):
        pass

    analyzer = MobileAPKAnalyzer(empty_apk)
    findings = analyzer.analyze_all()

    # Should handle gracefully
    assert isinstance(findings, list)

    os.unlink(empty_apk)


def test_severity_assignment():
    """Test severity is assigned correctly based on secret type."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')

    # Critical
    assert analyzer._get_secret_severity('aws_access_key') == MobileSeverity.CRITICAL
    assert analyzer._get_secret_severity('private_key') == MobileSeverity.CRITICAL
    assert analyzer._get_secret_severity('stripe_live') == MobileSeverity.CRITICAL

    # High
    assert analyzer._get_secret_severity('api_key') == MobileSeverity.HIGH
    assert analyzer._get_secret_severity('google_api') == MobileSeverity.HIGH

    # Medium (default)
    assert analyzer._get_secret_severity('unknown_key') == MobileSeverity.MEDIUM


def test_finding_with_all_fields():
    """Test finding with all optional fields populated."""
    finding = MobileFinding(
        title='Complete Finding',
        severity=MobileSeverity.HIGH,
        vuln_type=MobileVulnType.HARDCODED_SECRET,
        description='Full description',
        poc='Detailed POC',
        impact='Detailed impact',
        recommendation='Detailed recommendation',
        location='/path/to/file',
        value='secret_value',
        endpoint='https://api.example.com',
        evidence={'key1': 'value1', 'key2': 'value2'},
        cwe_id='CWE-798'
    )

    finding_dict = finding.to_dict()

    assert all(key in finding_dict for key in [
        'title', 'severity', 'vuln_type', 'description', 'poc',
        'impact', 'recommendation', 'location', 'value', 'endpoint',
        'evidence', 'cwe_id', 'discovered_date'
    ])


# ===== Performance Tests =====

def test_large_apk_handling(temp_apk):
    """Test handling of APK with many files."""
    # Create APK with many files
    with zipfile.ZipFile(temp_apk, 'a') as zf:
        for i in range(100):
            zf.writestr(f'smali/Class{i}.smali', f'// File {i}')

    analyzer = MobileAPKAnalyzer(temp_apk)
    findings = analyzer.analyze_all()

    # Should complete without errors
    assert isinstance(findings, list)


def test_secret_pattern_performance():
    """Test that secret patterns don't cause catastrophic backtracking."""
    analyzer = MobileAPKAnalyzer('/tmp/test.apk')
    analyzer.extracted_dir = tempfile.mkdtemp()

    # Create file with long string to test regex performance
    test_file = os.path.join(analyzer.extracted_dir, 'large.txt')
    with open(test_file, 'w') as f:
        f.write('a' * 10000)  # Large file without secrets

    import time
    start = time.time()
    analyzer.find_hardcoded_secrets()
    elapsed = time.time() - start

    # Should complete quickly (< 1 second)
    assert elapsed < 1.0

    os.unlink(test_file)
    os.rmdir(analyzer.extracted_dir)
