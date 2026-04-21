"""
Comprehensive test suite for APK analyzer - 95%+ coverage target
Tests all methods including manifest parsing, permissions, activities, services,
receivers, API endpoints, secrets detection, security analysis, and more.
"""

import pytest
import tempfile
import json
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import xml.etree.ElementTree as ET
from engine.mobile.android.apk_analyzer import APKAnalyzer


@pytest.fixture
def mock_apk_file():
    """Create a temporary mock APK file"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.apk', delete=False) as f:
        f.write(b'PK\x03\x04')  # Minimal APK (ZIP) header
        apk_path = Path(f.name)

    yield apk_path

    # Cleanup
    if apk_path.exists():
        apk_path.unlink()


@pytest.fixture
def mock_androguard_apk():
    """Create a mock androguard APK object"""
    mock_apk = Mock()
    mock_apk.get_package.return_value = "com.example.testapp"
    mock_apk.get_androidversion_name.return_value = "1.0.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = "21"
    mock_apk.get_target_sdk_version.return_value = "30"
    mock_apk.get_permissions.return_value = [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.CAMERA"
    ]
    mock_apk.get_activities.return_value = [
        "com.example.testapp.MainActivity",
        "com.example.testapp.SettingsActivity"
    ]
    mock_apk.get_services.return_value = [
        "com.example.testapp.MyService"
    ]
    mock_apk.get_receivers.return_value = [
        "com.example.testapp.MyReceiver"
    ]

    # Mock AndroidManifest XML
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name="com.example.testapp.MainActivity"
                  android:exported="true" />
        <activity android:name="com.example.testapp.SettingsActivity"
                  android:exported="false" />
        <service android:name="com.example.testapp.MyService"
                 android:exported="true" />
        <receiver android:name="com.example.testapp.MyReceiver"
                  android:exported="false" />
    </application>
</manifest>"""

    mock_apk.get_android_manifest_xml.return_value = ET.fromstring(manifest_xml)

    return mock_apk


class TestAPKAnalyzerInit:
    """Test APK analyzer initialization and validation"""

    def test_init_with_valid_apk(self, mock_apk_file):
        """Test initialization with valid APK file"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            assert analyzer.apk_path == mock_apk_file.resolve()
            assert analyzer.findings == []
            assert analyzer.apk is None
            assert analyzer.output_dir.exists()

    def test_init_with_target_name(self, mock_apk_file):
        """Test initialization with custom target name"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file), target="custom.target")

            assert analyzer.target == "custom.target"

    def test_init_uses_package_name_as_target(self, mock_apk_file, mock_androguard_apk):
        """Test that package name is used as target when available"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))

                assert analyzer.target == "com.example.testapp"

    def test_init_falls_back_to_filename(self, mock_apk_file):
        """Test target falls back to filename when package unavailable"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            assert analyzer.target == mock_apk_file.stem

    def test_output_directory_creation(self, mock_apk_file):
        """Test that output directory is created"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            expected_dir = mock_apk_file.parent / f"{mock_apk_file.stem}_analysis"
            assert analyzer.output_dir == expected_dir
            assert analyzer.output_dir.exists()


class TestAPKAnalyzerValidation:
    """Test path validation and security checks"""

    def test_rejects_shell_metacharacters_semicolon(self):
        """Test rejection of semicolon in path"""
        with pytest.raises(ValueError, match="shell metacharacters"):
            APKAnalyzer("test.apk; rm -rf /")

    def test_rejects_shell_metacharacters_pipe(self):
        """Test rejection of pipe in path"""
        with pytest.raises(ValueError, match="shell metacharacters"):
            APKAnalyzer("test.apk | cat")

    def test_rejects_shell_metacharacters_ampersand(self):
        """Test rejection of ampersand in path"""
        with pytest.raises(ValueError, match="shell metacharacters"):
            APKAnalyzer("test.apk && whoami")

    def test_rejects_shell_metacharacters_dollar(self):
        """Test rejection of dollar sign in path"""
        with pytest.raises(ValueError, match="shell metacharacters"):
            APKAnalyzer("test.apk$(whoami)")

    def test_rejects_shell_metacharacters_backtick(self):
        """Test rejection of backtick in path"""
        with pytest.raises(ValueError, match="shell metacharacters"):
            APKAnalyzer("test`whoami`.apk")

    def test_rejects_path_traversal(self):
        """Test rejection of path traversal attempts"""
        with pytest.raises(ValueError, match="path traversal"):
            APKAnalyzer("../../../etc/passwd.apk")

    def test_rejects_non_apk_extension(self):
        """Test rejection of non-APK file extensions"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('test')
            txt_file = Path(f.name)

        try:
            with pytest.raises(ValueError, match="must be .apk"):
                APKAnalyzer(str(txt_file))
        finally:
            txt_file.unlink()

    def test_rejects_nonexistent_file(self):
        """Test rejection of non-existent files"""
        with pytest.raises(ValueError, match="does not exist"):
            APKAnalyzer("/nonexistent/path/test.apk")

    def test_accepts_valid_apk_path(self, mock_apk_file):
        """Test acceptance of valid APK path"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))
            assert analyzer is not None


class TestAPKInfo:
    """Test APK information extraction"""

    def test_get_apk_info_with_androguard(self, mock_apk_file, mock_androguard_apk):
        """Test APK info extraction with androguard available"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                info = analyzer.get_apk_info()

                assert info['package'] == "com.example.testapp"
                assert info['version_name'] == "1.0.0"
                assert info['version_code'] == "1"
                assert info['min_sdk'] == "21"
                assert info['target_sdk'] == "30"
                assert info['permissions_count'] == 3
                assert info['activities_count'] == 2
                assert info['services_count'] == 1

    def test_get_apk_info_without_androguard(self, mock_apk_file):
        """Test APK info returns empty dict without androguard"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))
            info = analyzer.get_apk_info()

            assert info == {}


class TestPermissionsAnalysis:
    """Test permissions analysis"""

    def test_analyze_permissions_detects_dangerous(self, mock_apk_file, mock_androguard_apk):
        """Test detection of dangerous permissions"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                perms = analyzer.analyze_permissions()

                # Should detect READ_SMS and CAMERA as dangerous
                assert len(perms) == 2

                sms_perm = next((p for p in perms if 'READ_SMS' in p['permission']), None)
                assert sms_perm is not None
                assert sms_perm['risk'] == 'HIGH'

                camera_perm = next((p for p in perms if 'CAMERA' in p['permission']), None)
                assert camera_perm is not None

    def test_analyze_permissions_adds_findings(self, mock_apk_file, mock_androguard_apk):
        """Test that dangerous permissions create findings"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                analyzer.analyze_permissions()

                # Should have findings for dangerous permissions
                assert len(analyzer.findings) >= 2

                severities = [f['severity'] for f in analyzer.findings]
                assert 'MEDIUM' in severities

    def test_analyze_permissions_without_androguard(self, mock_apk_file):
        """Test permissions analysis without androguard"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))
            perms = analyzer.analyze_permissions()

            assert perms == []


class TestComponentExtraction:
    """Test extraction of activities, services, and receivers"""

    def test_get_activities(self, mock_apk_file, mock_androguard_apk):
        """Test extraction of activities"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                activities = analyzer.get_activities()

                assert len(activities) == 2
                assert "com.example.testapp.MainActivity" in activities
                assert "com.example.testapp.SettingsActivity" in activities

    def test_get_activities_without_androguard(self, mock_apk_file):
        """Test activities extraction without androguard"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))
            activities = analyzer.get_activities()

            assert activities == []

    def test_get_services(self, mock_apk_file, mock_androguard_apk):
        """Test extraction of services"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                services = analyzer.get_services()

                assert len(services) == 1
                assert "com.example.testapp.MyService" in services

    def test_get_services_without_androguard(self, mock_apk_file):
        """Test services extraction without androguard"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))
            services = analyzer.get_services()

            assert services == []

    def test_get_receivers(self, mock_apk_file, mock_androguard_apk):
        """Test extraction of broadcast receivers"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                receivers = analyzer.get_receivers()

                assert len(receivers) == 1
                assert "com.example.testapp.MyReceiver" in receivers

    def test_get_receivers_without_androguard(self, mock_apk_file):
        """Test receivers extraction without androguard"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))
            receivers = analyzer.get_receivers()

            assert receivers == []


class TestExportedComponents:
    """Test exported components detection"""

    def test_find_exported_components(self, mock_apk_file, mock_androguard_apk):
        """Test finding exported components"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))
                exported = analyzer.find_exported_components()

                # MainActivity (exported activity) and MyService (exported service)
                assert len(exported) == 2

                # Check activity export
                exported_activity = next((c for c in exported if c['type'] == 'activity'), None)
                assert exported_activity is not None
                assert 'MainActivity' in exported_activity['name']
                assert exported_activity['risk'] == 'MEDIUM'

                # Check service export
                exported_service = next((c for c in exported if c['type'] == 'service'), None)
                assert exported_service is not None
                assert exported_service['risk'] == 'HIGH'

    def test_is_exported_with_boolean(self, mock_apk_file):
        """Test _is_exported with boolean values"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            assert analyzer._is_exported(True) == True
            assert analyzer._is_exported(False) == False

    def test_is_exported_with_string(self, mock_apk_file):
        """Test _is_exported with string values"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            assert analyzer._is_exported("true") == True
            assert analyzer._is_exported("True") == True
            assert analyzer._is_exported("TRUE") == True
            assert analyzer._is_exported("false") == False
            assert analyzer._is_exported("False") == False

    def test_is_exported_with_none(self, mock_apk_file):
        """Test _is_exported with None"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            assert analyzer._is_exported(None) == False

    def test_is_exported_component_not_found(self, mock_apk_file, mock_androguard_apk):
        """Test is_exported returns False when component not found"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))

                result = analyzer.is_exported("NonExistentActivity", "activity")
                assert result == False


class TestAPIEndpoints:
    """Test API endpoint extraction"""

    def test_extract_api_endpoints_from_decompiled(self, mock_apk_file):
        """Test extraction of API endpoints from decompiled code"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            # Create mock decompiled directory with Java file
            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Test.java"
            java_file.write_text("""
                public class Test {
                    String apiUrl = "https://api.example.com/v1/users";
                    String backendUrl = "https://backend.example.com/data";
                    String schemaUrl = "https://schema.org/test";  // Should be filtered
                }
            """)

            try:
                # Don't patch decompile_apk since the directory exists
                endpoints = analyzer.extract_api_endpoints()

                assert len(endpoints) >= 2
                assert "https://api.example.com/v1/users" in endpoints
                assert "https://backend.example.com/data" in endpoints
                # schema.org should be filtered
                assert not any("schema.org" in url for url in endpoints)
            finally:
                java_file.unlink()
                import shutil
                shutil.rmtree(decompiled_dir)

    def test_extract_api_endpoints_deduplication(self, mock_apk_file):
        """Test that duplicate URLs are removed"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Test.java"
            java_file.write_text("""
                String url1 = "https://api.example.com/v1/users";
                String url2 = "https://api.example.com/v1/users";
                String url3 = "https://api.example.com/v1/users";
            """)

            try:
                endpoints = analyzer.extract_api_endpoints()

                # Should only have one unique URL
                assert endpoints.count("https://api.example.com/v1/users") == 1
            finally:
                java_file.unlink()
                import shutil
                shutil.rmtree(decompiled_dir)

    def test_extract_api_endpoints_no_decompiled(self, mock_apk_file):
        """Test endpoint extraction when no decompiled directory exists"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            with patch.object(analyzer, 'decompile_apk'):
                endpoints = analyzer.extract_api_endpoints()

                assert endpoints == []


class TestSecretsDetection:
    """Test hardcoded secrets detection"""

    def test_find_aws_access_key(self, mock_apk_file):
        """Test detection of AWS access keys"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Config.java"
            java_file.write_text("""
                public class Config {
                    String awsKey = "AKIAIOSFODNN7EXAMPLE";
                }
            """)

            try:
                secrets = analyzer.find_hardcoded_secrets()

                assert len(secrets) >= 1
                aws_secret = next((s for s in secrets if s['type'] == 'AWS Access Key'), None)
                assert aws_secret is not None
                assert 'AKIAIOSFODNN7EXAMPLE' in aws_secret['value']
                assert aws_secret['severity'] == 'CRITICAL'
            finally:
                java_file.unlink()
                shutil.rmtree(decompiled_dir)

    def test_find_github_token(self, mock_apk_file):
        """Test detection of GitHub tokens"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Auth.java"
            # GitHub token pattern: ghp_ followed by exactly 36 alphanumeric chars
            java_file.write_text("""
                String token = "ghp_123456789012345678901234567890123456";
            """)

            try:
                secrets = analyzer.find_hardcoded_secrets()

                github_secret = next((s for s in secrets if s['type'] == 'GitHub Token'), None)
                assert github_secret is not None
            finally:
                java_file.unlink()
                import shutil
                shutil.rmtree(decompiled_dir)

    def test_find_google_api_key(self, mock_apk_file):
        """Test detection of Google API keys"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Maps.java"
            # Google API key: AIza followed by exactly 35 chars
            java_file.write_text("""
                String apiKey = "AIzaSyDemoKey1234567890abcdefghijkl";
            """)

            try:
                secrets = analyzer.find_hardcoded_secrets()

                google_secret = next((s for s in secrets if s['type'] == 'Google API Key'), None)
                assert google_secret is not None
            finally:
                java_file.unlink()
                import shutil
                shutil.rmtree(decompiled_dir)

    def test_secrets_create_findings(self, mock_apk_file):
        """Test that found secrets create CRITICAL findings"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Secret.java"
            java_file.write_text("""
                String key = "AKIAIOSFODNN7EXAMPLE";
            """)

            try:
                analyzer.find_hardcoded_secrets()

                critical_findings = [f for f in analyzer.findings if f['severity'] == 'CRITICAL']
                assert len(critical_findings) >= 1
            finally:
                java_file.unlink()
                shutil.rmtree(decompiled_dir)

    def test_no_secrets_when_no_decompiled(self, mock_apk_file):
        """Test secrets detection when no decompiled directory exists"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            secrets = analyzer.find_hardcoded_secrets()

            assert secrets == []


class TestInsecureMethods:
    """Test insecure methods detection"""

    def test_find_javascript_enabled(self, mock_apk_file):
        """Test detection of JavaScript enabled in WebView"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "WebActivity.java"
            java_file.write_text("""
                webView.getSettings().setJavaScriptEnabled(true);
            """)

            try:
                insecure = analyzer.find_insecure_methods()

                js_finding = next((m for m in insecure if 'JavaScript' in m['description']), None)
                assert js_finding is not None
                assert js_finding['severity'] == 'HIGH'
            finally:
                java_file.unlink()
                shutil.rmtree(decompiled_dir)

    def test_find_custom_trustmanager(self, mock_apk_file):
        """Test detection of custom TrustManager"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Network.java"
            java_file.write_text("""
                TrustManager[] trustAllCerts = new TrustManager[]{...};
            """)

            try:
                insecure = analyzer.find_insecure_methods()

                trust_finding = next((m for m in insecure if 'TrustManager' in m['method']), None)
                assert trust_finding is not None
            finally:
                java_file.unlink()
                shutil.rmtree(decompiled_dir)

    def test_find_world_readable(self, mock_apk_file):
        """Test detection of world-readable files"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            java_file = decompiled_dir / "Storage.java"
            java_file.write_text("""
                int mode = MODE_WORLD_READABLE;
            """)

            try:
                insecure = analyzer.find_insecure_methods()

                readable_finding = next((m for m in insecure if 'WORLD_READABLE' in m['method']), None)
                assert readable_finding is not None
            finally:
                java_file.unlink()
                shutil.rmtree(decompiled_dir)


class TestDecompilation:
    """Test APK decompilation"""

    def test_decompile_uses_cached_if_exists(self, mock_apk_file):
        """Test that decompilation uses cached results"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            # Create decompiled directory
            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            try:
                with patch('subprocess.run') as mock_run:
                    with patch('builtins.print'):  # Suppress print
                        analyzer.decompile_apk()

                    # Should not call subprocess if directory exists
                    mock_run.assert_not_called()
            finally:
                shutil.rmtree(decompiled_dir)

    def test_decompile_calls_jadx(self, mock_apk_file):
        """Test that decompilation calls jadx"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            with patch('subprocess.run') as mock_run:
                analyzer.decompile_apk()

                # Should call jadx
                mock_run.assert_called_once()
                call_args = mock_run.call_args[0][0]
                assert call_args[0] == "jadx"

    def test_decompile_handles_jadx_not_found(self, mock_apk_file):
        """Test graceful handling when jadx is not installed"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            with patch('subprocess.run', side_effect=FileNotFoundError):
                # Should not raise exception
                analyzer.decompile_apk()


class TestReporting:
    """Test report generation and findings"""

    def test_add_finding(self, mock_apk_file):
        """Test adding security findings"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            analyzer.add_finding("HIGH", "Test Vulnerability", "Description of issue")

            assert len(analyzer.findings) == 1
            assert analyzer.findings[0]['severity'] == "HIGH"
            assert analyzer.findings[0]['title'] == "Test Vulnerability"
            assert analyzer.findings[0]['description'] == "Description of issue"

    def test_save_report(self, mock_apk_file):
        """Test saving analysis report"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            results = {
                "apk_info": {},
                "permissions": [],
                "api_endpoints": ["https://api.example.com"],
                "secrets": [],
                "findings": []
            }

            # Suppress print output during test
            with patch('builtins.print'):
                analyzer.save_report(results)

            report_path = analyzer.output_dir / "security_report.json"
            assert report_path.exists()

            # Verify report content
            with open(report_path) as f:
                saved_report = json.load(f)
                assert saved_report['api_endpoints'] == ["https://api.example.com"]


class TestFullAnalysis:
    """Test complete analysis workflow"""

    def test_analyze_with_database_skip(self, mock_apk_file):
        """Test analysis respects database skip recommendations"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            mock_context = {
                'should_skip': True,
                'reason': 'Tested recently',
                'previous_findings': []
            }

            with patch('engine.mobile.android.apk_analyzer.DatabaseHooks.before_test', return_value=mock_context):
                results = analyzer.analyze()

                assert results['skipped'] == True
                assert results['reason'] == 'Tested recently'

    def test_analyze_full_workflow(self, mock_apk_file, mock_androguard_apk):
        """Test complete analysis workflow"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            with patch('engine.mobile.android.apk_analyzer.APK', return_value=mock_androguard_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))

                mock_context = {
                    'should_skip': False,
                    'reason': 'Ready to test'
                }

                with patch('engine.mobile.android.apk_analyzer.DatabaseHooks.before_test', return_value=mock_context):
                    with patch.object(analyzer, 'decompile_apk'):
                        with patch('engine.core.database.BountyHoundDB') as mock_db:
                            with patch('builtins.print'):  # Suppress print output
                                results = analyzer.analyze()

                            assert 'apk_info' in results
                            assert 'permissions' in results
                            assert 'api_endpoints' in results
                            assert 'secrets' in results
                            assert 'activities' in results
                            assert 'services' in results
                            assert 'receivers' in results
                            assert 'exported_components' in results
                            assert 'insecure_methods' in results
                            assert 'findings' in results

    def test_analyze_records_tool_run(self, mock_apk_file):
        """Test that analysis records tool run in database"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            mock_context = {
                'should_skip': False,
                'reason': 'Ready to test'
            }

            with patch('engine.mobile.android.apk_analyzer.DatabaseHooks.before_test', return_value=mock_context):
                with patch.object(analyzer, 'decompile_apk'):
                    with patch('engine.core.database.BountyHoundDB') as mock_db_class:
                        mock_db = Mock()
                        mock_db_class.return_value = mock_db

                        analyzer.analyze()

                        # Verify database record was created
                        mock_db.record_tool_run.assert_called_once()


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_handles_file_read_errors_in_endpoints(self, mock_apk_file):
        """Test graceful handling of file read errors during endpoint extraction"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(mock_apk_file))

            decompiled_dir = analyzer.output_dir / "decompiled"
            decompiled_dir.mkdir(parents=True, exist_ok=True)

            # Create file that will cause read error
            java_file = decompiled_dir / "Bad.java"
            java_file.touch()

            try:
                with patch.object(Path, 'read_text', side_effect=Exception("Read error")):
                    # Should not raise exception
                    endpoints = analyzer.extract_api_endpoints()
                    assert isinstance(endpoints, list)
            finally:
                java_file.unlink()
                decompiled_dir.rmdir()

    def test_handles_manifest_parsing_errors(self, mock_apk_file):
        """Test graceful handling of manifest parsing errors"""
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', True):
            mock_apk = Mock()
            mock_apk.get_package.return_value = "com.test"
            mock_apk.get_activities.return_value = ["TestActivity"]
            mock_apk.get_android_manifest_xml.side_effect = Exception("Parse error")

            with patch('androguard.core.apk.APK', return_value=mock_apk):
                analyzer = APKAnalyzer(str(mock_apk_file))

                # Should return False when parsing fails
                result = analyzer.is_exported("TestActivity", "activity")
                assert result == False
