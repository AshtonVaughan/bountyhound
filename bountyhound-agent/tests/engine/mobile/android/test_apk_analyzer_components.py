import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
from engine.mobile.android.apk_analyzer import APKAnalyzer

def test_detects_exported_components_with_boolean():
    """Test detection of exported components when XML uses boolean true"""
    # Create mock AndroidManifest.xml with exported component (boolean)
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".VulnerableActivity"
                  android:exported="true" />
        <activity android:name=".SafeActivity"
                  android:exported="false" />
    </application>
</manifest>"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(manifest_xml)
        manifest_file = Path(f.name)

    try:
        analyzer = APKAnalyzer.__new__(APKAnalyzer)
        analyzer.output_dir = manifest_file.parent
        analyzer.findings = []

        # Parse and check components
        tree = ET.parse(manifest_file)
        root = tree.getroot()

        # Manually call the component detection logic
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        for activity in root.findall('.//activity', ns):
            exported = activity.get('{http://schemas.android.com/apk/res/android}exported')

            # The fix should detect this
            is_exported = analyzer._is_exported(exported)

            name = activity.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')

            if is_exported and 'Vulnerable' in name:
                # Should detect VulnerableActivity as exported
                assert True
                return

        pytest.fail("Failed to detect exported component with boolean true")

    finally:
        manifest_file.unlink()

def test_detects_exported_components_with_string():
    """Test detection when XML uses string 'true'"""
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <service android:name=".VulnerableService"
                 android:exported="true" />
    </application>
</manifest>"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(manifest_xml)
        manifest_file = Path(f.name)

    try:
        analyzer = APKAnalyzer.__new__(APKAnalyzer)
        analyzer.findings = []

        tree = ET.parse(manifest_file)
        root = tree.getroot()

        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        for service in root.findall('.//service', ns):
            exported = service.get('{http://schemas.android.com/apk/res/android}exported')
            is_exported = analyzer._is_exported(exported)

            assert is_exported, "Should detect string 'true' as exported"

    finally:
        manifest_file.unlink()

def test_is_exported_helper_function():
    """Test the _is_exported() helper function with various inputs"""
    analyzer = APKAnalyzer.__new__(APKAnalyzer)

    # Should return True for these values
    assert analyzer._is_exported('true') == True
    assert analyzer._is_exported(True) == True
    assert analyzer._is_exported('True') == True

    # Should return False for these values
    assert analyzer._is_exported('false') == False
    assert analyzer._is_exported(False) == False
    assert analyzer._is_exported(None) == False
    assert analyzer._is_exported('') == False
    assert analyzer._is_exported('random') == False
