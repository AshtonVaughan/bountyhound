"""
Extended test coverage for APK analyzer
Adds tests for initialization, validation, metadata extraction, and error handling
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from engine.mobile.android.apk_analyzer import APKAnalyzer


def test_apk_analyzer_init():
    """Test APK analyzer initialization with valid APK"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.apk', delete=False) as f:
        f.write(b'PK\x03\x04')  # Minimal APK (ZIP) header
        apk_file = Path(f.name)

    try:
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(apk_file))

            assert analyzer.apk_path == apk_file.resolve()
            assert analyzer.findings == []
            assert analyzer.output_dir.exists()
    finally:
        apk_file.unlink()
        if analyzer.output_dir.exists():
            analyzer.output_dir.rmdir()


def test_apk_analyzer_validate_path_invalid():
    """Test path validation rejects dangerous characters"""
    # Test shell metacharacters
    dangerous_paths = [
        'test.apk; rm -rf /',
        'test.apk | cat',
        'test.apk && whoami',
        'test.apk $(echo hack)',
        'test`whoami`.apk'
    ]

    for path in dangerous_paths:
        with pytest.raises(ValueError, match="shell metacharacters"):
            APKAnalyzer(path)


def test_apk_analyzer_validate_path_non_apk():
    """Test path validation rejects non-APK files"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('not an apk')
        txt_file = Path(f.name)

    try:
        with pytest.raises(ValueError, match="must be .apk"):
            APKAnalyzer(str(txt_file))
    finally:
        txt_file.unlink()


def test_apk_analyzer_validate_path_traversal():
    """Test path validation detects path traversal"""
    with pytest.raises(ValueError, match="path traversal"):
        APKAnalyzer('../../../etc/passwd.apk')


def test_apk_analyzer_extract_metadata_structure():
    """Test metadata extraction returns correct structure when androguard not available"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.apk', delete=False) as f:
        f.write(b'PK\x03\x04')
        apk_file = Path(f.name)

    try:
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(apk_file))

            # When androguard is not available, get_apk_info returns empty dict
            info = analyzer.get_apk_info()

            # Should return empty dict when androguard not available
            assert isinstance(info, dict)
    finally:
        apk_file.unlink()


def test_apk_analyzer_find_endpoints_returns_list():
    """Test endpoint discovery returns list"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.apk', delete=False) as f:
        f.write(b'PK\x03\x04')
        apk_file = Path(f.name)

    try:
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(apk_file))
            endpoints = analyzer.extract_api_endpoints()

            assert isinstance(endpoints, list)
    finally:
        apk_file.unlink()


def test_apk_analyzer_error_handling():
    """Test analyzer handles missing APK gracefully"""
    with pytest.raises(ValueError, match="does not exist"):
        APKAnalyzer('/nonexistent/path/to/app.apk')


def test_apk_analyzer_add_finding():
    """Test adding security findings"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.apk', delete=False) as f:
        f.write(b'PK\x03\x04')
        apk_file = Path(f.name)

    try:
        with patch('engine.mobile.android.apk_analyzer.ANDROGUARD_AVAILABLE', False):
            analyzer = APKAnalyzer(str(apk_file))

            analyzer.add_finding('HIGH', 'Test Finding', 'Test description')

            assert len(analyzer.findings) == 1
            assert analyzer.findings[0]['severity'] == 'HIGH'
            assert analyzer.findings[0]['title'] == 'Test Finding'
            assert analyzer.findings[0]['description'] == 'Test description'
    finally:
        apk_file.unlink()
