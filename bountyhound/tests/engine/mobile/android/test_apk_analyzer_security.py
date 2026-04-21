import pytest
from pathlib import Path
from engine.mobile.android.apk_analyzer import APKAnalyzer

def test_rejects_invalid_apk_path():
    """Test that malicious paths are rejected"""
    with pytest.raises(ValueError, match="Invalid APK path"):
        analyzer = APKAnalyzer("evil.apk; rm -rf /")

def test_rejects_non_apk_file():
    """Test that non-APK files are rejected"""
    with pytest.raises(ValueError, match="File must be .apk"):
        analyzer = APKAnalyzer("test.txt")

def test_rejects_nonexistent_file():
    """Test that nonexistent files are rejected"""
    with pytest.raises(ValueError, match="Invalid APK path"):
        analyzer = APKAnalyzer("/nonexistent/path.apk")
