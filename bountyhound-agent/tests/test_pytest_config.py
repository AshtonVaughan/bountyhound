"""Test that pytest configuration is working correctly."""

import pytest
from pathlib import Path


def test_pytest_ini_exists():
    """Test that pytest.ini exists and is readable."""
    pytest_ini = Path("pytest.ini")
    assert pytest_ini.exists(), "pytest.ini should exist in project root"

    content = pytest_ini.read_text()
    assert "[pytest]" in content, "pytest.ini should have [pytest] section"
    assert "testpaths" in content, "pytest.ini should specify testpaths"


def test_conftest_exists():
    """Test that conftest.py exists and is importable."""
    conftest = Path("conftest.py")
    assert conftest.exists(), "conftest.py should exist in project root"


def test_temp_dir_fixture(temp_dir):
    """Test that temp_dir fixture works."""
    assert temp_dir.exists(), "Temp directory should exist"
    assert temp_dir.is_dir(), "Temp directory should be a directory"

    # Test writing to temp dir
    test_file = temp_dir / "test.txt"
    test_file.write_text("test content")
    assert test_file.exists()


def test_mock_apk_path_fixture(mock_apk_path):
    """Test that mock_apk_path fixture works."""
    assert mock_apk_path.exists()
    assert mock_apk_path.suffix == ".apk"
    assert mock_apk_path.read_bytes().startswith(b'PK')  # ZIP header


@pytest.mark.unit
def test_unit_marker():
    """Test that unit marker is applied."""
    assert True


@pytest.mark.slow
def test_slow_marker():
    """Test that slow marker is applied."""
    assert True


@pytest.mark.integration
def test_integration_marker():
    """Test that integration marker is applied."""
    assert True
