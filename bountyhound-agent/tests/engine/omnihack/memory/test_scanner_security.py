"""
Security tests for memory scanner to prevent arbitrary file write vulnerabilities
"""
import pytest
from pathlib import Path
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from engine.omnihack.memory.scanner import MemoryScanner


@pytest.fixture
def mock_scanner():
    """Create a mock MemoryScanner without attaching to a real process"""
    with patch('engine.omnihack.memory.scanner.pymem.Pymem') as mock_pymem:
        # Mock the pymem instance
        mock_pm = MagicMock()
        mock_pm.process_base.lpBaseOfDll = 0x400000
        mock_pymem.return_value = mock_pm

        scanner = MemoryScanner(process_name="notepad.exe")

        # Mock the read_bytes method to return dummy data
        scanner.pm.read_bytes = Mock(return_value=b'\x00' * 100)

        yield scanner

        # Cleanup dumps directory after each test
        if Path("dumps").exists():
            shutil.rmtree("dumps", ignore_errors=True)


def test_rejects_path_traversal_in_dump(mock_scanner):
    """Test that path traversal in dump filename is prevented"""
    # Try to write outside dumps directory using path traversal
    mock_scanner.dump_region(address=0x1000, size=100, filename="../../etc/passwd")

    # File should be in dumps/ directory with sanitized name (only the basename)
    expected_path = Path("dumps/passwd")
    assert expected_path.exists(), "File should be in dumps/ with sanitized name 'passwd'"

    # Should NOT exist outside dumps/ directory
    traversal_path = Path("../../etc/passwd")
    assert not traversal_path.exists(), "Path traversal should be prevented - file should not exist at ../../etc/passwd"

    # Verify the file was written with correct content
    assert expected_path.stat().st_size == 100, "File should contain 100 bytes"


def test_rejects_empty_filename(mock_scanner):
    """Test that empty filename is rejected"""
    with pytest.raises(ValueError, match="Filename cannot be empty"):
        mock_scanner.dump_region(address=0x1000, size=100, filename="")


def test_rejects_whitespace_only_filename(mock_scanner):
    """Test that whitespace-only filename is rejected"""
    with pytest.raises(ValueError, match="Filename cannot be empty"):
        mock_scanner.dump_region(address=0x1000, size=100, filename="   ")


def test_creates_dumps_directory_if_not_exists(mock_scanner):
    """Test that dumps directory is created if it doesn't exist"""
    # Ensure dumps directory doesn't exist
    if Path("dumps").exists():
        shutil.rmtree("dumps")

    assert not Path("dumps").exists(), "dumps/ should not exist before test"

    # Call dump_region
    mock_scanner.dump_region(address=0x1000, size=100, filename="test.bin")

    # Verify dumps directory was created
    assert Path("dumps").exists(), "dumps/ directory should be created"
    assert Path("dumps/test.bin").exists(), "File should be created in dumps/"


def test_strips_absolute_path(mock_scanner):
    """Test that absolute paths are stripped to just the filename"""
    mock_scanner.dump_region(address=0x1000, size=100, filename="/etc/passwd")

    # Only the basename should be used
    expected_path = Path("dumps/passwd")
    assert expected_path.exists(), "File should be in dumps/ with basename only"


def test_strips_windows_path(mock_scanner):
    """Test that Windows-style paths are stripped to just the filename"""
    mock_scanner.dump_region(address=0x1000, size=100, filename="C:\\Windows\\System32\\config\\SAM")

    # Only the basename should be used
    expected_path = Path("dumps/SAM")
    assert expected_path.exists(), "File should be in dumps/ with basename only"


def test_normal_filename_works(mock_scanner):
    """Test that normal filenames work correctly"""
    mock_scanner.dump_region(address=0x1000, size=100, filename="memory_dump.bin")

    expected_path = Path("dumps/memory_dump.bin")
    assert expected_path.exists(), "Normal filename should work"
    assert expected_path.stat().st_size == 100, "File should contain correct data"
