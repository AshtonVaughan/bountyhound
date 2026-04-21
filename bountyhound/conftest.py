"""
Pytest configuration and shared fixtures for BountyHound test suite.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock
import sys
import platform


# ============================================================================
# Session-level fixtures
# ============================================================================

@pytest.fixture(scope="session")
def test_data_dir():
    """Directory containing test data files."""
    return Path(__file__).parent / "tests" / "data"


@pytest.fixture(scope="session")
def platform_info():
    """Information about the test platform."""
    return {
        'system': platform.system(),
        'is_windows': platform.system() == 'Windows',
        'is_unix': platform.system() in ['Linux', 'Darwin'],
        'is_macos': platform.system() == 'Darwin',
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}"
    }


# ============================================================================
# Function-level fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def mock_apk_path(temp_dir):
    """Create a mock APK file for testing."""
    apk_path = temp_dir / "test.apk"
    apk_path.write_bytes(b'PK\x03\x04')  # ZIP header
    return apk_path


@pytest.fixture
def mock_ipa_path(temp_dir):
    """Create a mock IPA file for testing."""
    ipa_path = temp_dir / "test.ipa"
    ipa_path.write_bytes(b'PK\x03\x04')  # ZIP header
    return ipa_path


@pytest.fixture
def mock_solidity_contract(temp_dir):
    """Create a mock Solidity contract file."""
    contract_path = temp_dir / "test.sol"
    contract_path.write_text("""
pragma solidity ^0.8.0;

contract Test {
    mapping(address => uint) public balances;

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
""")
    return contract_path


@pytest.fixture
def mock_aws_credentials(monkeypatch):
    """Mock AWS credentials for testing."""
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7EXAMPLE')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')


@pytest.fixture
def mock_boto3_client(monkeypatch):
    """Mock boto3 client for AWS testing."""
    mock_client = MagicMock()

    try:
        import boto3
        original_client = boto3.client

        def mock_client_factory(*args, **kwargs):
            return mock_client

        monkeypatch.setattr(boto3, 'client', mock_client_factory)
    except ImportError:
        # boto3 not installed, return mock anyway
        pass

    return mock_client


@pytest.fixture
def capture_colorama_output(monkeypatch):
    """Capture colorized terminal output."""
    try:
        from colorama import Fore, Style

        # Disable colorama for testing
        monkeypatch.setattr(Fore, 'GREEN', '')
        monkeypatch.setattr(Fore, 'RED', '')
        monkeypatch.setattr(Fore, 'YELLOW', '')
        monkeypatch.setattr(Fore, 'CYAN', '')
        monkeypatch.setattr(Style, 'RESET_ALL', '')
    except ImportError:
        # colorama not installed, skip
        pass


# ============================================================================
# Test markers
# ============================================================================

def pytest_configure(config):
    """Configure custom test markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


# ============================================================================
# Test collection hooks
# ============================================================================

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add 'unit' marker to all tests by default
        if not any(marker.name in ['integration', 'slow'] for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)

        # Add platform-specific markers
        if platform.system() == 'Windows':
            if 'unix_only' in item.keywords:
                item.add_marker(pytest.mark.skip(reason="Unix/Linux only test"))
        else:
            if 'windows_only' in item.keywords:
                item.add_marker(pytest.mark.skip(reason="Windows only test"))


# ============================================================================
# Cleanup hooks
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup temp files after each test."""
    yield
    # Cleanup logic runs after test
    temp_patterns = [
        'dumps',
        'test_output',
        '*.pyc',
        '__pycache__'
    ]
    for pattern in temp_patterns:
        try:
            for path in Path('.').glob(f'**/{pattern}'):
                try:
                    if path.is_dir():
                        shutil.rmtree(path, ignore_errors=True)
                    elif path.is_file():
                        path.unlink(missing_ok=True)
                except (PermissionError, OSError):
                    pass
        except (FileNotFoundError, OSError):
            # Directory disappeared during traversal (e.g. __pycache__ deleted mid-glob)
            pass
