"""
Pytest configuration for APK analyzer tests
Mocks androguard module to avoid dependency issues
"""

import sys
from unittest.mock import Mock
import pytest


@pytest.fixture(scope="session", autouse=True)
def mock_androguard():
    """Mock androguard module for testing without installation"""
    # Create mock modules
    mock_androguard = Mock()
    mock_androguard_core = Mock()
    mock_androguard_apk_module = Mock()
    mock_androguard_dex = Mock()

    # Create mock APK and DEX classes
    mock_apk_class = Mock()
    mock_dex_class = Mock()

    # Set up module hierarchy
    mock_androguard.core = mock_androguard_core
    mock_androguard_core.apk = mock_androguard_apk_module
    mock_androguard_core.dex = mock_androguard_dex

    # Add APK and DEX classes to modules
    mock_androguard_apk_module.APK = mock_apk_class
    mock_androguard_dex.DEX = mock_dex_class

    # Add to sys.modules before any imports
    sys.modules['androguard'] = mock_androguard
    sys.modules['androguard.core'] = mock_androguard_core
    sys.modules['androguard.core.apk'] = mock_androguard_apk_module
    sys.modules['androguard.core.dex'] = mock_androguard_dex

    yield

    # Cleanup after tests
    for module in ['androguard', 'androguard.core', 'androguard.core.apk', 'androguard.core.dex']:
        if module in sys.modules:
            del sys.modules[module]

    # Remove apk_analyzer from sys.modules to force reload
    if 'engine.mobile.android.apk_analyzer' in sys.modules:
        del sys.modules['engine.mobile.android.apk_analyzer']
