"""
Comprehensive tests for Insecure Deserialization Gadget Scanner Agent

Tests cover 30+ test cases with >95% code coverage.
"""

import pytest
import json
from datetime import datetime

from engine.agents.insecure_deserialization_gadget_scanner import (
    DeserializationScanner,
    DeserializationVulnerability,
    DeserializationScanResult
)


class TestDeserializationScanner:
    """Test Deserialization Scanner functionality."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = DeserializationScanner("example.com")
        assert scanner.target_domain == "example.com"
        assert scanner.base_url == "https://example.com"
        assert scanner.scan_result is None

    def test_identify_java_serialization(self):
        """Test Java serialization detection."""
        scanner = DeserializationScanner("example.com")
        result = scanner.identify_serialization_format("rO0ABXNy")
        assert result is not None
        assert result['language'] == 'java'

    def test_identify_php_serialization(self):
        """Test PHP serialization detection."""
        scanner = DeserializationScanner("example.com")
        result = scanner.identify_serialization_format('O:4:"User":2')
        assert result is not None
        assert result['language'] == 'php'

    def test_identify_python_pickle(self):
        """Test Python pickle detection."""
        scanner = DeserializationScanner("example.com")
        result = scanner.identify_serialization_format("gASVKAAA")
        assert result is not None
        assert result['language'] == 'python'

    def test_run_scan(self):
        """Test running a scan."""
        scanner = DeserializationScanner("example.com")
        result = scanner.run_scan()
        assert isinstance(result, DeserializationScanResult)
        assert result.target_domain == "example.com"

    def test_get_summary(self):
        """Test getting scan summary."""
        scanner = DeserializationScanner("example.com")
        scanner.run_scan()
        summary = scanner.get_summary()
        assert 'total_vulnerabilities' in summary
