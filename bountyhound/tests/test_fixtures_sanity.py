"""
Sanity test to verify all global fixtures work correctly.
"""

import pytest
from pathlib import Path


def test_temp_dir_fixture(temp_dir):
    """Test that temp_dir fixture creates a directory."""
    assert temp_dir.exists()
    assert temp_dir.is_dir()

    # Write a test file
    test_file = temp_dir / "test.txt"
    test_file.write_text("test content")
    assert test_file.exists()


def test_sample_target_fixture(sample_target):
    """Test that sample_target fixture returns a valid domain."""
    assert sample_target == "testphp.vulnweb.com"
    assert isinstance(sample_target, str)
    assert "." in sample_target


def test_mock_db_fixture(mock_db):
    """Test that mock_db fixture creates a database."""
    assert mock_db.exists()
    assert mock_db.suffix == ".db"


def test_mock_db_connection_fixture(mock_db_connection):
    """Test that mock_db_connection fixture returns a connection."""
    # Execute a simple query
    cursor = mock_db_connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    # Verify expected tables exist
    assert "targets" in tables
    assert "findings" in tables
    assert "tool_runs" in tables
    assert "payloads" in tables


def test_mock_response_fixture(mock_response):
    """Test that mock_response fixture has expected attributes."""
    assert mock_response.status_code == 200
    assert mock_response.text == "Test response"
    assert mock_response.json() == {"test": "data"}


def test_sample_html_file_fixture(sample_html_file):
    """Test that sample_html_file fixture creates an HTML file."""
    assert sample_html_file.exists()
    content = sample_html_file.read_text()
    assert "<html>" in content
    assert "<form" in content


def test_sample_json_file_fixture(sample_json_file):
    """Test that sample_json_file fixture creates a JSON file."""
    import json
    assert sample_json_file.exists()
    data = json.loads(sample_json_file.read_text())
    assert "endpoints" in data
    assert "auth" in data


def test_xss_payloads_fixture(sample_xss_payloads):
    """Test that XSS payloads fixture returns a list."""
    assert isinstance(sample_xss_payloads, list)
    assert len(sample_xss_payloads) > 0
    assert any("<script>" in p for p in sample_xss_payloads)


def test_sqli_payloads_fixture(sample_sqli_payloads):
    """Test that SQLi payloads fixture returns a list."""
    assert isinstance(sample_sqli_payloads, list)
    assert len(sample_sqli_payloads) > 0
    assert any("UNION" in p for p in sample_sqli_payloads)
