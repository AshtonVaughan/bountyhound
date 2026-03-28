"""
Global test fixtures for BountyHound test suite.

This file provides shared fixtures used across all test modules.
"""

import pytest
import tempfile
import shutil
import sqlite3
from pathlib import Path
from unittest.mock import Mock, MagicMock


# ============================================================================
# Directory and file fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """
    Create a temporary directory for test files.

    Returns:
        Path: Path to temporary directory

    The directory and all contents are automatically cleaned up after the test.
    """
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
# Target fixtures
# ============================================================================

@pytest.fixture
def sample_target():
    """
    Return a safe test target domain.

    Returns:
        str: Safe test domain (testphp.vulnweb.com)
    """
    return "testphp.vulnweb.com"


@pytest.fixture
def sample_targets():
    """
    Return a list of safe test target domains.

    Returns:
        list[str]: List of safe test domains
    """
    return [
        "testphp.vulnweb.com",
        "testaspnet.vulnweb.com",
        "testasp.vulnweb.com"
    ]


# ============================================================================
# Database fixtures
# ============================================================================

@pytest.fixture
def mock_db(temp_dir):
    """
    Create a temporary test database with schema.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path: Path to temporary database file

    The database includes the full BountyHound schema but no data.
    """
    db_path = temp_dir / "test_bountyhound.db"

    # Create database with basic schema
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create minimal schema for testing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_tested TIMESTAMP,
            total_findings INTEGER DEFAULT 0,
            total_payouts REAL DEFAULT 0.0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'draft',
            payout REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            findings_count INTEGER DEFAULT 0,
            duration_seconds REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            tech_stack TEXT,
            success_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    yield db_path

    # Cleanup is handled by temp_dir fixture


@pytest.fixture
def mock_db_connection(mock_db):
    """
    Return a connection to the mock database.

    Args:
        mock_db: Mock database path fixture

    Returns:
        sqlite3.Connection: Database connection
    """
    conn = sqlite3.connect(str(mock_db))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# ============================================================================
# HTTP and API fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """
    Create a mock HTTP response object.

    Returns:
        Mock: Mock response with common attributes
    """
    response = Mock()
    response.status_code = 200
    response.text = "Test response"
    response.json.return_value = {"test": "data"}
    response.headers = {"Content-Type": "application/json"}
    return response


@pytest.fixture
def mock_graphql_response():
    """
    Create a mock GraphQL response.

    Returns:
        Mock: Mock GraphQL response
    """
    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {"test": "value"},
        "errors": None
    }
    return response


# ============================================================================
# File fixtures
# ============================================================================

@pytest.fixture
def sample_html_file(temp_dir):
    """
    Create a sample HTML file for testing.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path: Path to HTML file
    """
    html_path = temp_dir / "test.html"
    html_path.write_text("""
        <!DOCTYPE html>
        <html>
        <head><title>Test Page</title></head>
        <body>
            <form action="/submit" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    """)
    return html_path


@pytest.fixture
def sample_json_file(temp_dir):
    """
    Create a sample JSON file for testing.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path: Path to JSON file
    """
    import json
    json_path = temp_dir / "test.json"
    json_path.write_text(json.dumps({
        "endpoints": ["/api/users", "/api/posts"],
        "auth": {"type": "bearer"}
    }, indent=2))
    return json_path


# ============================================================================
# Payload fixtures
# ============================================================================

@pytest.fixture
def sample_xss_payloads():
    """
    Return sample XSS payloads for testing.

    Returns:
        list[str]: List of XSS test payloads
    """
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>"
    ]


@pytest.fixture
def sample_sqli_payloads():
    """
    Return sample SQL injection payloads for testing.

    Returns:
        list[str]: List of SQLi test payloads
    """
    return [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "admin'--",
        "1' AND SLEEP(5)--"
    ]


# ============================================================================
# Mock service fixtures
# ============================================================================

@pytest.fixture
def mock_browser():
    """
    Create a mock browser object for testing.

    Returns:
        Mock: Mock browser with common methods
    """
    browser = MagicMock()
    browser.navigate.return_value = True
    browser.click.return_value = True
    browser.type.return_value = True
    browser.get_text.return_value = "Test content"
    return browser


@pytest.fixture
def mock_nuclei_runner():
    """
    Create a mock Nuclei scanner runner.

    Returns:
        Mock: Mock Nuclei runner
    """
    runner = MagicMock()
    runner.run.return_value = {
        "findings": [],
        "duration": 10.5
    }
    return runner


# ============================================================================
# Cleanup fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_test_artifacts():
    """
    Automatically cleanup test artifacts after each test.

    This fixture runs automatically for every test.
    """
    yield

    # Cleanup patterns
    patterns = [
        "*.pyc",
        "__pycache__",
        ".pytest_cache",
        "*.log",
        "test_output*"
    ]

    for pattern in patterns:
        try:
            paths = list(Path('.').glob(f'**/{pattern}'))
            for path in paths:
                try:
                    if path.is_dir():
                        shutil.rmtree(path, ignore_errors=True)
                    elif path.is_file():
                        path.unlink(missing_ok=True)
                except (PermissionError, OSError):
                    # Skip files that can't be deleted
                    pass
        except (FileNotFoundError, OSError):
            pass
