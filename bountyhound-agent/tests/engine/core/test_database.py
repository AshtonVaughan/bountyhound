"""
Tests for BountyHoundDB class
"""

import pytest
import os
import tempfile
from datetime import date, timedelta
from engine.core.database import BountyHoundDB


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = BountyHoundDB(db_path=db_path)
        yield db


def test_database_initialization(temp_db):
    """Test database is initialized with all tables"""
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()

        # Check all 8 tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            'targets', 'findings', 'testing_sessions', 'successful_payloads',
            'assets', 'recon_data', 'notes', 'automation_runs'
        }

        assert expected_tables.issubset(tables), \
            f"Missing tables: {expected_tables - tables}"


def test_get_or_create_target(temp_db):
    """Test creating and retrieving targets"""
    # Create new target
    target_id1 = temp_db.get_or_create_target('example.com')
    assert target_id1 is not None
    assert target_id1 > 0

    # Get existing target
    target_id2 = temp_db.get_or_create_target('example.com')
    assert target_id1 == target_id2, "Should return same ID for existing target"

    # Create different target
    target_id3 = temp_db.get_or_create_target('different.com')
    assert target_id3 != target_id1, "Different domain should get different ID"


def test_get_target_stats_nonexistent(temp_db):
    """Test getting stats for nonexistent target returns None"""
    stats = temp_db.get_target_stats('nonexistent.com')
    assert stats is None


def test_get_target_stats(temp_db):
    """Test getting target statistics"""
    # Create target and add some data
    target_id = temp_db.get_or_create_target('example.com')

    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE targets
            SET total_findings = 5, accepted_findings = 3,
                total_payouts = 1500.0, last_tested = ?
            WHERE id = ?
        """, (date.today().isoformat(), target_id))

    # Get stats
    stats = temp_db.get_target_stats('example.com')

    assert stats is not None
    assert stats['domain'] == 'example.com'
    assert stats['total_findings'] == 5
    assert stats['accepted_findings'] == 3
    assert stats['total_payouts'] == 1500.0
    assert stats['last_tested'] == date.today()


def test_record_tool_run(temp_db):
    """Test recording tool runs"""
    temp_db.record_tool_run('example.com', 's3_enumerator', findings_count=3, success=True)

    # Verify it was recorded
    run = temp_db.get_last_tool_run('example.com', 's3_enumerator')

    assert run is not None
    assert run['findings_count'] == 3
    assert run['success'] == 1  # SQLite stores boolean as 1
    assert run['run_date'] == date.today()


def test_get_last_tool_run_nonexistent(temp_db):
    """Test getting last run for tool that was never run"""
    run = temp_db.get_last_tool_run('example.com', 'nonexistent_tool')
    assert run is None


def test_get_recent_findings(temp_db):
    """Test retrieving recent findings"""
    target_id = temp_db.get_or_create_target('example.com')

    # Add some findings
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        for i in range(5):
            cursor.execute("""
                INSERT INTO findings (target_id, title, severity, vuln_type, discovered_date, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (target_id, f"Finding {i}", "HIGH", "IDOR", date.today().isoformat(), "accepted"))

    # Get recent findings
    findings = temp_db.get_recent_findings('example.com', limit=3)

    assert len(findings) == 3
    assert all(f['severity'] == 'HIGH' for f in findings)


def test_find_similar_findings(temp_db):
    """Test duplicate finding detection"""
    target_id = temp_db.get_or_create_target('example.com')

    # Add a finding
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings
            (target_id, title, severity, vuln_type, discovered_date, status, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_id, "IDOR in API users endpoint", "HIGH", "IDOR",
              date.today().isoformat(), "accepted", "Can access other users data"))

    # Search for similar
    similar = temp_db.find_similar_findings('example.com', 'IDOR', ['api', 'users'])

    assert similar is not None
    assert 'users' in similar['title'].lower()
    assert 'api' in similar['title'].lower()
    assert similar['status'] == 'accepted'


def test_find_similar_findings_no_match(temp_db):
    """Test finding no similar findings"""
    similar = temp_db.find_similar_findings('example.com', 'XSS', ['login', 'form'])
    assert similar is None


def test_database_persistence(temp_db):
    """Test data persists across connections"""
    # Create target
    temp_db.get_or_create_target('example.com')
    temp_db.record_tool_run('example.com', 'test_tool', findings_count=5)

    # Create new database instance with same path
    db2 = BountyHoundDB(db_path=temp_db.db_path)

    # Data should persist
    run = db2.get_last_tool_run('example.com', 'test_tool')
    assert run is not None
    assert run['findings_count'] == 5


def test_get_findings_by_tool_filters_correctly(temp_db):
    """get_findings_by_tool should return only findings from that specific tool."""
    target_id = temp_db.get_or_create_target('example.com')

    # Add findings from different tools
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings
            (target_id, title, severity, vuln_type, discovered_date, status, tool_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_id, "SSRF in API", "HIGH", "SSRF", date.today().isoformat(), "accepted", "ssrf_tester"))

        cursor.execute("""
            INSERT INTO findings
            (target_id, title, severity, vuln_type, discovered_date, status, tool_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_id, "Another SSRF", "MEDIUM", "SSRF", date.today().isoformat(), "pending", "ssrf_tester"))

        cursor.execute("""
            INSERT INTO findings
            (target_id, title, severity, vuln_type, discovered_date, status, tool_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_id, "XSS in form", "MEDIUM", "XSS", date.today().isoformat(), "accepted", "xss_tester"))

    # Should only return SSRF findings from ssrf_tester
    ssrf_findings = temp_db.get_findings_by_tool('example.com', 'ssrf_tester')

    assert isinstance(ssrf_findings, list)
    assert len(ssrf_findings) == 2
    assert all(f['tool_name'] == 'ssrf_tester' for f in ssrf_findings)
    assert all('SSRF' in f['title'] for f in ssrf_findings)

    # Should only return XSS findings from xss_tester
    xss_findings = temp_db.get_findings_by_tool('example.com', 'xss_tester')
    assert len(xss_findings) == 1
    assert xss_findings[0]['tool_name'] == 'xss_tester'
    assert 'XSS' in xss_findings[0]['title']
