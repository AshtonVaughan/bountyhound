"""
Tests for DatabaseHooks class
"""

import pytest
import os
import tempfile
from datetime import date, timedelta
from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        # Create database
        db = BountyHoundDB(db_path=db_path)

        # Monkey-patch BountyHoundDB to use this test database
        original_init = BountyHoundDB.__init__

        def patched_init(self, db_path_arg=None):
            original_init(self, db_path=db_path)

        BountyHoundDB.__init__ = patched_init

        yield db

        # Restore original
        BountyHoundDB.__init__ = original_init


def test_before_test_never_tested(temp_db):
    """Test database check for never-tested target"""
    context = DatabaseHooks.before_test('new-target.com', 'test_tool')

    assert context['should_skip'] == False
    assert context['reason'] == 'Never tested before'
    assert len(context['previous_findings']) == 0
    assert context['last_tested_days'] is None
    assert 'Full test recommended' in context['recommendations'][0]


def test_before_test_recent(temp_db):
    """Test database check for recently-tested target"""
    # Create target tested 3 days ago
    target_id = temp_db.get_or_create_target('recent.com')

    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        recent_date = (date.today() - timedelta(days=3)).isoformat()
        cursor.execute("UPDATE targets SET last_tested = ? WHERE id = ?", (recent_date, target_id))

    context = DatabaseHooks.before_test('recent.com', 'test_tool')

    assert context['should_skip'] == True
    assert '3 day(s) ago' in context['reason']
    assert 'too recent' in context['reason'].lower()
    assert 'Skip this target' in context['recommendations'][0]


def test_before_test_moderate(temp_db):
    """Test database check for moderately-old target (7-30 days)"""
    # Create target tested 15 days ago
    target_id = temp_db.get_or_create_target('moderate.com')

    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        moderate_date = (date.today() - timedelta(days=15)).isoformat()
        cursor.execute("UPDATE targets SET last_tested = ? WHERE id = ?", (moderate_date, target_id))

    context = DatabaseHooks.before_test('moderate.com', 'test_tool')

    assert context['should_skip'] == False
    assert '15 day(s) ago' in context['reason']
    assert 'Selective retest recommended' in context['recommendations'][0]


def test_before_test_old(temp_db):
    """Test database check for old target (>30 days)"""
    # Create target tested 45 days ago
    target_id = temp_db.get_or_create_target('old.com')

    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        old_date = (date.today() - timedelta(days=45)).isoformat()
        cursor.execute("UPDATE targets SET last_tested = ? WHERE id = ?", (old_date, target_id))

    context = DatabaseHooks.before_test('old.com', 'test_tool')

    assert context['should_skip'] == False
    assert '45 day(s) ago' in context['reason']
    assert 'Full retest recommended' in context['recommendations'][0]


def test_before_test_tool_specific_recent(temp_db):
    """Test database check for recently-run tool"""
    target_id = temp_db.get_or_create_target('example.com')

    # Set target as moderately old (20 days)
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        moderate_date = (date.today() - timedelta(days=20)).isoformat()
        cursor.execute("UPDATE targets SET last_tested = ? WHERE id = ?", (moderate_date, target_id))

    # But record tool run 5 days ago
    tool_run_date = (date.today() - timedelta(days=5)).isoformat()
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO automation_runs (target_id, tool_name, run_date, findings_count)
            VALUES (?, ?, ?, ?)
        """, (target_id, 's3_enumerator', tool_run_date, 3))

    context = DatabaseHooks.before_test('example.com', 's3_enumerator')

    # Should skip because tool was run recently (< 14 days)
    assert context['should_skip'] == True
    assert 's3_enumerator was run 5 day(s) ago' in context['reason']


def test_check_duplicate_found(temp_db):
    """Test duplicate detection when similar finding exists"""
    target_id = temp_db.get_or_create_target('example.com')

    # Add existing finding
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings
            (target_id, title, severity, vuln_type, discovered_date, status, description, platform_report_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (target_id, "IDOR in /api/users endpoint", "HIGH", "IDOR",
              date.today().isoformat(), "accepted", "Can read other users", "HO-123456"))

    # Check for duplicate
    result = DatabaseHooks.check_duplicate('example.com', 'IDOR', ['api', 'users'])

    assert result['is_duplicate'] == True
    assert result['match_type'] == 'keyword'
    assert len(result['matches']) > 0
    assert 'users' in result['matches'][0]['title'].lower()
    assert 'REJECT' in result['recommendation']


def test_check_duplicate_not_found(temp_db):
    """Test duplicate detection when no similar finding exists"""
    temp_db.get_or_create_target('example.com')

    result = DatabaseHooks.check_duplicate('example.com', 'XSS', ['login', 'form'])

    assert result['is_duplicate'] == False
    assert result['match_type'] is None
    assert len(result['matches']) == 0
    assert 'PROCEED' in result['recommendation']


def test_get_successful_payloads(temp_db):
    """Test retrieving successful payloads"""
    # Add some successful payloads
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO successful_payloads
            (vuln_type, payload, context, tech_stack, success_count, last_used)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('XSS', '<img src=x onerror=alert(1)>', 'parameter', 'React',
              5, date.today().isoformat()))

        cursor.execute("""
            INSERT INTO successful_payloads
            (vuln_type, payload, context, tech_stack, success_count, last_used)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('XSS', '"><script>alert(1)</script>', 'parameter', 'PHP',
              3, date.today().isoformat()))

    # Get XSS payloads for React
    payloads = DatabaseHooks.get_successful_payloads('XSS', tech_stack='React')

    assert len(payloads) == 1
    assert payloads[0]['payload'] == '<img src=x onerror=alert(1)>'
    assert payloads[0]['success_count'] == 5


def test_get_successful_payloads_all(temp_db):
    """Test retrieving all payloads for a type"""
    # Add payloads
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        for i in range(5):
            cursor.execute("""
                INSERT INTO successful_payloads
                (vuln_type, payload, success_count, last_used)
                VALUES (?, ?, ?, ?)
            """, ('SQLi', f'payload_{i}', 10 - i, date.today().isoformat()))

    # Get all SQLi payloads
    payloads = DatabaseHooks.get_successful_payloads('SQLi')

    assert len(payloads) == 5
    # Should be ordered by success_count DESC
    assert payloads[0]['payload'] == 'payload_0'  # success_count = 10
    assert payloads[0]['success_count'] == 10
