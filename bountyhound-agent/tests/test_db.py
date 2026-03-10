import pytest
import sqlite3
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from data.db import BountyHoundDB

SCHEMA_FILE = Path(__file__).parent.parent / "data" / "schema.sql"

@pytest.fixture
def db(tmp_path):
    db_file = tmp_path / "test.db"
    conn = sqlite3.connect(db_file)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_FILE.read_text())
    conn.close()
    return BountyHoundDB(db_file)

def test_upsert_and_get_program(db):
    db._conn().execute(
        "INSERT INTO programs (handle, name, platform) VALUES ('test-prog', 'Test', 'hackerone')"
    ).connection.commit()
    result = db.get_program('test-prog')
    assert result is not None
    assert result['handle'] == 'test-prog'

def test_get_program_missing_returns_none(db):
    assert db.get_program('nonexistent') is None

def test_upsert_target_creates_and_returns_id(db):
    db._conn().execute(
        "INSERT INTO programs (handle, platform) VALUES ('prog', 'hackerone')"
    ).connection.commit()
    pid = db._conn().execute("SELECT id FROM programs WHERE handle='prog'").fetchone()[0]
    tid = db.upsert_target(pid, 'example.com', {'tech_stack': {'framework': 'Rails'}})
    assert isinstance(tid, int)
    assert tid > 0

def test_upsert_target_is_idempotent(db):
    db._conn().execute(
        "INSERT INTO programs (handle, platform) VALUES ('prog2', 'hackerone')"
    ).connection.commit()
    pid = db._conn().execute("SELECT id FROM programs WHERE handle='prog2'").fetchone()[0]
    tid1 = db.upsert_target(pid, 'example.com', {'tech_stack': {}})
    tid2 = db.upsert_target(pid, 'example.com', {'tech_stack': {'framework': 'Next.js'}})
    assert tid1 == tid2

def test_insert_finding_and_evidence(db):
    db._conn().execute(
        "INSERT INTO programs (handle, platform) VALUES ('p', 'hackerone')"
    ).connection.commit()
    pid = db._conn().execute("SELECT id FROM programs WHERE handle='p'").fetchone()[0]
    tid = db.upsert_target(pid, 't.com', {})
    fid = db.insert_finding({
        'target_id': tid, 'title': 'IDOR on /api/user',
        'severity': 'high', 'cvss_score': 7.5
    })
    assert fid > 0
    db.insert_evidence(fid, 'gif', '/tmp/test.gif', 'exploit recording')
    conn = db._conn()
    row = conn.execute("SELECT * FROM evidence WHERE finding_id=?", (fid,)).fetchone()
    assert row['evidence_type'] == 'gif'

def test_get_cves_for_tech_returns_list(db):
    db._conn().execute(
        "INSERT INTO cves (cve_id, description, cvss_score) VALUES ('CVE-2024-1234', 'next.js vuln', 9.1)"
    ).connection.commit()
    results = db.get_cves_for_tech('next.js')
    assert len(results) >= 1
    assert results[0]['cve_id'] == 'CVE-2024-1234'

def test_hunt_session_lifecycle(db):
    db._conn().execute(
        "INSERT INTO programs (handle, platform) VALUES ('q', 'hackerone')"
    ).connection.commit()
    pid = db._conn().execute("SELECT id FROM programs WHERE handle='q'").fetchone()[0]
    tid = db.upsert_target(pid, 'q.com', {})
    sid = db.start_hunt_session(tid)
    assert sid > 0
    db.complete_hunt_session(sid, hypotheses_tested=5, findings_count=1)
    conn = db._conn()
    row = conn.execute("SELECT * FROM hunt_sessions WHERE id=?", (sid,)).fetchone()
    assert row['hypotheses_tested'] == 5
    assert row['findings_count'] == 1
    assert row['completed_at'] is not None
