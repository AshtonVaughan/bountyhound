import sqlite3
import pytest
from pathlib import Path

SCHEMA_FILE = Path(__file__).parent.parent / "data" / "schema.sql"
EXPECTED_TABLES = {
    "programs", "cves", "targets", "endpoints",
    "hypotheses", "findings", "hunt_sessions", "evidence"
}

def test_schema_file_exists():
    assert SCHEMA_FILE.exists(), f"schema.sql not found at {SCHEMA_FILE}"

def test_schema_creates_all_tables():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_FILE.read_text())
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    assert EXPECTED_TABLES <= tables, f"Missing tables: {EXPECTED_TABLES - tables}"

def test_evidence_has_finding_id_fk():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_FILE.read_text())
    info = conn.execute("PRAGMA table_info(evidence)").fetchall()
    cols = [r[1] for r in info]
    assert "finding_id" in cols

def test_hypotheses_has_target_id_fk():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_FILE.read_text())
    info = conn.execute("PRAGMA table_info(hypotheses)").fetchall()
    cols = [r[1] for r in info]
    assert "target_id" in cols

def test_targets_unique_program_domain():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_FILE.read_text())
    conn.execute("INSERT INTO programs (handle, platform) VALUES ('test', 'hackerone')")
    pid = conn.execute("SELECT id FROM programs").fetchone()[0]
    conn.execute("INSERT INTO targets (program_id, domain) VALUES (?, 'example.com')", (pid,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO targets (program_id, domain) VALUES (?, 'example.com')", (pid,))

def test_foreign_key_enforcement():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_FILE.read_text())
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO targets (program_id, domain) VALUES (999, 'test.com')")
        conn.commit()
