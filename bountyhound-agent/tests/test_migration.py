# bountyhound-agent/tests/test_migration.py
import sqlite3
import shutil
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

SCHEMA_FILE = Path(__file__).parent.parent / "data" / "schema.sql"

@pytest.fixture
def fake_codex_db(tmp_path):
    """Minimal CODEXDATABASE.db with 3 CVE rows."""
    db = tmp_path / "CODEXDATABASE.db"
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE vulnerabilities (
        cve_id TEXT, description TEXT, cvss_score REAL)""")
    conn.executemany("INSERT INTO vulnerabilities VALUES (?,?,?)", [
        ("CVE-2024-0001", "Test vuln A", 9.1),
        ("CVE-2024-0002", "Test vuln B", 7.5),
        ("CVE-2024-0003", "Test vuln C", 5.0),
    ])
    conn.commit()
    conn.close()
    return db

@pytest.fixture
def fake_h1_db(tmp_path):
    """Minimal h1-programs.db with 2 program rows."""
    db = tmp_path / "h1-programs.db"
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE programs (
        handle TEXT, name TEXT, url TEXT, offers_bounties INTEGER,
        min_bounty REAL, max_bounty REAL, policy_url TEXT)""")
    conn.executemany("INSERT INTO programs VALUES (?,?,?,?,?,?,?)", [
        ("vercel", "Vercel", "https://vercel.com", 1, 250.0, 25000.0, ""),
        ("shopify", "Shopify", "https://shopify.com", 1, 500.0, 50000.0, ""),
    ])
    conn.commit()
    conn.close()
    return db

def run_migration(tmp_path, codex_db, h1_db):
    """Helper: run migration script with fake paths."""
    import importlib.util, types
    spec = importlib.util.spec_from_file_location(
        "migrate",
        Path(__file__).parent.parent.parent / "migrate_to_bountyhound_db.py"
    )
    mod = importlib.util.module_from_spec(spec)
    bh_db = tmp_path / "bountyhound.db"
    spec.loader.exec_module(mod)
    # Patch after exec so module-body assignments don't overwrite our paths
    mod.CODEX_DB = codex_db
    mod.H1_DB = h1_db
    mod.BH_DB = bh_db
    mod.SCHEMA_FILE = SCHEMA_FILE
    mod.main(dry_run=True)
    return bh_db

def test_migration_creates_bountyhound_db(tmp_path, fake_codex_db, fake_h1_db):
    bh = run_migration(tmp_path, fake_codex_db, fake_h1_db)
    assert bh.exists()

def test_migration_programs_count(tmp_path, fake_codex_db, fake_h1_db):
    bh = run_migration(tmp_path, fake_codex_db, fake_h1_db)
    conn = sqlite3.connect(bh)
    count = conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0]
    assert count >= 2

def test_migration_cves_count(tmp_path, fake_codex_db, fake_h1_db):
    bh = run_migration(tmp_path, fake_codex_db, fake_h1_db)
    conn = sqlite3.connect(bh)
    count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    assert count >= 3

def test_migration_dry_run_leaves_source_files(tmp_path, fake_codex_db, fake_h1_db):
    run_migration(tmp_path, fake_codex_db, fake_h1_db)
    assert fake_codex_db.exists(), "dry_run should not delete source files"
    assert fake_h1_db.exists(), "dry_run should not delete source files"

def test_migration_creates_backups(tmp_path, fake_codex_db, fake_h1_db):
    run_migration(tmp_path, fake_codex_db, fake_h1_db)
    bak_files = list(tmp_path.glob("*.bak"))
    assert len(bak_files) >= 2
