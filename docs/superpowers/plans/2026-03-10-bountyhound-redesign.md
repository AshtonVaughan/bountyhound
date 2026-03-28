# BountyHound Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the BountyHound hunt pipeline to produce only confirmed, reproducible findings by replacing 138 dead agents + generic pattern-matching with a 6-phase intelligence loop, a novel hypothesis engine, and a hard 4-layer validation gate.

**Architecture:** Four new agents (intelligence-loop, target-researcher, hypothesis-engine, validator) replace the existing phased-hunter/discovery-engine/poc-validator. A unified `bountyhound.db` replaces CODEXDATABASE.db and h1-programs.db. Two new skills (target-research, validation) provide deep methodology for the new agents. The correct execution order is: Chunks 1 and 2 in parallel → Chunk 3 in parallel with both → Chunk 4 last.

**Tech Stack:** Python 3.10+, SQLite3, standard library only (no new deps), markdown (agent/skill files)

---

## Chunk 1: Database Migration (Sub-project 1 — no dependencies)

### Task 1: Create the database schema

**Files:**
- Create: `bountyhound-agent/data/schema.sql`
- Test: `bountyhound-agent/tests/test_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# bountyhound-agent/tests/test_schema.py
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
    assert EXPECTED_TABLES == tables, f"Missing tables: {EXPECTED_TABLES - tables}"

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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd C:/Users/vaugh/Desktop/BountyHound
python -m pytest bountyhound-agent/tests/test_schema.py -v
```
Expected: FAIL — `schema.sql not found`

- [ ] **Step 3: Create the schema**

```sql
-- bountyhound-agent/data/schema.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS programs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    handle          TEXT    NOT NULL UNIQUE,
    name            TEXT,
    platform        TEXT    NOT NULL DEFAULT 'hackerone',
    url             TEXT,
    offers_bounties INTEGER NOT NULL DEFAULT 0,
    min_bounty      REAL,
    max_bounty      REAL,
    scope_json      TEXT,
    out_of_scope_json TEXT,
    policy_url      TEXT,
    last_updated    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                  TEXT    UNIQUE,
    description             TEXT,
    cvss_score              REAL,
    cvss_vector             TEXT,
    affected_products_json  TEXT,
    exploit_available       INTEGER NOT NULL DEFAULT 0,
    exploit_url             TEXT,
    published_date          TEXT,
    last_modified           TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id      INTEGER NOT NULL REFERENCES programs(id),
    domain          TEXT    NOT NULL,
    model_json      TEXT,
    source_available INTEGER NOT NULL DEFAULT 0,
    auth_tested     INTEGER NOT NULL DEFAULT 0,
    last_updated    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, domain)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    url             TEXT    NOT NULL,
    method          TEXT,
    auth_required   INTEGER NOT NULL DEFAULT 0,
    params_json     TEXT,
    discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id                  TEXT    PRIMARY KEY,
    target_id           INTEGER NOT NULL REFERENCES targets(id),
    title               TEXT    NOT NULL,
    attack_surface      TEXT,
    technique           TEXT,
    track               INTEGER NOT NULL DEFAULT 2,
    novelty_score       REAL,
    exploitability_score REAL,
    impact_score        REAL,
    effort_score        REAL,
    total_score         REAL,
    status              TEXT    NOT NULL DEFAULT 'pending',
    outcome             TEXT,
    tested_at           TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id   TEXT    REFERENCES hypotheses(id),
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    title           TEXT    NOT NULL,
    severity        TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    status          TEXT    NOT NULL DEFAULT 'draft',
    report_path     TEXT,
    payout          REAL,
    submitted_at    TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings(id),
    evidence_type   TEXT    NOT NULL,
    file_path       TEXT,
    description     TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hunt_sessions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id           INTEGER NOT NULL REFERENCES targets(id),
    started_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMP,
    hypotheses_tested   INTEGER NOT NULL DEFAULT 0,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_products ON cves(affected_products_json);
CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id, status);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest bountyhound-agent/tests/test_schema.py -v
```
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add bountyhound-agent/data/schema.sql bountyhound-agent/tests/test_schema.py
git commit -m "feat(db): add bountyhound.db schema with all 8 tables and FK relationships"
```

---

### Task 2: Create the database interface

**Files:**
- Create: `bountyhound-agent/data/db.py`
- Test: `bountyhound-agent/tests/test_db.py`

- [ ] **Step 1: Write the failing tests**

```python
# bountyhound-agent/tests/test_db.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest bountyhound-agent/tests/test_db.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'data.db'`

- [ ] **Step 3: Write the database interface**

```python
# bountyhound-agent/data/db.py
"""BountyHound database interface — read/write access to bountyhound.db."""
import sqlite3
import json
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "bountyhound.db"


class BountyHoundDB:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # --- Programs ---

    def get_program(self, handle: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM programs WHERE handle = ?", (handle,)
            ).fetchone()
            return dict(row) if row else None

    def search_programs(self, query: str) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM programs WHERE handle LIKE ? OR name LIKE ? LIMIT 20",
                (f"%{query}%", f"%{query}%")
            ).fetchall()
            return [dict(r) for r in rows]

    # --- CVEs ---

    def get_cves_for_tech(self, product: str) -> list:
        """Find CVEs whose description or affected_products_json mention the product."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM cves
                   WHERE affected_products_json LIKE ?
                   OR description LIKE ?
                   ORDER BY cvss_score DESC LIMIT 50""",
                (f"%{product}%", f"%{product}%")
            ).fetchall()
            return [dict(r) for r in rows]

    def get_cve(self, cve_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            return dict(row) if row else None

    # --- Targets ---

    def get_target(self, program_id: int, domain: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM targets WHERE program_id = ? AND domain = ?",
                (program_id, domain)
            ).fetchone()
            return dict(row) if row else None

    def upsert_target(self, program_id: int, domain: str, model: dict) -> int:
        """Insert or update a target. Returns the target row id."""
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO targets (program_id, domain, model_json, last_updated,
                    source_available, auth_tested)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                ON CONFLICT(program_id, domain) DO UPDATE SET
                    model_json = excluded.model_json,
                    last_updated = CURRENT_TIMESTAMP,
                    source_available = excluded.source_available,
                    auth_tested = excluded.auth_tested
            """, (
                program_id, domain, json.dumps(model),
                1 if model.get('source_available') else 0,
                1 if model.get('auth_tested') else 0,
            ))
            conn.commit()
            row = conn.execute(
                "SELECT id FROM targets WHERE program_id = ? AND domain = ?",
                (program_id, domain)
            ).fetchone()
            return row[0]

    # --- Hypotheses ---

    def get_hypothesis(self, hypothesis_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,)
            ).fetchone()
            return dict(row) if row else None

    def upsert_hypothesis(self, h: dict) -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO hypotheses
                    (id, target_id, title, attack_surface, technique, track,
                     novelty_score, exploitability_score, impact_score, effort_score,
                     total_score, status, outcome, tested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                h['id'], h['target_id'], h['title'], h.get('attack_surface'),
                h.get('technique'), h.get('track', 2),
                h.get('novelty_score'), h.get('exploitability_score'),
                h.get('impact_score'), h.get('effort_score'),
                h.get('total_score'), h.get('status', 'pending'),
                h.get('outcome'), h.get('tested_at'),
            ))
            conn.commit()

    # --- Findings ---

    def insert_finding(self, f: dict) -> int:
        with self._conn() as conn:
            cursor = conn.execute("""
                INSERT INTO findings
                    (hypothesis_id, target_id, title, severity, cvss_score,
                     cvss_vector, status, report_path)
                VALUES (?, ?, ?, ?, ?, ?, 'draft', ?)
            """, (
                f.get('hypothesis_id'), f['target_id'], f['title'],
                f.get('severity'), f.get('cvss_score'), f.get('cvss_vector'),
                f.get('report_path'),
            ))
            conn.commit()
            return cursor.lastrowid

    def insert_evidence(self, finding_id: int, evidence_type: str,
                        file_path: str, description: str = '') -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO evidence (finding_id, evidence_type, file_path, description)
                VALUES (?, ?, ?, ?)
            """, (finding_id, evidence_type, file_path, description))
            conn.commit()

    # --- Hunt Sessions ---

    def start_hunt_session(self, target_id: int) -> int:
        with self._conn() as conn:
            cursor = conn.execute(
                "INSERT INTO hunt_sessions (target_id) VALUES (?)", (target_id,)
            )
            conn.commit()
            return cursor.lastrowid

    def complete_hunt_session(self, session_id: int,
                               hypotheses_tested: int, findings_count: int) -> None:
        with self._conn() as conn:
            conn.execute("""
                UPDATE hunt_sessions SET
                    completed_at = CURRENT_TIMESTAMP,
                    hypotheses_tested = ?,
                    findings_count = ?
                WHERE id = ?
            """, (hypotheses_tested, findings_count, session_id))
            conn.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest bountyhound-agent/tests/test_db.py -v
```
Expected: 7 PASS

- [ ] **Step 5: Commit**

```bash
git add bountyhound-agent/data/db.py bountyhound-agent/tests/test_db.py
git commit -m "feat(db): add BountyHoundDB interface with full CRUD for all tables"
```

---

### Task 3: Write the migration script

**Files:**
- Create: `migrate_to_bountyhound_db.py`
- Test: `bountyhound-agent/tests/test_migration.py`

- [ ] **Step 1: Write failing tests**

```python
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
    # Patch paths in the module
    spec = importlib.util.spec_from_file_location(
        "migrate",
        Path(__file__).parent.parent.parent / "migrate_to_bountyhound_db.py"
    )
    mod = importlib.util.module_from_spec(spec)
    bh_db = tmp_path / "bountyhound.db"
    mod.CODEX_DB = codex_db
    mod.H1_DB = h1_db
    mod.BH_DB = bh_db
    mod.SCHEMA_FILE = SCHEMA_FILE
    spec.loader.exec_module(mod)
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
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest bountyhound-agent/tests/test_migration.py -v
```
Expected: FAIL — migration script not found

- [ ] **Step 3: Write the migration script**

```python
#!/usr/bin/env python3
# migrate_to_bountyhound_db.py
"""
One-time migration from CODEXDATABASE.db + h1-programs.db into bountyhound.db.

Usage:
    python3 migrate_to_bountyhound_db.py           # full migration
    python3 migrate_to_bountyhound_db.py --dry-run # migrate but skip deletion
"""
import sqlite3
import shutil
import sys
import argparse
from pathlib import Path
from datetime import datetime

AGENT_DATA_DIR = Path(__file__).parent / "bountyhound-agent" / "data"
CODEX_DB   = AGENT_DATA_DIR / "CODEXDATABASE.db"
H1_DB      = AGENT_DATA_DIR / "h1-programs.db"
BH_DB      = AGENT_DATA_DIR / "bountyhound.db"
SCHEMA_FILE = AGENT_DATA_DIR / "schema.sql"


def backup_source_dbs() -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    for src in [CODEX_DB, H1_DB]:
        if src.exists():
            bak = src.parent / f"{src.stem}.{ts}.bak"
            shutil.copy2(src, bak)
            print(f"  Backed up {src.name} → {bak.name}")


def create_bountyhound_db() -> None:
    if BH_DB.exists():
        BH_DB.unlink()
    conn = sqlite3.connect(BH_DB)
    conn.executescript(SCHEMA_FILE.read_text())
    conn.commit()
    conn.close()
    print(f"  Created {BH_DB.name}")


def migrate_programs() -> int:
    if not H1_DB.exists():
        print("  h1-programs.db not found — skipping")
        return 0
    src = sqlite3.connect(H1_DB)
    src.row_factory = sqlite3.Row
    dst = sqlite3.connect(BH_DB)
    tables = [r[0] for r in src.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    print(f"  h1-programs.db tables: {tables}")
    inserted = 0
    for tname in tables:
        cols = [r[1] for r in src.execute(f"PRAGMA table_info({tname})").fetchall()]
        rows = src.execute(f"SELECT * FROM {tname}").fetchall()
        for row in rows:
            rd = dict(zip(cols, row))
            handle = rd.get('handle') or rd.get('name', f'unknown_{inserted}')
            try:
                dst.execute("""
                    INSERT OR IGNORE INTO programs
                        (handle, name, platform, url, offers_bounties,
                         min_bounty, max_bounty, policy_url)
                    VALUES (?, ?, 'hackerone', ?, ?, ?, ?, ?)
                """, (
                    handle, rd.get('name', ''), rd.get('url', ''),
                    1 if rd.get('offers_bounties') else 0,
                    rd.get('min_bounty'), rd.get('max_bounty'),
                    rd.get('policy_url', ''),
                ))
                inserted += 1
            except Exception as e:
                print(f"  Skipped row in {tname}: {e}")
    dst.commit()
    src.close()
    dst.close()
    print(f"  Migrated {inserted} programs")
    return inserted


def migrate_cves() -> int:
    if not CODEX_DB.exists():
        print("  CODEXDATABASE.db not found — skipping")
        return 0
    src = sqlite3.connect(CODEX_DB)
    src.row_factory = sqlite3.Row
    dst = sqlite3.connect(BH_DB)
    tables = [r[0] for r in src.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    print(f"  CODEXDATABASE.db tables: {tables}")
    inserted = 0
    for tname in tables:
        cols = [r[1] for r in src.execute(f"PRAGMA table_info({tname})").fetchall()]
        cve_col = next((c for c in cols if 'cve' in c.lower()), None)
        if not cve_col:
            print(f"  Skipping table {tname} — no CVE column found")
            continue
        rows = src.execute(f"SELECT * FROM {tname}").fetchall()
        for row in rows:
            rd = dict(zip(cols, row))
            try:
                dst.execute("""
                    INSERT OR IGNORE INTO cves
                        (cve_id, description, cvss_score, cvss_vector,
                         affected_products_json, published_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    rd.get(cve_col),
                    rd.get('description', ''),
                    rd.get('cvss_score') or rd.get('cvss') or rd.get('score'),
                    rd.get('cvss_vector'),
                    rd.get('affected_products') or rd.get('products'),
                    rd.get('published_date') or rd.get('date'),
                ))
                inserted += 1
            except Exception as e:
                print(f"  Skipped row in {tname}: {e}")
    dst.commit()
    src.close()
    dst.close()
    print(f"  Migrated {inserted} CVE records")
    return inserted


def verify(programs_count: int, cves_count: int) -> bool:
    conn = sqlite3.connect(BH_DB)
    bh_programs = conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0]
    bh_cves     = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    conn.close()
    print(f"\n  Verification:")
    print(f"    programs: source={programs_count}, bountyhound={bh_programs}")
    print(f"    cves:     source={cves_count},     bountyhound={bh_cves}")
    if bh_programs < programs_count or bh_cves < cves_count:
        print("  ❌ Row count mismatch — aborting deletion. Check errors above.")
        return False
    print("  ✅ Verification passed")
    return True


def delete_source_dbs() -> None:
    for db in [CODEX_DB, H1_DB]:
        if db.exists():
            db.unlink()
            print(f"  Deleted {db.name}")


def main(dry_run: bool = False) -> None:
    print("Step 1: Backing up source databases...")
    backup_source_dbs()
    print("Step 2: Creating bountyhound.db schema...")
    create_bountyhound_db()
    print("Step 3: Migrating data...")
    programs_count = migrate_programs()
    cves_count = migrate_cves()
    print("Step 4: Verifying row counts...")
    ok = verify(programs_count, cves_count)
    if not ok:
        sys.exit(1)
    if dry_run:
        print("\n--dry-run: source databases NOT deleted")
    else:
        print("Step 5: Deleting source databases...")
        delete_source_dbs()
    print("\n✅ Migration complete. bountyhound.db is ready.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    main(dry_run=args.dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest bountyhound-agent/tests/test_migration.py -v
```
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add migrate_to_bountyhound_db.py bountyhound-agent/tests/test_migration.py
git commit -m "feat(db): add migration script with backup, verify, and dry-run support"
```

---

### Task 4: Run the real migration

- [ ] **Step 1: Run dry-run first**

```bash
cd C:/Users/vaugh/Desktop/BountyHound
python migrate_to_bountyhound_db.py --dry-run
```
Expected: Migration output with row counts. Both source DBs still present after.

- [ ] **Step 2: Inspect row counts in output — confirm they look right**

Check the printed counts:
- programs count should match what h1-programs.db had
- cves count should match what CODEXDATABASE.db had

If something looks wrong, investigate before proceeding. Do NOT run without `--dry-run` until counts are correct.

- [ ] **Step 3: Run the real migration**

```bash
python migrate_to_bountyhound_db.py
```
Expected: `✅ Migration complete. bountyhound.db is ready.`
Both source DBs deleted. `.bak` files remain.

- [ ] **Step 4: Verify bountyhound.db**

```bash
python -c "
import sqlite3
conn = sqlite3.connect('bountyhound-agent/data/bountyhound.db')
for table in ['programs', 'cves', 'targets', 'hypotheses', 'findings', 'evidence', 'hunt_sessions', 'endpoints']:
    count = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
    print(f'{table}: {count} rows')
"
```
Expected: programs and cves have data; others have 0 rows (not yet populated).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(db): run migration — bountyhound.db live, source DBs removed"
```

---

### Task 5: Update scrape_hackerone_bbp.py to write to bountyhound.db

**Files:**
- Modify: `scrape_hackerone_bbp.py`

- [ ] **Step 1: Find the save/write method in scrape_hackerone_bbp.py**

```bash
grep -n "def save\|def write\|json.dump\|open(" scrape_hackerone_bbp.py | head -20
```
Note the line numbers where programs are persisted.

- [ ] **Step 2: Add bountyhound.db sync at the end of the save method**

Find the method that saves program data (likely `save_program` or similar). After the existing JSON/file save, add:

```python
def _sync_to_db(self, program_data: dict) -> None:
    """Mirror scraped program to bountyhound.db programs table."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent / "bountyhound-agent"))
    from data.db import BountyHoundDB
    db = BountyHoundDB()
    handle = program_data.get('handle', '')
    if not handle:
        return
    conn = db._conn()
    conn.execute("""
        INSERT OR REPLACE INTO programs
            (handle, name, platform, url, offers_bounties, min_bounty, max_bounty, policy_url)
        VALUES (?, ?, 'hackerone', ?, ?, ?, ?, ?)
    """, (
        handle,
        program_data.get('name', ''),
        program_data.get('url', ''),
        1 if program_data.get('offers_bounties') else 0,
        program_data.get('minimum_bounty_table', {}).get('value'),
        program_data.get('maximum_bounty_table', {}).get('value'),
        f"https://hackerone.com/{handle}",
    ))
    conn.commit()
```

Call `self._sync_to_db(program_data)` immediately after the existing file write in the save method.

- [ ] **Step 3: Verify it works by running the scraper in dry-run/test mode**

```bash
python scrape_hackerone_bbp.py --help
```
If there's no test mode, run on a single known program and verify it appears in bountyhound.db:

```bash
python -c "
from data.db import BountyHoundDB
import sys
sys.path.insert(0, 'bountyhound-agent')
from data.db import BountyHoundDB
db = BountyHoundDB()
results = db.search_programs('hackerone')
print(f'Programs in db: {len(results)}')
"
```

- [ ] **Step 4: Commit**

```bash
git add scrape_hackerone_bbp.py
git commit -m "feat(db): scrape_hackerone_bbp now mirrors programs to bountyhound.db"
```

---

## Chunk 2: New Skills (Sub-project 3 — no dependencies, parallel with Chunk 1)

### Task 6: Write the target-research skill

**Files:**
- Create: `bountyhound-agent/skills/target-research/SKILL.md`
- Create: `bountyhound-agent/skills/target-research/references/tech-fingerprinting.md`
- Create: `bountyhound-agent/skills/target-research/references/js-analysis.md`

- [ ] **Step 1: Create the skill directory**

```bash
mkdir -p "bountyhound-agent/skills/target-research/references"
```

- [ ] **Step 2: Write SKILL.md**

```markdown
---
name: target-research
description: |
  Methodology for building a comprehensive target model for a bug bounty target.
  Use this skill whenever performing target reconnaissance, building a target profile,
  or starting a new hunt session on an unfamiliar target. Load this before running
  any recon — it defines what to look for and how to structure what you find.
model: inherit
tools: all
---

# Target Research Skill

Build a target model that makes attack hypotheses specific, grounded, and novel.
The model is the foundation of the entire hunt — a shallow model produces generic
attacks; a deep model produces findings nobody else has found.

## What You Are Building

`findings/<program>/target-model.json` — a structured JSON file with these fields:

```json
{
  "domain": "example.com",
  "program_handle": "example-program",
  "tech_stack": {
    "framework": "Next.js",
    "version": "14.1.0",
    "language": "JavaScript",
    "cdn": "Cloudflare",
    "cloud": "Vercel",
    "auth_system": "NextAuth.js",
    "database": "PostgreSQL (inferred from error messages)"
  },
  "endpoints": [
    {"url": "/api/user/{id}", "method": "GET", "auth_required": true},
    {"url": "/api/upload", "method": "POST", "auth_required": true}
  ],
  "auth_model": {
    "session_type": "JWT",
    "token_format": "HS256",
    "oauth_flows": ["authorization_code"],
    "mfa_present": false,
    "password_reset_mechanism": "email link"
  },
  "business_logic": "SaaS. Roles: free/pro/admin. Sensitive: payment, data export, team management.",
  "attack_surface": ["Auth flow", "File upload", "API endpoints", "Webhook receivers"],
  "cves_relevant": [],
  "prior_disclosures": [],
  "hypotheses_queue": [],
  "tested_hypotheses": [],
  "confirmed_findings": [],
  "source_available": false,
  "auth_tested": false,
  "last_updated": "2026-03-10T00:00:00Z"
}
```

## Step-by-Step Research Process

See `references/tech-fingerprinting.md` for the full fingerprinting guide.
See `references/js-analysis.md` for deep JS bundle analysis techniques.

### Step 1 — Subdomain Enumeration
Run: `amass_enum(domain=target, timeout=300)`
Save results. If no subdomains found: note it, continue with primary domain only.

### Step 2 — Port Scan
Run: `nmap_scan(target=domain, flags="-sV -p 80,443,8080,8443,3000,8000,9000")`
Record any non-standard ports — they often host admin interfaces or internal APIs.

### Step 3 — Tech Stack Fingerprint
Open browser to target. Read `references/tech-fingerprinting.md` → HTTP Headers table.
Check: Server header, X-Powered-By, cookies, error pages, JS bundle names.
Record: framework + version (if detectable), CDN, cloud host, auth mechanism.

### Step 4 — JS Bundle Analysis
Read `references/js-analysis.md` for extraction commands.
Extract: API endpoint patterns, auth flow indicators, feature flags, potential secrets.
Document any internal URLs, unusual endpoints, or hardcoded configuration found.

### Step 5 — Source Code Check
Search GitHub for `github.com/<org>` or `site:github.com <target_name> security`.
If found: read `package.json` / `requirements.txt` / `Gemfile.lock` for exact versions.
Read auth-related files: middleware, route guards, session handlers.
Set `source_available: true` if found, `false` if not.

### Step 6 — CVE Pull
Query bountyhound.db for each identified framework/library:
```python
from data.db import BountyHoundDB
db = BountyHoundDB()
cves = db.get_cves_for_tech('next.js')
# Add top 10 by CVSS to model cves_relevant
```

### Step 7 — Prior Disclosures
Check hackerone.com/<handle>/hacktivity (filter: disclosed).
Note which vulnerability classes have been found — these may have unpatched siblings.
Note which areas have never had a report — these are the most valuable to explore.

### Step 8 — Authenticated Browse (if credentials available)
Use auth-manager to get credentials. Spend 5 minutes in the application:
- Map key user flows (signup → feature → export)
- Identify user roles and what each can access
- Note sensitive actions (payment, admin, data export)
- Look for unusual UI patterns that suggest complex backend logic
Set `auth_tested: true` when done.

## Minimum Viable Model Rule

If recon hits blockers (CDN blocks amass, no GitHub, no credentials):
- Record what you have
- Mark affected fields as `unknown` or `false`
- Proceed anyway — the hypothesis engine adapts to incomplete models
- Never let incomplete recon block the hunt
```

- [ ] **Step 3: Write references/tech-fingerprinting.md**

```markdown
# Tech Stack Fingerprinting Reference

## HTTP Response Headers (fastest signal)

| Header | What it reveals |
|--------|----------------|
| `Server: nginx/1.18.0` | Web server + version |
| `Server: Apache/2.4.41` | Apache version |
| `X-Powered-By: Express` | Node.js + Express |
| `X-Powered-By: PHP/8.1.0` | PHP version |
| `X-Generator: Drupal 9` | CMS |
| `CF-Ray: ...` | Cloudflare CDN |
| `x-amz-cf-id: ...` | AWS CloudFront |
| `x-vercel-id: ...` | Vercel hosting |
| `x-github-request-id: ...` | GitHub Pages |

## Cookie Names (auth system signal)

| Cookie name | Framework |
|------------|-----------|
| `PHPSESSID` | PHP |
| `csrftoken` + `sessionid` | Django |
| `_session_id` | Rails |
| `JSESSIONID` | Java / Spring |
| `connect.sid` | Node.js / Express-session |
| `next-auth.session-token` | Next.js / NextAuth |
| `__Host-next-auth.csrf-token` | NextAuth CSRF |

## JS Bundle Name Patterns

| Pattern | Framework |
|---------|-----------|
| `_next/static/` | Next.js |
| `__nuxt/` | Nuxt.js |
| `ng-` prefix in bundle | Angular |
| `runtime.js` + `main.js` + `vendor.js` | Create React App |
| `app.js` + `chunk-vendors.js` | Vue CLI |
| `application.js` (single bundle) | Rails / Sprockets |

## Error Page Fingerprinting

Visit a guaranteed 404 path (`/definitely-does-not-exist-12345`):
- Yellow/white stacktrace with file paths → Rails or Django debug mode
- `Whitelabel Error Page` → Spring Boot
- `Cannot GET /path` → Express.js
- Default nginx 404 → no framework info, likely SSR disabled
- Custom error page → check HTML source for framework hints

## Version Detection Tips

Version numbers appear in unexpected places:
1. Bundle filenames: `/static/js/main.14.1.0.chunk.js`
2. `X-App-Version` response header
3. `/api/version` or `/api/health` endpoints (try both)
4. HTML comments: `<!-- Generated by Next.js 14.1.0 -->`
5. `robots.txt` generator comment
6. Meta tags: `<meta name="generator" content="...">`
7. GraphQL introspection `__schema` → often includes server version
8. `package.json` if accessible at root (common misconfiguration)
```

- [ ] **Step 4: Write references/js-analysis.md**

```markdown
# JavaScript Bundle Analysis Reference

## Download and Format a Bundle

```bash
# Download
curl -s "https://target.com/static/js/main.abc123.js" -o main.js

# Make readable (if prettier is available)
npx prettier --parser babel main.js > main_formatted.js

# Or use python to do basic formatting
python3 -c "
import re, sys
src = open('main.js').read()
# Basic deobfuscation: split on semicolons and newlines
print(re.sub(r';', ';\n', src))
" > main_formatted.js
```

## Extract API Endpoints

```bash
# REST endpoints
grep -oE '"/api/[^"]*"' main_formatted.js | sort -u

# GraphQL
grep -iE '(graphql|__schema|__type)' main_formatted.js | head -20

# WebSocket
grep -iE '(ws://|wss://|WebSocket)' main_formatted.js | head -10

# All paths starting with /
grep -oE '"(/[a-zA-Z0-9_/-]{3,})"' main_formatted.js | sort -u | grep -v 'node_modules'
```

## Extract Auth Flow Indicators

```bash
grep -iE '(token|jwt|oauth|session|auth|login|logout|refresh|bearer|authorization)' \
  main_formatted.js | head -50
```

Look for:
- `localStorage.setItem('token', ...)` → token stored client-side (look for key name)
- `Authorization: Bearer ${token}` → JWT usage
- `/oauth/authorize` or `/auth/callback` → OAuth flow
- `grant_type=password` → password grant (legacy, often poorly secured)
- `refresh_token` → token refresh logic

## Extract Feature Flags

```bash
grep -iE '(feature_flag|featureFlag|features\.|FEATURE_|ff\.)' main_formatted.js | head -30
```

Feature flags often reveal unreleased endpoints or admin-only functionality.

## Find Internal URLs and Hostnames

```bash
# Internal domains
grep -oE '"https?://[^"]*\.(internal|corp|local|dev|staging|qa)[^"]*"' main_formatted.js

# Non-production API endpoints
grep -oE '"https?://[^"]*api[^"]*"' main_formatted.js | sort -u

# AWS/GCP/Azure endpoints
grep -oE '"https?://[^"]*\.(amazonaws\.com|googleapis\.com|azure\.com)[^"]*"' main_formatted.js
```

## Find Potential Secrets (high false positive rate — verify manually)

```bash
grep -iE '(api_key|apiKey|secret|password|token|key)\s*[:=]\s*"[^"]{8,}"' \
  main_formatted.js | grep -v 'example\|placeholder\|YOUR_\|REPLACE'
```

Any hit here: verify it's real by testing the credential before reporting.

## Source Map Exploitation

If `//# sourceMappingURL=main.js.map` is present at the end of the bundle:

```bash
curl -s "https://target.com/static/js/main.js.map" | python3 -c "
import json, sys
data = json.load(sys.stdin)
# List all source file paths
for src in data.get('sources', []):
    print(src)
"
```

Source maps expose the original file structure and often contain comments, logic, and
variable names that make vulnerability research dramatically easier.
```

- [ ] **Step 5: Verify skill loads**

```bash
# Verify SKILL.md has valid YAML frontmatter
python3 -c "
import re
content = open('bountyhound-agent/skills/target-research/SKILL.md').read()
assert content.startswith('---'), 'Missing YAML frontmatter'
assert 'name: target-research' in content
assert 'description:' in content
print('SKILL.md valid')
# Verify reference files exist
from pathlib import Path
refs = ['references/tech-fingerprinting.md', 'references/js-analysis.md']
for ref in refs:
    p = Path('bountyhound-agent/skills/target-research') / ref
    assert p.exists(), f'Missing: {ref}'
    print(f'OK: {ref}')
"
```
Expected: 3 OK lines, no errors.

- [ ] **Step 6: Commit**

```bash
git add bountyhound-agent/skills/target-research/
git commit -m "feat(skills): add target-research skill with tech fingerprinting and JS analysis references"
```

---

### Task 7: Write the validation skill

**Files:**
- Create: `bountyhound-agent/skills/validation/SKILL.md`
- Create: `bountyhound-agent/skills/validation/references/layer-pass-conditions.md`
- Create: `bountyhound-agent/skills/validation/references/challenge-protocol.md`

- [ ] **Step 1: Create the skill directory**

```bash
mkdir -p "bountyhound-agent/skills/validation/references"
```

- [ ] **Step 2: Write SKILL.md**

```markdown
---
name: validation
description: |
  4-layer validation protocol for confirming bug bounty findings before surfacing them.
  Use this skill when validating any potential finding. Ensures zero false positives
  reach the hunter. The hard rule: a finding that fails any layer is silently discarded.
  Load this skill whenever the validator agent runs.
model: inherit
tools: all
---

# Validation Skill

Every finding must pass 4 layers before being surfaced. You only report confirmed,
reproducible findings. A false positive (especially one the user has to challenge)
is worse than missing a real bug — it destroys trust in every future finding.

## The Hard Rule

If you are not certain a finding is real and non-intentional, **discard it.**
Certainty means: you can demonstrate it in browser, reproduce it with curl, and
articulate what an attacker can actually do with it.

## Layer 0 — By-Design Check

Run before any testing. Sources to check, in order:

1. Program policy page — is this vulnerability class explicitly excluded?
2. Public documentation — does any doc describe this behaviour as intentional?
3. GitHub issues — search for the behaviour. Closed as "by design"? Discard.
4. GitHub PRs / commits — was this intentionally implemented with an explanation?
5. Changelog / release notes — was this behaviour deliberately added?
6. Prior H1 disclosed reports for this program — same issue closed as informative? Discard.
7. Source code comments — does the code say `// intentional` or `// by spec`?
8. RFC or protocol spec — is this required behaviour per the standard?

See `references/layer-pass-conditions.md` for exact PASS/FAIL wording templates.

**PASS:** State specifically what you checked and what you did NOT find.
"I checked [all 8 sources]. [Source A] and [Source B] do not mention this behaviour.
There is no evidence this is intentional."

**FAIL:** State what you found.
"Discarded: by design. [Source] states [quote/description]."

## Layer 1 — Browser Reproduction

Execute the exploit in Chrome. Record a GIF. Proxy captures raw HTTP.

See `references/layer-pass-conditions.md` → Layer 1 table for PASS conditions
per vulnerability class. The key insight: "visible" does not always mean rendered
in the browser UI — proxy capture and DevTools count as observation.

**FAIL:** No observable impact anywhere → discard immediately. Do not proceed to Layer 2.

## Layer 2 — Curl Chain

Extract the minimal reproducible request sequence from proxy capture.

Headers to KEEP: `Authorization`, `Cookie`, `Content-Type`, `Origin`, `Referer`,
any `X-*` custom headers that affect routing or auth, `Host`.

Headers to STRIP: `Accept-Encoding`, `Accept-Language`, `Cache-Control`,
`Upgrade-Insecure-Requests`, `User-Agent` (unless UA-specific bug).

Re-run the stripped curl chain. Confirm the response matches Layer 1 observation.

**FAIL:** curl does not reproduce the same response → browser state dependency,
not a real reproducible finding. Discard.

## Layer 3 — Impact Analysis

Answer all four questions with specific, concrete answers:
1. What data or functionality is exposed or modified? (name specific data types)
2. How many users could be affected? (estimate: one, some, all)
3. Is it exploitable without special access? (unauthenticated, or low-privilege user)
4. What is the measurable business impact? (data breach, financial loss, service disruption)
5. Calculate CVSS 3.1 score.

See `references/layer-pass-conditions.md` → CVSS quick reference.

**FAIL:** No measurable impact, or requires admin access to exploit with no escalation path → discard.

## Challenge Protocol

See `references/challenge-protocol.md` for the complete protocol.

**Summary:** One challenge from the user = immediate fresh re-evaluation of Layer 0.
You do not defend the finding. You do not reference your previous check.
You report the result honestly. If any doubt: discard.
```

- [ ] **Step 3: Write references/layer-pass-conditions.md**

```markdown
# Layer Pass Conditions Reference

## Layer 0 — Pass/Fail Wording

**PASS template:**
"Layer 0 passed. I checked: program policy, public docs, GitHub issues/PRs,
changelog, H1 disclosures, source comments, and relevant RFCs. None of these
sources describe [the observed behaviour] as intentional. Proceeding to Layer 1."

**FAIL template:**
"Discarded at Layer 0: by design.
Evidence: [Source] — [direct quote or description of what it says].
This finding will not be surfaced."

## Layer 1 — Pass Conditions by Vulnerability Class

| Vulnerability Class | PASS condition |
|--------------------|---------------|
| XSS (reflected/stored) | Alert or DOM manipulation visible in browser UI |
| CSRF | State-changing action completed from attacker origin, confirmed in proxy |
| IDOR / BOLA | Another user's data returned in response body, visible in browser or proxy |
| Auth bypass | Restricted resource returns 200 with content without valid session |
| SQL injection | DB error message in response, or data not belonging to current user returned |
| SSRF | Outbound request to attacker-controlled URL captured in proxy or OAST tool |
| Open redirect | Browser navigates to external attacker domain, confirmed in URL bar or proxy |
| Information disclosure | Sensitive data (secrets, PII, internal paths) in response headers, body, or DevTools Network tab |
| Missing security header | Expected header absent in proxy capture of the relevant response |
| Clickjacking | Target page rendered in iframe on attacker-controlled page |
| Business logic | Unintended application state achieved and visible in UI or API response |
| Command injection | Command output in response, or timing difference >2s for sleep-based detection |
| Path traversal | File content from outside webroot in response body |
| XXE | File content or SSRF callback in response or OOB channel |
| SSTI | Template evaluation result (e.g., `49` for `{{7*7}}`) in response body |

## Layer 2 — Curl Chain Format

```bash
# Minimal working curl chain format:
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<session>" \
  -d '{"param": "payload"}' | python3 -m json.tool
```

The chain must be pasteable and runnable with only token/session substitution.
If the chain requires multiple sequential requests, number them and show full flow.

## CVSS 3.1 Quick Reference

| Severity | Score Range | Common Example |
|----------|------------|----------------|
| Critical | 9.0–10.0 | Unauth RCE, ATO of all users, mass data breach |
| High | 7.0–8.9 | Auth bypass, mass IDOR, stored XSS on admin panel |
| Medium | 4.0–6.9 | Reflected XSS (user interaction needed), limited IDOR |
| Low | 0.1–3.9 | Info disclosure of non-sensitive data, missing header |

**Most common High finding vector:**
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5 (Medium)
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 (High — unauthenticated)
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1 (Critical — unauth + write)
```

- [ ] **Step 4: Write references/challenge-protocol.md**

```markdown
# Challenge Protocol

## When It Triggers

The challenge protocol activates on ANY of these user phrases:
- "Is this by design?"
- "Is this intended?"
- "Are you sure?"
- "I think this might be intentional"
- "Isn't this just how [feature] works?"
- Any expression of doubt about a finding's validity

## What You Do

**Step 1: Acknowledge immediately.**
Say: "Let me re-check this with fresh eyes."

Do NOT say:
- "As I mentioned..."
- "I already checked..."
- "I'm confident because..."
- "The evidence still shows..."

**Step 2: Re-run Layer 0 completely from scratch.**
Treat it as if you have never checked before. Check all 8 sources again.

**Step 3: Report honestly.**

If re-check still supports the finding:
"After fresh re-evaluation: I checked [sources] and found [specific evidence].
The finding stands because [concrete reason]. Here's what I found: [details]."

If re-check reveals doubt or evidence of by-design:
"You were right to question this. [Source] shows [evidence].
I'm discarding this finding. It appears to be [by design / unconfirmable / out of scope]."

## What Never Happens

- A second defence of the same finding
- "I already explained this"
- Asking the user to challenge again before you'll reconsider
- Surfacing the same finding again in the same session after discarding it

## The Standard

The user should never need to challenge a finding twice. If the challenge protocol
works correctly, one challenge produces one honest answer with cited evidence.
```

- [ ] **Step 5: Verify skill loads**

```bash
python3 -c "
from pathlib import Path
base = Path('bountyhound-agent/skills/validation')
files = ['SKILL.md', 'references/layer-pass-conditions.md', 'references/challenge-protocol.md']
for f in files:
    p = base / f
    assert p.exists(), f'Missing: {f}'
    content = p.read_text()
    assert len(content) > 100, f'File too short: {f}'
    print(f'OK: {f} ({len(content)} chars)')
"
```
Expected: 3 OK lines.

- [ ] **Step 6: Commit**

```bash
git add bountyhound-agent/skills/validation/
git commit -m "feat(skills): add validation skill with 4-layer protocol and challenge protocol references"
```

---

## Chunk 3: Agent Cleanup (Sub-project 2 — no dependencies, run in parallel with Chunks 1+2)

### Task 8: Audit engine/core and delete unused files

**Files:**
- Delete: `bountyhound-agent/engine/` (contents to be audited first)

- [ ] **Step 1: Check what engine/core files are actually imported**

```bash
# Find all Python files in engine/core
ls bountyhound-agent/engine/core/ | wc -l

# Check which engine files are imported anywhere outside engine/
grep -r "from engine\|import engine" bountyhound-agent/ \
  --include="*.py" --include="*.md" \
  | grep -v "^bountyhound-agent/engine/" \
  | grep -v "test_"
```

If nothing outside engine/ imports from engine/: the entire engine/core directory is dead weight. Delete it.
If some files are imported: note exactly which ones and keep only those.

- [ ] **Step 2: Delete unused engine files**

```bash
# If no external imports found — delete the whole engine directory:
rm -rf bountyhound-agent/engine/

# If some files are imported — delete only unused ones:
# (adjust based on Step 1 findings)
```

- [ ] **Step 3: Verify nothing broke**

```bash
# Run existing tests to confirm no broken imports
python -m pytest bountyhound-agent/tests/ -v 2>&1 | tail -20
```
Expected: All previously passing tests still pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: delete unused engine/core files (65 files, 0 external imports)"
```

---

### Task 9: Delete 138 unused agents

**Files:**
- Delete: 138 agent markdown files from `bountyhound-agent/agents/`
- Keep: `phased-hunter.md`, `discovery-engine.md`, `poc-validator.md`, `reporter-agent.md`, `auth-manager.md`

> Note: phased-hunter, discovery-engine, and poc-validator will be *replaced* in Chunk 4.
> Keep them now so the system doesn't break before Chunk 4 runs.

- [ ] **Step 1: Count current agents and identify keepers**

```bash
ls bountyhound-agent/agents/ | wc -l
```
Expected: ~151 files.

Agents to KEEP (do not delete):
- `phased-hunter.md`
- `discovery-engine.md`
- `poc-validator.md`
- `reporter-agent.md`
- `auth-manager.md`

- [ ] **Step 2: Delete all other agents**

```bash
cd bountyhound-agent/agents/

# Keep the 5 listed files, delete everything else
for f in *.md; do
  case "$f" in
    phased-hunter.md|discovery-engine.md|poc-validator.md|reporter-agent.md|auth-manager.md)
      echo "Keeping: $f"
      ;;
    *)
      echo "Deleting: $f"
      rm "$f"
      ;;
  esac
done
```

- [ ] **Step 3: Verify only 5 agents remain**

```bash
ls bountyhound-agent/agents/ | wc -l
ls bountyhound-agent/agents/
```
Expected: 5 files.

- [ ] **Step 4: Commit**

```bash
cd C:/Users/vaugh/Desktop/BountyHound
git add -A
git commit -m "chore: delete 138 unused agents — keep 5 core agents only"
```

---

### Task 10: Delete stale documentation

**Files:**
- Delete: `AGENT_UPDATE_REPORT.md`, `COMPLETION_REPORT.txt`, `HUNT_FLOW_DIAGRAM.txt`
- Delete: `OPTIMIZED_HUNT_ARCHITECTURE.md`, `OPTIMIZED_HUNT_DESIGN_v2.md`, `OPTIMIZED_FLOW_DIAGRAM.txt`
- Delete: `IMPLEMENTATION_SUMMARY.md`, `METHODOLOGY_GAPS_TODO.md`, `ARCHITECTURE_REVIEW.md`
- Delete: `PROJECT_COMPLETION_SUMMARY.md`, `TOP50_HUNTER_REPORT.md`, `TEST_REPORT.md`
- Keep: `README.md`, `QUICKSTART.md`, `PROXY_ENGINE_SYSTEM.md`

- [ ] **Step 1: Delete stale files**

```bash
cd C:/Users/vaugh/Desktop/BountyHound
rm -f AGENT_UPDATE_REPORT.md COMPLETION_REPORT.txt HUNT_FLOW_DIAGRAM.txt
rm -f OPTIMIZED_HUNT_ARCHITECTURE.md OPTIMIZED_HUNT_DESIGN_v2.md OPTIMIZED_FLOW_DIAGRAM.txt
rm -f IMPLEMENTATION_SUMMARY.md METHODOLOGY_GAPS_TODO.md ARCHITECTURE_REVIEW.md
rm -f PROJECT_COMPLETION_SUMMARY.md TOP50_HUNTER_REPORT.md TEST_REPORT.md
```

- [ ] **Step 2: Verify keepers still exist**

```bash
ls README.md QUICKSTART.md PROXY_ENGINE_SYSTEM.md
```
Expected: All 3 present.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "chore: delete stale design docs — keep README, QUICKSTART, PROXY_ENGINE_SYSTEM"
```

---

## Chunk 4: Core Agents Rebuild (Sub-project 4 — depends on Chunks 1 and 2)

> **Do not start this chunk until Chunk 1 (bountyhound.db exists) and Chunk 2 (both skills written) are complete.**

### Task 11: Write intelligence-loop.md

**Files:**
- Create: `bountyhound-agent/agents/intelligence-loop.md`

- [ ] **Step 1: Create the agent file**

```markdown
---
name: intelligence-loop
description: |
  Main hunt orchestrator for BountyHound. Runs the complete 6-phase intelligence
  loop: research → model → hypotheses → browser test → validate → report.
  Invoke this agent when the user runs /hunt <target>. It orchestrates all other
  hunt agents and ensures only confirmed findings reach the user.
model: inherit
tools: all
---

# Intelligence Loop

You are the main hunt orchestrator. When invoked with a target domain and program
handle, you run the 6-phase intelligence loop and surface only confirmed findings.

**Core philosophy:** Understand before you attack. Every finding you surface has
a GIF recording, a working curl chain, and a clear impact statement. If a finding
cannot pass the 4-layer validator, it does not exist.

---

## Phase ① — Check Target Model Freshness

1. Look for `findings/<program_handle>/target-model.json`
2. If it exists: read `last_updated`. If less than 14 days ago → skip to Phase ③.
3. If missing or stale: invoke `target-researcher` agent with the target domain and
   program handle. Wait for it to complete and write the model file.

---

## Phase ② — Read Target Model

Read `findings/<program_handle>/target-model.json`. Keep it in context — every
subsequent phase reads from it.

Start a hunt session in bountyhound.db:
```python
import sys
sys.path.insert(0, 'bountyhound-agent')
from data.db import BountyHoundDB
db = BountyHoundDB()
program = db.get_program('<program_handle>')
# If program not in db yet, insert it
target_id = db.upsert_target(program['id'], '<domain>', <model_dict>)
session_id = db.start_hunt_session(target_id)
```

---

## Phase ③ — Hypothesis Generation

Invoke the `hypothesis-engine` agent. Provide it:
- The full target model (pass as context)
- The program handle (for prior disclosure lookup)

The hypothesis engine returns a scored queue. Read it from `hypotheses_queue` in
the updated target model file.

---

## Phase ④+⑤ — Browser Testing + Validation Loop

For each hypothesis in `hypotheses_queue` (highest `total_score` first):

1. **Duplicate check:** If `hypothesis.id` already exists in `tested_hypotheses`,
   skip silently.

2. **Load relevant skill:** Based on the hypothesis technique:
   - OAuth/JWT issue → @oauth-auth-deep
   - IDOR / framework-specific → @data-exfil-deep
   - LLM integration → @llm-security-deep
   - Injection → @injection-attacks
   - Auth bypass → @auth-attacks
   - WAF involved → @waf-bypass

3. **Browser test:** Open Chrome to the target. Execute the hypothesis test.
   Use Claude-in-Chrome browser automation tools. Proxy must be running on port 8080.
   Record a GIF of every test attempt (pass or fail) using `gif_creator`.

4. **Invoke validator agent** with:
   - The hypothesis details
   - What you observed in the browser
   - The GIF path
   - The proxy capture (from `proxy_list_flows`)

5. **If validator returns `confirmed: true`:** Proceed to Phase ⑥ for this finding.
   Then continue to the next hypothesis.

6. **If validator returns `confirmed: false`:** Log the discard reason to
   `tested_hypotheses` in the model. Continue to the next hypothesis.

**Stop condition:** After 8 hypotheses tested OR 90 minutes elapsed, whichever first.

---

## Phase ⑥ — Report Confirmed Findings

For each confirmed finding:

1. Invoke `reporter-agent` with the finding details, GIF path, curl chain, and
   impact statement from the validator output.

2. Save the report to `findings/<program_handle>/reports/<finding_title_slug>.md`

3. Record in bountyhound.db:
```python
fid = db.insert_finding({
    'hypothesis_id': finding['hypothesis_id'],
    'target_id': target_id,
    'title': finding['title'],
    'severity': finding['severity'],
    'cvss_score': finding['cvss_score'],
    'cvss_vector': finding['cvss_vector'],
    'report_path': report_path,
})
db.insert_evidence(fid, 'gif', finding['gif_path'], 'exploit recording')
db.insert_evidence(fid, 'curl_chain', finding['curl_chain_path'], 'reproduction steps')
```

---

## End of Hunt

```python
db.complete_hunt_session(session_id,
    hypotheses_tested=<count>,
    findings_count=<confirmed_count>)
```

Tell the user:
- "Hunt complete. X hypotheses tested, Y confirmed findings."
- List each confirmed finding with: title, severity, report path.
- If 0 findings: "No confirmed findings this session. Target model updated —
  next session starts with new hypotheses."

---

## Challenge Protocol

If the user says anything like "is this by design?", "is this intended?",
"are you sure?", or expresses any doubt about a finding:

1. Say: "Let me re-check this with fresh eyes."
2. Do NOT defend the finding or reference previous reasoning.
3. Invoke the `validator` agent specifically for Layer 0 re-check.
4. Report the result honestly with cited evidence.
5. If any doubt exists: discard the finding.

One challenge = one honest answer. No second defence. Ever.
```

- [ ] **Step 2: Verify file has valid frontmatter**

```bash
python3 -c "
content = open('bountyhound-agent/agents/intelligence-loop.md').read()
assert content.startswith('---'), 'Missing frontmatter'
assert 'name: intelligence-loop' in content
assert 'Phase ①' in content
assert 'Challenge Protocol' in content
print('OK: intelligence-loop.md valid')
"
```

- [ ] **Step 3: Commit**

```bash
git add bountyhound-agent/agents/intelligence-loop.md
git commit -m "feat(agents): add intelligence-loop — 6-phase hunt orchestrator"
```

---

### Task 12: Write target-researcher.md

**Files:**
- Create: `bountyhound-agent/agents/target-researcher.md`

- [ ] **Step 1: Create the agent file**

```markdown
---
name: target-researcher
description: |
  Builds the target model for a given domain. Runs all recon steps and writes
  findings/<program>/target-model.json. Invoked by intelligence-loop when a
  fresh or missing target model is needed. Read @target-research skill first.
model: inherit
tools: all
---

# Target Researcher

You build the target model that the hypothesis engine needs to generate grounded,
novel hypotheses. A thorough model produces interesting findings. A shallow model
produces generic scans. Take the time to do this well.

Read @target-research skill before starting — it has the full fingerprinting guide
and JS analysis commands.

## Inputs
- `target_domain`: the primary domain to research (e.g., `example.com`)
- `program_handle`: the bug bounty program handle (e.g., `vercel-open-source`)

## Steps

### 1 — Subdomain Enumeration
```
amass_enum(domain=target_domain, timeout=300)
```
Save results to `recon/<program_handle>/subdomains.txt`.
If no results: note it and continue with primary domain only.

### 2 — Port Scan
```
nmap_scan(target=target_domain, flags="-sV -p 80,443,8080,8443,3000,8000,9000")
```
Note any non-standard ports — these often host admin interfaces or internal APIs.

### 3 — Tech Stack Fingerprint
Open browser to `https://<target_domain>`. Observe:
- Response headers (Server, X-Powered-By, cookies)
- Error pages at `/definitely-does-not-exist-12345`
- JS bundle filenames in page source
- Cookie names on login page

Use the `target_analysis` tool from proxy-engine for automated fingerprinting:
```
target_analysis(host=target_domain)
```

### 4 — JS Bundle Analysis
From the browser Network tab, identify the main JS bundles.
Run the extraction commands from @target-research → references/js-analysis.md.
Extract: API endpoints, auth flow indicators, feature flags, internal URLs.
Record anything unusual or unexpected.

### 5 — Source Code Check
Search for public GitHub repos: `github.com/<org>` or web search `site:github.com <program_name> security`.

If found:
- Read `package.json` / `requirements.txt` / `Gemfile.lock` → record exact dependency versions
- Search for auth middleware: files containing `authenticate`, `authorize`, `middleware`
- Read route configuration files

Set `source_available = true` in model if found.

### 6 — CVE Pull
```python
import sys; sys.path.insert(0, 'bountyhound-agent')
from data.db import BountyHoundDB
db = BountyHoundDB()
framework = '<detected_framework>'
cves = db.get_cves_for_tech(framework)
# Take top 10 by cvss_score
```

### 7 — Prior Disclosures
```python
program = db.get_program('<program_handle>')
```
Also browse: `https://hackerone.com/<program_handle>/hacktivity?filter=disclosed`
Note which vulnerability classes have been reported before.

### 8 — Authenticated Browse (if credentials available)
Check if credentials exist via `auth-manager`. If yes:
- Log in and spend 5 minutes exploring the application
- Map: key user flows, roles, sensitive actions, unusual UI patterns
- Set `auth_tested = true`

If no credentials: set `auth_tested = false`, continue.

## Write Target Model

Create `findings/<program_handle>/` directory if it doesn't exist.
Write `findings/<program_handle>/target-model.json` with all collected data.
Use the schema from @target-research skill SKILL.md.

Sync to bountyhound.db:
```python
program = db.get_program(program_handle) or {'id': None}
if program['id']:
    db.upsert_target(program['id'], target_domain, model_dict)
```

Tell the orchestrator: "Target model complete. Tech stack: [summary].
Source available: [yes/no]. Auth tested: [yes/no].
[N] endpoints discovered. [N] CVEs relevant. Written to findings/<handle>/target-model.json"
```

- [ ] **Step 2: Verify**

```bash
python3 -c "
content = open('bountyhound-agent/agents/target-researcher.md').read()
assert 'name: target-researcher' in content
assert '@target-research' in content
assert 'target-model.json' in content
assert 'auth_tested' in content
print('OK: target-researcher.md valid')
"
```

- [ ] **Step 3: Commit**

```bash
git add bountyhound-agent/agents/target-researcher.md
git commit -m "feat(agents): add target-researcher — builds target-model.json from 8-step recon"
```

---

### Task 13: Write hypothesis-engine.md

**Files:**
- Create: `bountyhound-agent/agents/hypothesis-engine.md`

- [ ] **Step 1: Create the agent file**

```markdown
---
name: hypothesis-engine
description: |
  Generates a prioritised queue of attack hypotheses grounded in the target model.
  Replaces discovery-engine. Runs two tracks: Track 1 (fast CVE baseline) and
  Track 2 (novel hypotheses from implementation reasoning). Every hypothesis must
  reference something specific in the target model — no generic attacks.
model: inherit
tools: all
---

# Hypothesis Engine

You generate a prioritised attack queue from the target model. Generic hypotheses
("check for XSS") are worthless. Every hypothesis must be grounded in something
specific observed in the target model — a specific version, a specific endpoint,
a specific auth pattern, a specific code path.

## Inputs
- Full target model (from `findings/<program_handle>/target-model.json`)
- Program handle (for prior disclosure context)

## Track 1 — Baseline (run first, 10 minutes max)

Quick pass to grab anything obvious. Low expectations — mature programs are already patched.

1. For each entry in `model.cves_relevant`: create a hypothesis with track=1, novelty=1.
2. Run nuclei against the primary domain:
   ```
   nuclei_scan(target=domain, templates=["cves", "vulnerabilities", "exposed-panels"])
   ```
   Add any hits as Track 1 hypotheses.

Track 1 is the floor. Do not spend more than 10 minutes here.

## Track 2 — Novel Hypotheses (the primary work)

For each of the 6 lenses below, generate 1–3 hypotheses IF the target model shows
relevant attack surface. Skip lenses where there is no corresponding attack surface.

### Lens 1: Implementation Reasoning

Read available source code (if `source_available = true`). Ask:
"Where would a developer under deadline pressure skip validation in this specific app?"

Look for these characteristic patterns:
- Authorization check present in web controller but absent in API controller for same resource
- Rate limiting on POST but not GET of the same resource
- Input validation on user-facing form but not on programmatic API endpoint
- Admin-only check by role name but not by permission object
- CORS configured permissively "temporarily" in a commit message

### Lens 2: Business Logic Abuse

Understand what the app does from `model.business_logic`. Ask:
"What can a user get that they shouldn't be able to get for free or without the right role?"

Common patterns:
- Negative quantities or zero-price items in purchase flows
- Requesting a resource as user B while authenticated as user A (IDOR)
- Skipping a required workflow step via direct API call
- Accessing pro/paid features by manipulating plan identifier in request

### Lens 3: Component Interaction

Look at the tech_stack map. Ask: "What happens at the seams between these components?"

Specific seams to examine:
- CDN layer ↔ origin server: does CDN cache responses it shouldn't?
- Load balancer ↔ app: does LB trust X-Forwarded-For or X-Real-IP?
- Auth service ↔ API: does API trust an internal header the user can set externally?
- Cache ↔ database: are session/user data cached without user-scoping?

### Lens 4: Recent Change Analysis

Check GitHub commits and changelog from the last 90 days. Security patches often
leave unpatched siblings.

Ask: "The patch fixed endpoint A. Does endpoint B share the same vulnerable code path?"
Also: "What did this commit add that might not have received the same scrutiny as the patch?"

### Lens 5: Variant Generation

For each entry in `model.cves_relevant` where `cvss_score >= 7.0`:
Read the CVE description. Ask: "What did the patch not fix?"

Common incomplete patches:
- Patch fixes one HTTP method but not another (GET vs POST)
- Patch fixes the documented endpoint but not an undocumented alias
- Patch adds validation but only for the specific input format in the CVE PoC
- Patch is in the web layer but the mobile API shares the same backend

### Lens 6: Adversarial Framing

For the top 3 attack surfaces in `model.attack_surface`:
"If I built this feature in 2 days to hit a deadline, where would I cut corners?"

Then test those spots.

## Skill Router

Load only skills relevant to this target's actual stack:
- OAuth flows or JWT in `auth_model` → load @oauth-auth-deep, use reasoning-framework.md as a lens
- Rails/Django/Spring/Express in `tech_stack` → load @data-exfil-deep, use framework-idor.md
- GraphQL endpoint in `endpoints` → load @injection-attacks (GraphQL chapter)
- LLM integration detected in JS analysis → load @llm-security-deep
- File upload endpoint in `endpoints` → load @injection-attacks (upload chapter)
- Auth complexity (OAuth, SAML, SSO) → load @auth-attacks

## Scoring

Score each hypothesis on 4 dimensions (use 1, 5, or 10 only):

| Dimension | 10 | 5 | 1 |
|-----------|----|----|---|
| Novelty | Not in any prior disclosure or CVE | Known variant of a patched issue | Direct CVE match |
| Exploitability | Attack surface confirmed in target model | Probable based on tech stack | Speculative |
| Impact | Critical/High (ATO, data breach, RCE) | Medium (limited exposure) | Low |
| Effort (inverted) | Testable in under 10 minutes | 10–30 minutes | Over 30 minutes |

`total_score = (novelty + exploitability + impact + effort) / 4`

Sort descending by total_score. Keep the top 10. Discard the rest.

## Duplicate Detection

Before adding a hypothesis to the queue: compute its ID as:
```python
import hashlib
hypothesis_id = hashlib.sha256(
    f"{attack_surface}|{technique}".encode()
).hexdigest()[:16]
```
If this ID already exists in `model.tested_hypotheses` → skip silently.

## Output

Write the scored queue to `model.hypotheses_queue` in target-model.json.
Also insert each hypothesis into bountyhound.db:
```python
import sys; sys.path.insert(0, 'bountyhound-agent')
from data.db import BountyHoundDB
db = BountyHoundDB()
for h in hypothesis_queue:
    db.upsert_hypothesis({**h, 'target_id': target_id})
```

Return to intelligence-loop: "Hypothesis queue ready: [N] hypotheses.
Top 3: [title, score], [title, score], [title, score]."
```

- [ ] **Step 2: Verify**

```bash
python3 -c "
content = open('bountyhound-agent/agents/hypothesis-engine.md').read()
assert 'name: hypothesis-engine' in content
assert 'Track 1' in content and 'Track 2' in content
assert 'total_score' in content
assert 'hashlib' in content
print('OK: hypothesis-engine.md valid')
"
```

- [ ] **Step 3: Commit**

```bash
git add bountyhound-agent/agents/hypothesis-engine.md
git commit -m "feat(agents): add hypothesis-engine — 2-track scoring with 6 novel lenses"
```

---

### Task 14: Write validator.md

**Files:**
- Create: `bountyhound-agent/agents/validator.md`

- [ ] **Step 1: Create the agent file**

```markdown
---
name: validator
description: |
  4-layer validation gate for potential findings. Replaces poc-validator.
  A finding that fails any layer is silently discarded — only confirmed,
  reproducible findings are returned. Read @validation skill first.
  Implements the challenge protocol: one user challenge = immediate discard if doubt.
model: inherit
tools: all
---

# Validator

You apply the 4-layer gate. A finding that fails any layer is discarded. You only
return confirmed findings. Read @validation skill before starting — it has the
full pass/fail conditions by vulnerability class and the challenge protocol detail.

## Hard Rule

If you are not certain, discard. The cost of a false positive is higher than
the cost of a missed finding.

## Inputs
- `hypothesis`: the hypothesis being tested
- `browser_observation`: what was observed during the browser test in Phase ④
- `gif_path`: path to the recorded GIF
- `proxy_flows`: captured traffic from proxy-engine

## Layer 0 — By-Design Check

**Check all 8 sources.** See @validation → references/layer-pass-conditions.md for templates.

Sources to check:
1. Program policy page at `https://hackerone.com/<handle>/policy`
2. Public documentation — search `site:<domain> <observed_behaviour>`
3. GitHub issues — search `<org>/<repo>/issues?q=<behaviour_description>`
4. GitHub PRs / commits — search for behaviour in commit messages
5. Changelog at `<domain>/changelog` or GitHub releases
6. H1 disclosures — `https://hackerone.com/<handle>/hacktivity?filter=disclosed`
7. Source code comments — grep source for `// intentional` or `// by design`
8. RFC or protocol spec — look up the relevant standard

**PASS:** State specifically what you checked and what you did NOT find.
**FAIL:** State what you found. Log and return `{"confirmed": false, "layer_failed": 0, "reason": "..."}`.

## Layer 1 — Browser Reproduction

Use the `browser_observation` and `gif_path` from Phase ④.

Check pass condition for this vulnerability class in @validation → references/layer-pass-conditions.md.

If the observation already happened in Phase ④: confirm it meets the Layer 1 pass
condition. If unclear: re-execute in browser.

**PASS:** Impact observable in browser, DevTools, or proxy capture — per vulnerability class.
**FAIL:** Return `{"confirmed": false, "layer_failed": 1, "reason": "No observable impact in browser/DevTools/proxy"}`.

## Layer 2 — Curl Chain

Extract the minimal reproduction from proxy capture:
```
flows = proxy_list_flows(host=target_domain)
flow = proxy_get_flow(flow_id=<relevant_flow_id>)
```

Build minimal curl command. Strip non-essential headers (see @validation SKILL.md).
Run the curl chain via bash. Confirm response matches Layer 1 observation.

Save to `findings/<program>/evidence/<hypothesis_id>.curl`.

**PASS:** curl reproduces same impact.
**FAIL:** Return `{"confirmed": false, "layer_failed": 2, "reason": "curl chain does not reproduce impact"}`.

## Layer 3 — Impact Analysis

Answer all four questions:
1. What specific data or functionality is exposed or modified?
2. How many users affected? (one / some / all)
3. Exploitable without special access? (unauthenticated or low-privilege)
4. What is the measurable business impact?

Calculate CVSS 3.1. Reference the quick table in @validation → references/layer-pass-conditions.md.

Minimum CVSS for surfacing: 4.0 (Medium). Anything below: discard.

**PASS:** Return the confirmed finding JSON (see below).
**FAIL:** Return `{"confirmed": false, "layer_failed": 3, "reason": "No measurable impact / CVSS < 4.0"}`.

## Confirmed Finding Output

```json
{
  "confirmed": true,
  "hypothesis_id": "<id>",
  "title": "Specific, concrete finding title",
  "severity": "critical|high|medium|low",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "gif_path": "findings/<program>/evidence/<hypothesis_id>.gif",
  "curl_chain_path": "findings/<program>/evidence/<hypothesis_id>.curl",
  "impact_summary": "An unauthenticated attacker can read any user's private profile data by changing the user_id parameter.",
  "users_affected": "All registered users (~N if known)",
  "by_design_evidence": "Confirmed not by design: checked [8 sources], none describe this as intentional."
}
```

## Challenge Protocol

See @validation → references/challenge-protocol.md for complete protocol.

**Summary:**
- User challenge → say "Let me re-check this with fresh eyes"
- Re-run Layer 0 completely, as if for the first time
- Report result with cited evidence
- If any doubt → discard
- No second defence. No "as I mentioned". No defending.
```

- [ ] **Step 2: Verify**

```bash
python3 -c "
content = open('bountyhound-agent/agents/validator.md').read()
assert 'name: validator' in content
assert 'Layer 0' in content
assert 'Layer 1' in content
assert 'Layer 2' in content
assert 'Layer 3' in content
assert 'Challenge Protocol' in content
assert '@validation' in content
print('OK: validator.md valid')
"
```

- [ ] **Step 3: Commit**

```bash
git add bountyhound-agent/agents/validator.md
git commit -m "feat(agents): add validator — 4-layer gate with by-design check and challenge protocol"
```

---

### Task 15: Delete replaced agents and update hunt command

**Files:**
- Delete: `bountyhound-agent/agents/phased-hunter.md`
- Delete: `bountyhound-agent/agents/discovery-engine.md`
- Delete: `bountyhound-agent/agents/poc-validator.md`
- Modify: `bountyhound-agent/commands/hunt.md`

- [ ] **Step 1: Delete the replaced agents**

```bash
rm bountyhound-agent/agents/phased-hunter.md
rm bountyhound-agent/agents/discovery-engine.md
rm bountyhound-agent/agents/poc-validator.md
```

- [ ] **Step 2: Verify only the 6 correct agents remain**

```bash
ls bountyhound-agent/agents/
```
Expected exactly: `intelligence-loop.md`, `target-researcher.md`, `hypothesis-engine.md`,
`validator.md`, `reporter-agent.md`, `auth-manager.md`

- [ ] **Step 3: Update hunt.md to invoke intelligence-loop**

Read current `bountyhound-agent/commands/hunt.md`. Find the line that references
`phased-hunter` and update it to invoke `intelligence-loop` instead.

The key section to update will look something like:
```
# invokes phased-hunter ...
```
Change to reference `intelligence-loop` and reflect the new 6-phase structure.

Add this section at the top of hunt.md if not already present:
```markdown
## Quick Start

/hunt <target_url> [program_handle]

Example: /hunt https://example.com example-program

This invokes the intelligence-loop agent which:
1. Checks/builds the target model (skips if fresh)
2. Generates grounded hypotheses via hypothesis-engine
3. Tests each hypothesis in browser via Chrome automation
4. Validates each finding through the 4-layer gate
5. Reports only confirmed findings with GIF + curl chain + impact

You will only see confirmed, reproducible findings. Everything else is discarded silently.
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(agents): delete replaced agents, update hunt.md for intelligence-loop"
```

---

### Task 16: Run sync.py to deploy everything

- [ ] **Step 1: Run sync**

```bash
cd C:/Users/vaugh/Desktop/BountyHound
python sync.py
```
Expected: Sync output showing agents/, skills/, commands/, CLAUDE.md copied to plugin cache.

- [ ] **Step 2: Run repatch.py to restore auth context**

```bash
python repatch.py
```
Expected: Authorization context re-applied to new agent files.

- [ ] **Step 3: Smoke test — verify all new files are in plugin cache**

```bash
ls "C:/Users/vaugh/.claude/plugins/cache/bountyhound-marketplace/bountyhound-agent/6.1.0/agents/"
```
Expected: 6 agent files including `intelligence-loop.md`, `validator.md`.

```bash
ls "C:/Users/vaugh/.claude/plugins/cache/bountyhound-marketplace/bountyhound-agent/6.1.0/skills/"
```
Expected: skills directory includes `target-research/` and `validation/`.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: BountyHound redesign complete — intelligence loop, 4-layer validator, bountyhound.db"
```

---

## Verification Against Success Criteria

After Chunk 4 is complete, verify each success criterion from the spec:

- [ ] **SC1:** Run `/hunt <known_target>` — confirm no findings surface without GIF + curl chain
- [ ] **SC2:** Check that every confirmed finding has evidence in `findings/<program>/evidence/`
- [ ] **SC3:** Check hypothesis-engine output — confirm at least 1 Track 2 (novel) hypothesis generated
- [ ] **SC4:** Run `/hunt` on a previously-hunted target — confirm Phase ① is skipped (model reused)
- [ ] **SC5:** Surface a finding, then say "is this by design?" — confirm one honest answer with cited source, no second defence
- [ ] **SC6:** `python -c "import sqlite3; c=sqlite3.connect('bountyhound-agent/data/bountyhound.db'); print(c.execute('SELECT COUNT(*) FROM programs').fetchone(), c.execute('SELECT COUNT(*) FROM cves').fetchone())"`
  Expected: both counts > 0
