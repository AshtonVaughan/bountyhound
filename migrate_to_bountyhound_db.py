#!/usr/bin/env python3
# migrate_to_bountyhound_db.py
"""
One-time migration from CODEXDATABASE.db + h1-programs.db into bountyhound.db.

Usage:
    python migrate_to_bountyhound_db.py           # full migration
    python migrate_to_bountyhound_db.py --dry-run # migrate but skip deletion
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
            print(f"  Backed up {src.name} -> {bak.name}")


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
        print("  h1-programs.db not found -- skipping")
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
                cur = dst.execute("""
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
                if cur.rowcount:
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
        print("  CODEXDATABASE.db not found -- skipping")
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
            print(f"  Skipping table {tname} -- no CVE column found")
            continue
        rows = src.execute(f"SELECT * FROM {tname}").fetchall()
        for row in rows:
            rd = dict(zip(cols, row))
            try:
                cur = dst.execute("""
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
                if cur.rowcount:
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
        print("  Row count mismatch -- aborting deletion. Check errors above.")
        return False
    print("  Verification passed")
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
    print("\nMigration complete. bountyhound.db is ready.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    main(dry_run=args.dry_run)
