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
