"""
Pattern Sharing Module

Enables sharing of learned attack patterns across sessions. Imports and exports
successful patterns, hypotheses, and payloads so that knowledge accumulated in
one hunt can be reused in future sessions.

Export format: JSON files organized by type (patterns, payloads, hypotheses).
Default sync directory: C:/Users/vaugh/BountyHound/database/pattern-sync/
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from engine.core.database import BountyHoundDB
from engine.core.config import BountyHoundConfig


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYNC_BASE_DIR = BountyHoundConfig.PATTERN_SYNC_DIR
EXPORT_VERSION = "1.0"


def _ensure_dir(path: Path) -> Path:
    """Create directory if it doesn't exist and return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def _timestamp_label() -> str:
    """Return a filesystem-safe timestamp label (e.g. '2026-02-18_143025')."""
    return datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")


def _write_json(data: Any, path: Path) -> str:
    """Write *data* as indented JSON to *path*. Returns the absolute path string."""
    _ensure_dir(path.parent)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return str(path)


def _read_json(path: Path) -> Any:
    """Read and return JSON from *path*."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ===========================================================================
# PatternExporter
# ===========================================================================

class PatternExporter:
    """Export successful patterns, payloads, and hypotheses from the database."""

    def __init__(self, db: Optional[BountyHoundDB] = None):
        self.db = db or BountyHoundDB.get_instance()

    # -----------------------------------------------------------------------
    # Patterns (learned_patterns table)
    # -----------------------------------------------------------------------

    def export_patterns(self, output_file: Optional[str] = None) -> str:
        """
        Export all successful learned patterns from the database to JSON.

        Args:
            output_file: Optional path for the output file. Defaults to
                         <sync_dir>/patterns.json

        Returns:
            Absolute path of the written file.
        """
        patterns: List[Dict] = []

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, tech, indicators, exploit_template,
                       success_count, failure_count,
                       targets_succeeded, targets_failed,
                       created_at, updated_at
                FROM learned_patterns
                ORDER BY success_count DESC
            """)
            for row in cursor.fetchall():
                record = dict(row)
                # Parse JSON fields stored as text
                for json_field in ("tech", "indicators", "targets_succeeded", "targets_failed"):
                    if record.get(json_field) and isinstance(record[json_field], str):
                        try:
                            record[json_field] = json.loads(record[json_field])
                        except (json.JSONDecodeError, TypeError):
                            pass
                patterns.append(record)

        envelope = {
            "version": EXPORT_VERSION,
            "type": "patterns",
            "exported_at": datetime.utcnow().isoformat(),
            "count": len(patterns),
            "patterns": patterns,
        }

        dest = Path(output_file) if output_file else SYNC_BASE_DIR / "patterns.json"
        return _write_json(envelope, dest)

    # -----------------------------------------------------------------------
    # Payloads (successful_payloads table)
    # -----------------------------------------------------------------------

    def export_payloads(
        self,
        vuln_type: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> str:
        """
        Export proven payloads from the database to JSON.

        Args:
            vuln_type: If provided, only export payloads for this vulnerability
                       type (e.g. 'XSS', 'SQLi').
            output_file: Optional path for the output file. Defaults to
                         <sync_dir>/payloads.json

        Returns:
            Absolute path of the written file.
        """
        payloads: List[Dict] = []

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            if vuln_type:
                cursor.execute("""
                    SELECT id, vuln_type, payload, context, tech_stack,
                           success_count, last_used, notes
                    FROM successful_payloads
                    WHERE vuln_type = ?
                    ORDER BY success_count DESC
                """, (vuln_type,))
            else:
                cursor.execute("""
                    SELECT id, vuln_type, payload, context, tech_stack,
                           success_count, last_used, notes
                    FROM successful_payloads
                    ORDER BY success_count DESC
                """)

            payloads = [dict(row) for row in cursor.fetchall()]

        envelope = {
            "version": EXPORT_VERSION,
            "type": "payloads",
            "exported_at": datetime.utcnow().isoformat(),
            "filter_vuln_type": vuln_type,
            "count": len(payloads),
            "payloads": payloads,
        }

        dest = Path(output_file) if output_file else SYNC_BASE_DIR / "payloads.json"
        return _write_json(envelope, dest)

    # -----------------------------------------------------------------------
    # Hypotheses (hypothesis_tests table)
    # -----------------------------------------------------------------------

    def export_hypotheses(
        self,
        target: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> str:
        """
        Export validated hypotheses from the database to JSON.

        Only hypotheses whose result is 'confirmed' or 'partial' are exported
        so that importing sessions receive high-signal data.

        Args:
            target: If provided, only export hypotheses for this target domain.
            output_file: Optional path for the output file. Defaults to
                         <sync_dir>/hypotheses.json

        Returns:
            Absolute path of the written file.
        """
        hypotheses: List[Dict] = []

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            if target:
                cursor.execute("""
                    SELECT id, target, hypothesis_title, hypothesis_test,
                           rationale, confidence, result, finding_id, tested_at
                    FROM hypothesis_tests
                    WHERE target = ? AND result IN ('confirmed', 'partial')
                    ORDER BY tested_at DESC
                """, (target,))
            else:
                cursor.execute("""
                    SELECT id, target, hypothesis_title, hypothesis_test,
                           rationale, confidence, result, finding_id, tested_at
                    FROM hypothesis_tests
                    WHERE result IN ('confirmed', 'partial')
                    ORDER BY tested_at DESC
                """)

            hypotheses = [dict(row) for row in cursor.fetchall()]

        envelope = {
            "version": EXPORT_VERSION,
            "type": "hypotheses",
            "exported_at": datetime.utcnow().isoformat(),
            "filter_target": target,
            "count": len(hypotheses),
            "hypotheses": hypotheses,
        }

        dest = Path(output_file) if output_file else SYNC_BASE_DIR / "hypotheses.json"
        return _write_json(envelope, dest)

    # -----------------------------------------------------------------------
    # Export everything
    # -----------------------------------------------------------------------

    def export_all(self, output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Export patterns, payloads, and hypotheses into a timestamped directory.

        Args:
            output_dir: Optional base directory. A timestamped subdirectory is
                        created automatically. Defaults to <sync_dir>/exports/.

        Returns:
            Dict mapping type name to the absolute path of the written file.
        """
        base = Path(output_dir) if output_dir else SYNC_BASE_DIR / "exports"
        export_dir = _ensure_dir(base / _timestamp_label())

        results = {
            "patterns": self.export_patterns(str(export_dir / "patterns.json")),
            "payloads": self.export_payloads(output_file=str(export_dir / "payloads.json")),
            "hypotheses": self.export_hypotheses(output_file=str(export_dir / "hypotheses.json")),
        }

        # Write a small manifest alongside the data files
        manifest = {
            "version": EXPORT_VERSION,
            "exported_at": datetime.utcnow().isoformat(),
            "files": results,
        }
        _write_json(manifest, export_dir / "manifest.json")

        return results


# ===========================================================================
# PatternImporter
# ===========================================================================

class PatternImporter:
    """Import patterns, payloads, and hypotheses from JSON files into the DB."""

    def __init__(self, db: Optional[BountyHoundDB] = None):
        self.db = db or BountyHoundDB.get_instance()

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _merge_pattern(existing: Dict, new: Dict) -> Dict:
        """
        Smart-merge two pattern records.

        Rules:
        - Keep the higher success_count.
        - Keep the higher failure_count.
        - Merge targets_succeeded / targets_failed lists (deduplicated).
        - Keep the more recent updated_at timestamp.
        - Prefer the existing exploit_template unless the new one is non-empty
          and the existing one is empty.

        Args:
            existing: The pattern record already in the database.
            new: The incoming pattern record from the import file.

        Returns:
            A merged dict ready for UPDATE.
        """

        def _parse_json_field(value):
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return []
            return value if value else []

        def _merge_lists(a, b):
            """Merge two lists, deduplicating while preserving order."""
            seen = set()
            merged = []
            for item in list(a) + list(b):
                key = str(item)
                if key not in seen:
                    seen.add(key)
                    merged.append(item)
            return merged

        merged = dict(existing)  # start from existing

        # Numeric maximums
        merged["success_count"] = max(
            existing.get("success_count") or 0,
            new.get("success_count") or 0,
        )
        merged["failure_count"] = max(
            existing.get("failure_count") or 0,
            new.get("failure_count") or 0,
        )

        # Merge target lists
        merged["targets_succeeded"] = _merge_lists(
            _parse_json_field(existing.get("targets_succeeded")),
            _parse_json_field(new.get("targets_succeeded")),
        )
        merged["targets_failed"] = _merge_lists(
            _parse_json_field(existing.get("targets_failed")),
            _parse_json_field(new.get("targets_failed")),
        )

        # Exploit template: prefer non-empty
        new_tmpl = (new.get("exploit_template") or "").strip()
        old_tmpl = (existing.get("exploit_template") or "").strip()
        if new_tmpl and not old_tmpl:
            merged["exploit_template"] = new_tmpl

        # Timestamp: keep the more recent
        new_ts = new.get("updated_at") or ""
        old_ts = existing.get("updated_at") or ""
        if new_ts > old_ts:
            merged["updated_at"] = new_ts

        return merged

    # -----------------------------------------------------------------------
    # Import patterns
    # -----------------------------------------------------------------------

    def import_patterns(self, input_file: str) -> Dict[str, int]:
        """
        Import patterns from a JSON export file, merging with existing records.

        Matching is done by pattern *name* and *tech* pair. If a match is found
        in the database the two records are merged via ``_merge_pattern``;
        otherwise a new row is inserted.

        Args:
            input_file: Path to the patterns JSON file.

        Returns:
            Dict with counts: inserted, updated, skipped.
        """
        data = _read_json(Path(input_file))
        patterns = data.get("patterns", [])

        inserted = 0
        updated = 0
        skipped = 0

        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            for pat in patterns:
                name = pat.get("name", "").strip()
                tech_raw = pat.get("tech")
                tech_str = json.dumps(tech_raw) if not isinstance(tech_raw, str) else tech_raw

                if not name:
                    skipped += 1
                    continue

                # Look for existing record by name + tech
                cursor.execute(
                    "SELECT * FROM learned_patterns WHERE name = ? AND tech = ?",
                    (name, tech_str),
                )
                existing_row = cursor.fetchone()

                if existing_row:
                    existing = dict(existing_row)
                    merged = self._merge_pattern(existing, pat)

                    cursor.execute("""
                        UPDATE learned_patterns
                        SET success_count = ?,
                            failure_count = ?,
                            targets_succeeded = ?,
                            targets_failed = ?,
                            exploit_template = ?,
                            indicators = ?,
                            updated_at = ?
                        WHERE id = ?
                    """, (
                        merged["success_count"],
                        merged["failure_count"],
                        json.dumps(merged["targets_succeeded"], default=str),
                        json.dumps(merged["targets_failed"], default=str),
                        merged.get("exploit_template", ""),
                        json.dumps(merged.get("indicators")) if merged.get("indicators") else None,
                        merged.get("updated_at", datetime.utcnow().isoformat()),
                        existing["id"],
                    ))
                    updated += 1
                else:
                    cursor.execute("""
                        INSERT INTO learned_patterns
                            (name, tech, indicators, exploit_template,
                             success_count, failure_count,
                             targets_succeeded, targets_failed,
                             created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        name,
                        tech_str,
                        json.dumps(pat.get("indicators")) if pat.get("indicators") else None,
                        pat.get("exploit_template", ""),
                        pat.get("success_count", 0),
                        pat.get("failure_count", 0),
                        json.dumps(pat.get("targets_succeeded", []), default=str),
                        json.dumps(pat.get("targets_failed", []), default=str),
                        pat.get("created_at", datetime.utcnow().isoformat()),
                        pat.get("updated_at", datetime.utcnow().isoformat()),
                    ))
                    inserted += 1

        return {"inserted": inserted, "updated": updated, "skipped": skipped}

    # -----------------------------------------------------------------------
    # Import payloads
    # -----------------------------------------------------------------------

    def import_payloads(self, input_file: str) -> Dict[str, int]:
        """
        Import payloads from a JSON export file, skipping exact duplicates.

        A payload is considered duplicate if the same (vuln_type, payload,
        tech_stack) triple already exists in the database. When a duplicate is
        found, the success_count is updated to the maximum of the two values.

        Args:
            input_file: Path to the payloads JSON file.

        Returns:
            Dict with counts: inserted, updated, skipped.
        """
        data = _read_json(Path(input_file))
        payloads = data.get("payloads", [])

        inserted = 0
        updated = 0
        skipped = 0

        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            for pl in payloads:
                vuln_type = (pl.get("vuln_type") or "").strip()
                payload_text = (pl.get("payload") or "").strip()

                if not vuln_type or not payload_text:
                    skipped += 1
                    continue

                tech_stack = pl.get("tech_stack") or ""

                # Check for exact duplicate
                cursor.execute("""
                    SELECT id, success_count FROM successful_payloads
                    WHERE vuln_type = ? AND payload = ? AND COALESCE(tech_stack, '') = ?
                """, (vuln_type, payload_text, tech_stack))
                existing = cursor.fetchone()

                if existing:
                    new_count = pl.get("success_count", 1)
                    old_count = existing["success_count"] or 0
                    if new_count > old_count:
                        cursor.execute("""
                            UPDATE successful_payloads
                            SET success_count = ?, last_used = ?
                            WHERE id = ?
                        """, (new_count, pl.get("last_used"), existing["id"]))
                        updated += 1
                    else:
                        skipped += 1
                else:
                    cursor.execute("""
                        INSERT INTO successful_payloads
                            (vuln_type, payload, context, tech_stack,
                             success_count, last_used, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        vuln_type,
                        payload_text,
                        pl.get("context"),
                        tech_stack if tech_stack else None,
                        pl.get("success_count", 1),
                        pl.get("last_used"),
                        pl.get("notes"),
                    ))
                    inserted += 1

        return {"inserted": inserted, "updated": updated, "skipped": skipped}

    # -----------------------------------------------------------------------
    # Import hypotheses
    # -----------------------------------------------------------------------

    def import_hypotheses(self, input_file: str) -> Dict[str, int]:
        """
        Import hypotheses from a JSON export file.

        Duplicates are detected by (target, hypothesis_title) pair. If a
        hypothesis already exists for the same target the import is skipped.

        Args:
            input_file: Path to the hypotheses JSON file.

        Returns:
            Dict with counts: inserted, skipped.
        """
        data = _read_json(Path(input_file))
        hypotheses = data.get("hypotheses", [])

        inserted = 0
        skipped = 0

        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            for hyp in hypotheses:
                target = (hyp.get("target") or "").strip()
                title = (hyp.get("hypothesis_title") or "").strip()

                if not target or not title:
                    skipped += 1
                    continue

                # Check for existing
                cursor.execute("""
                    SELECT id FROM hypothesis_tests
                    WHERE target = ? AND hypothesis_title = ?
                """, (target, title))

                if cursor.fetchone():
                    skipped += 1
                    continue

                cursor.execute("""
                    INSERT INTO hypothesis_tests
                        (target, hypothesis_title, hypothesis_test,
                         rationale, confidence, result, tested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    target,
                    title,
                    hyp.get("hypothesis_test", ""),
                    hyp.get("rationale"),
                    hyp.get("confidence"),
                    hyp.get("result"),
                    hyp.get("tested_at", datetime.utcnow().isoformat()),
                ))
                inserted += 1

        return {"inserted": inserted, "skipped": skipped}

    # -----------------------------------------------------------------------
    # Import everything from a full export directory
    # -----------------------------------------------------------------------

    def import_all(self, input_dir: str) -> Dict[str, Dict[str, int]]:
        """
        Import patterns, payloads, and hypotheses from a full export directory.

        The directory is expected to contain patterns.json, payloads.json, and
        hypotheses.json (as produced by ``PatternExporter.export_all``).
        Missing files are silently skipped.

        Args:
            input_dir: Path to the directory containing the export files.

        Returns:
            Dict mapping each type to its import result counts.
        """
        base = Path(input_dir)
        results: Dict[str, Dict[str, int]] = {}

        patterns_file = base / "patterns.json"
        if patterns_file.exists():
            results["patterns"] = self.import_patterns(str(patterns_file))

        payloads_file = base / "payloads.json"
        if payloads_file.exists():
            results["payloads"] = self.import_payloads(str(payloads_file))

        hypotheses_file = base / "hypotheses.json"
        if hypotheses_file.exists():
            results["hypotheses"] = self.import_hypotheses(str(hypotheses_file))

        return results


# ===========================================================================
# PatternSyncManager
# ===========================================================================

class PatternSyncManager:
    """
    High-level manager for automatic pattern import/export between sessions.

    The sync directory lives at C:/Users/vaugh/BountyHound/database/pattern-sync/
    and contains:
        - patterns.json   (latest snapshot)
        - payloads.json   (latest snapshot)
        - hypotheses.json (latest snapshot)
        - exports/        (timestamped full exports)
    """

    def __init__(self, db: Optional[BountyHoundDB] = None):
        self.db = db or BountyHoundDB.get_instance()
        self.sync_dir = _ensure_dir(SYNC_BASE_DIR)
        self.exporter = PatternExporter(db=self.db)
        self.importer = PatternImporter(db=self.db)

    # -----------------------------------------------------------------------
    # Auto-export (call after each hunt)
    # -----------------------------------------------------------------------

    def auto_export(self) -> Dict[str, str]:
        """
        Export all current patterns to the sync directory.

        Writes the latest snapshot files (patterns.json, payloads.json,
        hypotheses.json) directly into the sync directory so they are ready
        for the next session's auto_import. Also creates a timestamped
        archive under exports/.

        Returns:
            Dict mapping type name to written file path.
        """
        # Write latest snapshots into sync root
        snapshot_results = {
            "patterns": self.exporter.export_patterns(),
            "payloads": self.exporter.export_payloads(),
            "hypotheses": self.exporter.export_hypotheses(),
        }

        # Also create a timestamped archive for history
        archive_results = self.exporter.export_all(
            str(self.sync_dir / "exports")
        )

        return snapshot_results

    # -----------------------------------------------------------------------
    # Auto-import (call before each hunt)
    # -----------------------------------------------------------------------

    def auto_import(self) -> Dict[str, Dict[str, int]]:
        """
        Import any patterns from the sync directory that are not yet in the DB.

        Reads the latest snapshot files from the sync root directory.
        If no snapshot files exist yet (first run), returns empty results.

        Returns:
            Dict mapping each type to its import result counts.
        """
        results: Dict[str, Dict[str, int]] = {}

        patterns_file = self.sync_dir / "patterns.json"
        if patterns_file.exists():
            results["patterns"] = self.importer.import_patterns(str(patterns_file))

        payloads_file = self.sync_dir / "payloads.json"
        if payloads_file.exists():
            results["payloads"] = self.importer.import_payloads(str(payloads_file))

        hypotheses_file = self.sync_dir / "hypotheses.json"
        if hypotheses_file.exists():
            results["hypotheses"] = self.importer.import_hypotheses(str(hypotheses_file))

        return results

    # -----------------------------------------------------------------------
    # Status & listing
    # -----------------------------------------------------------------------

    def get_sync_status(self) -> Dict[str, Any]:
        """
        Show what patterns are available in the sync directory and database.

        Returns:
            Dict with counts of DB records and sync-file record counts,
            plus timestamps of last export.
        """
        status: Dict[str, Any] = {
            "sync_dir": str(self.sync_dir),
            "database": {},
            "sync_files": {},
        }

        # Database counts
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            try:
                cursor.execute("SELECT COUNT(*) as cnt FROM learned_patterns")
                status["database"]["patterns"] = cursor.fetchone()["cnt"]
            except Exception:
                status["database"]["patterns"] = 0

            try:
                cursor.execute("SELECT COUNT(*) as cnt FROM successful_payloads")
                status["database"]["payloads"] = cursor.fetchone()["cnt"]
            except Exception:
                status["database"]["payloads"] = 0

            try:
                cursor.execute(
                    "SELECT COUNT(*) as cnt FROM hypothesis_tests WHERE result IN ('confirmed', 'partial')"
                )
                status["database"]["hypotheses"] = cursor.fetchone()["cnt"]
            except Exception:
                status["database"]["hypotheses"] = 0

        # Sync file info
        for name in ("patterns", "payloads", "hypotheses"):
            filepath = self.sync_dir / f"{name}.json"
            if filepath.exists():
                try:
                    data = _read_json(filepath)
                    status["sync_files"][name] = {
                        "count": data.get("count", 0),
                        "exported_at": data.get("exported_at"),
                        "file": str(filepath),
                    }
                except (json.JSONDecodeError, KeyError):
                    status["sync_files"][name] = {"error": "corrupt file"}
            else:
                status["sync_files"][name] = {"exists": False}

        # Number of archived exports
        exports_dir = self.sync_dir / "exports"
        if exports_dir.exists():
            status["archived_exports"] = len(
                [d for d in exports_dir.iterdir() if d.is_dir()]
            )
        else:
            status["archived_exports"] = 0

        return status

    def list_exports(self) -> List[Dict[str, Any]]:
        """
        List all available timestamped export directories.

        Returns:
            List of dicts, each with 'directory', 'timestamp', and 'files' keys,
            sorted newest-first.
        """
        exports_dir = self.sync_dir / "exports"
        if not exports_dir.exists():
            return []

        entries: List[Dict[str, Any]] = []
        for child in sorted(exports_dir.iterdir(), reverse=True):
            if not child.is_dir():
                continue

            entry: Dict[str, Any] = {
                "directory": str(child),
                "timestamp": child.name,
                "files": [],
            }

            manifest_path = child / "manifest.json"
            if manifest_path.exists():
                try:
                    manifest = _read_json(manifest_path)
                    entry["exported_at"] = manifest.get("exported_at")
                    entry["files"] = list(manifest.get("files", {}).keys())
                except (json.JSONDecodeError, KeyError):
                    pass

            # Fallback: list json files directly
            if not entry["files"]:
                entry["files"] = [
                    f.name for f in child.iterdir()
                    if f.suffix == ".json" and f.name != "manifest.json"
                ]

            entries.append(entry)

        return entries
