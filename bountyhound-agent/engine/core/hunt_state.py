"""
Hunt State Persistence

Manages hunt state snapshots and generates RESUME.md files so that nothing
is lost between sessions. Each hunt session gets a unique session_id and
periodically saves snapshots to the hunt_snapshots DB table. When a new
session starts, it can load the latest snapshot for the target and resume
from where the previous session left off.

Usage:
    # Start a new hunt
    state = HuntState('example.com')
    state.update_phase('recon', 'in_progress')
    state.add_endpoint('https://example.com/api/users', 'GET')
    state.add_finding('IDOR in /api/users', 'HIGH', 'IDOR')
    state.generate_resume()

    # Resume a previous hunt
    state = HuntState.load_latest('example.com')
    if state:
        progress = state.get_progress()
        print(f"Resuming from phase: {state._state['phase']}")
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from engine.core.config import BountyHoundConfig
from engine.core.database import BountyHoundDB


class HuntState:
    """Manages hunt state snapshots and generates RESUME.md files."""

    def __init__(self, target: str):
        self.target = target
        self.session_id = str(uuid4())[:8]
        self._state = {
            'phase': 'init',
            'status': 'starting',
            'endpoints_discovered': [],
            'endpoints_tested': [],
            'findings': [],
            'pending_tests': [],
            'active_creds': [],
            'notes': [],
            'started_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # State mutation helpers
    # ------------------------------------------------------------------

    def update_phase(self, phase: str, status: str = 'in_progress') -> None:
        """Update current phase and save snapshot to DB."""
        try:
            self._state['phase'] = phase
            self._state['status'] = status
            self._state['last_updated'] = datetime.now().isoformat()
            self.save_snapshot()
        except Exception:
            # Never let a state-tracking failure crash the hunt
            pass

    def add_endpoint(self, url: str, method: str = 'GET') -> None:
        """Record an endpoint discovery."""
        try:
            entry = f"{method} {url}"
            if entry not in self._state['endpoints_discovered']:
                self._state['endpoints_discovered'].append(entry)
                self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    def mark_tested(self, url: str) -> None:
        """Mark an endpoint as tested."""
        try:
            if url not in self._state['endpoints_tested']:
                self._state['endpoints_tested'].append(url)
                self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    def add_finding(self, title: str, severity: str, vuln_type: str) -> None:
        """Record a finding."""
        try:
            finding = {
                'title': title,
                'severity': severity,
                'vuln_type': vuln_type,
                'found_at': datetime.now().isoformat(),
            }
            self._state['findings'].append(finding)
            self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    def add_pending_test(self, test_description: str) -> None:
        """Add a test to the pending queue."""
        try:
            if test_description not in self._state['pending_tests']:
                self._state['pending_tests'].append(test_description)
                self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    def remove_pending_test(self, test_description: str) -> None:
        """Remove a test from the pending queue (completed or skipped)."""
        try:
            if test_description in self._state['pending_tests']:
                self._state['pending_tests'].remove(test_description)
                self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    def set_creds(self, cred_info: Dict) -> None:
        """Record active credential info.

        *cred_info* should be a dict with keys like ``label``, ``token``,
        ``expires``, etc.
        """
        try:
            # Replace existing entry with the same label if present
            label = cred_info.get('label', '')
            self._state['active_creds'] = [
                c for c in self._state['active_creds']
                if c.get('label') != label
            ]
            self._state['active_creds'].append(cred_info)
            self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    def add_note(self, note: str) -> None:
        """Add a timestamped note."""
        try:
            entry = f"[{datetime.now().strftime('%H:%M:%S')}] {note}"
            self._state['notes'].append(entry)
            self._state['last_updated'] = datetime.now().isoformat()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_snapshot(self) -> None:
        """Save current state as a snapshot to the hunt_snapshots DB table.

        Lists are serialised as JSON strings so they fit in TEXT columns.
        """
        try:
            db = BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO hunt_snapshots
                        (target, session_id, phase, status,
                         endpoints_discovered, endpoints_tested,
                         findings_so_far, pending_tests,
                         active_creds, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.target,
                        self.session_id,
                        self._state['phase'],
                        self._state['status'],
                        json.dumps(self._state['endpoints_discovered']),
                        json.dumps(self._state['endpoints_tested']),
                        json.dumps(self._state['findings']),
                        json.dumps(self._state['pending_tests']),
                        json.dumps(self._state['active_creds']),
                        json.dumps(self._state['notes']),
                    ),
                )
        except Exception:
            pass

    def generate_resume(self) -> str:
        """Generate RESUME.md content and write to disk.

        Returns the markdown string that was written.
        """
        try:
            BountyHoundConfig.ensure_target_dirs(self.target)
            resume_path = BountyHoundConfig.resume_file(self.target)

            total_eps = len(self._state['endpoints_discovered'])
            tested_eps = len(self._state['endpoints_tested'])
            finding_count = len(self._state['findings'])
            pending_count = len(self._state['pending_tests'])

            lines: List[str] = []
            lines.append(f"# Hunt Resume: {self.target}")
            lines.append(
                f"**Session**: {self.session_id} | "
                f"**Last Updated**: {self._state['last_updated']}"
            )
            lines.append("")

            # Phase
            lines.append(
                f"## Current Phase: {self._state['phase']} "
                f"({self._state['status']})"
            )
            lines.append("")

            # Endpoints discovered
            lines.append(f"## Endpoints Discovered ({total_eps})")
            if self._state['endpoints_discovered']:
                for ep in self._state['endpoints_discovered']:
                    lines.append(f"- {ep}")
            else:
                lines.append("- (none yet)")
            lines.append("")

            # Endpoints tested
            lines.append(f"## Endpoints Tested ({tested_eps}/{total_eps})")
            discovered_set = set(self._state['endpoints_discovered'])
            for ep in self._state['endpoints_discovered']:
                tested_marker = (
                    "[x]" if ep in self._state['endpoints_tested'] else "[ ]"
                )
                lines.append(f"- {tested_marker} {ep}")
            lines.append("")

            # Findings
            lines.append(f"## Findings ({finding_count})")
            if self._state['findings']:
                for f in self._state['findings']:
                    lines.append(
                        f"- [{f.get('severity', '?')}] {f.get('title', 'Untitled')}"
                    )
            else:
                lines.append("- (none yet)")
            lines.append("")

            # Pending tests
            lines.append(f"## Pending Tests ({pending_count})")
            if self._state['pending_tests']:
                for t in self._state['pending_tests']:
                    lines.append(f"- {t}")
            else:
                lines.append("- (none)")
            lines.append("")

            # Active credentials
            lines.append("## Active Credentials")
            if self._state['active_creds']:
                for cred in self._state['active_creds']:
                    label = cred.get('label', 'unknown')
                    token_preview = str(cred.get('token', ''))[:20]
                    expires = cred.get('expires', 'unknown')
                    lines.append(
                        f"- {label}: {token_preview}... (expires: {expires})"
                    )
            else:
                lines.append("- (none)")
            lines.append("")

            # Notes
            lines.append("## Notes")
            if self._state['notes']:
                for n in self._state['notes']:
                    lines.append(f"- {n}")
            else:
                lines.append("- (none)")
            lines.append("")

            # Next steps
            lines.append("## Next Steps")
            lines.append(f"1. Continue from Phase **{self._state['phase']}**")
            remaining = total_eps - tested_eps
            if remaining > 0:
                lines.append(f"2. Test remaining {remaining} endpoints")
            if pending_count > 0:
                lines.append(
                    f"3. Complete {pending_count} pending tests"
                )
            if finding_count > 0:
                lines.append(
                    f"4. Validate and report {finding_count} findings"
                )
            lines.append("")

            content = "\n".join(lines)

            resume_path.parent.mkdir(parents=True, exist_ok=True)
            with open(resume_path, 'w', encoding='utf-8') as fh:
                fh.write(content)

            return content
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Loading / querying
    # ------------------------------------------------------------------

    @classmethod
    def load_latest(cls, target: str) -> Optional['HuntState']:
        """Load the most recent hunt state from DB for a target.

        Reconstructs a ``HuntState`` instance from the newest snapshot
        row so the caller can continue where the last session left off.
        """
        try:
            db = BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT session_id, phase, status,
                           endpoints_discovered, endpoints_tested,
                           findings_so_far, pending_tests,
                           active_creds, notes, created_at
                    FROM hunt_snapshots
                    WHERE target = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (target,),
                )
                row = cursor.fetchone()

            if row is None:
                return None

            row = dict(row)

            instance = cls.__new__(cls)
            instance.target = target
            instance.session_id = row['session_id']

            def _safe_json(val: str, default=None):
                """Parse a JSON string, returning *default* on failure."""
                if default is None:
                    default = []
                if not val:
                    return default
                try:
                    return json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    return default

            instance._state = {
                'phase': row['phase'],
                'status': row['status'],
                'endpoints_discovered': _safe_json(row['endpoints_discovered']),
                'endpoints_tested': _safe_json(row['endpoints_tested']),
                'findings': _safe_json(row['findings_so_far']),
                'pending_tests': _safe_json(row['pending_tests']),
                'active_creds': _safe_json(row['active_creds']),
                'notes': _safe_json(row['notes']),
                'started_at': row.get('created_at', datetime.now().isoformat()),
                'last_updated': row.get('created_at', datetime.now().isoformat()),
            }
            return instance
        except Exception:
            return None

    def get_progress(self) -> Dict:
        """Return progress summary.

        Keys:
            endpoints_discovered  - total discovered count
            endpoints_tested      - tested count
            endpoints_remaining   - untested count
            findings_count        - total findings so far
            pending_tests         - number of pending tests
            phase                 - current phase name
            status                - current status string
            started_at            - ISO timestamp
            last_updated          - ISO timestamp
            elapsed_seconds       - seconds since *started_at*
        """
        try:
            total = len(self._state['endpoints_discovered'])
            tested = len(self._state['endpoints_tested'])

            started = datetime.fromisoformat(self._state['started_at'])
            elapsed = (datetime.now() - started).total_seconds()

            return {
                'endpoints_discovered': total,
                'endpoints_tested': tested,
                'endpoints_remaining': total - tested,
                'findings_count': len(self._state['findings']),
                'pending_tests': len(self._state['pending_tests']),
                'phase': self._state['phase'],
                'status': self._state['status'],
                'started_at': self._state['started_at'],
                'last_updated': self._state['last_updated'],
                'elapsed_seconds': int(elapsed),
            }
        except Exception:
            return {
                'endpoints_discovered': 0,
                'endpoints_tested': 0,
                'endpoints_remaining': 0,
                'findings_count': 0,
                'pending_tests': 0,
                'phase': self._state.get('phase', 'unknown'),
                'status': self._state.get('status', 'unknown'),
                'started_at': self._state.get('started_at', ''),
                'last_updated': self._state.get('last_updated', ''),
                'elapsed_seconds': 0,
            }
