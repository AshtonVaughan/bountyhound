"""
BountyHound SQLite Database

Tracks targets, findings, testing sessions, and payloads for data-driven hunting.
"""

import sqlite3
import os
import threading
from datetime import datetime, date
from pathlib import Path
from typing import Optional, Dict, List, Any
from contextlib import contextmanager


class BountyHoundDB:
    """SQLite database for tracking bug bounty hunting activity."""

    _instances: Dict[str, 'BountyHoundDB'] = {}
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> 'BountyHoundDB':
        """Get or create a singleton instance keyed by db_path."""
        if db_path is None:
            db_path = os.path.expanduser("~/.bountyhound/bountyhound.db")
        with cls._instance_lock:
            if db_path not in cls._instances:
                cls._instances[db_path] = cls(db_path)
            return cls._instances[db_path]

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file. Defaults to ~/.bountyhound/bountyhound.db
        """
        if db_path is None:
            db_path = os.path.expanduser("~/.bountyhound/bountyhound.db")

        self.db_path = db_path
        self._persistent_conn = None
        self._write_lock = threading.Lock()

        # Ensure directory exists (skip for :memory: databases)
        if db_path != ":memory:":
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        # Keep a persistent connection for all databases
        self._persistent_conn = sqlite3.connect(db_path, check_same_thread=False)
        self._persistent_conn.row_factory = sqlite3.Row

        # Enable WAL mode for better concurrent read performance (file-based only)
        if db_path != ":memory:":
            self._persistent_conn.execute("PRAGMA journal_mode=WAL")

        # Initialize database
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections (uses persistent connection)."""
        with self._write_lock:
            try:
                yield self._persistent_conn
                self._persistent_conn.commit()
            except Exception:
                self._persistent_conn.rollback()
                raise

    def _apply_migrations(self, cursor):
        """Apply database migrations for schema changes."""
        # Migration 1: Add currency column to findings table
        try:
            cursor.execute("SELECT currency FROM findings LIMIT 1")
        except sqlite3.OperationalError:
            # Column doesn't exist, add it
            cursor.execute("ALTER TABLE findings ADD COLUMN currency TEXT DEFAULT 'USD'")

        # Migration 8: Request log, hunt snapshots, FP patterns, agent metrics, payload attempts
        try:
            cursor.execute("SELECT id FROM request_log LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS request_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    request_headers TEXT,
                    request_body TEXT,
                    status_code INTEGER,
                    response_headers TEXT,
                    response_body_file TEXT,
                    response_size INTEGER DEFAULT 0,
                    duration_ms INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    phase TEXT,
                    agent TEXT,
                    tags TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hunt_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT NOT NULL,
                    endpoints_discovered TEXT,
                    endpoints_tested TEXT,
                    findings_so_far TEXT,
                    pending_tests TEXT,
                    active_creds TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS fp_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_name TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    indicators TEXT NOT NULL,
                    target_learned_from TEXT,
                    times_matched INTEGER DEFAULT 1,
                    last_matched DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    findings_produced INTEGER DEFAULT 0,
                    findings_confirmed INTEGER DEFAULT 0,
                    findings_false_positive INTEGER DEFAULT 0,
                    precision REAL GENERATED ALWAYS AS (
                        CAST(findings_confirmed AS REAL) /
                        NULLIF(findings_confirmed + findings_false_positive, 0)
                    ) VIRTUAL,
                    avg_severity_score REAL DEFAULT 0,
                    total_time_seconds INTEGER DEFAULT 0,
                    last_run DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payload_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    parameter TEXT,
                    payload TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    status_code INTEGER,
                    response_snippet TEXT,
                    success BOOLEAN DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recon_cache_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    data_value TEXT NOT NULL,
                    source TEXT,
                    ttl_days INTEGER DEFAULT 7,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_log_target ON request_log(target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_log_url ON request_log(url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_log_timestamp ON request_log(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_snapshots_target ON hunt_snapshots(target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_snapshots_session ON hunt_snapshots(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_fp_patterns_type ON fp_patterns(pattern_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent ON agent_metrics(agent_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_payload_attempts_target ON payload_attempts(target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_payload_attempts_endpoint ON payload_attempts(endpoint)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_payload_attempts_vuln ON payload_attempts(vuln_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_recon_cache_v2_target ON recon_cache_v2(target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_recon_cache_v2_type ON recon_cache_v2(data_type)")

        # Migration 7: AI Learning tables
        try:
            cursor.execute("SELECT id FROM learned_patterns LIMIT 1")
        except sqlite3.OperationalError:
            # Tables don't exist, create them via inline SQL
            # Cannot use cursor.executescript() inside a transaction
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    tech JSON NOT NULL,
                    indicators JSON,
                    exploit_template TEXT,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    success_rate REAL GENERATED ALWAYS AS (
                        CAST(success_count AS REAL) / NULLIF(success_count + failure_count, 0)
                    ) VIRTUAL,
                    targets_succeeded JSON,
                    targets_failed JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hypothesis_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    hypothesis_title TEXT NOT NULL,
                    hypothesis_test TEXT NOT NULL,
                    rationale TEXT,
                    confidence TEXT,
                    result TEXT,
                    finding_id INTEGER,
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (finding_id) REFERENCES findings(id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploit_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    chain_title TEXT NOT NULL,
                    steps JSON NOT NULL,
                    findings_used JSON NOT NULL,
                    impact TEXT,
                    verified BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learned_patterns_tech ON learned_patterns(tech)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learned_patterns_success_rate ON learned_patterns(success_rate)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hypothesis_tests_target ON hypothesis_tests(target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hypothesis_tests_result ON hypothesis_tests(result)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploit_chains_target ON exploit_chains(target)")

    def _init_database(self):
        """Create database tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Table 1: targets - Programs being hunted
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    program_name TEXT,
                    platform TEXT,  -- hackerone, bugcrowd, etc.
                    platform_handle TEXT,
                    added_date DATE NOT NULL,
                    last_tested DATE,
                    total_findings INTEGER DEFAULT 0,
                    accepted_findings INTEGER DEFAULT 0,
                    total_payouts REAL DEFAULT 0.0,
                    avg_payout REAL DEFAULT 0.0,
                    notes TEXT
                )
            """)

            # Table 2: findings - All vulnerabilities
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
                    vuln_type TEXT NOT NULL,  -- IDOR, XSS, SQLi, etc.
                    discovered_date DATE NOT NULL,
                    status TEXT NOT NULL,  -- pending, accepted, duplicate, informative, n/a
                    platform_report_id TEXT,
                    payout REAL DEFAULT 0.0,
                    currency TEXT DEFAULT 'USD',
                    description TEXT,
                    poc TEXT,
                    endpoints TEXT,  -- JSON array of affected endpoints
                    tool_name TEXT DEFAULT '',  -- Tool that discovered this finding
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """)

            # Table 3: testing_sessions - Time tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS testing_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    start_time DATETIME NOT NULL,
                    end_time DATETIME,
                    duration_minutes INTEGER,
                    findings_count INTEGER DEFAULT 0,
                    tools_used TEXT,  -- JSON array of tool names
                    notes TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """)

            # Table 4: successful_payloads - Exploit library
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS successful_payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    context TEXT,  -- where it worked (parameter, header, etc.)
                    tech_stack TEXT,  -- React, PHP, etc.
                    success_count INTEGER DEFAULT 1,
                    last_used DATE,
                    notes TEXT
                )
            """)

            # Table 5: assets - Tested infrastructure
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,  -- subdomain, s3_bucket, api_endpoint, etc.
                    asset_value TEXT NOT NULL,
                    discovered_date DATE NOT NULL,
                    tested BOOLEAN DEFAULT 0,
                    last_tested DATE,
                    findings_count INTEGER DEFAULT 0,
                    notes TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """)

            # Table 6: recon_data - Discovery results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recon_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    data_type TEXT NOT NULL,  -- subdomain, tech_stack, js_file, etc.
                    data_value TEXT NOT NULL,
                    source TEXT,  -- subfinder, httpx, manual, etc.
                    discovered_date DATE NOT NULL,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """)

            # Table 7: notes - Observations
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    note_type TEXT,  -- observation, idea, blocker, etc.
                    content TEXT NOT NULL,
                    created_date DATETIME NOT NULL,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """)

            # Table 8: automation_runs - Tool history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS automation_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    run_date DATE NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    duration_seconds INTEGER,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """)

            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_platform_report_id ON findings(platform_report_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_discovered_date ON findings(discovered_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_testing_sessions_target ON testing_sessions(target_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_successful_payloads_vuln_type ON successful_payloads(vuln_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_automation_target_tool ON automation_runs(target_id, tool_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id)")

            # Apply migrations (must be after table creation)
            self._apply_migrations(cursor)

    def get_or_create_target(self, domain: str) -> int:
        """Get target ID or create if doesn't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Try to get existing
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            row = cursor.fetchone()

            if row:
                return row['id']

            # Create new
            cursor.execute(
                "INSERT INTO targets (domain, added_date) VALUES (?, ?)",
                (domain, date.today().isoformat())
            )
            return cursor.lastrowid

    def get_target_stats(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get target statistics for DatabaseHooks.

        Returns:
            Dict with last_tested, total_findings, total_payouts, etc.
            None if target doesn't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, domain, last_tested, total_findings, accepted_findings,
                       total_payouts, avg_payout
                FROM targets
                WHERE domain = ?
            """, (domain,))

            row = cursor.fetchone()
            if not row:
                return None

            # Convert to dict and parse date
            result = dict(row)
            if result['last_tested']:
                result['last_tested'] = datetime.strptime(result['last_tested'], '%Y-%m-%d').date()

            return result

    def get_recent_findings(self, domain: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent findings for a target."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.title, f.description, f.vuln_type, f.severity, f.status,
                       f.discovered_date, f.payout
                FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE t.domain = ?
                ORDER BY f.discovered_date DESC
                LIMIT ?
            """, (domain, limit))

            return [dict(row) for row in cursor.fetchall()]

    def get_last_tool_run(self, domain: str, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get the last time a tool was run on a target."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT a.run_date, a.findings_count, a.success
                FROM automation_runs a
                JOIN targets t ON a.target_id = t.id
                WHERE t.domain = ? AND a.tool_name = ?
                ORDER BY a.run_date DESC
                LIMIT 1
            """, (domain, tool_name))

            row = cursor.fetchone()
            if not row:
                return None

            result = dict(row)
            result['run_date'] = datetime.strptime(result['run_date'], '%Y-%m-%d').date()
            return result

    def get_findings_by_tool(self, domain: str, tool_name: str) -> List[Dict[str, Any]]:
        """Get all findings discovered by a specific tool."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.* FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE t.domain = ? AND f.tool_name = ?
                ORDER BY f.discovered_date DESC
            """, (domain, tool_name))
            return [dict(row) for row in cursor.fetchall()]

    def record_tool_run(self, domain: str, tool_name: str, findings_count: int = 0,
                       duration_seconds: Optional[int] = None, success: bool = True,
                       error_message: Optional[str] = None):
        """Record that a tool was run."""
        target_id = self.get_or_create_target(domain)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO automation_runs
                (target_id, tool_name, run_date, findings_count, duration_seconds, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (target_id, tool_name, date.today().isoformat(), findings_count,
                  duration_seconds, 1 if success else 0, error_message))

            # Update target last_tested
            cursor.execute("""
                UPDATE targets SET last_tested = ? WHERE id = ?
            """, (date.today().isoformat(), target_id))

    def find_similar_findings(self, domain: str, vuln_type: str, keywords: List[str]) -> Optional[Dict[str, Any]]:
        """
        Find similar findings to prevent duplicates.

        Args:
            domain: Target domain
            vuln_type: Vulnerability type (IDOR, XSS, etc.)
            keywords: Keywords to search in title/description

        Returns:
            First matching finding or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Build keyword search
            keyword_conditions = " OR ".join(["(f.title LIKE ? OR f.description LIKE ?)"] * len(keywords))
            keyword_params = []
            for kw in keywords:
                keyword_params.extend([f"%{kw}%", f"%{kw}%"])

            query = f"""
                SELECT f.title, f.severity, f.status, f.platform_report_id, f.discovered_date
                FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE t.domain = ? AND f.vuln_type = ?
                AND ({keyword_conditions})
                ORDER BY f.discovered_date DESC
                LIMIT 1
            """

            cursor.execute(query, [domain, vuln_type] + keyword_params)
            row = cursor.fetchone()

            return dict(row) if row else None

    def get_finding_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Get finding by platform report ID.

        Args:
            report_id: Platform report ID (HackerOne, Bugcrowd, etc.)

        Returns:
            Finding dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM findings WHERE platform_report_id = ?",
                (report_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_finding_payout(self, report_id: str, amount: float, currency: str = "USD"):
        """
        Update payout for an existing finding.

        Args:
            report_id: Platform report ID
            amount: Payout amount
            currency: Currency code (default: USD)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE findings SET payout = ? WHERE platform_report_id = ?",
                (amount, report_id)
            )

            # Also update target totals if finding is accepted
            cursor.execute("""
                UPDATE targets
                SET total_payouts = (
                    SELECT COALESCE(SUM(payout), 0)
                    FROM findings
                    WHERE target_id = targets.id AND status = 'accepted'
                ),
                avg_payout = (
                    SELECT COALESCE(AVG(payout), 0)
                    FROM findings
                    WHERE target_id = targets.id AND status = 'accepted' AND payout > 0
                )
                WHERE id = (
                    SELECT target_id FROM findings WHERE platform_report_id = ?
                )
            """, (report_id,))

    def insert_finding(self, target: str, vuln_type: str, title: str,
                      severity: str, status: str = "pending",
                      payout: float = 0.0, currency: str = "USD",
                      report_id: Optional[str] = None, description: Optional[str] = None,
                      poc: Optional[str] = None, endpoints: Optional[str] = None,
                      tool_name: Optional[str] = None):
        """
        Insert a new finding into the database.

        Args:
            target: Target domain
            vuln_type: Vulnerability type (XSS, IDOR, SQLi, etc.)
            title: Finding title
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            status: Finding status (default: pending)
            payout: Payout amount (default: 0.0)
            currency: Currency code (default: USD)
            report_id: Platform report ID (optional)
            description: Description text (optional)
            poc: Proof of concept (optional)
            endpoints: JSON array of affected endpoints (optional)
            tool_name: Tool that discovered this finding (optional)

        Returns:
            ID of inserted finding
        """
        target_id = self.get_or_create_target(target)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO findings
                (target_id, title, severity, vuln_type, discovered_date, status,
                 platform_report_id, payout, description, poc, endpoints, tool_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (target_id, title, severity, vuln_type, date.today().isoformat(),
                  status, report_id, payout, description, poc, endpoints, tool_name))

            # Update target statistics
            cursor.execute("""
                UPDATE targets
                SET total_findings = total_findings + 1,
                    accepted_findings = accepted_findings + CASE WHEN ? = 'accepted' THEN 1 ELSE 0 END,
                    total_payouts = total_payouts + CASE WHEN ? = 'accepted' THEN ? ELSE 0 END
                WHERE id = ?
            """, (status, status, payout, target_id))

            # Update average payout
            cursor.execute("""
                UPDATE targets
                SET avg_payout = (
                    SELECT COALESCE(AVG(payout), 0)
                    FROM findings
                    WHERE target_id = ? AND status = 'accepted' AND payout > 0
                )
                WHERE id = ?
            """, (target_id, target_id))

            return cursor.lastrowid

    def get_recent_findings_by_type(self, domain: str, vuln_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent findings for a target filtered by vulnerability type (SQL-side)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.title, f.description, f.vuln_type, f.severity, f.status,
                       f.discovered_date, f.payout
                FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE t.domain = ? AND f.vuln_type = ?
                ORDER BY f.discovered_date DESC
                LIMIT ?
            """, (domain, vuln_type, limit))
            return [dict(row) for row in cursor.fetchall()]

    def get_findings_by_vuln_type(self, vuln_type: str) -> List[Dict]:
        """Get all findings of a specific vulnerability type"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.*, t.domain as target
                FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE f.vuln_type = ?
                ORDER BY f.discovered_date DESC
            """, (vuln_type,))
            return [dict(row) for row in cursor.fetchall()]

    def get_findings_by_target(self, target: str) -> List[Dict]:
        """Get all findings for a specific target"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.*, t.domain as target
                FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE t.domain = ?
                ORDER BY f.discovered_date DESC
            """, (target,))
            return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close database connection (compatibility method for tests)."""
        if self._persistent_conn:
            self._persistent_conn.close()
            self._persistent_conn = None
        # Remove from singleton cache
        with self._instance_lock:
            self._instances.pop(self.db_path, None)
