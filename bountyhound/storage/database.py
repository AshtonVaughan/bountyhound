"""SQLite database operations for BountyHound."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from bountyhound.storage.models import Target, Subdomain, Port, Finding, Run


class Database:
    """SQLite database wrapper for storing targets, subdomains, and findings."""

    def __init__(self, db_path: Path) -> None:
        """Initialize database with path, creating parent directories if needed."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        """Get or create a SQLite connection with row_factory."""
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
        return self._connection

    def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a SQL query with optional parameters."""
        conn = self.connect()
        return conn.execute(query, params)

    def initialize(self) -> None:
        """Create all database tables if they don't exist."""
        conn = self.connect()

        # Create targets table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                last_recon TEXT,
                last_scan TEXT
            )
        """)

        # Create subdomains table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                status_code INTEGER,
                technologies TEXT,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (target_id) REFERENCES targets (id),
                UNIQUE (target_id, hostname)
            )
        """)

        # Create ports table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                version TEXT,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (subdomain_id) REFERENCES subdomains (id),
                UNIQUE (subdomain_id, port)
            )
        """)

        # Create findings table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                url TEXT,
                evidence TEXT,
                template TEXT,
                found_at TEXT NOT NULL,
                FOREIGN KEY (subdomain_id) REFERENCES subdomains (id)
            )
        """)

        # Create runs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                stage TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        """)

        conn.commit()

    def add_target(self, domain: str) -> int:
        """Add a target domain, returning its ID. Ignores if already exists."""
        conn = self.connect()
        now = datetime.now().isoformat()

        conn.execute(
            "INSERT OR IGNORE INTO targets (domain, added_at) VALUES (?, ?)",
            (domain, now),
        )
        conn.commit()

        cursor = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
        row = cursor.fetchone()
        return row["id"]

    def get_target(self, domain: str) -> Optional[Target]:
        """Get a target by domain name, or None if not found."""
        cursor = self.execute("SELECT * FROM targets WHERE domain = ?", (domain,))
        row = cursor.fetchone()

        if row is None:
            return None

        return Target(
            id=row["id"],
            domain=row["domain"],
            added_at=datetime.fromisoformat(row["added_at"]),
            last_recon=datetime.fromisoformat(row["last_recon"]) if row["last_recon"] else None,
            last_scan=datetime.fromisoformat(row["last_scan"]) if row["last_scan"] else None,
        )

    def get_all_targets(self) -> list[Target]:
        """Get all targets from the database."""
        cursor = self.execute("SELECT * FROM targets ORDER BY added_at DESC")
        targets = []

        for row in cursor.fetchall():
            targets.append(
                Target(
                    id=row["id"],
                    domain=row["domain"],
                    added_at=datetime.fromisoformat(row["added_at"]),
                    last_recon=datetime.fromisoformat(row["last_recon"]) if row["last_recon"] else None,
                    last_scan=datetime.fromisoformat(row["last_scan"]) if row["last_scan"] else None,
                )
            )

        return targets

    def add_subdomain(
        self,
        target_id: int,
        hostname: str,
        ip_address: Optional[str] = None,
        status_code: Optional[int] = None,
        technologies: Optional[list[str]] = None,
    ) -> int:
        """Add or update a subdomain, returning its ID."""
        conn = self.connect()
        now = datetime.now().isoformat()
        tech_json = json.dumps(technologies or [])

        conn.execute(
            """
            INSERT OR REPLACE INTO subdomains
            (target_id, hostname, ip_address, status_code, technologies, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (target_id, hostname, ip_address, status_code, tech_json, now),
        )
        conn.commit()

        cursor = conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
            (target_id, hostname),
        )
        row = cursor.fetchone()
        return row["id"]

    def get_subdomains(self, target_id: int) -> list[Subdomain]:
        """Get all subdomains for a target."""
        cursor = self.execute(
            "SELECT * FROM subdomains WHERE target_id = ? ORDER BY hostname",
            (target_id,),
        )
        subdomains = []

        for row in cursor.fetchall():
            technologies = json.loads(row["technologies"]) if row["technologies"] else []
            subdomains.append(
                Subdomain(
                    id=row["id"],
                    target_id=row["target_id"],
                    hostname=row["hostname"],
                    ip_address=row["ip_address"],
                    status_code=row["status_code"],
                    technologies=technologies,
                    discovered_at=datetime.fromisoformat(row["discovered_at"]),
                )
            )

        return subdomains

    def add_finding(
        self,
        subdomain_id: int,
        name: str,
        severity: str,
        url: Optional[str] = None,
        evidence: Optional[str] = None,
        template: Optional[str] = None,
    ) -> int:
        """Add a finding, returning its ID."""
        conn = self.connect()
        now = datetime.now().isoformat()

        cursor = conn.execute(
            """
            INSERT INTO findings (subdomain_id, name, severity, url, evidence, template, found_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (subdomain_id, name, severity, url, evidence, template, now),
        )
        conn.commit()

        return cursor.lastrowid

    def get_findings(self, target_id: int) -> list[Finding]:
        """Get all findings for a target (joins with subdomains)."""
        cursor = self.execute(
            """
            SELECT f.* FROM findings f
            JOIN subdomains s ON f.subdomain_id = s.id
            WHERE s.target_id = ?
            ORDER BY f.found_at DESC
            """,
            (target_id,),
        )
        findings = []

        for row in cursor.fetchall():
            findings.append(
                Finding(
                    id=row["id"],
                    subdomain_id=row["subdomain_id"],
                    name=row["name"],
                    severity=row["severity"],
                    url=row["url"],
                    evidence=row["evidence"],
                    template=row["template"],
                    found_at=datetime.fromisoformat(row["found_at"]),
                )
            )

        return findings

    def update_target_recon_time(self, target_id: int) -> None:
        """Update the last_recon timestamp for a target."""
        conn = self.connect()
        now = datetime.now().isoformat()

        conn.execute(
            "UPDATE targets SET last_recon = ? WHERE id = ?",
            (now, target_id),
        )
        conn.commit()

    def update_target_scan_time(self, target_id: int) -> None:
        """Update the last_scan timestamp for a target."""
        conn = self.connect()
        now = datetime.now().isoformat()

        conn.execute(
            "UPDATE targets SET last_scan = ? WHERE id = ?",
            (now, target_id),
        )
        conn.commit()

    def get_subdomain_count(self, target_id: int) -> int:
        """Get the count of subdomains for a target."""
        cursor = self.execute(
            "SELECT COUNT(*) as count FROM subdomains WHERE target_id = ?",
            (target_id,),
        )
        row = cursor.fetchone()
        return row["count"]

    def get_finding_count(self, target_id: int) -> dict[str, int]:
        """Get finding counts by severity for a target."""
        cursor = self.execute(
            """
            SELECT f.severity, COUNT(*) as count FROM findings f
            JOIN subdomains s ON f.subdomain_id = s.id
            WHERE s.target_id = ?
            GROUP BY f.severity
            """,
            (target_id,),
        )

        counts = {}
        for row in cursor.fetchall():
            counts[row["severity"]] = row["count"]

        return counts
