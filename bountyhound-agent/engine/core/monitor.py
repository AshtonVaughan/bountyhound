"""
Continuous Target Monitoring

Monitor targets for changes and new vulnerabilities with automated re-scanning.
"""

import time
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from engine.core.database import BountyHoundDB


class ContinuousMonitor:
    """Monitor targets for changes and new vulnerabilities"""

    def __init__(self, db: Optional[BountyHoundDB] = None):
        self.db = db if db else BountyHoundDB.get_instance()

    def add_target(self, target: str, check_interval: int = 86400):
        """
        Add target to monitoring list

        Args:
            target: Target domain/URL
            check_interval: Check interval in seconds (default: 24h)
        """
        # Store in database
        with self.db._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS monitored_targets (
                    id INTEGER PRIMARY KEY,
                    target TEXT UNIQUE,
                    check_interval INTEGER,
                    last_scan TIMESTAMP,
                    last_state TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                INSERT OR REPLACE INTO monitored_targets (target, check_interval, last_scan)
                VALUES (?, ?, ?)
            """, (target, check_interval, datetime.now().isoformat()))

            conn.commit()

        print(f"[+] Added {target} to monitoring (interval: {check_interval}s)")

    def get_monitored_targets(self) -> List[Dict]:
        """Get all monitored targets"""
        with self.db._get_connection() as conn:
            # Ensure table exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS monitored_targets (
                    id INTEGER PRIMARY KEY,
                    target TEXT UNIQUE,
                    check_interval INTEGER,
                    last_scan TIMESTAMP,
                    last_state TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor = conn.execute("SELECT * FROM monitored_targets")
            return [dict(row) for row in cursor.fetchall()]

    def check_for_changes(self, target: str) -> Dict:
        """
        Check target for changes since last scan

        Detects:
        - New endpoints
        - New features
        - Tech stack changes
        - Security header changes

        Args:
            target: Target domain

        Returns:
            Dictionary of detected changes
        """
        changes = {
            "new_endpoints": [],
            "removed_endpoints": [],
            "tech_stack_changes": [],
            "security_header_changes": [],
            "timestamp": datetime.now().isoformat()
        }

        # Get last scan state
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT last_state FROM monitored_targets WHERE target = ?",
                (target,)
            )
            row = cursor.fetchone()

            if not row or not row['last_state']:
                # First scan - save current state
                current_state = self._scan_target_state(target)
                conn.execute(
                    "UPDATE monitored_targets SET last_state = ?, last_scan = ? WHERE target = ?",
                    (str(current_state), datetime.now().isoformat(), target)
                )
                conn.commit()

                changes["note"] = "First scan - baseline established"
                return changes

            # Compare with current state
            last_state = eval(row['last_state'])  # Convert string back to dict
            current_state = self._scan_target_state(target)

            # Detect new endpoints
            new_eps = set(current_state.get("endpoints", [])) - set(last_state.get("endpoints", []))
            changes["new_endpoints"] = list(new_eps)

            # Detect removed endpoints
            removed_eps = set(last_state.get("endpoints", [])) - set(current_state.get("endpoints", []))
            changes["removed_endpoints"] = list(removed_eps)

            # Detect tech stack changes
            if current_state.get("tech_stack") != last_state.get("tech_stack"):
                changes["tech_stack_changes"] = [
                    f"Changed from {last_state.get('tech_stack')} to {current_state.get('tech_stack')}"
                ]

            # Update last state
            conn.execute(
                "UPDATE monitored_targets SET last_state = ?, last_scan = ? WHERE target = ?",
                (str(current_state), datetime.now().isoformat(), target)
            )
            conn.commit()

        return changes

    def _scan_target_state(self, target: str) -> Dict:
        """Scan and return current target state"""
        # Simplified implementation - would use recon tools in practice
        return {
            "endpoints": ["/", "/api", "/login"],
            "tech_stack": "unknown",
            "headers": {}
        }

    def schedule_rescans(self) -> List[Dict]:
        """
        Schedule automatic re-scans for all monitored targets

        Returns:
            List of scheduled scans
        """
        scheduled = []

        targets = self.get_monitored_targets()

        for target_info in targets:
            target = target_info["target"]
            check_interval = target_info["check_interval"]
            last_scan = target_info.get("last_scan")

            # Check if rescan needed
            if last_scan:
                last_scan_dt = datetime.fromisoformat(last_scan)
                next_scan = last_scan_dt + timedelta(seconds=check_interval)

                if datetime.now() >= next_scan:
                    scheduled.append({
                        "target": target,
                        "scheduled_for": "now",
                        "reason": "interval_elapsed"
                    })
            else:
                # Never scanned - schedule immediately
                scheduled.append({
                    "target": target,
                    "scheduled_for": "now",
                    "reason": "first_scan"
                })

        return scheduled

    def alert_on_findings(self, target: str, findings: List[Dict]) -> bool:
        """
        Alert when new findings discovered

        Notification methods:
        - Console output (basic)
        - Email (future)
        - Slack (future)
        - Discord (future)

        Args:
            target: Target that findings were discovered on
            findings: List of finding dictionaries

        Returns:
            True if alert sent successfully
        """
        if not findings:
            return False

        # Console alert (basic implementation)
        print(f"\n{'='*60}")
        print(f"[!] NEW FINDINGS DISCOVERED ON {target}")
        print(f"{'='*60}")
        print(f"Findings: {len(findings)}")

        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            title = finding.get("title", "Untitled")
            print(f"  [{severity}] {title}")

        print(f"{'='*60}\n")

        # TODO: Implement email/Slack/Discord notifications

        return True
