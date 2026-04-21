"""
Payload Tracker

Tracks every payload attempt per target so that tests are never repeated.
All data is stored in the ``payload_attempts`` table via ``BountyHoundDB``.

Before sending a payload the caller should check ``was_tried()`` or
``was_endpoint_tested()`` to avoid wasting time on duplicate work.  After
each attempt the caller records the result with ``record_attempt()``.

Usage:
    tracker = PayloadTracker('example.com')

    # Before testing
    if not tracker.was_tried('/api/users', "' OR 1=1 --"):
        resp = send_payload(...)
        tracker.record_attempt(
            endpoint='/api/users',
            payload="' OR 1=1 --",
            vuln_type='SQLi',
            parameter='id',
            status_code=resp.status_code,
            response_snippet=resp.text[:200],
            success=(resp.status_code == 200 and 'admin' in resp.text),
        )

    # Find untested endpoints
    untested = tracker.get_untested_endpoints(all_endpoints, 'XSS')
"""

from datetime import datetime
from typing import Dict, List, Optional

from engine.core.config import BountyHoundConfig
from engine.core.database import BountyHoundDB


class PayloadTracker:
    """Tracks payload attempts per target to prevent duplicate testing."""

    def __init__(self, target: str):
        self.target = target

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _db() -> BountyHoundDB:
        return BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_attempt(
        self,
        endpoint: str,
        payload: str,
        vuln_type: str,
        parameter: str = '',
        status_code: int = 0,
        response_snippet: str = '',
        success: bool = False,
    ) -> None:
        """Record a payload attempt in the payload_attempts table."""
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO payload_attempts
                        (target, endpoint, parameter, payload, vuln_type,
                         status_code, response_snippet, success)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.target,
                        endpoint,
                        parameter,
                        payload,
                        vuln_type,
                        status_code,
                        response_snippet[:2000] if response_snippet else '',
                        1 if success else 0,
                    ),
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Deduplication checks
    # ------------------------------------------------------------------

    def was_tried(self, endpoint: str, payload: str) -> bool:
        """Check if this exact payload was already tried on this endpoint."""
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM payload_attempts
                    WHERE target = ? AND endpoint = ? AND payload = ?
                    """,
                    (self.target, endpoint, payload),
                )
                row = cursor.fetchone()
                return (row['cnt'] if row else 0) > 0
        except Exception:
            return False

    def was_endpoint_tested(self, endpoint: str, vuln_type: str) -> bool:
        """Check if this endpoint was tested for a given vuln type."""
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM payload_attempts
                    WHERE target = ? AND endpoint = ? AND vuln_type = ?
                    """,
                    (self.target, endpoint, vuln_type),
                )
                row = cursor.fetchone()
                return (row['cnt'] if row else 0) > 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_successful(self, vuln_type: Optional[str] = None) -> List[Dict]:
        """Get all successful payloads for this target.

        Optionally filter by *vuln_type*.  Returns a list of dicts with
        keys: ``endpoint``, ``parameter``, ``payload``, ``vuln_type``,
        ``status_code``, ``response_snippet``, ``timestamp``.
        """
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                if vuln_type is not None:
                    cursor.execute(
                        """
                        SELECT endpoint, parameter, payload, vuln_type,
                               status_code, response_snippet, timestamp
                        FROM payload_attempts
                        WHERE target = ? AND success = 1 AND vuln_type = ?
                        ORDER BY timestamp DESC
                        """,
                        (self.target, vuln_type),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT endpoint, parameter, payload, vuln_type,
                               status_code, response_snippet, timestamp
                        FROM payload_attempts
                        WHERE target = ? AND success = 1
                        ORDER BY timestamp DESC
                        """,
                        (self.target,),
                    )
                return [
                    {
                        'endpoint': row['endpoint'],
                        'parameter': row['parameter'],
                        'payload': row['payload'],
                        'vuln_type': row['vuln_type'],
                        'status_code': row['status_code'],
                        'response_snippet': row['response_snippet'],
                        'timestamp': row['timestamp'],
                    }
                    for row in cursor.fetchall()
                ]
        except Exception:
            return []

    def get_attempts(self, endpoint: str) -> List[Dict]:
        """Get all payload attempts for a specific endpoint."""
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT endpoint, parameter, payload, vuln_type,
                           status_code, response_snippet, success, timestamp
                    FROM payload_attempts
                    WHERE target = ? AND endpoint = ?
                    ORDER BY timestamp DESC
                    """,
                    (self.target, endpoint),
                )
                return [
                    {
                        'endpoint': row['endpoint'],
                        'parameter': row['parameter'],
                        'payload': row['payload'],
                        'vuln_type': row['vuln_type'],
                        'status_code': row['status_code'],
                        'response_snippet': row['response_snippet'],
                        'success': bool(row['success']),
                        'timestamp': row['timestamp'],
                    }
                    for row in cursor.fetchall()
                ]
        except Exception:
            return []

    def get_untested_endpoints(
        self, all_endpoints: List[str], vuln_type: str
    ) -> List[str]:
        """Given a list of endpoints, return only those not yet tested for
        the specified vuln type.
        """
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT DISTINCT endpoint
                    FROM payload_attempts
                    WHERE target = ? AND vuln_type = ?
                    """,
                    (self.target, vuln_type),
                )
                tested = {row['endpoint'] for row in cursor.fetchall()}
            return [ep for ep in all_endpoints if ep not in tested]
        except Exception:
            return list(all_endpoints)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict:
        """Return a summary of payload attempts for this target.

        Returns a dict with keys:
            ``total_attempts`` -- total number of attempts
            ``successful``     -- number of successful attempts
            ``by_vuln_type``   -- dict mapping vuln_type to
                ``{tried: int, succeeded: int}``
        """
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()

                # Overall counts
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS succeeded
                    FROM payload_attempts
                    WHERE target = ?
                    """,
                    (self.target,),
                )
                totals_row = cursor.fetchone()
                total_attempts = totals_row['total'] if totals_row else 0
                total_successful = totals_row['succeeded'] if totals_row else 0

                # Per vuln-type breakdown
                cursor.execute(
                    """
                    SELECT
                        vuln_type,
                        COUNT(*) AS tried,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS succeeded
                    FROM payload_attempts
                    WHERE target = ?
                    GROUP BY vuln_type
                    ORDER BY tried DESC
                    """,
                    (self.target,),
                )
                by_type = {}
                for row in cursor.fetchall():
                    by_type[row['vuln_type']] = {
                        'tried': row['tried'],
                        'succeeded': row['succeeded'],
                    }

                return {
                    'total_attempts': total_attempts,
                    'successful': total_successful,
                    'by_vuln_type': by_type,
                }
        except Exception:
            return {
                'total_attempts': 0,
                'successful': 0,
                'by_vuln_type': {},
            }
