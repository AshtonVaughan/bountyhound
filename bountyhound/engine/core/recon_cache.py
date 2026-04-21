"""
Recon Cache with TTL

Caches recon data (subdomains, ports, tech stacks, endpoints, JS files, etc.)
with a configurable time-to-live so that expensive recon steps are not repeated
unnecessarily.  All data is stored in the ``recon_cache_v2`` SQLite table via
``BountyHoundDB``.

Usage:
    cache = ReconCache('example.com')

    # Store results from subfinder
    cache.store_batch('subdomain', ['a.example.com', 'b.example.com'],
                      source='subfinder', ttl_days=7)

    # Check freshness before re-running recon
    if not cache.is_fresh('subdomain'):
        run_subfinder()

    # Retrieve cached data
    subs = cache.get('subdomain')
    # [{'value': 'a.example.com', 'source': 'subfinder', ...}, ...]
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from engine.core.config import BountyHoundConfig
from engine.core.database import BountyHoundDB


class ReconCache:
    """TTL-aware recon data cache backed by recon_cache_v2 table."""

    def __init__(self, target: str):
        self.target = target

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _db() -> BountyHoundDB:
        return BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def store(
        self,
        data_type: str,
        data_value: str,
        source: str = 'unknown',
        ttl_days: int = 7,
    ) -> None:
        """Store a single recon data item with TTL.

        Common *data_type* values: ``subdomain``, ``port``, ``tech_stack``,
        ``endpoint``, ``js_file``, ``api_endpoint``, ``email``.
        """
        try:
            expires_at = (
                datetime.now() + timedelta(days=ttl_days)
            ).strftime('%Y-%m-%d %H:%M:%S')

            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO recon_cache_v2
                        (target, data_type, data_value, source, ttl_days, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (self.target, data_type, data_value, source, ttl_days, expires_at),
                )
        except Exception:
            pass

    def store_batch(
        self,
        data_type: str,
        values: List[str],
        source: str = 'unknown',
        ttl_days: int = 7,
    ) -> int:
        """Store multiple items at once. Returns count stored."""
        stored = 0
        try:
            expires_at = (
                datetime.now() + timedelta(days=ttl_days)
            ).strftime('%Y-%m-%d %H:%M:%S')

            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                rows = [
                    (self.target, data_type, v, source, ttl_days, expires_at)
                    for v in values
                ]
                cursor.executemany(
                    """
                    INSERT INTO recon_cache_v2
                        (target, data_type, data_value, source, ttl_days, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                stored = len(rows)
        except Exception:
            pass
        return stored

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get(
        self, data_type: str, include_expired: bool = False
    ) -> List[Dict]:
        """Get all cached values of a given type.

        Returns a list of dicts with keys: ``value``, ``source``,
        ``cached_at``, ``expires_at``.  Expired entries are excluded
        unless *include_expired* is ``True``.
        """
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()

                if include_expired:
                    cursor.execute(
                        """
                        SELECT data_value, source, created_at, expires_at
                        FROM recon_cache_v2
                        WHERE target = ? AND data_type = ?
                        ORDER BY created_at DESC
                        """,
                        (self.target, data_type),
                    )
                else:
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute(
                        """
                        SELECT data_value, source, created_at, expires_at
                        FROM recon_cache_v2
                        WHERE target = ? AND data_type = ?
                          AND (expires_at IS NULL OR expires_at > ?)
                        ORDER BY created_at DESC
                        """,
                        (self.target, data_type, now),
                    )

                return [
                    {
                        'value': row['data_value'],
                        'source': row['source'],
                        'cached_at': row['created_at'],
                        'expires_at': row['expires_at'],
                    }
                    for row in cursor.fetchall()
                ]
        except Exception:
            return []

    def get_all(self, include_expired: bool = False) -> Dict[str, List[Dict]]:
        """Get all cached data grouped by type."""
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()

                if include_expired:
                    cursor.execute(
                        """
                        SELECT data_type, data_value, source, created_at, expires_at
                        FROM recon_cache_v2
                        WHERE target = ?
                        ORDER BY data_type, created_at DESC
                        """,
                        (self.target,),
                    )
                else:
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute(
                        """
                        SELECT data_type, data_value, source, created_at, expires_at
                        FROM recon_cache_v2
                        WHERE target = ?
                          AND (expires_at IS NULL OR expires_at > ?)
                        ORDER BY data_type, created_at DESC
                        """,
                        (self.target, now),
                    )

                grouped: Dict[str, List[Dict]] = {}
                for row in cursor.fetchall():
                    dtype = row['data_type']
                    entry = {
                        'value': row['data_value'],
                        'source': row['source'],
                        'cached_at': row['created_at'],
                        'expires_at': row['expires_at'],
                    }
                    grouped.setdefault(dtype, []).append(entry)
                return grouped
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Freshness checks
    # ------------------------------------------------------------------

    def is_fresh(self, data_type: str) -> bool:
        """Check if we have non-expired cache for this data type."""
        try:
            db = self._db()
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM recon_cache_v2
                    WHERE target = ? AND data_type = ?
                      AND (expires_at IS NULL OR expires_at > ?)
                    """,
                    (self.target, data_type, now),
                )
                row = cursor.fetchone()
                return (row['cnt'] if row else 0) > 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def clear(self, data_type: Optional[str] = None) -> int:
        """Clear cache entries. If *data_type* is given, only clear that type.

        Returns the number of rows deleted.
        """
        try:
            db = self._db()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                if data_type is not None:
                    cursor.execute(
                        """
                        DELETE FROM recon_cache_v2
                        WHERE target = ? AND data_type = ?
                        """,
                        (self.target, data_type),
                    )
                else:
                    cursor.execute(
                        "DELETE FROM recon_cache_v2 WHERE target = ?",
                        (self.target,),
                    )
                return cursor.rowcount
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Summaries
    # ------------------------------------------------------------------

    def summary(self) -> Dict:
        """Returns a dict mapping each data_type to its cached item count
        (non-expired only).
        """
        try:
            db = self._db()
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT data_type, COUNT(*) AS cnt
                    FROM recon_cache_v2
                    WHERE target = ?
                      AND (expires_at IS NULL OR expires_at > ?)
                    GROUP BY data_type
                    """,
                    (self.target, now),
                )
                return {row['data_type']: row['cnt'] for row in cursor.fetchall()}
        except Exception:
            return {}

    @staticmethod
    def get_cached_targets() -> List[Dict]:
        """List all targets with cached recon data and freshness info.

        Returns a list of dicts:
            ``target``, ``total_items``, ``fresh_items``, ``data_types``,
            ``oldest``, ``newest``.
        """
        try:
            db = BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT
                        target,
                        COUNT(*) AS total_items,
                        SUM(CASE
                            WHEN expires_at IS NULL OR expires_at > ?
                            THEN 1 ELSE 0
                        END) AS fresh_items,
                        GROUP_CONCAT(DISTINCT data_type) AS data_types,
                        MIN(created_at) AS oldest,
                        MAX(created_at) AS newest
                    FROM recon_cache_v2
                    GROUP BY target
                    ORDER BY newest DESC
                    """,
                    (now,),
                )
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'target': row['target'],
                        'total_items': row['total_items'],
                        'fresh_items': row['fresh_items'],
                        'data_types': (
                            row['data_types'].split(',')
                            if row['data_types']
                            else []
                        ),
                        'oldest': row['oldest'],
                        'newest': row['newest'],
                    })
                return results
        except Exception:
            return []
