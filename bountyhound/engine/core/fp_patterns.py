"""
False Positive Pattern Database - Learn from mistakes, never repeat them.

Maintains a persistent database of known false positive patterns.  Every time
a finding turns out to be a false positive, the pattern is recorded so future
hunts can automatically flag (or skip) the same mistake.

Two tiers of patterns:
  1. BUILTIN_PATTERNS  -- hard-coded, always available, never deleted.
  2. Learned patterns  -- discovered during hunts, stored in the fp_patterns
     SQLite table, can be deleted.

Usage:
    from engine.core.fp_patterns import FalsePositiveDB

    fpdb = FalsePositiveDB()
    result = fpdb.check_finding({
        'title': 'Auth bypass via GraphQL',
        'description': 'HTTP 200 returned with __typename',
        'evidence': '{"data":{"__typename":"User"}}',
        'vuln_type': 'AUTH_BYPASS',
        'severity': 'HIGH',
    })
    if result['is_false_positive']:
        print(f"DROP: {result['matched_patterns'][0]['description']}")
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FalsePositiveDB:
    """Database of known false positive patterns to prevent repeating mistakes."""

    # ---------------------------------------------------------------
    # Built-in patterns (always available, never deleted)
    # ---------------------------------------------------------------
    BUILTIN_PATTERNS: List[Dict[str, Any]] = [
        {
            'name': 'grpc_unimplemented',
            'type': 'protocol_error',
            'description': (
                'gRPC status 12 (UNIMPLEMENTED) is not missing auth - '
                'the method does not exist'
            ),
            'indicators': ['grpc', 'status', '12', 'UNIMPLEMENTED'],
        },
        {
            'name': 'grpc_internal_error',
            'type': 'protocol_error',
            'description': (
                'gRPC status 13 (INTERNAL) is a server error, not an auth bypass'
            ),
            'indicators': ['grpc', 'status', '13', 'INTERNAL'],
        },
        {
            'name': 'graphql_200_not_success',
            'type': 'protocol_error',
            'description': (
                'GraphQL always returns HTTP 200 even for errors. '
                'Check errors[] array.'
            ),
            'indicators': ['graphql', '200', 'errors', '__typename'],
        },
        {
            'name': 'cors_star_no_credentials',
            'type': 'cors',
            'description': (
                'ACAO:* with ACAC:true is blocked by browsers per spec. '
                'Not exploitable.'
            ),
            'indicators': [
                'access-control-allow-origin', '*',
                'access-control-allow-credentials', 'true',
            ],
        },
        {
            'name': 'cors_star_no_acac',
            'type': 'cors',
            'description': (
                'ACAO:* without ACAC means no cookies sent. Only INFO '
                'unless sensitive data in response.'
            ),
            'indicators': ['access-control-allow-origin', '*'],
        },
        {
            'name': 'validation_before_auth',
            'type': 'auth_confusion',
            'description': (
                'HTTP 400 before 401 means input validation runs first, '
                'not missing auth'
            ),
            'indicators': ['400', 'validation', 'invalid', 'required'],
        },
        {
            'name': 'server_version_header',
            'type': 'info_noise',
            'description': (
                'Server version headers are INFO at best, not worth '
                'reporting alone'
            ),
            'indicators': [
                'server:', 'x-powered-by:', 'nginx', 'apache', 'express',
            ],
        },
        {
            'name': 'graphql_typename_only',
            'type': 'data_confusion',
            'description': (
                'Response with only __typename field is not data access'
            ),
            'indicators': ['__typename', 'data', 'null'],
        },
        {
            'name': 'csp_theoretical_chain',
            'type': 'overrated_severity',
            'description': (
                'CSP bypass requiring 5+ steps and specific conditions '
                'is theoretical, not practical'
            ),
            'indicators': [
                'content-security-policy', 'unsafe-inline', 'chain', 'bypass',
            ],
        },
        {
            'name': 'http_500_stack_trace',
            'type': 'info_noise',
            'description': (
                'Stack trace in 500 error is LOW info disclosure, '
                'not a critical vuln'
            ),
            'indicators': ['500', 'stack', 'trace', 'traceback', 'at '],
        },
    ]

    _BUILTIN_NAMES = frozenset(p['name'] for p in BUILTIN_PATTERNS)

    # Minimum fraction of indicators that must match to flag a finding
    _MATCH_THRESHOLD = 0.6

    def __init__(self):
        self._db = None  # Lazy-loaded

    # ---------------------------------------------------------------
    # Database access
    # ---------------------------------------------------------------

    def _get_db(self):
        """Lazy-load the singleton database instance."""
        if self._db is None:
            try:
                from engine.core.database import BountyHoundDB
                self._db = BountyHoundDB.get_instance()
            except Exception as exc:
                logger.warning("Failed to load BountyHoundDB: %s", exc)
        return self._db

    # ---------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------

    def check_finding(self, finding: Dict) -> Dict:
        """
        Check if a finding matches any known false positive patterns.

        Args:
            finding: Dict with keys 'title', 'description', 'evidence',
                     'vuln_type', 'severity'.

        Returns:
            {
                'is_false_positive': bool,
                'matched_patterns': List[Dict],  # name, description, confidence
                'recommendation': str,           # 'report' | 'investigate_more' | 'drop'
            }
        """
        try:
            # Build a single searchable text blob from the finding
            search_text = self._finding_to_text(finding).lower()

            all_patterns = self.get_all_patterns()
            matched: List[Dict] = []

            for pattern in all_patterns:
                indicators = pattern.get('indicators', [])
                if not indicators:
                    continue

                hits = sum(
                    1 for ind in indicators
                    if ind.lower() in search_text
                )
                ratio = hits / len(indicators)

                if ratio >= self._MATCH_THRESHOLD:
                    matched.append({
                        'name': pattern['name'],
                        'description': pattern['description'],
                        'type': pattern.get('type', 'unknown'),
                        'confidence': round(ratio, 2),
                    })
                    # Record the match (non-fatal if DB unavailable)
                    try:
                        self.record_match(pattern['name'])
                    except Exception:
                        pass

            # Sort by confidence descending
            matched.sort(key=lambda m: m['confidence'], reverse=True)

            if not matched:
                return {
                    'is_false_positive': False,
                    'matched_patterns': [],
                    'recommendation': 'report',
                }

            top_confidence = matched[0]['confidence']

            if top_confidence >= 0.9:
                recommendation = 'drop'
            elif top_confidence >= 0.7:
                recommendation = 'investigate_more'
            else:
                recommendation = 'investigate_more'

            return {
                'is_false_positive': top_confidence >= 0.7,
                'matched_patterns': matched,
                'recommendation': recommendation,
            }

        except Exception as exc:
            logger.error("Error checking finding against FP patterns: %s", exc)
            return {
                'is_false_positive': False,
                'matched_patterns': [],
                'recommendation': 'report',
            }

    def learn_pattern(
        self,
        name: str,
        pattern_type: str,
        description: str,
        indicators: List[str],
        target: str = '',
    ) -> None:
        """
        Learn a new false positive pattern from experience.

        Args:
            name:         Short identifier (e.g. 'airbnb_mutation_200_no_effect').
            pattern_type: Category (e.g. 'protocol_error', 'data_confusion').
            description:  Human-readable explanation.
            indicators:   List of strings to match in future findings.
            target:       Target domain where this was learned (optional).
        """
        db = self._get_db()
        if db is None:
            logger.warning("Cannot learn pattern: database unavailable")
            return

        try:
            indicators_json = json.dumps(indicators)
            with db._get_connection() as conn:
                cursor = conn.cursor()

                # Check if pattern with this name already exists
                cursor.execute(
                    "SELECT id FROM fp_patterns WHERE pattern_name = ?",
                    (name,),
                )
                existing = cursor.fetchone()

                if existing:
                    # Update existing pattern
                    cursor.execute(
                        """UPDATE fp_patterns
                           SET pattern_type = ?, description = ?,
                               indicators = ?, target_learned_from = ?,
                               times_matched = times_matched + 1,
                               last_matched = ?
                           WHERE pattern_name = ?""",
                        (
                            pattern_type, description, indicators_json,
                            target, datetime.utcnow().isoformat(), name,
                        ),
                    )
                    logger.info("Updated existing FP pattern: %s", name)
                else:
                    cursor.execute(
                        """INSERT INTO fp_patterns
                           (pattern_name, pattern_type, description, indicators,
                            target_learned_from, times_matched, last_matched, created_at)
                           VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                        (
                            name, pattern_type, description, indicators_json,
                            target, datetime.utcnow().isoformat(),
                            datetime.utcnow().isoformat(),
                        ),
                    )
                    logger.info("Learned new FP pattern: %s", name)

        except Exception as exc:
            logger.error("Failed to learn pattern '%s': %s", name, exc)

    def record_match(self, pattern_name: str) -> None:
        """Record that a pattern was matched (increment times_matched)."""
        db = self._get_db()
        if db is None:
            return

        try:
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """UPDATE fp_patterns
                       SET times_matched = times_matched + 1,
                           last_matched = ?
                       WHERE pattern_name = ?""",
                    (datetime.utcnow().isoformat(), pattern_name),
                )
        except Exception as exc:
            logger.debug("Failed to record match for '%s': %s", pattern_name, exc)

    def get_all_patterns(self) -> List[Dict]:
        """
        Get all patterns (builtin + learned) sorted by times_matched desc.
        """
        patterns: List[Dict] = []

        # Builtin patterns first
        for bp in self.BUILTIN_PATTERNS:
            patterns.append({
                'name': bp['name'],
                'type': bp['type'],
                'description': bp['description'],
                'indicators': list(bp['indicators']),
                'source': 'builtin',
                'target_learned_from': '',
                'times_matched': 0,
                'last_matched': None,
            })

        # Learned patterns from DB
        db = self._get_db()
        if db is not None:
            try:
                with db._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """SELECT pattern_name, pattern_type, description,
                                  indicators, target_learned_from,
                                  times_matched, last_matched
                           FROM fp_patterns
                           ORDER BY times_matched DESC"""
                    )
                    for row in cursor.fetchall():
                        row_dict = dict(row)
                        # Parse indicators JSON
                        try:
                            indicators = json.loads(row_dict.get('indicators', '[]'))
                        except (json.JSONDecodeError, TypeError):
                            indicators = []

                        # Avoid duplicates if a builtin was also stored in DB
                        name = row_dict['pattern_name']
                        if name in self._BUILTIN_NAMES:
                            # Update the builtin entry's match count
                            for p in patterns:
                                if p['name'] == name:
                                    p['times_matched'] = row_dict.get('times_matched', 0)
                                    p['last_matched'] = row_dict.get('last_matched')
                                    break
                            continue

                        patterns.append({
                            'name': name,
                            'type': row_dict.get('pattern_type', 'unknown'),
                            'description': row_dict.get('description', ''),
                            'indicators': indicators,
                            'source': 'learned',
                            'target_learned_from': row_dict.get('target_learned_from', ''),
                            'times_matched': row_dict.get('times_matched', 0),
                            'last_matched': row_dict.get('last_matched'),
                        })
            except Exception as exc:
                logger.warning("Failed to load learned patterns from DB: %s", exc)

        # Sort all by times_matched descending
        patterns.sort(key=lambda p: p.get('times_matched', 0), reverse=True)
        return patterns

    def get_learned_patterns(self) -> List[Dict]:
        """Get only patterns learned from experience (not builtin)."""
        all_patterns = self.get_all_patterns()
        return [p for p in all_patterns if p.get('source') == 'learned']

    def delete_pattern(self, pattern_name: str) -> bool:
        """
        Delete a learned pattern. Cannot delete builtin patterns.

        Returns:
            True if deleted, False if not found or is builtin.
        """
        if pattern_name in self._BUILTIN_NAMES:
            logger.warning("Cannot delete builtin pattern: %s", pattern_name)
            return False

        db = self._get_db()
        if db is None:
            logger.warning("Cannot delete pattern: database unavailable")
            return False

        try:
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM fp_patterns WHERE pattern_name = ?",
                    (pattern_name,),
                )
                deleted = cursor.rowcount > 0

            if deleted:
                logger.info("Deleted FP pattern: %s", pattern_name)
            else:
                logger.info("Pattern not found for deletion: %s", pattern_name)

            return deleted

        except Exception as exc:
            logger.error("Failed to delete pattern '%s': %s", pattern_name, exc)
            return False

    # ---------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _finding_to_text(finding: Dict) -> str:
        """Flatten a finding dict into a single searchable string."""
        parts = []
        for key in ('title', 'description', 'evidence', 'vuln_type', 'severity'):
            val = finding.get(key)
            if val:
                parts.append(str(val))
        return ' '.join(parts)
