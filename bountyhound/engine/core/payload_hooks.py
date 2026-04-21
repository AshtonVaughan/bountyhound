"""
Payload Learning Hooks

Integration points for the automatic payload learning system.
Tools call these hooks to get smart payload recommendations.
"""

from typing import List, Dict, Optional
from datetime import date

from engine.core.payload_learner import PayloadRecommender, PayloadLearner
from engine.core.database import BountyHoundDB


class PayloadHooks:
    """Hooks for payload learning integration."""

    _recommender = None
    _db = None

    @classmethod
    def _get_recommender(cls) -> PayloadRecommender:
        """Get or create recommender instance (singleton)."""
        if cls._recommender is None:
            cls._recommender = PayloadRecommender()
        return cls._recommender

    @classmethod
    def get_recommended_payloads(cls, domain: str, vuln_type: str,
                                limit: int = 5) -> List[Dict]:
        """
        Get recommended payloads for a target and vulnerability type.

        Args:
            domain: Target domain
            vuln_type: Vulnerability type (XSS, SQLi, IDOR, etc.)
            limit: Number of payloads to return

        Returns:
            List of recommended payloads sorted by expected success rate
        """
        recommender = cls._get_recommender()
        return recommender.get_recommendations(domain, vuln_type, limit)

    @classmethod
    def get_payloads_by_type(cls, vuln_type: str, limit: int = 5) -> List[Dict]:
        """
        Get top payloads for a vulnerability type (generic, not target-specific).

        Args:
            vuln_type: Vulnerability type
            limit: Number of payloads to return

        Returns:
            List of top payloads
        """
        recommender = cls._get_recommender()
        learner = recommender.learner

        payloads = learner.get_top_payloads_by_type(vuln_type, limit)
        return [
            {
                'payload': p['payload'],
                'context': p.get('context'),
                'success_count': p['success_count'],
                'notes': p.get('notes')
            }
            for p in payloads
        ]

    @classmethod
    def get_payloads_for_tech_stack(cls, tech_stack: str, vuln_type: Optional[str] = None,
                                   limit: int = 5) -> List[Dict]:
        """
        Get recommended payloads for a specific tech stack.

        Args:
            tech_stack: Technology stack (React, Django, etc.)
            vuln_type: Optional, narrow to specific vulnerability type
            limit: Number of payloads to return

        Returns:
            List of payloads optimized for the tech stack
        """
        recommender = cls._get_recommender()
        learner = recommender.learner

        payloads = learner.get_payloads_for_stack(tech_stack, vuln_type, limit)
        return [
            {
                'payload': p['payload'],
                'vuln_type': p['vuln_type'],
                'context': p.get('context'),
                'success_count': p['success_count'],
                'notes': p.get('notes')
            }
            for p in payloads
        ]

    @classmethod
    def record_payload_success(cls, payload_text: str, vuln_type: str,
                              context: Optional[str] = None,
                              tech_stack: Optional[str] = None,
                              notes: Optional[str] = None):
        """
        Record that a payload was successful (for learning).

        Args:
            payload_text: The payload that worked
            vuln_type: Vulnerability type
            context: Context where it worked (parameter, header, etc.)
            tech_stack: Tech stack it worked against
            notes: Additional notes
        """
        if cls._db is None:
            cls._db = BountyHoundDB.get_instance()

        with cls._db._get_connection() as conn:
            cursor = conn.cursor()

            # Check if payload already exists
            cursor.execute("""
                SELECT id FROM successful_payloads
                WHERE payload = ? AND vuln_type = ?
            """, (payload_text, vuln_type))

            existing = cursor.fetchone()

            if existing:
                # Update existing
                cursor.execute("""
                    UPDATE successful_payloads
                    SET success_count = success_count + 1,
                        last_used = ?,
                        context = COALESCE(?, context),
                        tech_stack = COALESCE(?, tech_stack),
                        notes = COALESCE(?, notes)
                    WHERE id = ?
                """, (date.today().isoformat(), context, tech_stack, notes, existing['id']))
            else:
                # Insert new
                cursor.execute("""
                    INSERT INTO successful_payloads
                    (vuln_type, payload, context, tech_stack, success_count, last_used, notes)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                """, (vuln_type, payload_text, context, tech_stack,
                      date.today().isoformat(), notes))

    @classmethod
    def get_success_rate(cls, vuln_type: str, tech_stack: Optional[str] = None) -> float:
        """
        Get success rate for a vulnerability type.

        Args:
            vuln_type: Vulnerability type
            tech_stack: Optional, narrow to specific tech stack

        Returns:
            Success rate as percentage (0-100)
        """
        recommender = cls._get_recommender()
        learner = recommender.learner
        return learner.get_success_rate(vuln_type, tech_stack)

    @classmethod
    def get_trending_payloads(cls, days: int = 30, limit: int = 10) -> List[Dict]:
        """
        Get recently successful payloads (trending).

        Args:
            days: How many days back to look
            limit: Number of payloads to return

        Returns:
            List of trending payloads
        """
        recommender = cls._get_recommender()
        learner = recommender.learner

        payloads = learner.get_trending_payloads(days, limit)
        return [
            {
                'payload': p['payload'],
                'vuln_type': p['vuln_type'],
                'success_count': p['success_count'],
                'tech_stack': p.get('tech_stack'),
                'context': p.get('context')
            }
            for p in payloads
        ]

    @classmethod
    def reset(cls):
        """Reset singleton instances (for testing)."""
        cls._recommender = None
        cls._db = None


def get_payloads_for_test(domain: str, vuln_type: str, tech_stack: Optional[str] = None,
                         limit: int = 5) -> List[Dict]:
    """
    Convenience function: Get smart payload recommendations for a test.

    This is the main entry point tools should use.

    Args:
        domain: Target domain
        vuln_type: Vulnerability type to test
        tech_stack: Target tech stack (optional, will be looked up if not provided)
        limit: Number of payloads to recommend

    Returns:
        List of recommended payloads
    """
    recommender = PayloadHooks._get_recommender()

    # If tech stack not provided, try to get it from database
    if not tech_stack:
        tech_stack = recommender.get_target_tech_stack(domain)

    return PayloadHooks.get_recommended_payloads(domain, vuln_type, limit)
