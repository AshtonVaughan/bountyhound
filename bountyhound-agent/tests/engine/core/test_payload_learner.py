"""
Tests for Automatic Payload Learning System

Tests PayloadLearner, PayloadScorer, and PayloadRecommender classes.
"""

import pytest
from datetime import date, datetime, timedelta
from pathlib import Path
import tempfile
import sqlite3

from engine.core.payload_learner import PayloadLearner, PayloadScorer, PayloadRecommender
from engine.core.payload_hooks import PayloadHooks, get_payloads_for_test
from engine.core.database import BountyHoundDB


@pytest.fixture
def temp_db():
    """Create temporary test database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = BountyHoundDB(str(db_path))

        # Add test payloads
        with db._get_connection() as conn:
            cursor = conn.cursor()

            # XSS payloads
            cursor.execute("""
                INSERT INTO successful_payloads
                (vuln_type, payload, context, tech_stack, success_count, last_used, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('XSS', '"><script>alert(1)</script>', 'parameter', 'React',
                  10, date.today().isoformat(), 'Works on React apps'))

            cursor.execute("""
                INSERT INTO successful_payloads
                (vuln_type, payload, context, tech_stack, success_count, last_used, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('XSS', 'onclick="alert(1)"', 'attribute', 'Generic',
                  5, (date.today() - timedelta(days=15)).isoformat(), 'Works on older sites'))

            # SQL Injection payloads
            cursor.execute("""
                INSERT INTO successful_payloads
                (vuln_type, payload, context, tech_stack, success_count, last_used, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('SQLi', "' OR '1'='1", 'parameter', 'PHP',
                  8, date.today().isoformat(), 'Classic SQLi bypass'))

            cursor.execute("""
                INSERT INTO successful_payloads
                (vuln_type, payload, context, tech_stack, success_count, last_used, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('SQLi', '"; DROP TABLE users; --', 'parameter', 'Django',
                  3, (date.today() - timedelta(days=60)).isoformat(), 'Destructive SQLi'))

            # IDOR payloads
            cursor.execute("""
                INSERT INTO successful_payloads
                (vuln_type, payload, context, tech_stack, success_count, last_used, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('IDOR', 'id=999&user_id=1', 'parameter', 'Generic',
                  15, date.today().isoformat(), 'User ID bypass'))

        yield db


class TestPayloadLearner:
    """Test PayloadLearner class."""

    def test_load_payloads(self, temp_db):
        """Test loading payloads from database."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        assert len(learner.payloads) == 5
        assert len(learner.patterns) == 3  # XSS, SQLi, IDOR

    def test_get_success_rate_by_type(self, temp_db):
        """Test success rate calculation by vulnerability type."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        # IDOR should have high success rate (1 payload with 15 successes)
        idor_rate = learner.get_success_rate('IDOR')
        assert idor_rate > 0

        # XSS should have moderate rate
        xss_rate = learner.get_success_rate('XSS')
        assert xss_rate > 0

    def test_get_top_payloads_by_type(self, temp_db):
        """Test getting top payloads for a type."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        xss_payloads = learner.get_top_payloads_by_type('XSS', limit=2)
        assert len(xss_payloads) <= 2
        assert xss_payloads[0]['success_count'] >= xss_payloads[1]['success_count']

    def test_get_payloads_for_stack(self, temp_db):
        """Test getting payloads for specific tech stack."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        react_payloads = learner.get_payloads_for_stack('React')
        assert len(react_payloads) > 0
        assert any(p['tech_stack'] == 'React' for p in react_payloads)

    def test_get_trending_payloads(self, temp_db):
        """Test getting recently successful payloads."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        # Get trending from last 30 days
        trending = learner.get_trending_payloads(days=30, limit=10)
        assert len(trending) > 0
        # Should include recent payloads
        assert any(p['vuln_type'] == 'XSS' for p in trending)

    def test_analyze_vuln_type_stats(self, temp_db):
        """Test vulnerability type statistics."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        stats = learner.analyze_vuln_type_stats()
        assert len(stats) == 3
        assert 'XSS' in stats
        assert stats['XSS']['payload_count'] == 2
        assert stats['XSS']['total_successes'] == 15


class TestPayloadScorer:
    """Test PayloadScorer class."""

    def test_score_exact_type_match(self, temp_db):
        """Test scoring with exact vulnerability type match."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        scorer = PayloadScorer(learner)

        # Get an XSS payload
        xss_payload = next(p for p in learner.payloads if p['vuln_type'] == 'XSS')
        score = scorer.score_payload(xss_payload, 'XSS', tech_stack=None)

        assert score >= 40  # Should get points for type match

    def test_score_stack_match(self, temp_db):
        """Test scoring with tech stack match."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        scorer = PayloadScorer(learner)

        # Get a React XSS payload
        react_payload = next(p for p in learner.payloads if p['vuln_type'] == 'XSS' and p['tech_stack'] == 'React')
        score = scorer.score_payload(react_payload, 'XSS', tech_stack='React')

        assert score > 40  # Should include type + stack match

    def test_score_success_count(self, temp_db):
        """Test that payloads with higher success count score higher."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        scorer = PayloadScorer(learner)

        # IDOR payload has 15 successes
        idor_payload = [p for p in learner.payloads if p['vuln_type'] == 'IDOR'][0]
        # XSS payload has 10 successes
        xss_payload = learner.payloads[0]

        idor_score = scorer.score_payload(idor_payload, 'IDOR')
        xss_score = scorer.score_payload(xss_payload, 'XSS')

        # IDOR should score higher due to success count
        assert idor_score >= xss_score

    def test_rank_payloads(self, temp_db):
        """Test ranking payloads by score."""
        learner = PayloadLearner()
        learner.db = temp_db
        learner.load_payloads()

        scorer = PayloadScorer(learner)

        ranked = scorer.rank_payloads('XSS', limit=5)
        assert len(ranked) > 0
        assert ranked[0][1] >= ranked[1][1]  # Scores should be descending


class TestPayloadRecommender:
    """Test PayloadRecommender class."""

    def test_get_recommendations(self, temp_db):
        """Test getting recommendations for a target."""
        recommender = PayloadRecommender(db=temp_db)

        # Add a target
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (domain, added_date)
                VALUES (?, ?)
            """, ('example.com', date.today().isoformat()))

        recs = recommender.get_recommendations('example.com', 'XSS', limit=3)
        assert len(recs) > 0
        assert all(r['vuln_type'] == 'XSS' for r in recs)

    def test_recommendation_scoring(self, temp_db):
        """Test that recommendations are properly scored."""
        recommender = PayloadRecommender(db=temp_db)

        # Add a target with React tech stack
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (domain, added_date)
                VALUES (?, ?)
            """, ('react.example.com', date.today().isoformat()))

            target_id = cursor.lastrowid

            # Add recon data for tech stack
            cursor.execute("""
                INSERT INTO recon_data (target_id, data_type, data_value, source, discovered_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target_id, 'tech_stack', 'React', 'manual', date.today().isoformat()))

        recs = recommender.get_recommendations('react.example.com', 'XSS')
        assert len(recs) > 0
        # React XSS payload should be highly scored
        assert recs[0]['score'] >= 50

    def test_record_payload_usage(self, temp_db):
        """Test recording payload usage."""
        recommender = PayloadRecommender(db=temp_db)

        # Get a payload ID
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM successful_payloads LIMIT 1")
            payload_id = cursor.fetchone()['id']

            # Get old success count
            cursor.execute("SELECT success_count FROM successful_payloads WHERE id = ?", (payload_id,))
            old_count = cursor.fetchone()['success_count']

        # Record usage
        recommender.record_payload_usage(payload_id, successful=True)

        # Check new count
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT success_count, last_used FROM successful_payloads WHERE id = ?", (payload_id,))
            row = cursor.fetchone()
            assert row['success_count'] == old_count + 1
            assert row['last_used'] == date.today().isoformat()


class TestPayloadHooks:
    """Test PayloadHooks integration."""

    def test_get_recommended_payloads(self, temp_db):
        """Test hook for getting recommended payloads."""
        PayloadHooks.reset()
        recommender = PayloadRecommender(db=temp_db)
        PayloadHooks._recommender = recommender

        # Add target
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (domain, added_date)
                VALUES (?, ?)
            """, ('test.com', date.today().isoformat()))

        recs = PayloadHooks.get_recommended_payloads('test.com', 'XSS', limit=3)
        assert len(recs) > 0
        assert all(isinstance(r, dict) for r in recs)

    def test_get_payloads_by_type(self, temp_db):
        """Test hook for getting payloads by type."""
        PayloadHooks.reset()
        recommender = PayloadRecommender(db=temp_db)
        PayloadHooks._recommender = recommender

        payloads = PayloadHooks.get_payloads_by_type('XSS', limit=5)
        assert len(payloads) > 0

    def test_record_payload_success(self, temp_db):
        """Test recording successful payload usage."""
        PayloadHooks.reset()
        PayloadHooks._db = temp_db

        # Record a new payload
        PayloadHooks.record_payload_success(
            'new_payload"<script>',
            'XSS',
            context='parameter',
            tech_stack='Node',
            notes='Found in user input'
        )

        # Verify it was recorded
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM successful_payloads WHERE payload = ? AND vuln_type = ?
            """, ('new_payload"<script>', 'XSS'))
            assert cursor.fetchone() is not None

    def test_get_payloads_for_test_convenience(self, temp_db):
        """Test convenience function for getting payloads."""
        PayloadHooks.reset()
        recommender = PayloadRecommender(db=temp_db)
        PayloadHooks._recommender = recommender

        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (domain, added_date)
                VALUES (?, ?)
            """, ('conv.test.com', date.today().isoformat()))

        # Get payloads for a type that exists in test data (XSS)
        payloads = get_payloads_for_test('conv.test.com', 'XSS')
        assert len(payloads) > 0
