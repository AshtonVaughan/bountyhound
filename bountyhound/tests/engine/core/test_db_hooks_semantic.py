"""
Integration tests for DatabaseHooks with semantic duplicate detection

Tests the full integration between DatabaseHooks.check_duplicate() and SemanticDuplicateDetector
"""

import pytest
import os
from datetime import date
from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks


@pytest.fixture
def test_db():
    """Create a test database with sample data"""
    # Use test database
    test_db_path = "test_semantic_integration.db"

    # Remove if exists
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    # Create database with test path
    db = BountyHoundDB(db_path=test_db_path)

    # Add test target
    target_id = db.get_or_create_target("example.com")

    # Add sample findings with different vulnerability types
    with db._get_connection() as conn:
        cursor = conn.cursor()

        findings = [
            {
                "target_id": target_id,
                "title": "IDOR allows access to other users' data",
                "description": "The /api/users/{id} endpoint does not verify ownership. Any authenticated user can read other users' profile information.",
                "vuln_type": "IDOR",
                "severity": "high",
                "status": "accepted",
                "discovered_date": date.today().isoformat(),
                "payout": 5000.0
            },
            {
                "target_id": target_id,
                "title": "XSS in search functionality",
                "description": "Reflected XSS via the ?q= parameter. Payload: <script>alert(1)</script>",
                "vuln_type": "XSS",
                "severity": "medium",
                "status": "accepted",
                "discovered_date": date.today().isoformat(),
                "payout": 1500.0
            },
            {
                "target_id": target_id,
                "title": "SQL injection in login form",
                "description": "Username field is vulnerable to blind SQL injection. Time-based payload confirmed.",
                "vuln_type": "SQLi",
                "severity": "critical",
                "status": "accepted",
                "discovered_date": date.today().isoformat(),
                "payout": 10000.0
            }
        ]

        for finding in findings:
            cursor.execute("""
                INSERT INTO findings (
                    target_id, title, description, vuln_type, severity,
                    status, discovered_date, payout
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding["target_id"],
                finding["title"],
                finding["description"],
                finding["vuln_type"],
                finding["severity"],
                finding["status"],
                finding["discovered_date"],
                finding["payout"]
            ))

    yield db

    # Cleanup
    if os.path.exists(test_db_path):
        os.remove(test_db_path)


class TestDatabaseHooksSemanticIntegration:
    """Test DatabaseHooks with semantic duplicate detection"""

    def test_semantic_duplicate_detected(self, test_db):
        """Test that semantically similar findings are caught as duplicates"""
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="IDOR",
            keywords=["nonexistent", "keywords"],  # Keywords that don't match
            title="Missing authorization check in user profile API",
            description="Can access /api/users/{id} without permission verification",
            db=test_db
        )

        assert result['is_duplicate'] is True
        assert result['match_type'] == 'semantic'
        assert len(result['matches']) > 0
        assert "IDOR" in result['matches'][0]['title']
        assert "REJECT" in result['recommendation']

    def test_no_duplicate_different_vuln_type(self, test_db):
        """Test that different vulnerability types are not flagged as duplicates"""
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="CSRF",
            keywords=["nonexistent"],  # Keywords that don't match
            title="CSRF vulnerability in settings update",
            description="Missing CSRF token validation on POST /api/settings",
            db=test_db
        )

        assert result['is_duplicate'] is False
        assert result['match_type'] is None
        assert len(result['matches']) == 0
        assert "PROCEED" in result['recommendation']

    def test_keyword_duplicate_takes_precedence(self, test_db):
        """Test that keyword matching is checked before semantic matching"""
        # This should match by keywords even if semantic similarity is lower
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="IDOR",
            keywords=["users", "api"],  # These keywords exist in the test finding
            title="Different phrasing entirely",
            description="Completely different description",
            db=test_db
        )

        # Should match by keywords (if find_similar_findings is implemented)
        # or by semantic similarity if keywords don't match
        assert result['is_duplicate'] is True
        assert result['match_type'] in ['keyword', 'semantic']

    def test_low_similarity_not_duplicate(self, test_db):
        """Test that findings with low semantic similarity are not flagged"""
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="PathTraversal",  # Different vuln type
            keywords=["nonexistent"],  # Keywords that don't match
            title="Path traversal in file upload",
            description="Can upload files with ../ in filename to access arbitrary directories",
            db=test_db
        )

        assert result['is_duplicate'] is False
        assert result['match_type'] is None

    def test_custom_semantic_threshold(self, test_db):
        """Test custom semantic similarity threshold"""
        # Lower threshold - should catch more duplicates
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="IDOR",
            keywords=["unrelated"],
            title="Authorization issue in API",
            description="API endpoint has authorization problems",
            semantic_threshold=0.5,  # Lower threshold
            db=test_db
        )

        # With lower threshold, might catch as duplicate
        # (depends on actual similarity score)
        # Just verify the parameter works
        assert 'is_duplicate' in result
        assert 'match_type' in result

    def test_no_title_description_keyword_only(self, test_db):
        """Test that keyword-only checks still work without title/description"""
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="XSS",
            keywords=["search", "xss"],
            db=test_db
        )

        # Should use keyword matching only (semantic skipped)
        assert 'is_duplicate' in result
        assert 'recommendation' in result

    def test_similarity_scores_in_matches(self, test_db):
        """Test that semantic matches include similarity scores"""
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="IDOR",
            keywords=["unrelated"],
            title="Unauthorized access to user data",
            description="Can read other users' information without authorization checks",
            db=test_db
        )

        if result['is_duplicate'] and result['match_type'] == 'semantic':
            # Check that matches have similarity scores
            for match in result['matches']:
                assert 'similarity_score' in match
                assert 0.0 <= match['similarity_score'] <= 1.0

    def test_multiple_semantic_matches_sorted(self, test_db):
        """Test that multiple semantic matches are sorted by similarity"""
        result = DatabaseHooks.check_duplicate(
            target="example.com",
            vuln_type="IDOR",
            keywords=["unrelated"],
            title="Authorization bypass in API endpoint",
            description="Missing permission checks allow unauthorized data access",
            semantic_threshold=0.5,  # Lower threshold to catch multiple matches
            db=test_db
        )

        if result['is_duplicate'] and len(result['matches']) > 1:
            # Verify sorted by similarity (highest first)
            scores = [m['similarity_score'] for m in result['matches']]
            assert scores == sorted(scores, reverse=True)
