"""
Tests for semantic duplicate detection

TDD tests for catching duplicates via semantic similarity instead of just keywords.
"""

import pytest
from engine.core.semantic_dedup import SemanticDuplicateDetector


class TestSemanticSimilarity:
    """Test semantic similarity computation"""

    def test_semantic_similarity_high(self):
        """Test that semantically similar findings are detected as duplicates"""
        detector = SemanticDuplicateDetector()

        finding1 = {
            "title": "IDOR allows unauthorized access to user data",
            "description": "The /api/users/{id} endpoint does not verify ownership"
        }

        finding2 = {
            "title": "Missing authorization check in user profile endpoint",
            "description": "Any authenticated user can access /api/users/{id} without permission check"
        }

        similarity = detector.compute_similarity(finding1, finding2)
        assert similarity > 0.8, f"Expected high similarity (>0.8), got {similarity}"

    def test_semantic_similarity_low(self):
        """Test that different findings are not flagged as duplicates"""
        detector = SemanticDuplicateDetector()

        finding1 = {
            "title": "XSS in search parameter",
            "description": "Reflected XSS via ?q= parameter"
        }

        finding2 = {
            "title": "SQL injection in login form",
            "description": "Username field vulnerable to SQLi"
        }

        similarity = detector.compute_similarity(finding1, finding2)
        assert similarity < 0.3, f"Expected low similarity (<0.3), got {similarity}"

    def test_find_duplicates_in_database(self):
        """Test finding duplicates against existing database entries"""
        detector = SemanticDuplicateDetector()

        new_finding = {
            "title": "Authorization bypass in user API",
            "description": "Can access other users' data via /api/users endpoint"
        }

        existing_findings = [
            {"title": "IDOR in user endpoint", "description": "Missing auth check allows data access"},
            {"title": "XSS in comments", "description": "Reflected XSS vulnerability"}
        ]

        duplicates = detector.find_duplicates(new_finding, existing_findings, threshold=0.75)
        assert len(duplicates) == 1
        assert duplicates[0]["title"] == "IDOR in user endpoint"

    def test_empty_findings(self):
        """Test handling of empty findings"""
        detector = SemanticDuplicateDetector()

        finding1 = {"title": "", "description": ""}
        finding2 = {"title": "XSS", "description": "Test"}

        similarity = detector.compute_similarity(finding1, finding2)
        assert similarity == 0.0

    def test_identical_findings(self):
        """Test that identical findings have perfect similarity"""
        detector = SemanticDuplicateDetector()

        finding = {
            "title": "SQL Injection in login form",
            "description": "Username parameter is vulnerable to SQLi"
        }

        similarity = detector.compute_similarity(finding, finding)
        assert similarity > 0.99, f"Expected near-perfect similarity (>0.99), got {similarity}"

    def test_find_duplicates_no_matches(self):
        """Test finding duplicates when there are no matches"""
        detector = SemanticDuplicateDetector()

        new_finding = {
            "title": "XSS in search",
            "description": "Reflected XSS vulnerability"
        }

        existing_findings = [
            {"title": "SQL injection", "description": "SQLi in login"},
            {"title": "IDOR in API", "description": "Missing authorization"}
        ]

        duplicates = detector.find_duplicates(new_finding, existing_findings, threshold=0.75)
        assert len(duplicates) == 0

    def test_find_duplicates_sorted_by_similarity(self):
        """Test that duplicates are sorted by similarity score (highest first)"""
        detector = SemanticDuplicateDetector()

        new_finding = {
            "title": "IDOR in user API",
            "description": "Can access other users' data"
        }

        existing_findings = [
            {"title": "Authorization issue", "description": "User API has auth problems"},  # Medium match
            {"title": "IDOR allows unauthorized access", "description": "User data can be accessed without permission"},  # High match
            {"title": "Missing auth check", "description": "API endpoint lacks verification"}  # Lower match
        ]

        duplicates = detector.find_duplicates(new_finding, existing_findings, threshold=0.5)

        # Should be sorted by similarity (highest first)
        assert len(duplicates) >= 2
        for i in range(len(duplicates) - 1):
            assert duplicates[i]["similarity_score"] >= duplicates[i + 1]["similarity_score"]

    def test_vuln_term_boosting(self):
        """Test that vulnerability-specific terms get appropriate weight"""
        detector = SemanticDuplicateDetector()

        # Both have "idor" - should be weighted more heavily
        finding1 = {
            "title": "IDOR vulnerability in API",
            "description": "Can access resources without authorization"
        }

        finding2 = {
            "title": "IDOR issue in endpoint",
            "description": "Missing permission checks"
        }

        # Compare to generic similarity
        finding3 = {
            "title": "Issue in API",
            "description": "Can access resources"
        }

        finding4 = {
            "title": "Problem in endpoint",
            "description": "Missing checks"
        }

        vuln_similarity = detector.compute_similarity(finding1, finding2)
        generic_similarity = detector.compute_similarity(finding3, finding4)

        # Vulnerability-specific terms should produce higher similarity
        assert vuln_similarity > generic_similarity
