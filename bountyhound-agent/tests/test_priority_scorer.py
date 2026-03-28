"""
Unit tests for engine.scoring.priority_scorer

Coverage
--------
- test_auth_endpoint_gets_high_severity
- test_skip_tier_for_low_score
- test_novelty_drops_for_known_pattern
- test_score_many_sorted
- test_invalid_url_skipped
"""

import pytest

from engine.scoring import EndpointScore, PriorityScorer, score_endpoints


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def scorer_no_disclosed():
    """PriorityScorer with no known disclosed patterns."""
    return PriorityScorer(disclosed_patterns=None)


@pytest.fixture()
def scorer_with_disclosed():
    """PriorityScorer pre-loaded with a set of disclosed patterns."""
    return PriorityScorer(
        disclosed_patterns=[
            "/api/user",
            "/account/reset",
            "/admin/dashboard",
        ]
    )


# ---------------------------------------------------------------------------
# 1. Authentication endpoints should receive very high severity
# ---------------------------------------------------------------------------

class TestSeverityScoring:
    def test_auth_endpoint_gets_high_severity(self, scorer_no_disclosed):
        """
        /api/login contains the '/login' auth pattern.
        Severity must be >= 0.9 (rule assigns 0.95).
        """
        result = scorer_no_disclosed.score("https://example.com/api/login", "POST")

        assert isinstance(result, EndpointScore)
        assert result.severity_potential >= 0.9, (
            f"Expected severity >= 0.9 for /api/login, got {result.severity_potential}"
        )
        assert "login" in result.severity_reason.lower() or "auth" in result.severity_reason.lower()

    def test_admin_endpoint_severity(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/admin/users")
        assert result.severity_potential == 0.85

    def test_upload_endpoint_severity(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/api/upload")
        assert result.severity_potential == 0.80

    def test_api_with_id_severity(self, scorer_no_disclosed):
        """Numeric ID in an /api/ path should score 0.70."""
        result = scorer_no_disclosed.score("https://example.com/api/users/42")
        assert result.severity_potential == 0.70

    def test_api_with_uuid_severity(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score(
            "https://example.com/api/orders/550e8400-e29b-41d4-a716-446655440000"
        )
        assert result.severity_potential == 0.70

    def test_api_with_template_id_severity(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/api/items/{item_id}")
        assert result.severity_potential == 0.70

    def test_search_endpoint_severity(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/search")
        assert result.severity_potential == 0.50

    def test_default_severity_for_static(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/static/logo.png")
        assert result.severity_potential == 0.30


# ---------------------------------------------------------------------------
# 2. Static / benign endpoints should land in the "skip" tier
# ---------------------------------------------------------------------------

class TestTierAssignment:
    def test_skip_tier_for_low_score(self, scorer_no_disclosed):
        """
        A static asset URL has low severity (0.30) and full novelty (1.0 with
        no disclosed patterns).  Composite = (0.30×0.6) + (1.0×0.4) = 0.58,
        which lands in the 'medium' tier.

        To force a genuine 'skip' we use a scorer that already knows the
        pattern (novelty 0.10), giving composite = (0.30×0.6) + (0.10×0.4)
        = 0.18 + 0.04 = 0.22.
        """
        scorer = PriorityScorer(disclosed_patterns=["/static/logo.png"])
        result = scorer.score("https://cdn.example.com/static/logo.png")
        assert result.tier == "skip", (
            f"Expected 'skip' tier, got '{result.tier}' "
            f"(composite={result.composite_score})"
        )
        assert result.composite_score < 0.55

    def test_critical_tier_for_auth(self, scorer_no_disclosed):
        """
        Auth endpoint with no disclosed patterns:
        composite = (0.95 × 0.6) + (1.0 × 0.4) = 0.57 + 0.40 = 0.97 → critical
        """
        result = scorer_no_disclosed.score("https://example.com/login")
        assert result.tier == "critical"

    def test_high_tier_composite(self, scorer_no_disclosed):
        """
        Search endpoint (severity 0.50) with no disclosed patterns:
        composite = (0.50 × 0.6) + (1.0 × 0.4) = 0.30 + 0.40 = 0.70 → high
        """
        result = scorer_no_disclosed.score("https://example.com/search")
        assert result.tier == "high"

    def test_medium_tier_composite(self):
        """
        Static asset known to scorer  (novelty 0.10), severity 0.30:
        composite = 0.18 + 0.04 = 0.22 → skip.

        For 'medium' we use a partially-known API-id endpoint.
        /api/items/42 → severity 0.70, novelty 0.50 (similar to /api/items)
        composite = (0.70 × 0.6) + (0.50 × 0.4) = 0.42 + 0.20 = 0.62 → medium
        """
        scorer = PriorityScorer(disclosed_patterns=["/api/items"])
        result = scorer.score("https://example.com/api/items/42")
        assert result.tier == "medium", (
            f"Expected 'medium', got '{result.tier}' "
            f"(composite={result.composite_score})"
        )


# ---------------------------------------------------------------------------
# 3. Novelty drops when path matches a disclosed pattern
# ---------------------------------------------------------------------------

class TestNoveltyScoring:
    def test_novelty_drops_for_known_pattern(self, scorer_with_disclosed):
        """
        /api/user is in the disclosed list — novelty must be 0.10.
        """
        result = scorer_with_disclosed.score("https://example.com/api/user", "GET")

        assert result.novelty_score == 0.10, (
            f"Expected novelty 0.10 for exact disclosed match, got {result.novelty_score}"
        )
        assert "exact match" in result.novelty_reason.lower() or "disclosed" in result.novelty_reason.lower()

    def test_novelty_is_full_for_unknown(self, scorer_with_disclosed):
        result = scorer_with_disclosed.score("https://example.com/api/payments/webhook")
        assert result.novelty_score == 1.0

    def test_novelty_is_partial_for_similar(self, scorer_with_disclosed):
        """
        /admin/dashboard/settings shares significant tokens with the disclosed
        /admin/dashboard — expect novelty 0.50.
        """
        result = scorer_with_disclosed.score(
            "https://example.com/admin/dashboard/settings"
        )
        assert result.novelty_score == 0.50, (
            f"Expected 0.50 for similar path, got {result.novelty_score}"
        )

    def test_novelty_full_when_no_disclosed(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/anything")
        assert result.novelty_score == 1.0

    def test_novelty_full_for_empty_disclosed_list(self):
        scorer = PriorityScorer(disclosed_patterns=[])
        result = scorer.score("https://example.com/api/user")
        assert result.novelty_score == 1.0


# ---------------------------------------------------------------------------
# 4. score_many / score_endpoints returns results sorted descending
# ---------------------------------------------------------------------------

class TestScoreMany:
    def test_score_many_sorted(self, scorer_no_disclosed):
        """
        score_many must return results sorted by composite_score descending.
        """
        endpoints = [
            {"url": "https://example.com/static/style.css", "method": "GET"},
            {"url": "https://example.com/login",             "method": "POST"},
            {"url": "https://example.com/search",            "method": "GET"},
            {"url": "https://example.com/admin/panel",       "method": "GET"},
            {"url": "https://example.com/api/users/99",      "method": "DELETE"},
        ]
        results = scorer_no_disclosed.score_many(endpoints)

        scores = [r.composite_score for r in results]
        assert scores == sorted(scores, reverse=True), (
            f"Results not sorted descending: {scores}"
        )

    def test_score_endpoints_convenience(self):
        """Module-level score_endpoints should behave identically to PriorityScorer.score_many."""
        endpoints = [
            {"url": "https://example.com/upload", "method": "POST"},
            {"url": "https://example.com/about",  "method": "GET"},
        ]
        results = score_endpoints(endpoints)
        scores = [r.composite_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_score_many_returns_endpoint_score_instances(self, scorer_no_disclosed):
        endpoints = [{"url": "https://example.com/api/users", "method": "GET"}]
        results = scorer_no_disclosed.score_many(endpoints)
        assert len(results) == 1
        assert isinstance(results[0], EndpointScore)

    def test_score_many_empty_list(self, scorer_no_disclosed):
        results = scorer_no_disclosed.score_many([])
        assert results == []


# ---------------------------------------------------------------------------
# 5. Invalid / empty URLs are skipped gracefully
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_invalid_url_skipped(self, scorer_no_disclosed):
        """
        Empty string, None, and non-string values should be excluded from
        score_many results without raising an exception.
        """
        endpoints = [
            {"url": "",    "method": "GET"},           # empty string
            {"url": None,  "method": "GET"},           # None
            {"url": 12345, "method": "GET"},           # non-string
            {"method": "GET"},                         # missing key entirely
            {"url": "https://example.com/api/login"},  # valid — should be included
        ]
        results = scorer_no_disclosed.score_many(endpoints)

        assert len(results) == 1, (
            f"Expected 1 valid result, got {len(results)}: {results}"
        )
        assert "login" in results[0].url

    def test_whitespace_only_url_skipped(self, scorer_no_disclosed):
        endpoints = [
            {"url": "   ", "method": "GET"},
            {"url": "https://example.com/reset"},
        ]
        results = scorer_no_disclosed.score_many(endpoints)
        assert len(results) == 1

    def test_score_endpoints_with_invalid_entries(self):
        endpoints = [
            {"url": None},
            {"url": "https://example.com/admin"},
        ]
        results = score_endpoints(endpoints)
        assert len(results) == 1
        assert results[0].severity_potential == 0.85

    def test_method_defaults_to_get(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/api/items")
        assert result.method == "GET"

    def test_method_uppercased(self, scorer_no_disclosed):
        result = scorer_no_disclosed.score("https://example.com/api/items", "post")
        assert result.method == "POST"


# ---------------------------------------------------------------------------
# 6. Normalisation behaviour
# ---------------------------------------------------------------------------

class TestNormalisation:
    def test_trailing_slash_stripped(self, scorer_no_disclosed):
        """Trailing slash on path should not affect scoring."""
        r1 = scorer_no_disclosed.score("https://example.com/login")
        r2 = scorer_no_disclosed.score("https://example.com/login/")
        assert r1.severity_potential == r2.severity_potential
        assert r1.novelty_score == r2.novelty_score

    def test_path_case_insensitive(self, scorer_no_disclosed):
        """Path matching is case-insensitive."""
        r1 = scorer_no_disclosed.score("https://example.com/Login")
        r2 = scorer_no_disclosed.score("https://example.com/login")
        assert r1.severity_potential == r2.severity_potential

    def test_composite_score_formula(self, scorer_no_disclosed):
        """
        Verify composite = (severity × 0.6) + (novelty × 0.4) within
        floating-point tolerance.
        """
        result = scorer_no_disclosed.score("https://example.com/login")
        expected = round((result.severity_potential * 0.6) + (result.novelty_score * 0.4), 4)
        assert abs(result.composite_score - expected) < 1e-9
