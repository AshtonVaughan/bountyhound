"""
Tests for engine.intel.changelog_fetcher — ChangelogFetcher.

Covers:
  1. fetch(None) → []
  2. fetch(42)   → []
  3. _is_security_relevant: security keywords are matched
  4. _is_security_relevant: word-boundary false-positive guard ("prefix", "suffix")
  5. GitHub search returning 429 → []
  6. Date filter: changelog section dated 100 days ago is excluded
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
import requests

from engine.intel.changelog_fetcher import ChangelogFetcher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_search_429():
    """Return a Mock response with status_code 429."""
    response = MagicMock()
    response.status_code = 429
    response.ok = False
    return response


def _mock_search_200_empty():
    """Return a Mock GitHub search response with zero results."""
    response = MagicMock()
    response.status_code = 200
    response.ok = True
    response.json.return_value = {"items": []}
    return response


# ---------------------------------------------------------------------------
# Test 1: fetch(None) → []
# ---------------------------------------------------------------------------

class TestFetchNoneReturnsEmpty:
    def test_fetch_none_returns_empty(self):
        """fetch(None) must return [] without raising."""
        fetcher = ChangelogFetcher()
        result = fetcher.fetch(None)
        assert result == []


# ---------------------------------------------------------------------------
# Test 2: fetch(integer) → []
# ---------------------------------------------------------------------------

class TestFetchIntegerReturnsEmpty:
    def test_fetch_integer_returns_empty(self):
        """fetch(42) must return [] without raising (not a string)."""
        fetcher = ChangelogFetcher()
        result = fetcher.fetch(42)
        assert result == []


# ---------------------------------------------------------------------------
# Test 3: _is_security_relevant — positive matches
# ---------------------------------------------------------------------------

class TestIsSecurityRelevantTrue:
    @pytest.mark.parametrize("line", [
        "fix: remote code execution in parser",
        "patch applied for buffer overflow",
        "authentication bypass via crafted token",
        "prevent XSS in template rendering",
        "CSRF protection added to forms",
        "address injection vulnerability",
        "resolve privilege escalation in admin panel",
        "update session handling logic",
        "sanitize user input before rendering",
        "escape HTML entities correctly",
        "CVE-2024-1234 — critical vuln fixed",
        "security hardening of endpoint",
    ])
    def test_is_security_relevant_true(self, line):
        """Lines with known security keywords must be flagged as relevant."""
        assert ChangelogFetcher._is_security_relevant(line) is True


# ---------------------------------------------------------------------------
# Test 4: _is_security_relevant — no false positives (word boundary)
# ---------------------------------------------------------------------------

class TestIsSecurityRelevantNoFalsePositive:
    @pytest.mark.parametrize("line", [
        "prefix changes applied to module names",
        "suffix removed from response headers",
        "refixed layout in dashboard component",    # "refixed" should NOT match "fix"
        "completely unrelated cosmetic change",      # no security keyword at all
        "configuration updated",                     # no keyword
        "update documentation typo",
    ])
    def test_is_security_relevant_no_false_positive(self, line):
        """Lines that merely contain keyword sub-strings without word boundaries must NOT match."""
        # "prefix" — "fix" appears but not at a word boundary from "pre"
        # "suffix" — "fix" appears but not at a word boundary
        # "refixed" — "fix" not isolated at word boundary
        assert ChangelogFetcher._is_security_relevant(line) is False


# ---------------------------------------------------------------------------
# Test 5: GitHub rate limit during search → []
# ---------------------------------------------------------------------------

class TestFetchGithubRateLimit:
    def test_fetch_github_rate_limit(self):
        """
        When the GitHub search API returns HTTP 429, fetch() must return []
        gracefully without raising.
        """
        with patch(
            "engine.intel.changelog_fetcher.requests.get",
            return_value=_mock_search_429(),
        ):
            fetcher = ChangelogFetcher()
            result = fetcher.fetch("shopify")

        assert result == []


# ---------------------------------------------------------------------------
# Test 6: Date filter excludes entries older than 90 days
# ---------------------------------------------------------------------------

class TestDateFilterExcludesOld:
    def test_date_filter_excludes_old(self):
        """
        A changelog section whose header date is 100 days ago must not
        produce any results, even when lines contain security keywords.
        """
        hundred_days_ago = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
        old_changelog = (
            f"## [1.0.0] - {hundred_days_ago}\n"
            "- fix: critical security vulnerability in auth module\n"
            "- patch: XSS escape added to search\n"
        )

        fetcher = ChangelogFetcher()
        # Use internal method directly — no network calls needed
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        lines = fetcher._extract_recent_security_lines(old_changelog, cutoff)

        assert lines == [], (
            f"Expected [] for a 100-day-old section, but got: {lines}"
        )
