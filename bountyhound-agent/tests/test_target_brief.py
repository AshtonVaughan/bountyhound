"""
Tests for engine.intel.target_brief — TargetBrief dataclass and TargetBriefBuilder.

Covers:
  1. build_pre_recon with no fetchers available → valid empty TargetBrief
  2. Cache roundtrip — save + load → all fields preserved
  3. TTL: brief 1 hour old is fresh
  4. TTL: brief 25 hours old is stale
  5. build_pre_recon uses cache when fresh (fetchers not called)
  6. _generate_summary with anthropic_client=None → non-empty string
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from engine.intel.target_brief import TargetBrief, TargetBriefBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_brief(
    program_handle: str = "acme",
    generated_at: str | None = None,
    cached: bool = False,
) -> TargetBrief:
    """Return a minimal TargetBrief for use in tests."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()
    return TargetBrief(
        program_handle=program_handle,
        disclosed_vulns=[{"title": "XSS", "cwe": "CWE-79", "endpoint": "/search", "bounty": 500, "date": "2025-01-01"}],
        known_cves=[{"id": "CVE-2024-1234", "description": "RCE", "cvss": 9.8, "affected": "lib:1.0"}],
        recent_changes=["fix: patch authentication bypass"],
        summary="Test summary content.",
        cached=cached,
        generated_at=generated_at,
    )


def _builder_with_tmp_cache(tmp_path: Path, program_handle: str = "acme") -> TargetBriefBuilder:
    """
    Create a TargetBriefBuilder whose CACHE_DIR is redirected to tmp_path.
    """
    builder = TargetBriefBuilder(program_handle=program_handle)
    builder.CACHE_DIR = tmp_path / ".bountyhound" / "intel"
    builder.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return builder


# ---------------------------------------------------------------------------
# Test 1: build_pre_recon with no fetchers available
# ---------------------------------------------------------------------------

class TestBuildPreReconEmptyFetchers:
    def test_build_pre_recon_empty_fetchers(self, tmp_path):
        """
        When HAS_H1, HAS_CHANGELOG are False, build_pre_recon() must still
        return a valid TargetBrief whose lists are empty and summary non-empty.
        """
        builder = _builder_with_tmp_cache(tmp_path, "shopify")

        with (
            patch("engine.intel.target_brief.HAS_H1", False),
            patch("engine.intel.target_brief.HAS_CHANGELOG", False),
            patch("engine.intel.target_brief.HAS_CVE", False),
        ):
            brief = builder.build_pre_recon()

        assert isinstance(brief, TargetBrief)
        assert brief.program_handle == "shopify"
        assert brief.disclosed_vulns == []
        assert brief.known_cves == []
        assert brief.recent_changes == []
        assert isinstance(brief.summary, str)
        assert len(brief.summary) > 0
        assert brief.cached is False


# ---------------------------------------------------------------------------
# Test 2: Cache roundtrip
# ---------------------------------------------------------------------------

class TestCacheRoundtrip:
    def test_cache_roundtrip(self, tmp_path):
        """
        _save_cache then _load_cache must reproduce all TargetBrief fields exactly.
        """
        builder = _builder_with_tmp_cache(tmp_path, "acme")
        original = _make_brief(program_handle="acme")

        builder._save_cache(original)
        loaded = builder._load_cache()

        assert loaded is not None
        assert loaded.program_handle == original.program_handle
        assert loaded.disclosed_vulns == original.disclosed_vulns
        assert loaded.known_cves == original.known_cves
        assert loaded.recent_changes == original.recent_changes
        assert loaded.summary == original.summary
        assert loaded.generated_at == original.generated_at
        # loaded always has cached=True (set by _load_cache)
        assert loaded.cached is True


# ---------------------------------------------------------------------------
# Test 3: TTL — fresh brief
# ---------------------------------------------------------------------------

class TestCacheTTLFresh:
    def test_cache_ttl_fresh(self, tmp_path):
        """A brief generated 1 hour ago must be considered fresh (< 24h TTL)."""
        builder = _builder_with_tmp_cache(tmp_path, "acme")
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        brief = _make_brief(generated_at=one_hour_ago)

        assert builder._is_fresh(brief) is True


# ---------------------------------------------------------------------------
# Test 4: TTL — stale brief
# ---------------------------------------------------------------------------

class TestCacheTTLStale:
    def test_cache_ttl_stale(self, tmp_path):
        """A brief generated 25 hours ago must be considered stale (> 24h TTL)."""
        builder = _builder_with_tmp_cache(tmp_path, "acme")
        twenty_five_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        brief = _make_brief(generated_at=twenty_five_hours_ago)

        assert builder._is_fresh(brief) is False


# ---------------------------------------------------------------------------
# Test 5: build_pre_recon uses cache when fresh
# ---------------------------------------------------------------------------

class TestBuildPreReconUsesCache:
    def test_build_pre_recon_uses_cache(self, tmp_path):
        """
        When a fresh brief is in the cache, build_pre_recon() must return it
        without calling H1Fetcher or ChangelogFetcher.
        """
        builder = _builder_with_tmp_cache(tmp_path, "shopify")

        # Persist a fresh brief to the builder's cache directory
        fresh_brief = _make_brief(
            program_handle="shopify",
            generated_at=datetime.now(timezone.utc).isoformat(),
            cached=False,
        )
        builder._save_cache(fresh_brief)

        h1_mock = MagicMock()
        changelog_mock = MagicMock()

        with (
            patch("engine.intel.target_brief.HAS_H1", True),
            patch("engine.intel.target_brief.HAS_CHANGELOG", True),
            patch("engine.intel.target_brief.H1Fetcher", return_value=h1_mock),
            patch("engine.intel.target_brief.ChangelogFetcher", return_value=changelog_mock),
        ):
            result = builder.build_pre_recon()

        # Fetchers must NOT have been called
        h1_mock.fetch.assert_not_called()
        changelog_mock.fetch.assert_not_called()

        # Returned brief must carry the cached data
        assert result.cached is True
        assert result.program_handle == "shopify"
        assert result.summary == fresh_brief.summary


# ---------------------------------------------------------------------------
# Test 6: _generate_summary with anthropic_client=None
# ---------------------------------------------------------------------------

class TestGenerateSummaryNoClient:
    def test_generate_summary_no_client(self, tmp_path):
        """
        With anthropic_client=None, _generate_summary() must return a
        non-empty string (the plain-text fallback).
        """
        builder = _builder_with_tmp_cache(tmp_path, "acme")
        # anthropic_client defaults to None
        brief = _make_brief()

        summary = builder._generate_summary(brief)

        assert isinstance(summary, str)
        assert len(summary.strip()) > 0
        # The fallback summary includes the program handle
        assert "acme" in summary
