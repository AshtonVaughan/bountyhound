"""
Priority Scorer — endpoint selection layer for the Perfect Hunter methodology.

Scores discovered endpoints by severity potential and novelty, then assigns a
priority tier that controls downstream testing budget.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("bountyhound.scoring.priority")

# ---------------------------------------------------------------------------
# Pattern definitions for severity scoring
# ---------------------------------------------------------------------------

AUTH_PATTERNS = [
    "/login", "/signin", "/oauth", "/token", "/reset", "/password",
    "/auth", "/sso", "/saml", "/2fa", "/mfa", "/logout", "/session",
]

ADMIN_PATTERNS = [
    "/admin", "/staff", "/internal", "/manage", "/superuser", "/root",
    "/dashboard", "/console", "/panel",
]

UPLOAD_PATTERNS = [
    "/upload", "/file", "/attachment", "/import", "/media", "/image",
    "/document", "/blob", "/storage",
]

# Matches /api/users/123, /api/items/<uuid>, /api/resource/{id}
API_ID_PATTERN = re.compile(r"/api/.*(/\d+|/[a-f0-9-]{8,}|/\{[^}]+\})")

SEARCH_PATTERNS = [
    "/search", "/query", "/filter", "/find", "/lookup",
]


# ---------------------------------------------------------------------------
# Tier thresholds
# ---------------------------------------------------------------------------

TIER_CRITICAL = 0.85   # 30 min / 50 req budget
TIER_HIGH = 0.70       # 15 min / 25 req budget
TIER_MEDIUM = 0.55     # 5 min  / 10 req budget
# Below 0.55 → "skip" (1 probe only)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EndpointScore:
    """Scored representation of a single HTTP endpoint."""

    url: str
    method: str                 # GET, POST, etc.
    severity_potential: float   # 0.0 – 1.0
    novelty_score: float        # 0.0 – 1.0
    composite_score: float      # (severity × 0.6) + (novelty × 0.4)
    tier: str                   # "critical", "high", "medium", "skip"
    severity_reason: str        # why this severity score was assigned
    novelty_reason: str         # why this novelty score was assigned


# ---------------------------------------------------------------------------
# Core scorer
# ---------------------------------------------------------------------------

class PriorityScorer:
    """
    Scores HTTP endpoints by combining severity potential and novelty.

    Parameters
    ----------
    disclosed_patterns:
        URL path patterns already found in Target Brief disclosed reports.
        Example: ["/api/user", "/account/reset", "/admin/dashboard"]
        Pass ``None`` or ``[]`` to treat every endpoint as novel.
    """

    def __init__(self, disclosed_patterns: Optional[List[str]] = None) -> None:
        self._disclosed: List[str] = list(disclosed_patterns) if disclosed_patterns else []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, url: str, method: str = "GET") -> EndpointScore:
        """Score a single endpoint and return an :class:`EndpointScore`."""
        normalised_url = self._normalise_url(url)
        path = self._extract_path(normalised_url)

        severity, sev_reason = self._score_severity(path)
        novelty, nov_reason = self._score_novelty(path)

        composite = round((severity * 0.6) + (novelty * 0.4), 4)
        tier = self._assign_tier(composite)

        return EndpointScore(
            url=normalised_url,
            method=method.upper(),
            severity_potential=severity,
            novelty_score=novelty,
            composite_score=composite,
            tier=tier,
            severity_reason=sev_reason,
            novelty_reason=nov_reason,
        )

    def score_many(self, endpoints: List[dict]) -> List[EndpointScore]:
        """
        Score a list of endpoint dicts and return them sorted by
        ``composite_score`` descending.

        Each dict must have at least a ``"url"`` key.  ``"method"`` is
        optional and defaults to ``"GET"``.

        Invalid entries (empty or non-string URL) are skipped with a warning.
        """
        results: List[EndpointScore] = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not isinstance(url, str) or not url.strip():
                logger.warning("Skipping endpoint with invalid URL: %r", url)
                continue
            method = ep.get("method", "GET")
            results.append(self.score(url, method))

        results.sort(key=lambda e: e.composite_score, reverse=True)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_url(url: str) -> str:
        """Strip trailing slash from path; lowercase path but preserve scheme+host."""
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip("/").lower() or "/"
            # Reconstruct with original scheme/host but lowercased path
            normalised = parsed._replace(path=path)
            return normalised.geturl()
        except Exception:
            # If URL parsing fails, return as-is after basic cleanup
            return url.rstrip("/")

    @staticmethod
    def _extract_path(url: str) -> str:
        """Return the URL path component in lowercase."""
        try:
            return urlparse(url).path.lower()
        except Exception:
            return url.lower()

    # ------------------------------------------------------------------
    # Severity scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _score_severity(path: str):
        """Return (severity_float, reason_str) for a given path."""
        # Check in priority order — first match wins
        for pattern in AUTH_PATTERNS:
            if pattern in path:
                return 0.95, f"Authentication endpoint matched pattern '{pattern}'"

        for pattern in ADMIN_PATTERNS:
            if pattern in path:
                return 0.85, f"Admin/privileged endpoint matched pattern '{pattern}'"

        for pattern in UPLOAD_PATTERNS:
            if pattern in path:
                return 0.80, f"File upload/storage endpoint matched pattern '{pattern}'"

        if API_ID_PATTERN.search(path):
            return 0.70, "API endpoint with numeric/UUID/template ID — potential IDOR"

        for pattern in SEARCH_PATTERNS:
            if pattern in path:
                return 0.50, f"Search/query endpoint matched pattern '{pattern}'"

        return 0.30, "No high-severity pattern matched — default severity"

    # ------------------------------------------------------------------
    # Novelty scoring
    # ------------------------------------------------------------------

    def _score_novelty(self, path: str):
        """
        Compare *path* against :attr:`_disclosed` patterns.

        Rules
        -----
        - Exact path match in disclosed  → 0.10 (already found)
        - Similar path (>60 % token overlap) → 0.50
        - No match / no disclosed patterns  → 1.0 (novel surface)
        """
        if not self._disclosed:
            return 1.0, "No disclosed patterns provided — treating as novel surface"

        # Normalise path segments for comparison
        path_tokens = set(filter(None, path.split("/")))

        # Check for exact match first
        for disclosed in self._disclosed:
            disclosed_norm = disclosed.rstrip("/").lower()
            if path == disclosed_norm or path == disclosed_norm + "/":
                return 0.10, f"Exact match with disclosed pattern '{disclosed}'"

        # Check for high-overlap (similar) match
        for disclosed in self._disclosed:
            disclosed_tokens = set(filter(None, disclosed.lower().split("/")))
            if not disclosed_tokens:
                continue
            union = path_tokens | disclosed_tokens
            if not union:
                continue
            overlap = len(path_tokens & disclosed_tokens) / len(union)
            if overlap > 0.60:
                return 0.50, (
                    f"High token overlap ({overlap:.0%}) with disclosed "
                    f"pattern '{disclosed}' — likely known surface"
                )

        return 1.0, "No match with any disclosed pattern — novel attack surface"

    # ------------------------------------------------------------------
    # Tier assignment
    # ------------------------------------------------------------------

    @staticmethod
    def _assign_tier(composite: float) -> str:
        if composite >= TIER_CRITICAL:
            return "critical"
        if composite >= TIER_HIGH:
            return "high"
        if composite >= TIER_MEDIUM:
            return "medium"
        return "skip"


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def score_endpoints(
    endpoints: List[dict],
    disclosed_patterns: Optional[List[str]] = None,
) -> List[EndpointScore]:
    """
    Score and sort a list of endpoint dicts.

    Parameters
    ----------
    endpoints:
        List of ``{"url": str, "method": str}`` dicts.  ``method`` is optional.
    disclosed_patterns:
        URL path patterns from Target Brief disclosed reports.

    Returns
    -------
    List[EndpointScore]
        Sorted by ``composite_score`` descending.
    """
    scorer = PriorityScorer(disclosed_patterns=disclosed_patterns)
    return scorer.score_many(endpoints)
