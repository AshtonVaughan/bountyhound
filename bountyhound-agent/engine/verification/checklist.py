"""
Verification Checklist — Stage A of the Perfect Hunter methodology.

Every finding must pass ALL 5 deterministic gates.  Failing any single gate
causes the finding to be dropped immediately; all gate results are still
collected so callers can inspect which gates failed.

Gates
-----
1. REPRODUCIBILITY  — evidence completeness (request/response pair + clean state)
2. SCOPE            — URL must be within allowed scope and not blocked
3. IMPACT           — impact statement must name real-world harm
4. SEVERITY FLOOR   — CVSS base score >= 4.0 (Medium or above)
5. DUPLICATE CHECK  — (normalised_url, vuln_type) must be novel
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("bountyhound.verification.checklist")

# ---------------------------------------------------------------------------
# Severity label → CVSS score mapping
# ---------------------------------------------------------------------------

LABEL_TO_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.0,
}

SEVERITY_FLOOR = 4.0  # Minimum acceptable CVSS score

# Keywords required in impact statement (at least one must be present)
IMPACT_KEYWORDS = ("attacker", "user", "system")
IMPACT_MIN_LENGTH = 15

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ChecklistInput:
    """A finding entering the Stage A checklist."""

    # Identification
    url: str
    vuln_type: str          # e.g. "XSS", "SQLI", "IDOR"

    # Reproducibility evidence
    request_method: str     # "GET", "POST", etc.
    request_body: str = ""  # Can be empty for GET requests
    response_snippet: str = ""  # First ~500 chars of response

    # Impact
    impact_statement: str = ""

    # Severity
    cvss_score: Optional[float] = None
    severity_label: str = ""  # "critical", "high", "medium", "low", "info"

    # Context
    clean_state_verified: bool = False  # Caller must set True after re-testing


@dataclass
class GateResult:
    """Result of a single gate check."""

    gate_name: str
    passed: bool
    reason: str


@dataclass
class ChecklistResult:
    """Result of running all 5 gates."""

    passed: bool                    # True only if ALL gates passed
    gates: List[GateResult]         # All 5 gate results
    failed_gates: List[str]         # Names of failed gates (empty if all pass)
    finding_id: str                 # Normalised "{normalised_url}::{normalised_vuln_type}"


# ---------------------------------------------------------------------------
# Core checklist
# ---------------------------------------------------------------------------


class VerificationChecklist:
    """
    Stage A — 5-gate deterministic checklist.

    Parameters
    ----------
    allowed_scope:
        URL/domain patterns that the finding URL must match.
        Supported formats:
          - Exact domain: ``"example.com"``
          - Wildcard subdomain: ``"*.example.com"``
          - URL prefix: ``"https://api.example.com/"``
        Pass ``None`` or ``[]`` to allow all URLs (useful in tests only).

    blocked_scope:
        URL/domain patterns that must NOT match.  A finding in blocked scope
        is rejected even if it also matches allowed scope.

    known_findings:
        Previously discovered findings in this session, as
        ``(normalised_url, normalised_vuln_type)`` tuples.

    disclosed_patterns:
        Public prior-art findings from Target Brief intel, as
        ``(normalised_url, normalised_vuln_type)`` tuples.
    """

    def __init__(
        self,
        allowed_scope: Optional[List[str]] = None,
        blocked_scope: Optional[List[str]] = None,
        known_findings: Optional[List[tuple]] = None,
        disclosed_patterns: Optional[List[tuple]] = None,
    ) -> None:
        self._allowed_scope: List[str] = list(allowed_scope) if allowed_scope else []
        self._blocked_scope: List[str] = list(blocked_scope) if blocked_scope else []
        self._known_findings: List[tuple] = list(known_findings) if known_findings else []
        self._disclosed_patterns: List[tuple] = list(disclosed_patterns) if disclosed_patterns else []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, finding: ChecklistInput) -> ChecklistResult:
        """
        Run all 5 gates against *finding*.

        Every gate is always evaluated so the caller can inspect every result.
        ``ChecklistResult.passed`` is ``True`` only when all 5 gates pass.
        """
        gate_methods = [
            self._gate_reproducibility,
            self._gate_scope,
            self._gate_impact,
            self._gate_severity,
            self._gate_duplicate,
        ]

        gate_results: List[GateResult] = []
        for gate_fn in gate_methods:
            result = gate_fn(finding)
            gate_results.append(result)
            logger.debug(
                "Gate %s: %s — %s",
                result.gate_name,
                "PASS" if result.passed else "FAIL",
                result.reason,
            )

        failed_gates = [g.gate_name for g in gate_results if not g.passed]
        overall_passed = len(failed_gates) == 0

        normalised_url = self.normalise_url(finding.url)
        normalised_vuln = self.normalise_vuln_type(finding.vuln_type)
        finding_id = f"{normalised_url}::{normalised_vuln}"

        if overall_passed:
            logger.info("Finding %r passed all 5 gates.", finding_id)
        else:
            logger.info(
                "Finding %r failed gates: %s",
                finding_id,
                ", ".join(failed_gates),
            )

        return ChecklistResult(
            passed=overall_passed,
            gates=gate_results,
            failed_gates=failed_gates,
            finding_id=finding_id,
        )

    # ------------------------------------------------------------------
    # Gate 1 — REPRODUCIBILITY
    # ------------------------------------------------------------------

    def _gate_reproducibility(self, finding: ChecklistInput) -> GateResult:
        """
        Verify the finding has a complete, re-testable evidence set.

        Required:
        - Non-empty ``url``
        - Non-empty ``request_method``
        - Non-empty ``response_snippet``
        - ``clean_state_verified`` must be ``True``
        """
        name = "REPRODUCIBILITY"

        if not finding.url or not finding.url.strip():
            return GateResult(name, False, "url is missing or empty")

        if not finding.request_method or not finding.request_method.strip():
            return GateResult(name, False, "request_method is missing or empty")

        if not finding.response_snippet or not finding.response_snippet.strip():
            return GateResult(name, False, "response_snippet is missing or empty")

        if not finding.clean_state_verified:
            return GateResult(
                name,
                False,
                "clean_state_verified is False — finding must be re-tested from a clean state",
            )

        return GateResult(
            name,
            True,
            "All required evidence fields present and clean-state re-test confirmed",
        )

    # ------------------------------------------------------------------
    # Gate 2 — SCOPE
    # ------------------------------------------------------------------

    def _gate_scope(self, finding: ChecklistInput) -> GateResult:
        """
        Confirm the finding URL is in-scope and not blocked.

        Scope matching rules:
        - ``"*.example.com"``   — wildcard: any subdomain of example.com
        - ``"example.com"``     — exact domain match (scheme-agnostic)
        - ``"https://api.example.com/"`` — URL prefix match
        """
        name = "SCOPE"

        # Blocked scope takes absolute precedence
        if self._blocked_scope and self._url_matches_any(finding.url, self._blocked_scope):
            return GateResult(
                name,
                False,
                f"URL '{finding.url}' matches blocked scope — rejected",
            )

        # If no allowed scope rules → allow everything (open scope mode)
        if not self._allowed_scope:
            return GateResult(name, True, "No allowed scope restrictions configured — URL accepted")

        if self._url_matches_any(finding.url, self._allowed_scope):
            return GateResult(name, True, f"URL '{finding.url}' matches allowed scope")

        return GateResult(
            name,
            False,
            f"URL '{finding.url}' does not match any allowed scope entry",
        )

    @staticmethod
    def _url_matches_any(url: str, scope_entries: List[str]) -> bool:
        """Return True if *url* matches at least one scope entry."""
        for entry in scope_entries:
            if VerificationChecklist._url_matches_entry(url, entry):
                return True
        return False

    @staticmethod
    def _url_matches_entry(url: str, entry: str) -> bool:
        """
        Match *url* against a single scope *entry*.

        Three supported entry formats:
        1. Wildcard subdomain: ``"*.example.com"``
        2. URL prefix (starts with ``http://`` or ``https://``): prefix match
        3. Plain domain: exact host match (case-insensitive)
        """
        url_lower = url.strip().lower()
        entry_lower = entry.strip().lower()

        # --- Wildcard subdomain: *.example.com ---
        if entry_lower.startswith("*."):
            base_domain = entry_lower[2:]  # strip "*."
            try:
                parsed = urlparse(url_lower if "://" in url_lower else "https://" + url_lower)
                host = parsed.hostname or ""
                # Match ONLY if the host ends with ".<base_domain>" (at least one subdomain label).
                # The bare base_domain itself must NOT match — the wildcard requires a prefix.
                return host.endswith("." + base_domain)
            except Exception:
                return False

        # --- URL prefix match ---
        if entry_lower.startswith("http://") or entry_lower.startswith("https://"):
            return url_lower.startswith(entry_lower)

        # --- Plain domain (exact host match) ---
        try:
            parsed = urlparse(url_lower if "://" in url_lower else "https://" + url_lower)
            host = parsed.hostname or ""
            return host == entry_lower
        except Exception:
            return url_lower == entry_lower

    # ------------------------------------------------------------------
    # Gate 3 — IMPACT
    # ------------------------------------------------------------------

    def _gate_impact(self, finding: ChecklistInput) -> GateResult:
        """
        Verify the impact statement describes real-world harm.

        Requirements:
        - Non-empty impact statement
        - At least 15 characters long
        - Contains at least one of: "attacker", "user", "system" (case-insensitive)
        """
        name = "IMPACT"

        stmt = finding.impact_statement.strip()

        if not stmt:
            return GateResult(name, False, "impact_statement is empty")

        if len(stmt) < IMPACT_MIN_LENGTH:
            return GateResult(
                name,
                False,
                f"impact_statement is too short ({len(stmt)} chars, minimum {IMPACT_MIN_LENGTH})",
            )

        stmt_lower = stmt.lower()
        if not any(kw in stmt_lower for kw in IMPACT_KEYWORDS):
            return GateResult(
                name,
                False,
                (
                    f"impact_statement lacks real-world harm framing — "
                    f"must contain at least one of: {', '.join(IMPACT_KEYWORDS)}"
                ),
            )

        return GateResult(
            name,
            True,
            f"Impact statement is valid ({len(stmt)} chars, harm framing confirmed)",
        )

    # ------------------------------------------------------------------
    # Gate 4 — SEVERITY FLOOR
    # ------------------------------------------------------------------

    def _gate_severity(self, finding: ChecklistInput) -> GateResult:
        """
        Ensure the finding meets the minimum severity threshold (CVSS >= 4.0).

        If no ``cvss_score`` is provided, attempt to infer from ``severity_label``.
        """
        name = "SEVERITY FLOOR"

        cvss = finding.cvss_score

        if cvss is None:
            # Try to infer from severity_label
            label = finding.severity_label.strip().lower()
            if label in LABEL_TO_CVSS:
                cvss = LABEL_TO_CVSS[label]
                inferred_note = f" (inferred from label '{label}')"
            else:
                return GateResult(
                    name,
                    False,
                    (
                        "No cvss_score provided and severity_label "
                        f"'{finding.severity_label}' is not recognised. "
                        f"Valid labels: {', '.join(LABEL_TO_CVSS.keys())}"
                    ),
                )
        else:
            inferred_note = ""

        if cvss < SEVERITY_FLOOR:
            return GateResult(
                name,
                False,
                f"CVSS score {cvss:.1f}{inferred_note} is below the minimum floor of {SEVERITY_FLOOR:.1f}",
            )

        return GateResult(
            name,
            True,
            f"CVSS score {cvss:.1f}{inferred_note} meets the minimum floor of {SEVERITY_FLOOR:.1f}",
        )

    # ------------------------------------------------------------------
    # Gate 5 — DUPLICATE CHECK
    # ------------------------------------------------------------------

    def _gate_duplicate(self, finding: ChecklistInput) -> GateResult:
        """
        Confirm the (normalised_url, normalised_vuln_type) pair is novel.

        Checked against:
        a) ``known_findings`` — previously confirmed findings this session
        b) ``disclosed_patterns`` — public prior-art from Target Brief
        """
        name = "DUPLICATE CHECK"

        norm_url = self.normalise_url(finding.url)
        norm_vuln = self.normalise_vuln_type(finding.vuln_type)
        pair = (norm_url, norm_vuln)

        for raw_url, raw_vuln in self._known_findings:
            known_norm = (self.normalise_url(raw_url), self.normalise_vuln_type(raw_vuln))
            if known_norm == pair:
                return GateResult(
                    name,
                    False,
                    f"Duplicate of known finding: ({norm_url}, {norm_vuln})",
                )

        for raw_url, raw_vuln in self._disclosed_patterns:
            known_norm = (self.normalise_url(raw_url), self.normalise_vuln_type(raw_vuln))
            if known_norm == pair:
                return GateResult(
                    name,
                    False,
                    f"Matches publicly disclosed pattern: ({norm_url}, {norm_vuln})",
                )

        return GateResult(
            name,
            True,
            f"Novel finding — ({norm_url}, {norm_vuln}) not in known or disclosed sets",
        )

    # ------------------------------------------------------------------
    # Normalisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def normalise_url(url: str) -> str:
        """
        Strip query string, lowercase, strip trailing slash.

        Examples
        --------
        >>> VerificationChecklist.normalise_url("https://Example.com/api/Users/?id=1")
        'https://example.com/api/users'
        >>> VerificationChecklist.normalise_url("https://api.example.com/v1/")
        'https://api.example.com/v1'
        """
        try:
            parsed = urlparse(url.strip())
            # Reconstruct without query string or fragment; lowercase everything
            normalised = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.lower().rstrip("/") or "/",
                "",   # params
                "",   # query — stripped
                "",   # fragment — stripped
            ))
            return normalised
        except Exception:
            return url.strip().lower().rstrip("/")

    @staticmethod
    def normalise_vuln_type(vuln_type: str) -> str:
        """
        Uppercase and strip surrounding whitespace.

        Examples
        --------
        >>> VerificationChecklist.normalise_vuln_type("  xss  ")
        'XSS'
        >>> VerificationChecklist.normalise_vuln_type("sql injection")
        'SQL INJECTION'
        """
        return vuln_type.strip().upper()
