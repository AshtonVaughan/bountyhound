"""
Self-Challenge Agent — Stage B of the Perfect Hunter methodology.

A second independent agent receives a finding and attempts to disprove it by
asking 4 challenge questions.  If the challenger cannot disprove the finding,
it is marked VERIFIED and advances to reporting.  If the challenger raises
valid doubt, the finding is returned for re-verification or dropped.

Challenge Questions
-------------------
1. Is this actually exploitable or just reflected/observed?
2. Does the program's threat model consider this in-scope impact?
3. Is there a simpler, benign explanation for this response?
4. Would a real attacker reproduce this without special access?

Modes
-----
- AI mode   : calls the Anthropic Claude API (requires api_key or ANTHROPIC_API_KEY)
- Heuristic : rule-based fallback when no API key is available
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .checklist import ChecklistInput

logger = logging.getLogger("bountyhound.verification.challenger")

# ---------------------------------------------------------------------------
# Lazy import of the anthropic package
# ---------------------------------------------------------------------------

try:
    import anthropic as _anthropic  # noqa: F401
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LABEL_TO_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.0,
}

# Vague impact phrases that lack specificity
_VAGUE_IMPACT_PHRASES = (
    "access data",
    "access information",
    "steal data",
    "get data",
    "obtain data",
    "view data",
    "see data",
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ChallengeResult:
    """Result of the Stage B self-challenge."""

    verified: bool                   # True = challenger could not disprove
    verdict: str                     # "VERIFIED" | "CHALLENGED"
    challenges_raised: List[str]     # Reasons the finding may not be valid
    failed_challenges: List[str]     # Reasons that were considered and ruled out
    confidence: float                # 0.0 - 1.0 confidence in the finding
    recommendation: str              # "SUBMIT" | "REVIEW" | "DROP"
    raw_response: str                # Full LLM response for traceability


# ---------------------------------------------------------------------------
# Challenger
# ---------------------------------------------------------------------------


class Challenger:
    """
    Stage B: AI self-challenge agent.

    Receives a finding and attempts to disprove it using 4 challenge questions.
    Uses the Anthropic Claude API if available, falls back to heuristic mode.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-haiku-4-5-20251001",
    ) -> None:
        """
        api_key : Anthropic API key.  If None, reads from ANTHROPIC_API_KEY
                  env var.  If still None, runs in heuristic-only mode.
        model   : Claude model to use.  Defaults to Haiku (fast + cheap).
        """
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

        self._api_key: Optional[str] = resolved_key if HAS_ANTHROPIC and resolved_key else None
        self._model = model

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        """Returns 'ai' or 'heuristic'."""
        return "ai" if self._api_key else "heuristic"

    def challenge(self, finding: ChecklistInput) -> ChallengeResult:
        """
        Run Stage B challenge against *finding*.

        If API key available: calls Claude with the challenge prompt.
        If no API key: runs heuristic mode (rule-based challenge).

        Returns ChallengeResult with verdict and reasoning.
        """
        if self._api_key:
            return self._ai_challenge(finding)
        return self._heuristic_challenge(finding)

    # ------------------------------------------------------------------
    # AI mode
    # ------------------------------------------------------------------

    def _ai_challenge(self, finding: ChecklistInput) -> ChallengeResult:
        """Call the Claude API and parse the result."""
        import anthropic  # local import — only reached when HAS_ANTHROPIC is True

        prompt = self._build_challenge_prompt(finding)

        try:
            client = anthropic.Anthropic(api_key=self._api_key)
            message = client.messages.create(
                model=self._model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_response = message.content[0].text
            logger.debug("Challenge AI response received (%d chars).", len(raw_response))
        except Exception as exc:
            logger.warning(
                "AI challenge call failed (%s); falling back to heuristic mode.", exc
            )
            result = self._heuristic_challenge(finding)
            return result

        result = self._parse_challenge_response(raw_response)
        return result

    def _build_challenge_prompt(self, finding: ChecklistInput) -> str:
        """Build the challenge prompt for the AI model."""
        cvss = self._resolve_cvss(finding)
        cvss_display = f"{cvss:.1f}" if cvss is not None else "unknown"

        snippet = (finding.response_snippet or "")[:300]

        prompt = (
            "You are a skeptical security researcher reviewing a reported vulnerability.\n"
            "Your job is to find reasons this finding may NOT be valid before it is submitted.\n"
            "Be rigorous. Protect the researcher's reputation by catching false positives.\n"
            "\n"
            "FINDING TO CHALLENGE:\n"
            f"URL: {finding.url}\n"
            f"Method: {finding.request_method}\n"
            f"Vulnerability Type: {finding.vuln_type}\n"
            f"Response Snippet: {snippet}\n"
            f"Impact Claim: {finding.impact_statement}\n"
            f"CVSS Score: {cvss_display}\n"
            "\n"
            "CHALLENGE QUESTIONS — answer each with reasoning:\n"
            "1. Is this actually exploitable or just reflected/observed without real impact?\n"
            "2. Does the program's threat model consider this in-scope harm?\n"
            "3. Is there a simpler, benign explanation for this server response?\n"
            "4. Would a real attacker reproduce this without special access or conditions?\n"
            "\n"
            "For each question, respond with:\n"
            "CHALLENGE_N: [RAISED|RULED_OUT] — <one-sentence reasoning>\n"
            "\n"
            "Then provide:\n"
            "VERDICT: [VERIFIED|CHALLENGED]\n"
            "CONFIDENCE: [0.0-1.0]\n"
            "RECOMMENDATION: [SUBMIT|REVIEW|DROP]\n"
            "SUMMARY: <one sentence>\n"
        )
        return prompt

    def _parse_challenge_response(self, response: str) -> ChallengeResult:
        """
        Parse the LLM's challenge response into a ChallengeResult.

        Handles malformed responses gracefully — never raises.
        """
        challenges_raised: List[str] = []
        failed_challenges: List[str] = []

        # Parse CHALLENGE_N lines
        challenge_pattern = re.compile(
            r"CHALLENGE_(\d+)\s*:\s*\[(RAISED|RULED_OUT)\]\s*[—\-–]\s*(.+)",
            re.IGNORECASE,
        )
        for match in challenge_pattern.finditer(response):
            status = match.group(2).upper()
            reason = match.group(3).strip()
            if status == "RAISED":
                challenges_raised.append(reason)
            else:
                failed_challenges.append(reason)

        # Parse VERDICT
        verdict_match = re.search(
            r"VERDICT\s*:\s*\[?(VERIFIED|CHALLENGED)\]?", response, re.IGNORECASE
        )
        if verdict_match:
            verdict = verdict_match.group(1).upper()
        else:
            # Malformed — infer from challenges raised
            verdict = "CHALLENGED" if challenges_raised else "VERIFIED"
            logger.warning(
                "Could not parse VERDICT from AI response; inferred '%s'.", verdict
            )

        verified = verdict == "VERIFIED"

        # Parse CONFIDENCE
        confidence_match = re.search(
            r"CONFIDENCE\s*:\s*\[?([\d.]+)\]?", response, re.IGNORECASE
        )
        if confidence_match:
            try:
                confidence = float(confidence_match.group(1))
                confidence = max(0.0, min(1.0, confidence))
            except ValueError:
                confidence = 0.85 if verified else 0.40
        else:
            confidence = 0.85 if verified else 0.40
            logger.warning("Could not parse CONFIDENCE from AI response; using default.")

        # Parse RECOMMENDATION
        rec_match = re.search(
            r"RECOMMENDATION\s*:\s*\[?(SUBMIT|REVIEW|DROP)\]?", response, re.IGNORECASE
        )
        if rec_match:
            recommendation = rec_match.group(1).upper()
        else:
            # Infer from verdict
            if verified:
                recommendation = "SUBMIT"
            elif len(challenges_raised) >= 2:
                recommendation = "DROP"
            else:
                recommendation = "REVIEW"
            logger.warning(
                "Could not parse RECOMMENDATION from AI response; inferred '%s'.",
                recommendation,
            )

        logger.info(
            "AI challenge verdict: %s (confidence=%.2f, recommendation=%s, "
            "raised=%d, ruled_out=%d)",
            verdict,
            confidence,
            recommendation,
            len(challenges_raised),
            len(failed_challenges),
        )

        return ChallengeResult(
            verified=verified,
            verdict=verdict,
            challenges_raised=challenges_raised,
            failed_challenges=failed_challenges,
            confidence=confidence,
            recommendation=recommendation,
            raw_response=response,
        )

    # ------------------------------------------------------------------
    # Heuristic mode
    # ------------------------------------------------------------------

    def _heuristic_challenge(self, finding: ChecklistInput) -> ChallengeResult:
        """
        Rule-based challenge when no API key is available.

        Heuristics applied:
        - Reflection-only XSS   : payload in snippet, no execution context
        - Low CVSS / high label : score <= 4.0 but label is critical/high
        - No clean state        : clean_state_verified=False
        - Vague impact          : impact statement lacks specificity
        """
        challenges_raised: List[str] = []
        failed_challenges: List[str] = []

        snippet_lower = (finding.response_snippet or "").lower()
        vuln_lower = finding.vuln_type.strip().upper()
        impact_lower = finding.impact_statement.strip().lower()
        severity_lower = finding.severity_label.strip().lower()
        cvss = self._resolve_cvss(finding)

        # ---- Heuristic 1: Reflection-only XSS ----
        h1_desc = "Reflection-only XSS: payload appears in response but no execution context detected"
        if vuln_lower == "XSS" and finding.response_snippet:
            # Check if response contains the payload text but no script execution indicators
            has_execution_context = any(
                indicator in snippet_lower
                for indicator in ("<script", "javascript:", "onerror=", "onload=", "eval(", "alert(")
            )
            if not has_execution_context:
                challenges_raised.append(h1_desc)
                logger.debug("Heuristic 1 raised: %s", h1_desc)
            else:
                failed_challenges.append(
                    "XSS execution context confirmed in response snippet"
                )
        else:
            failed_challenges.append(
                "Not an XSS finding or no snippet provided — reflection-only check skipped"
            )

        # ---- Heuristic 2: Low CVSS / high label mismatch ----
        h2_desc = "CVSS score <= 4.0 but severity label is 'critical' or 'high' — likely mislabelled"
        if cvss is not None and cvss <= 4.0 and severity_lower in ("critical", "high"):
            challenges_raised.append(h2_desc)
            logger.debug("Heuristic 2 raised: %s", h2_desc)
        else:
            failed_challenges.append(
                "CVSS score and severity label are consistent"
            )

        # ---- Heuristic 3: No clean state ----
        h3_desc = "clean_state_verified=False — finding was not re-tested from a clean state"
        if not finding.clean_state_verified:
            challenges_raised.append(h3_desc)
            logger.debug("Heuristic 3 raised: %s", h3_desc)
        else:
            failed_challenges.append(
                "clean_state_verified=True — finding confirmed from clean state"
            )

        # ---- Heuristic 4: Vague impact statement ----
        h4_desc = (
            "Impact statement is vague — does not describe a specific, concrete action "
            "the attacker can take (e.g. 'attacker can read all users emails')"
        )
        is_vague = any(phrase in impact_lower for phrase in _VAGUE_IMPACT_PHRASES)
        if is_vague:
            challenges_raised.append(h4_desc)
            logger.debug("Heuristic 4 raised: %s", h4_desc)
        else:
            failed_challenges.append(
                "Impact statement describes a specific, concrete harm"
            )

        # ---- Determine outcome ----
        num_raised = len(challenges_raised)

        if num_raised == 0:
            verdict = "VERIFIED"
            verified = True
            confidence = 0.85
            recommendation = "SUBMIT"
        elif num_raised == 1:
            verdict = "CHALLENGED"
            verified = False
            confidence = 0.60
            recommendation = "REVIEW"
        else:
            verdict = "CHALLENGED"
            verified = False
            confidence = 0.30
            recommendation = "DROP"

        raw_response = (
            f"[heuristic mode] challenges_raised={num_raised}, verdict={verdict}, "
            f"confidence={confidence:.2f}, recommendation={recommendation}"
        )

        logger.info(
            "Heuristic challenge verdict: %s (confidence=%.2f, recommendation=%s, "
            "raised=%d, ruled_out=%d)",
            verdict,
            confidence,
            recommendation,
            len(challenges_raised),
            len(failed_challenges),
        )

        return ChallengeResult(
            verified=verified,
            verdict=verdict,
            challenges_raised=challenges_raised,
            failed_challenges=failed_challenges,
            confidence=confidence,
            recommendation=recommendation,
            raw_response=raw_response,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_cvss(finding: ChecklistInput) -> Optional[float]:
        """Return the CVSS score, inferring from severity_label if needed."""
        if finding.cvss_score is not None:
            return finding.cvss_score
        label = finding.severity_label.strip().lower()
        return LABEL_TO_CVSS.get(label)
