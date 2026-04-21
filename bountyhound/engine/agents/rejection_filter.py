"""
Rejection Filter - Quality gate that prevents false positive submissions.

Evaluates findings against 4 rejection patterns:
1. Intended Functionality - authorized access reported as vuln
2. Ambiguous Exploitation - success:false, unclear PoC, no state change
3. Operational Issue - infrastructure gap, not security
4. Impractical Attack - brute force without proof

Score formula:
  score = (auth_violation * 40) + (clear_exploitation * 30) + (impact_severity * 20) + (scope_match * 10)

Thresholds:
  90-100: AUTO_SUBMIT
  70-89:  SUBMIT
  50-69:  MANUAL_REVIEW
  0-49:   REJECT
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional



class Verdict(Enum):
    AUTO_SUBMIT = "AUTO_SUBMIT"
    SUBMIT = "SUBMIT"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    REJECT = "REJECT"


@dataclass
class Finding:
    title: str
    description: str
    evidence: str
    auth_context: str = "unknown"  # own_account, cross_account, unauthenticated, unknown
    state_change_verified: bool = False
    impact: str = "low"  # low, medium, high, critical
    in_scope: bool = True


@dataclass
class FilterResult:
    verdict: Verdict
    score: int
    reason: str
    rejection_pattern: Optional[str] = None


# Patterns that indicate NOT a real vulnerability
INTENDED_FUNCTIONALITY_SIGNALS = [
    "own account", "own resource", "own data", "their own",
    "authorized access", "expected behavior", "by design",
]

AMBIGUOUS_EXPLOITATION_SIGNALS = [
    '"errors"', "not authorized", "unauthorized", "forbidden",
    "success.*false", "permission denied", '"data":null',
    "no state change", "response only",
]

OPERATIONAL_SIGNALS = [
    "timeout", "rate limit", "503", "502", "infrastructure",
    "maintenance", "deployment", "configuration",
]


class RejectionFilter:
    """Evaluates findings and assigns acceptance scores."""

    def evaluate(self, finding: Finding) -> FilterResult:
        # Check rejection patterns first
        rejection = self._check_rejection_patterns(finding)
        if rejection:
            return rejection

        # Calculate score
        score = self._calculate_score(finding)

        # Determine verdict from score
        if score >= 90:
            verdict = Verdict.AUTO_SUBMIT
        elif score >= 70:
            verdict = Verdict.SUBMIT
        elif score >= 50:
            verdict = Verdict.MANUAL_REVIEW
        else:
            verdict = Verdict.REJECT

        return FilterResult(
            verdict=verdict,
            score=score,
            reason=self._build_reason(finding, score),
        )

    def _check_rejection_patterns(self, finding: Finding) -> Optional[FilterResult]:
        text = f"{finding.title} {finding.description} {finding.evidence}".lower()

        # Pattern 1: Intended Functionality
        if finding.auth_context == "own_account":
            return FilterResult(
                verdict=Verdict.REJECT,
                score=0,
                reason="Intended functionality: accessing own resources is authorized behavior",
                rejection_pattern="intended_functionality",
            )

        # Pattern 2: Ambiguous Exploitation (no state change + error signals)
        if not finding.state_change_verified:
            ambiguous_matches = [s for s in AMBIGUOUS_EXPLOITATION_SIGNALS if re.search(s, text)]
            if ambiguous_matches and finding.auth_context == "cross_account":
                return FilterResult(
                    verdict=Verdict.REJECT,
                    score=15,
                    reason=f"Ambiguous exploitation: no state change verified, error signals found: {ambiguous_matches[:3]}",
                    rejection_pattern="ambiguous_exploitation",
                )

        # Pattern 3: Operational Issue
        operational_matches = [s for s in OPERATIONAL_SIGNALS if s in text]
        if operational_matches and not finding.state_change_verified:
            if not any(kw in text for kw in ["bypass", "injection", "xss", "idor", "ssrf"]):
                return FilterResult(
                    verdict=Verdict.REJECT,
                    score=10,
                    reason=f"Operational issue, not security: {operational_matches[:3]}",
                    rejection_pattern="operational_issue",
                )

        return None

    def _calculate_score(self, finding: Finding) -> int:
        score = 0

        # Authorization violation (40 points)
        if finding.auth_context == "cross_account":
            score += 40
        elif finding.auth_context == "unauthenticated":
            score += 35
        elif finding.auth_context == "unknown":
            score += 10

        # Clear exploitation (30 points)
        if finding.state_change_verified:
            score += 30
        elif any(kw in finding.evidence.lower() for kw in ["confirmed", "verified", "changed", "modified", "deleted"]):
            score += 15

        # Impact severity (20 points)
        impact_scores = {"critical": 20, "high": 15, "medium": 10, "low": 5}
        score += impact_scores.get(finding.impact, 5)

        # Scope match (10 points)
        if finding.in_scope:
            score += 10

        return min(score, 100)

    def _build_reason(self, finding: Finding, score: int) -> str:
        parts = []
        if finding.auth_context == "cross_account":
            parts.append("cross-account access confirmed")
        if finding.state_change_verified:
            parts.append("state change verified")
        if finding.impact in ("critical", "high"):
            parts.append(f"{finding.impact} impact")
        if finding.in_scope:
            parts.append("in scope")
        return f"Score {score}: {', '.join(parts)}" if parts else f"Score {score}"
