"""
source_audit_gates.py - Validation gates for source code audit findings.

The web-focused validation pipeline (validation_pipeline.py) handles HTTP/GraphQL/gRPC
findings. This module handles SOURCE CODE audit findings — crypto libraries, protocol
implementations, C/C++/Rust security bugs, etc.

Root cause it solves: automated audit agents consistently overclaim findings because they:
1. Don't check if behavior is documented/intentional
2. Don't verify code paths are reachable from protocol-level callers
3. Don't compare against prior audits
4. Rate everything High/Critical with no calibration
5. Report theoretical weaknesses as exploitable vulnerabilities

Every source code audit finding MUST pass through these gates before inclusion
in any report. Gates are ordered from fastest/cheapest to slowest/most expensive.

Usage:
    from engine.core.source_audit_gates import SourceAuditPipeline

    pipeline = SourceAuditPipeline()
    result = pipeline.validate(finding)

    if result.verdict == 'SUBMIT':
        include_in_report(result)
    elif result.verdict == 'DOWNGRADE':
        include_at_lower_severity(result)
    else:
        discard(result)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    FALSE_POSITIVE = "false_positive"


class Verdict(Enum):
    SUBMIT = "SUBMIT"
    DOWNGRADE = "DOWNGRADE"
    HOLD = "HOLD"
    REJECT = "REJECT"


@dataclass
class AuditFinding:
    """A source code audit finding to be validated."""
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    files: List[str]  # file paths with line numbers
    vuln_type: str  # e.g. "buffer_overread", "missing_validation", "timing_side_channel"

    # Validation fields — agents MUST populate these
    documentation_checked: bool = False
    docs_mention_behavior: bool = False  # True = behavior is documented/intentional
    doc_references: List[str] = field(default_factory=list)  # specific doc quotes

    code_is_reachable: bool = False  # True = confirmed called from protocol code
    call_chain: List[str] = field(default_factory=list)  # e.g. ["ecdsa_2p.cpp:340 -> decrypt()"]
    callers_with_untrusted_input: List[str] = field(default_factory=list)

    prior_audit_checked: bool = False
    known_in_prior_audit: bool = False  # True = already flagged by Cure53/etc
    prior_audit_id: str = ""  # e.g. "CBS-02-006"
    prior_audit_status: str = ""  # e.g. "partially_fixed", "wont_fix", "fixed"

    is_intentional_tradeoff: bool = False  # e.g. global abort mode
    tradeoff_justification: str = ""

    exploit_scenario: str = ""  # concrete attack, not theoretical
    prerequisites: List[str] = field(default_factory=list)  # what attacker needs
    impact: str = ""  # specific impact, not generic "could lead to..."

    # Counter-argument: why this might NOT be a real bug
    counter_argument: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ValidationResult:
    """Result of running a finding through source audit validation."""
    finding: AuditFinding
    verdict: str = "PENDING"
    original_severity: str = ""
    adjusted_severity: str = ""
    gates_passed: List[str] = field(default_factory=list)
    gates_failed: List[str] = field(default_factory=list)
    rejection_reasons: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.finding.id,
            "title": self.finding.title,
            "verdict": self.verdict,
            "original_severity": self.original_severity,
            "adjusted_severity": self.adjusted_severity,
            "gates_passed": self.gates_passed,
            "gates_failed": self.gates_failed,
            "rejection_reasons": self.rejection_reasons,
            "notes": self.notes,
            "confidence_score": self.confidence_score,
        }


class SourceAuditPipeline:
    """
    6-gate validation pipeline for source code audit findings.

    Gate 1: Completeness Check — did the agent do its homework?
    Gate 2: Documentation Gate — is this documented/intentional behavior?
    Gate 3: Prior Audit Gate — is this already known from prior audits?
    Gate 4: Reachability Gate — is the vulnerable code actually reachable?
    Gate 5: Exploitability Gate — is there a concrete exploit scenario?
    Gate 6: Severity Calibration — does the claimed severity match the evidence?
    """

    def validate(self, finding: AuditFinding) -> ValidationResult:
        result = ValidationResult(
            finding=finding,
            original_severity=finding.severity,
            adjusted_severity=finding.severity,
        )

        # Gate 1: Completeness
        if not self._gate_completeness(finding, result):
            result.verdict = Verdict.HOLD.value
            return result

        # Gate 2: Documentation
        if not self._gate_documentation(finding, result):
            return result  # verdict set inside

        # Gate 3: Prior Audit
        if not self._gate_prior_audit(finding, result):
            return result  # verdict set inside

        # Gate 4: Reachability
        if not self._gate_reachability(finding, result):
            return result  # verdict set inside

        # Gate 5: Exploitability
        if not self._gate_exploitability(finding, result):
            return result  # verdict set inside

        # Gate 6: Severity Calibration
        self._gate_severity_calibration(finding, result)

        # Final verdict
        self._compute_verdict(result)
        return result

    def validate_batch(self, findings: List[AuditFinding]) -> List[ValidationResult]:
        return [self.validate(f) for f in findings]

    # ------------------------------------------------------------------
    # Gate 1: Completeness — did the agent actually do validation work?
    # ------------------------------------------------------------------
    def _gate_completeness(self, f: AuditFinding, r: ValidationResult) -> bool:
        """Reject findings where the agent skipped mandatory validation steps."""
        missing = []

        if not f.documentation_checked:
            missing.append("documentation_checked=False: Agent did not review project documentation")

        if not f.prior_audit_checked:
            missing.append("prior_audit_checked=False: Agent did not check for prior audit findings")

        if not f.files:
            missing.append("No file paths provided")

        if not f.description or len(f.description) < 20:
            missing.append("Description too short — provide technical detail")

        if not f.counter_argument:
            missing.append(
                "counter_argument is empty: Agent MUST provide at least one reason "
                "why this finding might NOT be a real vulnerability"
            )

        if missing:
            r.gates_failed.append("COMPLETENESS")
            r.rejection_reasons.extend(missing)
            r.notes.append(
                "Finding returned for additional validation. Agent must populate "
                "all required fields before resubmission."
            )
            return False

        r.gates_passed.append("COMPLETENESS")
        return True

    # ------------------------------------------------------------------
    # Gate 2: Documentation — is this documented/intentional behavior?
    # ------------------------------------------------------------------
    def _gate_documentation(self, f: AuditFinding, r: ValidationResult) -> bool:
        """
        If the behavior is documented as intentional (e.g. secure-usage.pdf
        describes global abort mode bit-leak), the finding is NOT a vulnerability.
        """
        if f.docs_mention_behavior and f.is_intentional_tradeoff:
            r.gates_failed.append("DOCUMENTATION")
            r.verdict = Verdict.REJECT.value
            r.rejection_reasons.append(
                f"Behavior is documented as intentional. "
                f"References: {'; '.join(f.doc_references)}. "
                f"Tradeoff: {f.tradeoff_justification}"
            )
            r.notes.append(
                "This is documented, intended behavior — NOT a vulnerability. "
                "Submitting this would be rejected as 'Informative — known behavior'. "
                "The documentation explicitly describes this tradeoff."
            )
            return False

        if f.docs_mention_behavior and not f.is_intentional_tradeoff:
            # Documented but not explicitly intentional — downgrade severity
            r.notes.append(
                f"Behavior is mentioned in docs ({'; '.join(f.doc_references)}) "
                f"but not explicitly marked as intentional. Downgrading severity."
            )
            r.adjusted_severity = _downgrade_severity(f.severity)

        r.gates_passed.append("DOCUMENTATION")
        return True

    # ------------------------------------------------------------------
    # Gate 3: Prior Audit — is this already known?
    # ------------------------------------------------------------------
    def _gate_prior_audit(self, f: AuditFinding, r: ValidationResult) -> bool:
        """
        If a finding was already reported in a prior professional audit,
        reject or downgrade depending on fix status.
        """
        if not f.known_in_prior_audit:
            r.gates_passed.append("PRIOR_AUDIT")
            return True

        if f.prior_audit_status == "fixed":
            r.gates_failed.append("PRIOR_AUDIT")
            r.verdict = Verdict.REJECT.value
            r.rejection_reasons.append(
                f"Already reported in prior audit ({f.prior_audit_id}) and marked FIXED. "
                f"If you believe the fix is incomplete, document specifically what's still broken."
            )
            return False

        if f.prior_audit_status in ("partially_fixed", "wont_fix", "acknowledged"):
            # Known but not fully resolved — can submit as follow-up but must be explicit
            r.notes.append(
                f"Known from prior audit ({f.prior_audit_id}, status: {f.prior_audit_status}). "
                f"Submission must explicitly reference the prior finding and explain "
                f"what remains unfixed. Severity capped at prior audit's severity."
            )
            r.adjusted_severity = _downgrade_severity(f.severity)
            r.gates_passed.append("PRIOR_AUDIT (with note)")
            return True

        # Known but status unclear
        r.notes.append(
            f"Possibly known from prior audit ({f.prior_audit_id}). "
            f"Verify this is genuinely new before submitting."
        )
        r.gates_passed.append("PRIOR_AUDIT (uncertain)")
        return True

    # ------------------------------------------------------------------
    # Gate 4: Reachability — is the code actually called?
    # ------------------------------------------------------------------
    def _gate_reachability(self, f: AuditFinding, r: ValidationResult) -> bool:
        """
        A bug in dead code or an unused function is not a vulnerability.
        The agent must prove the vulnerable code is reachable from protocol-
        level callers with attacker-controlled input.
        """
        if not f.code_is_reachable:
            if not f.call_chain and not f.callers_with_untrusted_input:
                # No evidence of reachability at all
                r.gates_failed.append("REACHABILITY")
                r.adjusted_severity = _cap_severity(r.adjusted_severity, "low")
                r.notes.append(
                    "Code path not proven reachable from protocol-level callers. "
                    "Agent found no call chain or callers with untrusted input. "
                    "Severity capped at Low (latent/dormant bug)."
                )
                # Don't reject — dormant bugs can still be reported at Low
                r.gates_passed.append("REACHABILITY (capped)")
                return True
            else:
                # Agent provided call chain but marked as not reachable — contradiction
                r.notes.append("Call chain provided but code_is_reachable=False. Review needed.")
                r.gates_passed.append("REACHABILITY (review)")
                return True

        if not f.callers_with_untrusted_input:
            r.notes.append(
                "Code is reachable but no callers with untrusted input identified. "
                "Impact depends on whether attacker can influence the inputs."
            )
            r.adjusted_severity = _cap_severity(r.adjusted_severity, "medium")

        r.gates_passed.append("REACHABILITY")
        return True

    # ------------------------------------------------------------------
    # Gate 5: Exploitability — is there a concrete attack?
    # ------------------------------------------------------------------
    def _gate_exploitability(self, f: AuditFinding, r: ValidationResult) -> bool:
        """
        Theoretical weaknesses != exploitable vulnerabilities.
        Agent must describe a concrete exploit scenario, not just
        "could potentially lead to..." hand-waving.
        """
        if not f.exploit_scenario or len(f.exploit_scenario) < 30:
            r.notes.append(
                "No concrete exploit scenario provided. "
                "Theoretical weaknesses are capped at Medium severity."
            )
            r.adjusted_severity = _cap_severity(r.adjusted_severity, "medium")
            r.gates_passed.append("EXPLOITABILITY (theoretical)")
            return True

        # Check for weasel words that indicate theoretical-only analysis
        weasel_phrases = [
            "could potentially",
            "might allow",
            "theoretically possible",
            "in theory",
            "if an attacker were to",
            "could lead to",
            "may enable",
            "potentially exploitable",
        ]
        weasel_count = sum(
            1 for phrase in weasel_phrases
            if phrase.lower() in f.exploit_scenario.lower()
        )

        if weasel_count >= 2:
            r.notes.append(
                f"Exploit scenario contains {weasel_count} hedging phrases "
                f"('could potentially', 'might allow', etc.). "
                f"This suggests theoretical analysis, not a confirmed exploit. "
                f"Provide concrete steps: 'Send X to endpoint Y, observe Z.'"
            )
            r.adjusted_severity = _cap_severity(r.adjusted_severity, "medium")
            r.gates_passed.append("EXPLOITABILITY (hedged)")
            return True

        r.gates_passed.append("EXPLOITABILITY")
        return True

    # ------------------------------------------------------------------
    # Gate 6: Severity Calibration
    # ------------------------------------------------------------------
    def _gate_severity_calibration(self, f: AuditFinding, r: ValidationResult) -> None:
        """
        Apply domain-specific severity rules for source code findings.
        """
        sev = r.adjusted_severity.lower()

        # Rule 1: Critical requires key compromise or RCE with concrete exploit
        if sev == "critical":
            has_key_compromise = any(
                kw in f.impact.lower()
                for kw in ["private key", "key extraction", "key compromise", "rce", "remote code"]
            )
            has_concrete_exploit = (
                f.exploit_scenario
                and len(f.exploit_scenario) >= 50
                and f.code_is_reachable
                and f.callers_with_untrusted_input
            )
            if not (has_key_compromise and has_concrete_exploit):
                r.adjusted_severity = "high"
                r.notes.append(
                    "Critical requires: (1) key compromise or RCE impact AND "
                    "(2) concrete exploit with reachable code path and untrusted input. "
                    "Downgraded to High."
                )

        # Rule 2: High requires reachable code with demonstrated impact
        if sev == "high":
            if not f.code_is_reachable:
                r.adjusted_severity = "low"
                r.notes.append("High requires reachable code. Unreachable → Low.")
            elif not f.exploit_scenario:
                r.adjusted_severity = "medium"
                r.notes.append("High requires exploit scenario. No scenario → Medium.")

        # Rule 3: Timing side channels are Medium at most unless demonstrated
        if f.vuln_type in ("timing_side_channel", "side_channel"):
            if sev in ("critical", "high"):
                r.adjusted_severity = "medium"
                r.notes.append(
                    "Timing side channels capped at Medium unless demonstrated "
                    "with measured timing differences and concrete key recovery."
                )

        # Rule 4: Unused/dead code bugs are Low at most
        if not f.code_is_reachable and not f.callers_with_untrusted_input:
            r.adjusted_severity = _cap_severity(r.adjusted_severity, "low")
            if r.adjusted_severity != sev:
                r.notes.append("Dead/unused code bug → capped at Low.")

        # Rule 5: "Missing validation" without demonstrated exploit is Medium max
        if f.vuln_type in ("missing_validation", "missing_check", "input_validation"):
            if not f.exploit_scenario or len(f.exploit_scenario) < 50:
                r.adjusted_severity = _cap_severity(r.adjusted_severity, "medium")
                r.notes.append(
                    "Missing validation without demonstrated exploit → Medium max."
                )

        # Rule 6: cb_assert / debug-only issues are Low
        if "cb_assert" in f.description.lower() and "compiled out" in f.description.lower():
            r.adjusted_severity = _cap_severity(r.adjusted_severity, "low")
            r.notes.append(
                "Issues only exploitable when debug assertions are compiled out "
                "are Low severity (non-default build configuration)."
            )

        r.gates_passed.append("SEVERITY_CALIBRATION")

    # ------------------------------------------------------------------
    # Final verdict
    # ------------------------------------------------------------------
    def _compute_verdict(self, r: ValidationResult) -> None:
        sev = r.adjusted_severity.lower()
        f = r.finding

        # Compute confidence score
        score = 0.0
        if f.documentation_checked:
            score += 0.10
        if f.prior_audit_checked:
            score += 0.10
        if f.code_is_reachable:
            score += 0.20
        if f.callers_with_untrusted_input:
            score += 0.15
        if f.exploit_scenario and len(f.exploit_scenario) >= 50:
            score += 0.20
        if f.counter_argument and len(f.counter_argument) >= 20:
            score += 0.10
        if not f.is_intentional_tradeoff:
            score += 0.05
        if not f.known_in_prior_audit:
            score += 0.10
        r.confidence_score = min(score, 1.0)

        # Verdict based on adjusted severity + confidence
        if sev in ("critical", "high") and r.confidence_score >= 0.60:
            r.verdict = Verdict.SUBMIT.value
        elif sev == "medium" and r.confidence_score >= 0.50:
            r.verdict = Verdict.SUBMIT.value
        elif sev in ("critical", "high") and r.confidence_score < 0.60:
            r.verdict = Verdict.DOWNGRADE.value
            r.notes.append(
                f"Severity {sev} but confidence only {r.confidence_score:.2f}. "
                f"Gather more evidence or downgrade."
            )
        elif sev == "low":
            if r.confidence_score >= 0.40:
                r.verdict = Verdict.SUBMIT.value
                r.notes.append("Low severity — may not pay bounty but still a valid code fix.")
            else:
                r.verdict = Verdict.HOLD.value
        elif sev == "info":
            r.verdict = Verdict.HOLD.value
            r.notes.append("Info severity — typically not bounty-eligible.")
        else:
            r.verdict = Verdict.HOLD.value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _downgrade_severity(severity: str) -> str:
    """Reduce severity by one level."""
    idx = _SEVERITY_ORDER.index(severity.lower())
    if idx > 0:
        return _SEVERITY_ORDER[idx - 1]
    return severity.lower()


def _cap_severity(current: str, cap: str) -> str:
    """Cap severity at the given maximum level."""
    cur_idx = _SEVERITY_ORDER.index(current.lower())
    cap_idx = _SEVERITY_ORDER.index(cap.lower())
    if cur_idx > cap_idx:
        return cap.lower()
    return current.lower()


# ---------------------------------------------------------------------------
# Pre-audit checklist — agents must complete this BEFORE reporting findings
# ---------------------------------------------------------------------------

PRE_AUDIT_CHECKLIST = """
SOURCE CODE AUDIT — MANDATORY PRE-AUDIT CHECKLIST
===================================================

Before reporting ANY finding, the auditing agent MUST complete ALL of these steps.
Findings that skip these steps will be rejected by the validation pipeline.

1. DOCUMENTATION REVIEW (BLOCKING — do this FIRST)
   □ Read ALL documentation in docs/ directory
   □ Read README.md and any SECURITY.md
   □ Read secure-usage guides, threat models, design docs
   □ Read any prior audit reports (PDF or markdown)
   □ Note all documented security tradeoffs and known limitations
   □ Note all documented error codes and their intended meaning

2. PRIOR AUDIT COMPARISON (BLOCKING)
   □ List all findings from prior audits
   □ For each prior finding, check current fix status in code
   □ Do NOT re-report fixed findings as new
   □ For partially-fixed findings, document specifically what remains broken

3. CODE ARCHITECTURE UNDERSTANDING
   □ Understand the module boundaries and trust model
   □ Identify which inputs come from untrusted parties
   □ Identify which functions are public API vs internal
   □ Understand the build configurations (debug vs release)

4. FOR EACH POTENTIAL FINDING — VALIDATION CHECKLIST
   □ Is this behavior documented as intentional? → CHECK DOCS FIRST
   □ Is the code actually reachable from protocol-level callers? → GREP FOR CALLERS
   □ Are the inputs to the vulnerable path attacker-controlled? → TRACE DATA FLOW
   □ Was this already reported in a prior audit? → CHECK PRIOR FINDINGS
   □ What is the CONCRETE exploit scenario? (not "could potentially...")
   □ What does the attacker need? (network position, valid credentials, etc.)
   □ Write ONE PARAGRAPH arguing why this is NOT a bug (counter-argument)
   □ After writing the counter-argument, do you still believe it's a real bug?

5. SEVERITY ASSIGNMENT RULES
   CRITICAL: Key compromise or RCE with concrete exploit, reachable code, untrusted input
   HIGH:     Exploitable bug with demonstrated impact, reachable code path
   MEDIUM:   Theoretical weakness OR missing validation without demonstrated exploit
   LOW:      Dead/unused code bugs, defense-in-depth issues, non-default configs
   INFO:     Code quality, documentation suggestions, style issues

   NEVER rate a finding Critical or High without:
   - Confirmed reachable code path with untrusted input
   - Concrete exploit scenario (specific steps, not hand-waving)
   - Evidence that behavior is NOT documented/intentional

6. AUTOMATIC DOWNGRADES
   - Documented intentional behavior → REJECT (not a bug)
   - Already known from prior audit (fixed) → REJECT
   - Already known from prior audit (unfixed) → downgrade + reference prior ID
   - Code not reachable from protocol callers → cap at Low
   - No concrete exploit scenario → cap at Medium
   - Only exploitable with debug assertions off → cap at Low
   - Timing side channel without measurements → cap at Medium
"""


# ---------------------------------------------------------------------------
# Agent prompt injection — append this to source audit agent prompts
# ---------------------------------------------------------------------------

AGENT_VALIDATION_PROMPT = """
CRITICAL VALIDATION REQUIREMENTS FOR SOURCE CODE AUDITS
=========================================================

You are auditing source code for a bug bounty program. Your findings will be
validated through a quality gate pipeline. Findings that fail validation are
REJECTED and waste everyone's time.

BEFORE reporting any finding, you MUST:

1. CHECK THE DOCUMENTATION FIRST. Read ALL docs, READMEs, secure-usage guides,
   and prior audit reports. If the behavior you're flagging is documented as
   intentional, IT IS NOT A VULNERABILITY. Do not report it.

2. PROVE REACHABILITY. Grep for all callers of the vulnerable function. If no
   protocol-level code calls it, or if it's only called from tests, it's a
   DEAD CODE BUG at most (Low severity). Never rate dead code as High/Critical.

3. CHECK PRIOR AUDITS. If this library has been professionally audited before,
   compare your findings against the prior audit. Do not re-report known issues
   as new findings.

4. PROVIDE A COUNTER-ARGUMENT. For EVERY finding, write one paragraph arguing
   why it might NOT be a real vulnerability. If you can't argue against your own
   finding, you haven't thought about it hard enough.

5. USE CONCRETE LANGUAGE. Replace:
   - "could potentially lead to" → specific steps an attacker takes
   - "might allow an attacker" → "attacker sends X to Y, receives Z"
   - "theoretically possible" → either prove it or downgrade to Info

6. SEVERITY CAPS (enforced by pipeline):
   - Documented/intentional behavior → REJECTED
   - Dead/unused code → Low max
   - No concrete exploit → Medium max
   - Timing side channels without measurements → Medium max
   - Debug-only issues (cb_assert compiled out) → Low max
   - Known from prior audit → one level below prior severity

WHAT GETS YOU REJECTED:
- Rating something Critical when the docs explicitly describe it as intended
- Rating unused functions as High severity
- Reporting "missing validation" without showing who sends untrusted input
- Theoretical cryptographic weaknesses with no exploit demonstration
- Re-reporting prior audit findings without acknowledging them

Your goal is ACCURACY, not volume. One real Medium is worth more than ten
false-positive Criticals. Be skeptical of your own findings.
"""
