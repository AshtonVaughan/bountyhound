"""
Verification package — Perfect Hunter 2-stage verification pipeline.

Stage A (VerificationChecklist)
    5 deterministic gates every finding must pass:
      Gate 1: REPRODUCIBILITY  — evidence completeness check
      Gate 2: SCOPE            — URL must be in-scope and not blocked
      Gate 3: IMPACT           — impact statement quality check
      Gate 4: SEVERITY FLOOR   — CVSS >= 4.0 (Medium or above)
      Gate 5: DUPLICATE CHECK  — not already found or publicly disclosed

Stage B (Challenger)
    AI self-challenge agent that attempts to disprove a finding using
    4 challenge questions.  Uses Claude API when available; falls back to
    rule-based heuristics with zero external dependencies.
"""

from .checklist import VerificationChecklist, ChecklistInput, ChecklistResult, GateResult
from .challenger import Challenger, ChallengeResult

__all__ = [
    "VerificationChecklist", "ChecklistInput", "ChecklistResult", "GateResult",
    "Challenger", "ChallengeResult",
]
