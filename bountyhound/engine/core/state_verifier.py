"""
State Change Verifier - Prevents false positives by requiring proof of actual state change.

Protocol:
1. READ state (before)
2. ATTEMPT mutation/action
3. READ state (after)
4. COMPARE before vs after
5. Only claim vulnerability if state ACTUALLY changed

This module exists because of the Airbnb 2026-02-14 disaster where 6 findings
were false positives because HTTP 200 + __typename was treated as exploitation.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StateCheckResult:
    changed: bool
    mutation_succeeded: bool = False
    diff: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""


class StateVerifier:
    """Verifies actual state changes to prevent false positives."""

    def compare_states(self, before: Dict, after: Dict, path: str = "") -> StateCheckResult:
        """Deep compare two state snapshots. Returns diff of changes."""
        diff = self._deep_diff(before, after, path)
        return StateCheckResult(
            changed=len(diff) > 0,
            diff=diff,
            reason=f"Found {len(diff)} change(s)" if diff else "No state change detected",
        )

    def verify_mutation(
        self,
        before_state: Dict,
        mutation_response: Dict,
        after_state: Dict,
    ) -> StateCheckResult:
        """Full verification: check mutation response AND actual state change."""
        # Check if mutation response indicates failure
        mutation_succeeded = self._did_mutation_succeed(mutation_response)

        # Compare actual states regardless
        state_diff = self._deep_diff(before_state, after_state)

        return StateCheckResult(
            changed=len(state_diff) > 0,
            mutation_succeeded=mutation_succeeded,
            diff=state_diff,
            reason=self._build_reason(mutation_succeeded, state_diff),
        )

    def verify_from_status_code(self, status_code: int) -> StateCheckResult:
        """HTTP status code alone is NEVER sufficient proof."""
        return StateCheckResult(
            changed=False,
            mutation_succeeded=False,
            diff={},
            reason=f"Insufficient: HTTP {status_code} alone does not prove state change. "
                   f"Must compare before/after state.",
        )

    def _did_mutation_succeed(self, response: Dict) -> bool:
        """Check if a GraphQL/REST mutation actually succeeded."""
        # GraphQL: check for errors
        if "errors" in response and response.get("errors"):
            return False
        # GraphQL: check for null data
        if response.get("data") is None:
            return False
        # REST: check for success:false pattern
        if response.get("success") is False:
            return False
        if response.get("status") in ("error", "failed", "failure"):
            return False
        return True

    def _deep_diff(self, before: Any, after: Any, path: str = "") -> Dict[str, Any]:
        """Recursively diff two objects, returning changed fields."""
        diff = {}
        if type(before) != type(after):
            diff[path or "root"] = {"before": before, "after": after}
            return diff

        if isinstance(before, dict):
            all_keys = set(list(before.keys()) + list(after.keys()))
            for key in all_keys:
                new_path = f"{path}.{key}" if path else key
                if key not in before:
                    diff[new_path] = {"before": None, "after": after[key]}
                elif key not in after:
                    diff[new_path] = {"before": before[key], "after": None}
                else:
                    sub_diff = self._deep_diff(before[key], after[key], new_path)
                    diff.update(sub_diff)
        elif isinstance(before, list):
            if before != after:
                diff[path or "root"] = {"before": before, "after": after}
        else:
            if before != after:
                diff[path or "root"] = {"before": before, "after": after}

        return diff

    def _build_reason(self, mutation_succeeded: bool, diff: Dict) -> str:
        if mutation_succeeded and diff:
            return f"CONFIRMED: Mutation succeeded AND state changed. Diff: {list(diff.keys())}"
        elif mutation_succeeded and not diff:
            return "WARNING: Mutation response looks successful but no state change detected. Possible false positive."
        elif not mutation_succeeded and diff:
            return "ANOMALY: Mutation failed but state changed. Investigate further."
        else:
            return "NOT VULNERABLE: Mutation failed and no state change. This is a false positive."
