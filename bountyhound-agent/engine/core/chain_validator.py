"""
Chain Validator - Verifies multi-step exploit chains work end-to-end.

Prevents inflated severity claims by ensuring every step in a chain is
individually verified and the chain as a whole is practical and reproducible.

Usage:
    from engine.core.chain_validator import ChainValidator

    steps = [
        {'description': 'Create account A', 'verified': True, 'evidence': 'screenshot-1.png',
         'requires_auth': False, 'requires_interaction': False},
        {'description': 'Access B resource as A', 'verified': True, 'evidence': 'curl output',
         'requires_auth': True, 'requires_interaction': False},
    ]
    result = ChainValidator.validate_chain(steps)
    if result['valid']:
        impact = ChainValidator.assess_chain_impact(steps, 'Account takeover')
"""

from datetime import datetime
from typing import Dict, List, Optional


# Severity ordering for comparisons
_SEVERITY_ORDER = {
    'INFO': 0,
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}

_SEVERITY_FROM_SCORE = {v: k for k, v in _SEVERITY_ORDER.items()}


class ChainValidator:
    """Validate exploit chains by checking each step is achievable."""

    @staticmethod
    def validate_chain(steps: List[Dict]) -> Dict:
        """
        Validate an exploit chain.

        Each step dict should contain:
            description (str): What this step does.
            verified (bool): Whether this step has been independently proven.
            evidence (str): File path, curl output, or description of proof.
            requires_auth (bool): Whether this step requires authentication.
            requires_interaction (bool): Whether this step requires victim interaction.

        Returns:
            dict with:
                valid (bool): True only if every step is verified.
                steps_verified (int): Count of verified steps.
                steps_total (int): Total number of steps.
                first_broken_step (Optional[int]): 1-based index of first unverified step.
                chain_strength (float): Ratio of verified to total steps (0.0 to 1.0).
                practical (bool): Whether the chain is realistically exploitable.
                issues (List[str]): Human-readable list of problems found.
        """
        if not steps:
            return {
                'valid': False,
                'steps_verified': 0,
                'steps_total': 0,
                'first_broken_step': None,
                'chain_strength': 0.0,
                'practical': False,
                'issues': ['Chain has no steps'],
            }

        issues: List[str] = []
        steps_total = len(steps)
        steps_verified = 0
        first_broken_step: Optional[int] = None
        practical = True
        auth_established = False

        for idx, step in enumerate(steps):
            step_num = idx + 1  # 1-based for human readability

            # --- Verification check ---
            if step.get('verified', False):
                steps_verified += 1
            else:
                if first_broken_step is None:
                    first_broken_step = step_num
                issues.append(
                    f"Step {step_num} is not verified: {step.get('description', '(no description)')}"
                )

            # --- Evidence check ---
            if not step.get('evidence'):
                issues.append(f"Step {step_num} has no evidence attached")

            # --- Auth dependency check ---
            if step.get('requires_auth', False) and not auth_established:
                issues.append(
                    f"Step {step_num} requires auth but no prior step establishes it"
                )
                practical = False

            # Track whether a future step can rely on auth
            desc_lower = step.get('description', '').lower()
            if any(kw in desc_lower for kw in ('login', 'authenticate', 'create account',
                                                 'register', 'get token', 'obtain session',
                                                 'sign in', 'auth')):
                auth_established = True

            # --- Interaction in non-first step ---
            if step.get('requires_interaction', False) and idx > 0:
                issues.append(
                    f"Step {step_num} requires victim interaction mid-chain "
                    f"(reduces practicality)"
                )
                practical = False

        # --- Complexity warning ---
        if steps_total > 5:
            issues.append(
                f"Complex chain with {steps_total} steps — may be impractical to reproduce"
            )

        chain_strength = steps_verified / steps_total if steps_total > 0 else 0.0
        valid = (steps_verified == steps_total) and steps_total > 0

        return {
            'valid': valid,
            'steps_verified': steps_verified,
            'steps_total': steps_total,
            'first_broken_step': first_broken_step,
            'chain_strength': round(chain_strength, 4),
            'practical': practical,
            'issues': issues,
        }

    @staticmethod
    def assess_chain_impact(steps: List[Dict], final_impact: str) -> Dict:
        """
        Assess the combined impact of a chain.

        Determines whether chaining multiple lower-severity findings justifies
        escalating the overall severity in a report.

        Args:
            steps: The chain steps (same format as validate_chain).
            final_impact: Description of what the attacker ultimately achieves.

        Returns:
            dict with:
                original_severity (str): Highest individual step severity.
                chain_severity (str): Escalated severity considering the chain.
                escalation_justified (bool): Whether the escalation is defensible.
                reason (str): Human-readable explanation.
        """
        if not steps:
            return {
                'original_severity': 'INFO',
                'chain_severity': 'INFO',
                'escalation_justified': False,
                'reason': 'No steps provided — cannot assess impact',
            }

        # Collect individual severities from steps (default to LOW if missing)
        severities: List[str] = []
        for step in steps:
            sev = step.get('severity', 'LOW').upper()
            if sev not in _SEVERITY_ORDER:
                sev = 'LOW'
            severities.append(sev)

        severity_scores = [_SEVERITY_ORDER[s] for s in severities]
        max_score = max(severity_scores)
        original_severity = _SEVERITY_FROM_SCORE.get(max_score, 'LOW')

        # --- Escalation rules ---
        #
        # LOW + LOW = still LOW (no escalation)
        # LOW + MEDIUM = MEDIUM (minor escalation)
        # MEDIUM + MEDIUM -> HIGH (only if state change proven in chain)
        # Any step HIGH or CRITICAL -> at least HIGH

        has_state_change_proof = any(
            step.get('verified', False) and step.get('evidence')
            for step in steps
        )

        all_low = all(s == _SEVERITY_ORDER['LOW'] for s in severity_scores)
        has_medium = any(s == _SEVERITY_ORDER['MEDIUM'] for s in severity_scores)
        has_high_or_crit = any(s >= _SEVERITY_ORDER['HIGH'] for s in severity_scores)
        medium_count = sum(1 for s in severity_scores if s == _SEVERITY_ORDER['MEDIUM'])

        if has_high_or_crit:
            # Any HIGH or CRITICAL step means at least HIGH for the chain
            chain_score = max(max_score, _SEVERITY_ORDER['HIGH'])
            chain_severity = _SEVERITY_FROM_SCORE.get(chain_score, 'HIGH')
            escalation_justified = chain_score > max_score
            reason = (
                f"Chain contains HIGH/CRITICAL step(s). "
                f"Chain severity: {chain_severity}. Impact: {final_impact}"
            )
        elif medium_count >= 2 and has_state_change_proof:
            # Two or more MEDIUMs with proven state change -> HIGH
            chain_severity = 'HIGH'
            escalation_justified = True
            reason = (
                f"Multiple MEDIUM findings with verified state change "
                f"escalate to HIGH. Impact: {final_impact}"
            )
        elif has_medium:
            # LOW + MEDIUM = MEDIUM (no escalation beyond what's already there)
            chain_severity = 'MEDIUM'
            escalation_justified = (original_severity == 'LOW')
            reason = (
                f"Chain combines LOW and MEDIUM findings. "
                f"Overall: MEDIUM. Impact: {final_impact}"
            )
        elif all_low:
            # LOW + LOW = still LOW
            chain_severity = 'LOW'
            escalation_justified = False
            reason = (
                f"All steps are LOW severity. Chaining does not escalate. "
                f"Impact: {final_impact}"
            )
        else:
            # Fallback: INFO-level chain
            chain_severity = original_severity
            escalation_justified = False
            reason = f"No escalation applicable. Impact: {final_impact}"

        return {
            'original_severity': original_severity,
            'chain_severity': chain_severity,
            'escalation_justified': escalation_justified,
            'reason': reason,
        }

    @staticmethod
    def format_chain_report(chain_name: str, steps: List[Dict], validation: Dict) -> str:
        """
        Format a chain validation result as a markdown report.

        Args:
            chain_name: Human-readable name for this exploit chain.
            steps: The chain steps.
            validation: Output of validate_chain().

        Returns:
            Markdown-formatted string suitable for inclusion in a report.
        """
        lines: List[str] = []
        lines.append(f"## Exploit Chain: {chain_name}")
        lines.append("")

        # Status badge
        status = "VALID" if validation.get('valid') else "BROKEN"
        practical_label = "Practical" if validation.get('practical') else "Impractical"
        lines.append(
            f"**Status**: {status} | "
            f"**Strength**: {validation.get('chain_strength', 0):.0%} | "
            f"**Practical**: {practical_label}"
        )
        lines.append("")

        # Steps table
        lines.append("### Steps")
        lines.append("")
        lines.append("| # | Status | Description | Evidence |")
        lines.append("|---|--------|-------------|----------|")

        for idx, step in enumerate(steps):
            step_num = idx + 1
            check = "[x]" if step.get('verified') else "[ ]"
            desc = step.get('description', '(no description)')
            evidence = step.get('evidence', 'none')
            # Truncate long evidence strings for table readability
            if len(evidence) > 60:
                evidence = evidence[:57] + "..."
            lines.append(f"| {step_num} | {check} | {desc} | {evidence} |")

        lines.append("")

        # Verification summary
        lines.append("### Verification Summary")
        lines.append("")
        lines.append(
            f"- **Steps verified**: {validation.get('steps_verified', 0)}"
            f" / {validation.get('steps_total', 0)}"
        )

        first_broken = validation.get('first_broken_step')
        if first_broken is not None:
            lines.append(f"- **First broken step**: #{first_broken}")

        lines.append(
            f"- **Chain strength**: {validation.get('chain_strength', 0):.0%}"
        )
        lines.append("")

        # Issues
        issues = validation.get('issues', [])
        if issues:
            lines.append("### Issues")
            lines.append("")
            for issue in issues:
                lines.append(f"- {issue}")
            lines.append("")

        # Timestamp
        lines.append(f"*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")

        return "\n".join(lines)
