"""
BountyHound Bounty Estimator

Running value counter that estimates total bounty during a hunt.
Provides confidence-weighted estimates based on severity, vuln type,
and verification status.
"""

import logging
from typing import Dict, List, Optional

from engine.core.database import BountyHoundDB

logger = logging.getLogger(__name__)

# Bounty estimation ranges by severity (USD)
BOUNTY_RANGES: Dict[str, Dict[str, int]] = {
    'CRITICAL': {'min': 5000, 'max': 50000, 'typical': 15000},
    'HIGH': {'min': 1000, 'max': 15000, 'typical': 5000},
    'MEDIUM': {'min': 250, 'max': 5000, 'typical': 1000},
    'LOW': {'min': 50, 'max': 500, 'typical': 150},
    'INFO': {'min': 0, 'max': 100, 'typical': 0},
}

# Multipliers by vuln type (some types pay more than others)
VULN_TYPE_MULTIPLIERS: Dict[str, float] = {
    'RCE': 3.0,
    'SQLi': 2.5,
    'SSRF': 2.0,
    'Auth_Bypass': 2.0,
    'IDOR': 1.5,
    'XSS_Stored': 1.5,
    'CSRF': 1.0,
    'XSS_Reflected': 0.8,
    'Info_Disclosure': 0.5,
    'Open_Redirect': 0.3,
    'CORS': 0.3,
}

# Default multiplier for vuln types not in the map
_DEFAULT_MULTIPLIER = 1.0


def _severity_range(severity: str) -> Dict[str, int]:
    """Get bounty range for a severity level, defaulting to MEDIUM."""
    return BOUNTY_RANGES.get(severity.upper(), BOUNTY_RANGES['MEDIUM'])


def _vuln_multiplier(vuln_type: str) -> float:
    """Get multiplier for a vulnerability type, defaulting to 1.0."""
    return VULN_TYPE_MULTIPLIERS.get(vuln_type, _DEFAULT_MULTIPLIER)


def _compute_confidence(verified: bool, state_change_proven: bool) -> float:
    """Compute confidence score from verification signals.

    verified = 0.7 contribution, state_change_proven = 0.3 contribution.
    If neither, base confidence is 0.2.
    """
    confidence = 0.0
    if verified:
        confidence += 0.7
    if state_change_proven:
        confidence += 0.3
    if confidence == 0.0:
        confidence = 0.2
    return min(confidence, 1.0)


class BountyEstimator:
    """Estimate and track running bounty value during a hunt."""

    def __init__(self, target: str):
        """Initialize estimator for a specific target.

        Args:
            target: Target domain being hunted.
        """
        self.target = target
        self._findings: List[Dict] = []

    def add_finding(self, title: str, severity: str, vuln_type: str,
                    verified: bool = False, state_change_proven: bool = False) -> Dict:
        """Add a finding and return its estimated bounty range.

        Args:
            title: Short title of the finding.
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
            vuln_type: Vulnerability type key matching VULN_TYPE_MULTIPLIERS.
            verified: Whether the finding was verified with curl/replay.
            state_change_proven: Whether an actual state change was observed.

        Returns:
            Dictionary with estimated_min, estimated_max, estimated_typical,
            confidence, and adjusted_estimate (typical * confidence).
        """
        try:
            base = _severity_range(severity)
            multiplier = _vuln_multiplier(vuln_type)
            confidence = _compute_confidence(verified, state_change_proven)

            estimated_min = base['min'] * multiplier
            estimated_max = base['max'] * multiplier
            estimated_typical = base['typical'] * multiplier
            adjusted_estimate = estimated_typical * confidence

            finding_entry = {
                'title': title,
                'severity': severity.upper(),
                'vuln_type': vuln_type,
                'verified': verified,
                'state_change_proven': state_change_proven,
                'estimated_min': estimated_min,
                'estimated_max': estimated_max,
                'estimated_typical': estimated_typical,
                'confidence': confidence,
                'adjusted_estimate': adjusted_estimate,
            }
            self._findings.append(finding_entry)

            return {
                'title': title,
                'estimated_min': estimated_min,
                'estimated_max': estimated_max,
                'estimated_typical': estimated_typical,
                'confidence': confidence,
                'adjusted_estimate': adjusted_estimate,
            }
        except Exception as e:
            logger.error("Failed to add finding '%s': %s", title, e)
            return {
                'title': title,
                'estimated_min': 0.0,
                'estimated_max': 0.0,
                'estimated_typical': 0.0,
                'confidence': 0.0,
                'adjusted_estimate': 0.0,
            }

    def get_running_total(self) -> Dict:
        """Get current running total across all findings.

        Returns:
            Dictionary with total_min, total_max, total_typical, total_adjusted,
            finding_count, verified_count, and hourly_rate (0 if no time data).
        """
        if not self._findings:
            return {
                'total_min': 0.0,
                'total_max': 0.0,
                'total_typical': 0.0,
                'total_adjusted': 0.0,
                'finding_count': 0,
                'verified_count': 0,
                'hourly_rate': 0.0,
            }

        total_min = sum(f['estimated_min'] for f in self._findings)
        total_max = sum(f['estimated_max'] for f in self._findings)
        total_typical = sum(f['estimated_typical'] for f in self._findings)
        total_adjusted = sum(f['adjusted_estimate'] for f in self._findings)
        verified_count = sum(1 for f in self._findings if f['verified'])

        return {
            'total_min': total_min,
            'total_max': total_max,
            'total_typical': total_typical,
            'total_adjusted': total_adjusted,
            'finding_count': len(self._findings),
            'verified_count': verified_count,
            'hourly_rate': 0.0,
        }

    def estimate_single(self, severity: str, vuln_type: str,
                        verified: bool = False) -> Dict:
        """Quick estimate for a single finding without tracking it.

        Args:
            severity: Severity level.
            vuln_type: Vulnerability type key.
            verified: Whether the finding is verified.

        Returns:
            Dictionary with estimated_min, estimated_max, estimated_typical,
            confidence, and adjusted_estimate.
        """
        try:
            base = _severity_range(severity)
            multiplier = _vuln_multiplier(vuln_type)
            confidence = _compute_confidence(verified, False)

            estimated_min = base['min'] * multiplier
            estimated_max = base['max'] * multiplier
            estimated_typical = base['typical'] * multiplier
            adjusted_estimate = estimated_typical * confidence

            return {
                'estimated_min': estimated_min,
                'estimated_max': estimated_max,
                'estimated_typical': estimated_typical,
                'confidence': confidence,
                'adjusted_estimate': adjusted_estimate,
            }
        except Exception as e:
            logger.error("Failed to estimate for %s/%s: %s", severity, vuln_type, e)
            return {
                'estimated_min': 0.0,
                'estimated_max': 0.0,
                'estimated_typical': 0.0,
                'confidence': 0.0,
                'adjusted_estimate': 0.0,
            }

    def display_dashboard(self, elapsed_minutes: int = 0) -> str:
        """Generate formatted dashboard string.

        Args:
            elapsed_minutes: Minutes elapsed since hunt started (for rate calc).

        Returns:
            Multi-line box-drawn dashboard string.
        """
        totals = self.get_running_total()
        finding_count = totals['finding_count']
        verified_count = totals['verified_count']
        total_min = totals['total_min']
        total_max = totals['total_max']
        total_adjusted = totals['total_adjusted']

        # Calculate hourly rate if we have time data
        if elapsed_minutes > 0:
            hourly_rate = (total_adjusted / elapsed_minutes) * 60
            rate_line = f"Rate:      ${hourly_rate:,.0f}/hr ({elapsed_minutes} min elapsed)"
        else:
            rate_line = "Rate:      N/A (no elapsed time)"

        # Build the box
        width = 40
        border_top = "\u250c" + "\u2500" * width + "\u2510"
        border_mid = "\u251c" + "\u2500" * width + "\u2524"
        border_bot = "\u2514" + "\u2500" * width + "\u2518"

        def pad(text: str) -> str:
            """Pad text to fit inside the box."""
            return "\u2502 " + text.ljust(width - 1) + "\u2502"

        lines = [border_top]
        lines.append(pad(f"BOUNTY TRACKER: {self.target}"))
        lines.append(border_mid)
        lines.append(pad(f"Findings: {finding_count} ({verified_count} verified)"))
        lines.append(pad(f"Estimated: ${total_min:,.0f} - ${total_max:,.0f}"))
        lines.append(pad(f"Adjusted:  ${total_adjusted:,.0f} (confidence-wtd)"))
        lines.append(pad(rate_line))

        if self._findings:
            lines.append(border_mid)
            for f in self._findings:
                sev = f['severity'][:4].upper()
                title = f['title']
                adj = f['adjusted_estimate']
                # Truncate title if too long to fit
                max_title_len = width - 22  # account for severity tag + estimate
                if len(title) > max_title_len:
                    title = title[:max_title_len - 3] + "..."
                lines.append(pad(f"[{sev}] {title:<{max_title_len}} ~${adj:,.0f}"))

        lines.append(border_bot)
        return "\n".join(lines)

    def reset(self) -> None:
        """Clear current hunt tracking."""
        self._findings.clear()

    @staticmethod
    def estimate_from_history(target: str) -> Dict:
        """Estimate expected bounty based on historical data for this target.

        Queries the findings table for past payouts on this target and computes
        averages and totals.

        Args:
            target: Target domain to look up.

        Returns:
            Dictionary with avg_per_finding, best_finding, and total_earned.
        """
        try:
            db = BountyHoundDB.get_instance()
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT f.payout FROM findings f "
                    "JOIN targets t ON f.target_id = t.id "
                    "WHERE t.domain = ? AND f.payout > 0",
                    (target,)
                )
                rows = cursor.fetchall()

            if not rows:
                return {
                    'avg_per_finding': 0.0,
                    'best_finding': 0.0,
                    'total_earned': 0.0,
                }

            payouts = [row['payout'] for row in rows]
            return {
                'avg_per_finding': sum(payouts) / len(payouts),
                'best_finding': max(payouts),
                'total_earned': sum(payouts),
            }
        except Exception as e:
            logger.error("Failed to estimate from history for '%s': %s", target, e)
            return {
                'avg_per_finding': 0.0,
                'best_finding': 0.0,
                'total_earned': 0.0,
            }
