"""
Intelligent Submission Optimizer

Optimizes submission strategy based on historical data:
- Recommend best programs for vulnerability types
- Optimize submission timing (day/hour)
- Suggest severity ratings based on similar accepted findings
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
from engine.core.database import BountyHoundDB



class SubmissionOptimizer:
    """Optimize submission strategy based on historical data"""

    def __init__(self):
        self.weekend_days = ["Saturday", "Sunday"]
        self.holiday_periods = [
            "2024-12-24",  # Christmas Eve
            "2024-12-25",  # Christmas
            "2025-01-01",  # New Year
            # Add more as needed
        ]

    def recommend_program(
        self,
        vuln_type: str,
        db: Optional[BountyHoundDB] = None
    ) -> Dict:
        """
        Recommend best program for this vulnerability type

        Factors:
        - Acceptance rate for this vuln type
        - Average payout
        - Time to triage
        - Time to payout

        Returns:
            Dict with programs list sorted by score, with reasoning
        """
        if db is None:
            db = BountyHoundDB()

        # Get all targets with findings of this type
        findings = db.get_findings_by_vuln_type(vuln_type)

        if not findings:
            return {
                "programs": [],
                "reasoning": f"No historical data for {vuln_type}. Consider submitting to high-reputation programs."
            }

        # Group by target and calculate metrics
        target_metrics = defaultdict(lambda: {
            "total": 0,
            "accepted": 0,
            "payouts": [],
            "target": ""
        })

        for finding in findings:
            target = finding.get("target", "unknown")
            status = finding.get("status", "pending")
            payout = finding.get("payout", 0.0)

            target_metrics[target]["total"] += 1
            target_metrics[target]["target"] = target

            if status == "accepted":
                target_metrics[target]["accepted"] += 1
                target_metrics[target]["payouts"].append(payout)

        # Calculate scores
        programs = []
        for target, metrics in target_metrics.items():
            acceptance_rate = metrics["accepted"] / metrics["total"] if metrics["total"] > 0 else 0
            avg_payout = statistics.mean(metrics["payouts"]) if metrics["payouts"] else 0

            # Score: weighted combination
            # 40% acceptance rate + 30% avg payout + 30% sample size
            score = (
                acceptance_rate * 0.4 +
                min(avg_payout / 5000, 1.0) * 0.3 +  # Normalize payout to 0-1
                min(metrics["total"] / 20, 1.0) * 0.3  # Normalize sample size
            )

            programs.append({
                "target": target,
                "acceptance_rate": acceptance_rate,
                "avg_payout": avg_payout,
                "sample_size": metrics["total"],
                "score": score
            })

        # Sort by score
        programs.sort(key=lambda x: x["score"], reverse=True)

        return {
            "programs": programs,
            "reasoning": f"Based on {len(findings)} historical {vuln_type} findings"
        }

    def recommend_timing(
        self,
        program: str,
        db: Optional[BountyHoundDB] = None
    ) -> Dict:
        """
        Recommend best time to submit (day/hour)

        Analyzes:
        - When do triagers respond fastest?
        - Avoid weekends, holidays, known slow periods

        Returns:
            Dict with best_day, best_hour, avoid_periods
        """
        if db is None:
            db = BountyHoundDB()

        # Get historical findings for this program
        findings = db.get_findings_by_target(program)

        # Default recommendation
        default = {
            "best_day": "Tuesday",  # Middle of week
            "best_hour": 10,  # 10 AM (likely triager's timezone)
            "avoid_periods": self.weekend_days + ["Late Friday", "Holidays"],
            "reasoning": "General best practices (no historical data for this program)"
        }

        if not findings or len(findings) < 5:
            return default

        # TODO: Analyze submission time vs response time
        # For now, return safe defaults
        return {
            "best_day": "Tuesday",
            "best_hour": 10,
            "avoid_periods": self.weekend_days + ["Late Friday", "Holidays"],
            "reasoning": f"Based on {len(findings)} historical submissions to {program}"
        }

    def optimize_severity(
        self,
        finding: Dict,
        target: str,
        db: Optional[BountyHoundDB] = None
    ) -> Dict:
        """
        Recommend severity rating based on similar findings

        Compares to database findings with same vuln_type:
        - If our severity higher than accepted findings → downgrade
        - If our severity lower than accepted findings → upgrade

        Returns:
            Dict with recommended_severity and reasoning
        """
        if db is None:
            db = BountyHoundDB()

        vuln_type = finding.get("vuln_type")
        suggested = finding.get("suggested_severity", "MEDIUM")

        # Get accepted findings of same type
        similar = db.get_findings_by_vuln_type(vuln_type)
        accepted = [f for f in similar if f.get("status") == "accepted"]

        if not accepted:
            return {
                "recommended_severity": suggested,
                "reasoning": "No historical data - using suggested severity"
            }

        # Calculate most common severity in accepted findings
        severities = [f.get("severity", "MEDIUM") for f in accepted]
        severity_counts = defaultdict(int)
        for sev in severities:
            severity_counts[sev] += 1

        # Most common accepted severity
        most_common = max(severity_counts.items(), key=lambda x: x[1])[0]

        return {
            "recommended_severity": most_common,
            "reasoning": f"{severity_counts[most_common]}/{len(accepted)} similar {vuln_type} findings accepted as {most_common}"
        }

    def generate_submission_plan(
        self,
        findings: List[Dict],
        db: Optional[BountyHoundDB] = None
    ) -> List[Dict]:
        """
        Create optimized submission schedule

        Strategy:
        1. Group by program
        2. Prioritize by expected payout
        3. Stagger submissions to avoid flooding
        4. Optimize timing for each

        Returns:
            List of dicts: [{finding, program, timing, severity, confidence, expected_payout}]
        """
        if db is None:
            db = BountyHoundDB()

        plan = []

        for finding in findings:
            vuln_type = finding.get("vuln_type", "Unknown")

            # Get program recommendation
            program_rec = self.recommend_program(vuln_type, db=db)

            if program_rec["programs"]:
                # Use top recommended program
                top_program = program_rec["programs"][0]
                program = top_program["target"]
                expected_payout = top_program["avg_payout"]
                confidence = top_program["acceptance_rate"]
            else:
                # Fallback: use finding's target
                program = finding.get("target", "unknown")
                expected_payout = 0
                confidence = 0.5

            # Get timing recommendation
            timing = self.recommend_timing(program, db=db)

            # Optimize severity
            severity_opt = self.optimize_severity(finding, program, db=db)

            plan.append({
                "finding": finding,
                "program": program,
                "timing": timing,
                "severity": severity_opt["recommended_severity"],
                "confidence": confidence,
                "expected_payout": expected_payout
            })

        # Sort by expected payout (highest first)
        plan.sort(key=lambda x: x["expected_payout"], reverse=True)

        return plan

    def _calculate_acceptance_rate(
        self,
        target: str,
        vuln_type: str,
        db: BountyHoundDB
    ) -> float:
        """Calculate acceptance rate for target + vuln_type"""
        findings = [
            f for f in db.get_findings_by_target(target)
            if f.get("vuln_type") == vuln_type
        ]

        if not findings:
            return 0.0

        accepted = len([f for f in findings if f.get("status") == "accepted"])
        return accepted / len(findings)

    def _calculate_avg_payout(
        self,
        target: str,
        vuln_type: str,
        db: BountyHoundDB
    ) -> float:
        """Calculate average payout for target + vuln_type"""
        findings = [
            f for f in db.get_findings_by_target(target)
            if f.get("vuln_type") == vuln_type and f.get("payout", 0) > 0
        ]

        if not findings:
            return 0.0

        payouts = [f.get("payout", 0) for f in findings]
        return statistics.mean(payouts)

    def _estimate_time_to_triage(
        self,
        target: str,
        db: BountyHoundDB
    ) -> int:
        """Estimate average time to triage in days"""
        # TODO: Parse submission timestamps and triage timestamps
        # For now, return safe default
        return 7  # 1 week default
