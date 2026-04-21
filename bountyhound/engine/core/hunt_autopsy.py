"""
Hunt Autopsy - Post-hunt analysis to learn from failures.

After every hunt, this module examines what went wrong (and right) by
analyzing findings, false positive rates, time spent, and estimated
bounty return.  It generates actionable recommendations, discovers
new false positive patterns, and grades the hunt on an A-F scale.

Usage:
    from engine.core.hunt_autopsy import HuntAutopsy

    autopsy = HuntAutopsy('example.com')
    report = autopsy.analyze()
    print(f"Grade: {report['grade']}, FP rate: {report['false_positive_rate']:.0%}")

    # Save markdown report
    filepath = autopsy.save_report()
"""

import json
import logging
import os
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class HuntAutopsy:
    """Analyze completed hunts to learn from failures and improve future performance."""

    # Severity -> estimated dollar value for hourly rate calculation
    _SEVERITY_VALUE = {
        'CRITICAL': 10000.0,
        'HIGH': 3000.0,
        'MEDIUM': 1000.0,
        'LOW': 250.0,
        'INFO': 50.0,
    }

    # False-positive category labels
    FP_CATEGORIES = (
        'no_state_change',
        'error_misinterpreted',
        'info_only',
        'not_exploitable',
        'out_of_scope',
        'intended_functionality',
    )

    def __init__(self, target: str):
        self.target = target
        self._db = None

    # ---------------------------------------------------------------
    # Database access
    # ---------------------------------------------------------------

    def _get_db(self):
        if self._db is None:
            try:
                from engine.core.database import BountyHoundDB
                self._db = BountyHoundDB.get_instance()
            except Exception as exc:
                logger.warning("Failed to load BountyHoundDB: %s", exc)
        return self._db

    # ---------------------------------------------------------------
    # Primary API
    # ---------------------------------------------------------------

    def analyze(self) -> Dict:
        """
        Run full post-hunt analysis.

        Returns:
            {
                'target': str,
                'hunt_date': str,
                'total_time_minutes': int,
                'findings_produced': int,
                'findings_confirmed': int,
                'findings_false_positive': int,
                'false_positive_rate': float,
                'estimated_bounty': float,
                'hourly_rate': float,
                'failure_reasons': List[str],
                'patterns_to_learn': List[Dict],
                'recommendations': List[str],
                'grade': str,
            }
        """
        try:
            findings = self._load_findings()
            sessions = self._load_sessions()
            agent_metrics = self._load_agent_metrics()

            # Classify findings
            confirmed = [f for f in findings if f.get('status') in ('accepted', 'confirmed', 'triaged')]
            false_positives = [f for f in findings if f.get('status') in ('informative', 'n/a', 'not-applicable', 'false_positive')]
            pending = [f for f in findings if f.get('status') in ('pending', 'new')]

            findings_produced = len(findings)
            findings_confirmed = len(confirmed)
            findings_fp = len(false_positives)

            # FP rate (out of resolved findings, not pending)
            resolved = findings_confirmed + findings_fp
            fp_rate = (findings_fp / resolved) if resolved > 0 else 0.0

            # Time
            total_minutes = self._total_time_minutes(sessions, agent_metrics)

            # Bounty
            actual_bounty = sum(f.get('payout', 0) or 0 for f in confirmed)
            estimated_bounty = actual_bounty if actual_bounty > 0 else self._estimate_bounty(confirmed)

            # Hourly rate
            hourly_rate = self._calculate_hourly_rate(total_minutes, estimated_bounty)

            # Failure analysis
            fp_analysis = self._analyze_false_positives(false_positives)
            failure_reasons = [a['summary'] for a in fp_analysis]

            # Patterns to learn
            patterns_to_learn = self._extract_new_patterns(fp_analysis)

            # Build the analysis dict early so recommendations can reference it
            analysis = {
                'target': self.target,
                'hunt_date': date.today().isoformat(),
                'total_time_minutes': total_minutes,
                'findings_produced': findings_produced,
                'findings_confirmed': findings_confirmed,
                'findings_false_positive': findings_fp,
                'findings_pending': len(pending),
                'false_positive_rate': round(fp_rate, 4),
                'estimated_bounty': round(estimated_bounty, 2),
                'hourly_rate': round(hourly_rate, 2),
                'failure_reasons': failure_reasons,
                'patterns_to_learn': patterns_to_learn,
                'fp_analysis': fp_analysis,
                'agent_metrics': agent_metrics,
                'recommendations': [],
                'grade': 'F',
            }

            analysis['recommendations'] = self._generate_recommendations(analysis)
            analysis['grade'] = self._grade_hunt(analysis)

            return analysis

        except Exception as exc:
            logger.error("Hunt autopsy failed for %s: %s", self.target, exc)
            return {
                'target': self.target,
                'hunt_date': date.today().isoformat(),
                'total_time_minutes': 0,
                'findings_produced': 0,
                'findings_confirmed': 0,
                'findings_false_positive': 0,
                'findings_pending': 0,
                'false_positive_rate': 0.0,
                'estimated_bounty': 0.0,
                'hourly_rate': 0.0,
                'failure_reasons': [f"Autopsy error: {exc}"],
                'patterns_to_learn': [],
                'fp_analysis': [],
                'agent_metrics': [],
                'recommendations': ['Fix autopsy error and re-run.'],
                'grade': 'F',
            }

    def generate_report(self) -> str:
        """Generate a human-readable autopsy report as markdown."""
        analysis = self.analyze()

        lines: List[str] = []
        lines.append(f"# Hunt Autopsy: {analysis['target']}")
        lines.append("")
        lines.append(
            f"**Date**: {analysis['hunt_date']} | "
            f"**Duration**: {analysis['total_time_minutes']} min | "
            f"**Grade**: {analysis['grade']}"
        )
        lines.append("")

        # Results
        lines.append("## Results")
        lines.append("")
        lines.append(
            f"- **Findings produced**: {analysis['findings_produced']}"
        )
        lines.append(
            f"- **Findings confirmed**: {analysis['findings_confirmed']}"
        )
        lines.append(
            f"- **Findings false positive**: {analysis['findings_false_positive']}"
        )
        if analysis.get('findings_pending', 0) > 0:
            lines.append(
                f"- **Findings pending**: {analysis['findings_pending']}"
            )
        lines.append(
            f"- **False positive rate**: {analysis['false_positive_rate']:.0%}"
        )
        lines.append(
            f"- **Estimated bounty**: ${analysis['estimated_bounty']:,.2f}"
        )
        lines.append(
            f"- **Effective hourly rate**: ${analysis['hourly_rate']:,.2f}/hr"
        )
        lines.append("")

        # Failure Analysis
        if analysis['failure_reasons']:
            lines.append("## Failure Analysis")
            lines.append("")
            for reason in analysis['failure_reasons']:
                lines.append(f"- {reason}")
            lines.append("")

        # FP Breakdown
        if analysis.get('fp_analysis'):
            lines.append("## False Positive Breakdown")
            lines.append("")
            lines.append("| Category | Count | Examples |")
            lines.append("|----------|-------|----------|")
            for fp_group in analysis['fp_analysis']:
                examples = ', '.join(fp_group.get('example_titles', [])[:3])
                lines.append(
                    f"| {fp_group['category']} | {fp_group['count']} | {examples} |"
                )
            lines.append("")

        # Agent Performance
        if analysis.get('agent_metrics'):
            lines.append("## Agent Performance")
            lines.append("")
            lines.append("| Agent | Findings | Confirmed | FP | Precision |")
            lines.append("|-------|----------|-----------|-----|-----------|")
            for am in analysis['agent_metrics']:
                precision = am.get('precision')
                prec_str = f"{precision:.0%}" if precision is not None else "N/A"
                lines.append(
                    f"| {am.get('agent_name', '?')} | "
                    f"{am.get('findings_produced', 0)} | "
                    f"{am.get('findings_confirmed', 0)} | "
                    f"{am.get('findings_false_positive', 0)} | "
                    f"{prec_str} |"
                )
            lines.append("")

        # Patterns Learned
        if analysis['patterns_to_learn']:
            lines.append("## Patterns to Learn")
            lines.append("")
            for pattern in analysis['patterns_to_learn']:
                lines.append(f"### {pattern['name']}")
                lines.append(f"- **Type**: {pattern['type']}")
                lines.append(f"- **Description**: {pattern['description']}")
                lines.append(f"- **Indicators**: {', '.join(pattern['indicators'])}")
                lines.append("")

        # Recommendations
        if analysis['recommendations']:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(analysis['recommendations'], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return '\n'.join(lines)

    def save_report(self) -> str:
        """
        Save autopsy report to the findings directory.

        Returns:
            Absolute filepath of the saved report.
        """
        try:
            from engine.core.config import BountyHoundConfig
            findings_dir = BountyHoundConfig.findings_dir(self.target)
        except Exception:
            findings_dir = Path(f"C:/Users/vaugh/BountyHound/findings/{self.target}")

        findings_dir.mkdir(parents=True, exist_ok=True)

        filename = f"AUTOPSY-{date.today().isoformat()}.md"
        filepath = findings_dir / filename

        report_text = self.generate_report()

        try:
            filepath.write_text(report_text, encoding='utf-8')
            logger.info("Saved autopsy report to %s", filepath)
        except Exception as exc:
            logger.error("Failed to save autopsy report: %s", exc)

        return str(filepath)

    @staticmethod
    def get_recent_autopsies(limit: int = 10) -> List[Dict]:
        """
        Get recent autopsy summaries across all targets by scanning
        the findings directory for AUTOPSY-*.md files.
        """
        try:
            from engine.core.config import BountyHoundConfig
            findings_root = BountyHoundConfig.FINDINGS_DIR
        except Exception:
            findings_root = Path("C:/Users/vaugh/BountyHound/findings")

        autopsies: List[Dict] = []

        if not findings_root.exists():
            return autopsies

        try:
            for target_dir in findings_root.iterdir():
                if not target_dir.is_dir():
                    continue
                for f in target_dir.glob("AUTOPSY-*.md"):
                    # Extract date from filename
                    name = f.stem  # e.g. "AUTOPSY-2026-02-18"
                    date_part = name.replace("AUTOPSY-", "")
                    try:
                        autopsy_date = datetime.strptime(date_part, "%Y-%m-%d").date()
                    except ValueError:
                        autopsy_date = None

                    autopsies.append({
                        'target': target_dir.name,
                        'date': date_part,
                        'date_parsed': autopsy_date,
                        'filepath': str(f),
                    })

            # Sort by date descending
            autopsies.sort(
                key=lambda a: a.get('date_parsed') or date.min,
                reverse=True,
            )
            return autopsies[:limit]

        except Exception as exc:
            logger.warning("Failed to scan for autopsies: %s", exc)
            return []

    # ---------------------------------------------------------------
    # Internal: Data loading
    # ---------------------------------------------------------------

    def _load_findings(self) -> List[Dict]:
        """Load all findings for this target from the database."""
        db = self._get_db()
        if db is None:
            return []

        try:
            return db.get_findings_by_target(self.target)
        except Exception as exc:
            logger.warning("Failed to load findings for %s: %s", self.target, exc)
            return []

    def _load_sessions(self) -> List[Dict]:
        """Load testing sessions for this target."""
        db = self._get_db()
        if db is None:
            return []

        try:
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT ts.*
                       FROM testing_sessions ts
                       JOIN targets t ON ts.target_id = t.id
                       WHERE t.domain = ?
                       ORDER BY ts.start_time DESC""",
                    (self.target,),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as exc:
            logger.warning("Failed to load sessions for %s: %s", self.target, exc)
            return []

    def _load_agent_metrics(self) -> List[Dict]:
        """Load agent performance metrics for this target."""
        db = self._get_db()
        if db is None:
            return []

        try:
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT agent_name, target, findings_produced,
                              findings_confirmed, findings_false_positive,
                              precision, avg_severity_score, total_time_seconds,
                              last_run
                       FROM agent_metrics
                       WHERE target = ?
                       ORDER BY findings_produced DESC""",
                    (self.target,),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as exc:
            logger.warning("Failed to load agent metrics for %s: %s", self.target, exc)
            return []

    # ---------------------------------------------------------------
    # Internal: Analysis
    # ---------------------------------------------------------------

    def _analyze_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """
        Categorize false positive findings and extract patterns.

        Returns a list of dicts, one per category:
            {'category': str, 'count': int, 'summary': str, 'example_titles': List[str]}
        """
        if not findings:
            return []

        categorized: Dict[str, List[Dict]] = {}

        for f in findings:
            category = self._classify_fp(f)
            categorized.setdefault(category, []).append(f)

        results: List[Dict] = []
        for category, items in sorted(categorized.items(), key=lambda x: -len(x[1])):
            example_titles = [i.get('title', 'Untitled') for i in items[:5]]
            pct = len(items) / len(findings) if findings else 0
            summary = (
                f"{len(items)} FP(s) in '{category}' "
                f"({pct:.0%} of all FPs): {', '.join(example_titles[:3])}"
            )
            results.append({
                'category': category,
                'count': len(items),
                'percentage': round(pct, 2),
                'summary': summary,
                'example_titles': example_titles,
                'findings': items,
            })

        return results

    def _classify_fp(self, finding: Dict) -> str:
        """Classify a false positive finding into a category."""
        title = (finding.get('title') or '').lower()
        desc = (finding.get('description') or '').lower()
        text = f"{title} {desc}"

        if any(kw in text for kw in ('state change', 'no change', 'unchanged', 'not modified')):
            return 'no_state_change'
        if any(kw in text for kw in ('500', 'error', 'internal', 'grpc', 'unimplemented')):
            return 'error_misinterpreted'
        if any(kw in text for kw in ('info', 'disclosure', 'header', 'version', 'stack trace')):
            return 'info_only'
        if any(kw in text for kw in ('not exploitable', 'theoretical', 'requires', 'chain')):
            return 'not_exploitable'
        if any(kw in text for kw in ('scope', 'out of scope', 'excluded')):
            return 'out_of_scope'
        if any(kw in text for kw in ('intended', 'by design', 'feature', 'expected')):
            return 'intended_functionality'

        return 'error_misinterpreted'  # default bucket

    def _total_time_minutes(
        self,
        sessions: List[Dict],
        agent_metrics: List[Dict],
    ) -> int:
        """Calculate total time spent on this hunt in minutes."""
        total = 0

        # From testing sessions
        for s in sessions:
            duration = s.get('duration_minutes')
            if duration and isinstance(duration, (int, float)):
                total += int(duration)

        # If no sessions, estimate from agent metrics
        if total == 0 and agent_metrics:
            total_seconds = sum(
                am.get('total_time_seconds', 0) or 0 for am in agent_metrics
            )
            total = max(total_seconds // 60, 1) if total_seconds > 0 else 0

        # Fallback: if still 0, assume at least 30 minutes
        if total == 0:
            total = 30

        return total

    def _estimate_bounty(self, confirmed_findings: List[Dict]) -> float:
        """Estimate bounty from confirmed findings that have no payout recorded yet."""
        total = 0.0
        for f in confirmed_findings:
            payout = f.get('payout', 0) or 0
            if payout > 0:
                total += payout
            else:
                severity = (f.get('severity') or 'LOW').upper()
                total += self._SEVERITY_VALUE.get(severity, 250.0)
        return total

    def _calculate_hourly_rate(self, total_minutes: int, total_bounty: float) -> float:
        """Calculate effective hourly rate."""
        if total_minutes <= 0:
            return 0.0
        hours = total_minutes / 60.0
        return total_bounty / hours

    def _extract_new_patterns(self, fp_analysis: List[Dict]) -> List[Dict]:
        """
        Extract potential new false positive patterns from the FP analysis.
        """
        patterns: List[Dict] = []

        for group in fp_analysis:
            if group['count'] < 2:
                continue  # Need at least 2 instances to form a pattern

            category = group['category']
            example_titles = group.get('example_titles', [])

            # Extract common words across example titles
            common_words = self._extract_common_indicators(
                group.get('findings', [])
            )

            if common_words:
                pattern_name = f"{self.target}_{category}_{date.today().isoformat()}"
                patterns.append({
                    'name': pattern_name,
                    'type': category,
                    'description': (
                        f"Learned from {self.target}: {group['count']} false positives "
                        f"in '{category}' category. Examples: "
                        f"{', '.join(example_titles[:3])}"
                    ),
                    'indicators': common_words[:10],
                    'target': self.target,
                })

        return patterns

    def _extract_common_indicators(self, findings: List[Dict]) -> List[str]:
        """Extract words that appear in multiple findings (potential indicators)."""
        if len(findings) < 2:
            return []

        # Collect word frequency across findings
        word_counts: Dict[str, int] = {}
        stop_words = frozenset({
            'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
            'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
            'would', 'could', 'should', 'may', 'might', 'can', 'shall',
            'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from',
            'as', 'into', 'through', 'during', 'before', 'after', 'and',
            'but', 'or', 'nor', 'not', 'so', 'yet', 'both', 'either',
            'neither', 'each', 'every', 'all', 'any', 'few', 'more',
            'most', 'other', 'some', 'such', 'no', 'only', 'same', 'than',
            'too', 'very', 'just', 'because', 'this', 'that', 'these',
            'those', 'it', 'its', 'via', 'http', 'https', 'response',
            'request', 'returned', 'found', 'test', 'tested', 'testing',
        })

        for f in findings:
            text = f"{f.get('title', '')} {f.get('description', '')}".lower()
            words = set(
                w for w in text.split()
                if len(w) > 2 and w not in stop_words and w.isalpha()
            )
            for w in words:
                word_counts[w] = word_counts.get(w, 0) + 1

        # Words that appear in at least half the findings
        threshold = max(len(findings) // 2, 2)
        common = [
            word for word, count in sorted(
                word_counts.items(), key=lambda x: -x[1]
            )
            if count >= threshold
        ]

        return common

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recs: List[str] = []

        fp_rate = analysis.get('false_positive_rate', 0)
        hourly_rate = analysis.get('hourly_rate', 0)
        fp_analysis = analysis.get('fp_analysis', [])
        findings_produced = analysis.get('findings_produced', 0)
        findings_confirmed = analysis.get('findings_confirmed', 0)

        # High FP rate
        if fp_rate > 0.75:
            recs.append(
                f"CRITICAL: {fp_rate:.0%} false positive rate. "
                f"Enforce state change verification on EVERY finding before reporting."
            )
        elif fp_rate > 0.5:
            recs.append(
                f"WARNING: {fp_rate:.0%} false positive rate. "
                f"Add pre-submission validation checks."
            )

        # FP category-specific recs
        for group in fp_analysis:
            cat = group['category']
            count = group['count']
            pct = group.get('percentage', 0)

            if cat == 'error_misinterpreted' and count >= 2:
                recs.append(
                    f"{count} findings ({pct:.0%} of FPs) were errors misinterpreted "
                    f"as vulnerabilities. Add error-type classifiers (gRPC codes, "
                    f"GraphQL errors[], HTTP 5xx)."
                )
            elif cat == 'no_state_change' and count >= 2:
                recs.append(
                    f"{count} findings ({pct:.0%} of FPs) had no verified state change. "
                    f"Enforce the READ-MUTATE-READ-COMPARE protocol on all mutation tests."
                )
            elif cat == 'info_only' and count >= 2:
                recs.append(
                    f"{count} findings ({pct:.0%} of FPs) were info-level disclosures "
                    f"reported as higher severity. Calibrate severity thresholds."
                )
            elif cat == 'not_exploitable' and count >= 1:
                recs.append(
                    f"{count} finding(s) were not exploitable in practice. "
                    f"Require proof-of-concept exploitation before reporting."
                )

        # Hourly rate
        if hourly_rate == 0 and findings_produced > 0:
            recs.append(
                f"Estimated hourly rate: $0/hr. "
                f"Consider switching targets or focusing on higher-impact vulnerability types."
            )
        elif 0 < hourly_rate < 20:
            recs.append(
                f"Effective rate: ${hourly_rate:.0f}/hr is below minimum viable. "
                f"Focus on targets with proven payouts or higher-severity vuln types."
            )

        # Zero confirmed findings
        if findings_produced > 0 and findings_confirmed == 0:
            recs.append(
                "Zero confirmed findings despite producing candidates. "
                "Review the validation pipeline -- findings may not be real."
            )

        # No findings at all
        if findings_produced == 0:
            recs.append(
                "No findings produced. Check if recon was thorough enough, "
                "or if the target's attack surface has changed."
            )

        # Default rec if nothing else
        if not recs:
            recs.append(
                "Hunt performance is acceptable. Continue current approach."
            )

        return recs

    def _grade_hunt(self, analysis: Dict) -> str:
        """
        Grade the hunt A-F based on efficiency.

        A: $100+/hr effective rate AND <10% FP rate
        B: $50-100/hr OR <25% FP rate with confirmed findings
        C: $20-50/hr OR <50% FP rate with confirmed findings
        D: $1-20/hr OR <75% FP rate with some confirmed findings
        F: $0/hr OR >75% FP rate
        """
        hourly = analysis.get('hourly_rate', 0)
        fp_rate = analysis.get('false_positive_rate', 0)
        confirmed = analysis.get('findings_confirmed', 0)

        if hourly >= 100 and fp_rate < 0.10:
            return 'A'
        elif (hourly >= 50 or (fp_rate < 0.25 and confirmed > 0)):
            return 'B'
        elif (hourly >= 20 or (fp_rate < 0.50 and confirmed > 0)):
            return 'C'
        elif (hourly >= 1 or (fp_rate < 0.75 and confirmed > 0)):
            return 'D'
        else:
            return 'F'
