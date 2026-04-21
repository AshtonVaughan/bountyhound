"""
BountyHound Agent Metrics

Tracks which agents produce real findings vs false positives.
Used to prioritize accurate agents and deprioritize noisy ones.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from engine.core.database import BountyHoundDB

logger = logging.getLogger(__name__)

# Severity string to numeric score mapping
SEVERITY_SCORES: Dict[str, int] = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0,
}


class AgentMetrics:
    """Track precision and performance of each agent to prioritize accurate ones."""

    def __init__(self):
        self._db = BountyHoundDB.get_instance()

    def record_finding(self, agent_name: str, target: str, confirmed: bool,
                       severity: str = 'MEDIUM', time_seconds: int = 0) -> None:
        """Record a finding produced by an agent.

        If agent_name+target combo exists in agent_metrics table, update counts.
        Otherwise, insert a new row.

        Args:
            agent_name: Name of the agent that produced the finding.
            target: Target domain the finding applies to.
            confirmed: True if the finding was confirmed real, False if false positive.
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
            time_seconds: Time the agent spent producing this finding.
        """
        severity_score = SEVERITY_SCORES.get(severity.upper(), 2)

        try:
            with self._db._get_connection() as conn:
                cursor = conn.cursor()

                # Check if row exists for this agent+target pair
                cursor.execute(
                    "SELECT id, findings_produced, findings_confirmed, "
                    "findings_false_positive, avg_severity_score, total_time_seconds "
                    "FROM agent_metrics WHERE agent_name = ? AND target = ?",
                    (agent_name, target)
                )
                row = cursor.fetchone()

                if row:
                    row_dict = dict(row)
                    new_produced = row_dict['findings_produced'] + 1
                    new_confirmed = row_dict['findings_confirmed'] + (1 if confirmed else 0)
                    new_fp = row_dict['findings_false_positive'] + (0 if confirmed else 1)
                    new_time = row_dict['total_time_seconds'] + time_seconds

                    # Recalculate running average severity score
                    old_total = row_dict['avg_severity_score'] * row_dict['findings_produced']
                    new_avg_severity = (old_total + severity_score) / new_produced

                    cursor.execute(
                        "UPDATE agent_metrics SET "
                        "findings_produced = ?, findings_confirmed = ?, "
                        "findings_false_positive = ?, avg_severity_score = ?, "
                        "total_time_seconds = ?, last_run = ? "
                        "WHERE id = ?",
                        (new_produced, new_confirmed, new_fp, new_avg_severity,
                         new_time, datetime.utcnow().isoformat(), row_dict['id'])
                    )
                else:
                    # Insert new row
                    cursor.execute(
                        "INSERT INTO agent_metrics "
                        "(agent_name, target, findings_produced, findings_confirmed, "
                        "findings_false_positive, avg_severity_score, total_time_seconds, last_run) "
                        "VALUES (?, ?, 1, ?, ?, ?, ?, ?)",
                        (agent_name, target,
                         1 if confirmed else 0,
                         0 if confirmed else 1,
                         float(severity_score),
                         time_seconds,
                         datetime.utcnow().isoformat())
                    )
        except Exception as e:
            logger.error("Failed to record finding for agent '%s' on '%s': %s",
                         agent_name, target, e)

    def get_agent_stats(self, agent_name: str) -> Dict:
        """Get aggregate stats across all targets for an agent.

        Args:
            agent_name: Name of the agent.

        Returns:
            Dictionary with aggregated metrics:
                agent_name, total_findings, confirmed, false_positives,
                precision, avg_severity, targets_tested, total_time_hours.
        """
        try:
            with self._db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT "
                    "  SUM(findings_produced) AS total_findings, "
                    "  SUM(findings_confirmed) AS confirmed, "
                    "  SUM(findings_false_positive) AS false_positives, "
                    "  AVG(avg_severity_score) AS avg_severity, "
                    "  COUNT(DISTINCT target) AS targets_tested, "
                    "  SUM(total_time_seconds) AS total_time_seconds "
                    "FROM agent_metrics WHERE agent_name = ?",
                    (agent_name,)
                )
                row = cursor.fetchone()

                if row is None or row['total_findings'] is None:
                    return {
                        'agent_name': agent_name,
                        'total_findings': 0,
                        'confirmed': 0,
                        'false_positives': 0,
                        'precision': 0.0,
                        'avg_severity': 0.0,
                        'targets_tested': 0,
                        'total_time_hours': 0.0,
                    }

                row_dict = dict(row)
                total_findings = row_dict['total_findings'] or 0
                confirmed = row_dict['confirmed'] or 0
                false_positives = row_dict['false_positives'] or 0
                denominator = confirmed + false_positives

                return {
                    'agent_name': agent_name,
                    'total_findings': total_findings,
                    'confirmed': confirmed,
                    'false_positives': false_positives,
                    'precision': (confirmed / denominator) if denominator > 0 else 0.0,
                    'avg_severity': row_dict['avg_severity'] or 0.0,
                    'targets_tested': row_dict['targets_tested'] or 0,
                    'total_time_hours': (row_dict['total_time_seconds'] or 0) / 3600.0,
                }
        except Exception as e:
            logger.error("Failed to get stats for agent '%s': %s", agent_name, e)
            return {
                'agent_name': agent_name,
                'total_findings': 0,
                'confirmed': 0,
                'false_positives': 0,
                'precision': 0.0,
                'avg_severity': 0.0,
                'targets_tested': 0,
                'total_time_hours': 0.0,
            }

    def get_all_agents(self) -> List[Dict]:
        """Get stats for all agents, sorted by precision descending.

        Returns:
            List of stat dictionaries, one per agent, ordered by precision DESC.
        """
        try:
            with self._db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT DISTINCT agent_name FROM agent_metrics ORDER BY agent_name"
                )
                agent_names = [row['agent_name'] for row in cursor.fetchall()]

            results = [self.get_agent_stats(name) for name in agent_names]
            results.sort(key=lambda s: s['precision'], reverse=True)
            return results
        except Exception as e:
            logger.error("Failed to get all agent stats: %s", e)
            return []

    def get_best_agents(self, min_findings: int = 3) -> List[Dict]:
        """Get agents with highest precision (minimum N findings for statistical significance).

        Args:
            min_findings: Minimum number of total findings required (default 3).

        Returns:
            List of agent stats sorted by precision DESC, filtered to min_findings.
        """
        all_agents = self.get_all_agents()
        qualified = [a for a in all_agents if a['total_findings'] >= min_findings]
        return sorted(qualified, key=lambda s: s['precision'], reverse=True)

    def get_worst_agents(self, min_findings: int = 3) -> List[Dict]:
        """Get agents with lowest precision (potential candidates for deprioritizing).

        Args:
            min_findings: Minimum number of total findings required (default 3).

        Returns:
            List of agent stats sorted by precision ASC, filtered to min_findings.
        """
        all_agents = self.get_all_agents()
        qualified = [a for a in all_agents if a['total_findings'] >= min_findings]
        return sorted(qualified, key=lambda s: s['precision'])

    def should_use_agent(self, agent_name: str) -> Dict:
        """Recommend whether to use an agent based on track record.

        Args:
            agent_name: Name of the agent.

        Returns:
            Dictionary with:
                use: bool - whether to use the agent
                reason: str - explanation
                precision: float - current precision score
        """
        stats = self.get_agent_stats(agent_name)
        total = stats['total_findings']
        precision = stats['precision']

        if total < 3:
            return {
                'use': True,
                'reason': 'insufficient data (fewer than 3 findings)',
                'precision': precision,
            }

        if precision >= 0.5:
            return {
                'use': True,
                'reason': f'good track record ({precision:.0%} precision)',
                'precision': precision,
            }

        if 0.25 <= precision < 0.5:
            return {
                'use': True,
                'reason': f'warning: mediocre precision ({precision:.0%}), use with extra validation',
                'precision': precision,
            }

        # precision < 0.25
        return {
            'use': False,
            'reason': f'consistently produces false positives ({precision:.0%} precision)',
            'precision': precision,
        }

    def leaderboard(self) -> str:
        """Generate formatted leaderboard string for display.

        Returns:
            Multi-line string showing agents ranked by precision, plus
            a DEPRIORITIZE section for low-precision agents.
        """
        all_agents = self.get_all_agents()

        if not all_agents:
            return "Agent Precision Leaderboard\n===========================\nNo agent data recorded yet."

        lines = [
            "Agent Precision Leaderboard",
            "===========================",
        ]

        good_agents: List[Dict] = []
        bad_agents: List[Dict] = []

        for agent in all_agents:
            total = agent['total_findings']
            if total < 1:
                continue
            if agent['precision'] < 0.25 and total >= 3:
                bad_agents.append(agent)
            else:
                good_agents.append(agent)

        # Ranked list (already sorted by precision DESC from get_all_agents)
        for rank, agent in enumerate(good_agents, start=1):
            confirmed = agent['confirmed']
            total = agent['confirmed'] + agent['false_positives']
            pct = agent['precision'] * 100
            name = agent['agent_name']
            lines.append(
                f"{rank:>2}. {name:<25} {pct:>3.0f}% precision ({confirmed}/{total} confirmed)"
            )

        if bad_agents:
            lines.append("")
            lines.append("DEPRIORITIZE:")
            for agent in bad_agents:
                confirmed = agent['confirmed']
                total = agent['confirmed'] + agent['false_positives']
                pct = agent['precision'] * 100
                name = agent['agent_name']
                lines.append(
                    f"  - {name:<25} {pct:>3.0f}% precision ({confirmed}/{total} confirmed)"
                )

        return "\n".join(lines)
