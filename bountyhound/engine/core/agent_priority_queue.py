"""
Agent Priority Queue - Intelligent scoring and prioritization system.

Scores agents by:
- Track record (historical accuracy finding real vulns): 0-40
- Confidence output (does agent report confidence scores?): 0-30
- Speed (execution time): 0-20
- Stack-specificity (matches target's detected tech stack): 0-10

Agents with higher scores run first in hunt execution.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class AgentScore:
    """Score breakdown for a single agent."""
    agent_name: str
    track_record: int = 0          # 0-40: Historical accuracy
    confidence_output: int = 0     # 0-30: Reports confidence scores?
    speed: int = 0                 # 0-20: Execution time
    stack_specificity: int = 0     # 0-10: Matches tech stack?
    total: int = field(init=False) # 0-100: Total priority score

    def __post_init__(self):
        """Calculate total score."""
        self.total = (
            self.track_record +
            self.confidence_output +
            self.speed +
            self.stack_specificity
        )


# Track record scores from design - hardcoded based on historical accuracy
TRACK_RECORD_SCORES: Dict[str, int] = {
    'sqlmap_injection': 38,
    'nuclei_scan': 35,
    'nmap_scanner': 32,
    'bloodhound_enum': 28,
    'metasploit_execute': 25,
    'ffuf_fuzzer': 18,
    'amass_enum': 15,
    'generic_fuzzer': 12,
}
DEFAULT_TRACK_RECORD = 15

# Stack-specific agent bonuses
STACK_BONUSES: Dict[str, Set[str]] = {
    'django_auditor': {'has_django'},
    'aws_scanner': {'has_aws', 'has_s3'},
    'graphql_tester': {'has_graphql'},
    'websocket_tester': {'has_websocket'},
    'mobile_tester': {'has_mobile_app'},
}


class AgentPriorityQueue:
    """
    Priority queue for agent execution ordering.

    Scores and sorts agents based on track record, confidence, speed, and
    stack-specificity to ensure high-value agents run first.
    """

    def __init__(self):
        """Initialize the priority queue."""
        self.scores: Dict[str, AgentScore] = {}

    def calculate_scores(
        self,
        agent_stats: Dict[str, Dict],
        profile: Dict,
    ) -> Dict[str, AgentScore]:
        """
        Calculate priority scores for all agents.

        Args:
            agent_stats: Dict mapping agent_name -> {
                'track_record': int,
                'confidence_output': bool,
                'speed': int (seconds),
                'stack_specificity_matched': bool,
            }
                If empty, returns empty scores dict.
            profile: Dict with 'detected_tech' list containing tech stack tags
                    (e.g., ['has_django', 'has_graphql', 'has_aws'])

        Returns:
            Dict mapping agent_name -> AgentScore. Returns empty dict if agent_stats is empty.
        """
        self.scores = {}

        for agent_name, stats in agent_stats.items():
            # Score track record - use provided value or look up from table
            if 'track_record' in stats:
                track_record = stats['track_record']
            else:
                track_record = self._get_track_record(agent_name)

            # Score confidence output: 30 if True, 0 if False
            confidence_output = 30 if stats.get('confidence_output', False) else 0

            # Score speed
            speed = self._score_speed(stats.get('speed', 120))

            # Score stack-specificity bonus
            stack_bonus = self._get_stack_bonus(agent_name, profile, stats)

            # Create score record
            self.scores[agent_name] = AgentScore(
                agent_name=agent_name,
                track_record=track_record,
                confidence_output=confidence_output,
                speed=speed,
                stack_specificity=stack_bonus,
            )

        return self.scores

    def _get_track_record(self, agent_name: str) -> int:
        """
        Get track record score for an agent.

        Args:
            agent_name: Name of the agent

        Returns:
            Track record score (0-40)
        """
        return TRACK_RECORD_SCORES.get(agent_name, DEFAULT_TRACK_RECORD)

    def _score_speed(self, execution_time_seconds: int) -> int:
        """
        Score execution speed.

        Args:
            execution_time_seconds: Execution time in seconds

        Returns:
            Speed score (0-20)
        """
        # Speed scoring thresholds: <30s=20pts, <60s=15pts, <120s=10pts, >=120s=5pts
        if execution_time_seconds < 30:
            return 20
        elif execution_time_seconds < 60:
            return 15
        elif execution_time_seconds < 120:
            return 10
        else:
            return 5

    def _get_stack_bonus(
        self,
        agent_name: str,
        profile: Dict,
        stats: Dict,
    ) -> int:
        """
        Get stack-specific bonus if agent matches target's tech stack.

        Args:
            agent_name: Name of the agent
            profile: Target profile with 'detected_tech' list
            stats: Agent stats dict with 'stack_specificity_matched' bool

        Returns:
            Stack specificity bonus (10 if matched, 0 otherwise)
        """
        # Check if this agent has stack-specific bonuses defined
        if agent_name not in STACK_BONUSES:
            return 0

        # Check if agent is matched (from stats)
        if not stats.get('stack_specificity_matched', False):
            return 0

        # Verify match is in detected tech (defensive check - even though stats
        # indicates a match, we verify the detected_tech list independently to
        # guard against data inconsistency between caller and profile)
        agent_triggers = STACK_BONUSES[agent_name]
        detected_tech = set(profile.get('detected_tech', []))

        # If any of the agent's triggers are in detected tech, give bonus
        if agent_triggers & detected_tech:
            return 10

        return 0

    def sort_by_priority(
        self,
        scores: Dict[str, AgentScore],
    ) -> List[str]:
        """
        Sort agents by priority (descending by total score).

        Args:
            scores: Dict mapping agent_name -> AgentScore

        Returns:
            List of agent names sorted by priority (highest first)
        """
        return sorted(
            scores.keys(),
            key=lambda name: scores[name].total,
            reverse=True,
        )

    def get_execution_order(
        self,
        agent_stats: Dict[str, Dict],
        profile: Dict,
    ) -> List[str]:
        """
        Get complete execution order for agents.

        Args:
            agent_stats: Dict mapping agent_name -> agent stats
            profile: Target profile with 'detected_tech' list

        Returns:
            List of agent names in execution order (highest priority first)
        """
        self.calculate_scores(agent_stats, profile)
        return self.sort_by_priority(self.scores)

    def print_priority_report(self) -> None:
        """Print detailed priority report for current scores."""
        if not self.scores:
            print("No agents scored yet. Call calculate_scores() first.")
            return

        print("\n" + "=" * 100)
        print("AGENT PRIORITY QUEUE REPORT")
        print("=" * 100)

        # Sort by total score descending
        sorted_scores = sorted(
            self.scores.values(),
            key=lambda s: s.total,
            reverse=True,
        )

        print(f"\n{'Rank':<6} {'Agent':<30} {'Track':<8} {'Conf':<8} {'Speed':<8} {'Stack':<8} {'Total':<8}")
        print("-" * 100)

        for rank, score in enumerate(sorted_scores, 1):
            print(
                f"{rank:<6} {score.agent_name:<30} "
                f"{score.track_record:<8} {score.confidence_output:<8} "
                f"{score.speed:<8} {score.stack_specificity:<8} {score.total:<8}"
            )

        print("=" * 100 + "\n")
