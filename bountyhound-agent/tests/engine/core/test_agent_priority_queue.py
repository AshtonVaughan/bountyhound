"""
Tests for Agent Priority Queue system.

Tests verify that agents are properly scored and sorted by priority based on:
- Track record (historical accuracy finding real vulns)
- Confidence output (does agent report confidence scores?)
- Speed (execution time)
- Stack-specificity (matches target's detected tech stack)
"""

import pytest
from engine.core.agent_priority_queue import (
    AgentScore,
    AgentPriorityQueue,
)


@pytest.fixture
def priority_queue():
    """Create a fresh priority queue for each test."""
    return AgentPriorityQueue()


class TestPriorityScoreCalculation:
    """Test that priority scores are calculated correctly."""

    def test_priority_score_calculation(self, priority_queue):
        """Verify scores combine correctly from all components."""
        # Mock agent stats
        agent_stats = {
            'sqlmap_injection': {
                'track_record': 38,
                'confidence_output': True,
                'speed': 25,  # < 30s = 20 pts
                'stack_specificity_matched': False,
            },
            'nuclei_scan': {
                'track_record': 35,
                'confidence_output': True,
                'speed': 45,  # < 60s = 15 pts
                'stack_specificity_matched': False,
            },
            'ffuf_fuzzer': {
                'track_record': 18,
                'confidence_output': False,
                'speed': 180,  # > 120s = 5 pts
                'stack_specificity_matched': False,
            },
        }

        # Mock profile (no stack specificity bonuses)
        profile = {
            'detected_tech': [],
        }

        scores = priority_queue.calculate_scores(agent_stats, profile)

        # Verify scores exist for all agents
        assert 'sqlmap_injection' in scores
        assert 'nuclei_scan' in scores
        assert 'ffuf_fuzzer' in scores

        # Verify score components are in expected ranges
        sqlmap_score = scores['sqlmap_injection']
        assert 0 <= sqlmap_score.track_record <= 40
        assert 0 <= sqlmap_score.confidence_output <= 30
        assert 0 <= sqlmap_score.speed <= 20
        assert 0 <= sqlmap_score.stack_specificity <= 10
        assert 0 <= sqlmap_score.total <= 100

        # Verify total score is sum of components
        expected_total = (
            sqlmap_score.track_record +
            sqlmap_score.confidence_output +
            sqlmap_score.speed +
            sqlmap_score.stack_specificity
        )
        assert sqlmap_score.total == expected_total

        # Verify ordering: sqlmap > nuclei > ffuf
        sqlmap_total = scores['sqlmap_injection'].total
        nuclei_total = scores['nuclei_scan'].total
        ffuf_total = scores['ffuf_fuzzer'].total

        assert sqlmap_total > nuclei_total, "sqlmap should score higher than nuclei"
        assert nuclei_total > ffuf_total, "nuclei should score higher than ffuf"

    def test_track_record_scoring(self, priority_queue):
        """Verify track record scores are correct."""
        agent_stats = {
            'sqlmap_injection': {
                'track_record': 38,
                'confidence_output': False,
                'speed': 30,
                'stack_specificity_matched': False,
            },
            'unknown_agent': {
                'track_record': 15,  # Default for unknown
                'confidence_output': False,
                'speed': 30,
                'stack_specificity_matched': False,
            },
        }

        profile = {'detected_tech': []}
        scores = priority_queue.calculate_scores(agent_stats, profile)

        assert scores['sqlmap_injection'].track_record == 38
        assert scores['unknown_agent'].track_record == 15

    def test_confidence_output_scoring(self, priority_queue):
        """Verify confidence output is scored as 30 or 0."""
        agent_stats = {
            'with_confidence': {
                'track_record': 10,
                'confidence_output': True,
                'speed': 30,
                'stack_specificity_matched': False,
            },
            'without_confidence': {
                'track_record': 10,
                'confidence_output': False,
                'speed': 30,
                'stack_specificity_matched': False,
            },
        }

        profile = {'detected_tech': []}
        scores = priority_queue.calculate_scores(agent_stats, profile)

        assert scores['with_confidence'].confidence_output == 30
        assert scores['without_confidence'].confidence_output == 0

    def test_speed_scoring(self, priority_queue):
        """Verify speed scoring is correct."""
        agent_stats = {
            'fast': {
                'track_record': 10,
                'confidence_output': False,
                'speed': 20,  # < 30s = 20 pts
                'stack_specificity_matched': False,
            },
            'medium': {
                'track_record': 10,
                'confidence_output': False,
                'speed': 50,  # < 60s = 15 pts
                'stack_specificity_matched': False,
            },
            'slower': {
                'track_record': 10,
                'confidence_output': False,
                'speed': 90,  # < 120s = 10 pts
                'stack_specificity_matched': False,
            },
            'slow': {
                'track_record': 10,
                'confidence_output': False,
                'speed': 150,  # > 120s = 5 pts
                'stack_specificity_matched': False,
            },
        }

        profile = {'detected_tech': []}
        scores = priority_queue.calculate_scores(agent_stats, profile)

        assert scores['fast'].speed == 20
        assert scores['medium'].speed == 15
        assert scores['slower'].speed == 10
        assert scores['slow'].speed == 5


class TestPrioritySorting:
    """Test that agents are sorted correctly by priority."""

    def test_priority_sorting(self, priority_queue):
        """Verify agents are sorted descending by score."""
        # Create agents with specific scores
        agent_stats = {
            'agent_a': {
                'track_record': 30,
                'confidence_output': True,
                'speed': 20,
                'stack_specificity_matched': False,
            },
            'agent_b': {
                'track_record': 25,
                'confidence_output': True,
                'speed': 30,
                'stack_specificity_matched': False,
            },
            'agent_c': {
                'track_record': 10,
                'confidence_output': False,
                'speed': 100,
                'stack_specificity_matched': False,
            },
            'agent_d': {
                'track_record': 28,
                'confidence_output': True,
                'speed': 25,
                'stack_specificity_matched': False,
            },
        }

        profile = {'detected_tech': []}
        scores = priority_queue.calculate_scores(agent_stats, profile)
        sorted_agents = priority_queue.sort_by_priority(scores)

        # Verify all agents are present
        assert len(sorted_agents) == 4

        # Verify agents are sorted by total score descending
        for i in range(len(sorted_agents) - 1):
            current_score = scores[sorted_agents[i]].total
            next_score = scores[sorted_agents[i + 1]].total
            assert current_score >= next_score, (
                f"{sorted_agents[i]} ({current_score}) should be >= "
                f"{sorted_agents[i + 1]} ({next_score})"
            )

    def test_sort_returns_agent_names(self, priority_queue):
        """Verify sort returns agent names in correct order."""
        agent_stats = {
            'agent_x': {
                'track_record': 40,
                'confidence_output': True,
                'speed': 10,
                'stack_specificity_matched': False,
            },
            'agent_y': {
                'track_record': 20,
                'confidence_output': False,
                'speed': 50,
                'stack_specificity_matched': False,
            },
        }

        profile = {'detected_tech': []}
        scores = priority_queue.calculate_scores(agent_stats, profile)
        sorted_agents = priority_queue.sort_by_priority(scores)

        assert isinstance(sorted_agents, list)
        assert all(isinstance(name, str) for name in sorted_agents)
        assert sorted_agents[0] == 'agent_x'
        assert sorted_agents[1] == 'agent_y'


class TestStackSpecificityBonus:
    """Test that stack-specific agents get bonus points."""

    def test_stack_specificity_bonus_django(self, priority_queue):
        """Verify Django auditor gets +10 bonus on Django target."""
        agent_stats = {
            'django_auditor': {
                'track_record': 20,
                'confidence_output': True,
                'speed': 30,
                'stack_specificity_matched': True,  # Matched!
            },
            'sqlmap_injection': {
                'track_record': 38,
                'confidence_output': True,
                'speed': 25,
                'stack_specificity_matched': False,  # Not matched
            },
        }

        profile = {
            'detected_tech': ['has_django'],
        }

        scores = priority_queue.calculate_scores(agent_stats, profile)

        # Django auditor should get +10 bonus
        django_bonus = scores['django_auditor'].stack_specificity
        sqlmap_bonus = scores['sqlmap_injection'].stack_specificity

        assert django_bonus == 10, "django_auditor should get +10 for matching Django"
        assert sqlmap_bonus == 0, "sqlmap_injection should get 0 (not stack-specific)"

    def test_stack_specificity_bonus_graphql(self, priority_queue):
        """Verify GraphQL tester gets +10 bonus on GraphQL target."""
        agent_stats = {
            'graphql_tester': {
                'track_record': 25,
                'confidence_output': True,
                'speed': 40,
                'stack_specificity_matched': True,
            },
            'api_fuzzer': {
                'track_record': 20,
                'confidence_output': False,
                'speed': 50,
                'stack_specificity_matched': False,
            },
        }

        profile = {
            'detected_tech': ['has_graphql'],
        }

        scores = priority_queue.calculate_scores(agent_stats, profile)

        assert scores['graphql_tester'].stack_specificity == 10
        assert scores['api_fuzzer'].stack_specificity == 0

    def test_no_bonus_when_not_matched(self, priority_queue):
        """Verify no bonus is given when stack doesn't match."""
        agent_stats = {
            'aws_scanner': {
                'track_record': 30,
                'confidence_output': True,
                'speed': 35,
                'stack_specificity_matched': False,  # No match
            },
        }

        profile = {
            'detected_tech': ['has_django'],  # Django target, AWS scanner isn't matched
        }

        scores = priority_queue.calculate_scores(agent_stats, profile)

        assert scores['aws_scanner'].stack_specificity == 0

    def test_multiple_stack_bonuses(self, priority_queue):
        """Verify multiple agents can get stack bonuses."""
        agent_stats = {
            'graphql_tester': {
                'track_record': 25,
                'confidence_output': True,
                'speed': 40,
                'stack_specificity_matched': True,
            },
            'websocket_tester': {
                'track_record': 22,
                'confidence_output': True,
                'speed': 50,
                'stack_specificity_matched': True,
            },
            'generic_agent': {
                'track_record': 20,
                'confidence_output': False,
                'speed': 60,
                'stack_specificity_matched': False,
            },
        }

        profile = {
            'detected_tech': ['has_graphql', 'has_websocket'],
        }

        scores = priority_queue.calculate_scores(agent_stats, profile)

        assert scores['graphql_tester'].stack_specificity == 10
        assert scores['websocket_tester'].stack_specificity == 10
        assert scores['generic_agent'].stack_specificity == 0


class TestExecutionOrder:
    """Test getting complete execution order."""

    def test_get_execution_order(self, priority_queue):
        """Verify get_execution_order returns sorted agents."""
        agent_stats = {
            'agent_1': {
                'track_record': 35,
                'confidence_output': True,
                'speed': 20,
                'stack_specificity_matched': False,
            },
            'agent_2': {
                'track_record': 20,
                'confidence_output': False,
                'speed': 50,
                'stack_specificity_matched': False,
            },
        }

        profile = {'detected_tech': []}

        execution_order = priority_queue.get_execution_order(agent_stats, profile)

        assert isinstance(execution_order, list)
        assert len(execution_order) == 2
        assert execution_order[0] == 'agent_1'
        assert execution_order[1] == 'agent_2'

    def test_execution_order_with_stack_specificity(self, priority_queue):
        """Verify execution order respects stack-specific bonuses."""
        agent_stats = {
            'generic_high_score': {
                'track_record': 40,
                'confidence_output': True,
                'speed': 10,
                'stack_specificity_matched': False,
            },
            'django_auditor': {
                'track_record': 20,
                'confidence_output': True,
                'speed': 30,
                'stack_specificity_matched': True,  # Gets +10
            },
        }

        profile = {'detected_tech': ['has_django']}

        execution_order = priority_queue.get_execution_order(agent_stats, profile)

        # generic_high_score: 40 + 30 + 15 + 0 = 85
        # django_auditor: 20 + 30 + 15 + 10 = 75
        # generic_high_score should still be first
        assert execution_order[0] == 'generic_high_score'
        assert execution_order[1] == 'django_auditor'
