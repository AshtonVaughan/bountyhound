"""
engine.scoring — endpoint priority scoring for the Perfect Hunter methodology.

Exports
-------
EndpointScore   : dataclass holding all score dimensions for one endpoint
PriorityScorer  : class that scores individual or batches of endpoints
score_endpoints : convenience function for one-shot batch scoring
"""

from engine.scoring.priority_scorer import EndpointScore, PriorityScorer, score_endpoints

__all__ = ["EndpointScore", "PriorityScorer", "score_endpoints"]
