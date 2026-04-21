import re
from typing import Dict, List, Any, Optional

class CommandRouter:
    """Intelligent command router that simplifies BountyHound interface"""

    def __init__(self, api_key: str):
        self.api_key = api_key

        # Command patterns
        self.patterns = {
            r'^/hunt\s+(\S+)': self._route_hunt,
            r'^/test\s+(\S+)(?:\s+--context\s+["\'](.+)["\'])?': self._route_test,
            r'^/learn': self._route_learn,
            r'^/chain': self._route_chain,
            r'^/report(?:\s+(\S+))?': self._route_report,
        }

    def route(self, command: str) -> Dict:
        """Route command to appropriate agent/workflow"""

        for pattern, handler in self.patterns.items():
            match = re.match(pattern, command)
            if match:
                return handler(match)

        return {"type": "unknown", "error": "Unknown command"}

    def _route_hunt(self, match: re.Match) -> Dict:
        """Route to AI-powered continuous learning hunter"""
        target = match.group(1)

        return {
            "type": "ai_hunt",
            "agent": "AIPoweredHunter",
            "target": target,
            "config": {
                "max_iterations": 20,
                "mode": "continuous_learning"
            }
        }

    def _route_test(self, match: re.Match) -> Dict:
        """Route to targeted testing with intelligent agent selection"""
        target = match.group(1)
        context = match.group(2) if match.lastindex >= 2 else None

        # Intelligently select agents based on context
        agents = self._select_agents_from_context(context) if context else ["discovery_engine"]

        return {
            "type": "targeted_test",
            "target": target,
            "context": context,
            "agents": agents
        }

    def _route_learn(self, match: re.Match) -> Dict:
        """Route to pattern extraction and learning"""
        return {
            "type": "extract_patterns",
            "agent": "PatternExtractor"
        }

    def _route_chain(self, match: re.Match) -> Dict:
        """Route to exploit chain discovery"""
        return {
            "type": "find_chains",
            "agent": "ExploitChainer"
        }

    def _route_report(self, match: re.Match) -> Dict:
        """Route to report generation"""
        target = match.group(1) if match.lastindex and match.lastindex >= 1 else None

        return {
            "type": "generate_report",
            "agent": "ReportGenerator",
            "target": target
        }

    def _select_agents_from_context(self, context: str) -> List[str]:
        """Intelligently select agents based on context"""
        context_lower = context.lower()
        agents = []

        # Tech-based selection
        if "graphql" in context_lower:
            agents.append("graphql_tester")
        if "api" in context_lower or "rest" in context_lower:
            agents.append("api_tester")
        if "websocket" in context_lower or "ws" in context_lower:
            agents.append("websocket_tester")
        if "mobile" in context_lower or "ios" in context_lower or "android" in context_lower:
            agents.append("mobile_tester")
        if "cloud" in context_lower or "s3" in context_lower or "bucket" in context_lower:
            agents.extend(["s3_tester", "azure_tester", "gcp_tester"])

        return agents if agents else ["discovery_engine"]
