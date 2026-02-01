"""YesWeHack campaign parser."""

from typing import Optional
from urllib.parse import urlparse

from bountyhound.ai import AIAnalyzer
from bountyhound.campaign.parser import CampaignParser


class YesWeHackParser(CampaignParser):
    """Parser for YesWeHack campaign pages."""

    def __init__(self, ai: Optional[AIAnalyzer] = None) -> None:
        self.ai = ai

    def _ensure_ai(self) -> None:
        if self.ai is None:
            self.ai = AIAnalyzer()

    def _get_program_name(self, url: str) -> str:
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        # YesWeHack URLs: /programs/program-name
        if len(path_parts) >= 2:
            return path_parts[-1]
        elif path_parts:
            return path_parts[-1]
        return "unknown"

    def parse(self, html_content: str, url: str) -> dict:
        self._ensure_ai()
        scope = self.ai.parse_campaign_scope(html_content, url)
        if not scope.get("program_name") or scope["program_name"] == "Unknown":
            scope["program_name"] = self._get_program_name(url)
        return scope
