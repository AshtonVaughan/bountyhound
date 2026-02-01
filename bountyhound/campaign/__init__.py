"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser

__all__ = ["CampaignParser", "detect_platform", "HackerOneParser"]
