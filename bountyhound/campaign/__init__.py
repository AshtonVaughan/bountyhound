"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser
from bountyhound.campaign.intigriti import IntigritiParser
from bountyhound.campaign.yeswehack import YesWeHackParser
from bountyhound.campaign.runner import CampaignRunner

__all__ = [
    "CampaignParser",
    "detect_platform",
    "HackerOneParser",
    "BugcrowdParser",
    "IntigritiParser",
    "YesWeHackParser",
    "CampaignRunner",
]
