"""
engine.intel — Phase 0.5 Target Brief

Pre-recon intelligence package.  Exports TargetBrief and TargetBriefBuilder
for use throughout the BountyHound pipeline.
"""

from .target_brief import TargetBrief, TargetBriefBuilder
from .h1_fetcher import H1Fetcher
from .cve_fetcher import CveFetcher
from .changelog_fetcher import ChangelogFetcher

__all__ = ["TargetBrief", "TargetBriefBuilder", "H1Fetcher", "CveFetcher", "ChangelogFetcher"]
