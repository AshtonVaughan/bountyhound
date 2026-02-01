"""Base campaign parser and platform detection."""

from typing import Optional
from urllib.parse import urlparse


def detect_platform(url: str) -> Optional[str]:
    """Detect bug bounty platform from URL.

    Args:
        url: Campaign URL

    Returns:
        Platform name (hackerone, bugcrowd, intigriti, yeswehack) or None
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace("www.", "").replace("app.", "")

    if "hackerone.com" in host:
        return "hackerone"
    elif "bugcrowd.com" in host:
        return "bugcrowd"
    elif "intigriti.com" in host:
        return "intigriti"
    elif "yeswehack.com" in host:
        return "yeswehack"

    return None


class CampaignParser:
    """Base class for campaign parsers."""

    def parse(self, html_content: str, url: str) -> dict:
        """Parse campaign page HTML to extract scope.

        Args:
            html_content: Raw HTML of campaign page
            url: Original URL

        Returns:
            Scope dict with in_scope, out_of_scope, program_name, etc.
        """
        raise NotImplementedError("Subclasses must implement parse()")

    def scope_to_domains(self, scope: dict) -> list[str]:
        """Extract scannable domains from parsed scope.

        Args:
            scope: Parsed scope dict

        Returns:
            List of domain strings (may include wildcards like *.example.com)
        """
        domains = []
        for item in scope.get("in_scope", []):
            if item.get("type") == "domain":
                domains.append(item.get("target"))
        return domains
