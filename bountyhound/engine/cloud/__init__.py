"""Cloud security testing modules"""

from dataclasses import dataclass


@dataclass
class CloudFinding:
    """Shared finding dataclass for all cloud security testers."""
    title: str
    severity: str
    service: str
    evidence: str
    url: str = ""
    remediation: str = ""
