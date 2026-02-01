"""Data models for BountyHound."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Target(BaseModel):
    """A bug bounty target domain."""

    id: int
    domain: str
    added_at: datetime
    last_recon: Optional[datetime] = None
    last_scan: Optional[datetime] = None


class Subdomain(BaseModel):
    """A discovered subdomain."""

    id: int
    target_id: int
    hostname: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    technologies: list[str] = []
    discovered_at: datetime = datetime.now()


class Port(BaseModel):
    """An open port on a subdomain."""

    id: int
    subdomain_id: int
    port: int
    service: Optional[str] = None
    version: Optional[str] = None
    discovered_at: datetime = datetime.now()


class Finding(BaseModel):
    """A vulnerability finding."""

    id: int
    subdomain_id: int
    name: str
    severity: str
    url: Optional[str] = None
    evidence: Optional[str] = None
    template: Optional[str] = None
    found_at: datetime = datetime.now()


class Run(BaseModel):
    """A pipeline run record."""

    id: int
    target_id: int
    stage: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
