"""Base Pydantic models for BountyHound tools."""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field


# ── Job models ───────────────────────────────────────────────────────────────

class BaseJob(BaseModel):
    """Base job structure for all tools."""
    job_id: str
    status: str = "running"  # running, completed, cancelled, error
    error: str | None = None
    created_at: float = Field(default_factory=time.time)
    completed_at: float = 0.0
    tool: str = ""  # e.g. "nuclei", "sqlmap", "nmap"

    def is_completed(self) -> bool:
        """Check if job is in terminal state."""
        return self.status in ("completed", "cancelled", "error")


# ── Finding models ───────────────────────────────────────────────────────────

class BaseFinding(BaseModel):
    """Base finding structure for all vulnerability/discovery results."""
    name: str
    severity: str = "medium"  # critical, high, medium, low, info
    url: str = ""
    description: str = ""
    remediation: str = ""
    occurrence_count: int = 1
    metadata: dict[str, Any] = {}  # Tool-specific extra data


# ── Request models ───────────────────────────────────────────────────────────

class BaseRequest(BaseModel):
    """Generic request structure for all tools."""
    timeout: float = 30.0
    concurrency: int = 10
    metadata: dict[str, Any] = {}  # Extra options per tool


# ── Response models ───────────────────────────────────────────────────────────

class JobResponse(BaseModel):
    """Response when creating or fetching a job."""
    job_id: str
    status: str
    error: str | None = None
    created_at: float
    completed_at: float = 0.0
    tool: str = ""
    results: list[BaseFinding] = []


class StatusResponse(BaseModel):
    """Simple status response."""
    running: int = 0
    completed: int = 0
    error: int = 0
    cancelled: int = 0
