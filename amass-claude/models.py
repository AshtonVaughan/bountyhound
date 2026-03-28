"""Amass-specific Pydantic models."""

from __future__ import annotations

import sys
import os
import importlib.util
from typing import Any
from pydantic import BaseModel, Field

# Load bh-core models using absolute import to avoid circular imports
_bh_core_models_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core", "models.py"))
_spec = importlib.util.spec_from_file_location("bh_core_models", _bh_core_models_path)
_bh_core_models = importlib.util.module_from_spec(_spec)
sys.modules["bh_core_models"] = _bh_core_models
_spec.loader.exec_module(_bh_core_models)

BaseJob = _bh_core_models.BaseJob
BaseFinding = _bh_core_models.BaseFinding
BaseRequest = _bh_core_models.BaseRequest


class AmassRequest(BaseRequest):
    """Request for Amass subdomain enumeration."""
    domain: str
    passive: bool = False  # Passive enumeration only
    include_unresolved: bool = False  # Include DNS names that don't resolve
    min_for_recursive: int = 0  # Minimum number of names to recurse


class SubdomainFinding(BaseFinding):
    """Discovered subdomain."""
    domain: str = ""
    resolved_ips: list[str] = Field(default_factory=list)
    dns_records: dict[str, Any] = Field(default_factory=dict)


class AmassJob(BaseJob):
    """Amass enumeration job."""
    tool: str = "amass"
    domain: str = ""
    results: list[SubdomainFinding] = Field(default_factory=list)
    total_subdomains: int = 0
