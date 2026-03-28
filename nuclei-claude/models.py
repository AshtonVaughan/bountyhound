"""Nuclei-specific Pydantic models."""

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


class NucleiRequest(BaseRequest):
    """Request for Nuclei scanning."""
    urls: list[str] = Field(default_factory=list)
    templates: list[str] = Field(default_factory=list)  # e.g. ["http", "cves"]
    severity: str = ""  # Filter: critical, high, medium, low, info
    tag: str = ""  # Filter by tag
    exclude_templates: list[str] = Field(default_factory=list)
    rate_limit: int = 150  # Requests per second
    bulk_size: int = 25  # Requests per template per host


class NucleiFinding(BaseFinding):
    """Nuclei-specific finding."""
    template_id: str = ""
    template_info: dict[str, Any] = {}
    matcher_name: str = ""
    extracted_results: list[str] = Field(default_factory=list)


class NucleiJob(BaseJob):
    """Nuclei scan job."""
    tool: str = "nuclei"
    urls: list[str] = Field(default_factory=list)
    templates: list[str] = Field(default_factory=list)
    results: list[NucleiFinding] = Field(default_factory=list)
    total_findings: int = 0
