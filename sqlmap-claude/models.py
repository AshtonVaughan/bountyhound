"""SQLMap-specific Pydantic models."""

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


class SqlmapRequest(BaseRequest):
    """Request for SQLMap testing."""
    url: str
    method: str = "GET"
    data: str = ""  # POST data
    headers: dict[str, str] = Field(default_factory=dict)
    parameters: list[str] = Field(default_factory=list)  # Specific parameters to test
    level: int = 1  # 1-5, higher = more thorough
    risk: int = 1  # 1-3, higher = more aggressive


class SqliVulnerability(BaseFinding):
    """SQL injection vulnerability finding."""
    url: str
    parameter: str = ""
    injection_type: str = ""  # bool-based, time-based, UNION, etc.
    dbms: str = ""  # Detected DBMS
    payload: str = ""  # Proof of concept payload


class SqlmapJob(BaseJob):
    """SQLMap test job."""
    tool: str = "sqlmap"
    url: str = ""
    results: list[SqliVulnerability] = Field(default_factory=list)
    total_vulnerabilities: int = 0
