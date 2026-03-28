"""Ffuf-specific Pydantic models."""

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


class FfufRequest(BaseRequest):
    """Request for Ffuf fuzzing."""
    url: str
    wordlist: str  # Path to wordlist or URL
    method: str = "GET"
    match_status: str = ""  # e.g. "200,204"
    filter_status: str = ""  # e.g. "404,500"
    match_size: int = 0  # Match response size
    filter_size: int = 0  # Filter response size
    headers: dict[str, str] = Field(default_factory=dict)


class FfufResult(BaseFinding):
    """Ffuf result (discovered endpoint)."""
    url: str
    status: int = 0
    content_length: int = 0
    content_type: str = ""
    words: int = 0
    lines: int = 0


class FfufJob(BaseJob):
    """Ffuf fuzzing job."""
    tool: str = "ffuf"
    url: str = ""
    results: list[FfufResult] = Field(default_factory=list)
    total_results: int = 0
