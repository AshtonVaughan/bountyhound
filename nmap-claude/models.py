"""Nmap-specific Pydantic models."""

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


class NmapRequest(BaseRequest):
    """Request for Nmap scanning."""
    targets: list[str] = Field(default_factory=list)
    scan_type: str = "sV"  # sV (service), sS (syn), sT (connect), sU (UDP)
    ports: str = ""  # e.g. "80,443,8080" or "1-10000"
    aggressive: bool = False  # -A flag for aggressive scanning


class PortFinding(BaseFinding):
    """Port/service finding."""
    port: int = 0
    protocol: str = "tcp"  # tcp, udp
    state: str = "open"  # open, closed, filtered
    service: str = ""
    version: str = ""
    product: str = ""


class NmapJob(BaseJob):
    """Nmap scan job."""
    tool: str = "nmap"
    targets: list[str] = Field(default_factory=list)
    results: list[PortFinding] = Field(default_factory=list)
    total_ports: int = 0
