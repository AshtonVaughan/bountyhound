"""Volatility-specific Pydantic models for memory forensics."""

from __future__ import annotations

import sys
import os
import importlib.util
from typing import Any, Optional
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


class VolatilityPluginRequest(BaseRequest):
    """Request to run a Volatility3 plugin against a memory image."""
    memory_image: str                  # Path to memory dump file
    plugin: str                        # Plugin name (e.g. windows.pslist.PsList)
    plugin_args: dict[str, str] = Field(default_factory=dict)  # Extra plugin arguments
    output_format: str = "json"        # json, text, csv
    symbol_path: str = ""              # Custom symbol path for ISF files
    timeout: float = 300.0
    concurrency: int = 1


class VolatilityBatchRequest(BaseRequest):
    """Request to run multiple Volatility plugins in sequence."""
    memory_image: str
    plugins: list[str]                 # List of plugin names to run
    plugin_args: dict[str, dict[str, str]] = Field(default_factory=dict)  # Per-plugin args
    output_format: str = "json"
    symbol_path: str = ""
    stop_on_error: bool = False
    timeout: float = 1800.0
    concurrency: int = 1


class ProcessInfo(BaseModel):
    """Process entry from windows.pslist or linux.pslist."""
    pid: int = 0
    ppid: int = 0
    name: str = ""
    offset: str = ""                   # Memory offset (hex string)
    threads: int = 0
    handles: int = 0
    create_time: str = ""
    exit_time: str = ""
    wow64: bool = False
    image_file_name: str = ""


class NetworkConnection(BaseModel):
    """Network connection from netstat/netscan output."""
    pid: int = 0
    process_name: str = ""
    proto: str = ""                    # TCP, UDP, TCPv6, etc.
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""                    # ESTABLISHED, LISTEN, CLOSE_WAIT, etc.
    created: str = ""


class VolatilityFinding(BaseFinding):
    """A forensic finding from a Volatility plugin."""
    plugin: str = ""                   # Plugin that produced this finding
    process: Optional[ProcessInfo] = None
    network: Optional[NetworkConnection] = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    indicator_type: str = ""           # injected_code, hidden_process, suspicious_network, etc.
    memory_offset: str = ""


class VolatilityPluginJob(BaseJob):
    """Single Volatility plugin execution job."""
    tool: str = "volatility"
    job_type: str = "plugin"
    memory_image: str = ""
    plugin: str = ""
    plugin_args: dict[str, str] = Field(default_factory=dict)
    raw_output: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[VolatilityFinding] = Field(default_factory=list)
    row_count: int = 0
    os_profile: str = ""               # Detected OS (Windows, Linux, Mac)


class VolatilityBatchJob(BaseJob):
    """Multi-plugin Volatility batch analysis job."""
    tool: str = "volatility"
    job_type: str = "batch"
    memory_image: str = ""
    plugins_requested: list[str] = Field(default_factory=list)
    plugins_completed: list[str] = Field(default_factory=list)
    plugins_failed: list[str] = Field(default_factory=list)
    all_findings: list[VolatilityFinding] = Field(default_factory=list)
    plugin_results: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    total_findings: int = 0
    os_profile: str = ""
