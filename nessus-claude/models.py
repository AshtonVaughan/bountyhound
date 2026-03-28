"""Nessus-specific Pydantic models for vulnerability scanning."""

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


class NessusScanRequest(BaseRequest):
    """Request to launch a Nessus scan via REST API."""
    targets: list[str]                 # IP addresses, ranges, or hostnames
    scan_template: str = "basic"       # basic, advanced, compliance, webapp, etc.
    policy_id: int = 0                 # Nessus policy ID (0 = use template)
    folder_id: int = 0                 # Nessus folder (0 = My Scans)
    scan_name: str = ""                # Display name in Nessus UI
    # Nessus API credentials
    nessus_url: str = "https://127.0.0.1:8834"
    access_key: str = ""
    secret_key: str = ""
    # Credential scanning
    ssh_username: str = ""
    ssh_password: str = ""
    smb_username: str = ""
    smb_password: str = ""
    smb_domain: str = ""
    timeout: float = 7200.0            # 2-hour default (large scans take time)
    concurrency: int = 1


class NessusExportRequest(BaseRequest):
    """Request to export an existing Nessus scan."""
    scan_id: int
    export_format: str = "nessus"      # nessus, pdf, csv, html
    nessus_url: str = "https://127.0.0.1:8834"
    access_key: str = ""
    secret_key: str = ""
    timeout: float = 300.0


class NessusVulnerability(BaseFinding):
    """A single vulnerability finding from a Nessus scan."""
    plugin_id: int = 0
    plugin_name: str = ""
    plugin_family: str = ""
    cve_list: list[str] = Field(default_factory=list)
    cvss_base_score: float = 0.0
    cvss_vector: str = ""
    cvss3_base_score: float = 0.0
    risk_factor: str = ""              # None, Low, Medium, High, Critical
    solution: str = ""
    plugin_output: str = ""
    affected_hosts: list[str] = Field(default_factory=list)
    port: int = 0
    protocol: str = ""
    service: str = ""
    exploit_available: bool = False
    exploitability_ease: str = ""
    patch_publication_date: str = ""
    vuln_publication_date: str = ""


class NessusScanJob(BaseJob):
    """Nessus scan execution job."""
    tool: str = "nessus"
    job_type: str = "scan"
    scan_name: str = ""
    nessus_scan_id: int = 0            # Nessus internal scan ID
    targets: list[str] = Field(default_factory=list)
    scan_template: str = ""
    nessus_status: str = ""            # running, completed, paused, canceled, etc.
    vulnerabilities: list[NessusVulnerability] = Field(default_factory=list)
    total_vulnerabilities: int = 0
    hosts_scanned: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class NessusExportJob(BaseJob):
    """Nessus scan export job."""
    tool: str = "nessus"
    job_type: str = "export"
    scan_id: int = 0
    export_format: str = ""
    export_file: str = ""              # Path to downloaded export file
