"""Metasploit-specific Pydantic models for controlled exploit execution."""

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


# ── Module / exploit models ───────────────────────────────────────────────────

class MetasploitModuleOption(BaseModel):
    """A single Metasploit module option (RHOSTS, RPORT, PAYLOAD, etc.)."""
    name: str
    value: str = ""
    required: bool = False
    description: str = ""


class MetasploitModule(BaseModel):
    """Metasploit module descriptor."""
    module_type: str = "exploit"   # exploit, auxiliary, post, scanner, payload
    module_path: str = ""          # e.g. exploit/multi/handler
    name: str = ""
    description: str = ""
    rank: str = ""                 # excellent, great, good, normal, average, low, manual
    options: list[MetasploitModuleOption] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)  # CVE, BID, URL refs
    platforms: list[str] = Field(default_factory=list)
    arch: list[str] = Field(default_factory=list)


# ── Request models ────────────────────────────────────────────────────────────

class MetasploitRunRequest(BaseRequest):
    """Request to run a Metasploit module via msfconsole or MSFRPC."""
    module_type: str = "exploit"   # exploit, auxiliary, post, scanner
    module_path: str              # e.g. auxiliary/scanner/portscan/tcp
    options: dict[str, str] = Field(default_factory=dict)  # RHOSTS -> 10.0.0.1
    payload: str = ""             # Payload for exploits (e.g. linux/x86/meterpreter/reverse_tcp)
    payload_options: dict[str, str] = Field(default_factory=dict)  # LHOST, LPORT
    run_as_job: bool = True       # Run as background job vs foreground
    use_rpc: bool = False         # Use MSFRPC API vs msfconsole subprocess
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 55553
    rpc_password: str = "msf"
    timeout: float = 300.0
    concurrency: int = 1


class MetasploitSearchRequest(BaseRequest):
    """Request to search the Metasploit module database."""
    query: str                    # Search terms (CVE, module name, platform, etc.)
    module_type: str = ""         # Filter by type (exploit, auxiliary, post)
    rank: str = ""                # Minimum rank filter
    platform: str = ""            # Platform filter (windows, linux, etc.)
    timeout: float = 60.0


class MetasploitSessionRequest(BaseRequest):
    """Request to interact with an open Meterpreter/shell session."""
    session_id: int               # Metasploit session ID
    command: str                  # Command to run in session
    use_rpc: bool = False
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 55553
    rpc_password: str = "msf"
    timeout: float = 60.0


# ── Finding models ────────────────────────────────────────────────────────────

class MetasploitSession(BaseModel):
    """An active Metasploit session (Meterpreter or shell)."""
    session_id: int = 0
    session_type: str = ""         # meterpreter, shell
    platform: str = ""
    arch: str = ""
    hostname: str = ""
    username: str = ""
    uid: str = ""
    remote_host: str = ""
    remote_port: int = 0
    local_host: str = ""
    local_port: int = 0
    via_exploit: str = ""
    via_payload: str = ""
    opened_at: float = 0.0


class MetasploitFinding(BaseFinding):
    """A result from a Metasploit module execution."""
    module_path: str = ""
    module_type: str = ""
    target_host: str = ""
    target_port: int = 0
    session_opened: bool = False
    session: Optional[MetasploitSession] = None
    output_lines: list[str] = Field(default_factory=list)
    loot_files: list[str] = Field(default_factory=list)
    vuln_refs: list[str] = Field(default_factory=list)


# ── Job models ────────────────────────────────────────────────────────────────

class MetasploitRunJob(BaseJob):
    """Job tracking a Metasploit module execution."""
    tool: str = "metasploit"
    job_type: str = "run"
    module_path: str = ""
    module_type: str = ""
    options: dict[str, str] = Field(default_factory=dict)
    payload: str = ""
    msf_job_id: int = -1           # Internal Metasploit job ID (if run_as_job)
    sessions_opened: list[MetasploitSession] = Field(default_factory=list)
    findings: list[MetasploitFinding] = Field(default_factory=list)
    output: list[str] = Field(default_factory=list)
    total_hosts_tested: int = 0
    total_hosts_vulnerable: int = 0


class MetasploitSearchJob(BaseJob):
    """Job tracking a module search operation."""
    tool: str = "metasploit"
    job_type: str = "search"
    query: str = ""
    modules: list[MetasploitModule] = Field(default_factory=list)
    total_results: int = 0


class MetasploitSessionJob(BaseJob):
    """Job tracking session command execution."""
    tool: str = "metasploit"
    job_type: str = "session"
    session_id: int = 0
    command: str = ""
    output: str = ""
