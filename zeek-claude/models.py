"""Zeek-specific Pydantic models for network traffic analysis."""

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


class ZeekAnalyzeRequest(BaseRequest):
    """Request to analyze a PCAP file with Zeek."""
    pcap_file: str                     # Path to .pcap or .pcapng file
    scripts: list[str] = Field(default_factory=list)  # Extra Zeek script paths to load
    zeek_scripts_dir: str = ""         # Custom Zeek scripts directory
    output_dir: str = ""               # Where to write Zeek log files (default: temp)
    extract_files: bool = False        # Extract file payloads from PCAP
    analyze_dns: bool = True
    analyze_http: bool = True
    analyze_ssl: bool = True
    analyze_conn: bool = True
    timeout: float = 600.0
    concurrency: int = 1


class ZeekLiveRequest(BaseRequest):
    """Request to run Zeek against a live network interface."""
    interface: str                     # Network interface (e.g. eth0, en0)
    duration: float = 60.0            # Capture duration in seconds
    scripts: list[str] = Field(default_factory=list)
    output_dir: str = ""
    timeout: float = 120.0
    concurrency: int = 1


class ZeekLogQueryRequest(BaseRequest):
    """Request to query existing Zeek log files."""
    log_dir: str                       # Directory containing Zeek .log files
    log_type: str = "conn"            # conn, dns, http, ssl, files, weird, notice, etc.
    filter_expr: str = ""             # Optional filter (Python boolean expression on row dict)
    limit: int = 1000
    timeout: float = 60.0


# ── Connection / flow models ──────────────────────────────────────────────────

class ZeekConnection(BaseModel):
    """A network connection from conn.log."""
    ts: float = 0.0
    uid: str = ""
    id_orig_h: str = ""              # Source IP
    id_orig_p: int = 0               # Source port
    id_resp_h: str = ""              # Destination IP
    id_resp_p: int = 0               # Destination port
    proto: str = ""                  # tcp, udp, icmp
    service: str = ""
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = ""             # SF, S0, REJ, RSTO, etc.
    local_orig: bool = False
    missed_bytes: int = 0


class ZeekDNS(BaseModel):
    """A DNS query/answer from dns.log."""
    ts: float = 0.0
    uid: str = ""
    id_orig_h: str = ""
    query: str = ""
    qtype_name: str = ""
    rcode_name: str = ""
    answers: list[str] = Field(default_factory=list)
    TTLs: list[float] = Field(default_factory=list)


class ZeekHTTP(BaseModel):
    """An HTTP request from http.log."""
    ts: float = 0.0
    uid: str = ""
    id_orig_h: str = ""
    id_resp_h: str = ""
    id_resp_p: int = 0
    method: str = ""
    host: str = ""
    uri: str = ""
    status_code: int = 0
    resp_mime_types: list[str] = Field(default_factory=list)
    user_agent: str = ""
    username: str = ""
    password: str = ""


class ZeekSSL(BaseModel):
    """An SSL/TLS session from ssl.log."""
    ts: float = 0.0
    uid: str = ""
    id_orig_h: str = ""
    id_resp_h: str = ""
    id_resp_p: int = 0
    version: str = ""
    cipher: str = ""
    curve: str = ""
    server_name: str = ""
    validation_status: str = ""
    subject: str = ""
    issuer: str = ""
    established: bool = False


class ZeekFinding(BaseFinding):
    """A security finding identified in Zeek logs."""
    log_type: str = ""               # Source log (conn, dns, http, ssl, weird, notice)
    uid: str = ""                    # Zeek connection UID
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    indicator_type: str = ""         # c2_beacon, port_scan, dns_tunneling, cleartext_auth, etc.
    raw_data: dict[str, Any] = Field(default_factory=dict)
    pcap_offset: str = ""


# ── Job models ────────────────────────────────────────────────────────────────

class ZeekAnalyzeJob(BaseJob):
    """PCAP or live interface Zeek analysis job."""
    tool: str = "zeek"
    job_type: str = "analyze"
    pcap_file: str = ""
    interface: str = ""
    output_dir: str = ""
    log_files: list[str] = Field(default_factory=list)  # Generated .log file paths
    findings: list[ZeekFinding] = Field(default_factory=list)
    total_findings: int = 0
    conn_count: int = 0
    dns_count: int = 0
    http_count: int = 0
    ssl_count: int = 0
    weird_count: int = 0


class ZeekQueryJob(BaseJob):
    """Zeek log query job."""
    tool: str = "zeek"
    job_type: str = "query"
    log_type: str = ""
    log_dir: str = ""
    filter_expr: str = ""
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
