"""Gobuster-specific Pydantic models."""

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


class GobusterMode(str):
    """Gobuster scan modes."""
    DIR = "dir"
    DNS = "dns"
    VHOST = "vhost"
    FUZZ = "fuzz"
    S3 = "s3"


class GobusterRequest(BaseRequest):
    """Request to run a Gobuster enumeration."""
    target: str  # URL or domain
    mode: str = "dir"  # dir, dns, vhost, fuzz, s3
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    extensions: list[str] = Field(default_factory=list)  # e.g. ["php", "html", "txt"]
    status_codes: list[int] = Field(default_factory=lambda: [200, 204, 301, 302, 307, 401, 403])
    threads: int = 10
    follow_redirects: bool = False
    no_error: bool = True  # Suppress errors
    expand_path: bool = False  # Add base path to each result
    add_slash: bool = False  # Append slash to each request
    username: str = ""  # Basic auth
    password: str = ""
    cookies: str = ""  # Cookies header
    user_agent: str = "gobuster/3.0"
    proxy: str = ""
    timeout: float = 300.0
    concurrency: int = 10


class GobusterFinding(BaseFinding):
    """A single result from Gobuster enumeration."""
    path: str = ""           # Discovered path or subdomain
    status_code: int = 0     # HTTP status code (dir/vhost mode)
    size: int = 0            # Response size in bytes
    redirect_url: str = ""   # Redirect target if any
    dns_record_type: str = "" # DNS record type (dns mode)
    dns_record_value: str = "" # DNS record value (dns mode)
    found_by: str = ""       # Method that found this entry


class GobusterJob(BaseJob):
    """Gobuster enumeration job."""
    tool: str = "gobuster"
    target: str = ""
    mode: str = "dir"
    wordlist: str = ""
    results: list[GobusterFinding] = Field(default_factory=list)
    total_findings: int = 0
    words_tested: int = 0
    words_total: int = 0
    progress_percent: float = 0.0
