"""FastAPI server for metasploit-claude."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from typing import Union

from models import (
    MetasploitRunRequest,
    MetasploitSearchRequest,
    MetasploitSessionRequest,
    MetasploitRunJob,
    MetasploitSearchJob,
    MetasploitSessionJob,
)
from state import MetasploitStateManager
from scanner import start_module_run, start_module_search, start_session_command

app = FastAPI(
    title="metasploit-claude",
    description="Controlled Metasploit exploit execution, module search, and session management",
    version="1.0.0",
)
state = MetasploitStateManager()


# ── Module execution endpoints ────────────────────────────────────────────────

@app.post("/api/run", response_model=MetasploitRunJob, status_code=202)
async def run_module(request: MetasploitRunRequest) -> MetasploitRunJob:
    """Execute a Metasploit module (exploit, auxiliary, post, scanner).

    Runs in background via msfconsole resource script or MSFRPC.
    Returns job_id immediately — poll /api/run/{job_id} for results.

    Example request body:
    {
      "module_type": "auxiliary",
      "module_path": "scanner/portscan/tcp",
      "options": {"RHOSTS": "10.0.0.1", "PORTS": "1-1024"},
      "timeout": 120.0
    }
    """
    if not request.module_path:
        raise HTTPException(status_code=400, detail="module_path cannot be empty")

    job = await start_module_run(request)
    await state.add_job(job)
    return job


@app.get("/api/run/{job_id}", response_model=MetasploitRunJob)
async def get_run_job(job_id: str) -> MetasploitRunJob:
    """Get module execution status, sessions opened, and findings."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, MetasploitRunJob):
        raise HTTPException(status_code=404, detail=f"Run job {job_id} not found")
    return job


# ── Search endpoints ──────────────────────────────────────────────────────────

@app.post("/api/search", response_model=MetasploitSearchJob, status_code=202)
async def search_modules(request: MetasploitSearchRequest) -> MetasploitSearchJob:
    """Search the Metasploit module database.

    Supports CVE numbers, module names, platforms, and keyword search.
    """
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="query cannot be empty")

    job = await start_module_search(request)
    await state.add_job(job)
    return job


@app.get("/api/search/{job_id}", response_model=MetasploitSearchJob)
async def get_search_job(job_id: str) -> MetasploitSearchJob:
    """Get module search results."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, MetasploitSearchJob):
        raise HTTPException(status_code=404, detail=f"Search job {job_id} not found")
    return job


# ── Session endpoints ─────────────────────────────────────────────────────────

@app.post("/api/session", response_model=MetasploitSessionJob, status_code=202)
async def run_session_command(request: MetasploitSessionRequest) -> MetasploitSessionJob:
    """Execute a command in an open Meterpreter or shell session.

    Returns job_id — poll /api/session/{job_id} for command output.
    """
    if not request.command.strip():
        raise HTTPException(status_code=400, detail="command cannot be empty")

    job = await start_session_command(request)
    await state.add_job(job)
    return job


@app.get("/api/session/{job_id}", response_model=MetasploitSessionJob)
async def get_session_job(job_id: str) -> MetasploitSessionJob:
    """Get session command output."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, MetasploitSessionJob):
        raise HTTPException(status_code=404, detail=f"Session job {job_id} not found")
    return job


@app.get("/api/sessions")
async def list_active_sessions() -> dict:
    """List all sessions opened across all run jobs."""
    sessions = await state.get_active_sessions()
    return {
        "sessions": sessions,
        "total": len(sessions),
    }


# ── Generic endpoints ─────────────────────────────────────────────────────────

@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    """Cancel any running Metasploit job."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": f"Job {job_id} cancelled"})


@app.get("/api/jobs")
async def list_jobs() -> dict:
    """List all jobs with type and summary."""
    all_jobs = await state.all_jobs()
    summary = []
    for j in all_jobs:
        entry: dict = {
            "job_id": j.job_id,
            "job_type": getattr(j, "job_type", "unknown"),
            "status": j.status,
            "created_at": j.created_at,
            "completed_at": j.completed_at,
        }
        if isinstance(j, MetasploitRunJob):
            entry["module_path"] = j.module_path
            entry["sessions_opened"] = len(j.sessions_opened)
            entry["findings"] = len(j.findings)
        elif isinstance(j, MetasploitSearchJob):
            entry["query"] = j.query
            entry["total_results"] = j.total_results
        elif isinstance(j, MetasploitSessionJob):
            entry["session_id"] = j.session_id
            entry["command"] = j.command
        summary.append(entry)
    return {"jobs": summary, "total": len(all_jobs)}


@app.get("/api/status")
async def server_status() -> dict:
    """Get metasploit-claude service health and job counts."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    sessions = await state.get_active_sessions()
    return {
        "tool": "metasploit",
        "version": "metasploit-claude/1.0",
        "jobs": counts,
        "total_jobs": len(all_jobs),
        "active_sessions": len(sessions),
    }


@app.get("/api/modules/common")
async def common_modules() -> dict:
    """Return a reference list of commonly used Metasploit modules."""
    return {
        "scanners": [
            "auxiliary/scanner/portscan/tcp",
            "auxiliary/scanner/portscan/syn",
            "auxiliary/scanner/smb/smb_version",
            "auxiliary/scanner/smb/smb_ms17_010",
            "auxiliary/scanner/http/http_version",
            "auxiliary/scanner/ftp/ftp_version",
            "auxiliary/scanner/ssh/ssh_version",
            "auxiliary/scanner/vnc/vnc_none_auth",
        ],
        "exploits": [
            "exploit/windows/smb/ms17_010_eternalblue",
            "exploit/windows/smb/ms08_067_netapi",
            "exploit/multi/handler",
            "exploit/unix/ftp/vsftpd_234_backdoor",
            "exploit/multi/misc/java_rmi_server",
        ],
        "post": [
            "post/multi/recon/local_exploit_suggester",
            "post/windows/gather/hashdump",
            "post/linux/gather/hashdump",
            "post/multi/manage/shell_to_meterpreter",
            "post/windows/escalate/getsystem",
        ],
        "payloads": {
            "windows_x64": "windows/x64/meterpreter/reverse_tcp",
            "windows_x86": "windows/meterpreter/reverse_tcp",
            "linux_x64": "linux/x64/meterpreter/reverse_tcp",
            "linux_x86": "linux/x86/meterpreter/reverse_tcp",
            "cmd_windows": "cmd/windows/reverse_powershell",
            "cmd_unix": "cmd/unix/reverse_bash",
        },
    }
