"""FastAPI server for gobuster-claude."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))
sys.path.insert(0, ".")  # local dir first

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import GobusterRequest, GobusterJob
from state import GobusterStateManager
from scanner import start_gobuster_scan, cancel_gobuster_scan

app = FastAPI(
    title="gobuster-claude",
    description="Directory/file/DNS enumeration via Gobuster",
    version="1.0.0",
)
state = GobusterStateManager()


@app.post("/api/enumerate", response_model=GobusterJob, status_code=202)
async def enumerate(request: GobusterRequest) -> GobusterJob:
    """Start a new Gobuster enumeration.

    Accepts all GobusterRequest parameters. Returns immediately with a job_id.
    Poll /api/enumerate/{job_id} for results.
    """
    if not request.target:
        raise HTTPException(status_code=400, detail="target cannot be empty")
    if not request.wordlist:
        raise HTTPException(status_code=400, detail="wordlist cannot be empty")

    job = await start_gobuster_scan(request)
    await state.add_job(job)
    return job


@app.get("/api/enumerate/{job_id}", response_model=GobusterJob)
async def get_job(job_id: str) -> GobusterJob:
    """Get enumeration job status and results.

    Returns the full GobusterJob including discovered paths/subdomains.
    """
    job = await state.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    """Cancel a running Gobuster enumeration.

    Sends SIGTERM to the underlying gobuster process.
    """
    # Kill the subprocess first
    await cancel_gobuster_scan(job_id)
    # Then update state
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": f"Job {job_id} cancelled"})


@app.get("/api/jobs")
async def list_jobs() -> dict:
    """List all jobs with summary information."""
    all_jobs = await state.all_jobs()
    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "status": j.status,
                "target": j.target,
                "mode": j.mode,
                "total_findings": j.total_findings,
                "created_at": j.created_at,
                "completed_at": j.completed_at,
            }
            for j in all_jobs
        ],
        "total": len(all_jobs),
    }


@app.get("/api/status")
async def server_status() -> dict:
    """Get overall gobuster-claude service status."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    return {
        "tool": "gobuster",
        "version": "gobuster-claude/1.0",
        "jobs": counts,
        "total_jobs": len(all_jobs),
    }


@app.get("/api/wordlists")
async def list_wordlists() -> dict:
    """Return common wordlist paths for convenience."""
    common = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ]
    available = []
    for path in common:
        if os.path.exists(path):
            available.append(path)
    return {
        "available": available,
        "all_known": common,
    }
