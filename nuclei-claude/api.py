"""FastAPI server for Nuclei."""

from __future__ import annotations

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import NucleiRequest, NucleiJob
from state import NucleiStateManager
from scanner import start_nuclei_scan

app = FastAPI(title="nuclei-claude", description="Nuclei template-based vulnerability scanner")
state = NucleiStateManager()


@app.post("/api/scan")
async def scan(request: NucleiRequest) -> NucleiJob:
    """Start a new Nuclei scan."""
    if not request.urls:
        raise HTTPException(status_code=400, detail="urls cannot be empty")

    job = await start_nuclei_scan(request)
    await state.add_job(job)
    return job


@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str) -> NucleiJob:
    """Get scan status and results."""
    job = await state.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_scan(job_id: str) -> JSONResponse:
    """Cancel a running scan."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": "Scan cancelled"})


@app.get("/api/status")
async def status() -> dict:
    """Get overall status."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    return {
        "tool": "nuclei",
        "jobs": counts,
        "total_jobs": len(all_jobs),
    }
