"""FastAPI server for Amass."""

from __future__ import annotations

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import AmassRequest, AmassJob
from state import AmassStateManager
from scanner import start_amass_enum

app = FastAPI(title="amass-claude", description="Amass subdomain enumeration")
state = AmassStateManager()


@app.post("/api/enum")
async def enum(request: AmassRequest) -> AmassJob:
    """Start a new Amass enumeration."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="domain cannot be empty")

    job = await start_amass_enum(request)
    await state.add_job(job)
    return job


@app.get("/api/enum/{job_id}")
async def get_enum_status(job_id: str) -> AmassJob:
    """Get enumeration status and results."""
    job = await state.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_enum(job_id: str) -> JSONResponse:
    """Cancel a running enumeration."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": "Enumeration cancelled"})


@app.get("/api/status")
async def status() -> dict:
    """Get overall status."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    return {
        "tool": "amass",
        "jobs": counts,
        "total_jobs": len(all_jobs),
    }
