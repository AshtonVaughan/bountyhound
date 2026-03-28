"""FastAPI server for Ffuf."""

from __future__ import annotations

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import FfufRequest, FfufJob
from state import FfufStateManager
from scanner import start_ffuf_fuzz

app = FastAPI(title="ffuf-claude", description="Ffuf web fuzzer")
state = FfufStateManager()


@app.post("/api/fuzz")
async def fuzz(request: FfufRequest) -> FfufJob:
    """Start a new Ffuf fuzz."""
    if not request.url:
        raise HTTPException(status_code=400, detail="url cannot be empty")
    if not request.wordlist:
        raise HTTPException(status_code=400, detail="wordlist cannot be empty")

    job = await start_ffuf_fuzz(request)
    await state.add_job(job)
    return job


@app.get("/api/fuzz/{job_id}")
async def get_fuzz_status(job_id: str) -> FfufJob:
    """Get fuzz status and results."""
    job = await state.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_fuzz(job_id: str) -> JSONResponse:
    """Cancel a running fuzz."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": "Fuzz cancelled"})


@app.get("/api/status")
async def status() -> dict:
    """Get overall status."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    return {
        "tool": "ffuf",
        "jobs": counts,
        "total_jobs": len(all_jobs),
    }
