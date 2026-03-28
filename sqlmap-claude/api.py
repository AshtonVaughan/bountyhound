"""FastAPI server for SQLMap."""

from __future__ import annotations

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import SqlmapRequest, SqlmapJob
from state import SqlmapStateManager
from scanner import start_sqlmap_test

app = FastAPI(title="sqlmap-claude", description="SQLMap SQL injection tester")
state = SqlmapStateManager()


@app.post("/api/test")
async def test(request: SqlmapRequest) -> SqlmapJob:
    """Start a new SQLMap test."""
    if not request.url:
        raise HTTPException(status_code=400, detail="url cannot be empty")

    job = await start_sqlmap_test(request)
    await state.add_job(job)
    return job


@app.get("/api/test/{job_id}")
async def get_test_status(job_id: str) -> SqlmapJob:
    """Get test status and results."""
    job = await state.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_test(job_id: str) -> JSONResponse:
    """Cancel a running test."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": "Test cancelled"})


@app.get("/api/status")
async def status() -> dict:
    """Get overall status."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    return {
        "tool": "sqlmap",
        "jobs": counts,
        "total_jobs": len(all_jobs),
    }
