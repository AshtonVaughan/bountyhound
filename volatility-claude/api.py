"""FastAPI server for volatility-claude."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import VolatilityPluginRequest, VolatilityBatchRequest, VolatilityPluginJob, VolatilityBatchJob
from state import VolatilityStateManager
from scanner import start_plugin, start_batch, get_triage_plugins

app = FastAPI(
    title="volatility-claude",
    description="Memory forensics via Volatility3 — process analysis, network forensics, malware detection",
    version="1.0.0",
)
state = VolatilityStateManager()


@app.post("/api/plugin", response_model=VolatilityPluginJob, status_code=202)
async def run_plugin(request: VolatilityPluginRequest) -> VolatilityPluginJob:
    """Run a single Volatility3 plugin against a memory image.

    Returns job_id immediately. Poll /api/plugin/{job_id} for results.
    The memory_image must be accessible on the server filesystem.
    """
    if not request.memory_image:
        raise HTTPException(status_code=400, detail="memory_image path is required")
    if not request.plugin:
        raise HTTPException(status_code=400, detail="plugin name is required")

    job = await start_plugin(request)
    await state.add_job(job)
    return job


@app.get("/api/plugin/{job_id}", response_model=VolatilityPluginJob)
async def get_plugin_job(job_id: str) -> VolatilityPluginJob:
    """Get plugin execution results and security findings."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, VolatilityPluginJob):
        raise HTTPException(status_code=404, detail=f"Plugin job {job_id} not found")
    return job


@app.post("/api/batch", response_model=VolatilityBatchJob, status_code=202)
async def run_batch(request: VolatilityBatchRequest) -> VolatilityBatchJob:
    """Run multiple Volatility3 plugins as a triage batch.

    Useful for forensic triage — runs process, network, malware, and credential
    plugins in sequence and aggregates findings.
    """
    if not request.memory_image:
        raise HTTPException(status_code=400, detail="memory_image path is required")
    if not request.plugins:
        raise HTTPException(status_code=400, detail="at least one plugin is required")

    job = await start_batch(request)
    await state.add_job(job)
    return job


@app.get("/api/batch/{job_id}", response_model=VolatilityBatchJob)
async def get_batch_job(job_id: str) -> VolatilityBatchJob:
    """Get batch analysis progress and aggregated findings."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, VolatilityBatchJob):
        raise HTTPException(status_code=404, detail=f"Batch job {job_id} not found")
    return job


@app.get("/api/triage-plugins")
async def triage_plugins(os: str = "windows") -> dict:
    """Return recommended plugin set for forensic triage.

    Args:
        os: Target OS — 'windows' or 'linux'
    """
    plugins = get_triage_plugins(os)
    return {"os": os, "plugins": plugins, "count": len(plugins)}


@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    """Cancel a running Volatility job."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": f"Job {job_id} cancelled"})


@app.get("/api/jobs")
async def list_jobs() -> dict:
    """List all Volatility jobs."""
    all_jobs = await state.all_jobs()
    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "job_type": getattr(j, "job_type", "unknown"),
                "status": j.status,
                "memory_image": getattr(j, "memory_image", ""),
                "created_at": j.created_at,
                "completed_at": j.completed_at,
                **({"plugin": j.plugin, "row_count": j.row_count, "findings": len(j.findings)}
                   if isinstance(j, VolatilityPluginJob) else
                   {"plugins_completed": len(j.plugins_completed), "total_findings": j.total_findings}),
            }
            for j in all_jobs
        ],
        "total": len(all_jobs),
    }


@app.get("/api/status")
async def server_status() -> dict:
    """Get volatility-claude service health."""
    counts = await state.job_count()
    return {
        "tool": "volatility",
        "version": "volatility-claude/1.0",
        "jobs": counts,
        "total_jobs": len(await state.all_jobs()),
    }
