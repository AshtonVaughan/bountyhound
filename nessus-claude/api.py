"""FastAPI server for nessus-claude."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import NessusScanRequest, NessusExportRequest, NessusScanJob, NessusExportJob
from state import NessusStateManager
from scanner import start_scan, start_export

app = FastAPI(
    title="nessus-claude",
    description="Nessus vulnerability scanner integration via REST API",
    version="1.0.0",
)
state = NessusStateManager()


@app.post("/api/scan", response_model=NessusScanJob, status_code=202)
async def launch_scan(request: NessusScanRequest) -> NessusScanJob:
    """Launch a Nessus vulnerability scan.

    Requires a running Nessus instance with valid API keys.
    Returns job_id — poll /api/scan/{job_id} until status is 'completed'.
    """
    if not request.targets:
        raise HTTPException(status_code=400, detail="targets cannot be empty")
    if not request.access_key or not request.secret_key:
        raise HTTPException(status_code=400, detail="Nessus access_key and secret_key are required")

    job = await start_scan(request)
    await state.add_job(job)
    return job


@app.get("/api/scan/{job_id}", response_model=NessusScanJob)
async def get_scan_job(job_id: str) -> NessusScanJob:
    """Get scan status and vulnerability findings."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, NessusScanJob):
        raise HTTPException(status_code=404, detail=f"Scan job {job_id} not found")
    return job


@app.post("/api/export", response_model=NessusExportJob, status_code=202)
async def export_scan(request: NessusExportRequest) -> NessusExportJob:
    """Export an existing Nessus scan to nessus/pdf/csv/html format."""
    job = await start_export(request)
    await state.add_job(job)
    return job


@app.get("/api/export/{job_id}", response_model=NessusExportJob)
async def get_export_job(job_id: str) -> NessusExportJob:
    """Get export status and file path."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, NessusExportJob):
        raise HTTPException(status_code=404, detail=f"Export job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    """Cancel a running Nessus job."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": f"Job {job_id} cancelled"})


@app.get("/api/jobs")
async def list_jobs() -> dict:
    """List all scan and export jobs."""
    all_jobs = await state.all_jobs()
    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "job_type": getattr(j, "job_type", "unknown"),
                "status": j.status,
                "created_at": j.created_at,
                "completed_at": j.completed_at,
                **({"total_vulnerabilities": j.total_vulnerabilities, "scan_name": j.scan_name}
                   if isinstance(j, NessusScanJob) else {"export_file": j.export_file}),
            }
            for j in all_jobs
        ],
        "total": len(all_jobs),
    }


@app.get("/api/status")
async def server_status() -> dict:
    """Get nessus-claude service health."""
    counts = await state.job_count()
    return {
        "tool": "nessus",
        "version": "nessus-claude/1.0",
        "jobs": counts,
        "total_jobs": len(await state.all_jobs()),
    }
