"""FastAPI server for zeek-claude."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import (
    ZeekAnalyzeRequest,
    ZeekLiveRequest,
    ZeekLogQueryRequest,
    ZeekAnalyzeJob,
    ZeekQueryJob,
)
from state import ZeekStateManager
from scanner import start_pcap_analysis, start_live_capture, start_log_query

app = FastAPI(
    title="zeek-claude",
    description="Network traffic analysis via Zeek — PCAP forensics, live capture, and log querying",
    version="1.0.0",
)
state = ZeekStateManager()


@app.post("/api/analyze", response_model=ZeekAnalyzeJob, status_code=202)
async def analyze_pcap(request: ZeekAnalyzeRequest) -> ZeekAnalyzeJob:
    """Analyze a PCAP file with Zeek.

    Runs Zeek against the specified PCAP file and generates structured logs.
    Automatically analyses conn, dns, http, ssl, and weird logs for security indicators.
    Returns job_id — poll /api/analyze/{job_id} until status is 'completed'.
    """
    if not request.pcap_file:
        raise HTTPException(status_code=400, detail="pcap_file path is required")

    job = await start_pcap_analysis(request)
    await state.add_job(job)
    return job


@app.get("/api/analyze/{job_id}", response_model=ZeekAnalyzeJob)
async def get_analyze_job(job_id: str) -> ZeekAnalyzeJob:
    """Get PCAP analysis status, log file paths, and security findings."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, ZeekAnalyzeJob):
        raise HTTPException(status_code=404, detail=f"Analyze job {job_id} not found")
    return job


@app.post("/api/live", response_model=ZeekAnalyzeJob, status_code=202)
async def live_capture(request: ZeekLiveRequest) -> ZeekAnalyzeJob:
    """Run Zeek against a live network interface.

    Captures traffic on the specified interface for the given duration,
    then analyses the generated logs for security indicators.
    Requires root/admin privileges and a running network interface.
    """
    if not request.interface:
        raise HTTPException(status_code=400, detail="interface is required")

    job = await start_live_capture(request)
    await state.add_job(job)
    return job


@app.post("/api/query", response_model=ZeekQueryJob, status_code=202)
async def query_logs(request: ZeekLogQueryRequest) -> ZeekQueryJob:
    """Query existing Zeek log files with optional filtering.

    Reads the specified log type from a Zeek log directory.
    Supports an optional Python boolean filter expression evaluated per row.
    Example filter: "int(id.resp_p) == 443"
    """
    if not request.log_dir:
        raise HTTPException(status_code=400, detail="log_dir is required")

    job = await start_log_query(request)
    await state.add_job(job)
    return job


@app.get("/api/query/{job_id}", response_model=ZeekQueryJob)
async def get_query_job(job_id: str) -> ZeekQueryJob:
    """Get log query results."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, ZeekQueryJob):
        raise HTTPException(status_code=404, detail=f"Query job {job_id} not found")
    return job


@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    """Cancel a running Zeek job."""
    cancelled = await state.cancel_job(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse({"message": f"Job {job_id} cancelled"})


@app.get("/api/jobs")
async def list_jobs() -> dict:
    """List all Zeek jobs."""
    all_jobs = await state.all_jobs()
    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "job_type": getattr(j, "job_type", "unknown"),
                "status": j.status,
                "created_at": j.created_at,
                "completed_at": j.completed_at,
                **(
                    {
                        "pcap_file": j.pcap_file,
                        "interface": j.interface,
                        "total_findings": j.total_findings,
                        "conn_count": j.conn_count,
                    }
                    if isinstance(j, ZeekAnalyzeJob)
                    else {
                        "log_type": j.log_type,
                        "row_count": j.row_count,
                    }
                ),
            }
            for j in all_jobs
        ],
        "total": len(all_jobs),
    }


@app.get("/api/status")
async def server_status() -> dict:
    """Get zeek-claude service health."""
    counts = await state.job_count()
    return {
        "tool": "zeek",
        "version": "zeek-claude/1.0",
        "jobs": counts,
        "total_jobs": len(await state.all_jobs()),
        "supported_log_types": ["conn", "dns", "http", "ssl", "files", "weird", "notice", "ftp", "smtp"],
    }
