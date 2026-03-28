"""FastAPI server for bloodhound-claude."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from typing import Union

from models import (
    BloodHoundCollectRequest,
    BloodHoundQueryRequest,
    BloodHoundPathRequest,
    BloodHoundCollectJob,
    BloodHoundQueryJob,
    BloodHoundPathJob,
)
from state import BloodHoundStateManager
from scanner import (
    start_collection,
    start_query,
    start_path_analysis,
    get_builtin_queries,
)

app = FastAPI(
    title="bloodhound-claude",
    description="Active Directory enumeration, Cypher queries, and attack path analysis via BloodHound",
    version="1.0.0",
)
state = BloodHoundStateManager()


# ── Collection endpoints ──────────────────────────────────────────────────────

@app.post("/api/collect", response_model=BloodHoundCollectJob, status_code=202)
async def collect(request: BloodHoundCollectRequest) -> BloodHoundCollectJob:
    """Start BloodHound data collection (bloodhound-python or SharpHound).

    Runs in background. Returns a job_id to poll for completion.
    Output files are written to the configured BH_OUTPUT_DIR.
    """
    if not request.domain:
        raise HTTPException(status_code=400, detail="domain cannot be empty")

    job = await start_collection(request)
    await state.add_job(job)
    return job


@app.get("/api/collect/{job_id}", response_model=BloodHoundCollectJob)
async def get_collect_job(job_id: str) -> BloodHoundCollectJob:
    """Get collection job status, output files, and object counts."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, BloodHoundCollectJob):
        raise HTTPException(status_code=404, detail=f"Collection job {job_id} not found")
    return job


# ── Query endpoints ───────────────────────────────────────────────────────────

@app.post("/api/query", response_model=BloodHoundQueryJob, status_code=202)
async def run_query(request: BloodHoundQueryRequest) -> BloodHoundQueryJob:
    """Execute a raw Cypher query against Neo4j.

    Returns a job_id. Poll /api/query/{job_id} for results.
    """
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="query cannot be empty")

    job = await start_query(request)
    await state.add_job(job)
    return job


@app.get("/api/query/{job_id}", response_model=BloodHoundQueryJob)
async def get_query_job(job_id: str) -> BloodHoundQueryJob:
    """Get Cypher query results."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, BloodHoundQueryJob):
        raise HTTPException(status_code=404, detail=f"Query job {job_id} not found")
    return job


@app.get("/api/queries")
async def list_builtin_queries() -> dict:
    """List built-in Cypher query shortcuts (kerberoastable, asrep, paths, etc.)."""
    return {"queries": get_builtin_queries()}


# ── Path analysis endpoints ───────────────────────────────────────────────────

@app.post("/api/paths", response_model=BloodHoundPathJob, status_code=202)
async def find_paths(request: BloodHoundPathRequest) -> BloodHoundPathJob:
    """Find attack paths between two AD nodes.

    path_type options:
      - shortest: shortestPath between source and target (default)
      - all: all paths up to depth 10
      - kerberoastable: uses built-in kerberoastable query (ignores source/target)
      - asreproastable: uses built-in asrep query
      - unconstrained_delegation: computers with unconstrained delegation
      - da_sessions: domain admin sessions
      - dcsync_principals: principals with DCSync rights
    """
    job = await start_path_analysis(request)
    await state.add_job(job)
    return job


@app.get("/api/paths/{job_id}", response_model=BloodHoundPathJob)
async def get_path_job(job_id: str) -> BloodHoundPathJob:
    """Get attack path results and findings."""
    job = await state.get_job(job_id)
    if not job or not isinstance(job, BloodHoundPathJob):
        raise HTTPException(status_code=404, detail=f"Path job {job_id} not found")
    return job


# ── Generic endpoints ─────────────────────────────────────────────────────────

@app.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str) -> JSONResponse:
    """Cancel any running BloodHound job."""
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
        if isinstance(j, BloodHoundCollectJob):
            entry["domain"] = j.domain
            entry["objects_collected"] = j.objects_collected
        elif isinstance(j, BloodHoundQueryJob):
            entry["row_count"] = j.row_count
            entry["query_preview"] = j.query[:60]
        elif isinstance(j, BloodHoundPathJob):
            entry["source"] = j.source
            entry["target"] = j.target
            entry["total_paths"] = j.total_paths
        summary.append(entry)
    return {"jobs": summary, "total": len(all_jobs)}


@app.get("/api/status")
async def server_status() -> dict:
    """Get bloodhound-claude service health and job counts."""
    counts = await state.job_count()
    all_jobs = await state.all_jobs()
    return {
        "tool": "bloodhound",
        "version": "bloodhound-claude/1.0",
        "jobs": counts,
        "total_jobs": len(all_jobs),
        "builtin_queries": list(get_builtin_queries().keys()),
    }
