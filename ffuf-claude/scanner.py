"""Ffuf subprocess wrapper and fuzzing logic."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from models import FfufJob, FfufRequest, FfufResult

log = logging.getLogger("ffuf-claude.scanner")


async def start_ffuf_fuzz(request: FfufRequest) -> FfufJob:
    """Start an Ffuf fuzzing job."""
    job = FfufJob(
        job_id=str(uuid.uuid4())[:8],
        url=request.url,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting Ffuf fuzz: {request.url}")

    asyncio.create_task(_run_ffuf_fuzz(job, request))
    return job


async def _run_ffuf_fuzz(job: FfufJob, request: FfufRequest) -> None:
    """Background task to run Ffuf subprocess."""
    try:
        cmd = ["ffuf", "-u", request.url, "-w", request.wordlist]

        # HTTP method
        if request.method.upper() != "GET":
            cmd.extend(["-X", request.method.upper()])

        # Status filters
        if request.match_status:
            cmd.extend(["-mc", request.match_status])
        if request.filter_status:
            cmd.extend(["-fc", request.filter_status])

        # Size filters
        if request.match_size > 0:
            cmd.extend(["-ms", str(request.match_size)])
        if request.filter_size > 0:
            cmd.extend(["-fs", str(request.filter_size)])

        # Headers
        for k, v in request.headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        # JSON output
        cmd.append("-json")

        log.debug(f"[{job.job_id}] Running: {' '.join(cmd)}")

        try:
            result = await asyncio.wait_for(
                _subprocess_json(cmd),
                timeout=request.timeout,
            )
            results = result.get("results", [])

            job.results = [
                FfufResult(
                    name=r.get("url", ""),
                    severity="medium",
                    url=r.get("url", ""),
                    status=r.get("status", 0),
                    content_length=r.get("length", 0),
                    content_type=r.get("content-type", ""),
                    words=r.get("words", 0),
                    lines=r.get("lines", 0),
                )
                for r in results
            ]
            job.total_results = len(job.results)
            job.status = "completed"
            log.info(f"[{job.job_id}] Completed: {job.total_results} results found")

        except asyncio.TimeoutError:
            job.status = "error"
            job.error = f"Fuzz timed out after {request.timeout}s"
            log.error(f"[{job.job_id}] {job.error}")

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[{job.job_id}] Exception: {e}", exc_info=True)

    finally:
        import time
        job.completed_at = time.time()


async def _subprocess_json(cmd: list[str]) -> dict:
    """Run subprocess and parse JSON output."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    results = []

    try:
        data = json.loads(stdout)
        results = data.get("results", [])
    except json.JSONDecodeError as e:
        log.debug(f"Error parsing Ffuf JSON: {e}")

    if proc.returncode != 0 and not results:
        stderr_text = stderr.decode()
        raise RuntimeError(f"Ffuf failed: {stderr_text}")

    return {"results": results}
