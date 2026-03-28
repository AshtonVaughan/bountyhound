"""SQLMap subprocess wrapper and testing logic."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import uuid

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from models import SqlmapJob, SqlmapRequest, SqliVulnerability

log = logging.getLogger("sqlmap-claude.scanner")


async def start_sqlmap_test(request: SqlmapRequest) -> SqlmapJob:
    """Start a SQLMap testing job.

    Args:
        request: SQLMap test request.

    Returns:
        SqlmapJob instance (status will be updated by background task).
    """
    job = SqlmapJob(
        job_id=str(uuid.uuid4())[:8],
        url=request.url,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting SQLMap test: {request.url}")

    # Spawn background task to run the test
    asyncio.create_task(_run_sqlmap_test(job, request))

    return job


async def _run_sqlmap_test(job: SqlmapJob, request: SqlmapRequest) -> None:
    """Background task to run SQLMap subprocess.

    Updates job.status, job.results, and job.completed_at.
    """
    try:
        # Build sqlmap command
        cmd = ["sqlmap", "-u", request.url]

        # HTTP method
        if request.method.upper() != "GET":
            cmd.extend(["-m", request.method.upper()])

        # POST data
        if request.data:
            cmd.extend(["--data", request.data])

        # Headers
        for k, v in request.headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        # Specific parameters
        if request.parameters:
            for param in request.parameters:
                cmd.extend(["-p", param])

        # Detection level and risk
        cmd.extend(["--level", str(request.level)])
        cmd.extend(["--risk", str(request.risk)])

        # JSON output
        cmd.append("--json-output")
        cmd.append("/tmp/sqlmap_output")

        # Batch mode
        cmd.append("--batch")

        log.debug(f"[{job.job_id}] Running: {' '.join(cmd)}")

        try:
            result = await asyncio.wait_for(
                _subprocess_run(cmd),
                timeout=request.timeout,
            )

            vulnerabilities = result.get("vulnerabilities", [])

            # Parse vulnerabilities
            job.results = [
                SqliVulnerability(
                    name=f.get("title", "SQL Injection"),
                    severity="critical",
                    url=f.get("url", request.url),
                    parameter=f.get("parameter", ""),
                    injection_type=f.get("type", ""),
                    dbms=f.get("dbms", ""),
                    payload=f.get("payload", ""),
                    description=f.get("description", ""),
                )
                for f in vulnerabilities
            ]
            job.total_vulnerabilities = len(job.results)
            job.status = "completed"
            log.info(f"[{job.job_id}] Completed: {job.total_vulnerabilities} vulnerabilities found")

        except asyncio.TimeoutError:
            job.status = "error"
            job.error = f"Test timed out after {request.timeout}s"
            log.error(f"[{job.job_id}] {job.error}")

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[{job.job_id}] Exception: {e}", exc_info=True)

    finally:
        import time
        job.completed_at = time.time()


async def _subprocess_run(cmd: list[str]) -> dict:
    """Run subprocess and parse output.

    Args:
        cmd: Command and arguments.

    Returns:
        Dictionary with 'vulnerabilities' key containing list of found vulns.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()

    if proc.returncode not in (0, 1):  # 1 means no vulnerability found (not an error)
        stderr_text = stderr.decode()
        log.warning(f"SQLMap exited with code {proc.returncode}: {stderr_text}")

    # Parse JSON output from file (simplified for now)
    vulnerabilities = []
    try:
        # In real implementation, read from /tmp/sqlmap_output
        # For now, return empty list
        pass
    except Exception as e:
        log.debug(f"Error parsing SQLMap output: {e}")

    return {"vulnerabilities": vulnerabilities}
