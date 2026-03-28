"""Nuclei subprocess wrapper and scanning logic."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import uuid

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from models import NucleiJob, NucleiRequest, NucleiFinding

log = logging.getLogger("nuclei-claude.scanner")


async def start_nuclei_scan(request: NucleiRequest) -> NucleiJob:
    """Start a Nuclei scan job.

    Args:
        request: Nuclei scan request.

    Returns:
        NucleiJob instance (status will be updated by background task).
    """
    job = NucleiJob(
        job_id=str(uuid.uuid4())[:8],
        urls=request.urls,
        templates=request.templates,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting Nuclei scan: {len(request.urls)} URLs, templates={request.templates}")

    # Spawn background task to run the scan
    asyncio.create_task(_run_nuclei_scan(job, request))

    return job


async def _run_nuclei_scan(job: NucleiJob, request: NucleiRequest) -> None:
    """Background task to run Nuclei subprocess.

    Updates job.status, job.results, and job.completed_at.
    """
    try:
        # Build nuclei command
        cmd = ["nuclei"]

        # Add URLs
        for url in request.urls:
            cmd.extend(["-u", url])

        # Add templates
        if request.templates:
            cmd.extend(["-t", ",".join(request.templates)])

        # Add filters
        if request.severity:
            cmd.extend(["-s", request.severity])
        if request.tag:
            cmd.extend(["-tags", request.tag])
        if request.exclude_templates:
            cmd.extend(["-et", ",".join(request.exclude_templates)])

        # Performance
        cmd.extend(["-rl", str(request.rate_limit)])
        cmd.extend(["-bs", str(request.bulk_size)])

        # JSON output
        cmd.append("-json")

        # Subprocess with timeout
        log.debug(f"[{job.job_id}] Running: {' '.join(cmd)}")

        try:
            result = await asyncio.wait_for(
                _subprocess_json(cmd),
                timeout=request.timeout,
            )
            findings = result.get("findings", [])

            # Parse findings
            job.results = [
                NucleiFinding(
                    name=f["template_id"],
                    severity=f.get("severity", "medium").lower(),
                    url=f.get("matched_url", ""),
                    description=f.get("info", {}).get("description", ""),
                    template_id=f.get("template_id", ""),
                    template_info=f.get("info", {}),
                    matcher_name=f.get("matcher_name", ""),
                    extracted_results=f.get("extracted_results", []),
                )
                for f in findings
            ]
            job.total_findings = len(job.results)
            job.status = "completed"
            log.info(f"[{job.job_id}] Completed: {job.total_findings} findings")

        except asyncio.TimeoutError:
            job.status = "error"
            job.error = f"Scan timed out after {request.timeout}s"
            log.error(f"[{job.job_id}] {job.error}")

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[{job.job_id}] Exception: {e}", exc_info=True)

    finally:
        import time
        job.completed_at = time.time()


async def _subprocess_json(cmd: list[str]) -> dict:
    """Run subprocess and parse JSON output line-by-line.

    Args:
        cmd: Command and arguments.

    Returns:
        Dictionary with 'findings' key containing list of parsed findings.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    findings = []

    # Parse JSON lines
    for line in stdout.decode().splitlines():
        if line.strip():
            try:
                obj = json.loads(line)
                findings.append(obj)
            except json.JSONDecodeError:
                log.debug(f"Could not parse JSON line: {line}")

    if proc.returncode != 0:
        stderr_text = stderr.decode()
        if findings:
            # Some findings were found before error
            log.warning(f"Nuclei exited with code {proc.returncode}: {stderr_text}")
        else:
            raise RuntimeError(f"Nuclei failed: {stderr_text}")

    return {"findings": findings}
