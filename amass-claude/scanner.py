"""Amass subprocess wrapper and enumeration logic."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from models import AmassJob, AmassRequest, SubdomainFinding

log = logging.getLogger("amass-claude.scanner")


async def start_amass_enum(request: AmassRequest) -> AmassJob:
    """Start an Amass enumeration job."""
    job = AmassJob(
        job_id=str(uuid.uuid4())[:8],
        domain=request.domain,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting Amass enum: {request.domain}")

    asyncio.create_task(_run_amass_enum(job, request))
    return job


async def _run_amass_enum(job: AmassJob, request: AmassRequest) -> None:
    """Background task to run Amass subprocess."""
    try:
        cmd = ["amass", "enum", "-d", request.domain]

        # Passive mode
        if request.passive:
            cmd.append("-passive")

        # Include unresolved
        if request.include_unresolved:
            cmd.append("-include-unresolved")

        # Min for recursive
        if request.min_for_recursive > 0:
            cmd.extend(["-min-for-recursive", str(request.min_for_recursive)])

        # JSON output
        cmd.append("-json")

        log.debug(f"[{job.job_id}] Running: {' '.join(cmd)}")

        try:
            result = await asyncio.wait_for(
                _subprocess_json(cmd),
                timeout=request.timeout,
            )
            subdomains = result.get("subdomains", [])

            job.results = [
                SubdomainFinding(
                    name=s.get("name", ""),
                    severity="info",
                    domain=s.get("name", ""),
                    resolved_ips=s.get("ips", []),
                    dns_records=s.get("records", {}),
                )
                for s in subdomains
            ]
            job.total_subdomains = len(job.results)
            job.status = "completed"
            log.info(f"[{job.job_id}] Completed: {job.total_subdomains} subdomains found")

        except asyncio.TimeoutError:
            job.status = "error"
            job.error = f"Enumeration timed out after {request.timeout}s"
            log.error(f"[{job.job_id}] {job.error}")

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[{job.job_id}] Exception: {e}", exc_info=True)

    finally:
        import time
        job.completed_at = time.time()


async def _subprocess_json(cmd: list[str]) -> dict:
    """Run subprocess and parse JSON output line-by-line."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    subdomains = []

    # Parse JSON lines
    for line in stdout.decode().splitlines():
        if line.strip():
            try:
                obj = json.loads(line)
                subdomains.append(obj)
            except json.JSONDecodeError:
                log.debug(f"Could not parse JSON line: {line}")

    if proc.returncode != 0 and not subdomains:
        stderr_text = stderr.decode()
        raise RuntimeError(f"Amass failed: {stderr_text}")

    return {"subdomains": subdomains}
