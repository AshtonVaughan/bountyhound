"""Gobuster subprocess wrapper and enumeration logic."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
import time
import uuid
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))
sys.path.insert(0, ".")  # local dir first

from models import GobusterJob, GobusterRequest, GobusterFinding

log = logging.getLogger("gobuster-claude.scanner")

# Global process registry for cancellation
_running_processes: dict[str, asyncio.subprocess.Process] = {}


async def start_gobuster_scan(request: GobusterRequest) -> GobusterJob:
    """Start a Gobuster enumeration job.

    Args:
        request: Gobuster scan request parameters.

    Returns:
        GobusterJob instance — background task populates results.
    """
    job = GobusterJob(
        job_id=str(uuid.uuid4())[:8],
        target=request.target,
        mode=request.mode,
        wordlist=request.wordlist,
        status="running",
    )
    log.info(
        f"[{job.job_id}] Starting gobuster {request.mode} scan "
        f"against {request.target} with wordlist {request.wordlist}"
    )
    asyncio.create_task(_run_gobuster(job, request))
    return job


async def cancel_gobuster_scan(job_id: str) -> bool:
    """Terminate a running gobuster process.

    Args:
        job_id: Job to terminate.

    Returns:
        True if process was found and killed.
    """
    proc = _running_processes.get(job_id)
    if proc:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        _running_processes.pop(job_id, None)
        return True
    return False


async def _run_gobuster(job: GobusterJob, request: GobusterRequest) -> None:
    """Background task: build command, spawn process, parse output."""
    try:
        cmd = _build_command(request)
        log.debug(f"[{job.job_id}] Command: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_processes[job.job_id] = proc

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=request.timeout,
            )
        except asyncio.TimeoutError:
            proc.terminate()
            job.status = "error"
            job.error = f"Gobuster timed out after {request.timeout}s"
            log.error(f"[{job.job_id}] {job.error}")
            return
        finally:
            _running_processes.pop(job.job_id, None)

        if job.status == "cancelled":
            # Already cancelled via cancel_gobuster_scan
            return

        findings = _parse_output(stdout.decode(errors="replace"), request.mode)
        job.results = findings
        job.total_findings = len(findings)

        if proc.returncode not in (0, 1) and not findings:
            stderr_text = stderr.decode(errors="replace").strip()
            job.status = "error"
            job.error = f"Gobuster exited {proc.returncode}: {stderr_text[:500]}"
            log.error(f"[{job.job_id}] {job.error}")
        else:
            job.status = "completed"
            log.info(f"[{job.job_id}] Completed: {job.total_findings} findings")

    except FileNotFoundError:
        job.status = "error"
        job.error = "gobuster binary not found — install gobuster and ensure it is in PATH"
        log.error(f"[{job.job_id}] {job.error}")
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Unexpected error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


def _build_command(request: GobusterRequest) -> list[str]:
    """Construct gobuster CLI command from request parameters.

    Args:
        request: GobusterRequest with all scan options.

    Returns:
        List of command tokens.
    """
    cmd = ["gobuster", request.mode]

    if request.mode in ("dir", "vhost", "fuzz"):
        cmd.extend(["-u", request.target])
    elif request.mode == "dns":
        cmd.extend(["-d", request.target])
    elif request.mode == "s3":
        pass  # s3 mode takes bucket names from wordlist

    cmd.extend(["-w", request.wordlist])
    cmd.extend(["-t", str(request.threads)])

    # Output in a parseable format (no colour)
    cmd.append("--no-color")

    if request.mode == "dir":
        if request.extensions:
            cmd.extend(["-x", ",".join(request.extensions)])
        if request.status_codes:
            cmd.extend(["-s", ",".join(str(c) for c in request.status_codes)])
        if request.follow_redirects:
            cmd.append("-r")
        if request.add_slash:
            cmd.append("-a")
        if request.expand_path:
            cmd.append("-e")

    if request.username and request.password:
        cmd.extend(["-U", request.username, "-P", request.password])

    if request.cookies:
        cmd.extend(["-c", request.cookies])

    if request.user_agent:
        cmd.extend(["-a", request.user_agent])

    if request.proxy:
        cmd.extend(["-p", request.proxy])

    if request.no_error:
        cmd.append("--no-error")

    return cmd


# Regexes for gobuster output lines
_DIR_PATTERN = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s+\[->\s*(?P<redirect>\S+)\])?",
    re.IGNORECASE,
)
_DNS_PATTERN = re.compile(
    r"^Found:\s+(?P<subdomain>\S+)$",
    re.IGNORECASE,
)
_VHOST_PATTERN = re.compile(
    r"^Found:\s+(?P<vhost>\S+)\s+\(Status:\s*(?P<status>\d+)\)",
    re.IGNORECASE,
)


def _parse_output(output: str, mode: str) -> list[GobusterFinding]:
    """Parse gobuster stdout into structured findings.

    Args:
        output: Raw stdout string from gobuster.
        mode: Scan mode (dir/dns/vhost/fuzz/s3).

    Returns:
        List of GobusterFinding instances.
    """
    findings: list[GobusterFinding] = []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("/") and "Gobuster" in line:
            continue

        if mode in ("dir", "fuzz"):
            m = _DIR_PATTERN.match(line)
            if m:
                status = int(m.group("status") or 0)
                size = int(m.group("size") or 0)
                redirect = m.group("redirect") or ""
                path = m.group("path")

                sev = _status_to_severity(status)
                findings.append(
                    GobusterFinding(
                        name=f"Discovered path: {path}",
                        severity=sev,
                        url=path,
                        description=f"HTTP {status} — {path}",
                        path=path,
                        status_code=status,
                        size=size,
                        redirect_url=redirect,
                        found_by=mode,
                    )
                )

        elif mode == "dns":
            m = _DNS_PATTERN.match(line)
            if m:
                subdomain = m.group("subdomain")
                findings.append(
                    GobusterFinding(
                        name=f"Subdomain: {subdomain}",
                        severity="info",
                        url=subdomain,
                        description=f"DNS subdomain discovered: {subdomain}",
                        path=subdomain,
                        found_by="dns",
                    )
                )

        elif mode == "vhost":
            m = _VHOST_PATTERN.match(line)
            if m:
                vhost = m.group("vhost")
                status = int(m.group("status") or 0)
                sev = _status_to_severity(status)
                findings.append(
                    GobusterFinding(
                        name=f"VHost: {vhost}",
                        severity=sev,
                        url=vhost,
                        description=f"Virtual host discovered: {vhost} (HTTP {status})",
                        path=vhost,
                        status_code=status,
                        found_by="vhost",
                    )
                )

        elif mode == "s3":
            # s3 output: BucketName  [Open/AuthRequired/DoesNotExist]
            parts = line.split()
            if len(parts) >= 2:
                bucket = parts[0]
                state_tag = parts[1].strip("[]")
                sev = "high" if state_tag == "Open" else "info"
                findings.append(
                    GobusterFinding(
                        name=f"S3 bucket: {bucket}",
                        severity=sev,
                        url=f"https://{bucket}.s3.amazonaws.com",
                        description=f"S3 bucket {bucket} is {state_tag}",
                        path=bucket,
                        found_by="s3",
                        metadata={"bucket_state": state_tag},
                    )
                )

    return findings


def _status_to_severity(status: int) -> str:
    """Map HTTP status code to a finding severity string."""
    if status in (200, 204):
        return "medium"
    if status in (301, 302, 307):
        return "low"
    if status in (401, 403):
        return "info"
    if status >= 500:
        return "high"
    return "info"
