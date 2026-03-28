"""Nmap subprocess wrapper and scanning logic."""

from __future__ import annotations

import asyncio
import logging
import uuid
import xml.etree.ElementTree as ET

import sys
sys.path.insert(0, "../bh-core")
sys.path.insert(0, ".")  # local dir first

from models import NmapJob, NmapRequest, PortFinding

log = logging.getLogger("nmap-claude.scanner")


async def start_nmap_scan(request: NmapRequest) -> NmapJob:
    """Start an Nmap scan job."""
    job = NmapJob(
        job_id=str(uuid.uuid4())[:8],
        targets=request.targets,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting Nmap scan: {len(request.targets)} targets")

    asyncio.create_task(_run_nmap_scan(job, request))
    return job


async def _run_nmap_scan(job: NmapJob, request: NmapRequest) -> None:
    """Background task to run Nmap subprocess."""
    try:
        cmd = ["nmap"]

        # Scan type
        if request.scan_type == "sS":
            cmd.append("-sS")
        elif request.scan_type == "sT":
            cmd.append("-sT")
        elif request.scan_type == "sU":
            cmd.append("-sU")
        else:  # sV (default)
            cmd.append("-sV")

        # Ports
        if request.ports:
            cmd.extend(["-p", request.ports])

        # Aggressive
        if request.aggressive:
            cmd.append("-A")

        # XML output
        cmd.extend(["-oX", "-"])

        # Targets
        cmd.extend(request.targets)

        log.debug(f"[{job.job_id}] Running: {' '.join(cmd)}")

        try:
            result = await asyncio.wait_for(
                _subprocess_xml(cmd),
                timeout=request.timeout,
            )
            ports = result.get("ports", [])

            job.results = [
                PortFinding(
                    name=f"{p['port']}/{p['protocol']} ({p.get('service', 'unknown')})",
                    severity="high" if p["state"] == "open" else "low",
                    port=p["port"],
                    protocol=p["protocol"],
                    state=p["state"],
                    service=p.get("service", ""),
                    version=p.get("version", ""),
                    product=p.get("product", ""),
                )
                for p in ports
            ]
            job.total_ports = len(job.results)
            job.status = "completed"
            log.info(f"[{job.job_id}] Completed: {job.total_ports} ports scanned")

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


async def _subprocess_xml(cmd: list[str]) -> dict:
    """Run subprocess and parse XML output."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    ports = []

    try:
        root = ET.fromstring(stdout)
        for host in root.findall("host"):
            for port in host.findall("ports/port"):
                state = port.find("state")
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid").split("/")[0]),
                    "protocol": port.get("protocol", "tcp"),
                    "state": state.get("state", "unknown") if state is not None else "unknown",
                    "service": service.get("name", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                })
    except Exception as e:
        log.debug(f"Error parsing Nmap XML: {e}")

    if proc.returncode != 0 and not ports:
        stderr_text = stderr.decode()
        raise RuntimeError(f"Nmap failed: {stderr_text}")

    return {"ports": ports}
