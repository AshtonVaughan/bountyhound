"""Nessus REST API client for scan management and result retrieval."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from models import (
    NessusScanJob,
    NessusScanRequest,
    NessusExportJob,
    NessusExportRequest,
    NessusVulnerability,
)

log = logging.getLogger("nessus-claude.scanner")

EXPORT_DIR = Path(os.environ.get("NESSUS_EXPORT_DIR", "/tmp/nessus-exports"))

# Severity mapping from Nessus risk_factor string
_SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "None": "info",
    "": "info",
}


async def start_scan(request: NessusScanRequest) -> NessusScanJob:
    """Launch a Nessus scan via REST API.

    Args:
        request: Scan parameters and Nessus API credentials.

    Returns:
        NessusScanJob — background task polls until complete.
    """
    name = request.scan_name or f"bountyhound-{int(time.time())}"
    job = NessusScanJob(
        job_id=str(uuid.uuid4())[:8],
        scan_name=name,
        targets=request.targets,
        scan_template=request.scan_template,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting Nessus scan '{name}' against {len(request.targets)} targets")
    asyncio.create_task(_run_scan(job, request))
    return job


async def _run_scan(job: NessusScanJob, request: NessusScanRequest) -> None:
    """Background task: create scan, poll status, retrieve results."""
    try:
        async with _NessusClient(
            request.nessus_url,
            request.access_key,
            request.secret_key,
        ) as client:
            # Create the scan
            scan_def = {
                "uuid": await client.get_template_uuid(request.scan_template),
                "settings": {
                    "name": job.scan_name,
                    "enabled": True,
                    "text_targets": "\n".join(request.targets),
                    "folder_id": request.folder_id or None,
                },
            }

            # Add credential settings if provided
            if request.ssh_username:
                scan_def["credentials"] = {
                    "add": {
                        "SSH": {"SSH": [{"username": request.ssh_username, "password": request.ssh_password}]}
                    }
                }

            scan_resp = await client.post("/scans", scan_def)
            nessus_scan_id = scan_resp["scan"]["id"]
            job.nessus_scan_id = nessus_scan_id

            # Launch the scan
            await client.post(f"/scans/{nessus_scan_id}/launch", {})
            log.info(f"[{job.job_id}] Nessus scan {nessus_scan_id} launched")

            # Poll until terminal state
            deadline = time.time() + request.timeout
            while time.time() < deadline:
                await asyncio.sleep(15)
                detail = await client.get(f"/scans/{nessus_scan_id}")
                nessus_status = detail.get("info", {}).get("status", "")
                job.nessus_status = nessus_status

                if nessus_status in ("completed", "canceled", "aborted"):
                    break
                if job.status == "cancelled":
                    await client.post(f"/scans/{nessus_scan_id}/stop", {})
                    return
            else:
                job.status = "error"
                job.error = f"Nessus scan timed out after {request.timeout}s"
                return

            # Retrieve results
            hosts = detail.get("hosts", [])
            job.hosts_scanned = len(hosts)

            vulns = await _fetch_vulnerabilities(client, nessus_scan_id, detail)
            job.vulnerabilities = vulns
            job.total_vulnerabilities = len(vulns)

            # Count by severity
            for v in vulns:
                if v.severity == "critical":
                    job.critical_count += 1
                elif v.severity == "high":
                    job.high_count += 1
                elif v.severity == "medium":
                    job.medium_count += 1
                elif v.severity == "low":
                    job.low_count += 1

            job.status = "completed"
            log.info(
                f"[{job.job_id}] Scan complete: "
                f"{job.total_vulnerabilities} vulns, "
                f"{job.critical_count} critical, {job.high_count} high"
            )

    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Scan error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


async def _fetch_vulnerabilities(
    client: "_NessusClient",
    scan_id: int,
    scan_detail: dict[str, Any],
) -> list[NessusVulnerability]:
    """Fetch per-plugin vulnerability details from scan results."""
    vulns: list[NessusVulnerability] = []
    plugins_seen: set[int] = set()

    for host in scan_detail.get("hosts", []):
        host_id = host.get("host_id", 0)
        host_ip = host.get("hostname", "")

        host_detail = await client.get(f"/scans/{scan_id}/hosts/{host_id}")
        for vuln_item in host_detail.get("vulnerabilities", []):
            plugin_id = vuln_item.get("plugin_id", 0)
            severity_int = vuln_item.get("severity", 0)
            severity = ["info", "low", "medium", "high", "critical"][min(severity_int, 4)]

            if plugin_id not in plugins_seen:
                plugins_seen.add(plugin_id)
                # Fetch plugin detail for full info
                try:
                    plugin_detail = await client.get(
                        f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
                    )
                    info = plugin_detail.get("info", {})
                    plugindesc = info.get("plugindescription", {})
                    pluginattr = plugindesc.get("pluginattributes", {})
                except Exception:
                    pluginattr = {}

                cve_list = [
                    r.get("ref") for r in pluginattr.get("ref_information", {}).get("ref", [])
                    if r.get("name") == "CVE"
                ]
                risk_info = pluginattr.get("risk_information", {})

                vulns.append(
                    NessusVulnerability(
                        name=vuln_item.get("plugin_name", f"Plugin {plugin_id}"),
                        severity=severity,
                        url=host_ip,
                        description=pluginattr.get("description", ""),
                        plugin_id=plugin_id,
                        plugin_name=vuln_item.get("plugin_name", ""),
                        plugin_family=vuln_item.get("plugin_family", ""),
                        cve_list=cve_list,
                        cvss_base_score=float(risk_info.get("cvss_base_score", 0)),
                        cvss_vector=risk_info.get("cvss_vector", ""),
                        cvss3_base_score=float(risk_info.get("cvss3_base_score", 0)),
                        risk_factor=risk_info.get("risk_factor", ""),
                        solution=pluginattr.get("solution", ""),
                        exploit_available=pluginattr.get("exploitability_information", {}).get(
                            "exploit_available", "false"
                        ).lower() == "true",
                        affected_hosts=[host_ip],
                        port=vuln_item.get("port", 0),
                        protocol=vuln_item.get("protocol", ""),
                        remediation=pluginattr.get("solution", ""),
                    )
                )
            else:
                # Already seen — just add the host to affected list
                for v in vulns:
                    if v.plugin_id == plugin_id and host_ip not in v.affected_hosts:
                        v.affected_hosts.append(host_ip)

    return vulns


async def start_export(request: NessusExportRequest) -> NessusExportJob:
    """Export an existing Nessus scan.

    Args:
        request: Scan ID, format, and API credentials.

    Returns:
        NessusExportJob — background task downloads the file.
    """
    job = NessusExportJob(
        job_id=str(uuid.uuid4())[:8],
        scan_id=request.scan_id,
        export_format=request.export_format,
        status="running",
    )
    log.info(f"[{job.job_id}] Exporting Nessus scan {request.scan_id} as {request.export_format}")
    asyncio.create_task(_run_export(job, request))
    return job


async def _run_export(job: NessusExportJob, request: NessusExportRequest) -> None:
    """Background task: request export, poll, and download."""
    try:
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        async with _NessusClient(
            request.nessus_url,
            request.access_key,
            request.secret_key,
        ) as client:
            # Request export
            export_resp = await client.post(
                f"/scans/{request.scan_id}/export",
                {"format": request.export_format},
            )
            file_id = export_resp.get("file")

            # Poll for readiness
            deadline = time.time() + request.timeout
            while time.time() < deadline:
                await asyncio.sleep(5)
                status_resp = await client.get(
                    f"/scans/{request.scan_id}/export/{file_id}/status"
                )
                if status_resp.get("status") == "ready":
                    break
            else:
                job.status = "error"
                job.error = "Export timed out"
                return

            # Download
            content = await client.download(
                f"/scans/{request.scan_id}/export/{file_id}/download"
            )
            out_path = EXPORT_DIR / f"scan_{request.scan_id}.{request.export_format}"
            out_path.write_bytes(content)
            job.export_file = str(out_path)
            job.status = "completed"
            log.info(f"[{job.job_id}] Export saved to {out_path}")

    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Export error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


class _NessusClient:
    """Async context-managed Nessus REST API client."""

    def __init__(self, base_url: str, access_key: str, secret_key: str):
        self.base_url = base_url.rstrip("/")
        self._headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._client: Any = None

    async def __aenter__(self) -> "_NessusClient":
        import httpx
        self._client = httpx.AsyncClient(
            verify=False,  # Nessus uses self-signed certs by default
            timeout=30.0,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def get(self, endpoint: str) -> dict[str, Any]:
        resp = await self._client.get(
            f"{self.base_url}{endpoint}", headers=self._headers
        )
        resp.raise_for_status()
        return resp.json()

    async def post(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = await self._client.post(
            f"{self.base_url}{endpoint}", headers=self._headers, json=body
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    async def download(self, endpoint: str) -> bytes:
        resp = await self._client.get(
            f"{self.base_url}{endpoint}", headers=self._headers
        )
        resp.raise_for_status()
        return resp.content

    async def get_template_uuid(self, template_name: str) -> str:
        """Look up scan template UUID by name."""
        templates = await self.get("/editor/scan/templates")
        for t in templates.get("templates", []):
            if t.get("name", "").lower() == template_name.lower():
                return t["uuid"]
        # Default to basic network scan template UUID
        return "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66"
