"""Volatility3 subprocess wrapper for memory forensics analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from models import (
    VolatilityPluginJob,
    VolatilityPluginRequest,
    VolatilityBatchJob,
    VolatilityBatchRequest,
    VolatilityFinding,
    ProcessInfo,
    NetworkConnection,
)

log = logging.getLogger("volatility-claude.scanner")

# Registry for process cancellation
_running_processes: dict[str, asyncio.subprocess.Process] = {}

# Built-in triage plugin sets
TRIAGE_PLUGINS_WINDOWS = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
    "windows.malfind.Malfind",
    "windows.dlllist.DllList",
    "windows.handles.Handles",
    "windows.svcscan.SvcScan",
    "windows.registry.userassist.UserAssist",
    "windows.hashdump.Hashdump",
]

TRIAGE_PLUGINS_LINUX = [
    "linux.bash.Bash",
    "linux.pslist.PsList",
    "linux.pstree.PsTree",
    "linux.netfilter.Netfilter",
    "linux.sockstat.Sockstat",
    "linux.malfind.Malfind",
    "linux.lsmod.Lsmod",
]


async def start_plugin(request: VolatilityPluginRequest) -> VolatilityPluginJob:
    """Run a single Volatility3 plugin against a memory image.

    Args:
        request: Plugin name, memory image path, and options.

    Returns:
        VolatilityPluginJob — background task runs vol3.
    """
    if not Path(request.memory_image).exists():
        job = VolatilityPluginJob(
            job_id=str(uuid.uuid4())[:8],
            memory_image=request.memory_image,
            plugin=request.plugin,
            status="error",
            error=f"Memory image not found: {request.memory_image}",
        )
        job.completed_at = time.time()
        return job

    job = VolatilityPluginJob(
        job_id=str(uuid.uuid4())[:8],
        memory_image=request.memory_image,
        plugin=request.plugin,
        plugin_args=request.plugin_args,
        status="running",
    )
    log.info(f"[{job.job_id}] Running {request.plugin} on {request.memory_image}")
    asyncio.create_task(_run_plugin(job, request))
    return job


async def _run_plugin(job: VolatilityPluginJob, request: VolatilityPluginRequest) -> None:
    """Background task: invoke vol3 and parse JSON output."""
    try:
        cmd = _build_vol3_command(
            request.memory_image,
            request.plugin,
            request.plugin_args,
            request.symbol_path,
        )
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
            job.error = f"Plugin timed out after {request.timeout}s"
            return
        finally:
            _running_processes.pop(job.job_id, None)

        if job.status == "cancelled":
            return

        output_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")

        rows = _parse_vol3_output(output_text, request.output_format)
        job.raw_output = rows
        job.row_count = len(rows)

        # Detect OS from stderr/stdout hints
        job.os_profile = _detect_os(output_text + stderr_text, request.plugin)

        # Analyse results for security-relevant findings
        job.findings = _analyse_plugin_output(request.plugin, rows)

        if proc.returncode not in (0, 1) and not rows:
            job.status = "error"
            job.error = f"vol3 exited {proc.returncode}: {stderr_text[:500]}"
            log.error(f"[{job.job_id}] {job.error}")
        else:
            job.status = "completed"
            log.info(f"[{job.job_id}] {request.plugin}: {len(rows)} rows, {len(job.findings)} findings")

    except FileNotFoundError:
        job.status = "error"
        job.error = "vol3 (Volatility3) not found — install with: pip install volatility3"
        log.error(f"[{job.job_id}] {job.error}")
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


def _build_vol3_command(
    image: str,
    plugin: str,
    args: dict[str, str],
    symbol_path: str,
) -> list[str]:
    """Build vol3 CLI command."""
    cmd = ["vol3", "-f", image, "--renderer", "json"]
    if symbol_path:
        cmd.extend(["--symbol-dirs", symbol_path])
    cmd.append(plugin)
    for key, val in args.items():
        cmd.extend([f"--{key}", val])
    return cmd


def _parse_vol3_output(output: str, fmt: str) -> list[dict[str, Any]]:
    """Parse vol3 JSON output into list of row dicts."""
    rows: list[dict[str, Any]] = []

    if fmt == "json" or True:  # Always try JSON first
        # vol3 --renderer json emits a single JSON object with "rows" and "columns"
        try:
            obj = json.loads(output)
            if isinstance(obj, dict) and "rows" in obj:
                columns = obj.get("columns", [])
                for row_vals in obj["rows"]:
                    if isinstance(row_vals, list):
                        rows.append(dict(zip(columns, row_vals)))
                    else:
                        rows.append(row_vals)
                return rows
            if isinstance(obj, list):
                return obj
        except json.JSONDecodeError:
            pass

        # Try parsing line-by-line JSON
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    return rows


def _detect_os(output: str, plugin: str) -> str:
    """Heuristically detect OS family from plugin name and output."""
    plugin_lower = plugin.lower()
    if plugin_lower.startswith("windows."):
        return "Windows"
    if plugin_lower.startswith("linux."):
        return "Linux"
    if plugin_lower.startswith("mac."):
        return "macOS"

    if re.search(r"windows|ntoskrnl|KDBG", output, re.I):
        return "Windows"
    if re.search(r"linux|vmlinux|swapper", output, re.I):
        return "Linux"
    return "Unknown"


def _analyse_plugin_output(
    plugin: str,
    rows: list[dict[str, Any]],
) -> list[VolatilityFinding]:
    """Convert plugin rows into security findings."""
    findings: list[VolatilityFinding] = []
    plugin_lower = plugin.lower()

    if "malfind" in plugin_lower:
        for row in rows:
            findings.append(
                VolatilityFinding(
                    name=f"Malfind: Suspicious memory region in PID {row.get('PID', row.get('pid', '?'))}",
                    severity="high",
                    description=(
                        f"Process {row.get('Process', row.get('process', 'Unknown'))} "
                        f"has suspicious memory with protection {row.get('Protection', 'UNKNOWN')}"
                    ),
                    plugin=plugin,
                    raw_data=row,
                    indicator_type="injected_code",
                    memory_offset=str(row.get("Start VPN", row.get("start", ""))),
                )
            )

    elif "pslist" in plugin_lower or "pstree" in plugin_lower:
        # Flag unusual parent-child relationships
        for row in rows:
            pid = int(row.get("PID", row.get("pid", 0)) or 0)
            ppid = int(row.get("PPID", row.get("ppid", 0)) or 0)
            name = str(row.get("ImageFileName", row.get("name", row.get("COMM", "")))).lower()

            # Flag cmd/powershell spawned by unusual parents
            suspicious_children = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}
            if name in suspicious_children and ppid not in (0, 4):
                proc = ProcessInfo(
                    pid=pid, ppid=ppid,
                    name=str(row.get("ImageFileName", row.get("COMM", ""))),
                    threads=int(row.get("Threads", 0) or 0),
                    handles=int(row.get("Handles", 0) or 0),
                )
                findings.append(
                    VolatilityFinding(
                        name=f"Suspicious process: {proc.name} (PID {pid}, PPID {ppid})",
                        severity="medium",
                        description=f"Potentially suspicious shell process spawned by PPID {ppid}",
                        plugin=plugin,
                        process=proc,
                        raw_data=row,
                        indicator_type="suspicious_process",
                    )
                )

    elif "netscan" in plugin_lower or "netstat" in plugin_lower or "sockstat" in plugin_lower:
        for row in rows:
            remote = str(row.get("ForeignAddr", row.get("remote_addr", "")))
            state = str(row.get("State", row.get("state", "")))
            pid = int(row.get("PID", row.get("pid", 0)) or 0)
            port = int(row.get("ForeignPort", row.get("remote_port", 0)) or 0)

            # Flag established connections to non-private IPs on suspicious ports
            suspicious_ports = {4444, 1234, 31337, 8080, 8443, 443, 80}
            if (state == "ESTABLISHED" and remote and not remote.startswith("0.0.0.0")
                    and not _is_private_ip(remote)):
                conn = NetworkConnection(
                    pid=pid,
                    proto=str(row.get("Proto", "")),
                    remote_addr=remote,
                    remote_port=port,
                    state=state,
                )
                sev = "high" if port in suspicious_ports else "medium"
                findings.append(
                    VolatilityFinding(
                        name=f"External connection: PID {pid} -> {remote}:{port}",
                        severity=sev,
                        description=f"Process {pid} has established connection to {remote}:{port}",
                        plugin=plugin,
                        network=conn,
                        raw_data=row,
                        indicator_type="suspicious_network",
                    )
                )

    elif "hashdump" in plugin_lower:
        for row in rows:
            username = str(row.get("Username", row.get("user", "??")))
            lm_hash = str(row.get("LMHash", row.get("lm", "")))
            nt_hash = str(row.get("NTHash", row.get("nt", "")))
            findings.append(
                VolatilityFinding(
                    name=f"Credential dump: {username}",
                    severity="critical",
                    description=f"Extracted credentials for {username}: NT={nt_hash[:8]}...",
                    plugin=plugin,
                    raw_data=row,
                    indicator_type="credential_dump",
                )
            )

    return findings


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in RFC1918 or loopback range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # IPv6 or invalid — skip
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
        )
    except ValueError:
        return True


# ── Batch analysis ────────────────────────────────────────────────────────────

async def start_batch(request: VolatilityBatchRequest) -> VolatilityBatchJob:
    """Run multiple Volatility plugins sequentially as a batch.

    Args:
        request: List of plugins and memory image path.

    Returns:
        VolatilityBatchJob — background task runs each plugin.
    """
    if not Path(request.memory_image).exists():
        job = VolatilityBatchJob(
            job_id=str(uuid.uuid4())[:8],
            memory_image=request.memory_image,
            plugins_requested=request.plugins,
            status="error",
            error=f"Memory image not found: {request.memory_image}",
        )
        job.completed_at = time.time()
        return job

    job = VolatilityBatchJob(
        job_id=str(uuid.uuid4())[:8],
        memory_image=request.memory_image,
        plugins_requested=request.plugins,
        status="running",
    )
    log.info(f"[{job.job_id}] Batch: {len(request.plugins)} plugins on {request.memory_image}")
    asyncio.create_task(_run_batch(job, request))
    return job


async def _run_batch(job: VolatilityBatchJob, request: VolatilityBatchRequest) -> None:
    """Background task: run each plugin sequentially."""
    try:
        for plugin in request.plugins:
            if job.status == "cancelled":
                break

            plugin_args = request.plugin_args.get(plugin, {})
            cmd = _build_vol3_command(
                request.memory_image,
                plugin,
                plugin_args,
                request.symbol_path,
            )

            log.debug(f"[{job.job_id}] Batch plugin: {plugin}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=min(request.timeout / len(request.plugins), 600),
                )
                rows = _parse_vol3_output(stdout.decode(errors="replace"), request.output_format)
                job.plugin_results[plugin] = rows

                # Detect OS from first info plugin
                if not job.os_profile and "info" in plugin.lower():
                    job.os_profile = _detect_os(stdout.decode(errors="replace"), plugin)

                findings = _analyse_plugin_output(plugin, rows)
                job.all_findings.extend(findings)
                job.plugins_completed.append(plugin)

            except asyncio.TimeoutError:
                log.warning(f"[{job.job_id}] Plugin {plugin} timed out — skipping")
                job.plugins_failed.append(plugin)
                if request.stop_on_error:
                    break
            except Exception as exc:
                log.warning(f"[{job.job_id}] Plugin {plugin} failed: {exc}")
                job.plugins_failed.append(plugin)
                if request.stop_on_error:
                    break

        job.total_findings = len(job.all_findings)
        job.status = "completed"
        log.info(
            f"[{job.job_id}] Batch complete: "
            f"{len(job.plugins_completed)}/{len(request.plugins)} plugins, "
            f"{job.total_findings} findings"
        )

    except FileNotFoundError:
        job.status = "error"
        job.error = "vol3 not found — install: pip install volatility3"
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Batch error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


def get_triage_plugins(os_family: str = "windows") -> list[str]:
    """Return a recommended triage plugin set for the given OS."""
    if os_family.lower() == "linux":
        return TRIAGE_PLUGINS_LINUX
    return TRIAGE_PLUGINS_WINDOWS
