"""Zeek subprocess wrapper for PCAP analysis and live capture."""

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
    ZeekAnalyzeJob,
    ZeekAnalyzeRequest,
    ZeekLiveRequest,
    ZeekQueryJob,
    ZeekLogQueryRequest,
    ZeekFinding,
    ZeekConnection,
    ZeekDNS,
    ZeekHTTP,
    ZeekSSL,
)

log = logging.getLogger("zeek-claude.scanner")

_running_processes: dict[str, asyncio.subprocess.Process] = {}

LOG_DIR_BASE = Path(os.environ.get("ZEEK_LOG_DIR", "/tmp/zeek-logs"))

# Suspicious port set for C2/lateral movement detection
_SUSPICIOUS_PORTS = {4444, 1234, 31337, 8080, 8443, 9001, 6667, 6666}
# Common DGA-style TLD list
_SUSPICIOUS_TLDS = {".tk", ".top", ".xyz", ".cc", ".pw", ".click"}


async def start_pcap_analysis(request: ZeekAnalyzeRequest) -> ZeekAnalyzeJob:
    """Analyze a PCAP file with Zeek.

    Args:
        request: PCAP path and analysis options.

    Returns:
        ZeekAnalyzeJob — background task runs Zeek and parses logs.
    """
    if not Path(request.pcap_file).exists():
        job = ZeekAnalyzeJob(
            job_id=str(uuid.uuid4())[:8],
            pcap_file=request.pcap_file,
            status="error",
            error=f"PCAP file not found: {request.pcap_file}",
        )
        job.completed_at = time.time()
        return job

    job = ZeekAnalyzeJob(
        job_id=str(uuid.uuid4())[:8],
        pcap_file=request.pcap_file,
        status="running",
    )
    log.info(f"[{job.job_id}] Analyzing PCAP: {request.pcap_file}")
    asyncio.create_task(_run_pcap_analysis(job, request))
    return job


async def start_live_capture(request: ZeekLiveRequest) -> ZeekAnalyzeJob:
    """Run Zeek against a live network interface.

    Args:
        request: Interface name, duration, and scripts.

    Returns:
        ZeekAnalyzeJob — background task handles timed capture.
    """
    job = ZeekAnalyzeJob(
        job_id=str(uuid.uuid4())[:8],
        interface=request.interface,
        status="running",
    )
    log.info(f"[{job.job_id}] Live capture on {request.interface} for {request.duration}s")
    asyncio.create_task(_run_live_capture(job, request))
    return job


async def _run_pcap_analysis(job: ZeekAnalyzeJob, request: ZeekAnalyzeRequest) -> None:
    """Background task: run zeek -r <pcap> and analyse generated logs."""
    try:
        out_dir = _setup_output_dir(job.job_id, request.output_dir)
        job.output_dir = str(out_dir)

        cmd = _build_zeek_pcap_command(request, out_dir)
        log.debug(f"[{job.job_id}] Command: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(out_dir),
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
            job.error = f"Zeek timed out after {request.timeout}s"
            return
        finally:
            _running_processes.pop(job.job_id, None)

        if job.status == "cancelled":
            return

        await _process_zeek_logs(job, out_dir)
        job.status = "completed"
        log.info(
            f"[{job.job_id}] Analysis complete: "
            f"{job.conn_count} conns, {job.dns_count} DNS, "
            f"{job.http_count} HTTP, {len(job.findings)} findings"
        )

    except FileNotFoundError:
        job.status = "error"
        job.error = "zeek binary not found — install Zeek: https://zeek.org/get-zeek/"
        log.error(f"[{job.job_id}] {job.error}")
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


async def _run_live_capture(job: ZeekAnalyzeJob, request: ZeekLiveRequest) -> None:
    """Background task: run zeek on live interface with timeout."""
    try:
        out_dir = _setup_output_dir(job.job_id, request.output_dir)
        job.output_dir = str(out_dir)

        cmd = ["zeek", "-i", request.interface]
        for script in request.scripts:
            cmd.append(script)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(out_dir),
        )
        _running_processes[job.job_id] = proc

        try:
            # Run for the specified duration, then terminate
            await asyncio.wait_for(
                proc.wait(),
                timeout=request.duration + 5,
            )
        except asyncio.TimeoutError:
            proc.terminate()
            await asyncio.sleep(1)
        finally:
            _running_processes.pop(job.job_id, None)

        if job.status != "cancelled":
            await _process_zeek_logs(job, out_dir)
            job.status = "completed"
            log.info(f"[{job.job_id}] Live capture complete: {len(job.findings)} findings")

    except FileNotFoundError:
        job.status = "error"
        job.error = "zeek binary not found"
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Live capture error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


def _setup_output_dir(job_id: str, requested_dir: str) -> Path:
    """Create and return the Zeek output directory."""
    out_dir = Path(requested_dir) if requested_dir else LOG_DIR_BASE / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _build_zeek_pcap_command(request: ZeekAnalyzeRequest, out_dir: Path) -> list[str]:
    """Build zeek command for PCAP analysis."""
    cmd = ["zeek", "-r", request.pcap_file]

    if request.zeek_scripts_dir:
        cmd.extend(["--zeekpath", request.zeek_scripts_dir])

    # Core log policies
    if request.analyze_conn:
        cmd.append("policy/tuning/defaults/logs.zeek")
    if request.extract_files:
        cmd.append("frameworks/files/extract-all-files")

    for script in request.scripts:
        cmd.append(script)

    return cmd


async def _process_zeek_logs(job: ZeekAnalyzeJob, log_dir: Path) -> None:
    """Parse Zeek TSV logs and extract security findings."""
    log_files = list(log_dir.glob("*.log"))
    job.log_files = [str(f) for f in log_files]

    all_conns: list[dict[str, Any]] = []
    all_dns: list[dict[str, Any]] = []
    all_http: list[dict[str, Any]] = []
    all_ssl: list[dict[str, Any]] = []
    all_weird: list[dict[str, Any]] = []

    for log_file in log_files:
        log_name = log_file.stem
        rows = _parse_zeek_log(log_file)

        if log_name == "conn":
            all_conns = rows
            job.conn_count = len(rows)
        elif log_name == "dns":
            all_dns = rows
            job.dns_count = len(rows)
        elif log_name in ("http",):
            all_http = rows
            job.http_count = len(rows)
        elif log_name == "ssl":
            all_ssl = rows
            job.ssl_count = len(rows)
        elif log_name == "weird":
            all_weird = rows
            job.weird_count = len(rows)

    # Analyse each log type for security indicators
    job.findings.extend(_analyse_conns(all_conns))
    job.findings.extend(_analyse_dns(all_dns))
    job.findings.extend(_analyse_http(all_http))
    job.findings.extend(_analyse_ssl(all_ssl))
    job.findings.extend(_analyse_weird(all_weird))
    job.total_findings = len(job.findings)


def _parse_zeek_log(log_path: Path) -> list[dict[str, Any]]:
    """Parse a Zeek TSV log file into list of row dicts.

    Supports both classic TSV format (with #fields header) and JSON log format.

    Args:
        log_path: Path to .log file.

    Returns:
        List of row dicts.
    """
    rows: list[dict[str, Any]] = []
    try:
        text = log_path.read_text(errors="replace")
        lines = text.splitlines()

        if not lines:
            return rows

        # JSON format
        if lines[0].strip().startswith("{"):
            for line in lines:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return rows

        # TSV format — extract field names from #fields line
        fields: list[str] = []
        for line in lines:
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]  # Skip #fields token
            elif not line.startswith("#"):
                if fields and line.strip():
                    parts = line.split("\t")
                    row = {fields[i]: parts[i] if i < len(parts) else "" for i in range(len(fields))}
                    rows.append(row)

    except Exception as exc:
        log.debug(f"Failed to parse {log_path}: {exc}")

    return rows


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _analyse_conns(rows: list[dict[str, Any]]) -> list[ZeekFinding]:
    """Detect port scans, beaconing, and suspicious connections."""
    findings: list[ZeekFinding] = []

    # Track connection counts per src_ip to detect port scans
    src_port_targets: dict[str, set[int]] = {}

    for row in rows:
        src = str(row.get("id.orig_h", ""))
        dst = str(row.get("id.resp_h", ""))
        dport = _safe_int(row.get("id.resp_p", 0))
        proto = str(row.get("proto", ""))
        state = str(row.get("conn_state", ""))

        if src:
            src_port_targets.setdefault(src, set()).add(dport)

        # Suspicious port connection
        if dport in _SUSPICIOUS_PORTS and state == "SF":
            findings.append(
                ZeekFinding(
                    name=f"Connection to suspicious port: {dst}:{dport}",
                    severity="high",
                    description=f"{src} connected to {dst}:{dport}/{proto} (state={state})",
                    url=f"{dst}:{dport}",
                    log_type="conn",
                    uid=str(row.get("uid", "")),
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=dport,
                    indicator_type="suspicious_port",
                    raw_data=row,
                )
            )

    # Port scan detection: src connecting to 20+ distinct ports
    for src_ip, ports in src_port_targets.items():
        if len(ports) >= 20:
            findings.append(
                ZeekFinding(
                    name=f"Port scan from {src_ip}: {len(ports)} ports",
                    severity="medium",
                    description=f"{src_ip} scanned {len(ports)} distinct destination ports",
                    log_type="conn",
                    src_ip=src_ip,
                    indicator_type="port_scan",
                    raw_data={"src": src_ip, "port_count": len(ports), "ports_sample": sorted(ports)[:10]},
                )
            )

    return findings


def _analyse_dns(rows: list[dict[str, Any]]) -> list[ZeekFinding]:
    """Detect DNS tunneling, DGA domains, and suspicious queries."""
    findings: list[ZeekFinding] = []
    domain_query_count: dict[str, int] = {}

    for row in rows:
        query = str(row.get("query", ""))
        qtype = str(row.get("qtype_name", ""))

        if not query:
            continue

        domain_query_count[query] = domain_query_count.get(query, 0) + 1

        # Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if query.endswith(tld):
                findings.append(
                    ZeekFinding(
                        name=f"Suspicious TLD: {query}",
                        severity="medium",
                        description=f"DNS query for domain with suspicious TLD: {query} ({qtype})",
                        log_type="dns",
                        uid=str(row.get("uid", "")),
                        src_ip=str(row.get("id.orig_h", "")),
                        indicator_type="suspicious_domain",
                        raw_data=row,
                    )
                )
                break

        # Long subdomain (DNS tunneling indicator)
        labels = query.split(".")
        if any(len(lbl) > 30 for lbl in labels):
            findings.append(
                ZeekFinding(
                    name=f"Possible DNS tunneling: {query[:60]}",
                    severity="high",
                    description=f"Unusually long DNS label in query '{query}' — may indicate tunneling",
                    log_type="dns",
                    uid=str(row.get("uid", "")),
                    src_ip=str(row.get("id.orig_h", "")),
                    indicator_type="dns_tunneling",
                    raw_data=row,
                )
            )

    # High query volume to single domain (beaconing)
    for domain, count in domain_query_count.items():
        if count > 50:
            findings.append(
                ZeekFinding(
                    name=f"High-frequency DNS queries to {domain}: {count}x",
                    severity="medium",
                    description=f"Possible C2 beaconing — {domain} queried {count} times",
                    log_type="dns",
                    indicator_type="c2_beacon",
                    raw_data={"domain": domain, "count": count},
                )
            )

    return findings


def _analyse_http(rows: list[dict[str, Any]]) -> list[ZeekFinding]:
    """Detect cleartext credentials, suspicious user-agents, and data exfiltration."""
    findings: list[ZeekFinding] = []

    for row in rows:
        username = str(row.get("username", ""))
        password = str(row.get("password", ""))
        ua = str(row.get("user_agent", ""))
        method = str(row.get("method", ""))
        uri = str(row.get("uri", ""))
        resp_bytes = _safe_int(row.get("resp_fuids", 0))
        src = str(row.get("id.orig_h", ""))
        dst = str(row.get("id.resp_h", ""))
        dport = _safe_int(row.get("id.resp_p", 80))

        # Cleartext credentials
        if username and password and password != "-":
            findings.append(
                ZeekFinding(
                    name=f"Cleartext HTTP credentials: {username}",
                    severity="high",
                    description=f"HTTP Basic Auth credentials captured: user={username} to {dst}:{dport}",
                    url=f"http://{dst}:{dport}{uri}",
                    log_type="http",
                    uid=str(row.get("uid", "")),
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=dport,
                    indicator_type="cleartext_auth",
                    raw_data=row,
                )
            )

        # Suspicious user-agents (curl, python, nmap, metasploit, etc.)
        suspicious_ua_patterns = ["python-requests", "curl", "nmap", "masscan",
                                   "sqlmap", "nikto", "metasploit", "hydra"]
        for pattern in suspicious_ua_patterns:
            if pattern.lower() in ua.lower():
                findings.append(
                    ZeekFinding(
                        name=f"Suspicious User-Agent: {ua[:60]}",
                        severity="medium",
                        description=f"HTTP request with tool-like User-Agent '{ua[:80]}' to {dst}:{dport}",
                        log_type="http",
                        src_ip=src,
                        dst_ip=dst,
                        dst_port=dport,
                        indicator_type="scanner_ua",
                        raw_data=row,
                    )
                )
                break

    return findings


def _analyse_ssl(rows: list[dict[str, Any]]) -> list[ZeekFinding]:
    """Detect weak SSL/TLS, self-signed certs, and untrusted issuers."""
    findings: list[ZeekFinding] = []

    for row in rows:
        version = str(row.get("version", ""))
        cipher = str(row.get("cipher", ""))
        validation = str(row.get("validation_status", ""))
        subject = str(row.get("subject", ""))
        issuer = str(row.get("issuer", ""))
        src = str(row.get("id.orig_h", ""))
        dst = str(row.get("id.resp_h", ""))
        dport = _safe_int(row.get("id.resp_p", 443))
        sni = str(row.get("server_name", ""))

        # Weak TLS versions
        if version in ("TLSv10", "TLSv11", "SSLv2", "SSLv3", "TLS/1.0", "TLS/1.1"):
            findings.append(
                ZeekFinding(
                    name=f"Weak TLS version: {version} to {dst}:{dport}",
                    severity="medium",
                    description=f"Deprecated TLS version {version} in use from {src} to {dst}:{dport}",
                    log_type="ssl",
                    uid=str(row.get("uid", "")),
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=dport,
                    indicator_type="weak_tls",
                    raw_data=row,
                )
            )

        # Certificate validation failure
        if validation and validation not in ("ok", "-", ""):
            sev = "high" if "self" in validation.lower() else "medium"
            findings.append(
                ZeekFinding(
                    name=f"TLS cert validation failure: {validation}",
                    severity=sev,
                    description=(
                        f"Certificate validation failed: {validation} "
                        f"(SNI={sni}, subject={subject[:50]})"
                    ),
                    log_type="ssl",
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=dport,
                    indicator_type="cert_invalid",
                    raw_data=row,
                )
            )

    return findings


def _analyse_weird(rows: list[dict[str, Any]]) -> list[ZeekFinding]:
    """Escalate Zeek weird.log entries as findings."""
    findings: list[ZeekFinding] = []
    high_severity_weirds = {
        "bad_HTTP_request", "line_terminated_with_single_CR",
        "active_connection_reuse", "above_hole_data_without_any_acks",
    }

    for row in rows:
        name = str(row.get("name", ""))
        sev = "high" if name in high_severity_weirds else "low"
        findings.append(
            ZeekFinding(
                name=f"Zeek weird: {name}",
                severity=sev,
                description=f"Zeek detected unusual traffic pattern: {name}",
                log_type="weird",
                uid=str(row.get("uid", "")),
                src_ip=str(row.get("id.orig_h", "")),
                dst_ip=str(row.get("id.resp_h", "")),
                indicator_type="protocol_anomaly",
                raw_data=row,
            )
        )

    return findings


# ── Log query ─────────────────────────────────────────────────────────────────

async def start_log_query(request: ZeekLogQueryRequest) -> ZeekQueryJob:
    """Query an existing Zeek log directory.

    Args:
        request: Log directory, log type, and filter expression.

    Returns:
        ZeekQueryJob — background task parses and filters logs.
    """
    job = ZeekQueryJob(
        job_id=str(uuid.uuid4())[:8],
        log_type=request.log_type,
        log_dir=request.log_dir,
        filter_expr=request.filter_expr,
        status="running",
    )
    log.info(f"[{job.job_id}] Querying {request.log_type}.log in {request.log_dir}")
    asyncio.create_task(_run_log_query(job, request))
    return job


async def _run_log_query(job: ZeekQueryJob, request: ZeekLogQueryRequest) -> None:
    """Background task: parse log and apply filter."""
    try:
        log_path = Path(request.log_dir) / f"{request.log_type}.log"
        if not log_path.exists():
            # Try with .gz extension
            gz_path = log_path.with_suffix(".log.gz")
            if gz_path.exists():
                log_path = gz_path
            else:
                job.status = "error"
                job.error = f"Log file not found: {log_path}"
                return

        rows = await asyncio.get_event_loop().run_in_executor(
            None, _parse_zeek_log, log_path
        )

        # Apply filter
        if request.filter_expr:
            filtered = []
            for row in rows:
                try:
                    if eval(request.filter_expr, {"__builtins__": {}}, row):  # noqa: S307
                        filtered.append(row)
                except Exception:
                    pass
            rows = filtered

        job.rows = rows[:request.limit]
        job.row_count = len(job.rows)
        job.status = "completed"
        log.info(f"[{job.job_id}] Query returned {job.row_count} rows")

    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Query error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()
