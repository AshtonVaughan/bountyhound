"""Metasploit module execution, search, and session management."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core")))

from models import (
    MetasploitRunJob,
    MetasploitRunRequest,
    MetasploitSearchJob,
    MetasploitSearchRequest,
    MetasploitSessionJob,
    MetasploitSessionRequest,
    MetasploitFinding,
    MetasploitModule,
    MetasploitModuleOption,
    MetasploitSession,
)

log = logging.getLogger("metasploit-claude.scanner")

# Process registry for cancellation
_running_processes: dict[str, asyncio.subprocess.Process] = {}

# RC file directory for msfconsole resource scripts
RC_DIR = Path(os.environ.get("MSF_RC_DIR", "/tmp/msf-rc"))


# ── Module execution ──────────────────────────────────────────────────────────

async def start_module_run(request: MetasploitRunRequest) -> MetasploitRunJob:
    """Start a Metasploit module execution job.

    Args:
        request: Module path, options, payload, and execution parameters.

    Returns:
        MetasploitRunJob — background task manages execution.
    """
    job = MetasploitRunJob(
        job_id=str(uuid.uuid4())[:8],
        module_path=request.module_path,
        module_type=request.module_type,
        options=request.options,
        payload=request.payload,
        status="running",
    )
    log.info(
        f"[{job.job_id}] Running {request.module_type}/{request.module_path} "
        f"with options {list(request.options.keys())}"
    )
    asyncio.create_task(_run_module(job, request))
    return job


async def _run_module(job: MetasploitRunJob, request: MetasploitRunRequest) -> None:
    """Background task: generate RC file and invoke msfconsole."""
    try:
        if request.use_rpc:
            await _run_via_rpc(job, request)
        else:
            await _run_via_msfconsole(job, request)
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Unexpected error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


async def _run_via_msfconsole(job: MetasploitRunJob, request: MetasploitRunRequest) -> None:
    """Execute module via msfconsole resource script."""
    RC_DIR.mkdir(parents=True, exist_ok=True)
    rc_path = RC_DIR / f"{job.job_id}.rc"

    # Build resource script
    rc_lines = [
        f"use {request.module_type}/{request.module_path}",
    ]
    for key, val in request.options.items():
        rc_lines.append(f"set {key} {val}")

    if request.payload:
        rc_lines.append(f"set PAYLOAD {request.payload}")
        for key, val in request.payload_options.items():
            rc_lines.append(f"set {key} {val}")

    rc_lines.append("run -j" if request.run_as_job else "run")
    rc_lines.append("sleep 5")  # Allow job to start
    rc_lines.append("jobs -l")
    rc_lines.append("sessions -l")
    rc_lines.append("exit -y")

    rc_path.write_text("\n".join(rc_lines))
    log.debug(f"[{job.job_id}] RC script:\n{rc_path.read_text()}")

    cmd = ["msfconsole", "-q", "-r", str(rc_path)]

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
        job.error = f"msfconsole timed out after {request.timeout}s"
        log.error(f"[{job.job_id}] {job.error}")
        return
    finally:
        _running_processes.pop(job.job_id, None)
        rc_path.unlink(missing_ok=True)

    if job.status == "cancelled":
        return

    output = stdout.decode(errors="replace")
    job.output = output.splitlines()

    # Parse sessions from output
    sessions = _parse_sessions_from_output(output)
    job.sessions_opened = sessions

    # Parse findings
    job.findings = _output_to_findings(output, request, sessions)
    job.total_hosts_vulnerable = len([f for f in job.findings if f.session_opened])
    job.total_hosts_tested = len(set(request.options.get("RHOSTS", "").split()))

    if proc.returncode not in (0, 1) and not job.output:
        stderr_text = stderr.decode(errors="replace").strip()
        job.status = "error"
        job.error = f"msfconsole exited {proc.returncode}: {stderr_text[:500]}"
        log.error(f"[{job.job_id}] {job.error}")
    else:
        job.status = "completed"
        log.info(
            f"[{job.job_id}] Completed: {len(sessions)} sessions, "
            f"{len(job.findings)} findings"
        )


async def _run_via_rpc(job: MetasploitRunJob, request: MetasploitRunRequest) -> None:
    """Execute module via Metasploit RPC API (msgpack)."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
    except ImportError:
        raise RuntimeError(
            "pymetasploit3 not installed — run: pip install pymetasploit3"
        )

    def _sync_rpc() -> dict:
        client = MsfRpcClient(
            request.rpc_password,
            server=request.rpc_host,
            port=request.rpc_port,
            ssl=False,
        )
        mod_type_map = {
            "exploit": client.modules.exploits,
            "auxiliary": client.modules.auxiliary,
            "post": client.modules.post,
        }
        mod_collection = mod_type_map.get(request.module_type, client.modules.auxiliary)
        module = mod_collection[request.module_path]

        for key, val in request.options.items():
            module[key] = val

        if request.payload:
            payload = client.modules.payloads[request.payload]
            for key, val in request.payload_options.items():
                payload[key] = val
            output = module.execute(payload=payload)
        else:
            output = module.execute()

        return output

    loop = asyncio.get_event_loop()
    try:
        rpc_result = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_rpc),
            timeout=request.timeout,
        )
        job.output = [str(rpc_result)]
        if rpc_result.get("job_id"):
            job.msf_job_id = int(rpc_result["job_id"])
        job.status = "completed"
    except asyncio.TimeoutError:
        job.status = "error"
        job.error = f"RPC call timed out after {request.timeout}s"
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        raise


def _parse_sessions_from_output(output: str) -> list[MetasploitSession]:
    """Extract session info from msfconsole output text."""
    sessions: list[MetasploitSession] = []

    # Pattern: "msf6 exploit(...) > [*] Meterpreter session 1 opened (10.0.0.5:4444 -> 10.0.0.10:12345)"
    session_pattern = re.compile(
        r"(\w+)\s+session\s+(\d+)\s+opened\s+\(([^:]+):(\d+)\s*->\s*([^:]+):(\d+)\)",
        re.I,
    )
    for m in session_pattern.finditer(output):
        sessions.append(
            MetasploitSession(
                session_type=m.group(1).lower(),
                session_id=int(m.group(2)),
                local_host=m.group(3),
                local_port=int(m.group(4)),
                remote_host=m.group(5),
                remote_port=int(m.group(6)),
                opened_at=time.time(),
            )
        )

    return sessions


def _output_to_findings(
    output: str,
    request: MetasploitRunRequest,
    sessions: list[MetasploitSession],
) -> list[MetasploitFinding]:
    """Generate MetasploitFinding objects from run output."""
    findings: list[MetasploitFinding] = []

    # One finding per opened session
    for session in sessions:
        findings.append(
            MetasploitFinding(
                name=f"Session opened: {request.module_path} -> {session.remote_host}",
                severity="critical",
                url=f"{session.remote_host}:{session.remote_port}",
                description=(
                    f"{session.session_type.title()} session {session.session_id} "
                    f"opened on {session.remote_host}:{session.remote_port} "
                    f"via {request.module_path}"
                ),
                module_path=request.module_path,
                module_type=request.module_type,
                target_host=session.remote_host,
                target_port=session.remote_port,
                session_opened=True,
                session=session,
                output_lines=output.splitlines()[-20:],
            )
        )

    # Check for auxiliary scan results (open ports, service detection)
    open_port_pattern = re.compile(r"\[\+\]\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+.+open", re.I)
    for m in open_port_pattern.finditer(output):
        host, port = m.group(1), int(m.group(2))
        # Avoid duplicating session findings
        if not any(f.target_host == host and f.target_port == port for f in findings):
            findings.append(
                MetasploitFinding(
                    name=f"Open port: {host}:{port}",
                    severity="info",
                    url=f"{host}:{port}",
                    description=f"Port {port} open on {host} (detected by {request.module_path})",
                    module_path=request.module_path,
                    module_type=request.module_type,
                    target_host=host,
                    target_port=port,
                    session_opened=False,
                )
            )

    return findings


# ── Module search ─────────────────────────────────────────────────────────────

async def start_module_search(request: MetasploitSearchRequest) -> MetasploitSearchJob:
    """Search the Metasploit module database.

    Args:
        request: Search terms and filters.

    Returns:
        MetasploitSearchJob — background task runs msfconsole search.
    """
    job = MetasploitSearchJob(
        job_id=str(uuid.uuid4())[:8],
        query=request.query,
        status="running",
    )
    log.info(f"[{job.job_id}] Searching modules: '{request.query}'")
    asyncio.create_task(_run_search(job, request))
    return job


async def _run_search(job: MetasploitSearchJob, request: MetasploitSearchRequest) -> None:
    """Background task: run msfconsole -x 'search ...' and parse results."""
    try:
        search_term = request.query
        if request.module_type:
            search_term += f" type:{request.module_type}"
        if request.platform:
            search_term += f" platform:{request.platform}"
        if request.rank:
            search_term += f" rank:{request.rank}"

        cmd = ["msfconsole", "-q", "-x", f"search {search_term}; exit"]

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
            job.error = f"Search timed out after {request.timeout}s"
            return
        finally:
            _running_processes.pop(job.job_id, None)

        output = stdout.decode(errors="replace")
        job.modules = _parse_search_output(output)
        job.total_results = len(job.modules)
        job.status = "completed"
        log.info(f"[{job.job_id}] Search found {job.total_results} modules")

    except FileNotFoundError:
        job.status = "error"
        job.error = "msfconsole not found — install Metasploit Framework"
        log.error(f"[{job.job_id}] {job.error}")
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


# Pattern for msfconsole search table rows
_SEARCH_ROW = re.compile(
    r"^\s*(\d+)\s+"                      # Index
    r"([\w/.-]+)\s+"                     # Module path
    r"(\d{4}-\d{2}-\d{2})\s+"           # Disclosure date
    r"(\w+)\s+"                          # Rank
    r"([^\s]+)\s+"                       # Check?
    r"(.+)$"                             # Description
)


def _parse_search_output(output: str) -> list[MetasploitModule]:
    """Parse msfconsole search table output into MetasploitModule objects."""
    modules: list[MetasploitModule] = []
    for line in output.splitlines():
        m = _SEARCH_ROW.match(line)
        if m:
            path = m.group(2).strip()
            # Determine type from path prefix
            parts = path.split("/")
            mod_type = parts[0] if parts else "unknown"
            mod_path = "/".join(parts[1:]) if len(parts) > 1 else path
            modules.append(
                MetasploitModule(
                    module_type=mod_type,
                    module_path=mod_path,
                    name=path,
                    description=m.group(6).strip(),
                    rank=m.group(4).strip(),
                )
            )
    return modules


# ── Session interaction ───────────────────────────────────────────────────────

async def start_session_command(request: MetasploitSessionRequest) -> MetasploitSessionJob:
    """Run a command inside an open Metasploit session.

    Args:
        request: Session ID and command to execute.

    Returns:
        MetasploitSessionJob — background task runs the command.
    """
    job = MetasploitSessionJob(
        job_id=str(uuid.uuid4())[:8],
        session_id=request.session_id,
        command=request.command,
        status="running",
    )
    log.info(f"[{job.job_id}] Session {request.session_id}: {request.command[:50]}")
    asyncio.create_task(_run_session_command(job, request))
    return job


async def _run_session_command(job: MetasploitSessionJob, request: MetasploitSessionRequest) -> None:
    """Background task: send command to session via RPC or msfconsole."""
    try:
        if request.use_rpc:
            output = await _rpc_session_run(
                request.session_id,
                request.command,
                request.rpc_host,
                request.rpc_port,
                request.rpc_password,
                request.timeout,
            )
        else:
            # Use msfconsole resource script to interact with session
            RC_DIR.mkdir(parents=True, exist_ok=True)
            rc_path = RC_DIR / f"sess_{job.job_id}.rc"
            rc_path.write_text(
                f"sessions -i {request.session_id} -c '{request.command}'\nexit -y\n"
            )
            cmd = ["msfconsole", "-q", "-r", str(rc_path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=request.timeout)
            finally:
                rc_path.unlink(missing_ok=True)
            output = stdout.decode(errors="replace")

        job.output = output
        job.status = "completed"
        log.info(f"[{job.job_id}] Session command completed ({len(output)} chars)")

    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Session error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


async def _rpc_session_run(
    session_id: int,
    command: str,
    host: str,
    port: int,
    password: str,
    timeout: float,
) -> str:
    """Run session command via pymetasploit3 RPC."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
    except ImportError:
        raise RuntimeError("pymetasploit3 not installed — run: pip install pymetasploit3")

    def _sync():
        client = MsfRpcClient(password, server=host, port=port, ssl=False)
        sessions = client.sessions.list
        if str(session_id) not in sessions:
            raise ValueError(f"Session {session_id} not found")
        session = client.sessions.session(str(session_id))
        session.write(command + "\n")
        import time as _time
        _time.sleep(2)
        return session.read()

    loop = asyncio.get_event_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, _sync),
        timeout=timeout,
    )
