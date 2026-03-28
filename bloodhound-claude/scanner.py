"""BloodHound collection, Cypher queries, and attack path analysis."""

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
    BloodHoundCollectJob,
    BloodHoundCollectRequest,
    BloodHoundQueryJob,
    BloodHoundQueryRequest,
    BloodHoundPathJob,
    BloodHoundPathRequest,
    BloodHoundFinding,
    AttackPath,
    ADNode,
    ADEdge,
)

log = logging.getLogger("bloodhound-claude.scanner")

# Process registry for cancellation
_running_processes: dict[str, asyncio.subprocess.Process] = {}

# Output directory for collected JSON files
OUTPUT_DIR = Path(os.environ.get("BH_OUTPUT_DIR", "/tmp/bloodhound-output"))


# ── Collection ────────────────────────────────────────────────────────────────

async def start_collection(request: BloodHoundCollectRequest) -> BloodHoundCollectJob:
    """Start a BloodHound data collection job.

    Args:
        request: Collection parameters including domain, credentials, methods.

    Returns:
        BloodHoundCollectJob — background task runs the collector.
    """
    job = BloodHoundCollectJob(
        job_id=str(uuid.uuid4())[:8],
        domain=request.domain,
        dc=request.dc,
        collection_methods=request.collection_methods,
        status="running",
    )
    log.info(f"[{job.job_id}] Starting BloodHound collection for domain {request.domain}")
    asyncio.create_task(_run_collection(job, request))
    return job


async def _run_collection(job: BloodHoundCollectJob, request: BloodHoundCollectRequest) -> None:
    """Background task: run bloodhound-python or SharpHound."""
    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        work_dir = OUTPUT_DIR / job.job_id
        work_dir.mkdir(parents=True, exist_ok=True)

        if request.use_python_collector:
            cmd = _build_bhpython_command(request, str(work_dir))
        else:
            cmd = _build_sharphound_command(request, str(work_dir))

        log.debug(f"[{job.job_id}] Command: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
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
            job.error = f"Collection timed out after {request.timeout}s"
            return
        finally:
            _running_processes.pop(job.job_id, None)

        if job.status == "cancelled":
            return

        # Collect output JSON files
        output_files = list(work_dir.glob("*.json")) + list(work_dir.glob("*.zip"))
        job.output_files = [str(f) for f in output_files]

        stderr_text = stderr.decode(errors="replace")
        stdout_text = stdout.decode(errors="replace")

        # Parse object count from bloodhound-python output
        count_match = re.search(r"(\d+)\s+objects", stdout_text + stderr_text, re.I)
        if count_match:
            job.objects_collected = int(count_match.group(1))

        if proc.returncode != 0 and not output_files:
            job.status = "error"
            job.error = f"Collector exited {proc.returncode}: {stderr_text[:500]}"
            log.error(f"[{job.job_id}] {job.error}")
        else:
            job.status = "completed"
            log.info(
                f"[{job.job_id}] Collection complete: "
                f"{len(output_files)} files, ~{job.objects_collected} objects"
            )

    except FileNotFoundError as exc:
        job.status = "error"
        job.error = f"Collector binary not found: {exc}. Install bloodhound-python or SharpHound."
        log.error(f"[{job.job_id}] {job.error}")
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Unexpected error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


def _build_bhpython_command(request: BloodHoundCollectRequest, output_dir: str) -> list[str]:
    """Build bloodhound-python command."""
    cmd = [
        "bloodhound-python",
        "-d", request.domain,
        "-c", ",".join(request.collection_methods),
        "-o", output_dir,
        "--zip",
    ]
    if request.dc:
        cmd.extend(["--dc", request.dc])
    if request.username:
        cmd.extend(["-u", request.username])
    if request.password:
        cmd.extend(["-p", request.password])
    if request.nameserver:
        cmd.extend(["-ns", request.nameserver])
    if request.dns_tcp:
        cmd.append("--dns-tcp")
    if request.stealth:
        cmd.append("--stealth")
    return cmd


def _build_sharphound_command(request: BloodHoundCollectRequest, output_dir: str) -> list[str]:
    """Build SharpHound.exe command (Windows-only)."""
    cmd = [
        "SharpHound.exe",
        "-c", ",".join(request.collection_methods),
        "--outputdirectory", output_dir,
        "--zipfilename", f"bh_{request.domain}",
    ]
    if request.dc:
        cmd.extend(["--domaincontroller", request.dc])
    if request.stealth:
        cmd.append("--stealth")
    return cmd


# ── Cypher queries ────────────────────────────────────────────────────────────

async def start_query(request: BloodHoundQueryRequest) -> BloodHoundQueryJob:
    """Start a Cypher query job against Neo4j.

    Args:
        request: Cypher query and Neo4j connection details.

    Returns:
        BloodHoundQueryJob — background task runs the query.
    """
    job = BloodHoundQueryJob(
        job_id=str(uuid.uuid4())[:8],
        query=request.query,
        status="running",
    )
    log.info(f"[{job.job_id}] Cypher query: {request.query[:80]}...")
    asyncio.create_task(_run_query(job, request))
    return job


async def _run_query(job: BloodHoundQueryJob, request: BloodHoundQueryRequest) -> None:
    """Background task: execute Cypher query via neo4j driver."""
    try:
        rows = await asyncio.wait_for(
            _execute_cypher(
                request.query,
                request.database_url,
                request.database_user,
                request.database_password,
                request.limit,
            ),
            timeout=request.timeout,
        )
        job.rows = rows
        job.row_count = len(rows)
        job.status = "completed"
        log.info(f"[{job.job_id}] Query returned {job.row_count} rows")
    except asyncio.TimeoutError:
        job.status = "error"
        job.error = f"Query timed out after {request.timeout}s"
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Query error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


async def _execute_cypher(
    query: str,
    bolt_url: str,
    user: str,
    password: str,
    limit: int,
) -> list[dict[str, Any]]:
    """Execute a Cypher query against Neo4j using the bolt driver.

    Runs synchronous neo4j driver in a thread pool to avoid blocking.

    Args:
        query: Cypher query string (LIMIT clause appended if absent).
        bolt_url: Neo4j bolt:// URL.
        user: Neo4j username.
        password: Neo4j password.
        limit: Maximum result rows.

    Returns:
        List of row dicts with string-coerced values.
    """
    import asyncio

    def _sync_query() -> list[dict[str, Any]]:
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError:
            raise RuntimeError(
                "neo4j Python driver not installed — run: pip install neo4j"
            )

        # Append LIMIT if the query doesn't already have one
        bounded_query = query
        if "LIMIT" not in query.upper():
            bounded_query = f"{query.rstrip().rstrip(';')} LIMIT {limit}"

        driver = GraphDatabase.driver(bolt_url, auth=(user, password))
        rows: list[dict[str, Any]] = []
        try:
            with driver.session() as session:
                result = session.run(bounded_query)
                for record in result:
                    rows.append({k: _coerce(v) for k, v in record.items()})
        finally:
            driver.close()

        return rows

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_query)


def _coerce(value: Any) -> Any:
    """Convert neo4j Node/Relationship objects to plain dicts."""
    try:
        from neo4j.graph import Node, Relationship  # type: ignore
        if isinstance(value, Node):
            return {"id": value.id, "labels": list(value.labels), "properties": dict(value)}
        if isinstance(value, Relationship):
            return {
                "type": value.type,
                "start": value.start_node.id,
                "end": value.end_node.id,
                "properties": dict(value),
            }
    except ImportError:
        pass
    return value


# ── Attack path analysis ──────────────────────────────────────────────────────

# Built-in high-value Cypher queries
_BUILTIN_QUERIES: dict[str, str] = {
    "kerberoastable": (
        "MATCH (u:User {hasspn:true}) WHERE u.enabled=true "
        "RETURN u.name AS name, u.serviceprincipalnames AS spns, "
        "u.admincount AS admincount ORDER BY admincount DESC"
    ),
    "asreproastable": (
        "MATCH (u:User {dontreqpreauth:true}) WHERE u.enabled=true "
        "RETURN u.name AS name, u.admincount AS admincount"
    ),
    "unconstrained_delegation": (
        "MATCH (c:Computer {unconstraineddelegation:true}) WHERE c.enabled=true "
        "RETURN c.name AS name, c.operatingsystem AS os"
    ),
    "da_sessions": (
        "MATCH p=(c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group) "
        "WHERE g.objectid ENDS WITH '-512' RETURN p LIMIT 25"
    ),
    "path_to_da": (
        "MATCH p=shortestPath((u:User {enabled:true})-[*1..10]->(g:Group)) "
        "WHERE g.objectid ENDS WITH '-512' AND NOT u=g RETURN p LIMIT 10"
    ),
    "computers_with_admin": (
        "MATCH p=(g:Group)-[:AdminTo]->(c:Computer) "
        "RETURN g.name AS group_name, c.name AS computer LIMIT 100"
    ),
    "dcsync_principals": (
        "MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) "
        "WHERE NOT n.objectid ENDS WITH '-516' AND NOT n.objectid ENDS WITH '-512' "
        "RETURN n.name AS name, labels(n) AS type"
    ),
    "laps_computers": (
        "MATCH (c:Computer {haslaps:false}) WHERE c.enabled=true "
        "RETURN c.name AS name, c.operatingsystem AS os LIMIT 100"
    ),
}


async def start_path_analysis(request: BloodHoundPathRequest) -> BloodHoundPathJob:
    """Find attack paths between two AD nodes.

    Args:
        request: Source, target, and Neo4j connection details.

    Returns:
        BloodHoundPathJob — background task queries Neo4j.
    """
    job = BloodHoundPathJob(
        job_id=str(uuid.uuid4())[:8],
        source=request.source,
        target=request.target,
        status="running",
    )
    log.info(f"[{job.job_id}] Path analysis: {request.source} -> {request.target}")
    asyncio.create_task(_run_path_analysis(job, request))
    return job


async def _run_path_analysis(job: BloodHoundPathJob, request: BloodHoundPathRequest) -> None:
    """Background task: run attack path Cypher queries."""
    try:
        # Choose built-in query or build a custom one
        if request.path_type in _BUILTIN_QUERIES and not request.source:
            cypher = _BUILTIN_QUERIES[request.path_type]
        elif request.path_type == "shortest":
            cypher = (
                f"MATCH p=shortestPath((src {{name:'{request.source}'}})"
                f"-[*1..15]->(dst {{name:'{request.target}'}})) RETURN p LIMIT {request.max_paths}"
            )
        else:
            cypher = (
                f"MATCH p=(src {{name:'{request.source}'}})"
                f"-[*1..10]->(dst {{name:'{request.target}'}}) RETURN p LIMIT {request.max_paths}"
            )

        rows = await asyncio.wait_for(
            _execute_cypher(
                cypher,
                request.database_url,
                request.database_user,
                request.database_password,
                request.max_paths * 50,
            ),
            timeout=request.timeout,
        )

        paths = _rows_to_paths(rows)
        job.paths = paths
        job.total_paths = len(paths)

        # Generate findings from paths
        job.findings = _paths_to_findings(paths, request.source, request.target)
        job.status = "completed"
        log.info(f"[{job.job_id}] Found {job.total_paths} paths, {len(job.findings)} findings")

    except asyncio.TimeoutError:
        job.status = "error"
        job.error = f"Path analysis timed out after {request.timeout}s"
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        log.error(f"[{job.job_id}] Path error: {exc}", exc_info=True)
    finally:
        job.completed_at = time.time()


def _rows_to_paths(rows: list[dict[str, Any]]) -> list[AttackPath]:
    """Convert Neo4j query rows containing path objects into AttackPath list."""
    paths: list[AttackPath] = []
    for i, row in enumerate(rows):
        path_data = row.get("p", row)
        if isinstance(path_data, dict) and "nodes" in path_data:
            nodes = [
                ADNode(
                    node_id=str(n.get("id", "")),
                    node_type=n.get("labels", ["Unknown"])[0] if n.get("labels") else "Unknown",
                    name=n.get("properties", {}).get("name", ""),
                    object_id=n.get("properties", {}).get("objectid", ""),
                    properties=n.get("properties", {}),
                )
                for n in path_data.get("nodes", [])
            ]
            edges = [
                ADEdge(
                    source=str(e.get("start", "")),
                    target=str(e.get("end", "")),
                    edge_type=e.get("type", ""),
                    properties=e.get("properties", {}),
                )
                for e in path_data.get("relationships", [])
            ]
            risk = _score_path(edges)
            paths.append(
                AttackPath(
                    path_id=i,
                    nodes=nodes,
                    edges=edges,
                    length=len(edges),
                    risk_score=risk,
                    description=_describe_path(nodes, edges),
                )
            )
        else:
            # Row is a flat result (e.g. kerberoastable)
            paths.append(
                AttackPath(
                    path_id=i,
                    nodes=[ADNode(name=str(list(row.values())[0]) if row else "")],
                    edges=[],
                    length=0,
                    risk_score=5.0,
                    description=str(row),
                )
            )
    return paths


def _score_path(edges: list[ADEdge]) -> float:
    """Assign a risk score (0-10) based on edge types in a path."""
    high_risk = {"DCSync", "GenericAll", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights"}
    med_risk = {"AdminTo", "ForceChangePassword", "AddMember", "MemberOf", "CanRDP"}
    score = 5.0
    for edge in edges:
        if edge.edge_type in high_risk:
            score = min(10.0, score + 2.0)
        elif edge.edge_type in med_risk:
            score = min(10.0, score + 1.0)
    return round(score, 1)


def _describe_path(nodes: list[ADNode], edges: list[ADEdge]) -> str:
    """Generate a human-readable path description."""
    if not nodes:
        return "Empty path"
    parts = [nodes[0].name or nodes[0].node_type]
    for edge in edges:
        parts.append(f"--[{edge.edge_type}]-->")
        tgt = next((n for n in nodes if str(n.node_id) == edge.target), None)
        parts.append(tgt.name if tgt else edge.target)
    return " ".join(parts)


def _paths_to_findings(
    paths: list[AttackPath],
    source: str,
    target: str,
) -> list[BloodHoundFinding]:
    """Convert attack paths into BloodHoundFinding objects."""
    if not paths:
        return []

    sev_map = {10.0: "critical", 9.0: "critical", 8.0: "high", 7.0: "high",
               6.0: "medium", 5.0: "medium", 4.0: "low", 3.0: "low"}

    findings: list[BloodHoundFinding] = []
    for path in paths:
        sev = sev_map.get(min(10.0, round(path.risk_score)), "info")
        findings.append(
            BloodHoundFinding(
                name=f"Attack path: {source} -> {target} (length {path.length})",
                severity=sev,
                url="",
                description=path.description,
                attack_paths=[path],
                affected_count=path.length,
                category="attack_path",
            )
        )
    return findings


def get_builtin_queries() -> dict[str, str]:
    """Return the built-in Cypher query library."""
    return dict(_BUILTIN_QUERIES)
