"""FastAPI REST API for the proxy engine — all endpoints."""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from models import (
    CompareRequest, CodecRequest, DiffResult,
    ExportFormat, Flow, InterceptModification, IntruderJob, IntruderRequest,
    MacroChain, MatchReplaceRule, OrganizerItem, ProxyStatus,
    RepeaterRequest, RepeaterModification, ReportRequest, ResourcePool,
    ScanJob, ScanRequest, ScanProfile, ScopeConfig, ScopeRule,
    SequencerRequest, SessionRule, CrawlJob, DiscoveryJob,
    TLSClientConfig, WebSocketModification,
)
from state import state

app = FastAPI(title="Proxy Engine", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Files ─────────────────────────────────────────────────────────────
app.mount("/web", StaticFiles(directory=Path(__file__).parent / "web"), name="web-static")


# ── Status ───────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status() -> ProxyStatus:
    import passive_scanner, extensions, scope as scope_mod, match_replace, session_handler
    active_intruder = sum(1 for j in state.intruder_jobs.values() if j.status == "running")
    active_scans = sum(1 for s in state.scanner_jobs.values() if s.status == "running")
    active_crawls = sum(1 for j in state.crawl_jobs.values() if j.status == "running")
    active_disc = sum(1 for j in state.discovery_jobs.values() if j.status == "running")
    return ProxyStatus(
        flow_count=len(state.flows),
        intercept_enabled=state.intercept_enabled,
        intercept_queue_size=len(state.intercept_queue),
        response_intercept_enabled=state.response_intercept_enabled,
        active_intruder_jobs=active_intruder,
        active_scans=active_scans,
        active_crawls=active_crawls,
        active_discoveries=active_disc,
        scope_enabled=scope_mod.config.enabled,
        websocket_messages=len(state.ws_messages),
        passive_findings=len(passive_scanner.findings),
        extensions_loaded=len(extensions.get_extensions()),
        match_replace_rules=len(match_replace.rules),
        session_rules=len(session_handler.rules),
        project_name=state.current_project,
    )


# ── Flows ────────────────────────────────────────────────────────────────────

@app.get("/api/flows")
async def list_flows(
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    content_type: str | None = None,
    search: str | None = None,
    search_body: bool = False,
    search_headers: bool = False,
    search_regex: bool = False,
    scope_only: bool = False,
    filter_expr: str | None = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
) -> list[dict]:
    flows = state.list_flows(
        host=host, method=method, status_code=status_code,
        content_type=content_type, search=search,
        search_body=search_body, search_headers=search_headers,
        search_regex=search_regex, scope_only=scope_only,
        filter_expr=filter_expr,
        limit=limit, offset=offset,
    )
    return [
        {
            "id": f.id, "method": f.request.method, "url": f.request.url,
            "host": f.host, "path": f.path,
            "status_code": f.response.status_code if f.response else None,
            "content_type": f.response.headers.get("content-type", "") if f.response else "",
            "length": len(f.response.body) if f.response and f.response.body else 0,
            "timestamp": f.timestamp,
            "tags": f.tags, "notes": f.notes, "highlight": f.highlight,
        }
        for f in flows
    ]


@app.get("/api/flows/{flow_id}")
async def get_flow(flow_id: str) -> Flow:
    flow = state.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow {flow_id} not found")
    return flow


@app.delete("/api/flows")
async def clear_flows() -> dict:
    return {"cleared": state.clear_flows()}


@app.patch("/api/flows/{flow_id}/notes")
async def update_flow_notes(flow_id: str, body: dict) -> dict:
    flow = state.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow {flow_id} not found")
    if "notes" in body:
        flow.notes = body["notes"]
    if "tags" in body:
        flow.tags = body["tags"]
    if "highlight" in body:
        flow.highlight = body["highlight"]
    return {"id": flow_id, "notes": flow.notes, "tags": flow.tags, "highlight": flow.highlight}


# ── Intercept ────────────────────────────────────────────────────────────────

@app.post("/api/intercept/enable")
async def intercept_enable() -> dict:
    state.intercept_enabled = True
    return {"intercept": True}

@app.post("/api/intercept/disable")
async def intercept_disable() -> dict:
    state.intercept_enabled = False
    for fid in list(state.intercept_queue.keys()):
        state.resolve_intercept(fid, "forward")
    return {"intercept": False}

@app.get("/api/intercept/queue")
async def intercept_queue() -> list[dict]:
    return [
        {"id": f.id, "method": f.request.method, "url": f.request.url,
         "headers": f.request.headers, "body": f.request.body}
        for f in state.intercept_queue.values()
    ]

@app.post("/api/intercept/{flow_id}/forward")
async def intercept_forward(flow_id: str, modification: InterceptModification | None = None) -> dict:
    mods = modification.model_dump(exclude_none=True) if modification else {}
    if not state.resolve_intercept(flow_id, "forward", mods):
        raise HTTPException(404, f"Flow {flow_id} not in intercept queue")
    return {"action": "forwarded", "flow_id": flow_id}

@app.post("/api/intercept/{flow_id}/drop")
async def intercept_drop(flow_id: str) -> dict:
    if not state.resolve_intercept(flow_id, "drop"):
        raise HTTPException(404, f"Flow {flow_id} not in intercept queue")
    return {"action": "dropped", "flow_id": flow_id}


# ── Scope ────────────────────────────────────────────────────────────────────

@app.get("/api/scope")
async def scope_get() -> ScopeConfig:
    from scope import get_config
    return get_config()

@app.put("/api/scope")
async def scope_set(cfg: ScopeConfig) -> ScopeConfig:
    from scope import set_config
    set_config(cfg)
    return cfg

@app.post("/api/scope/toggle")
async def scope_toggle(body: dict) -> ScopeConfig:
    from scope import toggle
    return toggle(body.get("enabled", False))

@app.post("/api/scope/include")
async def scope_add_include(rule: ScopeRule) -> ScopeConfig:
    from scope import add_include
    return add_include(rule.pattern, rule.target)

@app.post("/api/scope/exclude")
async def scope_add_exclude(rule: ScopeRule) -> ScopeConfig:
    from scope import add_exclude
    return add_exclude(rule.pattern, rule.target)

@app.delete("/api/scope/include/{index}")
async def scope_remove_include(index: int) -> ScopeConfig:
    from scope import remove_include
    return remove_include(index)

@app.delete("/api/scope/exclude/{index}")
async def scope_remove_exclude(index: int) -> ScopeConfig:
    from scope import remove_exclude
    return remove_exclude(index)


# ── Repeater ─────────────────────────────────────────────────────────────────

@app.post("/api/repeater/send")
async def repeater_send(req: RepeaterRequest) -> dict:
    from repeater import send_request
    return await send_request(req)

@app.post("/api/repeater/replay/{flow_id}")
async def repeater_replay(flow_id: str, modification: RepeaterModification | None = None) -> dict:
    from repeater import replay_flow
    return await replay_flow(flow_id, modification)

@app.get("/api/repeater/history")
async def repeater_history(limit: int = 50) -> list[dict]:
    from repeater import get_history
    return get_history(limit)


# ── Intruder ─────────────────────────────────────────────────────────────────

@app.post("/api/intruder/attack")
async def intruder_attack(req: IntruderRequest) -> dict:
    from intruder import start_attack
    job = await start_attack(req)
    return {"job_id": job.job_id, "status": job.status, "total": job.total}

@app.get("/api/intruder/{job_id}")
async def intruder_status(job_id: str) -> IntruderJob:
    job = state.intruder_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Intruder job {job_id} not found")
    return job

@app.delete("/api/intruder/{job_id}")
async def intruder_cancel(job_id: str) -> dict:
    from intruder import cancel_attack
    if not cancel_attack(job_id):
        raise HTTPException(404, f"Intruder job {job_id} not found")
    return {"cancelled": job_id}

@app.get("/api/intruder/payloads/list")
async def intruder_payload_lists() -> dict:
    from intruder import PAYLOADS
    return {k: len(v) for k, v in PAYLOADS.items()}

@app.post("/api/intruder/attack-flow")
async def intruder_attack_flow(body: dict) -> dict:
    """Launch an intruder attack from a captured flow — auto-extracts insertion points."""
    from intruder import attack_from_flow
    flow_id = body.get("flow_id")
    if not flow_id:
        raise HTTPException(400, "flow_id is required")
    job = await attack_from_flow(
        flow_id=flow_id,
        attack_type=body.get("attack_type", "sniper"),
        payloads=body.get("payloads"),
        concurrency=body.get("concurrency", 10),
    )
    return {"job_id": job.job_id, "status": job.status, "total": job.total}

@app.get("/api/intruder/{job_id}/export")
async def intruder_export(job_id: str, format: str = "csv") -> PlainTextResponse:
    from intruder import export_results
    job = state.intruder_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Intruder job {job_id} not found")
    content = export_results(job, format)
    return PlainTextResponse(content)

@app.get("/api/intruder/{job_id}/cluster")
async def intruder_cluster(job_id: str) -> dict:
    from intruder import cluster_results
    job = state.intruder_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Intruder job {job_id} not found")
    return cluster_results(job)

@app.get("/api/intruder/{job_id}/timing")
async def intruder_timing(job_id: str) -> dict:
    from intruder import analyze_timing
    job = state.intruder_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Intruder job {job_id} not found")
    return analyze_timing(job)


# ── Scanner ──────────────────────────────────────────────────────────────────

@app.post("/api/scanner/scan")
async def scanner_scan(req: ScanRequest) -> dict:
    from scanner import start_scan
    job = await start_scan(req)
    return {"scan_id": job.scan_id, "status": job.status}

@app.get("/api/scanner/profiles")
async def scanner_profiles() -> list[dict]:
    from scan_profiles import list_profiles
    return list_profiles()

@app.post("/api/scanner/profiles")
async def scanner_add_profile(profile: ScanProfile) -> list[dict]:
    from scan_profiles import add_profile
    return add_profile(profile)

@app.delete("/api/scanner/profiles/{name}")
async def scanner_remove_profile(name: str) -> dict:
    from scan_profiles import remove_profile
    if not remove_profile(name):
        raise HTTPException(404, f"Profile '{name}' not found (or is built-in)")
    return {"deleted": name}

@app.post("/api/scanner/scan-flow")
async def scanner_scan_flow(body: dict) -> dict:
    """Scan a captured flow by testing all insertion points individually."""
    from scanner import scan_flow
    flow_id = body.get("flow_id")
    if not flow_id:
        raise HTTPException(400, "flow_id is required")
    checks = body.get("checks")
    job = await scan_flow(flow_id, checks)
    if job.status == "error":
        raise HTTPException(400, job.error or "Scan failed")
    return {"scan_id": job.scan_id, "status": job.status}


@app.post("/api/scanner/insertion-points")
async def scanner_insertion_points(body: dict) -> dict:
    """Extract insertion points from a flow or raw request."""
    from insertion_points import extract_from_flow, extract_insertion_points
    flow_id = body.get("flow_id")
    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, f"Flow {flow_id} not found")
        parsed = extract_from_flow(flow.model_dump())
    else:
        parsed = extract_insertion_points(
            method=body.get("method", "GET"),
            url=body.get("url", ""),
            headers=body.get("headers", {}),
            body=body.get("body"),
        )
    return parsed.to_dict()


@app.get("/api/scanner/{scan_id}")
async def scanner_results(scan_id: str) -> ScanJob:
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return job

@app.get("/api/scanner/{scan_id}/tasks")
async def scanner_tasks(scan_id: str) -> list[dict]:
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return [t.model_dump() for t in job.tasks]

@app.post("/api/scanner/{scan_id}/tasks/{task_id}/pause")
async def scanner_task_pause(scan_id: str, task_id: str) -> dict:
    from scanner import pause_scan_task
    if not pause_scan_task(scan_id, task_id):
        raise HTTPException(404, "Task not found")
    return {"paused": task_id}

@app.post("/api/scanner/{scan_id}/tasks/{task_id}/resume")
async def scanner_task_resume(scan_id: str, task_id: str) -> dict:
    from scanner import resume_scan_task
    if not resume_scan_task(scan_id, task_id):
        raise HTTPException(404, "Task not found")
    return {"resumed": task_id}

@app.delete("/api/scanner/{scan_id}/tasks/{task_id}")
async def scanner_task_cancel(scan_id: str, task_id: str) -> dict:
    from scanner import cancel_scan_task
    if not cancel_scan_task(scan_id, task_id):
        raise HTTPException(404, "Task not found")
    return {"cancelled": task_id}

@app.post("/api/scanner/browser-scan")
async def scanner_browser_scan(body: dict) -> dict:
    from browser_scanner import BROWSER_CHECKS
    url = body.get("url")
    if not url:
        raise HTTPException(400, "url is required")
    checks = body.get("checks", list(BROWSER_CHECKS.keys()))
    results = []
    for check_name in checks:
        fn = BROWSER_CHECKS.get(check_name)
        if fn:
            findings = await fn(url)
            results.extend([f.model_dump() for f in findings])
    return {"url": url, "findings": results, "count": len(results)}

@app.post("/api/scanner/incremental-scan")
async def scanner_incremental_scan(req: ScanRequest) -> dict:
    from scanner import start_incremental_scan
    job = await start_incremental_scan(req)
    return {"scan_id": job.scan_id, "status": job.status, "skipped": len(req.urls) - len(job.urls)}


# ── Passive Scanner ──────────────────────────────────────────────────────────

@app.get("/api/passive")
async def passive_get() -> dict:
    import passive_scanner
    return {
        "enabled": passive_scanner.enabled,
        "findings": [f.model_dump() for f in passive_scanner.get_findings()],
        "count": len(passive_scanner.findings),
    }

@app.post("/api/passive/toggle")
async def passive_toggle(body: dict) -> dict:
    import passive_scanner
    passive_scanner.enabled = body.get("enabled", True)
    return {"enabled": passive_scanner.enabled}

@app.delete("/api/passive")
async def passive_clear() -> dict:
    import passive_scanner
    return {"cleared": passive_scanner.clear_findings()}

@app.get("/api/passive/rules")
async def passive_rules() -> list[dict]:
    import passive_scanner
    return passive_scanner.get_custom_rules()

@app.post("/api/passive/rules/load")
async def passive_rules_load(body: dict) -> dict:
    import passive_scanner
    path = body.get("path")
    if not path:
        raise HTTPException(400, "path is required")
    count = passive_scanner.load_custom_rules(path)
    return {"loaded": count}

@app.put("/api/passive/rules/{check_id}/severity")
async def passive_severity_override(check_id: str, body: dict) -> dict:
    import passive_scanner
    severity = body.get("severity")
    if not severity:
        raise HTTPException(400, "severity is required")
    passive_scanner.set_severity_override(check_id, severity)
    return {"check_id": check_id, "severity": severity}

@app.post("/api/passive/{index}/false-positive")
async def passive_false_positive(index: int, body: dict | None = None) -> dict:
    import passive_scanner
    reason = (body or {}).get("reason", "")
    if not passive_scanner.mark_false_positive(index, reason):
        raise HTTPException(404, "Finding not found")
    return {"marked": index, "reason": reason}


# ── Sitemap ──────────────────────────────────────────────────────────────────

@app.get("/api/sitemap")
async def sitemap_all() -> dict:
    from sitemap import build_sitemap
    return build_sitemap()

@app.get("/api/sitemap/{host}")
async def sitemap_host(host: str) -> dict:
    from sitemap import build_sitemap_for_host
    result = build_sitemap_for_host(host)
    if not result:
        raise HTTPException(404, f"No flows for host {host}")
    return result

@app.post("/api/sitemap/{host}/add-to-scope")
async def sitemap_add_to_scope(host: str) -> dict:
    from scope import add_include, toggle
    toggle(True)
    escaped = host.replace(".", r"\.")
    add_include(f"^{escaped}$", "host")
    return {"added": host}


# ── Comparer ─────────────────────────────────────────────────────────────────

@app.post("/api/comparer/diff")
async def comparer_diff(req: CompareRequest) -> DiffResult:
    from comparer import compare
    return compare(req)


# ── Decoder ──────────────────────────────────────────────────────────────────

@app.post("/api/decoder/encode")
async def decoder_encode(req: CodecRequest) -> dict:
    from decoder import encode
    return {"result": encode(req)}

@app.post("/api/decoder/decode")
async def decoder_decode(req: CodecRequest) -> dict:
    from decoder import decode
    return {"result": decode(req)}


# ── Collaborator ─────────────────────────────────────────────────────────

@app.post("/api/collaborator/start")
async def collaborator_start(body: dict | None = None) -> dict:
    from collaborator_server import start_servers
    cfg = body or {}
    result = await start_servers(
        domain=cfg.get("domain", "collab.localhost"),
        dns_port=cfg.get("dns_port", 5354),
        http_port=cfg.get("http_port", 9999),
        smtp_port=cfg.get("smtp_port", 2525),
    )
    return result

@app.post("/api/collaborator/stop")
async def collaborator_stop() -> dict:
    from collaborator_server import stop_servers
    await stop_servers()
    return {"stopped": True}

@app.get("/api/collaborator/config")
async def collaborator_config_get() -> dict:
    return state.collaborator_config.model_dump()

@app.put("/api/collaborator/config")
async def collaborator_config_set(body: dict) -> dict:
    from models import CollaboratorConfig
    cfg = state.collaborator_config
    for k, v in body.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)
    return cfg.model_dump()

@app.post("/api/collaborator/generate")
async def collaborator_generate(body: dict | None = None) -> dict:
    from collaborator_server import generate_unique_payload
    context = (body or {}).get("context", "")
    payload = generate_unique_payload(context=context)
    return payload.model_dump()

@app.get("/api/collaborator/poll")
async def collaborator_poll(correlation_id: str | None = None) -> dict:
    from collaborator_server import get_interactions
    interactions = get_interactions(correlation_id=correlation_id)
    return {"interactions": [i.model_dump() for i in interactions], "count": len(interactions)}

@app.get("/api/collaborator/interactions")
async def collaborator_interactions(correlation_id: str | None = None) -> list[dict]:
    return [i.model_dump() for i in state.collaborator_interactions
            if not correlation_id or i.correlation_id == correlation_id]

@app.delete("/api/collaborator/interactions")
async def collaborator_clear_interactions() -> dict:
    count = len(state.collaborator_interactions)
    state.collaborator_interactions.clear()
    return {"cleared": count}


# ── Sequencer ────────────────────────────────────────────────────────────────

@app.post("/api/sequencer/start")
async def sequencer_start(req: SequencerRequest) -> dict:
    from sequencer import start_sequencer
    job = await start_sequencer(req)
    return {"job_id": job.job_id, "status": job.status}

@app.get("/api/sequencer/{job_id}")
async def sequencer_status(job_id: str):
    job = state.sequencer_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Sequencer job {job_id} not found")
    return job

@app.delete("/api/sequencer/{job_id}")
async def sequencer_cancel(job_id: str) -> dict:
    from sequencer import cancel_sequencer
    if not cancel_sequencer(job_id):
        raise HTTPException(404, f"Sequencer job {job_id} not found")
    return {"cancelled": job_id}


# ── Session Handler ──────────────────────────────────────────────────────────

@app.get("/api/sessions/rules")
async def session_rules() -> list[SessionRule]:
    from session_handler import get_rules
    return get_rules()

@app.post("/api/sessions/rules")
async def session_add_rule(rule: SessionRule) -> list[SessionRule]:
    from session_handler import add_rule
    return add_rule(rule)

@app.delete("/api/sessions/rules/{index}")
async def session_remove_rule(index: int) -> list[SessionRule]:
    from session_handler import remove_rule
    return remove_rule(index)

@app.post("/api/sessions/test/{index}")
async def session_test_rule(index: int) -> dict:
    from session_handler import get_rules, execute_macro
    rules = get_rules()
    if index < 0 or index >= len(rules):
        raise HTTPException(404, "Rule not found")
    result = await execute_macro(rules[index])
    return result or {"error": "Macro failed to extract token"}


# ── Macro Chains ────────────────────────────────────────────────────────────

@app.get("/api/sessions/chains")
async def session_chains_list() -> list:
    from session_handler import get_chains
    return [c.model_dump() if hasattr(c, 'model_dump') else c for c in get_chains()]

@app.post("/api/sessions/chains")
async def session_chains_add(chain: MacroChain) -> list:
    from session_handler import add_chain
    return [c.model_dump() if hasattr(c, 'model_dump') else c for c in add_chain(chain)]

@app.delete("/api/sessions/chains/{index}")
async def session_chains_remove(index: int) -> list:
    from session_handler import remove_chain
    return [c.model_dump() if hasattr(c, 'model_dump') else c for c in remove_chain(index)]

@app.post("/api/sessions/chains/{index}/execute")
async def session_chains_execute(index: int) -> dict:
    from session_handler import get_chains, execute_chain
    chains = get_chains()
    if index < 0 or index >= len(chains):
        raise HTTPException(404, "Chain not found")
    return await execute_chain(chains[index])


# ── Export ───────────────────────────────────────────────────────────────────

@app.get("/api/export/{flow_id}")
async def export_single(flow_id: str, format: ExportFormat = ExportFormat.curl) -> PlainTextResponse:
    from exporter import export_flow
    flow = state.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow {flow_id} not found")
    content = export_flow(flow, format)
    return PlainTextResponse(content)

@app.post("/api/export")
async def export_multiple(body: dict) -> PlainTextResponse:
    from exporter import export_flows
    flow_ids = body.get("flow_ids")
    fmt = ExportFormat(body.get("format", "curl"))
    content = export_flows(flow_ids, fmt)
    return PlainTextResponse(content)

@app.post("/api/export/openapi")
async def export_openapi(body: dict) -> dict:
    from openapi_generator import generate_openapi_spec
    host = body.get("host", "")
    return generate_openapi_spec(host=host)

@app.post("/api/export/postman")
async def export_postman(body: dict) -> dict:
    from exporter import export_flows
    flow_ids = body.get("flow_ids")
    content = export_flows(flow_ids, ExportFormat.postman)
    import json
    return json.loads(content)

@app.post("/api/export/nuclei-template")
async def export_nuclei_template(body: dict) -> PlainTextResponse:
    from exporter import _to_nuclei_template
    scan_id = body.get("scan_id")
    finding_index = body.get("finding_index", 0)
    if not scan_id:
        raise HTTPException(400, "scan_id is required")
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if finding_index >= len(job.findings):
        raise HTTPException(404, "Finding index out of range")
    content = _to_nuclei_template(job.findings[finding_index])
    return PlainTextResponse(content)


# ── Extensions ───────────────────────────────────────────────────────────────

@app.get("/api/extensions")
async def extensions_list() -> list[dict]:
    from extensions import get_extensions
    return [e.model_dump() for e in get_extensions()]

@app.post("/api/extensions/reload")
async def extensions_reload() -> dict:
    from extensions import load_all
    loaded = load_all()
    return {"loaded": len(loaded)}

@app.post("/api/extensions/{name}/toggle")
async def extensions_toggle(name: str, body: dict) -> dict:
    from extensions import toggle_extension
    ok = toggle_extension(name, body.get("enabled", True))
    if not ok:
        raise HTTPException(404, f"Extension {name} not found")
    return {"name": name, "enabled": body.get("enabled", True)}

@app.get("/api/extensions/registry")
async def extensions_registry() -> list[dict]:
    from extension_registry import list_available, fetch_registry
    await fetch_registry()
    return list_available()

@app.post("/api/extensions/install")
async def extensions_install(body: dict) -> dict:
    from extension_registry import install_extension
    name = body.get("name")
    if not name:
        raise HTTPException(400, "name is required")
    return await install_extension(name)

@app.put("/api/extensions/{name}/config")
async def extensions_config_set(name: str, body: dict) -> dict:
    from extensions import set_extension_config
    if not set_extension_config(name, body):
        raise HTTPException(404, f"Extension {name} not found")
    return {"name": name, "config": body}

@app.get("/api/extensions/{name}/state")
async def extensions_state_get(name: str) -> dict:
    from extensions import get_extension_state
    ext_state = get_extension_state(name)
    if ext_state is None:
        raise HTTPException(404, f"Extension {name} not found")
    return ext_state


# ── WebSocket Messages ───────────────────────────────────────────────────────

@app.get("/api/websocket/messages")
async def ws_messages(flow_id: str | None = None, limit: int = 100) -> list[dict]:
    msgs = state.ws_messages
    if flow_id:
        msgs = [m for m in msgs if m.flow_id == flow_id]
    return [m.model_dump() for m in msgs[-limit:]]

@app.post("/api/websocket/intercept/enable")
async def ws_intercept_enable() -> dict:
    state.ws_intercept_enabled = True
    return {"ws_intercept": True}

@app.post("/api/websocket/intercept/disable")
async def ws_intercept_disable() -> dict:
    state.ws_intercept_enabled = False
    for mid in list(state.ws_intercept_queue.keys()):
        state.resolve_ws_intercept(mid, "forward")
    return {"ws_intercept": False}

@app.get("/api/websocket/intercept/queue")
async def ws_intercept_queue() -> list[dict]:
    return [
        {"id": mid, "flow_id": m.flow_id, "direction": m.direction,
         "content": m.content, "timestamp": m.timestamp}
        for mid, m in state.ws_intercept_queue.items()
    ]

@app.post("/api/websocket/intercept/{msg_id}/forward")
async def ws_intercept_forward(msg_id: str, body: dict | None = None) -> dict:
    content = body.get("content") if body else None
    if not state.resolve_ws_intercept(msg_id, "forward", content):
        raise HTTPException(404, f"WS message {msg_id} not in intercept queue")
    return {"action": "forwarded", "msg_id": msg_id}

@app.post("/api/websocket/intercept/{msg_id}/drop")
async def ws_intercept_drop(msg_id: str) -> dict:
    if not state.resolve_ws_intercept(msg_id, "drop"):
        raise HTTPException(404, f"WS message {msg_id} not in intercept queue")
    return {"action": "dropped", "msg_id": msg_id}

@app.post("/api/websocket/send/{flow_id}")
async def ws_send_message(flow_id: str, body: dict) -> dict:
    """Inject a WebSocket message into a flow (for testing)."""
    from models import WebSocketMessage
    import time as _time
    msg = WebSocketMessage(
        flow_id=flow_id,
        direction="send",
        content=body.get("content", ""),
        is_text=body.get("is_text", True),
        timestamp=_time.time(),
        length=len(body.get("content", "")),
    )
    state.add_ws_message(msg)
    return {"sent": True, "flow_id": flow_id}


# ── CA Cert ──────────────────────────────────────────────────────────────────

@app.get("/api/ca-cert")
async def ca_cert_info() -> dict:
    import os
    ca_dir = Path.home() / ".mitmproxy"
    ca_pem = ca_dir / "mitmproxy-ca-cert.pem"
    ca_p12 = ca_dir / "mitmproxy-ca-cert.p12"

    return {
        "ca_dir": str(ca_dir),
        "pem_exists": ca_pem.exists(),
        "p12_exists": ca_p12.exists(),
        "pem_path": str(ca_pem),
        "p12_path": str(ca_p12),
        "install_instructions": {
            "windows": f'certutil -addstore root "{ca_pem}"',
            "macos": f'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{ca_pem}"',
            "linux": f'sudo cp "{ca_pem}" /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates',
            "firefox": "Settings > Privacy & Security > View Certificates > Import > select mitmproxy-ca-cert.pem",
            "browser_auto": "Visit http://mitm.it while proxy is active to download certs",
        },
    }


# ── Match & Replace ─────────────────────────────────────────────────────────

@app.get("/api/match-replace")
async def match_replace_list() -> list[MatchReplaceRule]:
    import match_replace
    return match_replace.get_rules()

@app.post("/api/match-replace")
async def match_replace_add(rule: MatchReplaceRule) -> list[MatchReplaceRule]:
    import match_replace
    return match_replace.add_rule(rule)

@app.put("/api/match-replace/{index}")
async def match_replace_update(index: int, rule: MatchReplaceRule) -> list[MatchReplaceRule]:
    import match_replace
    return match_replace.update_rule(index, rule)

@app.delete("/api/match-replace/{index}")
async def match_replace_delete(index: int) -> list[MatchReplaceRule]:
    import match_replace
    return match_replace.remove_rule(index)


# ── Response Intercept ──────────────────────────────────────────────────────

@app.post("/api/intercept/response/enable")
async def response_intercept_enable() -> dict:
    state.response_intercept_enabled = True
    return {"response_intercept": True}

@app.post("/api/intercept/response/disable")
async def response_intercept_disable() -> dict:
    state.response_intercept_enabled = False
    for fid in list(state.response_intercept_queue.keys()):
        state.resolve_response_intercept(fid, "forward")
    return {"response_intercept": False}

@app.get("/api/intercept/response/queue")
async def response_intercept_queue() -> list[dict]:
    return [
        {"id": f.id, "method": f.request.method, "url": f.request.url,
         "status_code": f.response.status_code if f.response else None,
         "headers": f.response.headers if f.response else {},
         "body": f.response.body[:2000] if f.response and f.response.body else ""}
        for f in state.response_intercept_queue.values()
    ]

@app.post("/api/intercept/response/{flow_id}/forward")
async def response_intercept_forward(flow_id: str, modification: dict | None = None) -> dict:
    mods = modification or {}
    if not state.resolve_response_intercept(flow_id, "forward", mods):
        raise HTTPException(404, f"Flow {flow_id} not in response intercept queue")
    return {"action": "forwarded", "flow_id": flow_id}


# ── Crawler ─────────────────────────────────────────────────────────────────

@app.post("/api/crawler/start")
async def crawler_start(body: dict) -> dict:
    from crawler import start_crawl
    job = await start_crawl(
        url=body["url"],
        max_depth=body.get("max_depth", 3),
        concurrency=body.get("concurrency", 5),
        headers=body.get("headers", {}),
        js_render=body.get("js_render", False),
        submit_forms=body.get("submit_forms", False),
        login_url=body.get("login_url"),
        login_credentials=body.get("login_credentials"),
    )
    return {"job_id": job.job_id, "status": job.status}

@app.get("/api/crawler/{job_id}")
async def crawler_status(job_id: str) -> CrawlJob:
    job = state.crawl_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Crawl job {job_id} not found")
    return job

@app.delete("/api/crawler/{job_id}")
async def crawler_cancel(job_id: str) -> dict:
    from crawler import cancel_crawl
    if not cancel_crawl(job_id):
        raise HTTPException(404, f"Crawl job {job_id} not found")
    return {"cancelled": job_id}


# ── Content Discovery ───────────────────────────────────────────────────────

@app.post("/api/discovery/start")
async def discovery_start(body: dict) -> dict:
    from discovery import start_discovery
    job = await start_discovery(
        url=body["url"],
        wordlist=body.get("wordlist", "@common"),
        extensions=body.get("extensions", []),
        concurrency=body.get("concurrency", 20),
        headers=body.get("headers", {}),
        status_filter=body.get("status_filter"),
        method=body.get("method", "GET"),
        recursive=body.get("recursive", False),
        smart_wordlist=body.get("smart_wordlist", False),
    )
    return {"job_id": job.job_id, "status": job.status}

@app.post("/api/discovery/params")
async def discovery_params(body: dict) -> dict:
    from discovery import discover_parameters
    url = body.get("url")
    if not url:
        raise HTTPException(400, "url is required")
    job = await discover_parameters(
        url=url,
        wordlist=body.get("wordlist", "@common_params"),
        method=body.get("method", "GET"),
    )
    return {"job_id": job.job_id, "status": job.status}

@app.get("/api/discovery/wordlists")
async def discovery_wordlists() -> dict:
    from discovery import BUILTIN_WORDS
    return {k: len(v) for k, v in BUILTIN_WORDS.items()}

@app.get("/api/discovery/{job_id}")
async def discovery_status(job_id: str) -> DiscoveryJob:
    job = state.discovery_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Discovery job {job_id} not found")
    return job

@app.delete("/api/discovery/{job_id}")
async def discovery_cancel(job_id: str) -> dict:
    from discovery import cancel_discovery
    if not cancel_discovery(job_id):
        raise HTTPException(404, f"Discovery job {job_id} not found")
    return {"cancelled": job_id}


# ── Project Persistence ─────────────────────────────────────────────────────

@app.post("/api/project/save")
async def project_save(body: dict | None = None) -> dict:
    from persistence import save_project
    name = body.get("name") if body else None
    result = save_project(name)
    if name:
        state.current_project = name
    return result

@app.post("/api/project/load")
async def project_load(body: dict) -> dict:
    from persistence import load_project
    result = load_project(body["name"])
    if "error" not in result:
        state.current_project = body["name"]
    return result

@app.get("/api/project/list")
async def project_list() -> list[dict]:
    from persistence import list_projects
    return list_projects()

@app.delete("/api/project/{name}")
async def project_delete(name: str) -> dict:
    from persistence import delete_project
    if not delete_project(name):
        raise HTTPException(404, f"Project '{name}' not found")
    return {"deleted": name}


# ── Target Analysis ─────────────────────────────────────────────────────────

@app.get("/api/target/analysis")
async def target_analysis_all() -> dict:
    from target_analyzer import analyze_all
    return analyze_all()

@app.get("/api/target/analysis/{host}")
async def target_analysis_host(host: str) -> dict:
    from target_analyzer import analyze_host
    return analyze_host(host)


# ── TLS Pass-through ────────────────────────────────────────────────────────

@app.get("/api/tls-passthrough")
async def tls_passthrough_list() -> list[str]:
    from tls_passthrough import get_domains
    return get_domains()

@app.post("/api/tls-passthrough")
async def tls_passthrough_add(body: dict) -> list[str]:
    from tls_passthrough import add_domain
    return add_domain(body["pattern"])

@app.delete("/api/tls-passthrough/{index}")
async def tls_passthrough_remove(index: int) -> list[str]:
    from tls_passthrough import remove_domain
    return remove_domain(index)


# ── Report Generator ────────────────────────────────────────────────────────

@app.post("/api/report/generate")
async def report_generate(body: dict) -> dict:
    import passive_scanner
    from report_generator import (
        save_report, generate_json_report, generate_xml_report,
        generate_csv_report, generate_markdown_report, generate_pdf_report,
    )

    scan_id = body.get("scan_id")
    fmt = body.get("format", "html")
    title = body.get("title", "Vulnerability Scan Report")
    target = body.get("target", "")
    include_passive = body.get("include_passive", True)

    scan_findings = []
    if scan_id:
        job = state.scanner_jobs.get(scan_id)
        if not job:
            raise HTTPException(404, f"Scan {scan_id} not found")
        scan_findings = job.findings
    else:
        for job in state.scanner_jobs.values():
            if job.status == "completed":
                scan_findings.extend(job.findings)

    passive_list = passive_scanner.get_findings() if include_passive else []

    if fmt == "json":
        content = generate_json_report(scan_findings, passive_list, title, target)
        return {"content": content, "format": "json"}
    elif fmt == "xml":
        content = generate_xml_report(scan_findings, passive_list, title, target)
        return {"content": content, "format": "xml"}
    elif fmt == "csv":
        content = generate_csv_report(scan_findings, passive_list)
        return {"content": content, "format": "csv"}
    elif fmt == "markdown":
        content = generate_markdown_report(scan_findings, passive_list, title, target)
        return {"content": content, "format": "markdown"}
    elif fmt == "pdf":
        content = generate_pdf_report(scan_findings, passive_list, title, target)
        return {"content": content, "format": "pdf"}
    else:
        path = save_report(scan_findings, passive_list, title=title, target=target)
        return {"path": path, "format": "html", "findings_count": len(scan_findings), "passive_count": len(passive_list)}

@app.get("/api/report/scan/{scan_id}", response_class=HTMLResponse)
async def report_view(scan_id: str) -> HTMLResponse:
    from report_generator import generate_report
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} not found")
    report_html = generate_report(job.findings, title=f"Scan Report — {scan_id}", target=", ".join(job.urls[:3]))
    return HTMLResponse(report_html)

@app.get("/api/report/executive-summary")
async def report_executive_summary(scan_id: str | None = None) -> dict:
    import passive_scanner
    from report_generator import generate_executive_summary
    scan_findings = []
    if scan_id:
        job = state.scanner_jobs.get(scan_id)
        if not job:
            raise HTTPException(404, f"Scan {scan_id} not found")
        scan_findings = job.findings
    else:
        for job in state.scanner_jobs.values():
            if job.status == "completed":
                scan_findings.extend(job.findings)
    return generate_executive_summary(scan_findings, passive_scanner.get_findings())

@app.get("/api/report/trend/{scan_id}")
async def report_trend(scan_id: str, compare_scan_id: str | None = None) -> dict:
    from report_generator import generate_trend_analysis
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return generate_trend_analysis(job.findings, compare_scan_id)

@app.get("/api/report/compliance/{scan_id}")
async def report_compliance(scan_id: str) -> dict:
    from report_generator import generate_compliance_mapping
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return generate_compliance_mapping(job.findings)


# ── Cookie Jar ──────────────────────────────────────────────────────────────

@app.get("/api/cookie-jar")
async def cookie_jar_get(domain: str | None = None) -> dict:
    from cookie_jar import jar
    cookies = jar.get_all()
    if domain:
        cookies = [c for c in cookies if c.get("domain") == domain or domain in c.get("domain", "")]
    return {"cookies": cookies, "count": len(cookies)}

@app.post("/api/cookie-jar")
async def cookie_jar_set(body: dict) -> dict:
    from cookie_jar import jar
    jar.set_cookie(
        domain=body["domain"],
        name=body["name"],
        value=body["value"],
        path=body.get("path", "/"),
        secure=body.get("secure", False),
        httponly=body.get("httponly", False),
        expires=body.get("expires"),
    )
    return {"set": True, "domain": body["domain"], "name": body["name"]}

@app.delete("/api/cookie-jar")
async def cookie_jar_clear(domain: str | None = None) -> dict:
    from cookie_jar import jar
    if domain:
        count = jar.clear(domain)
        return {"cleared": domain, "count": count}
    count = jar.clear()
    return {"cleared": "all", "count": count}


# ── Organizer ───────────────────────────────────────────────────────────────

@app.get("/api/organizer")
async def organizer_list(
    category: str | None = None,
    status: str | None = None,
    tag: str | None = None,
) -> list[dict]:
    import organizer
    items = organizer.list_items(category=category, status=status, tag=tag)
    return [i.model_dump() for i in items]

@app.post("/api/organizer")
async def organizer_create(item: OrganizerItem) -> dict:
    import organizer
    created = organizer.create(item)
    return created.model_dump()

@app.get("/api/organizer/{item_id}")
async def organizer_get(item_id: str) -> dict:
    import organizer
    item = organizer.get(item_id)
    if not item:
        raise HTTPException(404, f"Organizer item {item_id} not found")
    return item.model_dump()

@app.patch("/api/organizer/{item_id}")
async def organizer_update(item_id: str, body: dict) -> dict:
    import organizer
    item = organizer.update(item_id, body)
    if not item:
        raise HTTPException(404, f"Organizer item {item_id} not found")
    return item.model_dump()

@app.delete("/api/organizer/{item_id}")
async def organizer_delete(item_id: str) -> dict:
    import organizer
    if not organizer.delete(item_id):
        raise HTTPException(404, f"Organizer item {item_id} not found")
    return {"deleted": item_id}

@app.post("/api/organizer/{item_id}/link-flow")
async def organizer_link_flow(item_id: str, body: dict) -> dict:
    import organizer
    item = organizer.link_flow(item_id, body["flow_id"])
    if not item:
        raise HTTPException(404, f"Organizer item {item_id} not found")
    return item.model_dump()

@app.post("/api/organizer/{item_id}/link-finding")
async def organizer_link_finding(item_id: str, body: dict) -> dict:
    import organizer
    item = organizer.link_finding(item_id, body["finding_id"])
    if not item:
        raise HTTPException(404, f"Organizer item {item_id} not found")
    return item.model_dump()


# ── Dashboard ───────────────────────────────────────────────────────────────

@app.get("/api/dashboard")
async def dashboard() -> dict:
    """Aggregated overview of all proxy engine state."""
    import passive_scanner, scope as scope_mod, session_handler
    from cookie_jar import jar
    import organizer
    import time as _time

    # Flow stats
    flow_count = len(state.flows)
    recent_flows = sum(1 for f in state.flows.values() if f.timestamp > _time.time() - 300)

    # Scan stats
    scan_stats = {"total": 0, "running": 0, "completed": 0, "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
    for job in state.scanner_jobs.values():
        scan_stats["total"] += 1
        if job.status == "running":
            scan_stats["running"] += 1
        elif job.status == "completed":
            scan_stats["completed"] += 1
        for f in job.findings:
            sev = getattr(f, "severity", "info").lower()
            if sev in scan_stats["findings"]:
                scan_stats["findings"][sev] += 1

    # Intruder stats
    intruder_active = sum(1 for j in state.intruder_jobs.values() if j.status == "running")
    intruder_completed = sum(1 for j in state.intruder_jobs.values() if j.status == "completed")

    # Crawl stats
    crawl_active = sum(1 for j in state.crawl_jobs.values() if j.status == "running")
    crawl_urls = sum(len(j.discovered_urls) for j in state.crawl_jobs.values())

    # Passive stats
    passive_by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in passive_scanner.findings:
        sev = getattr(f, "severity", "info").lower()
        if sev in passive_by_sev:
            passive_by_sev[sev] += 1

    return {
        "flows": {"total": flow_count, "recent_5min": recent_flows},
        "scans": scan_stats,
        "intruder": {"active": intruder_active, "completed": intruder_completed, "total": len(state.intruder_jobs)},
        "crawler": {"active": crawl_active, "discovered_urls": crawl_urls, "total": len(state.crawl_jobs)},
        "passive": {"total": len(passive_scanner.findings), "by_severity": passive_by_sev},
        "scope": {"enabled": scope_mod.config.enabled},
        "websocket": {"messages": len(state.ws_messages), "intercept_enabled": state.ws_intercept_enabled},
        "session_rules": len(session_handler.rules),
        "cookies": len(jar.get_all()),
        "organizer_items": len(organizer.items),
        "project": state.current_project,
    }


# ── TLS Client Certificates ────────────────────────────────────────────

@app.put("/api/tls/client-cert")
async def tls_client_cert_set(body: dict) -> dict:
    from models import TLSClientConfig
    state.tls_client_config = TLSClientConfig(**body)
    return state.tls_client_config.model_dump()

@app.get("/api/tls/client-cert")
async def tls_client_cert_get() -> dict:
    if not state.tls_client_config:
        return {"configured": False}
    return {**state.tls_client_config.model_dump(), "configured": True}


# ── OpenAPI Import ─────────────────────────────────────────────────────

@app.post("/api/import/openapi")
async def import_openapi(body: dict) -> dict:
    from openapi_importer import import_openapi_spec
    spec = body.get("spec")
    if not spec:
        raise HTTPException(400, "spec is required (JSON object or string)")
    return import_openapi_spec(spec)


# ── HTTP Logger ────────────────────────────────────────────────────────

@app.get("/api/logger")
async def logger_get(source: str | None = None, limit: int = 100) -> dict:
    from logger import logger
    entries = logger.get_entries(source=source, limit=limit)
    return {"entries": entries, "count": len(entries), "enabled": logger.enabled}

@app.post("/api/logger/toggle")
async def logger_toggle(body: dict) -> dict:
    from logger import logger
    enabled = body.get("enabled", True)
    return {"enabled": logger.toggle(enabled)}

@app.delete("/api/logger")
async def logger_clear() -> dict:
    from logger import logger
    return {"cleared": logger.clear()}


# ── Mobile Proxy Config ───────────────────────────────────────────────

@app.get("/api/mobile/pac")
async def mobile_pac(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> PlainTextResponse:
    from mobile_config import generate_pac_file
    return PlainTextResponse(generate_pac_file(proxy_host, proxy_port), media_type="application/x-ns-proxy-autoconfig")

@app.get("/api/mobile/qr")
async def mobile_qr(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> dict:
    from mobile_config import generate_qr_data
    data = generate_qr_data(proxy_host, proxy_port)
    return {"qr_base64": data, "proxy": f"{proxy_host}:{proxy_port}"}

@app.get("/api/mobile/ios-profile")
async def mobile_ios_profile(proxy_host: str = "127.0.0.1", proxy_port: int = 8080, ca_cert_path: str | None = None) -> PlainTextResponse:
    from mobile_config import generate_mobileconfig
    content = generate_mobileconfig(proxy_host, proxy_port, ca_cert_path)
    return PlainTextResponse(content, media_type="application/x-apple-aspen-config")


# ── Live Audit ─────────────────────────────────────────────────────────

@app.post("/api/live-audit/toggle")
async def live_audit_toggle_endpoint(body: dict) -> dict:
    import live_audit
    enabled = body.get("enabled", True)
    return live_audit.toggle(enabled)

@app.get("/api/live-audit/findings")
async def live_audit_findings_endpoint(severity: str | None = None, limit: int = 100) -> dict:
    import live_audit
    results = live_audit.findings
    if severity:
        results = [f for f in results if f.severity == severity]
    return {"findings": [f.model_dump() for f in results[-limit:]], "count": len(results)}

@app.put("/api/live-audit/config")
async def live_audit_config_endpoint(body: dict) -> dict:
    import live_audit
    return live_audit.configure(
        checks=body.get("checks"),
        severity=body.get("severity"),
        rate=body.get("rate"),
    )

@app.get("/api/live-audit/config")
async def live_audit_config_get() -> dict:
    import live_audit
    return live_audit.get_config()

@app.delete("/api/live-audit/findings")
async def live_audit_clear() -> dict:
    import live_audit
    return live_audit.clear_findings()


# ── Scanner Templates (Nuclei Native) ──────────────────────────────────

@app.get("/api/scanner/templates")
async def scanner_templates() -> dict:
    try:
        from nuclei_runtime import NucleiRuntime
        runtime = NucleiRuntime.get_instance()
        return runtime.get_stats()
    except Exception as e:
        return {"error": str(e), "total": 0}

@app.post("/api/scanner/templates/reload")
async def scanner_templates_reload() -> dict:
    try:
        from nuclei_runtime import NucleiRuntime
        runtime = NucleiRuntime.get_instance()
        count = runtime.reload_index()
        return {"reloaded": count}
    except Exception as e:
        return {"error": str(e)}


# ── CI/CD Integration ──────────────────────────────────────────────────

@app.post("/api/ci/scan")
async def ci_scan(body: dict) -> dict:
    """Synchronous scan endpoint for CI/CD — waits for completion, returns findings JSON."""
    _check_api_key_from_body(body)

    from models import ScanRequest
    from scanner import start_scan
    import asyncio

    urls = body.get("urls", [])
    if not urls:
        raise HTTPException(400, "urls is required")

    req = ScanRequest(
        urls=urls,
        custom_checks=body.get("checks", []),
        profile=body.get("profile"),
    )
    job = await start_scan(req)

    # Wait for completion (max 5 minutes)
    for _ in range(300):
        await asyncio.sleep(1)
        if job.status in ("completed", "error"):
            break

    return {
        "scan_id": job.scan_id,
        "status": job.status,
        "findings_count": len(job.findings),
        "findings": [f.model_dump() for f in job.findings],
    }

@app.post("/api/ci/scan-async")
async def ci_scan_async(body: dict) -> dict:
    """Async scan with webhook callback on completion."""
    _check_api_key_from_body(body)

    from models import ScanRequest
    from scanner import start_scan

    urls = body.get("urls", [])
    webhook_url = body.get("webhook_url", "")
    if not urls:
        raise HTTPException(400, "urls is required")

    req = ScanRequest(
        urls=urls,
        custom_checks=body.get("checks", []),
        profile=body.get("profile"),
    )
    job = await start_scan(req)

    if webhook_url:
        import asyncio
        from scheduler import _send_webhook
        asyncio.ensure_future(_send_webhook(webhook_url, job.scan_id, "ci-scan"))

    return {"scan_id": job.scan_id, "status": "running", "webhook_url": webhook_url}

@app.get("/api/ci/findings/{scan_id}")
async def ci_findings_sarif(scan_id: str, format: str = "sarif") -> dict:
    """Get scan findings in SARIF format for GitHub/GitLab integration."""
    job = state.scanner_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found")

    if format == "sarif":
        from scheduler import findings_to_sarif
        return findings_to_sarif(job.findings)

    return {
        "scan_id": scan_id,
        "status": job.status,
        "findings": [f.model_dump() for f in job.findings],
    }


# ── Schedule Management ────────────────────────────────────────────────

@app.get("/api/schedule")
async def schedule_list() -> dict:
    return {"schedules": [s.model_dump() for s in state.scheduled_scans]}

@app.post("/api/schedule")
async def schedule_create(body: dict) -> dict:
    from models import ScheduledScan
    import time

    scan = ScheduledScan(
        name=body.get("name", "scheduled-scan"),
        urls=body.get("urls", []),
        profile=body.get("profile", ""),
        interval_minutes=body.get("interval_minutes", 60),
        enabled=body.get("enabled", True),
        cron_expr=body.get("cron_expr", ""),
        webhook_url=body.get("webhook_url", ""),
    )

    if scan.interval_minutes > 0 and not scan.cron_expr:
        scan.next_run = time.time() + scan.interval_minutes * 60

    state.scheduled_scans.append(scan)
    return {"status": "created", "index": len(state.scheduled_scans) - 1, "schedule": scan.model_dump()}

@app.put("/api/schedule/{index}")
async def schedule_update(index: int, body: dict) -> dict:
    if index < 0 or index >= len(state.scheduled_scans):
        raise HTTPException(404, "Schedule not found")

    scan = state.scheduled_scans[index]
    for key in ("name", "urls", "profile", "interval_minutes", "enabled", "cron_expr", "webhook_url"):
        if key in body:
            setattr(scan, key, body[key])

    return {"status": "updated", "schedule": scan.model_dump()}

@app.delete("/api/schedule/{index}")
async def schedule_delete(index: int) -> dict:
    if index < 0 or index >= len(state.scheduled_scans):
        raise HTTPException(404, "Schedule not found")
    removed = state.scheduled_scans.pop(index)
    return {"status": "deleted", "name": removed.name}


# ── API Key Authentication ─────────────────────────────────────────────

def _check_api_key_from_body(body: dict) -> None:
    """Check API key from request body if PROXY_API_KEY is set."""
    import os
    api_key = os.environ.get("PROXY_API_KEY", "")
    if not api_key:
        return  # No key configured, skip auth
    provided = body.get("api_key", "")
    if provided != api_key:
        raise HTTPException(401, "Invalid or missing API key")


# ── SSE Event Stream ──────────────────────────────────────────────────────

_sse_clients: list[asyncio.Queue] = []

@app.get("/api/events")
async def event_stream():
    """Server-Sent Events for real-time flow updates — replaces polling."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    _sse_clients.append(queue)

    async def generate():
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"event: {data['event']}\ndata: {json.dumps(data['data'])}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in _sse_clients:
                _sse_clients.remove(queue)

    return StreamingResponse(generate(), media_type="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def sse_broadcast(event: str, data: dict) -> None:
    """Broadcast an event to all SSE clients. Called from addon/scanner."""
    for q in _sse_clients:
        try:
            q.put_nowait({"event": event, "data": data})
        except asyncio.QueueFull:
            pass


# ── Global Search ─────────────────────────────────────────────────────────

@app.get("/api/search")
async def global_search_endpoint(
    q: str = "",
    scope: str = "all",
    regex: bool = False,
    limit: int = 50,
) -> dict:
    from global_search import search
    return search(q, scope=scope, use_regex=regex, limit=limit)


# ── Macro Recorder ────────────────────────────────────────────────────────

@app.post("/api/macro/record/start")
async def macro_record_start() -> dict:
    from macro_recorder import start_recording
    return start_recording()

@app.post("/api/macro/record/stop")
async def macro_record_stop() -> dict:
    from macro_recorder import stop_recording
    return stop_recording()

@app.get("/api/macro/record/status")
async def macro_record_status() -> dict:
    from macro_recorder import get_status
    return get_status()


# ── CSRF Tracker ──────────────────────────────────────────────────────────

@app.get("/api/csrf/tokens")
async def csrf_tokens(host: str | None = None) -> dict:
    from csrf_tracker import get_tokens
    return {"tokens": get_tokens(host)}

@app.post("/api/csrf/toggle")
async def csrf_toggle(body: dict) -> dict:
    from csrf_tracker import toggle
    return toggle(body.get("enabled", True))

@app.delete("/api/csrf/tokens")
async def csrf_clear(host: str | None = None) -> dict:
    from csrf_tracker import clear_tokens
    return {"cleared": clear_tokens(host)}


# ── Scan Comparison ───────────────────────────────────────────────────────

@app.get("/api/scanner/compare/{id_a}/{id_b}")
async def scanner_compare(id_a: str, id_b: str) -> dict:
    from scan_comparison import compare_scans
    return compare_scans(id_a, id_b)


# ── API Documentation Scanner ────────────────────────────────────────────

@app.post("/api/api-docs/probe")
async def api_docs_probe(body: dict) -> dict:
    from api_doc_scanner import probe_api_docs
    url = body.get("url")
    if not url:
        raise HTTPException(400, "url is required")
    return await probe_api_docs(url)

@app.post("/api/api-docs/parse")
async def api_docs_parse(body: dict) -> dict:
    from api_doc_scanner import parse_spec_and_generate_tests
    url = body.get("spec_url")
    if not url:
        raise HTTPException(400, "spec_url is required")
    return await parse_spec_and_generate_tests(url)

@app.post("/api/api-docs/scan")
async def api_docs_scan(body: dict) -> dict:
    from api_doc_scanner import full_scan
    url = body.get("url")
    if not url:
        raise HTTPException(400, "url is required")
    return await full_scan(url)


# ── GraphQL Explorer ─────────────────────────────────────────────────────

@app.post("/api/graphql/introspect")
async def graphql_introspect(body: dict) -> dict:
    from graphql_explorer import introspect
    url = body.get("url")
    if not url:
        raise HTTPException(400, "url is required")
    return await introspect(url, headers=body.get("headers"))

@app.post("/api/graphql/query")
async def graphql_query(body: dict) -> dict:
    from graphql_explorer import execute_query
    url = body.get("url")
    query = body.get("query")
    if not url or not query:
        raise HTTPException(400, "url and query are required")
    return await execute_query(url, query, variables=body.get("variables"), headers=body.get("headers"))

@app.post("/api/graphql/check")
async def graphql_vuln_check(body: dict) -> dict:
    from graphql_explorer import check_vulnerabilities
    url = body.get("url")
    if not url:
        raise HTTPException(400, "url is required")
    findings = await check_vulnerabilities(url, headers=body.get("headers"))
    return {"url": url, "findings": findings, "count": len(findings)}

@app.get("/api/graphql/schema")
async def graphql_schema(url: str) -> dict:
    from graphql_explorer import introspect
    return await introspect(url)


# ── AI-Assisted Analysis ─────────────────────────────────────────────────

@app.post("/api/ai/triage")
async def ai_triage(body: dict) -> dict:
    from ai_analyzer import triage_finding
    return await triage_finding(body.get("finding", body))

@app.post("/api/ai/scope-suggest")
async def ai_scope_suggest() -> dict:
    from ai_analyzer import suggest_scope
    flows = [
        {"host": f.host, "method": f.request.method, "url": f.request.url,
         "status_code": f.response.status_code if f.response else None}
        for f in list(state.flows.values())[-500:]
    ]
    return await suggest_scope(flows)

@app.post("/api/ai/exploit")
async def ai_exploit(body: dict) -> dict:
    from ai_analyzer import generate_exploit
    return await generate_exploit(body.get("finding", body))

@app.post("/api/ai/report")
async def ai_report(body: dict) -> dict:
    from ai_analyzer import generate_report_section
    findings = body.get("findings", [])
    if not findings:
        # Gather from scan jobs
        for job in state.scanner_jobs.values():
            if job.status == "completed":
                findings.extend([f.model_dump() for f in job.findings])
    return await generate_report_section(findings, target=body.get("target", ""))

@app.post("/api/ai/chain")
async def ai_chain_detect(body: dict) -> dict:
    from chain_detector import detect_chains
    scan_ids = body.get("scan_ids")
    findings = body.get("findings")
    return detect_chains(findings=findings, scan_ids=scan_ids)


# ── Real-Time Collaboration ──────────────────────────────────────────────

@app.websocket("/ws/collab")
async def collab_websocket(websocket: WebSocket):
    from collaboration import websocket_handler
    await websocket_handler(websocket)

@app.get("/api/collab/clients")
async def collab_clients() -> dict:
    from collaboration import get_connected_clients, get_client_count
    return {"clients": get_connected_clients(), "count": get_client_count()}


# ── Burp Project Import ──────────────────────────────────────────────────

@app.post("/api/import/burp")
async def import_burp(body: dict) -> dict:
    from burp_importer import import_burp_xml
    xml_content = body.get("xml")
    if not xml_content:
        raise HTTPException(400, "xml content is required")
    return import_burp_xml(xml_content)


# ── Issue Tracker Export ──────────────────────────────────────────────────

@app.post("/api/export/github-issue")
async def export_github_issue(body: dict) -> dict:
    from issue_export import export_to_github, format_github_issue
    finding = body.get("finding")
    repo = body.get("repo")
    token = body.get("token")
    if not finding:
        raise HTTPException(400, "finding is required")
    if not repo or not token:
        # Just format, don't create
        return format_github_issue(finding)
    return await export_to_github(finding, repo, token)

@app.post("/api/export/jira")
async def export_jira_ticket(body: dict) -> dict:
    from issue_export import export_to_jira, format_jira_ticket
    finding = body.get("finding")
    jira_url = body.get("jira_url")
    email = body.get("email")
    api_token = body.get("api_token")
    project_key = body.get("project_key", "SEC")
    if not finding:
        raise HTTPException(400, "finding is required")
    if not jira_url or not email or not api_token:
        return format_jira_ticket(finding, project_key)
    return await export_to_jira(finding, jira_url, email, api_token, project_key)


# ── Web UI ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def web_ui():
    index_path = Path(__file__).parent / "web" / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Proxy Engine</h1><p>Web UI not built yet.</p>")


# ── API Key Middleware ─────────────────────────────────────────────────

@app.middleware("http")
async def api_key_middleware(request, call_next):
    """Optional API key authentication for all /api/ routes."""
    import os
    api_key = os.environ.get("PROXY_API_KEY", "")
    if api_key and request.url.path.startswith("/api/"):
        provided = request.headers.get("x-api-key", "")
        if not provided:
            provided = request.query_params.get("api_key", "")
        if provided and provided != api_key:
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Invalid API key"}, status_code=401)
    return await call_next(request)


# ── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    from extensions import load_all
    load_all()
