"""MCP Server — stdio bridge to the Proxy Engine REST API (all tools)."""

from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = "http://127.0.0.1:8187"

mcp = FastMCP("proxy-engine", instructions="Proxy Engine — intercept, repeat, fuzz, scan, analyze HTTP traffic")

_client: httpx.AsyncClient | None = None


async def client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(base_url=API_BASE, timeout=60.0)
    return _client


async def _get(path: str, params: dict | None = None) -> dict | list:
    c = await client()
    r = await c.get(path, params=params)
    r.raise_for_status()
    return r.json()


async def _post(path: str, data: dict | None = None) -> dict | list:
    c = await client()
    r = await c.post(path, json=data)
    r.raise_for_status()
    return r.json()


async def _put(path: str, data: dict | None = None) -> dict | list:
    c = await client()
    r = await c.put(path, json=data)
    r.raise_for_status()
    return r.json()


async def _patch(path: str, data: dict | None = None) -> dict | list:
    c = await client()
    r = await c.patch(path, json=data)
    r.raise_for_status()
    return r.json()


async def _delete(path: str) -> dict:
    c = await client()
    r = await c.delete(path)
    r.raise_for_status()
    return r.json()


async def _get_text(path: str, params: dict | None = None) -> str:
    c = await client()
    r = await c.get(path, params=params)
    r.raise_for_status()
    return r.text


# ── Status ───────────────────────────────────────────────────────────────

@mcp.tool()
async def proxy_status() -> str:
    """Get proxy engine status: flow count, intercept state, active jobs, scope, passive findings."""
    return json.dumps(await _get("/api/status"), indent=2)


# ── Flows ────────────────────────────────────────────────────────────────

@mcp.tool()
async def proxy_list_flows(
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
    search_body: bool = False,
    search_headers: bool = False,
    search_regex: bool = False,
    scope_only: bool = False,
    filter_expr: str | None = None,
    limit: int = 50,
) -> str:
    """List captured proxy flows. Filter by host, method, status_code, search text. Set search_body/search_headers/search_regex for deep search. filter_expr: boolean expression like 'status_code >= 400 AND NOT host CONTAINS cdn'. Operators: ==, !=, >, <, >=, <=, CONTAINS, MATCHES. Fields: status_code, method, host, path, content_type, length, has_params, url."""
    params: dict = {"limit": limit}
    if host: params["host"] = host
    if method: params["method"] = method
    if status_code: params["status_code"] = status_code
    if search: params["search"] = search
    if search_body: params["search_body"] = "true"
    if search_headers: params["search_headers"] = "true"
    if search_regex: params["search_regex"] = "true"
    if scope_only: params["scope_only"] = "true"
    if filter_expr: params["filter_expr"] = filter_expr
    return json.dumps(await _get("/api/flows", params=params), indent=2)

@mcp.tool()
async def proxy_get_flow(flow_id: str) -> str:
    """Get full request + response details for a specific flow by ID."""
    return json.dumps(await _get(f"/api/flows/{flow_id}"), indent=2)

@mcp.tool()
async def proxy_clear_flows() -> str:
    """Clear all captured flows."""
    return json.dumps(await _delete("/api/flows"))

@mcp.tool()
async def proxy_annotate_flow(flow_id: str, notes: str | None = None, tags: str | None = None, highlight: str | None = None) -> str:
    """Add notes, tags, or highlight color to a flow. Tags as comma-separated string."""
    data: dict = {}
    if notes is not None: data["notes"] = notes
    if tags is not None: data["tags"] = [t.strip() for t in tags.split(",")]
    if highlight is not None: data["highlight"] = highlight
    return json.dumps(await _patch(f"/api/flows/{flow_id}/notes", data))


# ── Intercept ────────────────────────────────────────────────────────────

@mcp.tool()
async def proxy_intercept_on() -> str:
    """Enable intercept mode — holds requests for review before forwarding."""
    return json.dumps(await _post("/api/intercept/enable"))

@mcp.tool()
async def proxy_intercept_off() -> str:
    """Disable intercept mode — releases all pending requests."""
    return json.dumps(await _post("/api/intercept/disable"))

@mcp.tool()
async def proxy_intercept_queue() -> str:
    """Get pending intercepted requests waiting for forward/drop decision."""
    return json.dumps(await _get("/api/intercept/queue"), indent=2)

@mcp.tool()
async def proxy_forward(flow_id: str, method: str | None = None, url: str | None = None, body: str | None = None) -> str:
    """Forward an intercepted request, optionally modifying method/url/body."""
    data = {}
    if method: data["method"] = method
    if url: data["url"] = url
    if body is not None: data["body"] = body
    return json.dumps(await _post(f"/api/intercept/{flow_id}/forward", data if data else None))

@mcp.tool()
async def proxy_drop(flow_id: str) -> str:
    """Drop an intercepted request."""
    return json.dumps(await _post(f"/api/intercept/{flow_id}/drop"))


# ── Scope ────────────────────────────────────────────────────────────────

@mcp.tool()
async def scope_get() -> str:
    """Get current scope configuration (include/exclude patterns)."""
    return json.dumps(await _get("/api/scope"), indent=2)

@mcp.tool()
async def scope_set(enabled: bool, include_patterns: str | None = None, exclude_patterns: str | None = None) -> str:
    """Set scope config. Patterns as comma-separated regex. Target defaults to 'host'."""
    cfg: dict = {"enabled": enabled, "include": [], "exclude": []}
    if include_patterns:
        for p in include_patterns.split(","):
            cfg["include"].append({"pattern": p.strip(), "target": "host", "enabled": True})
    if exclude_patterns:
        for p in exclude_patterns.split(","):
            cfg["exclude"].append({"pattern": p.strip(), "target": "host", "enabled": True})
    return json.dumps(await _put("/api/scope", cfg), indent=2)

@mcp.tool()
async def scope_add(pattern: str, rule_type: str = "include", target: str = "host") -> str:
    """Add a scope include or exclude pattern. rule_type: include/exclude. target: host/url."""
    endpoint = f"/api/scope/{rule_type}"
    return json.dumps(await _post(endpoint, {"pattern": pattern, "target": target, "enabled": True}), indent=2)


# ── Repeater ─────────────────────────────────────────────────────────────

@mcp.tool()
async def repeater_send(url: str, method: str = "GET", headers: str | None = None, body: str | None = None, follow_redirects: bool = False) -> str:
    """Send an HTTP request and get the full response. Headers as JSON object string."""
    data: dict = {"method": method, "url": url, "follow_redirects": follow_redirects}
    if headers:
        try:
            data["headers"] = json.loads(headers)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON for headers parameter"})
    if body is not None: data["body"] = body
    return json.dumps(await _post("/api/repeater/send", data), indent=2)

@mcp.tool()
async def repeater_replay(flow_id: str, method: str | None = None, url: str | None = None, body: str | None = None) -> str:
    """Replay a previously captured flow, optionally modifying method/url/body."""
    data = {}
    if method: data["method"] = method
    if url: data["url"] = url
    if body is not None: data["body"] = body
    return json.dumps(await _post(f"/api/repeater/replay/{flow_id}", data if data else None), indent=2)

@mcp.tool()
async def repeater_history(limit: int = 20) -> str:
    """Get repeater request history."""
    return json.dumps(await _get("/api/repeater/history", {"limit": limit}), indent=2)


# ── Intruder ─────────────────────────────────────────────────────────────

@mcp.tool()
async def intruder_attack(
    url: str, positions: str, payloads: str,
    method: str = "GET", body: str | None = None,
    attack_type: str = "sniper", concurrency: int = 10,
    payload_processing: str | None = None,
    grep_rules: str | None = None,
) -> str:
    """Start a fuzzing attack.
    positions: JSON array of {field, start, end}.
    payloads: JSON array of string arrays. Use @sqli, @xss, @path_traversal, @ssti, @common_passwords, @nosqli, @headers_inject.
    payload_processing: JSON array of {operation, value}. Operations: url_encode, base64_encode, md5_hash, sha256_hash, prefix, suffix, etc.
    grep_rules: JSON array of {pattern, location, negate}. location: body/headers/status."""
    data: dict = {
        "url": url, "method": method,
        "positions": json.loads(positions),
        "payloads": json.loads(payloads),
        "attack_type": attack_type,
        "concurrency": concurrency,
    }
    if body is not None: data["body"] = body
    if payload_processing: data["payload_processing"] = json.loads(payload_processing)
    if grep_rules: data["grep_rules"] = json.loads(grep_rules)
    return json.dumps(await _post("/api/intruder/attack", data), indent=2)

@mcp.tool()
async def intruder_status(job_id: str) -> str:
    """Get intruder attack status and results."""
    return json.dumps(await _get(f"/api/intruder/{job_id}"), indent=2)

@mcp.tool()
async def intruder_cancel(job_id: str) -> str:
    """Cancel a running intruder attack."""
    return json.dumps(await _delete(f"/api/intruder/{job_id}"))

@mcp.tool()
async def intruder_payloads() -> str:
    """List available built-in payload lists and their sizes."""
    return json.dumps(await _get("/api/intruder/payloads/list"), indent=2)

@mcp.tool()
async def intruder_attack_flow(
    flow_id: str,
    attack_type: str = "sniper",
    payloads: str | None = None,
    concurrency: int = 10,
) -> str:
    """Launch an intruder attack from a captured flow — auto-extracts all insertion points and assigns smart default payloads per parameter type. payloads: optional JSON array of string arrays to override defaults. Use @sqli, @xss, etc."""
    data: dict = {"flow_id": flow_id, "attack_type": attack_type, "concurrency": concurrency}
    if payloads:
        data["payloads"] = json.loads(payloads)
    return json.dumps(await _post("/api/intruder/attack-flow", data), indent=2)

@mcp.tool()
async def intruder_export(job_id: str, format: str = "csv") -> str:
    """Export intruder attack results. Formats: csv, json."""
    return await _get_text(f"/api/intruder/{job_id}/export", {"format": format})

@mcp.tool()
async def intruder_timing(job_id: str) -> str:
    """Get timing analysis for intruder attack — min/max/avg/p50/p95/p99/std_dev and anomalies."""
    return json.dumps(await _get(f"/api/intruder/{job_id}/timing"), indent=2)

@mcp.tool()
async def intruder_cluster(job_id: str) -> str:
    """Cluster intruder results by response similarity — identifies anomalies and interesting responses."""
    return json.dumps(await _get(f"/api/intruder/{job_id}/cluster"), indent=2)


# ── Scanner ──────────────────────────────────────────────────────────────

@mcp.tool()
async def scanner_scan(urls: str, templates: str | None = None, custom_checks: str | None = None, severity: str | None = None) -> str:
    """Start a vulnerability scan. URLs comma-separated. Custom checks: sqli, xss, open_redirect, ssrf, crlf, timing_sqli, header_injection, path_traversal, ssti, command_injection, verb_tampering, web_cache_deception, cors, prototype_pollution, dom_xss."""
    data: dict = {"urls": [u.strip() for u in urls.split(",")]}
    if templates: data["templates"] = [t.strip() for t in templates.split(",")]
    if custom_checks: data["custom_checks"] = [c.strip() for c in custom_checks.split(",")]
    if severity: data["severity"] = severity
    return json.dumps(await _post("/api/scanner/scan", data), indent=2)

@mcp.tool()
async def scanner_results(scan_id: str) -> str:
    """Get scan results by scan ID."""
    return json.dumps(await _get(f"/api/scanner/{scan_id}"), indent=2)


@mcp.tool()
async def scanner_scan_flow(flow_id: str, checks: str | None = None) -> str:
    """Scan a captured flow — auto-extracts all insertion points (URL params, body params, JSON keys, cookies, headers) and tests each one.
    checks: comma-separated list of check types (sqli, xss, ssti, path_traversal, command_injection). Default: all."""
    data: dict = {"flow_id": flow_id}
    if checks:
        data["checks"] = [c.strip() for c in checks.split(",")]
    return json.dumps(await _post("/api/scanner/scan-flow", data), indent=2)


@mcp.tool()
async def scanner_insertion_points(flow_id: str) -> str:
    """Extract all insertion points from a captured flow — shows every injectable parameter (URL params, body params, JSON keys, XML nodes, cookies, headers, path segments, multipart fields)."""
    return json.dumps(await _post("/api/scanner/insertion-points", {"flow_id": flow_id}), indent=2)

@mcp.tool()
async def scanner_browser_scan(url: str, checks: str | None = None) -> str:
    """Run browser-powered scans (DOM XSS, client template injection, stored XSS confirmation, open redirect). checks: comma-separated, default all."""
    data: dict = {"url": url}
    if checks:
        data["checks"] = [c.strip() for c in checks.split(",")]
    return json.dumps(await _post("/api/scanner/browser-scan", data), indent=2)

@mcp.tool()
async def scanner_incremental_scan(urls: str, custom_checks: str | None = None) -> str:
    """Run incremental scan — skips already-scanned URLs. URLs comma-separated."""
    data: dict = {"urls": [u.strip() for u in urls.split(",")]}
    if custom_checks:
        data["custom_checks"] = [c.strip() for c in custom_checks.split(",")]
    return json.dumps(await _post("/api/scanner/incremental-scan", data), indent=2)


# ── Passive Scanner ─────────────────────────────────────────────────────

@mcp.tool()
async def passive_findings() -> str:
    """Get passive scanner findings (missing headers, info disclosure, cookie issues, CORS, sensitive data, CSP)."""
    return json.dumps(await _get("/api/passive"), indent=2)

@mcp.tool()
async def passive_toggle(enabled: bool) -> str:
    """Enable or disable the passive scanner."""
    return json.dumps(await _post("/api/passive/toggle", {"enabled": enabled}))

@mcp.tool()
async def passive_clear() -> str:
    """Clear all passive scanner findings."""
    return json.dumps(await _delete("/api/passive"))

@mcp.tool()
async def passive_load_rules(path: str) -> str:
    """Load custom passive scanner rules from a YAML or JSON file."""
    return json.dumps(await _post("/api/passive/rules/load", {"path": path}))

@mcp.tool()
async def passive_set_severity(check_id: str, severity: str) -> str:
    """Override severity for a passive scanner check. Severity: critical, high, medium, low, info."""
    return json.dumps(await _put(f"/api/passive/rules/{check_id}/severity", {"severity": severity}))

@mcp.tool()
async def passive_mark_fp(index: int, reason: str = "") -> str:
    """Mark a passive finding as false positive."""
    return json.dumps(await _post(f"/api/passive/{index}/false-positive", {"reason": reason}))


# ── Sitemap ──────────────────────────────────────────────────────────────

@mcp.tool()
async def sitemap_get(host: str | None = None) -> str:
    """Get the site tree from captured flows. Optionally filter by host."""
    if host:
        return json.dumps(await _get(f"/api/sitemap/{host}"), indent=2)
    return json.dumps(await _get("/api/sitemap"), indent=2)

@mcp.tool()
async def sitemap_add_to_scope(host: str) -> str:
    """Add a host from the sitemap to the scope."""
    return json.dumps(await _post(f"/api/sitemap/{host}/add-to-scope"))


# ── Comparer ─────────────────────────────────────────────────────────────

@mcp.tool()
async def comparer_diff(left_flow_id: str | None = None, right_flow_id: str | None = None, left_content: str | None = None, right_content: str | None = None) -> str:
    """Diff two responses. Provide flow IDs or raw content."""
    data = {}
    if left_flow_id: data["left_flow_id"] = left_flow_id
    if right_flow_id: data["right_flow_id"] = right_flow_id
    if left_content is not None: data["left_content"] = left_content
    if right_content is not None: data["right_content"] = right_content
    return json.dumps(await _post("/api/comparer/diff", data), indent=2)


# ── Decoder ──────────────────────────────────────────────────────────────

@mcp.tool()
async def decoder_encode(text: str, operation: str = "base64") -> str:
    """Encode text. Operations: base64, url, hex, html, unicode_escape."""
    return json.dumps(await _post("/api/decoder/encode", {"text": text, "operation": operation}))

@mcp.tool()
async def decoder_decode(text: str, operation: str = "base64") -> str:
    """Decode text. Operations: base64, url, hex, html, jwt_decode, unicode_escape."""
    return json.dumps(await _post("/api/decoder/decode", {"text": text, "operation": operation}))


# ── Collaborator ─────────────────────────────────────────────────────────

@mcp.tool()
async def collaborator_start(domain: str = "collab.localhost", dns_port: int = 5354, http_port: int = 9999, smtp_port: int = 2525) -> str:
    """Start self-hosted OOB interaction detection servers (DNS, HTTP, SMTP)."""
    return json.dumps(await _post("/api/collaborator/start", {"domain": domain, "dns_port": dns_port, "http_port": http_port, "smtp_port": smtp_port}), indent=2)

@mcp.tool()
async def collaborator_stop() -> str:
    """Stop OOB interaction detection servers."""
    return json.dumps(await _post("/api/collaborator/stop"))

@mcp.tool()
async def collaborator_generate(context: str = "") -> str:
    """Generate a unique OAST payload for out-of-band interaction detection. Context helps correlate with specific tests."""
    return json.dumps(await _post("/api/collaborator/generate", {"context": context}), indent=2)

@mcp.tool()
async def collaborator_poll(correlation_id: str | None = None) -> str:
    """Poll for out-of-band interactions (DNS, HTTP, SMTP). Filter by correlation_id."""
    params = {}
    if correlation_id: params["correlation_id"] = correlation_id
    return json.dumps(await _get("/api/collaborator/poll", params=params if params else None), indent=2)

@mcp.tool()
async def collaborator_interactions(correlation_id: str | None = None) -> str:
    """Get all collaborator interactions. Filter by correlation_id."""
    params = {}
    if correlation_id: params["correlation_id"] = correlation_id
    return json.dumps(await _get("/api/collaborator/interactions", params=params if params else None), indent=2)


# ── Sequencer ────────────────────────────────────────────────────────────

@mcp.tool()
async def sequencer_start(url: str, token_location: str = "header", token_name: str = "", method: str = "GET", headers: str | None = None, body: str | None = None, sample_count: int = 100) -> str:
    """Start token entropy analysis. Collects tokens from repeated requests.
    token_location: header, cookie, or body_regex. token_name: header/cookie name or regex with capture group."""
    data: dict = {
        "url": url, "method": method, "token_location": token_location,
        "token_name": token_name, "sample_count": sample_count,
    }
    if headers: data["headers"] = json.loads(headers)
    if body is not None: data["body"] = body
    return json.dumps(await _post("/api/sequencer/start", data), indent=2)

@mcp.tool()
async def sequencer_results(job_id: str) -> str:
    """Get sequencer entropy analysis results."""
    return json.dumps(await _get(f"/api/sequencer/{job_id}"), indent=2)


# ── Export ───────────────────────────────────────────────────────────────

@mcp.tool()
async def export_flow(flow_id: str, format: str = "curl") -> str:
    """Export a flow as curl, raw HTTP, python requests code, or HAR. Formats: curl, raw, python, har."""
    return await _get_text(f"/api/export/{flow_id}", {"format": format})

@mcp.tool()
async def export_flows(flow_ids: str | None = None, format: str = "har") -> str:
    """Export multiple flows. flow_ids as comma-separated IDs, or omit for all. Formats: curl, raw, python, har."""
    data: dict = {"format": format}
    if flow_ids:
        data["flow_ids"] = [f.strip() for f in flow_ids.split(",")]
    c = await client()
    r = await c.post("/api/export", json=data)
    r.raise_for_status()
    return r.text

@mcp.tool()
async def export_openapi(host: str = "") -> str:
    """Generate OpenAPI 3.0 spec from captured proxy flows. Filter by host."""
    return json.dumps(await _post("/api/export/openapi", {"host": host}), indent=2)

@mcp.tool()
async def export_postman(flow_ids: str | None = None) -> str:
    """Export flows as Postman Collection v2.1. flow_ids: comma-separated, or omit for all."""
    data: dict = {}
    if flow_ids:
        data["flow_ids"] = [f.strip() for f in flow_ids.split(",")]
    return json.dumps(await _post("/api/export/postman", data), indent=2)

@mcp.tool()
async def export_nuclei_template(scan_id: str, finding_index: int = 0) -> str:
    """Generate a nuclei YAML template from a scan finding for automated retesting."""
    c = await client()
    r = await c.post("/api/export/nuclei-template", json={"scan_id": scan_id, "finding_index": finding_index})
    r.raise_for_status()
    return r.text


# ── Session Handler ──────────────────────────────────────────────────────

@mcp.tool()
async def session_rules() -> str:
    """Get session handling rules (auto-refresh tokens, login macros)."""
    return json.dumps(await _get("/api/sessions/rules"), indent=2)

@mcp.tool()
async def session_add_rule(
    name: str, scope_pattern: str = ".*",
    trigger: str = "status_403",
    macro_url: str = "", macro_method: str = "POST",
    macro_headers: str | None = None, macro_body: str | None = None,
    extract_from: str = "header", extract_name: str = "",
    inject_as: str = "header", inject_name: str = "",
) -> str:
    """Add a session handling rule. Trigger: status_401, status_403, regex:<pattern>.
    Extract from: header, cookie, body_regex. Inject as: header, cookie."""
    data: dict = {
        "name": name, "scope_pattern": scope_pattern, "trigger": trigger,
        "macro_method": macro_method, "macro_url": macro_url,
        "extract_from": extract_from, "extract_name": extract_name,
        "inject_as": inject_as, "inject_name": inject_name,
    }
    if macro_headers: data["macro_headers"] = json.loads(macro_headers)
    if macro_body is not None: data["macro_body"] = macro_body
    return json.dumps(await _post("/api/sessions/rules", data), indent=2)


# ── Macro Chains ─────────────────────────────────────────────────────────

@mcp.tool()
async def session_chains_list() -> str:
    """List all macro chains (multi-step authentication sequences with variable extraction)."""
    return json.dumps(await _get("/api/sessions/chains"), indent=2)

@mcp.tool()
async def session_chain_add(
    name: str, steps: str,
    trigger: str = "manual",
    final_inject_as: str = "header",
    final_extract_var: str = "",
) -> str:
    """Add a multi-step macro chain. steps: JSON array of {method, url, headers, body, extract_from, extract_name, extract_var}. URLs/bodies support {{var_name}} substitution from previous steps. trigger: manual, status_401, status_403."""
    data = {
        "name": name,
        "steps": json.loads(steps),
        "trigger": trigger,
        "final_inject_as": final_inject_as,
        "final_extract_var": final_extract_var,
    }
    return json.dumps(await _post("/api/sessions/chains", data), indent=2)

@mcp.tool()
async def session_chain_remove(index: int) -> str:
    """Remove a macro chain by index."""
    return json.dumps(await _delete(f"/api/sessions/chains/{index}"))

@mcp.tool()
async def session_chain_execute(index: int) -> str:
    """Execute a macro chain by index — runs all steps, extracts variables, returns results."""
    return json.dumps(await _post(f"/api/sessions/chains/{index}/execute"), indent=2)


# ── WebSocket ────────────────────────────────────────────────────────────

@mcp.tool()
async def websocket_messages(flow_id: str | None = None, limit: int = 50) -> str:
    """Get captured WebSocket messages. Optionally filter by flow_id."""
    params: dict = {"limit": limit}
    if flow_id: params["flow_id"] = flow_id
    return json.dumps(await _get("/api/websocket/messages", params=params), indent=2)

@mcp.tool()
async def websocket_intercept_on() -> str:
    """Enable WebSocket message interception — hold WS messages for review before forwarding."""
    return json.dumps(await _post("/api/websocket/intercept/enable"))

@mcp.tool()
async def websocket_intercept_off() -> str:
    """Disable WebSocket message interception."""
    return json.dumps(await _post("/api/websocket/intercept/disable"))

@mcp.tool()
async def websocket_intercept_queue() -> str:
    """Get pending intercepted WebSocket messages waiting for forward/drop decision."""
    return json.dumps(await _get("/api/websocket/intercept/queue"), indent=2)

@mcp.tool()
async def websocket_intercept_forward(msg_id: str, content: str | None = None) -> str:
    """Forward an intercepted WebSocket message, optionally modifying its content."""
    data = {}
    if content is not None:
        data["content"] = content
    return json.dumps(await _post(f"/api/websocket/intercept/{msg_id}/forward", data if data else None))

@mcp.tool()
async def websocket_intercept_drop(msg_id: str) -> str:
    """Drop an intercepted WebSocket message."""
    return json.dumps(await _post(f"/api/websocket/intercept/{msg_id}/drop"))

@mcp.tool()
async def websocket_send(flow_id: str, content: str, is_text: bool = True) -> str:
    """Inject a WebSocket message into a flow for testing."""
    return json.dumps(await _post(f"/api/websocket/send/{flow_id}", {"content": content, "is_text": is_text}))


# ── Extensions ───────────────────────────────────────────────────────────

@mcp.tool()
async def extensions_list() -> str:
    """List loaded extensions/plugins."""
    return json.dumps(await _get("/api/extensions"), indent=2)

@mcp.tool()
async def extensions_reload() -> str:
    """Reload all extensions from the extensions/ directory."""
    return json.dumps(await _post("/api/extensions/reload"))


# ── CA Cert ──────────────────────────────────────────────────────────────

@mcp.tool()
async def ca_cert_info() -> str:
    """Get mitmproxy CA certificate info and install instructions for HTTPS interception."""
    return json.dumps(await _get("/api/ca-cert"), indent=2)


# ── Match & Replace ─────────────────────────────────────────────────────

@mcp.tool()
async def match_replace_list() -> str:
    """List all match & replace rules (auto-modify requests/responses)."""
    return json.dumps(await _get("/api/match-replace"), indent=2)

@mcp.tool()
async def match_replace_add(
    name: str, match: str, replace: str,
    phase: str = "request", target: str = "header",
    target_name: str = "", is_regex: bool = False,
) -> str:
    """Add a match & replace rule. Phase: request/response/both. Target: url/method/header/body/add_header/remove_header."""
    data = {
        "name": name, "match": match, "replace": replace,
        "phase": phase, "target": target, "target_name": target_name,
        "is_regex": is_regex, "enabled": True,
    }
    return json.dumps(await _post("/api/match-replace", data), indent=2)

@mcp.tool()
async def match_replace_remove(index: int) -> str:
    """Remove a match & replace rule by index."""
    return json.dumps(await _delete(f"/api/match-replace/{index}"))


# ── Response Intercept ──────────────────────────────────────────────────

@mcp.tool()
async def response_intercept_on() -> str:
    """Enable response interception — hold responses for modification before browser receives them."""
    return json.dumps(await _post("/api/intercept/response/enable"))

@mcp.tool()
async def response_intercept_off() -> str:
    """Disable response interception."""
    return json.dumps(await _post("/api/intercept/response/disable"))

@mcp.tool()
async def response_intercept_queue() -> str:
    """Get pending intercepted responses waiting for modification."""
    return json.dumps(await _get("/api/intercept/response/queue"), indent=2)

@mcp.tool()
async def response_intercept_forward(flow_id: str, body: str | None = None) -> str:
    """Forward an intercepted response, optionally modifying the body."""
    data = {}
    if body is not None:
        data["body"] = body
    return json.dumps(await _post(f"/api/intercept/response/{flow_id}/forward", data if data else None))


# ── Crawler ─────────────────────────────────────────────────────────────

@mcp.tool()
async def crawler_start(
    url: str, max_depth: int = 3, concurrency: int = 5,
    js_render: bool = False, submit_forms: bool = False,
    login_url: str | None = None, login_credentials: str | None = None,
) -> str:
    """Start crawling a target URL to discover endpoints, forms, and parameters.
    js_render: Playwright-based JS-aware crawling for SPAs.
    submit_forms: auto-submit forms with smart default values.
    login_url: URL of login page for authenticated crawling.
    login_credentials: JSON object like {"username": "user", "password": "pass"}."""
    data: dict = {"url": url, "max_depth": max_depth, "concurrency": concurrency,
                  "js_render": js_render, "submit_forms": submit_forms}
    if login_url:
        data["login_url"] = login_url
    if login_credentials:
        data["login_credentials"] = json.loads(login_credentials)
    return json.dumps(await _post("/api/crawler/start", data), indent=2)

@mcp.tool()
async def crawler_status(job_id: str) -> str:
    """Get crawler job status and discovered URLs."""
    return json.dumps(await _get(f"/api/crawler/{job_id}"), indent=2)

@mcp.tool()
async def crawler_cancel(job_id: str) -> str:
    """Cancel a running crawl job."""
    return json.dumps(await _delete(f"/api/crawler/{job_id}"))


# ── Content Discovery ───────────────────────────────────────────────────

@mcp.tool()
async def discovery_start(url: str, wordlist: str = "@common", extensions: str = "", concurrency: int = 20, recursive: bool = False, smart_wordlist: bool = False) -> str:
    """Start directory brute-force. Wordlists: @common, @api_endpoints, @backup_files, @common_params. Extensions comma-separated. recursive: follow found dirs. smart_wordlist: generate from captured flows."""
    data: dict = {"url": url, "wordlist": wordlist, "concurrency": concurrency, "recursive": recursive, "smart_wordlist": smart_wordlist}
    if extensions:
        data["extensions"] = [e.strip() for e in extensions.split(",")]
    return json.dumps(await _post("/api/discovery/start", data), indent=2)

@mcp.tool()
async def discovery_status(job_id: str) -> str:
    """Get content discovery job status and found paths."""
    return json.dumps(await _get(f"/api/discovery/{job_id}"), indent=2)

@mcp.tool()
async def discovery_cancel(job_id: str) -> str:
    """Cancel a running discovery job."""
    return json.dumps(await _delete(f"/api/discovery/{job_id}"))

@mcp.tool()
async def discovery_wordlists() -> str:
    """List available built-in wordlists for content discovery."""
    return json.dumps(await _get("/api/discovery/wordlists"), indent=2)

@mcp.tool()
async def discovery_params(url: str, wordlist: str = "@common_params", method: str = "GET") -> str:
    """Discover valid parameters by fuzzing. Tests GET/POST params and detects valid ones by response diff."""
    return json.dumps(await _post("/api/discovery/params", {"url": url, "wordlist": wordlist, "method": method}), indent=2)


# ── Project Persistence ─────────────────────────────────────────────────

@mcp.tool()
async def project_save(name: str | None = None) -> str:
    """Save current state (flows, findings, rules) to a project file."""
    data = {"name": name} if name else {}
    return json.dumps(await _post("/api/project/save", data if data else None), indent=2)

@mcp.tool()
async def project_load(name: str) -> str:
    """Load a previously saved project."""
    return json.dumps(await _post("/api/project/load", {"name": name}), indent=2)

@mcp.tool()
async def project_list() -> str:
    """List all saved projects."""
    return json.dumps(await _get("/api/project/list"), indent=2)


# ── Target Analysis ─────────────────────────────────────────────────────

@mcp.tool()
async def target_analysis(host: str | None = None) -> str:
    """Analyze a target host — discovered technologies, parameters, endpoints, cookies. Omit host for all."""
    if host:
        return json.dumps(await _get(f"/api/target/analysis/{host}"), indent=2)
    return json.dumps(await _get("/api/target/analysis"), indent=2)


# ── TLS Pass-through ────────────────────────────────────────────────────

@mcp.tool()
async def tls_passthrough_list() -> str:
    """List domains that bypass TLS interception (banking, etc.)."""
    return json.dumps(await _get("/api/tls-passthrough"), indent=2)

@mcp.tool()
async def tls_passthrough_add(pattern: str) -> str:
    """Add a domain pattern to TLS pass-through list (regex)."""
    return json.dumps(await _post("/api/tls-passthrough", {"pattern": pattern}), indent=2)


# ── Scan Profiles ───────────────────────────────────────────────────────

@mcp.tool()
async def scanner_profiles() -> str:
    """List available scan profiles (fast, thorough, passive_only, api, custom)."""
    return json.dumps(await _get("/api/scanner/profiles"), indent=2)


# ── Report Generator ───────────────────────────────────────────────────

@mcp.tool()
async def report_generate(scan_id: str | None = None, target: str = "", title: str = "Vulnerability Scan Report", format: str = "html", include_passive: bool = True) -> str:
    """Generate a vulnerability report. Formats: html, json, xml, csv, markdown, pdf. Returns file path or content."""
    data: dict = {"target": target, "title": title, "format": format, "include_passive": include_passive}
    if scan_id:
        data["scan_id"] = scan_id
    return json.dumps(await _post("/api/report/generate", data), indent=2)

@mcp.tool()
async def report_executive_summary(scan_id: str | None = None) -> str:
    """Generate executive summary with risk score 0-100, top risks, and priorities."""
    params = {}
    if scan_id: params["scan_id"] = scan_id
    return json.dumps(await _get("/api/report/executive-summary", params=params if params else None), indent=2)

@mcp.tool()
async def report_compliance(scan_id: str) -> str:
    """Generate compliance mapping (PCI-DSS, NIST 800-53, OWASP ASVS) for scan findings."""
    return json.dumps(await _get(f"/api/report/compliance/{scan_id}"), indent=2)


# ── Cookie Jar ───────────────────────────────────────────────────────────

@mcp.tool()
async def cookie_jar_get(domain: str | None = None) -> str:
    """Get all cookies from the global cookie jar. Optionally filter by domain."""
    params = {}
    if domain:
        params["domain"] = domain
    return json.dumps(await _get("/api/cookie-jar", params=params if params else None), indent=2)

@mcp.tool()
async def cookie_jar_set(domain: str, name: str, value: str, path: str = "/", secure: bool = False, httponly: bool = False) -> str:
    """Set a cookie in the global cookie jar. Cookies are automatically injected into matching requests."""
    data = {"domain": domain, "name": name, "value": value, "path": path, "secure": secure, "httponly": httponly}
    return json.dumps(await _post("/api/cookie-jar", data))

@mcp.tool()
async def cookie_jar_clear(domain: str | None = None) -> str:
    """Clear all cookies, or only cookies for a specific domain."""
    c = await client()
    params = {}
    if domain:
        params["domain"] = domain
    r = await c.delete("/api/cookie-jar", params=params)
    r.raise_for_status()
    return json.dumps(r.json())


# ── Organizer ────────────────────────────────────────────────────────────

@mcp.tool()
async def organizer_list(category: str | None = None, status: str | None = None, tag: str | None = None) -> str:
    """List organizer items (manual testing notebook). Filter by category (vulnerability/interesting/todo/note), status (open/confirmed/false_positive/fixed), or tag."""
    params = {}
    if category: params["category"] = category
    if status: params["status"] = status
    if tag: params["tag"] = tag
    return json.dumps(await _get("/api/organizer", params=params if params else None), indent=2)

@mcp.tool()
async def organizer_create(
    title: str,
    category: str = "note",
    severity: str = "",
    description: str = "",
    tags: str | None = None,
    status: str = "open",
) -> str:
    """Create an organizer item. Category: vulnerability, interesting, todo, note. Severity: critical, high, medium, low, info. Tags: comma-separated."""
    data: dict = {"title": title, "category": category, "severity": severity, "description": description, "status": status}
    if tags:
        data["tags"] = [t.strip() for t in tags.split(",")]
    return json.dumps(await _post("/api/organizer", data), indent=2)

@mcp.tool()
async def organizer_update(item_id: str, title: str | None = None, category: str | None = None, severity: str | None = None, description: str | None = None, status: str | None = None) -> str:
    """Update an organizer item's fields."""
    data = {}
    if title is not None: data["title"] = title
    if category is not None: data["category"] = category
    if severity is not None: data["severity"] = severity
    if description is not None: data["description"] = description
    if status is not None: data["status"] = status
    return json.dumps(await _patch(f"/api/organizer/{item_id}", data), indent=2)

@mcp.tool()
async def organizer_delete(item_id: str) -> str:
    """Delete an organizer item."""
    return json.dumps(await _delete(f"/api/organizer/{item_id}"))

@mcp.tool()
async def organizer_link_flow(item_id: str, flow_id: str) -> str:
    """Link a captured flow to an organizer item for cross-referencing."""
    return json.dumps(await _post(f"/api/organizer/{item_id}/link-flow", {"flow_id": flow_id}), indent=2)

@mcp.tool()
async def organizer_link_finding(item_id: str, finding_id: str) -> str:
    """Link a scanner/passive finding to an organizer item."""
    return json.dumps(await _post(f"/api/organizer/{item_id}/link-finding", {"finding_id": finding_id}), indent=2)


# ── OpenAPI Import ───────────────────────────────────────────────────────

@mcp.tool()
async def import_openapi(spec: str, base_url: str = "") -> str:
    """Import an OpenAPI/Swagger spec — extract endpoints, parameters, scope rules. spec: JSON string of the spec."""
    try:
        spec_data = json.loads(spec)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON for spec parameter"})
    return json.dumps(await _post("/api/import/openapi", {"spec": spec_data}), indent=2)


# ── HTTP Logger ─────────────────────────────────────────────────────────

@mcp.tool()
async def http_logger(source: str | None = None, limit: int = 100) -> str:
    """Get HTTP request/response log entries from repeater, intruder, scanner. Filter by source."""
    params: dict = {"limit": limit}
    if source: params["source"] = source
    return json.dumps(await _get("/api/logger", params=params), indent=2)

@mcp.tool()
async def http_logger_toggle(enabled: bool) -> str:
    """Enable or disable the HTTP traffic logger."""
    return json.dumps(await _post("/api/logger/toggle", {"enabled": enabled}))


# ── Mobile Proxy Config ────────────────────────────────────────────────

@mcp.tool()
async def mobile_proxy_config(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> str:
    """Get mobile device proxy configuration — PAC file URL, QR code for setup, iOS profile download."""
    qr = await _get("/api/mobile/qr", {"proxy_host": proxy_host, "proxy_port": proxy_port})
    return json.dumps({
        "pac_url": f"http://{proxy_host}:8187/api/mobile/pac?proxy_host={proxy_host}&proxy_port={proxy_port}",
        "ios_profile_url": f"http://{proxy_host}:8187/api/mobile/ios-profile?proxy_host={proxy_host}&proxy_port={proxy_port}",
        "qr_base64": qr.get("qr_base64", ""),
        "proxy": f"{proxy_host}:{proxy_port}",
    }, indent=2)


# ── Dashboard ────────────────────────────────────────────────────────────

@mcp.tool()
async def proxy_dashboard() -> str:
    """Get aggregated dashboard overview: flow count + rate, active/completed scans with finding counts by severity, intruder jobs, crawl progress, passive findings by severity, scope status, WebSocket stats, cookies, organizer items."""
    return json.dumps(await _get("/api/dashboard"), indent=2)


# ── Live Audit ──────────────────────────────────────────────────────────

@mcp.tool()
async def live_audit_toggle(enabled: bool) -> str:
    """Enable or disable live audit — automatically scans flows as they pass through the proxy."""
    return json.dumps(await _post("/api/live-audit/toggle", {"enabled": enabled}))

@mcp.tool()
async def live_audit_findings(severity: str | None = None, limit: int = 100) -> str:
    """Get live audit findings (auto-detected vulnerabilities from proxied traffic)."""
    params: dict = {"limit": limit}
    if severity:
        params["severity"] = severity
    return json.dumps(await _get("/api/live-audit/findings", params=params), indent=2)

@mcp.tool()
async def live_audit_config(checks: list[str] | None = None, severity: str | None = None, rate: float | None = None) -> str:
    """Configure live audit — set which checks to run, severity threshold, and rate limit."""
    body: dict = {}
    if checks is not None:
        body["checks"] = checks
    if severity is not None:
        body["severity"] = severity
    if rate is not None:
        body["rate"] = rate
    return json.dumps(await _put("/api/live-audit/config", body))

@mcp.tool()
async def live_audit_clear() -> str:
    """Clear all live audit findings."""
    return json.dumps(await _delete("/api/live-audit/findings"))


# ── Scanner Templates ───────────────────────────────────────────────────

@mcp.tool()
async def scanner_templates() -> str:
    """Get nuclei template index stats — template count by category and severity."""
    return json.dumps(await _get("/api/scanner/templates"), indent=2)

@mcp.tool()
async def scanner_templates_reload() -> str:
    """Rebuild nuclei template index from disk."""
    return json.dumps(await _post("/api/scanner/templates/reload"))


# ── CI/CD Integration ───────────────────────────────────────────────────

@mcp.tool()
async def ci_scan(urls: list[str], checks: list[str] | None = None, profile: str | None = None) -> str:
    """Run a synchronous scan (CI/CD mode) — waits for completion and returns all findings."""
    body: dict = {"urls": urls}
    if checks:
        body["checks"] = checks
    if profile:
        body["profile"] = profile
    return json.dumps(await _post("/api/ci/scan", body), indent=2)

@mcp.tool()
async def ci_findings_sarif(scan_id: str) -> str:
    """Get scan findings in SARIF format for GitHub/GitLab CI integration."""
    return json.dumps(await _get(f"/api/ci/findings/{scan_id}", {"format": "sarif"}), indent=2)


# ── Schedule Management ─────────────────────────────────────────────────

@mcp.tool()
async def schedule_create(
    name: str, urls: list[str], cron: str = "", interval_minutes: int = 60,
    checks: list[str] | None = None, webhook_url: str = "",
) -> str:
    """Create a scheduled scan — cron expression or interval-based."""
    body: dict = {"name": name, "urls": urls, "cron_expr": cron, "interval_minutes": interval_minutes, "webhook_url": webhook_url}
    if checks:
        body["checks"] = checks
    return json.dumps(await _post("/api/schedule", body), indent=2)

@mcp.tool()
async def schedule_list() -> str:
    """List all scheduled scans."""
    return json.dumps(await _get("/api/schedule"), indent=2)


# ── Global Search ─────────────────────────────────────────────────────────

@mcp.tool()
async def search(query: str, scope: str = "all", regex: bool = False) -> str:
    """Search across all flows, scan findings, and passive findings. Scope: all, flows, findings, passive."""
    params: dict = {"q": query, "scope": scope, "regex": str(regex).lower()}
    return json.dumps(await _get("/api/search", params=params), indent=2)


# ── GraphQL ──────────────────────────────────────────────────────────────

@mcp.tool()
async def graphql_introspect(url: str, headers: str = "{}") -> str:
    """Run GraphQL introspection query against a target URL. Returns schema types, queries, mutations."""
    data: dict = {"url": url, "headers": json.loads(headers)}
    return json.dumps(await _post("/api/graphql/introspect", data), indent=2)

@mcp.tool()
async def graphql_query(url: str, query: str, variables: str = "{}", headers: str = "{}") -> str:
    """Execute a GraphQL query against a target. variables/headers: JSON strings."""
    data: dict = {"url": url, "query": query, "variables": json.loads(variables), "headers": json.loads(headers)}
    return json.dumps(await _post("/api/graphql/query", data), indent=2)

@mcp.tool()
async def graphql_vulncheck(url: str, headers: str = "{}") -> str:
    """Check a GraphQL endpoint for vulnerabilities — introspection exposure, batching, depth limit, alias abuse."""
    data: dict = {"url": url, "headers": json.loads(headers)}
    return json.dumps(await _post("/api/graphql/check", data), indent=2)


# ── AI Analysis ──────────────────────────────────────────────────────────

@mcp.tool()
async def ai_triage(finding_json: str) -> str:
    """AI-powered finding triage — classifies severity, exploitability, business impact. Pass finding as JSON string."""
    return json.dumps(await _post("/api/ai/triage", {"finding": json.loads(finding_json)}), indent=2)

@mcp.tool()
async def ai_suggest_scope() -> str:
    """AI-powered scope suggestion — analyzes traffic patterns and suggests include/exclude rules."""
    return json.dumps(await _post("/api/ai/scope-suggest"), indent=2)

@mcp.tool()
async def ai_generate_exploit(finding_json: str) -> str:
    """Generate a Python exploit/PoC script from a vulnerability finding."""
    return json.dumps(await _post("/api/ai/exploit", {"finding": json.loads(finding_json)}), indent=2)

@mcp.tool()
async def ai_generate_report(finding_json: str) -> str:
    """Generate a narrative report section with context for a vulnerability finding."""
    return json.dumps(await _post("/api/ai/report", {"finding": json.loads(finding_json)}), indent=2)

@mcp.tool()
async def ai_detect_chains() -> str:
    """Detect multi-step vulnerability chains — e.g., Open Redirect + XSS, SSRF + metadata, IDOR + PII."""
    return json.dumps(await _post("/api/ai/chain"), indent=2)


# ── Macro Recorder ───────────────────────────────────────────────────────

@mcp.tool()
async def macro_start_recording() -> str:
    """Start recording a macro — captures flow sequence for session handling or replay."""
    return json.dumps(await _post("/api/macro/record/start"))

@mcp.tool()
async def macro_stop_recording() -> str:
    """Stop recording and return the captured macro chain with auto-detected extraction rules."""
    return json.dumps(await _post("/api/macro/record/stop"), indent=2)

@mcp.tool()
async def macro_recording_status() -> str:
    """Check if macro recording is active and how many flows have been captured."""
    return json.dumps(await _get("/api/macro/record/status"))


# ── Scan Comparison ──────────────────────────────────────────────────────

@mcp.tool()
async def scan_compare(scan_id_a: str, scan_id_b: str) -> str:
    """Compare two scans — shows new, resolved, changed, and unchanged findings."""
    return json.dumps(await _get(f"/api/scanner/compare/{scan_id_a}/{scan_id_b}"), indent=2)


# ── CSRF Tracking ───────────────────────────────────────────────────────

@mcp.tool()
async def csrf_tokens(host: str | None = None) -> str:
    """Get all auto-detected CSRF tokens. Optionally filter by host."""
    params = {}
    if host: params["host"] = host
    return json.dumps(await _get("/api/csrf/tokens", params=params if params else None), indent=2)

@mcp.tool()
async def csrf_toggle(enabled: bool) -> str:
    """Enable or disable automatic CSRF token tracking and injection."""
    return json.dumps(await _post("/api/csrf/toggle", {"enabled": enabled}))


# ── Burp Import ─────────────────────────────────────────────────────────

@mcp.tool()
async def import_burp_xml(xml_content: str) -> str:
    """Import Burp Suite XML export — converts flows into ProxyEngine format."""
    return json.dumps(await _post("/api/import/burp", {"xml_content": xml_content}), indent=2)


# ── Entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
