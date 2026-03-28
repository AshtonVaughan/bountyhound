"""Global Search — regex search across flows, scan findings, passive findings simultaneously."""

from __future__ import annotations

import re
from state import state
from safe_regex import safe_compile


def search(
    query: str,
    scope: str = "all",
    use_regex: bool = False,
    limit: int = 50,
) -> dict:
    """Search across all data stores.

    scope: "all", "flows", "findings", "passive"
    """
    results: list[dict] = []

    pattern = None
    if use_regex:
        pattern = safe_compile(query)
        if not pattern:
            return {"results": [], "error": "Invalid regex", "total": 0}

    def matches(text: str) -> bool:
        if not text:
            return False
        if pattern:
            return bool(pattern.search(text))
        return query.lower() in text.lower()

    # Search flows
    if scope in ("all", "flows"):
        for flow in reversed(list(state.flows.values())):
            if len(results) >= limit:
                break
            haystack = f"{flow.request.method} {flow.request.url} {flow.host} {flow.path}"
            if flow.request.body:
                haystack += f" {flow.request.body[:2000]}"
            if flow.response and flow.response.body:
                haystack += f" {flow.response.body[:2000]}"
            if flow.notes:
                haystack += f" {flow.notes}"
            if matches(haystack):
                results.append({
                    "type": "flow",
                    "id": flow.id,
                    "title": f"{flow.request.method} {flow.request.url}",
                    "subtitle": f"{flow.response.status_code if flow.response else 'pending'} | {flow.host}",
                    "timestamp": flow.timestamp,
                })

    # Search scan findings
    if scope in ("all", "findings"):
        for job in state.scanner_jobs.values():
            for i, finding in enumerate(job.findings):
                if len(results) >= limit:
                    break
                haystack = f"{finding.name} {finding.url} {finding.description} {finding.template_id}"
                if finding.raw:
                    haystack += f" {finding.raw[:1000]}"
                if matches(haystack):
                    results.append({
                        "type": "finding",
                        "id": f"{job.scan_id}:{i}",
                        "title": f"[{finding.severity.upper()}] {finding.name}",
                        "subtitle": finding.url,
                        "severity": finding.severity,
                        "scan_id": job.scan_id,
                        "index": i,
                    })

    # Search passive findings
    if scope in ("all", "passive"):
        try:
            import passive_scanner
            for i, finding in enumerate(passive_scanner.findings):
                if len(results) >= limit:
                    break
                haystack = f"{finding.name} {finding.url} {finding.description} {finding.evidence}"
                if matches(haystack):
                    results.append({
                        "type": "passive",
                        "id": f"passive:{i}",
                        "title": f"[{finding.severity.upper()}] {finding.name}",
                        "subtitle": finding.url,
                        "severity": finding.severity,
                        "index": i,
                    })
        except ImportError:
            pass

    return {
        "results": results[:limit],
        "total": len(results),
        "query": query,
        "scope": scope,
    }
