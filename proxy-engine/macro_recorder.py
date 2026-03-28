"""Macro Recorder — captures flow sequences and converts to MacroChain.

Auto-suggests extraction rules for CSRF tokens, session cookies, auth headers.
"""

from __future__ import annotations

import re
import time

from models import MacroChain, MacroStep
from state import state

# Recording state
_recording: bool = False
_recorded_flow_ids: list[str] = []
_recording_start: float = 0.0


def start_recording() -> dict:
    global _recording, _recorded_flow_ids, _recording_start
    _recording = True
    _recorded_flow_ids = []
    _recording_start = time.time()
    return {"recording": True, "started_at": _recording_start}


def stop_recording() -> dict:
    global _recording
    _recording = False
    flows = [state.get_flow(fid) for fid in _recorded_flow_ids if state.get_flow(fid)]
    chain = _build_chain(flows)
    return {
        "recording": False,
        "flow_count": len(flows),
        "chain": chain.model_dump() if chain else None,
        "suggestions": _suggest_extractions(flows),
    }


def get_status() -> dict:
    return {
        "recording": _recording,
        "flow_count": len(_recorded_flow_ids),
        "started_at": _recording_start if _recording else 0,
        "flow_ids": _recorded_flow_ids[-20:],
    }


def is_recording() -> bool:
    return _recording


def record_flow(flow_id: str) -> None:
    """Called from addon.py when a flow completes."""
    if _recording:
        _recorded_flow_ids.append(flow_id)


def _build_chain(flows: list) -> MacroChain | None:
    if not flows:
        return None

    steps = []
    for flow in flows:
        step = MacroStep(
            method=flow.request.method,
            url=flow.request.url,
            headers=flow.request.headers,
            body=flow.request.body,
        )
        steps.append(step)

    chain = MacroChain(
        name=f"recorded-{int(time.time())}",
        steps=steps,
        trigger="manual",
    )

    # Auto-detect extraction points
    for i, flow in enumerate(flows):
        if flow.response:
            extractions = _detect_extractions(flow)
            if extractions and i < len(steps):
                best = extractions[0]
                steps[i].extract_from = best["from"]
                steps[i].extract_name = best["name"]
                steps[i].extract_var = best["var"]

    return chain


def _detect_extractions(flow) -> list[dict]:
    """Auto-detect tokens, CSRF values, and session data in response."""
    extractions = []

    if not flow.response:
        return extractions

    # Check Set-Cookie headers
    for k, v in flow.response.headers.items():
        if k.lower() == "set-cookie":
            cookie_name = v.split("=")[0].strip() if "=" in v else ""
            if cookie_name:
                extractions.append({
                    "from": "cookie",
                    "name": cookie_name,
                    "var": f"cookie_{cookie_name}",
                    "confidence": "high",
                    "reason": "Set-Cookie header",
                })

    # Check response body for CSRF tokens
    body = flow.response.body or ""
    csrf_patterns = [
        (r'name=["\']csrf[_-]?token["\'].*?value=["\']([^"\']+)', "csrf_token"),
        (r'name=["\']_token["\'].*?value=["\']([^"\']+)', "_token"),
        (r'"csrfToken"\s*:\s*"([^"]+)"', "csrfToken"),
        (r'"csrf"\s*:\s*"([^"]+)"', "csrf"),
        (r'name=["\']authenticity_token["\'].*?value=["\']([^"\']+)', "authenticity_token"),
        (r'X-CSRF-TOKEN.*?content=["\']([^"\']+)', "x-csrf-token"),
    ]

    for pattern, name in csrf_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            extractions.append({
                "from": "body_regex",
                "name": pattern,
                "var": name,
                "confidence": "high",
                "reason": f"CSRF token pattern: {name}",
            })

    # Check for auth tokens in response headers
    for header_name in ["authorization", "x-auth-token", "x-access-token", "token"]:
        if header_name in (k.lower() for k in flow.response.headers):
            val_key = next(k for k in flow.response.headers if k.lower() == header_name)
            extractions.append({
                "from": "header",
                "name": val_key,
                "var": f"header_{header_name}",
                "confidence": "medium",
                "reason": f"Auth header: {val_key}",
            })

    return extractions


def _suggest_extractions(flows: list) -> list[dict]:
    """Analyze all flows and suggest extraction rules."""
    suggestions = []
    for flow in flows:
        if flow.response:
            for ext in _detect_extractions(flow):
                ext["flow_id"] = flow.id
                ext["url"] = flow.request.url
                suggestions.append(ext)
    return suggestions
