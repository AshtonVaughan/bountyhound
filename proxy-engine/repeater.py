"""Repeater — send arbitrary requests, replay captured flows, redirect chain, keep history."""

from __future__ import annotations

import time

import httpx

from models import RepeaterRequest, RepeaterModification
from state import state


def _auto_content_length(headers: dict[str, str], body: str | None) -> dict[str, str]:
    """Auto-compute and set Content-Length when a body is present."""
    if body is not None:
        encoded = body.encode("utf-8")
        headers = dict(headers)
        headers["Content-Length"] = str(len(encoded))
    return headers


async def send_request(req: RepeaterRequest) -> dict:
    """Send an arbitrary HTTP request and return the response."""
    start = time.monotonic()

    headers = _auto_content_length(req.headers or {}, req.body)

    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=req.follow_redirects,
            timeout=30.0,
        ) as client:
            response = await client.request(
                method=req.method,
                url=req.url,
                headers=headers,
                content=req.body.encode("utf-8") if req.body else None,
            )
    except Exception as e:
        duration_ms = (time.monotonic() - start) * 1000
        result = {
            "status_code": 0,
            "headers": {},
            "body": "",
            "length": 0,
            "duration_ms": round(duration_ms, 2),
            "url": req.url,
            "error": str(e),
        }
        state.add_repeater_entry(req, result)
        return result

    duration_ms = (time.monotonic() - start) * 1000
    body_text = response.text
    result = {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": body_text,
        "length": len(body_text),
        "duration_ms": round(duration_ms, 2),
        "url": str(response.url),
    }

    state.add_repeater_entry(req, result)
    return result


async def replay_flow(flow_id: str, modification: RepeaterModification | None = None) -> dict:
    """Replay a captured flow, optionally with modifications."""
    flow = state.get_flow(flow_id)
    if not flow:
        return {"error": f"Flow {flow_id} not found"}

    method = flow.request.method
    url = flow.request.url
    headers = dict(flow.request.headers)
    body = flow.request.body
    follow_redirects = False

    if modification:
        if modification.method:
            method = modification.method
        if modification.url:
            url = modification.url
        if modification.headers:
            headers.update(modification.headers)
        if modification.body is not None:
            body = modification.body
        follow_redirects = modification.follow_redirects

    headers = _auto_content_length(headers, body)
    req = RepeaterRequest(
        method=method, url=url, headers=headers,
        body=body, follow_redirects=follow_redirects,
    )
    result = await send_request(req)
    result["original_flow_id"] = flow_id
    return result


async def send_with_redirect_chain(req: RepeaterRequest, max_redirects: int = 10) -> dict:
    """Send request and capture the full redirect chain (Task #27)."""
    chain = []
    current_url = req.url
    current_method = req.method
    current_headers = dict(req.headers or {})
    current_body = req.body

    start = time.monotonic()

    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=30.0,
        ) as client:
            for i in range(max_redirects + 1):
                resp = await client.request(
                    method=current_method,
                    url=current_url,
                    headers=current_headers,
                    content=current_body.encode("utf-8") if current_body else None,
                )

                step = {
                    "index": i,
                    "url": current_url,
                    "method": current_method,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": resp.text[:500],
                    "length": len(resp.text),
                }
                chain.append(step)

                # Check if this is a redirect
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Resolve relative URLs
                    if location.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    current_url = location
                    # 303 always becomes GET
                    if resp.status_code == 303:
                        current_method = "GET"
                        current_body = None
                    # 301/302 convert POST to GET (common browser behavior)
                    elif resp.status_code in (301, 302) and current_method == "POST":
                        current_method = "GET"
                        current_body = None
                else:
                    break

    except Exception as e:
        duration_ms = (time.monotonic() - start) * 1000
        return {
            "error": str(e),
            "chain": chain,
            "total_redirects": len(chain) - 1,
            "duration_ms": round(duration_ms, 2),
        }

    duration_ms = (time.monotonic() - start) * 1000
    final = chain[-1] if chain else {}

    result = {
        "chain": chain,
        "total_redirects": max(0, len(chain) - 1),
        "final_url": final.get("url", ""),
        "final_status": final.get("status_code", 0),
        "duration_ms": round(duration_ms, 2),
    }

    # Also save to repeater history
    state.add_repeater_entry(req, {
        "status_code": final.get("status_code", 0),
        "headers": final.get("headers", {}),
        "body": final.get("body_preview", ""),
        "length": final.get("length", 0),
        "duration_ms": round(duration_ms, 2),
        "url": final.get("url", req.url),
        "redirect_chain": True,
    })

    return result


def get_history(limit: int = 50) -> list[dict]:
    """Get repeater history, newest first."""
    entries = list(reversed(state.repeater_history[-limit:]))
    return [
        {
            "id": e.id,
            "method": e.request.method,
            "url": e.request.url,
            "status_code": e.response.get("status_code", 0),
            "length": e.response.get("length", 0),
            "duration_ms": e.response.get("duration_ms", 0),
            "timestamp": e.timestamp,
        }
        for e in entries
    ]
