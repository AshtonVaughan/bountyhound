"""Burp Suite Project Importer — parse Burp XML export, import flows into ProxyEngine."""

from __future__ import annotations

import base64
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from models import Flow, FlowRequest, FlowResponse
from state import state


def import_burp_xml(xml_content: str) -> dict:
    """Parse Burp Suite XML export and import flows.

    Supports both Burp's HTTP history XML export and Burp project export formats.
    """
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        return {"error": f"XML parse error: {e}", "imported": 0}

    imported = 0
    errors = 0
    duplicates = 0

    # Find items — could be <item> or <request-response>
    items = root.findall(".//item")
    if not items:
        items = root.findall(".//request-response")
    if not items:
        # Try direct children
        items = list(root)

    for item in items:
        try:
            flow = _parse_burp_item(item)
            if flow:
                # Check for duplicate by URL+method
                existing = any(
                    f.request.url == flow.request.url and f.request.method == flow.request.method
                    for f in list(state.flows.values())[-100:]
                )
                if existing:
                    duplicates += 1
                    continue

                state.add_flow(flow)
                imported += 1
        except Exception:
            errors += 1

    return {
        "imported": imported,
        "errors": errors,
        "duplicates": duplicates,
        "total_items": len(items),
    }


def _parse_burp_item(item: ET.Element) -> Flow | None:
    """Parse a single Burp XML item into a Flow."""
    # Extract request
    req_el = item.find("request")
    if req_el is None:
        return None

    is_base64 = req_el.get("base64", "false").lower() == "true"
    req_raw = req_el.text or ""
    if is_base64:
        try:
            req_raw = base64.b64decode(req_raw).decode("utf-8", errors="replace")
        except Exception:
            return None

    # Parse request
    method, url, headers, body = _parse_raw_request(req_raw, item)
    if not method or not url:
        return None

    parsed = urlparse(url)
    host = parsed.hostname or item.findtext("host", "")

    # Build flow request
    flow_req = FlowRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        timestamp=_parse_timestamp(item.findtext("time", "")),
    )

    # Extract response
    resp = None
    resp_el = item.find("response")
    if resp_el is not None:
        is_base64_resp = resp_el.get("base64", "false").lower() == "true"
        resp_raw = resp_el.text or ""
        if is_base64_resp:
            try:
                resp_raw = base64.b64decode(resp_raw).decode("utf-8", errors="replace")
            except Exception:
                resp_raw = ""

        if resp_raw:
            resp = _parse_raw_response(resp_raw, item)

    flow_id = state.next_flow_id()
    return Flow(
        id=flow_id,
        request=flow_req,
        response=resp,
        host=host,
        path=parsed.path or "/",
        timestamp=flow_req.timestamp or time.time(),
    )


def _parse_raw_request(raw: str, item: ET.Element) -> tuple[str, str, dict, str | None]:
    """Parse raw HTTP request into components."""
    lines = raw.split("\n")
    if not lines:
        return "", "", {}, None

    # Request line
    first_line = lines[0].strip()
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return "", "", {}, None

    method = parts[0]
    path = parts[1]

    # Build URL from item metadata or Host header
    protocol = item.findtext("protocol", "https")
    host = item.findtext("host", "")
    port = item.findtext("port", "")

    # Extract headers
    headers = {}
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if not stripped:
            body_start = i + 1
            break
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host" and not host:
                host = v.strip()

    # Build URL
    if host:
        port_suffix = f":{port}" if port and port not in ("80", "443") else ""
        url = f"{protocol}://{host}{port_suffix}{path}"
    else:
        url = path

    # Body
    body = None
    if body_start and body_start < len(lines):
        body = "\n".join(lines[body_start:])
        if not body.strip():
            body = None

    return method, url, headers, body


def _parse_raw_response(raw: str, item: ET.Element) -> FlowResponse | None:
    """Parse raw HTTP response."""
    lines = raw.split("\n")
    if not lines:
        return None

    # Status line
    first_line = lines[0].strip()
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return None

    try:
        status_code = int(parts[1])
    except ValueError:
        return None

    reason = parts[2] if len(parts) > 2 else ""

    # Headers and body
    headers = {}
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if not stripped:
            body_start = i + 1
            break
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            headers[k.strip()] = v.strip()

    body = None
    if body_start and body_start < len(lines):
        body = "\n".join(lines[body_start:])

    status_code_from_item = item.findtext("status")
    if status_code_from_item:
        try:
            status_code = int(status_code_from_item)
        except ValueError:
            pass

    return FlowResponse(
        status_code=status_code,
        reason=reason,
        headers=headers,
        body=body,
        timestamp=time.time(),
    )


def _parse_timestamp(time_str: str) -> float:
    """Parse Burp's timestamp format."""
    if not time_str:
        return time.time()
    try:
        from datetime import datetime
        # Burp uses format like "Mon Jan 01 00:00:00 GMT 2024"
        dt = datetime.strptime(time_str, "%a %b %d %H:%M:%S %Z %Y")
        return dt.timestamp()
    except Exception:
        return time.time()
