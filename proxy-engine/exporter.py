"""Exporter — export flows as HAR, cURL, raw HTTP, or Python requests."""

from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from models import Flow, ExportFormat
from state import state


def export_flow(flow: Flow, fmt: ExportFormat) -> str:
    """Export a single flow in the specified format."""
    match fmt:
        case ExportFormat.curl:
            return _to_curl(flow)
        case ExportFormat.raw:
            return _to_raw(flow)
        case ExportFormat.python:
            return _to_python(flow)
        case ExportFormat.har:
            return json.dumps(_to_har_entry(flow), indent=2)
        case ExportFormat.javascript:
            return _to_javascript(flow)
        case ExportFormat.powershell:
            return _to_powershell(flow)
    return ""


def export_flows(flow_ids: list[str] | None, fmt: ExportFormat) -> str:
    """Export multiple flows. If flow_ids is None, export all."""
    if flow_ids:
        flows = [state.get_flow(fid) for fid in flow_ids]
        flows = [f for f in flows if f is not None]
    else:
        flows = list(state.flows.values())

    if fmt == ExportFormat.har:
        return _to_har(flows)

    if fmt == ExportFormat.postman:
        return _to_postman_collection(flows)

    parts = []
    for f in flows:
        parts.append(export_flow(f, fmt))
    separator = "\n\n" + "=" * 60 + "\n\n"
    return separator.join(parts)


def _to_curl(flow: Flow) -> str:
    """Convert flow to cURL command."""
    parts = [f"curl -X {flow.request.method}"]

    for k, v in flow.request.headers.items():
        if k.lower() in ("host", "content-length"):
            continue
        hdr_val = f"{k}: {v}".replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'  -H "{hdr_val}"')

    if flow.request.body:
        escaped = flow.request.body.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'  -d "{escaped}"')

    parts.append(f"  '{flow.request.url}'")
    return " \\\n".join(parts)


def _to_raw(flow: Flow) -> str:
    """Convert flow to raw HTTP request + response."""
    parsed = urlparse(flow.request.url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    lines = [f"{flow.request.method} {path} {flow.request.http_version}"]
    for k, v in flow.request.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if flow.request.body:
        lines.append(flow.request.body)

    if flow.response:
        lines.append("")
        lines.append("--- Response ---")
        lines.append(f"HTTP/{flow.request.http_version.split('/')[-1]} {flow.response.status_code} {flow.response.reason}")
        for k, v in flow.response.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if flow.response.body:
            lines.append(flow.response.body)

    return "\n".join(lines)


def _to_python(flow: Flow) -> str:
    """Convert flow to Python requests code."""
    lines = ["import requests", ""]

    headers = {k: v for k, v in flow.request.headers.items()
               if k.lower() not in ("host", "content-length", "transfer-encoding")}

    if headers:
        lines.append(f"headers = {json.dumps(headers, indent=4)}")
        headers_arg = "headers=headers"
    else:
        headers_arg = ""

    if flow.request.body:
        lines.append(f"data = {json.dumps(flow.request.body)}")
        data_arg = "data=data"
    else:
        data_arg = ""

    args = ", ".join(filter(None, [
        f"'{flow.request.url}'",
        headers_arg,
        data_arg,
        "verify=False",
    ]))

    method = flow.request.method.lower()
    if method in ("get", "post", "put", "delete", "patch", "options", "head"):
        lines.append(f"response = requests.{method}({args})")
    else:
        lines.append(f"response = requests.request('{flow.request.method}', {args})")

    lines.append("print(response.status_code, len(response.text))")
    lines.append("print(response.text)")
    return "\n".join(lines)


def _to_har_entry(flow: Flow) -> dict:
    """Convert a single flow to a HAR entry."""
    parsed = urlparse(flow.request.url)

    entry = {
        "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(flow.timestamp)),
        "time": 0,
        "request": {
            "method": flow.request.method,
            "url": flow.request.url,
            "httpVersion": flow.request.http_version,
            "headers": [{"name": k, "value": v} for k, v in flow.request.headers.items()],
            "queryString": [
                {"name": p.split("=", 1)[0], "value": p.split("=", 1)[1] if "=" in p else ""}
                for p in (parsed.query.split("&") if parsed.query else [])
            ],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(flow.request.body) if flow.request.body else 0,
        },
        "response": {
            "status": 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "content": {"size": 0, "mimeType": "", "text": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
        },
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }

    if flow.request.body:
        ct = flow.request.headers.get("content-type", "application/octet-stream")
        entry["request"]["postData"] = {"mimeType": ct, "text": flow.request.body}

    if flow.response:
        resp = flow.response
        entry["time"] = round((resp.timestamp - flow.request.timestamp) * 1000) if resp.timestamp and flow.request.timestamp else 0
        entry["response"] = {
            "status": resp.status_code,
            "statusText": resp.reason,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
            "cookies": [],
            "content": {
                "size": len(resp.body) if resp.body else 0,
                "mimeType": resp.headers.get("content-type", ""),
                "text": resp.body or "",
            },
            "redirectURL": resp.headers.get("location", ""),
            "headersSize": -1,
            "bodySize": len(resp.body) if resp.body else 0,
        }

    return entry


def _to_har(flows: list[Flow]) -> str:
    """Convert flows to HAR format."""
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "Proxy Engine", "version": "1.0"},
            "entries": [_to_har_entry(f) for f in flows],
        }
    }
    return json.dumps(har, indent=2)


def _to_javascript(flow: Flow) -> str:
    """Convert flow to JavaScript fetch code."""
    import json as _json

    headers = {k: v for k, v in flow.request.headers.items()
               if k.lower() not in ("host", "content-length")}

    lines = ["// JavaScript fetch"]
    opts: dict = {"method": flow.request.method}
    if headers:
        opts["headers"] = headers
    if flow.request.body:
        opts["body"] = flow.request.body

    lines.append(f"const response = await fetch('{flow.request.url}', {_json.dumps(opts, indent=2)});")
    lines.append("const data = await response.text();")
    lines.append("console.log(response.status, data.length);")
    return "\n".join(lines)


def _to_powershell(flow: Flow) -> str:
    """Convert flow to PowerShell Invoke-WebRequest code."""
    lines = ["# PowerShell"]

    headers = {k: v for k, v in flow.request.headers.items()
               if k.lower() not in ("host", "content-length")}

    if headers:
        lines.append("$headers = @{")
        for k, v in headers.items():
            lines.append(f'    "{k}" = "{v}"')
        lines.append("}")

    cmd_parts = [f"Invoke-WebRequest -Uri '{flow.request.url}' -Method {flow.request.method}"]
    if headers:
        cmd_parts.append("-Headers $headers")
    if flow.request.body:
        escaped = flow.request.body.replace("'", "''")
        cmd_parts.append(f"-Body '{escaped}'")
    cmd_parts.append("-SkipCertificateCheck")

    lines.append("$response = " + " `\n    ".join(cmd_parts))
    lines.append("$response.StatusCode")
    lines.append("$response.Content")
    return "\n".join(lines)


def _to_postman_collection(flows: list[Flow]) -> str:
    """Convert flows to Postman Collection v2.1 JSON."""
    import json as _json

    items = []
    for flow in flows:
        parsed = urlparse(flow.request.url)

        headers = [{"key": k, "value": v} for k, v in flow.request.headers.items()
                   if k.lower() not in ("host", "content-length")]

        item: dict = {
            "name": f"{flow.request.method} {parsed.path or '/'}",
            "request": {
                "method": flow.request.method,
                "header": headers,
                "url": {
                    "raw": flow.request.url,
                    "protocol": parsed.scheme,
                    "host": [parsed.hostname or ""],
                    "path": [p for p in (parsed.path or "/").split("/") if p],
                    "query": [
                        {"key": p.split("=", 1)[0], "value": p.split("=", 1)[1] if "=" in p else ""}
                        for p in (parsed.query.split("&") if parsed.query else [])
                    ],
                },
            },
        }

        if flow.request.body:
            ct = flow.request.headers.get("content-type", "")
            item["request"]["body"] = {
                "mode": "raw",
                "raw": flow.request.body,
                "options": {"raw": {"language": "json" if "json" in ct else "text"}},
            }

        items.append(item)

    collection = {
        "info": {
            "name": "Proxy Engine Export",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }
    return _json.dumps(collection, indent=2)


def _to_nuclei_template(finding) -> str:
    """Convert a scan finding to a nuclei YAML template."""
    severity = getattr(finding, 'severity', 'info').lower()
    name = getattr(finding, 'name', 'Unknown')
    template_id = getattr(finding, 'template_id', 'custom-check')
    description = getattr(finding, 'description', '')
    url = getattr(finding, 'url', '')

    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or "/"

    template = f"""id: {template_id}-custom

info:
  name: {name}
  severity: {severity}
  description: |
    {description}
  tags: proxy-engine,custom

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    matchers:
      - type: status
        status:
          - 200
"""
    return template
