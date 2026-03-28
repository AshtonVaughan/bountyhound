"""OpenAPI spec generator — infer API schema from captured flows."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

from state import state


def generate_openapi_spec(flows: list | None = None, host: str = "") -> dict:
    """Infer an OpenAPI 3.0 spec from captured proxy flows."""
    if flows is None:
        flows = list(state.flows.values())
        if host:
            flows = [f for f in flows if f.host == host]

    if not flows and host:
        return {"error": f"No flows found for host {host}"}

    # Group by normalized path + method
    endpoints: dict[str, dict] = defaultdict(lambda: {
        "methods": {},
        "examples": [],
    })

    target_host = host
    for flow in flows:
        if not target_host:
            target_host = flow.host

        parsed = urlparse(flow.request.url)
        norm_path = _normalize_path(parsed.path or "/")
        method = flow.request.method.lower()

        ep = endpoints[norm_path]
        if method not in ep["methods"]:
            ep["methods"][method] = {
                "params": {},
                "request_bodies": [],
                "responses": {},
                "content_types": set(),
            }

        method_info = ep["methods"][method]

        # Query parameters
        for k, v_list in parse_qs(parsed.query).items():
            if k not in method_info["params"]:
                method_info["params"][k] = {"in": "query", "examples": []}
            method_info["params"][k]["examples"].extend(v_list[:3])

        # Request body
        if flow.request.body:
            ct = flow.request.headers.get("content-type", "")
            method_info["content_types"].add(ct.split(";")[0].strip())
            schema = _infer_schema(flow.request.body, ct)
            if schema:
                method_info["request_bodies"].append(schema)

        # Response
        if flow.response:
            status = str(flow.response.status_code)
            if status not in method_info["responses"]:
                resp_ct = flow.response.headers.get("content-type", "")
                resp_schema = _infer_schema(flow.response.body, resp_ct) if flow.response.body else {}
                method_info["responses"][status] = {
                    "content_type": resp_ct.split(";")[0].strip(),
                    "schema": resp_schema,
                }

    # Build OpenAPI spec
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": f"API for {target_host}",
            "version": "1.0.0",
            "description": f"Auto-generated from {len(flows)} captured proxy flows.",
        },
        "servers": [{"url": f"https://{target_host}"}],
        "paths": {},
    }

    for path, ep_data in sorted(endpoints.items()):
        path_item = {}
        for method, method_info in ep_data["methods"].items():
            operation: dict = {
                "summary": f"{method.upper()} {path}",
                "responses": {},
            }

            # Parameters
            if method_info["params"]:
                operation["parameters"] = []
                for pname, pinfo in method_info["params"].items():
                    param = {
                        "name": pname,
                        "in": pinfo["in"],
                        "schema": {"type": "string"},
                    }
                    if pinfo["examples"]:
                        param["example"] = pinfo["examples"][0]
                    operation["parameters"].append(param)

            # Request body
            if method_info["request_bodies"]:
                ct = "application/json"
                for c in method_info["content_types"]:
                    if c:
                        ct = c
                        break
                operation["requestBody"] = {
                    "content": {
                        ct: {"schema": method_info["request_bodies"][0]}
                    }
                }

            # Responses
            for status, resp_info in method_info["responses"].items():
                resp_def: dict = {"description": f"HTTP {status}"}
                if resp_info.get("schema"):
                    resp_ct = resp_info.get("content_type", "application/json")
                    resp_def["content"] = {resp_ct: {"schema": resp_info["schema"]}}
                operation["responses"][status] = resp_def

            if not operation["responses"]:
                operation["responses"]["200"] = {"description": "OK"}

            path_item[method] = operation

        spec["paths"][path] = path_item

    return spec


def _normalize_path(path: str) -> str:
    """Replace numeric/UUID segments with parameter placeholders."""
    parts = path.strip("/").split("/")
    normalized = []
    for part in parts:
        if re.match(r"^\d+$", part):
            normalized.append("{id}")
        elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", part, re.I):
            normalized.append("{uuid}")
        elif re.match(r"^[0-9a-f]{24}$", part, re.I):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"


def _infer_schema(body: str | None, content_type: str) -> dict:
    """Infer JSON schema from a sample body."""
    if not body:
        return {}

    if "json" in content_type.lower():
        try:
            data = json.loads(body)
            return _json_to_schema(data)
        except json.JSONDecodeError:
            pass

    if "form" in content_type.lower():
        props = {}
        for pair in body.split("&"):
            if "=" in pair:
                k = pair.split("=", 1)[0]
                props[k] = {"type": "string"}
        if props:
            return {"type": "object", "properties": props}

    return {"type": "string"}


def _json_to_schema(data) -> dict:
    """Convert a JSON value to an OpenAPI schema."""
    if isinstance(data, dict):
        props = {}
        for k, v in data.items():
            props[k] = _json_to_schema(v)
        return {"type": "object", "properties": props}
    elif isinstance(data, list):
        if data:
            return {"type": "array", "items": _json_to_schema(data[0])}
        return {"type": "array", "items": {}}
    elif isinstance(data, bool):
        return {"type": "boolean"}
    elif isinstance(data, int):
        return {"type": "integer"}
    elif isinstance(data, float):
        return {"type": "number"}
    else:
        return {"type": "string"}
