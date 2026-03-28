"""OpenAPI importer — parse specs, extract endpoints, generate scope rules + scan URLs."""

from __future__ import annotations

import json
import logging
from urllib.parse import urljoin

from models import ScanRequest, ScopeRule

log = logging.getLogger("proxy-engine.openapi-importer")


def import_openapi_spec(spec: dict | str) -> dict:
    """Parse an OpenAPI spec and extract endpoints, methods, parameters."""
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

    version = spec.get("openapi", spec.get("swagger", ""))
    info = spec.get("info", {})
    servers = spec.get("servers", [])
    base_url = servers[0]["url"] if servers else ""

    # Swagger 2.0 compat
    if not base_url and "host" in spec:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath", "")
        base_url = f"{scheme}://{spec['host']}{base_path}"

    endpoints = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            if method not in path_item:
                continue

            operation = path_item[method]
            params = []

            # Path-level + operation-level parameters
            for param in path_item.get("parameters", []) + operation.get("parameters", []):
                params.append({
                    "name": param.get("name", ""),
                    "in": param.get("in", "query"),
                    "required": param.get("required", False),
                    "type": param.get("schema", {}).get("type", "string") if "schema" in param else param.get("type", "string"),
                })

            has_body = bool(operation.get("requestBody"))

            endpoints.append({
                "method": method.upper(),
                "path": path,
                "full_url": urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
                "operation_id": operation.get("operationId", ""),
                "summary": operation.get("summary", ""),
                "parameters": params,
                "has_request_body": has_body,
                "tags": operation.get("tags", []),
            })

    # Extract security schemes
    security_schemes = {}
    components = spec.get("components", spec.get("securityDefinitions", {}))
    if isinstance(components, dict):
        security_schemes = components.get("securitySchemes", components)

    # Generate scope rules from spec servers
    scope_rules = []
    for server in servers:
        from urllib.parse import urlparse
        parsed = urlparse(server["url"])
        if parsed.hostname:
            escaped = parsed.hostname.replace(".", r"\.")
            scope_rules.append(ScopeRule(
                pattern=f"^{escaped}$",
                target="host",
                enabled=True,
            ))

    return {
        "version": version,
        "title": info.get("title", ""),
        "description": info.get("description", ""),
        "base_url": base_url,
        "endpoints": endpoints,
        "endpoint_count": len(endpoints),
        "scope_rules": [r.model_dump() for r in scope_rules],
        "security_schemes": security_schemes if isinstance(security_schemes, dict) else {},
    }


def spec_to_scan_request(spec: dict | str, base_url: str = "") -> ScanRequest:
    """Convert an OpenAPI spec to a ScanRequest for the scanner."""
    parsed = import_openapi_spec(spec)

    if "error" in parsed:
        raise ValueError(parsed["error"])

    effective_base = base_url or parsed.get("base_url", "")
    urls = []

    for ep in parsed.get("endpoints", []):
        url = ep.get("full_url", "")
        if not url and effective_base:
            url = urljoin(effective_base.rstrip("/") + "/", ep["path"].lstrip("/"))
        if url:
            # Replace path parameters with sample values
            url = url.replace("{id}", "1").replace("{uuid}", "00000000-0000-0000-0000-000000000000")
            urls.append(url)

    return ScanRequest(
        urls=list(set(urls)),
        custom_checks=["sqli", "xss", "ssti", "path_traversal", "command_injection"],
    )
