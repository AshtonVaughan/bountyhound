#!/usr/bin/env python3
"""
schema_importer.py — Auto-discover and parse OpenAPI/Swagger/GraphQL schemas.

Probes well-known schema paths on a target URL, parses any discovered
schemas, and outputs a structured endpoint list.

CLI:
    python schema_importer.py <target_url> [--out <file>]

Output JSON:
    {
        "endpoints": [{"url", "method", "params", "auth_required"}],
        "graphql_ops": [{"name", "type", "args"}],
        "schemas_found": ["https://..."]
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

# ---------------------------------------------------------------------------
# Probe paths
# ---------------------------------------------------------------------------

_OPENAPI_PATHS: list[str] = [
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/v1/openapi.json",
    "/v2/api-docs",
    "/api/swagger",
    "/api/openapi",
    "/.well-known/openapi.yaml",
]

_GRAPHQL_PATHS: list[str] = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
]

_GRAPHQL_INTROSPECTION_QUERY: dict[str, str] = {
    "query": "{ __schema { types { name fields { name args { name type { name kind ofType { name kind } } } } } } }"
}

_HEADERS: dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (compatible; BountyHound/1.0)",
    "Accept": "application/json, application/yaml, text/yaml, */*",
}

_TIMEOUT: int = 10

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get(url: str) -> requests.Response | None:
    """GET a URL; return Response or None on error."""
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, allow_redirects=True)
        return resp
    except requests.RequestException:
        return None


def _head(url: str) -> int:
    """HEAD a URL; return status code or 0 on error."""
    try:
        resp = requests.head(url, headers=_HEADERS, timeout=_TIMEOUT, allow_redirects=True)
        return resp.status_code
    except requests.RequestException:
        return 0


def _post_json(url: str, payload: dict[str, Any]) -> requests.Response | None:
    """POST JSON; return Response or None on error."""
    try:
        resp = requests.post(
            url,
            json=payload,
            headers={**_HEADERS, "Content-Type": "application/json"},
            timeout=_TIMEOUT,
        )
        return resp
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# OpenAPI / Swagger parsing
# ---------------------------------------------------------------------------


def _parse_openapi(schema: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    """
    Parse an OpenAPI 2.x or 3.x schema dict into a flat endpoint list.
    Returns list of {url, method, params, auth_required}.
    """
    endpoints: list[dict[str, Any]] = []

    # Detect OpenAPI version
    version_str: str = str(schema.get("openapi", schema.get("swagger", "2.0")))
    is_v3 = version_str.startswith("3")

    # Base path (Swagger 2.x)
    base_path: str = schema.get("basePath", "")
    host: str = schema.get("host", urlparse(base_url).netloc)

    # Global security definitions / schemes
    security_defs = schema.get("securityDefinitions") or schema.get("components", {}).get(
        "securitySchemes", {}
    )
    global_security: list[Any] = schema.get("security", [])

    paths: dict[str, Any] = schema.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        full_url: str
        if is_v3:
            # OpenAPI 3: servers block
            servers = schema.get("servers", [{"url": base_url}])
            server_url = servers[0].get("url", base_url) if servers else base_url
            full_url = server_url.rstrip("/") + path
        else:
            # Swagger 2
            scheme = "https"
            full_url = f"{scheme}://{host}{base_path}{path}"

        http_methods = ["get", "post", "put", "patch", "delete", "head", "options"]
        for method in http_methods:
            operation: dict[str, Any] | None = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            # Parameters
            params: list[str] = []
            raw_params: list[Any] = path_item.get("parameters", []) + operation.get(
                "parameters", []
            )
            for p in raw_params:
                if isinstance(p, dict) and "name" in p:
                    params.append(p["name"])

            # Request body (OpenAPI 3)
            if is_v3 and "requestBody" in operation:
                rb = operation["requestBody"]
                content = rb.get("content", {})
                for media_type, media in content.items():
                    schema_obj = media.get("schema", {})
                    props = schema_obj.get("properties", {})
                    params.extend(props.keys())

            # Auth required
            op_security = operation.get("security", global_security)
            auth_required: bool = len(op_security) > 0 if op_security else bool(global_security)

            endpoints.append({
                "url": full_url,
                "method": method.upper(),
                "params": params,
                "auth_required": auth_required,
            })

    return endpoints


def _try_parse_yaml(text: str) -> dict[str, Any] | None:
    """Try to parse YAML text without a third-party dep (best-effort JSON fallback)."""
    # First try JSON (YAML is a superset; valid JSON is valid YAML)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Minimal YAML → attempt via stdlib — Python ships without a YAML parser,
    # but many OpenAPI YAML files can be partially read. We handle only
    # the common case where the file is actually JSON with a .yaml extension.
    # For full YAML, users should install PyYAML; we degrade gracefully here.
    return None


def _probe_openapi(base_url: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Probe all OpenAPI paths. Return (endpoints, schemas_found_urls)."""
    all_endpoints: list[dict[str, Any]] = []
    schemas_found: list[str] = []

    for path in _OPENAPI_PATHS:
        url = urljoin(base_url, path)
        status = _head(url)
        if status != 200:
            continue

        resp = _get(url)
        if resp is None or resp.status_code != 200:
            continue

        # Try JSON first
        schema: dict[str, Any] | None = None
        content_type = resp.headers.get("Content-Type", "")

        if "json" in content_type:
            try:
                schema = resp.json()
            except (ValueError, json.JSONDecodeError):
                pass
        elif "yaml" in content_type or path.endswith(".yaml"):
            schema = _try_parse_yaml(resp.text)
        else:
            # Try JSON, then YAML
            try:
                schema = resp.json()
            except (ValueError, json.JSONDecodeError):
                schema = _try_parse_yaml(resp.text)

        if not isinstance(schema, dict):
            continue

        # Validate it's actually a Swagger/OpenAPI doc
        if "paths" not in schema and "openapi" not in schema and "swagger" not in schema:
            continue

        schemas_found.append(url)
        endpoints = _parse_openapi(schema, base_url)
        all_endpoints.extend(endpoints)

    return all_endpoints, schemas_found


# ---------------------------------------------------------------------------
# GraphQL introspection parsing
# ---------------------------------------------------------------------------


def _parse_graphql_introspection(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse a GraphQL introspection result into a list of operations.
    Returns list of {name, type, args}.
    """
    ops: list[dict[str, Any]] = []

    schema_data = data.get("data", {}).get("__schema", {})
    types: list[dict[str, Any]] = schema_data.get("types", [])

    # Query and Mutation root types
    query_type_name = schema_data.get("queryType", {}).get("name") if isinstance(
        schema_data.get("queryType"), dict
    ) else None
    mutation_type_name = schema_data.get("mutationType", {}).get("name") if isinstance(
        schema_data.get("mutationType"), dict
    ) else None

    root_type_names: dict[str, str] = {}
    if query_type_name:
        root_type_names[query_type_name] = "query"
    if mutation_type_name:
        root_type_names[mutation_type_name] = "mutation"

    # If introspection didn't return queryType/mutationType,
    # infer from common names
    if not root_type_names:
        root_type_names = {"Query": "query", "Mutation": "mutation"}

    for gql_type in types:
        if not isinstance(gql_type, dict):
            continue
        type_name = gql_type.get("name", "")
        op_type = root_type_names.get(type_name)
        if not op_type:
            continue

        fields = gql_type.get("fields") or []
        for field in fields:
            if not isinstance(field, dict):
                continue
            field_name = field.get("name", "")
            if field_name.startswith("__"):
                continue

            # Extract argument names and types
            args: list[dict[str, str]] = []
            for arg in field.get("args", []) or []:
                if not isinstance(arg, dict):
                    continue
                arg_type_info = arg.get("type", {}) or {}
                # Resolve ofType chain
                type_name_resolved = (
                    arg_type_info.get("name")
                    or (arg_type_info.get("ofType") or {}).get("name")
                    or "unknown"
                )
                args.append({"name": arg.get("name", ""), "type": type_name_resolved})

            ops.append({"name": field_name, "type": op_type, "args": args})

    return ops


def _probe_graphql(base_url: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Probe all GraphQL paths. Return (graphql_ops, schemas_found_urls)."""
    all_ops: list[dict[str, Any]] = []
    schemas_found: list[str] = []

    for path in _GRAPHQL_PATHS:
        url = urljoin(base_url, path)
        resp = _post_json(url, _GRAPHQL_INTROSPECTION_QUERY)
        if resp is None or resp.status_code not in (200, 400):
            continue

        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            continue

        # A valid GraphQL endpoint returns {"data": {"__schema": ...}}
        # or an error object — both confirm the endpoint exists
        if "data" not in data and "errors" not in data:
            continue

        schemas_found.append(url)

        if "data" in data and data["data"]:
            ops = _parse_graphql_introspection(data)
            all_ops.extend(ops)

    return all_ops, schemas_found


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def discover(target_url: str) -> dict[str, Any]:
    """
    Probe target_url for OpenAPI/Swagger/GraphQL schemas.
    Returns the combined result dict.
    """
    # Normalise: ensure scheme present
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Strip trailing slash for consistent urljoin behaviour
    base = target_url.rstrip("/")

    openapi_endpoints, openapi_schemas = _probe_openapi(base)
    graphql_ops, graphql_schemas = _probe_graphql(base)

    # Deduplicate endpoints by (url, method)
    seen_endpoints: set[tuple[str, str]] = set()
    deduped_endpoints: list[dict[str, Any]] = []
    for ep in openapi_endpoints:
        key = (ep["url"], ep["method"])
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            deduped_endpoints.append(ep)

    return {
        "endpoints": deduped_endpoints,
        "graphql_ops": graphql_ops,
        "schemas_found": openapi_schemas + graphql_schemas,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto-discover and parse OpenAPI/GraphQL schemas."
    )
    parser.add_argument("target_url", help="Target base URL (e.g. https://api.example.com)")
    parser.add_argument("--out", metavar="FILE", help="Write JSON output to FILE instead of stdout")
    args = parser.parse_args()

    result = discover(args.target_url)
    output = json.dumps(result, indent=2)

    if args.out:
        from pathlib import Path
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(
            f"Wrote {len(result['endpoints'])} endpoints, "
            f"{len(result['graphql_ops'])} GraphQL ops, "
            f"{len(result['schemas_found'])} schemas to {args.out}",
            file=sys.stderr,
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
