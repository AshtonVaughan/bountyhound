"""API Documentation Scanner — auto-discover OpenAPI/Swagger specs and generate test requests."""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urljoin

import httpx

log = logging.getLogger("proxy-engine.api-doc-scanner")

# Common paths where API documentation is found
COMMON_SPEC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/api.json",
    "/.well-known/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/graphql",  # GraphQL introspection
    "/api/graphql",
]


async def probe_api_docs(base_url: str, timeout: float = 10.0) -> dict:
    """Probe common API documentation paths and return discovered specs."""
    discovered = []
    base_url = base_url.rstrip("/")

    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
        tasks = []
        for path in COMMON_SPEC_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            tasks.append(_check_url(client, url, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict) and result.get("found"):
                discovered.append(result)

    return {
        "base_url": base_url,
        "discovered": discovered,
        "total_probed": len(COMMON_SPEC_PATHS),
        "total_found": len(discovered),
    }


async def _check_url(client: httpx.AsyncClient, url: str, path: str) -> dict:
    """Check if a URL returns an API specification."""
    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            return {"found": False, "path": path}

        content_type = resp.headers.get("content-type", "")
        body = resp.text[:50000]

        # Check if it looks like an OpenAPI/Swagger spec
        spec_type = _detect_spec_type(body, content_type, path)
        if not spec_type:
            return {"found": False, "path": path}

        return {
            "found": True,
            "path": path,
            "url": url,
            "spec_type": spec_type,
            "status_code": resp.status_code,
            "content_type": content_type,
            "size": len(body),
        }
    except Exception:
        return {"found": False, "path": path}


def _detect_spec_type(body: str, content_type: str, path: str) -> str | None:
    """Detect what type of API spec this is."""
    # GraphQL
    if "graphql" in path.lower():
        if "__schema" in body or "GraphQL" in body or '"data"' in body:
            return "graphql"

    # OpenAPI/Swagger JSON
    if "json" in content_type or body.lstrip().startswith("{"):
        try:
            data = json.loads(body)
            if "openapi" in data:
                return f"openapi-{data['openapi']}"
            if "swagger" in data:
                return f"swagger-{data['swagger']}"
            if "paths" in data and ("info" in data or "servers" in data):
                return "openapi-unknown"
        except (json.JSONDecodeError, TypeError):
            pass

    # YAML
    if "yaml" in content_type or "yaml" in path:
        if "openapi:" in body or "swagger:" in body:
            return "openapi-yaml"

    # HTML docs page (Swagger UI, etc.)
    if "text/html" in content_type:
        if "swagger" in body.lower() and ("SwaggerUIBundle" in body or "swagger-ui" in body):
            return "swagger-ui"
        if "redoc" in body.lower():
            return "redoc"

    return None


async def parse_spec_and_generate_tests(spec_url: str, timeout: float = 10.0) -> dict:
    """Fetch an API spec and generate test requests for each endpoint."""
    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(spec_url)
        if resp.status_code != 200:
            return {"error": f"Failed to fetch spec: {resp.status_code}"}

    try:
        spec = json.loads(resp.text)
    except json.JSONDecodeError:
        return {"error": "Failed to parse spec as JSON"}

    # Extract base URL from spec
    base_url = ""
    if "servers" in spec:
        base_url = spec["servers"][0].get("url", "")
    elif "host" in spec:
        scheme = "https" if "https" in spec.get("schemes", ["https"]) else "http"
        base_url = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"

    tests = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                continue

            test = {
                "method": method.upper(),
                "path": path,
                "url": f"{base_url}{path}" if base_url else path,
                "summary": details.get("summary", ""),
                "parameters": [],
                "security": details.get("security", []),
                "tags": details.get("tags", []),
            }

            # Extract parameters
            for param in details.get("parameters", []):
                test["parameters"].append({
                    "name": param.get("name", ""),
                    "in": param.get("in", ""),
                    "required": param.get("required", False),
                    "type": param.get("schema", {}).get("type", param.get("type", "string")),
                })

            # Request body
            if "requestBody" in details:
                content = details["requestBody"].get("content", {})
                for ct, schema_info in content.items():
                    test["content_type"] = ct
                    test["body_schema"] = schema_info.get("schema", {})
                    break

            tests.append(test)

    return {
        "spec_url": spec_url,
        "base_url": base_url,
        "title": spec.get("info", {}).get("title", ""),
        "version": spec.get("info", {}).get("version", ""),
        "endpoints": len(tests),
        "tests": tests,
    }


async def full_scan(base_url: str) -> dict:
    """Probe for API docs, parse any found, and generate test requests."""
    probe_result = await probe_api_docs(base_url)

    all_tests = []
    for spec in probe_result["discovered"]:
        if spec.get("spec_type", "").startswith(("openapi", "swagger")):
            try:
                test_result = await parse_spec_and_generate_tests(spec["url"])
                if "tests" in test_result:
                    all_tests.extend(test_result["tests"])
            except Exception as e:
                log.debug(f"Failed to parse spec at {spec['url']}: {e}")

    return {
        "base_url": base_url,
        "specs_found": probe_result["total_found"],
        "discovered": probe_result["discovered"],
        "test_requests": all_tests,
        "total_endpoints": len(all_tests),
    }
