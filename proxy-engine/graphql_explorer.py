"""GraphQL Explorer — introspection, schema browser, vulnerability checks."""

from __future__ import annotations

import asyncio
import json
import logging

import httpx

log = logging.getLogger("proxy-engine.graphql")

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { name description type { ...TypeRef } defaultValue }
        type { ...TypeRef }
      }
      inputFields { name description type { ...TypeRef } defaultValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }
    directives { name description locations args { name description type { ...TypeRef } defaultValue } }
  }
}

fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
"""


async def introspect(url: str, headers: dict[str, str] | None = None, timeout: float = 15.0) -> dict:
    """Run GraphQL introspection query."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        # Try POST with JSON body
        resp = await client.post(url, json={"query": INTROSPECTION_QUERY}, headers=hdrs)

        if resp.status_code != 200:
            return {"error": f"Introspection failed: HTTP {resp.status_code}", "body": resp.text[:500]}

        try:
            data = resp.json()
        except Exception:
            return {"error": "Invalid JSON response", "body": resp.text[:500]}

        if "errors" in data and not data.get("data"):
            return {"error": "Introspection disabled", "errors": data["errors"]}

        schema = data.get("data", {}).get("__schema", {})
        if not schema:
            return {"error": "No schema in response", "data": data}

        return {
            "url": url,
            "schema": schema,
            "types": _summarize_types(schema),
            "queries": _extract_operations(schema, "queryType"),
            "mutations": _extract_operations(schema, "mutationType"),
            "subscriptions": _extract_operations(schema, "subscriptionType"),
        }


def _summarize_types(schema: dict) -> list[dict]:
    """Summarize types for the schema browser."""
    types = []
    for t in schema.get("types", []):
        if t["name"].startswith("__"):
            continue
        types.append({
            "name": t["name"],
            "kind": t["kind"],
            "description": t.get("description", ""),
            "field_count": len(t.get("fields") or []),
            "fields": [
                {
                    "name": f["name"],
                    "type": _type_to_string(f.get("type", {})),
                    "args": [a["name"] for a in f.get("args", [])],
                    "deprecated": f.get("isDeprecated", False),
                }
                for f in (t.get("fields") or [])
            ],
        })
    return types


def _extract_operations(schema: dict, type_key: str) -> list[dict]:
    """Extract query/mutation/subscription operations."""
    type_info = schema.get(type_key)
    if not type_info:
        return []

    type_name = type_info.get("name", "")
    for t in schema.get("types", []):
        if t["name"] == type_name:
            return [
                {
                    "name": f["name"],
                    "type": _type_to_string(f.get("type", {})),
                    "args": [
                        {"name": a["name"], "type": _type_to_string(a.get("type", {}))}
                        for a in f.get("args", [])
                    ],
                    "description": f.get("description", ""),
                }
                for f in (t.get("fields") or [])
            ]
    return []


def _type_to_string(type_info: dict) -> str:
    """Convert a GraphQL type reference to readable string."""
    if not type_info:
        return "?"
    kind = type_info.get("kind", "")
    name = type_info.get("name", "")
    of_type = type_info.get("ofType")

    if kind == "NON_NULL":
        return f"{_type_to_string(of_type)}!"
    if kind == "LIST":
        return f"[{_type_to_string(of_type)}]"
    return name or "?"


async def execute_query(url: str, query: str, variables: dict | None = None,
                       headers: dict[str, str] | None = None, timeout: float = 15.0) -> dict:
    """Execute a GraphQL query."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)

    body = {"query": query}
    if variables:
        body["variables"] = variables

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        resp = await client.post(url, json=body, headers=hdrs)
        return {
            "status_code": resp.status_code,
            "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text[:5000]},
            "headers": dict(resp.headers),
        }


async def check_vulnerabilities(url: str, headers: dict[str, str] | None = None) -> list[dict]:
    """Run GraphQL-specific vulnerability checks."""
    findings = []
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)

    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        # 1. Check introspection enabled
        try:
            resp = await client.post(url, json={"query": INTROSPECTION_QUERY}, headers=hdrs)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data", {}).get("__schema"):
                    findings.append({
                        "name": "GraphQL Introspection Enabled",
                        "severity": "low",
                        "description": "Introspection is enabled, exposing the full API schema.",
                    })
        except Exception:
            pass

        # 2. Check query batching
        try:
            batch = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            resp = await client.post(url, json=batch, headers=hdrs)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) >= 2:
                    findings.append({
                        "name": "GraphQL Query Batching Enabled",
                        "severity": "medium",
                        "description": "Query batching is enabled. Can be used for rate limit bypass or batch brute-force.",
                    })
        except Exception:
            pass

        # 3. Check query depth limit
        try:
            deep_query = "{ __schema { types { fields { type { fields { type { name } } } } } } }"
            resp = await client.post(url, json={"query": deep_query}, headers=hdrs)
            if resp.status_code == 200:
                data = resp.json()
                if not data.get("errors"):
                    findings.append({
                        "name": "No Query Depth Limit",
                        "severity": "medium",
                        "description": "No depth limit detected. Deep recursive queries could cause DoS.",
                    })
        except Exception:
            pass

        # 4. Check alias-based batching (IDOR potential)
        try:
            alias_query = '{ a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename }'
            resp = await client.post(url, json={"query": alias_query}, headers=hdrs)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data") and len(data["data"]) >= 5:
                    findings.append({
                        "name": "GraphQL Alias Batching",
                        "severity": "low",
                        "description": "Alias-based query batching works. Can be used for IDOR enumeration.",
                    })
        except Exception:
            pass

        # 5. Check field suggestions (information disclosure)
        try:
            typo_query = "{ __schem }"
            resp = await client.post(url, json={"query": typo_query}, headers=hdrs)
            if resp.status_code in (200, 400):
                text = resp.text
                if "Did you mean" in text or "suggestion" in text.lower():
                    findings.append({
                        "name": "GraphQL Field Suggestions Enabled",
                        "severity": "info",
                        "description": "Field suggestions are enabled, leaking field names even without introspection.",
                    })
        except Exception:
            pass

    return findings
