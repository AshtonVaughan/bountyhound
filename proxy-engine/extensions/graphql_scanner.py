"""GraphQL Scanner — introspection, batching abuse, depth bomb, and field suggestion enumeration."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse, urljoin

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.graphql-scanner")

NAME = "graphql-scanner"
DESCRIPTION = "GraphQL introspection, batching abuse, depth bomb, field suggestion enumeration"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "batch_size": 100,
    "depth_levels": 15,
    "timeout": 15.0,
}

# Common GraphQL endpoints to try
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/v1",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
    "/graphiql",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Run GraphQL security checks."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 15.0)

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Determine GraphQL endpoints to test
    endpoints = []
    if parsed.path and parsed.path != "/":
        endpoints.append(url)
    for path in GRAPHQL_PATHS:
        ep = urljoin(base_url, path)
        if ep not in endpoints:
            endpoints.append(ep)

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        for endpoint in endpoints:
            # Quick check if endpoint is GraphQL
            is_gql = await _is_graphql_endpoint(client, endpoint)
            if not is_gql:
                continue

            log.debug(f"GraphQL endpoint found: {endpoint}")

            # Test introspection
            findings.extend(await _test_introspection(client, endpoint))

            # Test batching abuse
            findings.extend(await _test_batching(client, endpoint))

            # Test depth bomb
            findings.extend(await _test_depth_bomb(client, endpoint))

            # Test field suggestion enumeration
            findings.extend(await _test_field_suggestions(client, endpoint))

            # Test alias-based DoS
            findings.extend(await _test_alias_overloading(client, endpoint))

            break  # Found working endpoint, don't test others

    return findings


async def _is_graphql_endpoint(client: httpx.AsyncClient, url: str) -> bool:
    """Check if URL is a GraphQL endpoint."""
    try:
        resp = await client.post(
            url,
            json={"query": "{__typename}"},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            return "data" in data or "errors" in data
    except Exception:
        pass

    try:
        resp = await client.get(f"{url}?query={{__typename}}")
        if resp.status_code == 200:
            data = resp.json()
            return "data" in data or "errors" in data
    except Exception:
        pass

    return False


async def _test_introspection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test if introspection is enabled."""
    findings: list[ScanFinding] = []

    introspection_queries = [
        # Full introspection
        '{ __schema { types { name kind fields { name type { name } } } } }',
        # Short introspection
        '{ __schema { queryType { name } mutationType { name } types { name } } }',
        # Alternative syntax
        'query IntrospectionQuery { __schema { types { name } } }',
    ]

    for query in introspection_queries:
        try:
            resp = await client.post(
                url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                schema = data.get("data", {}).get("__schema", {})
                types = schema.get("types", [])

                if types:
                    type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
                    findings.append(ScanFinding(
                        template_id="graphql_introspection",
                        name="GraphQL Introspection Enabled",
                        severity="medium",
                        url=url,
                        matched_at=url,
                        description=(
                            f"GraphQL introspection is enabled, exposing the full API schema. "
                            f"Found {len(types)} types including: {', '.join(type_names[:10])}"
                            f"{'...' if len(type_names) > 10 else ''}"
                        ),
                        extracted=[
                            f"Total types: {len(types)}",
                            f"Custom types: {', '.join(type_names[:20])}",
                        ],
                        source="extension",
                        confidence="confirmed",
                        remediation=(
                            "Disable introspection in production. "
                            "Use allowlisting for permitted queries if possible."
                        ),
                    ))
                    break

        except Exception as e:
            log.debug(f"Introspection test error: {e}")

    return findings


async def _test_batching(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test batch query abuse (send array of N queries)."""
    findings: list[ScanFinding] = []
    batch_size = _config.get("batch_size", 100)

    batch = [{"query": "{__typename}"} for _ in range(batch_size)]

    try:
        resp = await client.post(
            url,
            json=batch,
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) >= batch_size:
                findings.append(ScanFinding(
                    template_id="graphql_batch_abuse",
                    name="GraphQL Batching Abuse",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Server processed a batch of {batch_size} queries in a single request. "
                        f"Returned {len(data)} results. This enables brute-force attacks "
                        "(e.g., OTP bypass, credential stuffing) and DoS."
                    ),
                    extracted=[
                        f"Batch size: {batch_size}",
                        f"Results returned: {len(data)}",
                    ],
                    source="extension",
                    confidence="confirmed",
                    remediation=(
                        "Limit batch query size. Implement query cost analysis. "
                        "Rate-limit based on query complexity, not just request count."
                    ),
                ))
    except Exception as e:
        log.debug(f"Batching test error: {e}")

    return findings


async def _test_depth_bomb(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test deeply nested query (depth bomb / DoS)."""
    findings: list[ScanFinding] = []
    depth = _config.get("depth_levels", 15)

    # Build deeply nested query
    # e.g., { a { b { c { ... { __typename } ... } } } }
    inner = "__typename"
    for i in range(depth):
        field = f"f{i}"
        inner = f"{field} {{ {inner} }}"
    deep_query = f"{{ {inner} }}"

    try:
        resp = await client.post(
            url,
            json={"query": deep_query},
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code == 200:
            data = resp.json()
            errors = data.get("errors", [])

            # If no depth limit error, it's vulnerable
            depth_limited = any(
                "depth" in str(e).lower() or "complexity" in str(e).lower() or "limit" in str(e).lower()
                for e in errors
            )

            if not depth_limited and "data" in data:
                findings.append(ScanFinding(
                    template_id="graphql_depth_bomb",
                    name="GraphQL: No Query Depth Limit",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Server accepted a query with {depth} levels of nesting without "
                        "enforcing a depth limit. This enables Denial of Service via "
                        "deeply nested queries."
                    ),
                    extracted=[f"Depth tested: {depth}", f"Response status: {resp.status_code}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Implement query depth limiting (recommended max: 7-10 levels).",
                ))

    except httpx.ReadTimeout:
        # Timeout might mean the server is struggling with the deep query
        findings.append(ScanFinding(
            template_id="graphql_depth_dos",
            name="GraphQL: Depth Bomb DoS",
            severity="high",
            url=url,
            matched_at=url,
            description=(
                f"Server timed out processing a deeply nested query ({depth} levels). "
                "Confirmed denial of service via query depth."
            ),
            extracted=[f"Depth: {depth}", "Result: timeout"],
            source="extension",
            confidence="confirmed",
            remediation="Implement query depth limiting and query cost analysis.",
        ))
    except Exception as e:
        log.debug(f"Depth bomb test error: {e}")

    return findings


async def _test_field_suggestions(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Use field suggestion errors to enumerate schema fields."""
    findings: list[ScanFinding] = []

    # Query with intentionally wrong field names to trigger suggestions
    probe_fields = [
        "usrs", "usr", "acounts", "passwrd", "admn",
        "secrt", "tokn", "emial", "phne", "adres",
        "paymen", "crdit", "ordr", "prfile", "settngs",
    ]

    all_suggestions: set[str] = set()

    for field in probe_fields:
        try:
            resp = await client.post(
                url,
                json={"query": f"{{ {field} }}"},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                errors = data.get("errors", [])
                for error in errors:
                    msg = error.get("message", "")
                    # Extract field suggestions like "Did you mean 'users'?"
                    import re
                    suggestions = re.findall(r"['\"](\w+)['\"]", msg)
                    for s in suggestions:
                        if s != field and len(s) > 1:
                            all_suggestions.add(s)

        except Exception:
            continue

    if all_suggestions:
        findings.append(ScanFinding(
            template_id="graphql_field_suggestions",
            name="GraphQL Field Suggestion Enumeration",
            severity="low",
            url=url,
            matched_at=url,
            description=(
                f"GraphQL field suggestions leak schema information. "
                f"Discovered {len(all_suggestions)} fields via typo suggestions: "
                f"{', '.join(sorted(all_suggestions)[:20])}"
            ),
            extracted=[f"Fields: {', '.join(sorted(all_suggestions))}"],
            source="extension",
            confidence="confirmed",
            remediation=(
                "Disable field suggestions in production (e.g., set didYouMean to false). "
                "This leaks schema information even when introspection is disabled."
            ),
        ))

    return findings


async def _test_alias_overloading(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test alias-based query amplification."""
    findings: list[ScanFinding] = []

    # Create query with 100 aliases of the same field
    aliases = " ".join(f"a{i}: __typename" for i in range(100))
    query = f"{{ {aliases} }}"

    try:
        resp = await client.post(
            url,
            json={"query": query},
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code == 200:
            data = resp.json()
            result_data = data.get("data", {})

            if isinstance(result_data, dict) and len(result_data) >= 100:
                findings.append(ScanFinding(
                    template_id="graphql_alias_overload",
                    name="GraphQL Alias Overloading",
                    severity="low",
                    url=url,
                    matched_at=url,
                    description=(
                        "Server allows 100+ aliases in a single query without limiting. "
                        "Combined with expensive resolvers, this enables DoS."
                    ),
                    extracted=[f"Aliases sent: 100", f"Results: {len(result_data)}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Implement alias count limits and query cost analysis.",
                ))

    except Exception as e:
        log.debug(f"Alias overloading test error: {e}")

    return findings
