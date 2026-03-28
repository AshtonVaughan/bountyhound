"""Target Analysis — summarize discovered technologies, parameters, endpoints per host."""

from __future__ import annotations

import logging
import re
from collections import Counter

from state import state

log = logging.getLogger("proxy-engine.target_analyzer")


def analyze_host(host: str) -> dict:
    """Analyze a specific host from captured flows."""
    flows = [f for f in state.flows.values() if f.host == host]
    if not flows:
        return {"error": f"No flows for host {host}"}

    return _build_analysis(host, flows)


def analyze_all() -> dict:
    """Analyze all hosts from captured flows."""
    hosts: dict[str, list] = {}
    for flow in state.flows.values():
        hosts.setdefault(flow.host, []).append(flow)

    result = {}
    for host, flows in hosts.items():
        result[host] = _build_analysis(host, flows)

    return {"hosts": result, "total_hosts": len(result)}


def _build_analysis(host: str, flows: list) -> dict:
    """Build analysis for a set of flows."""
    # Tech detection
    technologies = set()
    all_headers: dict[str, set] = {}
    all_cookies = set()
    all_params = set()
    all_endpoints = set()
    all_methods = Counter()
    status_codes = Counter()
    content_types = Counter()
    has_forms = False
    has_websocket = False
    has_api = False

    for flow in flows:
        all_endpoints.add(flow.path)
        all_methods[flow.request.method] += 1

        # Analyze request
        for k, v in flow.request.headers.items():
            all_headers.setdefault(k.lower(), set()).add(v)

        # Extract query params
        if "?" in flow.request.url:
            qs = flow.request.url.split("?", 1)[1]
            for part in qs.split("&"):
                if "=" in part:
                    all_params.add(part.split("=", 1)[0])

        # Body params
        if flow.request.body:
            ct = flow.request.headers.get("content-type", "")
            if "form" in ct:
                for part in flow.request.body.split("&"):
                    if "=" in part:
                        all_params.add(part.split("=", 1)[0])
            elif "json" in ct:
                # Extract top-level JSON keys
                import json
                try:
                    data = json.loads(flow.request.body)
                    if isinstance(data, dict):
                        all_params.update(data.keys())
                except Exception:
                    pass

        if flow.response:
            status_codes[flow.response.status_code] += 1
            ct = flow.response.headers.get("content-type", "")
            if ct:
                content_types[ct.split(";")[0].strip()] += 1

            # Tech detection from response headers
            resp_headers = {k.lower(): v for k, v in flow.response.headers.items()}

            server = resp_headers.get("server", "")
            if server:
                technologies.add(f"Server: {server}")

            powered = resp_headers.get("x-powered-by", "")
            if powered:
                technologies.add(f"Framework: {powered}")

            if resp_headers.get("x-aspnet-version") or resp_headers.get("x-aspnetmvc-version"):
                technologies.add("ASP.NET")

            if "x-drupal" in " ".join(resp_headers.keys()):
                technologies.add("Drupal")

            if "wp-" in flow.path:
                technologies.add("WordPress")

            if resp_headers.get("x-shopify-stage"):
                technologies.add("Shopify")

            # Cookie analysis
            for cookie_hdr in [v for k, v in flow.response.headers.items() if k.lower() == "set-cookie"]:
                cookie_name = cookie_hdr.split("=", 1)[0].strip()
                all_cookies.add(cookie_name)

                # Tech hints from cookie names
                if "PHPSESSID" in cookie_name:
                    technologies.add("PHP")
                elif "JSESSIONID" in cookie_name:
                    technologies.add("Java")
                elif "ASP.NET" in cookie_name:
                    technologies.add("ASP.NET")
                elif "laravel" in cookie_name.lower():
                    technologies.add("Laravel (PHP)")
                elif "django" in cookie_name.lower() or "csrf" in cookie_name.lower():
                    technologies.add("Django (Python)")
                elif "connect.sid" in cookie_name:
                    technologies.add("Express.js (Node)")
                elif "_rails" in cookie_name.lower():
                    technologies.add("Ruby on Rails")

            # Body-based tech detection
            if flow.response.body:
                body = flow.response.body[:5000]
                if "application/json" in ct:
                    has_api = True
                if "<form" in body.lower():
                    has_forms = True

                # Framework hints
                tech_hints = {
                    r"react": "React",
                    r"angular": "Angular",
                    r"vue\.js|vuejs": "Vue.js",
                    r"next\.js|nextjs|__NEXT_DATA__": "Next.js",
                    r"nuxt": "Nuxt.js",
                    r"jquery": "jQuery",
                    r"bootstrap": "Bootstrap",
                    r"tailwind": "Tailwind CSS",
                    r"graphql|__schema": "GraphQL",
                }
                for pattern, tech in tech_hints.items():
                    if re.search(pattern, body, re.IGNORECASE):
                        technologies.add(tech)

        if flow.path.startswith("/api/") or flow.path.startswith("/v1/") or flow.path.startswith("/v2/"):
            has_api = True

    # Check for WebSocket flows
    ws_msgs = [m for m in state.ws_messages if m.flow_id in {f.id for f in flows}]
    if ws_msgs:
        has_websocket = True
        technologies.add("WebSocket")

    return {
        "host": host,
        "total_requests": len(flows),
        "technologies": sorted(technologies),
        "endpoints": sorted(all_endpoints),
        "endpoint_count": len(all_endpoints),
        "parameters": sorted(all_params),
        "parameter_count": len(all_params),
        "cookies": sorted(all_cookies),
        "methods": dict(all_methods.most_common()),
        "status_codes": dict(status_codes.most_common()),
        "content_types": dict(content_types.most_common()),
        "has_forms": has_forms,
        "has_api": has_api,
        "has_websocket": has_websocket,
        "interesting_headers": {
            k: list(v)[:5] for k, v in all_headers.items()
            if k in ("authorization", "x-api-key", "x-csrf-token", "x-request-id")
        },
    }
