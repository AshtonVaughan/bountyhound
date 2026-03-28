"""Sitemap — build site tree from captured flows."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from state import state


def _add_to_tree(tree: dict, parts: list[str], method: str, status_code: int | None) -> None:
    """Recursively add a path to the tree."""
    if not parts:
        return

    name = parts[0]
    if name not in tree:
        tree[name] = {
            "name": name,
            "methods": [],
            "status_codes": [],
            "children": {},
            "flow_count": 0,
        }

    node = tree[name]
    node["flow_count"] += 1

    if method not in node["methods"]:
        node["methods"].append(method)

    if status_code and status_code not in node["status_codes"]:
        node["status_codes"].append(status_code)

    if len(parts) > 1:
        _add_to_tree(node["children"], parts[1:], method, status_code)


def _annotate_node(node: dict, host: str, path: str) -> dict:
    """Add parameter aggregation, content-types, and scanner issue annotations."""
    # Collect parameters from flows matching this path
    params: set[str] = set()
    content_types: set[str] = set()
    for flow in state.flows.values():
        if flow.host == host and flow.path.split("?")[0] == path:
            parsed = urlparse(flow.request.url)
            for k in parse_qs(parsed.query).keys():
                params.add(k)
            if flow.response:
                ct = flow.response.headers.get("content-type", "")
                if ct:
                    content_types.add(ct.split(";")[0].strip())

    if params:
        node["parameters"] = sorted(params)
    if content_types:
        node["content_types"] = sorted(content_types)

    # Annotate with scanner findings
    issues = []
    for job in state.scanner_jobs.values():
        for finding in job.findings:
            if host in finding.url and path in finding.url:
                issues.append({
                    "type": finding.vuln_type,
                    "severity": finding.severity,
                    "confidence": getattr(finding, "confidence", ""),
                })
    if issues:
        node["issues"] = issues

    return node


def _annotate_tree(tree: dict, host: str, prefix: str) -> None:
    """Recursively annotate all nodes in the tree."""
    for name, node in tree.items():
        current_path = f"{prefix}/{name}" if name != "/" else "/"
        _annotate_node(node, host, current_path)
        if node.get("children"):
            _annotate_tree(node["children"], host, current_path)


def build_sitemap() -> dict:
    """Build a full sitemap from all captured flows, grouped by host."""
    hosts: dict[str, dict] = {}

    for flow in state.flows.values():
        parsed = urlparse(flow.request.url)
        host = parsed.hostname or "unknown"
        path = parsed.path or "/"

        if host not in hosts:
            hosts[host] = {
                "host": host,
                "scheme": parsed.scheme or "https",
                "flow_count": 0,
                "tree": {},
            }

        hosts[host]["flow_count"] += 1
        status = flow.response.status_code if flow.response else None
        parts = [p for p in path.split("/") if p]
        if not parts:
            parts = ["/"]
        _add_to_tree(hosts[host]["tree"], parts, flow.request.method, status)

    # Annotate leaf nodes with parameters, content-types, and scanner issues
    for host_name, host_data in hosts.items():
        _annotate_tree(host_data["tree"], host_name, "")

    return {"hosts": hosts, "total_hosts": len(hosts)}


def build_sitemap_for_host(host: str) -> dict | None:
    """Build sitemap for a specific host."""
    full = build_sitemap()
    host_lower = host.lower()

    for h, data in full["hosts"].items():
        if h.lower() == host_lower:
            return data

    return None
