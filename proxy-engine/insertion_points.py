"""Auto insertion point detection — parse requests to find all injectable parameters."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse, unquote
from xml.etree import ElementTree

log = logging.getLogger("proxy-engine.insertion_points")


@dataclass
class InsertionPoint:
    """A single injectable parameter in a request."""
    name: str
    value: str
    location: str  # "url_param", "body_param", "json_key", "xml_node", "cookie", "header", "multipart_field", "url_path"
    path: str = ""  # JSON path like "user.name" or XML path

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value, "location": self.location, "path": self.path}


@dataclass
class ParsedRequest:
    """A fully parsed request with all insertion points identified."""
    method: str
    url: str
    headers: dict[str, str]
    body: str | None
    content_type: str
    insertion_points: list[InsertionPoint] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "content_type": self.content_type,
            "insertion_points": [ip.to_dict() for ip in self.insertion_points],
            "total_points": len(self.insertion_points),
        }


def extract_insertion_points(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None = None,
) -> ParsedRequest:
    """Extract all injectable parameters from a request.

    Finds insertion points in:
    - URL query parameters
    - URL path segments
    - Form body parameters (application/x-www-form-urlencoded)
    - JSON body keys (recursive)
    - XML body nodes (recursive)
    - Multipart form fields
    - Cookies
    - Selected headers (Referer, Origin, X-Forwarded-For, etc.)
    """
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break

    parsed = ParsedRequest(
        method=method, url=url, headers=headers, body=body, content_type=ct,
    )

    _extract_url_params(parsed)
    _extract_url_path_segments(parsed)
    _extract_cookies(parsed)
    _extract_injectable_headers(parsed)

    if body:
        if "json" in ct:
            _extract_json_keys(parsed, body)
        elif "xml" in ct or "soap" in ct:
            _extract_xml_nodes(parsed, body)
        elif "multipart" in ct:
            _extract_multipart_fields(parsed, body, ct)
        elif "x-www-form-urlencoded" in ct or (not ct and "=" in body):
            _extract_form_params(parsed, body)

    return parsed


def extract_from_flow(flow_dict: dict) -> ParsedRequest:
    """Extract insertion points from a Flow dict (as returned by the API)."""
    req = flow_dict.get("request", {})
    return extract_insertion_points(
        method=req.get("method", "GET"),
        url=req.get("url", ""),
        headers=req.get("headers", {}),
        body=req.get("body"),
    )


# ── URL parameters ──────────────────────────────────────────────────────────

def _extract_url_params(parsed: ParsedRequest) -> None:
    qs = urlparse(parsed.url).query
    if not qs:
        return
    params = parse_qs(qs, keep_blank_values=True)
    for name, values in params.items():
        for val in values:
            parsed.insertion_points.append(
                InsertionPoint(name=name, value=val, location="url_param")
            )


# ── URL path segments ───────────────────────────────────────────────────────

_PATH_ID_PATTERNS = [
    re.compile(r"^\d+$"),                     # numeric ID
    re.compile(r"^[0-9a-f]{8,}$", re.I),     # hex ID / UUID fragment
    re.compile(r"^[0-9a-f]{8}-", re.I),       # UUID
    re.compile(r"^[A-Za-z0-9_-]{20,}$"),      # base64-ish token
]


def _extract_url_path_segments(parsed: ParsedRequest) -> None:
    path = urlparse(parsed.url).path
    segments = [s for s in path.split("/") if s]
    for i, seg in enumerate(segments):
        decoded = unquote(seg)
        if any(p.match(decoded) for p in _PATH_ID_PATTERNS):
            parsed.insertion_points.append(
                InsertionPoint(
                    name=f"path_segment_{i}",
                    value=decoded,
                    location="url_path",
                    path=f"/{'/'.join(segments[:i+1])}",
                )
            )


# ── Form body parameters ───────────────────────────────────────────────────

def _extract_form_params(parsed: ParsedRequest, body: str) -> None:
    params = parse_qs(body, keep_blank_values=True)
    for name, values in params.items():
        for val in values:
            parsed.insertion_points.append(
                InsertionPoint(name=name, value=val, location="body_param")
            )


# ── JSON keys ───────────────────────────────────────────────────────────────

def _extract_json_keys(parsed: ParsedRequest, body: str, prefix: str = "") -> None:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return
    _walk_json(parsed, data, prefix)


def _walk_json(parsed: ParsedRequest, data, prefix: str) -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (str, int, float, bool)) or value is None:
                parsed.insertion_points.append(
                    InsertionPoint(
                        name=key,
                        value=str(value) if value is not None else "",
                        location="json_key",
                        path=path,
                    )
                )
            elif isinstance(value, dict):
                _walk_json(parsed, value, path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    _walk_json(parsed, item, f"{path}[{i}]")
    elif isinstance(data, list):
        for i, item in enumerate(data):
            _walk_json(parsed, item, f"{prefix}[{i}]")


# ── XML nodes ───────────────────────────────────────────────────────────────

def _extract_xml_nodes(parsed: ParsedRequest, body: str) -> None:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return
    _walk_xml(parsed, root, "")


def _walk_xml(parsed: ParsedRequest, elem: ElementTree.Element, prefix: str) -> None:
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    path = f"{prefix}/{tag}" if prefix else tag

    # Text content
    if elem.text and elem.text.strip():
        parsed.insertion_points.append(
            InsertionPoint(name=tag, value=elem.text.strip(), location="xml_node", path=path)
        )

    # Attributes
    for attr_name, attr_val in elem.attrib.items():
        parsed.insertion_points.append(
            InsertionPoint(
                name=f"{tag}@{attr_name}",
                value=attr_val,
                location="xml_node",
                path=f"{path}/@{attr_name}",
            )
        )

    for child in elem:
        _walk_xml(parsed, child, path)


# ── Multipart fields ───────────────────────────────────────────────────────

_MULTIPART_BOUNDARY_RE = re.compile(r"boundary=([^\s;]+)", re.I)
_CONTENT_DISPOSITION_RE = re.compile(r'name="([^"]+)"', re.I)


def _extract_multipart_fields(parsed: ParsedRequest, body: str, ct: str) -> None:
    m = _MULTIPART_BOUNDARY_RE.search(ct)
    if not m:
        return
    boundary = m.group(1).strip('"')
    parts = body.split(f"--{boundary}")

    for part in parts:
        if not part.strip() or part.strip() == "--":
            continue
        dm = _CONTENT_DISPOSITION_RE.search(part)
        if dm:
            name = dm.group(1)
            # Split header from body at double newline
            sections = re.split(r"\r?\n\r?\n", part, maxsplit=1)
            value = sections[1].strip() if len(sections) > 1 else ""
            # Skip file uploads (they have filename=)
            if 'filename="' not in part:
                parsed.insertion_points.append(
                    InsertionPoint(name=name, value=value, location="multipart_field")
                )


# ── Cookies ─────────────────────────────────────────────────────────────────

def _extract_cookies(parsed: ParsedRequest) -> None:
    cookie_header = ""
    for k, v in parsed.headers.items():
        if k.lower() == "cookie":
            cookie_header = v
            break
    if not cookie_header:
        return

    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, value = pair.partition("=")
            parsed.insertion_points.append(
                InsertionPoint(name=name.strip(), value=value.strip(), location="cookie")
            )


# ── Injectable headers ─────────────────────────────────────────────────────

_INJECTABLE_HEADERS = {
    "referer", "origin", "x-forwarded-for", "x-forwarded-host",
    "x-original-url", "x-rewrite-url", "x-custom-ip-authorization",
    "true-client-ip", "client-ip", "forwarded", "x-client-ip",
    "x-real-ip", "x-remote-addr", "x-host",
}


def _extract_injectable_headers(parsed: ParsedRequest) -> None:
    for name, value in parsed.headers.items():
        if name.lower() in _INJECTABLE_HEADERS:
            parsed.insertion_points.append(
                InsertionPoint(name=name, value=value, location="header")
            )
