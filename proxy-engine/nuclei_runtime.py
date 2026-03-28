"""Native nuclei YAML template runtime — interpret 3000+ templates without the Go binary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar

import httpx
import yaml

log = logging.getLogger("nuclei-runtime")

TEMPLATES_DIR = Path(__file__).parent / "nuclei-templates"


# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class NucleiExtractor:
    type: str = "regex"          # regex, kval, json, xpath, dsl
    name: str = ""               # variable name to store result
    part: str = "body"           # body, header, all, status_code
    group: int = 0               # regex capture group
    regex: list[str] = field(default_factory=list)
    kval: list[str] = field(default_factory=list)
    json_path: list[str] = field(default_factory=list)
    dsl: list[str] = field(default_factory=list)
    internal: bool = False


@dataclass
class NucleiMatcher:
    type: str = "word"           # word, status, regex, dsl, binary, size
    part: str = "body"           # body, header, all, status_code
    words: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    dsl: list[str] = field(default_factory=list)
    binary: list[str] = field(default_factory=list)
    size: list[int] = field(default_factory=list)
    condition: str = "or"        # and, or
    negative: bool = False
    case_insensitive: bool = False
    internal: bool = False


@dataclass
class NucleiRequestSpec:
    method: str = "GET"
    path: list[str] = field(default_factory=lambda: ["/"])
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    matchers_condition: str = "or"  # and, or
    matchers: list[NucleiMatcher] = field(default_factory=list)
    extractors: list[NucleiExtractor] = field(default_factory=list)
    redirects: bool = False
    max_redirects: int = 10
    cookie_reuse: bool = False
    raw: list[str] = field(default_factory=list)


@dataclass
class NucleiTemplate:
    id: str = ""
    name: str = ""
    severity: str = "info"
    tags: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    classification: dict[str, Any] = field(default_factory=dict)
    requests: list[NucleiRequestSpec] = field(default_factory=list)
    file_path: str = ""


# ── Template Parser ──────────────────────────────────────────────────────────

def _parse_matchers(raw_matchers: list[dict]) -> list[NucleiMatcher]:
    result = []
    for m in raw_matchers:
        matcher = NucleiMatcher(
            type=m.get("type", "word"),
            part=m.get("part", "body"),
            words=m.get("words", []),
            status=m.get("status", []),
            regex=m.get("regex", []),
            dsl=m.get("dsl", []),
            binary=m.get("binary", []),
            size=m.get("size", []),
            condition=m.get("condition", "or"),
            negative=m.get("negative", False),
            case_insensitive=m.get("case-insensitive", False),
            internal=m.get("internal", False),
        )
        result.append(matcher)
    return result


def _parse_extractors(raw_extractors: list[dict]) -> list[NucleiExtractor]:
    result = []
    for e in raw_extractors:
        ext = NucleiExtractor(
            type=e.get("type", "regex"),
            name=e.get("name", ""),
            part=e.get("part", "body"),
            group=e.get("group", 0),
            regex=e.get("regex", []),
            kval=e.get("kval", []),
            json_path=e.get("json", []),
            dsl=e.get("dsl", []),
            internal=e.get("internal", False),
        )
        result.append(ext)
    return result


def _parse_requests(raw_requests: list[dict]) -> list[NucleiRequestSpec]:
    result = []
    for r in raw_requests:
        spec = NucleiRequestSpec(
            method=r.get("method", "GET").upper(),
            path=r.get("path", ["/"]),
            headers=r.get("headers", {}),
            body=r.get("body", ""),
            matchers_condition=r.get("matchers-condition", "or"),
            matchers=_parse_matchers(r.get("matchers", [])),
            extractors=_parse_extractors(r.get("extractors", [])),
            redirects=r.get("redirects", False),
            max_redirects=r.get("max-redirects", 10),
            cookie_reuse=r.get("cookie-reuse", False),
            raw=r.get("raw", []),
        )
        result.append(spec)
    return result


def parse_template(file_path: str | Path) -> NucleiTemplate | None:
    """Parse a full nuclei YAML template file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = yaml.safe_load(f)
        if not data or not isinstance(data, dict):
            return None

        info = data.get("info", {})
        template = NucleiTemplate(
            id=data.get("id", ""),
            name=info.get("name", ""),
            severity=info.get("severity", "info").lower(),
            tags=_split_tags(info.get("tags", "")),
            description=info.get("description", ""),
            remediation=info.get("remediation", ""),
            classification=info.get("classification", {}),
            requests=_parse_requests(data.get("requests", data.get("http", []))),
            file_path=str(file_path),
        )
        return template
    except Exception as e:
        log.debug(f"Failed to parse template {file_path}: {e}")
        return None


def _split_tags(tags: str | list) -> list[str]:
    if isinstance(tags, list):
        return tags
    if isinstance(tags, str):
        return [t.strip() for t in tags.split(",") if t.strip()]
    return []


def parse_metadata_fast(file_path: str | Path) -> dict | None:
    """Fast metadata-only parser — reads first 30 lines for id + severity + tags."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= 30:
                    break
                lines.append(line)

        text = "".join(lines)
        result: dict[str, Any] = {"file": str(file_path)}

        id_match = re.search(r"^id:\s*(.+)$", text, re.MULTILINE)
        if id_match:
            result["id"] = id_match.group(1).strip()
        else:
            return None

        sev_match = re.search(r"severity:\s*(\w+)", text)
        result["severity"] = sev_match.group(1).lower() if sev_match else "info"

        tags_match = re.search(r"tags:\s*(.+)$", text, re.MULTILINE)
        result["tags"] = _split_tags(tags_match.group(1)) if tags_match else []

        name_match = re.search(r"name:\s*(.+)$", text, re.MULTILINE)
        result["name"] = name_match.group(1).strip() if name_match else result["id"]

        return result
    except Exception:
        return None


# ── Variable Substitution ────────────────────────────────────────────────────

def _resolve_variables(text: str, target_url: str, context: dict[str, str]) -> str:
    """Resolve nuclei template variables — two-pass for nested variables."""
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    port = str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80")
    path = parsed.path or "/"

    builtins = {
        "BaseURL": target_url.rstrip("/"),
        "RootURL": f"{parsed.scheme}://{parsed.netloc}",
        "Hostname": hostname,
        "Host": hostname,
        "Port": port,
        "Path": path,
        "Scheme": parsed.scheme,
    }

    all_vars = {**builtins, **context}

    # Two-pass replacement for nested variables
    for _ in range(2):
        def _replace(m: re.Match) -> str:
            key = m.group(1)
            return all_vars.get(key, m.group(0))
        text = re.sub(r"\{\{(\w+)\}\}", _replace, text)

    return text


# ── Matcher Engine ───────────────────────────────────────────────────────────

def _get_match_part(resp: httpx.Response, part: str) -> str:
    """Extract the specified part from an HTTP response."""
    if part == "header":
        return "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    elif part == "status_code":
        return str(resp.status_code)
    elif part == "all":
        headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text
        return f"{headers}\r\n\r\n{body}"
    else:  # body
        return resp.text


def _match_word(matcher: NucleiMatcher, content: str) -> bool:
    """Word matcher — substring check with and/or condition."""
    check_content = content.lower() if matcher.case_insensitive else content

    results = []
    for word in matcher.words:
        check_word = word.lower() if matcher.case_insensitive else word
        results.append(check_word in check_content)

    if not results:
        return False

    matched = all(results) if matcher.condition == "and" else any(results)
    return not matched if matcher.negative else matched


def _match_status(matcher: NucleiMatcher, resp: httpx.Response) -> bool:
    matched = resp.status_code in matcher.status
    return not matched if matcher.negative else matched


def _match_regex(matcher: NucleiMatcher, content: str) -> bool:
    """Regex matcher with ReDoS protection."""
    try:
        from safe_regex import safe_compile
    except ImportError:
        safe_compile = None  # type: ignore[assignment]

    results = []
    for pattern in matcher.regex:
        if safe_compile:
            compiled = safe_compile(pattern)
            if compiled:
                results.append(bool(compiled.search(content)))
            else:
                results.append(False)
        else:
            try:
                flags = re.IGNORECASE if matcher.case_insensitive else 0
                results.append(bool(re.search(pattern, content, flags)))
            except re.error:
                results.append(False)

    if not results:
        return False
    matched = all(results) if matcher.condition == "and" else any(results)
    return not matched if matcher.negative else matched


def _match_size(matcher: NucleiMatcher, resp: httpx.Response) -> bool:
    content_length = len(resp.content)
    matched = content_length in matcher.size
    return not matched if matcher.negative else matched


def _match_binary(matcher: NucleiMatcher, resp: httpx.Response) -> bool:
    """Binary matcher — hex byte pattern against raw bytes."""
    raw = resp.content
    results = []
    for hex_pattern in matcher.binary:
        try:
            pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
            results.append(pattern_bytes in raw)
        except ValueError:
            results.append(False)

    if not results:
        return False
    matched = all(results) if matcher.condition == "and" else any(results)
    return not matched if matcher.negative else matched


# ── DSL Expression Evaluator (safe recursive descent) ────────────────────────

class _DSLEvaluator:
    """Lightweight DSL evaluator — recursive descent, no eval()."""

    def __init__(self, variables: dict[str, Any]):
        self.vars = variables

    def evaluate(self, expr: str) -> Any:
        expr = expr.strip()
        # Handle comparisons
        for op in ("==", "!=", ">=", "<=", ">", "<"):
            parts = expr.split(op, 1)
            if len(parts) == 2:
                left = self._eval_value(parts[0].strip())
                right = self._eval_value(parts[1].strip())
                if op == "==":
                    return left == right
                elif op == "!=":
                    return left != right
                elif op == ">=":
                    return float(left) >= float(right)
                elif op == "<=":
                    return float(left) <= float(right)
                elif op == ">":
                    return float(left) > float(right)
                elif op == "<":
                    return float(left) < float(right)

        # Handle logical operators
        if " && " in expr:
            parts = expr.split(" && ")
            return all(self.evaluate(p) for p in parts)
        if " || " in expr:
            parts = expr.split(" || ")
            return any(self.evaluate(p) for p in parts)

        return bool(self._eval_value(expr))

    def _eval_value(self, expr: str) -> Any:
        expr = expr.strip()

        # String literal
        if (expr.startswith('"') and expr.endswith('"')) or \
           (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]

        # Number
        try:
            if "." in expr:
                return float(expr)
            return int(expr)
        except ValueError:
            pass

        # Function call
        func_match = re.match(r"(\w+)\((.+)\)$", expr, re.DOTALL)
        if func_match:
            fname = func_match.group(1)
            args_str = func_match.group(2)
            return self._call_function(fname, args_str)

        # Variable
        return self.vars.get(expr, expr)

    def _call_function(self, name: str, args_str: str) -> Any:
        # Parse args (simple comma split, respecting strings)
        args = self._parse_args(args_str)
        evaled_args = [self._eval_value(a) for a in args]

        if name == "contains":
            return str(evaled_args[1]) in str(evaled_args[0]) if len(evaled_args) >= 2 else False
        elif name == "len":
            return len(str(evaled_args[0])) if evaled_args else 0
        elif name == "status_code":
            return self.vars.get("status_code", 0)
        elif name == "regex":
            if len(evaled_args) >= 2:
                return bool(re.search(str(evaled_args[1]), str(evaled_args[0])))
            return False
        elif name == "md5":
            return hashlib.md5(str(evaled_args[0]).encode()).hexdigest() if evaled_args else ""
        elif name == "sha256":
            return hashlib.sha256(str(evaled_args[0]).encode()).hexdigest() if evaled_args else ""
        elif name == "to_lower":
            return str(evaled_args[0]).lower() if evaled_args else ""
        elif name == "to_upper":
            return str(evaled_args[0]).upper() if evaled_args else ""
        elif name == "trim":
            return str(evaled_args[0]).strip() if evaled_args else ""
        elif name == "base64_decode":
            import base64
            try:
                return base64.b64decode(str(evaled_args[0])).decode("utf-8", errors="replace")
            except Exception:
                return ""
        return ""

    def _parse_args(self, args_str: str) -> list[str]:
        """Split args by comma, respecting quoted strings."""
        args = []
        current = ""
        depth = 0
        in_string = False
        quote_char = ""

        for ch in args_str:
            if ch in ('"', "'") and not in_string:
                in_string = True
                quote_char = ch
                current += ch
            elif ch == quote_char and in_string:
                in_string = False
                current += ch
            elif ch == "(" and not in_string:
                depth += 1
                current += ch
            elif ch == ")" and not in_string:
                depth -= 1
                current += ch
            elif ch == "," and depth == 0 and not in_string:
                args.append(current.strip())
                current = ""
            else:
                current += ch

        if current.strip():
            args.append(current.strip())
        return args


def _match_dsl(matcher: NucleiMatcher, resp: httpx.Response, context: dict) -> bool:
    """DSL matcher using safe recursive descent evaluator."""
    variables = {
        "body": resp.text,
        "header": "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "all_headers": dict(resp.headers),
        **context,
    }
    evaluator = _DSLEvaluator(variables)

    results = []
    for expr in matcher.dsl:
        try:
            results.append(bool(evaluator.evaluate(expr)))
        except Exception:
            results.append(False)

    if not results:
        return False
    matched = all(results) if matcher.condition == "and" else any(results)
    return not matched if matcher.negative else matched


def _check_matchers(
    request_spec: NucleiRequestSpec,
    resp: httpx.Response,
    context: dict,
) -> bool:
    """Run all matchers for a request spec, with and/or condition."""
    if not request_spec.matchers:
        return False

    results = []
    for matcher in request_spec.matchers:
        if matcher.internal:
            continue  # skip internal matchers for final result

        content = _get_match_part(resp, matcher.part)

        if matcher.type == "word":
            results.append(_match_word(matcher, content))
        elif matcher.type == "status":
            results.append(_match_status(matcher, resp))
        elif matcher.type == "regex":
            results.append(_match_regex(matcher, content))
        elif matcher.type == "dsl":
            results.append(_match_dsl(matcher, resp, context))
        elif matcher.type == "binary":
            results.append(_match_binary(matcher, resp))
        elif matcher.type == "size":
            results.append(_match_size(matcher, resp))

    if not results:
        return False

    if request_spec.matchers_condition == "and":
        return all(results)
    return any(results)


# ── Extractor Engine ─────────────────────────────────────────────────────────

def _run_extractors(
    extractors: list[NucleiExtractor],
    resp: httpx.Response,
    context: dict[str, str],
) -> dict[str, str]:
    """Run extractors and return name→value mapping."""
    extracted: dict[str, str] = {}

    for ext in extractors:
        content = _get_match_part(resp, ext.part)

        if ext.type == "regex":
            for pattern in ext.regex:
                try:
                    m = re.search(pattern, content)
                    if m:
                        value = m.group(ext.group) if ext.group <= len(m.groups()) else m.group(0)
                        if ext.name:
                            extracted[ext.name] = value
                except re.error:
                    pass

        elif ext.type == "kval":
            headers = dict(resp.headers)
            for key in ext.kval:
                val = headers.get(key, headers.get(key.lower(), ""))
                if val and ext.name:
                    extracted[ext.name] = val
                elif val:
                    extracted[key] = val

        elif ext.type == "json":
            try:
                data = resp.json()
                for path in ext.json_path:
                    # Simple dot-notation path resolution
                    val = data
                    for part in path.strip(".").split("."):
                        if isinstance(val, dict):
                            val = val.get(part)
                        elif isinstance(val, list) and part.isdigit():
                            val = val[int(part)]
                        else:
                            val = None
                            break
                    if val is not None and ext.name:
                        extracted[ext.name] = str(val)
            except Exception:
                pass

    return extracted


# ── Template Execution ───────────────────────────────────────────────────────

async def _execute_template(
    template: NucleiTemplate,
    target_url: str,
    client: httpx.AsyncClient,
) -> list:
    """Execute a single nuclei template against a target URL."""
    from models import ScanFinding

    findings: list[ScanFinding] = []
    context: dict[str, str] = {}

    for req_idx, req_spec in enumerate(template.requests):
        is_last = req_idx == len(template.requests) - 1

        # Handle raw requests
        if req_spec.raw:
            for raw_req in req_spec.raw:
                resolved = _resolve_variables(raw_req, target_url, context)
                resp = await _execute_raw_request(resolved, target_url, client)
                if resp is None:
                    continue

                new_ctx = _run_extractors(req_spec.extractors, resp, context)
                context.update(new_ctx)

                if is_last and _check_matchers(req_spec, resp, context):
                    findings.append(_make_finding(template, target_url, resp, context))
            continue

        # Handle standard requests
        for path in req_spec.path:
            resolved_path = _resolve_variables(path, target_url, context)
            resolved_body = _resolve_variables(req_spec.body, target_url, context) if req_spec.body else None

            # Resolve header variables
            resolved_headers = {}
            for hk, hv in req_spec.headers.items():
                resolved_headers[hk] = _resolve_variables(hv, target_url, context)

            # Build full URL
            if resolved_path.startswith("http"):
                full_url = resolved_path
            else:
                base = target_url.rstrip("/")
                full_url = base + resolved_path

            try:
                resp = await client.request(
                    req_spec.method,
                    full_url,
                    headers=resolved_headers,
                    content=resolved_body,
                    follow_redirects=req_spec.redirects,
                )
            except Exception:
                continue

            # Run extractors
            new_ctx = _run_extractors(req_spec.extractors, resp, context)
            context.update(new_ctx)

            # Check matchers only on final request (unless internal)
            if is_last and _check_matchers(req_spec, resp, context):
                findings.append(_make_finding(template, target_url, resp, context))

    return findings


async def _execute_raw_request(
    raw: str, target_url: str, client: httpx.AsyncClient,
) -> httpx.Response | None:
    """Parse and execute a raw HTTP request string."""
    from urllib.parse import urlparse

    lines = raw.strip().split("\n")
    if not lines:
        return None

    # Parse request line: METHOD PATH HTTP/1.1
    first_line = lines[0].strip()
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return None

    method = parts[0]
    path = parts[1]
    headers: dict[str, str] = {}
    body = ""
    in_body = False

    for line in lines[1:]:
        if in_body:
            body += line + "\n"
        elif line.strip() == "":
            in_body = True
        else:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()

    # Build full URL
    parsed = urlparse(target_url)
    if path.startswith("http"):
        full_url = path
    elif path.startswith("/"):
        full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
    else:
        full_url = f"{target_url.rstrip('/')}/{path}"

    try:
        return await client.request(
            method, full_url,
            headers=headers,
            content=body.strip() if body.strip() else None,
        )
    except Exception:
        return None


def _make_finding(
    template: NucleiTemplate,
    url: str,
    resp: httpx.Response,
    context: dict,
) -> Any:
    """Create a ScanFinding from a matched template."""
    from models import ScanFinding

    extracted = []
    if context:
        extracted = [f"{k}={v}" for k, v in context.items() if not k.startswith("_")]

    return ScanFinding(
        template_id=f"nuclei-{template.id}",
        name=template.name or template.id,
        severity=template.severity,
        url=url,
        matched_at=str(resp.url),
        description=template.description or f"Nuclei template {template.id} matched",
        extracted=extracted[:10],
        source="nuclei_native",
        confidence="firm",
        remediation=template.remediation,
    )


# ── Template Index ───────────────────────────────────────────────────────────

class TemplateIndex:
    """Efficient index for 3000+ templates — metadata-only scanning."""

    def __init__(self, templates_dir: str | Path = TEMPLATES_DIR):
        self.templates_dir = Path(templates_dir)
        self.entries: list[dict] = []
        self._index_path = self.templates_dir / "templates_index.json"
        self._cache: OrderedDict[str, NucleiTemplate] = OrderedDict()
        self._max_cache = 500

    def build_index(self) -> int:
        """Scan templates directory and build metadata index."""
        if not self.templates_dir.exists():
            log.warning(f"Templates directory not found: {self.templates_dir}")
            return 0

        self.entries = []
        yaml_files = list(self.templates_dir.rglob("*.yaml"))
        yaml_files.extend(self.templates_dir.rglob("*.yml"))

        for fp in yaml_files:
            meta = parse_metadata_fast(fp)
            if meta and meta.get("id"):
                # Add category from directory structure
                rel = fp.relative_to(self.templates_dir)
                category = rel.parts[0] if len(rel.parts) > 1 else "uncategorized"
                meta["category"] = category
                self.entries.append(meta)

        # Persist index
        try:
            with open(self._index_path, "w") as f:
                json.dump(self.entries, f)
        except Exception as e:
            log.debug(f"Could not persist index: {e}")

        log.info(f"Nuclei template index: {len(self.entries)} templates")
        return len(self.entries)

    def load_index(self) -> bool:
        """Load persisted index from disk."""
        if self._index_path.exists():
            try:
                with open(self._index_path) as f:
                    self.entries = json.load(f)
                return True
            except Exception:
                pass
        return False

    def filter_entries(
        self,
        severity: str | None = None,
        tags: list[str] | None = None,
        categories: list[str] | None = None,
        max_templates: int = 500,
    ) -> list[dict]:
        """Filter index entries by severity, tags, or categories."""
        results = self.entries

        if severity:
            allowed = {s.strip().lower() for s in severity.split(",")}
            results = [e for e in results if e.get("severity", "info") in allowed]

        if tags:
            tag_set = {t.lower() for t in tags}
            results = [
                e for e in results
                if tag_set & {t.lower() for t in e.get("tags", [])}
            ]

        if categories:
            cat_set = {c.lower() for c in categories}
            results = [e for e in results if e.get("category", "").lower() in cat_set]

        return results[:max_templates]

    def get_template(self, entry: dict) -> NucleiTemplate | None:
        """Load and cache a full template."""
        file_path = entry.get("file", "")
        if not file_path:
            return None

        # Check cache
        if file_path in self._cache:
            self._cache.move_to_end(file_path)
            return self._cache[file_path]

        # Parse and cache
        template = parse_template(file_path)
        if template:
            self._cache[file_path] = template
            # Evict if over limit
            while len(self._cache) > self._max_cache:
                self._cache.popitem(last=False)

        return template

    def get_stats(self) -> dict:
        """Template count by category and severity."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for e in self.entries:
            sev = e.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

            cat = e.get("category", "uncategorized")
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "total": len(self.entries),
            "by_severity": by_severity,
            "by_category": dict(sorted(by_category.items(), key=lambda x: -x[1])[:20]),
            "cached": len(self._cache),
        }


# ── Public API — NucleiRuntime ───────────────────────────────────────────────

class NucleiRuntime:
    """Singleton runtime for executing nuclei templates natively."""

    _instance: ClassVar[NucleiRuntime | None] = None

    def __init__(self) -> None:
        self.index = TemplateIndex()
        self._initialized = False

    @classmethod
    def get_instance(cls) -> NucleiRuntime:
        if cls._instance is None:
            cls._instance = NucleiRuntime()
        return cls._instance

    def _ensure_init(self) -> None:
        if not self._initialized:
            if not self.index.load_index():
                self.index.build_index()
            self._initialized = True

    def has_templates(self) -> bool:
        self._ensure_init()
        return len(self.index.entries) > 0

    async def scan(
        self,
        urls: list[str],
        severity: str | None = None,
        tags: list[str] | None = None,
        categories: list[str] | None = None,
        max_templates: int = 500,
    ) -> list:
        """Run filtered nuclei templates against target URLs."""
        self._ensure_init()

        entries = self.index.filter_entries(severity, tags, categories, max_templates)
        if not entries:
            return []

        all_findings = []
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            for url in urls:
                for entry in entries:
                    template = self.index.get_template(entry)
                    if not template or not template.requests:
                        continue
                    try:
                        findings = await _execute_template(template, url, client)
                        all_findings.extend(findings)
                    except Exception as e:
                        log.debug(f"Template {entry.get('id', '?')} error: {e}")

        log.info(f"Native nuclei scan: {len(entries)} templates × {len(urls)} URLs = {len(all_findings)} findings")
        return all_findings

    def get_stats(self) -> dict:
        self._ensure_init()
        return self.index.get_stats()

    def reload_index(self) -> int:
        count = self.index.build_index()
        self._initialized = True
        return count
