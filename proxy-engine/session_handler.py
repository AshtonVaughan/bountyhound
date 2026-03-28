"""Session handler — automatic token refresh and login macros with caching."""

from __future__ import annotations

import logging
import time

import httpx

from models import SessionRule
from safe_regex import safe_search, safe_compile

log = logging.getLogger("proxy-engine.session")

# Active rules
rules: list[SessionRule] = []

# Token cache: rule_name -> {token, expires_at, inject_as, inject_name}
_token_cache: dict[str, dict] = {}
TOKEN_CACHE_TTL = 300  # 5 minutes default


def add_rule(rule: SessionRule) -> list[SessionRule]:
    rules.append(rule)
    log.info(f"[session] Added rule: {rule.name}")
    return rules


def remove_rule(index: int) -> list[SessionRule]:
    if 0 <= index < len(rules):
        removed = rules.pop(index)
        _token_cache.pop(removed.name, None)
        log.info(f"[session] Removed rule: {removed.name}")
    return rules


def update_rule(index: int, rule: SessionRule) -> list[SessionRule]:
    if 0 <= index < len(rules):
        rules[index] = rule
        _token_cache.pop(rule.name, None)
    return rules


def get_rules() -> list[SessionRule]:
    return list(rules)


def get_cached_token(rule_name: str) -> dict | None:
    """Get a cached token if still valid."""
    cached = _token_cache.get(rule_name)
    if cached and cached.get("expires_at", 0) > time.time():
        return cached
    _token_cache.pop(rule_name, None)
    return None


def should_trigger(rule: SessionRule, status_code: int, response_body: str = "") -> bool:
    """Check if a session rule should trigger based on the response."""
    if not rule.enabled:
        return False

    trigger = rule.trigger
    if trigger == "status_401" and status_code == 401:
        return True
    if trigger == "status_403" and status_code == 403:
        return True
    if trigger.startswith("regex:"):
        pattern = trigger[6:]
        if safe_search(pattern, response_body):
            return True

    return False


async def execute_macro(rule: SessionRule) -> dict | None:
    """Execute a session macro (login request) and extract the token."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            response = await client.request(
                method=rule.macro_method,
                url=rule.macro_url,
                headers=rule.macro_headers or {},
                content=rule.macro_body.encode() if rule.macro_body else None,
            )

        # Extract token from response
        token = None
        if rule.extract_from == "header":
            token = response.headers.get(rule.extract_name)
        elif rule.extract_from == "cookie":
            for cookie_header in response.headers.get_list("set-cookie"):
                if cookie_header.startswith(rule.extract_name + "="):
                    token = cookie_header.split("=", 1)[1].split(";")[0]
                    break
        elif rule.extract_from == "body_regex":
            match = safe_search(rule.extract_name, response.text)
            if match:
                token = match.group(1) if match.groups() else match.group(0)

        if token:
            log.info(f"[session] Macro '{rule.name}' extracted token: {token[:20]}...")
            result = {
                "token": token,
                "inject_as": rule.inject_as,
                "inject_name": rule.inject_name,
                "status_code": response.status_code,
            }
            # Cache the token
            _token_cache[rule.name] = {
                **result,
                "expires_at": time.time() + TOKEN_CACHE_TTL,
            }
            return result
        else:
            log.warning(f"[session] Macro '{rule.name}' failed to extract token")
            return None

    except Exception as e:
        log.error(f"[session] Macro '{rule.name}' error: {e}")
        return None


async def check_and_refresh(
    host: str,
    status_code: int,
    response_body: str = "",
) -> dict | None:
    """Check all rules against a response and execute macro if triggered.
    Returns the injection info if a token was refreshed."""
    for rule in rules:
        if not rule.enabled:
            continue

        # Check scope
        compiled = safe_compile(rule.scope_pattern)
        if compiled and not compiled.search(host):
            continue

        if should_trigger(rule, status_code, response_body):
            log.info(f"[session] Rule '{rule.name}' triggered for {host}")

            # Check cache first
            cached = get_cached_token(rule.name)
            if cached:
                log.info(f"[session] Using cached token for '{rule.name}'")
                return cached

            result = await execute_macro(rule)
            if result:
                return result

    return None


async def proactive_refresh() -> list[dict]:
    """Proactively refresh all tokens that are about to expire. Called by scheduler."""
    refreshed = []
    for rule in rules:
        if not rule.enabled:
            continue
        cached = _token_cache.get(rule.name)
        if cached:
            # Refresh if less than 60s remaining
            if cached.get("expires_at", 0) - time.time() < 60:
                result = await execute_macro(rule)
                if result:
                    refreshed.append({"rule": rule.name, "status": "refreshed"})
        else:
            # No cached token — try to get one
            result = await execute_macro(rule)
            if result:
                refreshed.append({"rule": rule.name, "status": "new"})
    return refreshed


# ── Macro chains ─────────────────────────────────────────────────────────────

chains: list = []  # list[MacroChain]


def add_chain(chain) -> list:
    """Add a macro chain."""
    chains.append(chain)
    log.info(f"[session] Added macro chain: {chain.name}")
    return chains


def remove_chain(index: int) -> list:
    """Remove a macro chain by index."""
    if 0 <= index < len(chains):
        removed = chains.pop(index)
        log.info(f"[session] Removed macro chain: {removed.name}")
    return chains


def get_chains() -> list:
    return list(chains)


async def execute_chain(chain) -> dict:
    """Execute a multi-step macro chain with variable extraction between steps.

    URLs and bodies support {{var_name}} substitution from extracted variables.
    """
    variables: dict[str, str] = {}
    results: list[dict] = []

    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            for i, step in enumerate(chain.steps):
                # Substitute variables in URL and body
                url = _substitute_vars(step.url, variables)
                body = _substitute_vars(step.body, variables) if step.body else None
                headers = {k: _substitute_vars(v, variables) for k, v in step.headers.items()}

                log.info(f"[macro-chain] Step {i+1}/{len(chain.steps)}: {step.method} {url}")

                response = await client.request(
                    method=step.method,
                    url=url,
                    headers=headers,
                    content=body.encode() if body else None,
                )

                step_result = {
                    "step": i + 1,
                    "url": url,
                    "status_code": response.status_code,
                }

                # Conditional branching — handle step failure
                step_failed = response.status_code >= 400
                if step_failed:
                    on_failure = getattr(step, 'on_failure', 'abort')
                    if on_failure == 'skip':
                        results.append({**step_result, "skipped": True})
                        continue
                    elif on_failure == 'retry':
                        # Retry once
                        response = await client.request(
                            method=step.method,
                            url=url,
                            headers=headers,
                            content=body.encode() if body else None,
                        )
                        step_result["retry"] = True
                        step_result["status_code"] = response.status_code
                    elif on_failure == 'abort':
                        results.append({**step_result, "aborted": True})
                        break

                # Auto-extract CSRF tokens from response
                csrf_patterns = [
                    r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']',
                    r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
                    r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
                    r'"csrf_token"\s*:\s*"([^"]+)"',
                    r'"_csrf"\s*:\s*"([^"]+)"',
                ]
                for pattern in csrf_patterns:
                    match = safe_search(pattern, response.text)
                    if match:
                        variables["_csrf_token"] = match.group(1)
                        break

                # Extract variable if configured
                if step.extract_var and step.extract_from:
                    extracted = None
                    if step.extract_from == "header":
                        extracted = response.headers.get(step.extract_name)
                    elif step.extract_from == "cookie":
                        for ch in response.headers.get_list("set-cookie"):
                            if ch.startswith(step.extract_name + "="):
                                extracted = ch.split("=", 1)[1].split(";")[0]
                                break
                    elif step.extract_from == "body_regex":
                        match = safe_search(step.extract_name, response.text)
                        if match:
                            extracted = match.group(1) if match.groups() else match.group(0)

                    if extracted:
                        variables[step.extract_var] = extracted
                        step_result["extracted"] = {step.extract_var: extracted}
                        log.info(f"[macro-chain] Extracted {step.extract_var}={extracted[:30]}...")

                results.append(step_result)

        # Cache final token if configured
        final_token = variables.get(chain.final_extract_var, "")
        if final_token and chain.final_inject_as:
            _token_cache[chain.name] = {
                "token": final_token,
                "inject_as": chain.final_inject_as,
                "inject_name": chain.final_extract_var,
                "expires_at": time.time() + TOKEN_CACHE_TTL,
            }

        return {
            "chain": chain.name,
            "steps_completed": len(results),
            "variables": variables,
            "results": results,
        }

    except Exception as e:
        log.error(f"[macro-chain] Error in chain '{chain.name}': {e}")
        return {
            "chain": chain.name,
            "error": str(e),
            "steps_completed": len(results),
            "variables": variables,
            "results": results,
        }


def _substitute_vars(text: str | None, variables: dict[str, str]) -> str:
    """Replace {{var_name}} placeholders with variable values."""
    if not text:
        return text or ""
    import re
    def replacer(m):
        var_name = m.group(1)
        return variables.get(var_name, m.group(0))
    return re.sub(r'\{\{(\w+)\}\}', replacer, text)


def get_injection_headers(host: str) -> dict[str, str]:
    """Get any cached tokens that should be injected for a given host.
    Used by scanner/intruder for auth-aware requests."""
    headers = {}
    for rule in rules:
        if not rule.enabled:
            continue
        compiled = safe_compile(rule.scope_pattern)
        if compiled and not compiled.search(host):
            continue
        cached = get_cached_token(rule.name)
        if cached and cached.get("inject_as") == "header":
            headers[cached["inject_name"]] = cached["token"]
    return headers


def get_injection_cookies(host: str) -> dict[str, str]:
    """Get cached tokens that should be injected as cookies for a host."""
    cookies = {}
    for rule in rules:
        if not rule.enabled:
            continue
        compiled = safe_compile(rule.scope_pattern)
        if compiled and not compiled.search(host):
            continue
        cached = get_cached_token(rule.name)
        if cached and cached.get("inject_as") == "cookie":
            cookies[cached["inject_name"]] = cached["token"]
    return cookies


def get_injection_body_tokens(host: str) -> dict[str, str]:
    """Get cached tokens that should be injected into request body."""
    tokens = {}
    for rule in rules:
        if not rule.enabled:
            continue
        compiled = safe_compile(rule.scope_pattern)
        if compiled and not compiled.search(host):
            continue
        cached = get_cached_token(rule.name)
        if cached and cached.get("inject_as") == "body":
            tokens[cached["inject_name"]] = cached["token"]
    return tokens


def get_injection_query_params(host: str) -> dict[str, str]:
    """Get cached tokens that should be injected as query parameters."""
    params = {}
    for rule in rules:
        if not rule.enabled:
            continue
        compiled = safe_compile(rule.scope_pattern)
        if compiled and not compiled.search(host):
            continue
        cached = get_cached_token(rule.name)
        if cached and cached.get("inject_as") == "query":
            params[cached["inject_name"]] = cached["token"]
    return params


# ── Session tracer ───────────────────────────────────────────────────────────

_session_trace: list[dict] = []


def trace_session(flow_ids: list[str]) -> list[dict]:
    """Track Set-Cookie -> Cookie correlation across flows."""
    from state import state
    trace = []
    cookies_seen: dict[str, dict] = {}  # cookie_name -> {set_by, used_by, value}

    for fid in flow_ids:
        flow = state.get_flow(fid)
        if not flow:
            continue

        # Track Set-Cookie from responses
        if flow.response:
            for key, val in flow.response.headers.items():
                if key.lower() == "set-cookie":
                    cookie_name = val.split("=", 1)[0].strip()
                    cookie_val = val.split("=", 1)[1].split(";")[0] if "=" in val else ""
                    cookies_seen[cookie_name] = {
                        "set_by_flow": fid,
                        "set_by_url": flow.request.url,
                        "value_preview": cookie_val[:30],
                        "used_by": [],
                    }

        # Track Cookie usage in requests
        cookie_header = flow.request.headers.get("Cookie", flow.request.headers.get("cookie", ""))
        if cookie_header:
            for pair in cookie_header.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name = pair.split("=", 1)[0].strip()
                    if name in cookies_seen:
                        cookies_seen[name]["used_by"].append({
                            "flow_id": fid,
                            "url": flow.request.url,
                        })

    for name, info in cookies_seen.items():
        trace.append({"cookie_name": name, **info})

    return trace


def get_session_trace() -> list[dict]:
    """Return the current session trace."""
    return list(_session_trace)
