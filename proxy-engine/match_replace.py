"""Match & Replace — auto-modify requests/responses passing through the proxy."""

from __future__ import annotations

import logging

from models import MatchReplaceRule
from safe_regex import safe_compile, safe_sub

log = logging.getLogger("proxy-engine.match_replace")

# Active rules
rules: list[MatchReplaceRule] = []


def add_rule(rule: MatchReplaceRule) -> list[MatchReplaceRule]:
    rules.append(rule)
    log.info(f"[match_replace] Added rule: {rule.name}")
    return rules


def remove_rule(index: int) -> list[MatchReplaceRule]:
    if 0 <= index < len(rules):
        removed = rules.pop(index)
        log.info(f"[match_replace] Removed rule: {removed.name}")
    return rules


def update_rule(index: int, rule: MatchReplaceRule) -> list[MatchReplaceRule]:
    if 0 <= index < len(rules):
        rules[index] = rule
    return rules


def get_rules() -> list[MatchReplaceRule]:
    return list(rules)


def _rule_matches_scope(rule: MatchReplaceRule, host: str) -> bool:
    """Check if rule's scope_pattern matches the host. Empty = matches all."""
    if not rule.scope_pattern:
        return True
    compiled = safe_compile(rule.scope_pattern)
    if not compiled:
        return True  # invalid scope pattern → apply everywhere
    return bool(compiled.search(host))


def apply_request_rules(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    host: str = "",
) -> tuple[str, str, dict[str, str], str | None]:
    """Apply all enabled request-phase rules. Returns modified (method, url, headers, body)."""
    for rule in rules:
        if not rule.enabled or rule.phase not in ("request", "both"):
            continue
        if not _rule_matches_scope(rule, host):
            continue

        if rule.target == "url":
            url = _apply_pattern(rule, url)
        elif rule.target == "method":
            method = _apply_pattern(rule, method)
        elif rule.target == "header":
            if rule.target_name:
                if rule.target_name in headers:
                    headers[rule.target_name] = _apply_pattern(rule, headers[rule.target_name])
                elif rule.match == "" and rule.replace:
                    headers[rule.target_name] = rule.replace
            else:
                for k in list(headers.keys()):
                    headers[k] = _apply_pattern(rule, headers[k])
        elif rule.target == "body" and body is not None:
            body = _apply_pattern(rule, body)
        elif rule.target == "add_header" and rule.replace:
            parts = rule.replace.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip()] = parts[1].strip()
        elif rule.target == "remove_header" and rule.match:
            headers.pop(rule.match, None)

    return method, url, headers, body


def apply_response_rules(
    status_code: int,
    headers: dict[str, str],
    body: str | None,
    host: str = "",
) -> tuple[int, dict[str, str], str | None]:
    """Apply all enabled response-phase rules. Returns modified (status, headers, body)."""
    for rule in rules:
        if not rule.enabled or rule.phase not in ("response", "both"):
            continue
        if not _rule_matches_scope(rule, host):
            continue

        if rule.target == "header":
            if rule.target_name:
                if rule.target_name in headers:
                    headers[rule.target_name] = _apply_pattern(rule, headers[rule.target_name])
                elif rule.match == "" and rule.replace:
                    headers[rule.target_name] = rule.replace
            else:
                for k in list(headers.keys()):
                    headers[k] = _apply_pattern(rule, headers[k])
        elif rule.target == "body" and body is not None:
            body = _apply_pattern(rule, body)
        elif rule.target == "add_header" and rule.replace:
            parts = rule.replace.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip()] = parts[1].strip()
        elif rule.target == "remove_header" and rule.match:
            headers.pop(rule.match, None)

    return status_code, headers, body


def _apply_pattern(rule: MatchReplaceRule, text: str) -> str:
    """Apply a single match/replace rule to text."""
    if rule.is_regex:
        return safe_sub(rule.match, rule.replace, text, flags=0)
    else:
        return text.replace(rule.match, rule.replace)
