"""Scope management — include/exclude patterns for proxy capture and tools."""

from __future__ import annotations

import logging

from models import ScopeConfig, ScopeRule
from safe_regex import safe_compile

log = logging.getLogger("proxy-engine.scope")

# Module-level config
config = ScopeConfig()


def set_config(cfg: ScopeConfig) -> None:
    global config
    config = cfg
    log.info(f"[scope] Updated: enabled={cfg.enabled}, {len(cfg.include)} include, {len(cfg.exclude)} exclude rules")


def get_config() -> ScopeConfig:
    return config


def add_include(pattern: str, target: str = "host") -> ScopeConfig:
    config.include.append(ScopeRule(pattern=pattern, target=target))
    return config


def add_exclude(pattern: str, target: str = "host") -> ScopeConfig:
    config.exclude.append(ScopeRule(pattern=pattern, target=target))
    return config


def remove_include(index: int) -> ScopeConfig:
    if 0 <= index < len(config.include):
        config.include.pop(index)
    return config


def remove_exclude(index: int) -> ScopeConfig:
    if 0 <= index < len(config.exclude):
        config.exclude.pop(index)
    return config


def _rule_matches(rule: ScopeRule, host: str, url: str) -> bool:
    """Check if a single scope rule matches the given host/url."""
    # Primary pattern match
    value = host if rule.target == "host" else url
    compiled = safe_compile(rule.pattern)
    if not compiled or not compiled.search(value):
        return False

    # Extended fields — only checked if non-empty (backward compat)
    if url and (rule.protocol or rule.port is not None or rule.path_pattern):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
        except Exception:
            return True  # can't parse, skip extended checks

        if rule.protocol and parsed.scheme and parsed.scheme.lower() != rule.protocol.lower():
            return False
        if rule.port is not None:
            actual_port = parsed.port
            if actual_port is None:
                actual_port = 443 if parsed.scheme == "https" else 80
            if actual_port != rule.port:
                return False
        if rule.path_pattern:
            path_compiled = safe_compile(rule.path_pattern)
            if path_compiled and not path_compiled.search(parsed.path or "/"):
                return False

    return True


def is_in_scope(host: str, url: str = "") -> bool:
    """Check if a host/URL is in scope. If scope is disabled, everything is in scope."""
    if not config.enabled:
        return True

    # Must match at least one include rule (if any exist)
    if config.include:
        matched = False
        for rule in config.include:
            if not rule.enabled:
                continue
            if _rule_matches(rule, host, url):
                matched = True
                break
        if not matched:
            return False

    # Must not match any exclude rule
    for rule in config.exclude:
        if not rule.enabled:
            continue
        if _rule_matches(rule, host, url):
            return False

    return True


def toggle(enabled: bool) -> ScopeConfig:
    config.enabled = enabled
    return config
