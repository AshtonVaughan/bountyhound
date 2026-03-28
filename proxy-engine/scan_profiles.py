"""Scan Profiles — predefined scanning configurations."""

from __future__ import annotations

import logging

from models import ScanProfile, ScanRequest

log = logging.getLogger("proxy-engine.scan_profiles")

# Built-in profiles
BUILTIN_PROFILES: dict[str, ScanProfile] = {
    "fast": ScanProfile(
        name="fast",
        description="Quick scan — critical/high nuclei templates + custom SQLi/XSS only",
        nuclei_severity="critical,high",
        custom_checks=["sqli", "xss"],
        concurrency=20,
        timeout=120,
    ),
    "thorough": ScanProfile(
        name="thorough",
        description="Full scan — all severities, all custom checks, moderate concurrency",
        nuclei_severity="",
        custom_checks=["sqli", "xss", "open_redirect", "ssrf"],
        concurrency=10,
        timeout=600,
    ),
    "passive_only": ScanProfile(
        name="passive_only",
        description="No active scanning — only run passive checks on existing flows",
        nuclei_severity="",
        custom_checks=[],
        concurrency=1,
        timeout=60,
    ),
    "api": ScanProfile(
        name="api",
        description="API-focused scan — injection and SSRF checks",
        nuclei_severity="critical,high,medium",
        nuclei_templates=["http/vulnerabilities/", "http/misconfiguration/"],
        custom_checks=["sqli", "ssrf"],
        concurrency=15,
        timeout=300,
    ),
}

# Custom user profiles
_custom_profiles: dict[str, ScanProfile] = {}


def get_profile(name: str) -> ScanProfile | None:
    """Get a profile by name (builtin or custom)."""
    return _custom_profiles.get(name) or BUILTIN_PROFILES.get(name)


def list_profiles() -> list[dict]:
    """List all available profiles."""
    all_profiles = {**BUILTIN_PROFILES, **_custom_profiles}
    return [
        {
            "name": p.name,
            "description": p.description,
            "custom": p.name in _custom_profiles,
        }
        for p in all_profiles.values()
    ]


def add_profile(profile: ScanProfile) -> list[dict]:
    """Add a custom scan profile."""
    _custom_profiles[profile.name] = profile
    log.info(f"[scan_profiles] Added profile: {profile.name}")
    return list_profiles()


def remove_profile(name: str) -> bool:
    """Remove a custom profile."""
    if name in _custom_profiles:
        del _custom_profiles[name]
        return True
    return False


def profile_to_scan_request(profile: ScanProfile, urls: list[str]) -> ScanRequest:
    """Convert a profile to a ScanRequest."""
    return ScanRequest(
        urls=urls,
        templates=profile.nuclei_templates or None,
        custom_checks=profile.custom_checks or None,
        severity=profile.nuclei_severity or None,
        concurrency=profile.concurrency,
    )
