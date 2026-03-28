"""Autorize — automatic authorization bypass testing.

Replays requests without auth or with low-priv auth, compares responses
to detect IDOR and broken access control.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from models import Flow, PassiveFinding

log = logging.getLogger("ext-autorize")

NAME = "autorize"
DESCRIPTION = "Detect IDOR/broken access control by replaying requests with low-priv or no auth"
CHECK_TYPE = "passive"
ENABLED = False

# Configuration
_config: dict[str, Any] = {
    "high_priv_headers": {},        # Headers from high-priv session (auto-captured)
    "low_priv_headers": {},         # Headers from low-priv session (user-configured)
    "no_auth": True,                # Also test with no auth at all
    "similarity_threshold": 0.9,    # Response similarity threshold (0-1)
    "ignore_paths": [],             # Regex patterns to skip
    "enforcement_detectors": [      # Patterns indicating "access denied"
        r"(?i)(unauthorized|forbidden|access.denied|login.required|not.authorized)",
        r"(?i)(401|403)",
    ],
}

_tested_urls: set[str] = set()


def configure(config: dict) -> dict:
    """Update autorize configuration."""
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    """Get current autorize state."""
    return {
        "tested_urls": len(_tested_urls),
        "config": _config,
    }


def _similarity(a: str, b: str) -> float:
    """Quick similarity check between two response bodies."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    # Length-based quick check
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))
    if len_ratio < 0.5:
        return len_ratio

    # Sample-based similarity
    sample_size = min(1000, len(a), len(b))
    matches = sum(1 for i in range(sample_size) if i < len(a) and i < len(b) and a[i] == b[i])
    return matches / sample_size


def _is_enforced(body: str, status_code: int) -> bool:
    """Check if access control is enforced (error response detected)."""
    if status_code in (401, 403):
        return True
    for pattern in _config["enforcement_detectors"]:
        if re.search(pattern, body):
            return True
    return False


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Check if request can be replayed without auth for same result."""
    if not flow.response or not flow.response.body:
        return []

    findings = []
    url = flow.request.url

    # Skip if already tested or in ignore list
    if url in _tested_urls:
        return []
    for pattern in _config.get("ignore_paths", []):
        if re.search(pattern, url):
            return []

    _tested_urls.add(url)

    # Only check authenticated requests
    auth_headers = ["authorization", "cookie", "x-auth-token", "x-api-key"]
    has_auth = any(
        h.lower() in auth_headers
        for h in flow.request.headers
    )
    if not has_auth:
        return []

    # Detect sensitive endpoints (not static assets)
    path = flow.path.lower()
    skip_extensions = (".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2")
    if any(path.endswith(ext) for ext in skip_extensions):
        return []

    # Flag as needing active verification
    original_status = flow.response.status_code
    original_length = len(flow.response.body) if flow.response.body else 0

    if original_status == 200 and original_length > 0:
        findings.append(PassiveFinding(
            flow_id=flow.id,
            check_id="autorize-candidate",
            name=f"Authorization Test Candidate: {flow.request.method} {flow.path}",
            severity="info",
            description=(
                f"Authenticated request detected (has {', '.join(h for h in flow.request.headers if h.lower() in auth_headers)}). "
                f"Status: {original_status}, Length: {original_length}. "
                "Enable active testing to verify authorization enforcement."
            ),
            evidence=f"{flow.request.method} {url}",
            url=url,
        ))

    return findings
