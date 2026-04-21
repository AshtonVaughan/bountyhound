#!/usr/bin/env python3
"""
js_differ.py — Hash and diff JS bundle files between hunts.

Detects new endpoints, auth flows, and API keys by comparing
current JS bundle content against a stored baseline.

CLI:
    python js_differ.py <findings_dir> <target> [--store | --diff]
                        [--urls <url1> <url2> ...]

    --store   Download bundles, hash them, save to phases/js_bundles.json
    --diff    Compare current bundles vs stored hashes, print changes
    --urls    Additional/override JS URLs (used when 01_recon.json is absent)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Regex patterns for extraction
# ---------------------------------------------------------------------------

# Paths that look like API endpoints
_API_PATH_RE = re.compile(
    r'["\']'                          # opening quote
    r'(/(?:api|v\d+|graphql)[^"\'<>\s]{2,100})'  # /api/... /v1/... /graphql...
    r'["\']',                         # closing quote
    re.IGNORECASE,
)

# Secret / credential patterns:  key = "value_of_12plus_chars"
#   Matches both JS assignment ( = ) and JSON colon ( : ) separators
_SECRET_RE = re.compile(
    r'(?:api_?key|apiKey|secret|token|password|passwd|auth_?token|access_?key)'
    r'\s*(?:=|:)\s*'
    r'["\']([A-Za-z0-9+/_.~@#$%^&*!-]{12,})["\']',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch(url: str, timeout: int = 10) -> bytes | None:
    """Fetch a URL; return raw bytes or None on failure."""
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (compatible; BountyHound/1.0)"
        })
        if resp.status_code == 200:
            return resp.content
    except requests.RequestException:
        pass
    return None


def _extract_urls(content: bytes) -> list[str]:
    """Extract API-looking paths from JS bundle content."""
    text = content.decode("utf-8", errors="replace")
    matches = _API_PATH_RE.findall(text)
    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def _extract_secrets(content: bytes) -> list[str]:
    """Extract potential secret values from JS bundle content."""
    text = content.decode("utf-8", errors="replace")
    matches = _SECRET_RE.findall(text)
    seen: set[str] = set()
    result: list[str] = []
    for val in matches:
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _recon_path(findings_dir: Path, target: str) -> Path:
    return findings_dir / target / "phases" / "01_recon.json"


def _bundles_path(findings_dir: Path, target: str) -> Path:
    return findings_dir / target / "phases" / "js_bundles.json"


def _load_recon_urls(findings_dir: Path, target: str) -> list[str]:
    """Load JS bundle URLs from 01_recon.json (field: js_bundles)."""
    recon = _recon_path(findings_dir, target)
    if not recon.exists():
        return []
    try:
        data = json.loads(recon.read_text(encoding="utf-8"))
        return data.get("js_bundles", [])
    except (json.JSONDecodeError, OSError):
        return []


# ---------------------------------------------------------------------------
# --store mode
# ---------------------------------------------------------------------------


def cmd_store(findings_dir: Path, target: str, extra_urls: list[str]) -> dict[str, Any]:
    """
    Fetch all JS bundles, hash them, extract endpoints + secrets,
    and save to {findings_dir}/{target}/phases/js_bundles.json.
    """
    urls = _load_recon_urls(findings_dir, target)
    # Extra URLs provided on CLI override / supplement
    for u in extra_urls:
        if u not in urls:
            urls.append(u)

    if not urls:
        print(
            "ERROR: No JS bundle URLs found. "
            "Either populate 01_recon.json[js_bundles] or pass --urls.",
            file=sys.stderr,
        )
        sys.exit(1)

    bundles: dict[str, Any] = {}
    for url in urls:
        content = _fetch(url)
        if content is None:
            bundles[url] = {
                "hash": None,
                "size": 0,
                "urls_found": [],
                "secrets_found": [],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "error": "fetch_failed",
            }
            continue

        bundles[url] = {
            "hash": _sha256(content),
            "size": len(content),
            "urls_found": _extract_urls(content),
            "secrets_found": _extract_secrets(content),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    # Ensure output directory exists
    out_path = _bundles_path(findings_dir, target)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundles, indent=2), encoding="utf-8")

    result: dict[str, Any] = {
        "stored": len(bundles),
        "changed": 0,
        "new_urls": [],
        "new_secrets": [],
        "changed_bundles": [],
    }
    print(json.dumps(result))
    return result


# ---------------------------------------------------------------------------
# --diff mode
# ---------------------------------------------------------------------------


def cmd_diff(findings_dir: Path, target: str, extra_urls: list[str]) -> dict[str, Any]:
    """
    Re-fetch bundles and compare against the stored baseline.
    Print NEW_URL, REMOVED_URL, NEW_SECRET, BUNDLE_CHANGED lines,
    then emit a JSON summary.
    """
    bundles_path = _bundles_path(findings_dir, target)
    if not bundles_path.exists():
        print(
            "ERROR: No stored baseline found. Run --store first.",
            file=sys.stderr,
        )
        sys.exit(1)

    stored: dict[str, Any] = json.loads(bundles_path.read_text(encoding="utf-8"))

    # Determine current URL list
    current_urls = _load_recon_urls(findings_dir, target)
    for u in extra_urls:
        if u not in current_urls:
            current_urls.append(u)

    # Fall back to the URLs we already have stored if recon.json absent
    if not current_urls:
        current_urls = list(stored.keys())

    changed_bundles: list[str] = []
    all_new_urls: list[str] = []
    all_new_secrets: list[str] = []

    for url in current_urls:
        content = _fetch(url)
        if content is None:
            continue

        current_hash = _sha256(content)
        current_paths = set(_extract_urls(content))
        current_secrets = set(_extract_secrets(content))

        if url in stored:
            prev = stored[url]
            if prev.get("hash") and prev["hash"] != current_hash:
                print(f"BUNDLE_CHANGED: {url}")
                changed_bundles.append(url)

            prev_paths = set(prev.get("urls_found", []))
            prev_secrets = set(prev.get("secrets_found", []))

            for path in sorted(current_paths - prev_paths):
                print(f"NEW_URL: {path}")
                all_new_urls.append(path)

            for path in sorted(prev_paths - current_paths):
                print(f"REMOVED_URL: {path}")

            for secret in sorted(current_secrets - prev_secrets):
                print(f"NEW_SECRET: {secret}")
                all_new_secrets.append(secret)
        else:
            # Brand-new bundle not in stored baseline
            print(f"BUNDLE_CHANGED: {url}  [new bundle, not in baseline]")
            changed_bundles.append(url)
            for path in sorted(current_paths):
                print(f"NEW_URL: {path}")
                all_new_urls.append(path)
            for secret in sorted(current_secrets):
                print(f"NEW_SECRET: {secret}")
                all_new_secrets.append(secret)

    # Report removed bundles (in stored but not fetched this run)
    fetched_set = set(current_urls)
    for url in stored:
        if url not in fetched_set:
            print(f"REMOVED_URL: [bundle] {url}")

    result: dict[str, Any] = {
        "stored": len(stored),
        "changed": len(changed_bundles),
        "new_urls": all_new_urls,
        "new_secrets": all_new_secrets,
        "changed_bundles": changed_bundles,
    }
    print(json.dumps(result))
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hash and diff JS bundles between hunts."
    )
    parser.add_argument("findings_dir", help="Path to the findings root directory")
    parser.add_argument("target", help="Target handle (e.g. vercel-open-source)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--store",
        action="store_true",
        help="Download bundles and store baseline hashes",
    )
    mode.add_argument(
        "--diff",
        action="store_true",
        help="Compare current bundles to stored baseline",
    )
    parser.add_argument(
        "--urls",
        nargs="+",
        default=[],
        metavar="URL",
        help="Explicit JS bundle URLs (supplements or replaces 01_recon.json entries)",
    )
    args = parser.parse_args()

    findings_dir = Path(args.findings_dir)
    if args.store:
        cmd_store(findings_dir, args.target, args.urls)
    else:
        cmd_diff(findings_dir, args.target, args.urls)


if __name__ == "__main__":
    main()
