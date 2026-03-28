"""
scope_monitor.py — Detect when a program's scope changes between hunts.

CLI:
  python scope_monitor.py <program_handle> --save   # snapshot current scope
  python scope_monitor.py <program_handle> --check  # diff current vs snapshot
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AGENT = Path(__file__).resolve().parents[2]
SNAPSHOTS_DIR = AGENT / "data" / "scope_snapshots"

H1_API_BASE = "https://api.hackerone.com/v1"


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def _h1_get(path: str, username: str, token: str) -> dict[str, Any]:
    """GET from the HackerOne v1 API using Basic Auth."""
    import urllib.request
    import base64

    url = f"{H1_API_BASE}{path}"
    credentials = base64.b64encode(f"{username}:{token}".encode()).decode()
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Scope parsing
# ---------------------------------------------------------------------------

def _parse_scopes(api_response: dict[str, Any]) -> list[dict[str, str]]:
    """Extract structured scope items from the H1 API program response."""
    try:
        items = (
            api_response["data"]["relationships"]["structured_scopes"]["data"]
        )
    except (KeyError, TypeError):
        return []

    scopes: list[dict[str, str]] = []
    for item in items:
        attrs = item.get("attributes", {})
        scopes.append(
            {
                "asset_identifier": attrs.get("asset_identifier", ""),
                "asset_type": attrs.get("asset_type", ""),
                "eligible_for_bounty": str(
                    attrs.get("eligible_for_bounty", False)
                ),
            }
        )
    return scopes


def _scope_key(entry: dict[str, str]) -> str:
    """Stable key used to identify a scope entry across snapshots."""
    return f"{entry['asset_type']}::{entry['asset_identifier']}"


# ---------------------------------------------------------------------------
# Snapshot file helpers
# ---------------------------------------------------------------------------

def _snapshot_path(handle: str) -> Path:
    return SNAPSHOTS_DIR / f"{handle}.json"


def _load_snapshot(handle: str) -> dict[str, Any] | None:
    path = _snapshot_path(handle)
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _save_snapshot(handle: str, scopes: list[dict[str, str]]) -> None:
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "program_handle": handle,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "scopes": scopes,
    }
    with _snapshot_path(handle).open("w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)


# ---------------------------------------------------------------------------
# Fallback: program-map.md text hash
# ---------------------------------------------------------------------------

def _fallback_save(handle: str) -> None:
    """Save a hash of findings/<handle>/program-map.md as the snapshot."""
    map_path = AGENT.parent / "findings" / handle / "program-map.md"
    if not map_path.exists():
        print(
            f"[scope_monitor] ERROR: No H1 credentials and no program-map.md "
            f"at {map_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    text = map_path.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode()).hexdigest()
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "program_handle": handle,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "source": "program-map.md",
        "text_hash": digest,
    }
    with _snapshot_path(handle).open("w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
    print(f"[scope_monitor] Saved text hash snapshot from {map_path}")


def _fallback_check(handle: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compare current program-map.md hash vs saved hash."""
    map_path = AGENT.parent / "findings" / handle / "program-map.md"
    if not map_path.exists():
        return {
            "changes": [
                {
                    "type": "ERROR",
                    "detail": f"program-map.md not found at {map_path}",
                }
            ],
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "last_snapshot": snapshot.get("saved_at", "unknown"),
        }
    text = map_path.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode()).hexdigest()
    changes: list[dict[str, str]] = []
    if digest != snapshot.get("text_hash"):
        changes.append(
            {
                "type": "PROGRAM_MAP_CHANGED",
                "detail": "program-map.md content changed since last snapshot — re-read scope",
            }
        )
    return {
        "changes": changes,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "last_snapshot": snapshot.get("saved_at", "unknown"),
    }


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def do_save(handle: str) -> None:
    """Fetch current program scope from H1 API and save snapshot."""
    username = os.environ.get("H1_USERNAME", "")
    token = os.environ.get("H1_API_TOKEN", "")

    if not username or not token:
        print(
            "[scope_monitor] No H1 credentials — falling back to program-map.md hash",
            file=sys.stderr,
        )
        _fallback_save(handle)
        return

    try:
        data = _h1_get(f"/programs/{handle}", username, token)
    except Exception as exc:
        print(f"[scope_monitor] H1 API error: {exc}", file=sys.stderr)
        sys.exit(1)

    scopes = _parse_scopes(data)
    _save_snapshot(handle, scopes)
    print(
        f"[scope_monitor] Saved {len(scopes)} scope entries for '{handle}' "
        f"→ {_snapshot_path(handle)}"
    )


def do_check(handle: str) -> None:
    """Compare current scope vs stored snapshot and output diffs as JSON."""
    snapshot = _load_snapshot(handle)
    if snapshot is None:
        print(
            f"[scope_monitor] ERROR: No snapshot found for '{handle}'. "
            "Run with --save first.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Fallback path: snapshot was created from program-map.md
    if snapshot.get("source") == "program-map.md":
        username = os.environ.get("H1_USERNAME", "")
        token = os.environ.get("H1_API_TOKEN", "")
        if not username or not token:
            result = _fallback_check(handle, snapshot)
            print(json.dumps(result, indent=2))
            return

    username = os.environ.get("H1_USERNAME", "")
    token = os.environ.get("H1_API_TOKEN", "")

    if not username or not token:
        result = _fallback_check(handle, snapshot)
        print(json.dumps(result, indent=2))
        return

    try:
        data = _h1_get(f"/programs/{handle}", username, token)
    except Exception as exc:
        print(f"[scope_monitor] H1 API error: {exc}", file=sys.stderr)
        sys.exit(1)

    current_scopes = _parse_scopes(data)
    saved_scopes: list[dict[str, str]] = snapshot.get("scopes", [])

    # Build lookup maps
    current_map = {_scope_key(s): s for s in current_scopes}
    saved_map = {_scope_key(s): s for s in saved_scopes}

    changes: list[dict[str, str]] = []

    for key, entry in current_map.items():
        if key not in saved_map:
            changes.append(
                {
                    "type": "ADDED_SCOPE",
                    "asset": entry["asset_identifier"],
                    "asset_type": entry["asset_type"],
                }
            )
        else:
            saved = saved_map[key]
            if entry["eligible_for_bounty"] != saved["eligible_for_bounty"]:
                changes.append(
                    {
                        "type": "BOUNTY_CHANGED",
                        "asset": entry["asset_identifier"],
                        "asset_type": entry["asset_type"],
                        "from": saved["eligible_for_bounty"],
                        "to": entry["eligible_for_bounty"],
                    }
                )

    for key, entry in saved_map.items():
        if key not in current_map:
            changes.append(
                {
                    "type": "REMOVED_SCOPE",
                    "asset": entry["asset_identifier"],
                    "asset_type": entry["asset_type"],
                }
            )

    result = {
        "changes": changes,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "last_snapshot": snapshot.get("saved_at", "unknown"),
    }
    print(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor HackerOne program scope changes between hunts."
    )
    parser.add_argument("program_handle", help="H1 program handle (e.g. shopify)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--save",
        action="store_true",
        help="Fetch current scope and save as snapshot",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Compare current scope against saved snapshot",
    )
    args = parser.parse_args()

    if args.save:
        do_save(args.program_handle)
    else:
        do_check(args.program_handle)


if __name__ == "__main__":
    main()
