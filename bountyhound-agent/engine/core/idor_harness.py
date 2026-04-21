"""
IDOR Harness — Systematic Insecure Direct Object Reference testing.

CLI: python idor_harness.py <endpoints_file> <creds_file_a> <creds_file_b> [--out <file>]

endpoints_file: JSON array of {url, method, auth_required}
creds_file_a:   .env format — USER_A_TOKEN and USER_A_ID
creds_file_b:   .env format — USER_B_TOKEN and USER_B_ID
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from typing import Any

import requests

# ── Regex patterns for ID extraction ────────────────────────────────────────

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_NUMERIC_ID_RE = re.compile(r"\b([0-9]{4,})\b")

# URL path parameter patterns (literal placeholders)
_PATH_PARAM_RE = re.compile(r"\{(id|user_id|resource_id|account_id|object_id)\}", re.IGNORECASE)

REQUEST_TIMEOUT = 10  # seconds
RATE_LIMIT_DELAY = 0.5  # seconds between requests


# ── Credential loading ───────────────────────────────────────────────────────


def load_env_file(path: str) -> dict[str, str]:
    """Parse KEY=value lines from a .env file."""
    result: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes (single or double)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            result[key] = value
    return result


# ── HTTP helpers ─────────────────────────────────────────────────────────────


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_request(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> requests.Response | None:
    """Make a single request; return None on connection error."""
    headers = _auth_headers(token)
    try:
        resp = requests.request(
            method.upper(),
            url,
            headers=headers,
            json=body if method.upper() in ("POST", "PUT", "PATCH") else None,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        return resp
    except requests.RequestException:
        return None


def _response_preview(resp: requests.Response | None) -> str:
    """Return a short, printable summary of a response."""
    if resp is None:
        return "connection error"
    body = resp.text[:500].replace("\n", " ").strip()
    return f"{resp.status_code} — {body}"


# ── ID extraction ────────────────────────────────────────────────────────────


def _extract_ids_from_text(text: str) -> list[str]:
    """Pull UUIDs and long numeric IDs from arbitrary text."""
    ids: list[str] = []
    ids.extend(_UUID_RE.findall(text))
    ids.extend(m.group(1) for m in _NUMERIC_ID_RE.finditer(text))
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in ids:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _extract_ids_from_url(url: str) -> list[str]:
    """Pull IDs that appear in a URL path."""
    # Split path segments and filter for UUID / long-numeric patterns
    path = url.split("?")[0]
    segments = path.split("/")
    ids: list[str] = []
    for seg in segments:
        if _UUID_RE.fullmatch(seg.strip()):
            ids.append(seg.strip())
        elif _NUMERIC_ID_RE.fullmatch(seg.strip()):
            ids.append(seg.strip())
    return ids


def _substitute_id_in_url(url: str, old_id: str, new_id: str) -> str:
    """Replace the first occurrence of old_id in the URL path with new_id."""
    return url.replace(old_id, new_id, 1)


def _substitute_id_in_body(body: str, old_id: str, new_id: str, content_type: str = "") -> str:
    """Substitute IDs in request body, content-type aware.

    For JSON: parses and replaces in serialized form to handle nested objects.
    For form-encoded or other: simple string replacement.
    """
    if not body:
        return body
    if "json" in content_type.lower():
        try:
            # Parse and re-serialize to ensure valid JSON after replacement
            parsed = json.loads(body)
            serialized = json.dumps(parsed)
            return serialized.replace(old_id, new_id)
        except json.JSONDecodeError:
            return body.replace(old_id, new_id)
    return body.replace(old_id, new_id)


def _verify_state_change(url: str, token: str, method: str = "PATCH") -> dict:
    """Verify IDOR allows actual state modification, not just read access.

    Attempts a benign PATCH/PUT to check if User B can modify User A's resource.
    Returns dict with 'verified' bool and 'evidence' string.
    """
    # Try a benign modification
    test_marker = f"idor_test_{int(time.time())}"
    test_bodies = [
        json.dumps({"_test": test_marker}),
        f"_test={test_marker}",
    ]

    for body in test_bodies:
        content_type = "application/json" if body.startswith("{") else "application/x-www-form-urlencoded"
        resp = _make_request(method, url, token, body)
        if resp and resp.status_code in (200, 201, 204):
            # Check if modification persisted
            check = _make_request("GET", url, token, None)
            if check and test_marker in check.text:
                return {
                    "verified": True,
                    "evidence": f"State change confirmed: {method} returned {resp.status_code}, marker '{test_marker}' found in subsequent GET",
                }
            return {
                "verified": False,
                "evidence": f"{method} returned {resp.status_code} but marker not found in subsequent GET (may be read-only IDOR)",
            }

    return {"verified": False, "evidence": "Could not perform state modification (all attempts returned non-2xx)"}


# ── Response comparison ──────────────────────────────────────────────────────


def _bodies_match(resp_a: requests.Response, resp_b: requests.Response) -> bool:
    """Return True if User B's response looks like User A's data."""
    if resp_b.status_code != 200:
        return False
    # Normalise whitespace for comparison
    body_a = re.sub(r"\s+", " ", resp_a.text).strip()
    body_b = re.sub(r"\s+", " ", resp_b.text).strip()
    if not body_a or not body_b:
        return False
    # Require substantial overlap — at least 60% of A's body appears in B's body
    # Simple heuristic: check character-level similarity via longest common subsequence
    # approximation (just check if body_a content is mostly in body_b)
    if body_a == body_b:
        return True
    # Shared token check — split into words, compute Jaccard similarity
    words_a = set(body_a.split())
    words_b = set(body_b.split())
    if not words_a:
        return False
    intersection = words_a & words_b
    union = words_a | words_b
    jaccard = len(intersection) / len(union)
    return jaccard >= 0.6


def _confidence_level(resp_a: requests.Response, resp_b: requests.Response) -> str:
    """Assign confidence based on response characteristics."""
    if resp_b.status_code == 200 and _bodies_match(resp_a, resp_b):
        # Stronger signal if the response contains personal-looking fields
        personal_fields = ("email", "phone", "address", "name", "ssn", "dob", "password")
        body_lower = resp_b.text.lower()
        if any(f in body_lower for f in personal_fields):
            return "high"
        return "medium"
    return "low"


# ── Core IDOR test logic ─────────────────────────────────────────────────────


def _test_endpoint_idor(
    endpoint: dict[str, Any],
    token_a: str,
    id_a: str,
    token_b: str,
    id_b: str,
) -> list[dict[str, Any]]:
    """
    Test a single endpoint for IDOR. Returns a list of candidate findings
    (may be empty, or contain one or more candidates for different IDs).
    """
    url: str = endpoint["url"]
    method: str = endpoint.get("method", "GET").upper()
    candidates: list[dict[str, Any]] = []

    # ── Step 1: Make User A's baseline request ───────────────────────────────
    time.sleep(RATE_LIMIT_DELAY)
    resp_a = _make_request(method, url, token_a)
    if resp_a is None or resp_a.status_code in (404, 500):
        return candidates  # Skip — endpoint non-functional for User A

    a_preview = _response_preview(resp_a)

    # ── Step 2: Collect IDs to test ──────────────────────────────────────────
    ids_to_test: list[str] = []

    # IDs from User A's response body
    if resp_a.status_code == 200:
        ids_to_test.extend(_extract_ids_from_text(resp_a.text))

    # IDs embedded in the URL itself
    ids_to_test.extend(_extract_ids_from_url(url))

    # Always test User A's known ID
    if id_a and id_a not in ids_to_test:
        ids_to_test.append(id_a)

    # Deduplicate
    seen: set[str] = set()
    unique_ids: list[str] = []
    for item in ids_to_test:
        if item not in seen:
            seen.add(item)
            unique_ids.append(item)

    # ── Step 3: For each ID, try substituting and hitting with User B ────────
    for resource_id in unique_ids:
        # Build the URL User B will request — swap the ID in the path
        b_url = _substitute_id_in_url(url, resource_id, id_b)
        # (The URL already contains the ID; we keep it as-is and use User B's token)
        time.sleep(RATE_LIMIT_DELAY)
        resp_b = _make_request(method, b_url, token_b)
        if resp_b is None or resp_b.status_code in (404, 500):
            continue

        b_preview = _response_preview(resp_b)

        if resp_b.status_code == 200 and _bodies_match(resp_a, resp_b):
            confidence = _confidence_level(resp_a, resp_b)
            evidence = (
                f"User B token retrieved User A's resource at {resource_id}. "
                f"Response similarity >= 60%. Status 200."
            )
            candidates.append(
                {
                    "url": b_url,
                    "method": method,
                    "user_a_id": resource_id,
                    "user_a_response_preview": a_preview,
                    "user_b_response_preview": b_preview,
                    "confidence": confidence,
                    "evidence": evidence,
                }
            )

    # ── Step 3b: Body swap for POST/PUT/PATCH endpoints ──────────────────────
    body = endpoint.get("body")
    content_type = endpoint.get("content_type", "application/json")
    if method in ("POST", "PUT", "PATCH") and body:
        body_str = json.dumps(body) if isinstance(body, dict) else str(body)
        for resource_id in unique_ids:
            swapped_body = _substitute_id_in_body(body_str, resource_id, id_b, content_type)
            if swapped_body != body_str:
                time.sleep(RATE_LIMIT_DELAY)
                resp_b = _make_request(method, url, token_b, json.loads(swapped_body) if "json" in content_type.lower() else swapped_body)
                if resp_b and resp_b.status_code in (200, 201):
                    similarity = _bodies_match(resp_a, resp_b)
                    if similarity:
                        # Attempt state verification for write IDOR
                        state = _verify_state_change(url, token_b, method)
                        candidates.append({
                            "type": "IDOR_BODY_SWAP",
                            "url": url,
                            "method": method,
                            "swapped_field": resource_id,
                            "confidence": "high" if state["verified"] else "medium",
                            "state_change": state,
                            "user_a_response_preview": a_preview,
                            "user_b_response_preview": _response_preview(resp_b),
                            "evidence": (
                                f"Body ID swap: replaced '{resource_id}' with User B's ID in request body. "
                                f"User B token returned matching response. State change: {state['evidence']}"
                            ),
                        })

    # ── Step 4: Test URL path parameter placeholders ─────────────────────────
    if _PATH_PARAM_RE.search(url) and id_a:
        # Replace placeholder with User A's actual ID; request as User B
        substituted = _PATH_PARAM_RE.sub(id_a, url)
        time.sleep(RATE_LIMIT_DELAY)
        resp_b2 = _make_request(method, substituted, token_b)
        if resp_b2 is not None and resp_b2.status_code == 200:
            time.sleep(RATE_LIMIT_DELAY)
            resp_a2 = _make_request(method, substituted, token_a)
            if resp_a2 is not None and _bodies_match(resp_a2, resp_b2):
                confidence = _confidence_level(resp_a2, resp_b2)
                candidates.append(
                    {
                        "url": substituted,
                        "method": method,
                        "user_a_id": id_a,
                        "user_a_response_preview": _response_preview(resp_a2),
                        "user_b_response_preview": _response_preview(resp_b2),
                        "confidence": confidence,
                        "evidence": (
                            f"Placeholder in URL substituted with User A's ID ({id_a}). "
                            f"User B token returned matching response."
                        ),
                    }
                )

    return candidates


# ── Main orchestrator ────────────────────────────────────────────────────────


def run_idor_scan(
    endpoints: list[dict[str, Any]],
    token_a: str,
    id_a: str,
    token_b: str,
    id_b: str,
) -> dict[str, Any]:
    """
    Run IDOR tests across all auth-required endpoints.

    Returns a results dict with idor_candidates, tested count, candidates count.
    """
    if id_a == id_b:
        print(
            "[FATAL] USER_A_ID == USER_B_ID — cannot perform IDOR test with identical IDs.",
            file=sys.stderr,
        )
        sys.exit(1)

    auth_endpoints = [ep for ep in endpoints if ep.get("auth_required", True)]
    idor_candidates: list[dict[str, Any]] = []
    tested = 0

    for ep in auth_endpoints:
        print(f"  Testing {ep.get('method', 'GET')} {ep['url']} ...", end=" ", flush=True)
        candidates = _test_endpoint_idor(ep, token_a, id_a, token_b, id_b)
        tested += 1
        if candidates:
            print(f"CANDIDATE ({len(candidates)})")
            idor_candidates.extend(candidates)
        else:
            print("clean")

    return {
        "idor_candidates": idor_candidates,
        "tested": tested,
        "candidates": len(idor_candidates),
    }


# ── CLI entry point ──────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Systematic IDOR tester using User A and User B credentials."
    )
    parser.add_argument("endpoints_file", help="JSON array of {url, method, auth_required}")
    parser.add_argument("creds_file_a", help=".env file with USER_A_TOKEN and USER_A_ID")
    parser.add_argument("creds_file_b", help=".env file with USER_B_TOKEN and USER_B_ID")
    parser.add_argument("--out", default=None, help="Output JSON file path (default: stdout)")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # Load credentials
    env_a = load_env_file(args.creds_file_a)
    env_b = load_env_file(args.creds_file_b)

    token_a = env_a.get("USER_A_TOKEN", "")
    id_a = env_a.get("USER_A_ID", "")
    token_b = env_b.get("USER_B_TOKEN", "")
    id_b = env_b.get("USER_B_ID", "")

    for var, val, src in [
        ("USER_A_TOKEN", token_a, args.creds_file_a),
        ("USER_A_ID", id_a, args.creds_file_a),
        ("USER_B_TOKEN", token_b, args.creds_file_b),
        ("USER_B_ID", id_b, args.creds_file_b),
    ]:
        if not val:
            print(f"[ERROR] {var} not found in {src}", file=sys.stderr)
            sys.exit(1)

    # Load endpoints
    with open(args.endpoints_file, encoding="utf-8") as fh:
        endpoints: list[dict[str, Any]] = json.load(fh)

    if not isinstance(endpoints, list):
        print("[ERROR] endpoints_file must be a JSON array.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(endpoints)} endpoints. Auth-required filter will reduce this.")
    print(f"[*] User A ID: {id_a}  |  User B ID: {id_b}")
    print(f"[*] Rate limit: {RATE_LIMIT_DELAY}s between requests\n")

    results = run_idor_scan(endpoints, token_a, id_a, token_b, id_b)

    output_json = json.dumps(results, indent=2)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output_json)
        print(f"\n[+] Results written to {args.out}")
        print(f"[+] Tested: {results['tested']} endpoints")
        print(f"[+] IDOR candidates: {results['candidates']}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
