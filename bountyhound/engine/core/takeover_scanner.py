#!/usr/bin/env python3
"""
takeover_scanner.py — Check subdomains for takeover conditions.

Resolves CNAME chains for each subdomain and checks whether the
pointed-to service is unclaimed (returns a known error fingerprint).

CLI:
    python takeover_scanner.py <subdomains_file> [--out <file>]

Output JSON:
    {
        "vulnerable": [{"subdomain", "cname", "service", "confidence"}],
        "checked": N,
        "skipped": N
    }
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Takeover fingerprint database
# {service_name: (cname_pattern, verification_string)}
# cname_pattern is a substring matched against the resolved CNAME
# ---------------------------------------------------------------------------

FINGERPRINTS: dict[str, tuple[str, str]] = {
    "GitHub Pages":  ("github.io",          "There isn't a GitHub Pages site here"),
    "Heroku":        ("herokuapp.com",       "No such app"),
    "Netlify":       ("netlify.app",         "Not found"),
    "S3 (bucket)":   ("s3.amazonaws.com",    "NoSuchBucket"),
    "S3 (website)":  ("s3-website",         "NoSuchBucket"),
    "Azure":         ("azurewebsites.net",   "404 Web Site not found"),
    "Azure Cloud":   ("cloudapp.net",        "404 Web Site not found"),
    "Fastly":        ("fastly.net",          "Fastly error: unknown domain"),
    "Shopify":       ("myshopify.com",       "Sorry, this shop is currently unavailable"),
    "Surge":         ("surge.sh",            "project not found"),
    "Ghost":         ("ghost.io",            "The thing you were looking for is no longer here"),
    "Pantheon":      ("pantheonsite.io",     "404 error unknown site!"),
    "Zendesk":       ("zendesk.com",         "Help Center Closed"),
}

_HTTP_TIMEOUT: int = 10
_FETCH_HEADERS: dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (compatible; BountyHound/1.0)"
}

# ---------------------------------------------------------------------------
# DNS resolution via nslookup (cross-platform)
# Falls back to direct CNAME probe on failure
# ---------------------------------------------------------------------------


def _resolve_cname(subdomain: str) -> str | None:
    """
    Resolve the CNAME chain for a subdomain.
    Returns the final CNAME target (as a string) or None if resolution fails
    or the record is an A/AAAA (not a CNAME).
    """
    # Try nslookup first (available on Windows and Linux)
    try:
        result = subprocess.run(
            ["nslookup", "-type=CNAME", subdomain],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        # nslookup output: "canonical name = <target>"
        for line in output.splitlines():
            line = line.strip().lower()
            if "canonical name" in line or "cname" in line:
                # Extract everything after the last '='
                parts = line.split("=")
                if len(parts) >= 2:
                    cname = parts[-1].strip().rstrip(".")
                    if cname:
                        return cname
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Fallback: try `dig` (Linux/macOS)
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", subdomain],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip()
        if output and not output.startswith(";"):
            # dig +short CNAME returns just the target
            lines = [l.strip().rstrip(".") for l in output.splitlines() if l.strip()]
            if lines:
                return lines[-1]  # Last hop in the chain
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return None


def _match_service(cname: str) -> list[tuple[str, str]]:
    """
    Return list of (service_name, verification_string) for all fingerprints
    whose cname_pattern is present in the resolved CNAME.
    """
    cname_lower = cname.lower()
    matches: list[tuple[str, str]] = []
    for service, (pattern, verify_str) in FINGERPRINTS.items():
        if pattern.lower() in cname_lower:
            matches.append((service, verify_str))
    return matches


def _fetch_body(subdomain: str) -> str | None:
    """
    Fetch the HTTP(S) response body for a subdomain.
    Tries HTTPS first, then HTTP on failure.
    Returns body text or None.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                headers=_FETCH_HEADERS,
                timeout=_HTTP_TIMEOUT,
                allow_redirects=True,
                verify=False,  # Many dangling subdomains have expired certs
            )
            return resp.text
        except requests.RequestException:
            continue
    return None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan(subdomains: list[str]) -> dict[str, Any]:
    """
    Scan a list of subdomains for takeover conditions.
    Returns the result dict.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    vulnerable: list[dict[str, Any]] = []
    checked: int = 0
    skipped: int = 0

    for subdomain in subdomains:
        subdomain = subdomain.strip()
        if not subdomain or subdomain.startswith("#"):
            skipped += 1
            continue

        checked += 1

        # Step 1: Resolve CNAME
        cname = _resolve_cname(subdomain)
        if not cname:
            # No CNAME — A/AAAA record or unresolvable; skip
            continue

        # Step 2: Match against known fingerprints
        service_matches = _match_service(cname)
        if not service_matches:
            continue

        # Step 3: Fetch the subdomain and verify
        body = _fetch_body(subdomain)
        if body is None:
            # Could not reach it — still worth noting as low-confidence
            for service, _ in service_matches:
                vulnerable.append({
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "confidence": "low",
                    "note": "CNAME matched but host unreachable",
                })
            continue

        body_lower = body.lower()
        for service, verify_str in service_matches:
            if verify_str.lower() in body_lower:
                vulnerable.append({
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "confidence": "high",
                })
            else:
                # CNAME matched but verification string not in body
                # Could be a false positive or a partial claim
                vulnerable.append({
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "confidence": "medium",
                    "note": "CNAME matched but verification string not found in body",
                })

    return {
        "vulnerable": vulnerable,
        "checked": checked,
        "skipped": skipped,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check subdomains for takeover conditions."
    )
    parser.add_argument(
        "subdomains_file",
        help="Path to file with subdomains (one per line)",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout",
    )
    args = parser.parse_args()

    sub_path = Path(args.subdomains_file)
    if not sub_path.exists():
        print(f"ERROR: File not found: {sub_path}", file=sys.stderr)
        sys.exit(1)

    subdomains = sub_path.read_text(encoding="utf-8").splitlines()
    result = scan(subdomains)
    output = json.dumps(result, indent=2)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(
            f"Checked {result['checked']} subdomains — "
            f"{len(result['vulnerable'])} vulnerable, "
            f"{result['skipped']} skipped. "
            f"Written to {args.out}",
            file=sys.stderr,
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
