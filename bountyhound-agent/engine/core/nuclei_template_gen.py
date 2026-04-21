"""
nuclei_template_gen.py — Generate custom nuclei templates from target-model.json.

CLI:
  python nuclei_template_gen.py <target_model.json> [--out-dir <dir>]
  echo '{"tech_stack":[...]}' | python nuclei_template_gen.py - [--out-dir <dir>]
"""

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

AGENT = Path(__file__).resolve().parents[2]
DB_PATH = AGENT / "data" / "bountyhound.db"
# Also check CODEX DB which has the real CVE data
CODEX_DB = AGENT / "data" / "CODEXDATABASE.db"

DEFAULT_OUT_DIR = AGENT.parent / "findings" / "tmp" / "custom-templates"


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _sanitize_id(value: str) -> str:
    """Strip characters that are invalid in nuclei template IDs."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "-", value).lower()


# ---------------------------------------------------------------------------
# CVE lookup
# ---------------------------------------------------------------------------

def _query_cves(
    tech: str,
    version: str,
) -> list[dict[str, Any]]:
    """Return up to 5 CVEs from the CODEX/bountyhound DB matching tech+version."""
    results: list[dict[str, Any]] = []

    # Try CODEX first, fall back to bountyhound.db
    for db_path in (CODEX_DB, DB_PATH):
        if not db_path.exists():
            continue
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            # Detect which table holds CVE data
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            cve_table = next(
                (t for t in ("cves", "CVE", "vulnerabilities") if t in tables),
                None,
            )
            if cve_table is None:
                conn.close()
                continue

            col_info = conn.execute(f"PRAGMA table_info({cve_table})").fetchall()
            col_names = {row[1] for row in col_info}

            # Build query dynamically based on available columns
            id_col = next(
                (c for c in ("cve_id", "cve", "id") if c in col_names),
                None,
            )
            desc_col = next(
                (c for c in ("description", "summary", "desc") if c in col_names),
                None,
            )
            score_col = next(
                (c for c in ("cvss_score", "cvss", "base_score") if c in col_names),
                None,
            )
            prod_col = next(
                (
                    c
                    for c in ("affected_products_json", "affected_products", "products")
                    if c in col_names
                ),
                None,
            )

            if not id_col:
                conn.close()
                continue

            select_parts = [id_col]
            if desc_col:
                select_parts.append(desc_col)
            if score_col:
                select_parts.append(score_col)

            select_clause = ", ".join(select_parts)

            if prod_col:
                query = (
                    f"SELECT {select_clause} FROM {cve_table} "
                    f"WHERE {prod_col} LIKE ? AND {prod_col} LIKE ? "
                    f"ORDER BY {score_col if score_col else id_col} DESC LIMIT 5"
                )
                params = (f"%{tech}%", f"%{version}%")
            else:
                # No products column — do a best-effort description search
                if desc_col:
                    query = (
                        f"SELECT {select_clause} FROM {cve_table} "
                        f"WHERE {desc_col} LIKE ? AND {desc_col} LIKE ? "
                        f"ORDER BY {score_col if score_col else id_col} DESC LIMIT 5"
                    )
                    params = (f"%{tech}%", f"%{version}%")
                else:
                    conn.close()
                    continue

            rows = conn.execute(query, params).fetchall()
            for row in rows:
                d = dict(row)
                results.append(
                    {
                        "cve_id": d.get(id_col, ""),
                        "description": d.get(desc_col or "", "No description"),
                        "cvss_score": d.get(score_col or "", None),
                    }
                )
            conn.close()
            if results:
                break
        except sqlite3.Error:
            continue

    return results


# ---------------------------------------------------------------------------
# Template generation
# ---------------------------------------------------------------------------

_VERSION_PROBE_PATH_GUESSES: dict[str, list[str]] = {
    "nextcloud": ["/status.php", "/ocs/v1.php?format=json"],
    "wordpress": ["/wp-login.php", "/readme.html", "/?v={version}"],
    "drupal": ["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
    "jira": ["/rest/api/2/serverInfo", "/WEB-INF/web.xml"],
    "confluence": ["/rest/api/space", "/status"],
    "jenkins": ["/api/json", "/login?from=%2F"],
    "gitlab": ["/-/health", "/api/v4/version"],
    "grafana": ["/api/health", "/login"],
    "nginx": ["/nginx_status"],
    "apache": ["/server-status"],
    "default": ["/", "/version", "/info", "/api/version"],
}


def _version_probe_paths(tech: str) -> list[str]:
    tech_lower = tech.lower()
    for key, paths in _VERSION_PROBE_PATH_GUESSES.items():
        if key in tech_lower:
            return paths
    return _VERSION_PROBE_PATH_GUESSES["default"]


def _make_cve_template(
    cve_id: str,
    tech: str,
    version: str,
    description: str,
    cvss_score: float | None,
) -> str:
    severity = _cvss_to_severity(cvss_score)
    template_id = _sanitize_id(f"{cve_id}-{tech}")
    paths = _version_probe_paths(tech)
    path_lines = "\n".join(f'      - "{{{{BaseURL}}}}{p}"' for p in paths[:3])

    # Version string as a disclosure word — nuclei won't fire unless the
    # version appears in the response, avoiding wild false positives.
    version_word = version.replace('"', "'")

    return f"""\
id: {template_id}
info:
  name: "{cve_id} - {tech} {version}"
  author: bountyhound
  severity: {severity}
  description: |
    {description[:200].replace(chr(10), ' ')}
  tags: cve,{_sanitize_id(tech)},{severity}
  reference:
    - https://nvd.nist.gov/vuln/detail/{cve_id}

requests:
  - method: GET
    path:
{path_lines}
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "{version_word}"
        part: body
      - type: status
        status:
          - 200
          - 302
"""


def _make_version_probe_template(tech: str, version: str) -> str:
    template_id = _sanitize_id(f"version-disclosure-{tech}")
    paths = _version_probe_paths(tech)
    path_lines = "\n".join(f'      - "{{{{BaseURL}}}}{p}"' for p in paths[:3])
    version_word = version.replace('"', "'")

    return f"""\
id: {template_id}
info:
  name: "Version Disclosure — {tech} {version}"
  author: bountyhound
  severity: info
  description: |
    Detects whether {tech} version {version} is exposed in the HTTP response.
    Version disclosure aids attackers in targeting CVE-specific exploits.
  tags: disclosure,{_sanitize_id(tech)},version

requests:
  - method: GET
    path:
{path_lines}
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "{version_word}"
        part: body
      - type: status
        status:
          - 200
"""


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def generate_templates(
    target_model: dict[str, Any],
    out_dir: Path,
) -> list[dict[str, str]]:
    """
    Generate nuclei templates for each tech stack entry in target_model.

    Returns a list of dicts: {path, cve_id_or_type, tech, version}.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    tech_stack: list[dict[str, str]] = target_model.get("tech_stack", [])

    if not tech_stack:
        print("[nuclei_template_gen] WARNING: tech_stack is empty in target model.")

    generated: list[dict[str, str]] = []

    for entry in tech_stack:
        tech = entry.get("name", "").strip()
        version = entry.get("version", "").strip()

        if not tech or not version:
            continue

        cves = _query_cves(tech, version)

        if cves:
            for cve in cves:
                cve_id = cve["cve_id"]
                if not cve_id:
                    continue
                content = _make_cve_template(
                    cve_id=cve_id,
                    tech=tech,
                    version=version,
                    description=cve.get("description", ""),
                    cvss_score=cve.get("cvss_score"),
                )
                out_path = out_dir / f"{_sanitize_id(cve_id)}.yaml"
                out_path.write_text(content, encoding="utf-8")
                generated.append(
                    {
                        "path": str(out_path),
                        "type": "CVE",
                        "cve_id": cve_id,
                        "tech": tech,
                        "version": version,
                        "cvss": str(cve.get("cvss_score", "N/A")),
                    }
                )
        else:
            # No CVEs found — generate version-disclosure probe
            content = _make_version_probe_template(tech, version)
            out_path = out_dir / f"probe-{_sanitize_id(tech)}.yaml"
            out_path.write_text(content, encoding="utf-8")
            generated.append(
                {
                    "path": str(out_path),
                    "type": "version-probe",
                    "cve_id": "",
                    "tech": tech,
                    "version": version,
                    "cvss": "",
                }
            )

    return generated


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate custom nuclei templates from target-model.json."
    )
    parser.add_argument(
        "target_model",
        help="Path to target-model.json, or '-' to read from stdin",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help=f"Directory to write .yaml templates (default: {DEFAULT_OUT_DIR})",
    )
    args = parser.parse_args()

    # Load target model
    if args.target_model == "-":
        raw = sys.stdin.read()
    else:
        path = Path(args.target_model)
        if not path.exists():
            print(f"[nuclei_template_gen] ERROR: File not found: {path}", file=sys.stderr)
            sys.exit(1)
        raw = path.read_text(encoding="utf-8")

    try:
        model = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[nuclei_template_gen] ERROR: Invalid JSON — {exc}", file=sys.stderr)
        sys.exit(1)

    results = generate_templates(model, args.out_dir)

    if not results:
        print("[nuclei_template_gen] No templates generated (no versioned tech stack entries).")
        return

    print(f"\nGenerated {len(results)} template(s) -> {args.out_dir}\n")
    header = f"{'Type':<14} {'CVE/ID':<20} {'Tech':<20} {'Version':<12} {'CVSS':<6} Path"
    print(header)
    print("-" * len(header))
    for r in results:
        label = r["cve_id"] if r["type"] == "CVE" else f"probe-{r['tech']}"
        print(
            f"{r['type']:<14} {label:<20} {r['tech']:<20} "
            f"{r['version']:<12} {r['cvss']:<6} {r['path']}"
        )
    print()


if __name__ == "__main__":
    main()
