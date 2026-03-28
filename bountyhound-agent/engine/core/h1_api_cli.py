#!/usr/bin/env python3
"""CLI wrapper for H1Submitter — call from agent Bash blocks."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from engine.core.h1_submitter import H1Submitter, H1Report
    from engine.core.h1_disclosed_checker import H1DisclosedChecker
except ImportError as e:
    print(f"SETUP REQUIRED: Cannot import H1 modules — {e}")
    print("Run: pip install -r requirements/requirements.txt")
    sys.exit(1)

USAGE = """
Usage:
  python h1_api_cli.py submit <program_handle> <report_json_file> [file1.png file2.gif ...]
  python h1_api_cli.py status
  python h1_api_cli.py my-reports [program_handle]
  python h1_api_cli.py check-disclosed <program> <finding_json_file>
  python h1_api_cli.py lookup-weakness <program_handle> [vuln_type]
  python h1_api_cli.py lookup-scope <program_handle> [target_url]

Notes:
  submit      — Files are optional. When provided, uses the Report Intents workflow
                (create draft → upload files → submit). Without files, uses direct
                POST /hackers/reports endpoint.
  lookup-weakness — List all weakness IDs accepted by the program, or resolve a specific
                    vuln_type (e.g. "sqli", "xss") to its H1-internal ID.
  lookup-scope    — List all structured scopes, or resolve a target URL to its scope ID.
""".strip()


def cmd_status() -> None:
    """Check H1 credentials and account status."""
    submitter = H1Submitter()
    status = submitter.status()

    if not status["ready"]:
        result = {
            "ready": False,
            "error": "H1_API_TOKEN and H1_USERNAME environment variables not set",
            "has_api_token": status["has_api_token"],
            "has_username": status["has_username"],
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    # Verify credentials are live
    me = submitter.check_balance()
    result = {
        "ready": True,
        "has_api_token": True,
        "has_username": True,
        "account": me,
    }
    print(json.dumps(result, indent=2))


def cmd_submit(program_handle: str, report_json_file: str, file_paths: list = None) -> None:
    """Load finding JSON and submit to HackerOne.

    Uses prepare_report() which resolves weakness and scope IDs dynamically from the
    program's actual lists — more accurate than the static WEAKNESS_MAP fallback.

    If file_paths are provided, uses the Report Intents workflow so screenshots/GIFs
    are actually uploaded as attachments (not just listed as text paths in the report body).
    Without files, uses the direct POST /hackers/reports endpoint.
    """
    path = Path(report_json_file)
    if not path.exists():
        print(json.dumps({"success": False, "error": f"File not found: {report_json_file}"}))
        sys.exit(1)

    try:
        finding = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(json.dumps({"success": False, "error": f"Invalid JSON: {e}"}))
        sys.exit(1)

    submitter = H1Submitter()
    if not submitter.status()["ready"]:
        print(json.dumps({
            "success": False,
            "error": "H1_API_TOKEN and H1_USERNAME environment variables required",
        }))
        sys.exit(1)

    # prepare_report() resolves weakness/scope IDs dynamically from the program's actual lists
    report = submitter.prepare_report(finding, program_handle)

    if file_paths:
        # Report Intents flow: supports actual file attachment uploads
        print(json.dumps({"info": f"Submitting via Report Intents (uploading {len(file_paths)} file(s))"}))
        result = submitter.submit_report_with_attachments(program_handle, report, file_paths)
    else:
        # Direct submission: no attachments, faster
        result = submitter.submit_report(program_handle, report)

    output = {
        "success": result.success,
        "report_id": result.report_id,
        "report_url": result.report_url,
        "error": result.error,
    }
    print(json.dumps(output, indent=2))
    if not result.success:
        sys.exit(1)


def cmd_my_reports(program_handle: str = None) -> None:
    """List submitted reports, optionally filtered by program."""
    submitter = H1Submitter()
    if not submitter.status()["ready"]:
        print(json.dumps({
            "error": "H1_API_TOKEN and H1_USERNAME environment variables required",
            "reports": [],
        }))
        sys.exit(1)

    reports = submitter.get_my_reports(program_handle=program_handle)

    simplified = []
    for r in reports:
        attrs = r.get("attributes", {})
        simplified.append({
            "id": r.get("id"),
            "title": attrs.get("title", ""),
            "state": attrs.get("state", ""),
            "severity": attrs.get("severity_rating", ""),
            "created_at": attrs.get("created_at", ""),
            "url": f"https://hackerone.com/reports/{r.get('id', '')}",
        })

    print(json.dumps({"reports": simplified, "count": len(simplified)}, indent=2))


def cmd_check_disclosed(program: str, finding_json_file: str) -> None:
    """Check a finding against publicly disclosed H1 reports."""
    path = Path(finding_json_file)
    if not path.exists():
        print(json.dumps({
            "is_duplicate": False,
            "error": f"File not found: {finding_json_file}",
            "recommendation": "PROCEED - could not load finding file",
        }))
        sys.exit(1)

    try:
        finding = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(json.dumps({
            "is_duplicate": False,
            "error": f"Invalid JSON: {e}",
            "recommendation": "PROCEED - could not parse finding file",
        }))
        sys.exit(1)

    checker = H1DisclosedChecker()

    # If no credentials: skip gracefully
    if not checker.api_token or not checker.username:
        print(json.dumps({
            "is_duplicate": False,
            "skipped": True,
            "reason": "No H1_API_TOKEN/H1_USERNAME — dedup check skipped",
            "recommendation": "PROCEED - no credentials for dedup check",
        }))
        return

    result = checker.check_against_disclosed(finding, program, use_cache=True)

    # Add similarity score to top-level for easy shell parsing
    matches = result.get("matches", [])
    top_score = matches[0].get("similarity_score", 0.0) if matches else 0.0
    top_id = matches[0].get("id") if matches else None

    output = {
        "is_duplicate": result.get("is_duplicate", False),
        "similarity_score": round(top_score, 4),
        "matched_report_id": top_id,
        "match_type": result.get("match_type"),
        "matches": matches[:3],  # top 3 only to keep output compact
        "recommendation": result.get("recommendation", "PROCEED"),
    }
    print(json.dumps(output, indent=2))
    if result.get("is_duplicate"):
        sys.exit(2)  # exit 2 = duplicate (distinct from exit 1 = error)


def cmd_lookup_weakness(program_handle: str, vuln_type: str = None) -> None:
    """
    List weakness IDs for a program, or resolve a specific vuln_type to its H1-internal ID.

    Use this before building finding-draft.json so weakness_id is the actual H1 integer,
    not a CWE number (which is what the static WEAKNESS_MAP contains).

    Examples:
      lookup-weakness exness            — list all weaknesses for the program
      lookup-weakness exness sqli       — resolve "sqli" → H1-internal weakness ID
    """
    submitter = H1Submitter()
    if not submitter.status()["ready"]:
        print(json.dumps({"error": "H1_API_TOKEN and H1_USERNAME environment variables required"}))
        sys.exit(1)

    weaknesses = submitter.get_program_weaknesses(program_handle)
    if not weaknesses:
        print(json.dumps({
            "program": program_handle,
            "weaknesses": [],
            "note": "No weaknesses returned — check program handle and credentials",
        }))
        return

    if vuln_type:
        resolved_id = submitter.resolve_weakness_id(program_handle, vuln_type)
        matched = next((w for w in weaknesses if w['id'] == resolved_id), None)
        print(json.dumps({
            "program": program_handle,
            "vuln_type": vuln_type,
            "resolved_weakness_id": resolved_id,
            "matched_weakness": matched,
            "note": "Use this ID in finding-draft.json weakness_id field",
        }, indent=2))
    else:
        print(json.dumps({
            "program": program_handle,
            "count": len(weaknesses),
            "weaknesses": weaknesses,
        }, indent=2))


def cmd_lookup_scope(program_handle: str, target_url: str = None) -> None:
    """
    List structured scopes for a program, or resolve a target URL to its scope ID.

    Use this before building finding-draft.json so structured_scope_id is set correctly,
    which links the report to the specific asset and enables accurate bounty calculation.

    Examples:
      lookup-scope exness                        — list all scopes
      lookup-scope exness my.exnessaffiliates.com — resolve URL → scope ID
    """
    submitter = H1Submitter()
    if not submitter.status()["ready"]:
        print(json.dumps({"error": "H1_API_TOKEN and H1_USERNAME environment variables required"}))
        sys.exit(1)

    scopes = submitter.get_structured_scopes(program_handle)
    if not scopes:
        print(json.dumps({
            "program": program_handle,
            "scopes": [],
            "note": "No scopes returned — check program handle and credentials",
        }))
        return

    if target_url:
        resolved_id = submitter.resolve_scope_id(program_handle, target_url)
        matched = next((s for s in scopes if s['id'] == resolved_id), None)
        print(json.dumps({
            "program": program_handle,
            "target_url": target_url,
            "resolved_scope_id": resolved_id,
            "matched_scope": matched,
            "note": "Use this ID in finding-draft.json structured_scope_id field",
        }, indent=2))
    else:
        print(json.dumps({
            "program": program_handle,
            "count": len(scopes),
            "scopes": scopes,
        }, indent=2))


def main() -> None:
    args = sys.argv[1:]

    if not args:
        print(USAGE)
        sys.exit(1)

    command = args[0]

    if command == "status":
        cmd_status()

    elif command == "submit":
        if len(args) < 3:
            print("Usage: h1_api_cli.py submit <program_handle> <report_json_file> [file1 file2 ...]")
            sys.exit(1)
        # args[3:] are optional file attachments (screenshots, GIFs, reproduce.py)
        cmd_submit(args[1], args[2], file_paths=args[3:] if len(args) > 3 else None)

    elif command == "my-reports":
        program = args[1] if len(args) > 1 else None
        cmd_my_reports(program)

    elif command == "check-disclosed":
        if len(args) < 3:
            print("Usage: h1_api_cli.py check-disclosed <program> <finding_json_file>")
            sys.exit(1)
        cmd_check_disclosed(args[1], args[2])

    elif command == "lookup-weakness":
        if len(args) < 2:
            print("Usage: h1_api_cli.py lookup-weakness <program_handle> [vuln_type]")
            sys.exit(1)
        vuln_type = args[2] if len(args) > 2 else None
        cmd_lookup_weakness(args[1], vuln_type)

    elif command == "lookup-scope":
        if len(args) < 2:
            print("Usage: h1_api_cli.py lookup-scope <program_handle> [target_url]")
            sys.exit(1)
        target_url = args[2] if len(args) > 2 else None
        cmd_lookup_scope(args[1], target_url)

    else:
        print(f"Unknown command: {command}\n\n{USAGE}")
        sys.exit(1)


if __name__ == "__main__":
    main()
