"""Scan Comparison — diff two scans by dedup_key to show new/resolved/unchanged findings."""

from __future__ import annotations

from state import state
from models import ScanFinding


def compare_scans(scan_id_a: str, scan_id_b: str) -> dict:
    """Compare two scan jobs and categorize findings as new, resolved, or unchanged.

    scan_id_a: baseline (older) scan
    scan_id_b: current (newer) scan
    """
    job_a = state.scanner_jobs.get(scan_id_a)
    job_b = state.scanner_jobs.get(scan_id_b)

    if not job_a:
        return {"error": f"Scan {scan_id_a} not found"}
    if not job_b:
        return {"error": f"Scan {scan_id_b} not found"}

    # Build dedup_key maps
    findings_a = _build_key_map(job_a.findings)
    findings_b = _build_key_map(job_b.findings)

    keys_a = set(findings_a.keys())
    keys_b = set(findings_b.keys())

    new_keys = keys_b - keys_a
    resolved_keys = keys_a - keys_b
    unchanged_keys = keys_a & keys_b

    # Check for severity changes in unchanged
    changed = []
    truly_unchanged = []
    for key in unchanged_keys:
        fa = findings_a[key]
        fb = findings_b[key]
        if fa.severity != fb.severity:
            changed.append({
                "finding": fb.model_dump(),
                "old_severity": fa.severity,
                "new_severity": fb.severity,
            })
        else:
            truly_unchanged.append(fb.model_dump())

    return {
        "scan_a": scan_id_a,
        "scan_b": scan_id_b,
        "summary": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "changed": len(changed),
            "unchanged": len(truly_unchanged),
        },
        "new": [findings_b[k].model_dump() for k in new_keys],
        "resolved": [findings_a[k].model_dump() for k in resolved_keys],
        "changed": changed,
        "unchanged": truly_unchanged,
    }


def _build_key_map(findings: list[ScanFinding]) -> dict[str, ScanFinding]:
    """Build a map from dedup_key -> finding, using generated key if none set."""
    result = {}
    for f in findings:
        key = f.dedup_key or _generate_dedup_key(f)
        if key not in result:
            result[key] = f
    return result


def _generate_dedup_key(finding: ScanFinding) -> str:
    """Generate a dedup key from finding attributes."""
    from urllib.parse import urlparse
    parsed = urlparse(finding.url)
    # Normalize: template_id + host + path + name
    return f"{finding.template_id or finding.name}|{parsed.hostname or ''}|{parsed.path}|{finding.severity}"
