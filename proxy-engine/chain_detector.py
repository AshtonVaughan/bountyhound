"""Vulnerability Chain Detection — automatic multi-step attack path detection.

Patterns:
- Open Redirect + XSS → phishing
- SSRF + metadata → RCE
- IDOR + PII → breach
- CSRF + privesc
- SSTI + path traversal
"""

from __future__ import annotations

from models import ScanFinding


# Chain pattern definitions
CHAIN_PATTERNS = [
    {
        "name": "Open Redirect → XSS → Account Takeover",
        "severity": "high",
        "steps": [
            {"vuln_types": ["open_redirect", "redirect"], "role": "entry"},
            {"vuln_types": ["xss", "cross-site scripting", "reflected xss", "stored xss"], "role": "payload"},
        ],
        "impact": "Attacker can redirect victim to malicious page with XSS payload, stealing session tokens.",
        "exploitability": "easy",
    },
    {
        "name": "SSRF → Cloud Metadata → RCE/Credential Theft",
        "severity": "critical",
        "steps": [
            {"vuln_types": ["ssrf", "server-side request forgery"], "role": "entry"},
            {"vuln_types": ["information_disclosure", "cloud", "metadata", "aws", "gcp"], "role": "escalation"},
        ],
        "impact": "SSRF can access cloud metadata service (169.254.169.254) to steal IAM credentials.",
        "exploitability": "moderate",
    },
    {
        "name": "IDOR → PII Exposure → Data Breach",
        "severity": "critical",
        "steps": [
            {"vuln_types": ["idor", "insecure direct object", "authorization", "access control", "bola"], "role": "entry"},
        ],
        "impact": "Unauthorized access to other users' data, potential mass data exfiltration.",
        "exploitability": "easy",
        "amplification": "If IDOR returns PII (email, phone, SSN), this becomes a reportable data breach.",
    },
    {
        "name": "CSRF → Privilege Escalation",
        "severity": "high",
        "steps": [
            {"vuln_types": ["csrf", "cross-site request forgery"], "role": "entry"},
        ],
        "impact": "Force authenticated user to perform privileged actions (role change, password reset).",
        "exploitability": "moderate",
        "amplification": "Combine with XSS for self-propagating attack.",
    },
    {
        "name": "SSTI → Path Traversal → RCE",
        "severity": "critical",
        "steps": [
            {"vuln_types": ["ssti", "server-side template injection", "template injection"], "role": "entry"},
            {"vuln_types": ["path_traversal", "lfi", "local file inclusion", "directory traversal"], "role": "amplifier"},
        ],
        "impact": "Template injection can read arbitrary files and execute system commands.",
        "exploitability": "moderate",
    },
    {
        "name": "SQL Injection → Authentication Bypass → Admin Access",
        "severity": "critical",
        "steps": [
            {"vuln_types": ["sqli", "sql injection", "sql_injection"], "role": "entry"},
        ],
        "impact": "SQL injection in auth endpoint can bypass authentication entirely.",
        "exploitability": "easy",
        "amplification": "If on login page, can extract all user credentials.",
    },
    {
        "name": "XSS → Session Hijack → Account Takeover",
        "severity": "high",
        "steps": [
            {"vuln_types": ["stored xss", "persistent xss"], "role": "entry"},
        ],
        "impact": "Stored XSS steals session cookies from all users who view the page.",
        "exploitability": "easy",
    },
    {
        "name": "File Upload → Web Shell → RCE",
        "severity": "critical",
        "steps": [
            {"vuln_types": ["file upload", "unrestricted upload", "upload"], "role": "entry"},
        ],
        "impact": "Upload malicious file to gain remote code execution on the server.",
        "exploitability": "easy",
    },
    {
        "name": "CORS Misconfiguration → Data Theft",
        "severity": "medium",
        "steps": [
            {"vuln_types": ["cors", "cross-origin"], "role": "entry"},
        ],
        "impact": "Malicious site can read API responses with victim's credentials.",
        "exploitability": "moderate",
    },
    {
        "name": "JWT Weakness → Authentication Bypass",
        "severity": "high",
        "steps": [
            {"vuln_types": ["jwt", "json web token", "weak token", "none algorithm"], "role": "entry"},
        ],
        "impact": "Forge JWT tokens to impersonate any user.",
        "exploitability": "easy",
    },
]


def detect_chains(findings: list[dict] | None = None, scan_ids: list[str] | None = None) -> dict:
    """Detect vulnerability chains from findings across all scans."""
    from state import state

    all_findings = []

    if findings:
        all_findings = findings
    elif scan_ids:
        for sid in scan_ids:
            job = state.scanner_jobs.get(sid)
            if job:
                all_findings.extend([f.model_dump() for f in job.findings])
    else:
        # All findings from all scans
        for job in state.scanner_jobs.values():
            all_findings.extend([f.model_dump() for f in job.findings])
        # Include passive findings
        try:
            import passive_scanner
            all_findings.extend([f.model_dump() for f in passive_scanner.findings])
        except ImportError:
            pass

    if not all_findings:
        return {"chains": [], "total_findings": 0}

    # Categorize findings by type
    categorized = _categorize_findings(all_findings)

    # Match against chain patterns
    detected_chains = []
    for pattern in CHAIN_PATTERNS:
        chain = _match_pattern(pattern, categorized, all_findings)
        if chain:
            detected_chains.append(chain)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    detected_chains.sort(key=lambda c: sev_order.get(c["severity"], 5))

    return {
        "chains": detected_chains,
        "total_findings": len(all_findings),
        "categories": {k: len(v) for k, v in categorized.items()},
    }


def _categorize_findings(findings: list[dict]) -> dict[str, list[dict]]:
    """Categorize findings by vulnerability type."""
    categories: dict[str, list[dict]] = {}

    for f in findings:
        name = (f.get("name", "") + " " + f.get("template_id", "")).lower()
        # Map to known types
        for vuln_type in _ALL_VULN_TYPES:
            if vuln_type in name:
                categories.setdefault(vuln_type, []).append(f)

    return categories


def _match_pattern(pattern: dict, categorized: dict, all_findings: list) -> dict | None:
    """Check if findings match a chain pattern."""
    matched_findings = []

    for step in pattern["steps"]:
        step_matched = []
        for vuln_type in step["vuln_types"]:
            if vuln_type in categorized:
                step_matched.extend(categorized[vuln_type])

        if not step_matched:
            return None

        matched_findings.extend(step_matched)

    # Deduplicate
    seen = set()
    unique = []
    for f in matched_findings:
        key = f"{f.get('name')}|{f.get('url')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "name": pattern["name"],
        "severity": pattern["severity"],
        "impact": pattern["impact"],
        "exploitability": pattern.get("exploitability", "moderate"),
        "amplification": pattern.get("amplification", ""),
        "findings": unique[:10],  # Top 10 relevant findings
        "finding_count": len(unique),
        "steps": [
            {
                "role": s["role"],
                "matched_types": [vt for vt in s["vuln_types"] if vt in categorized],
            }
            for s in pattern["steps"]
        ],
    }


# All known vulnerability type keywords for categorization
_ALL_VULN_TYPES = {
    "sqli", "sql injection", "sql_injection",
    "xss", "cross-site scripting", "reflected xss", "stored xss", "persistent xss",
    "csrf", "cross-site request forgery",
    "ssrf", "server-side request forgery",
    "ssti", "server-side template injection", "template injection",
    "idor", "insecure direct object", "authorization", "access control", "bola",
    "open_redirect", "redirect",
    "path_traversal", "lfi", "local file inclusion", "directory traversal",
    "file upload", "unrestricted upload", "upload",
    "cors", "cross-origin",
    "jwt", "json web token", "weak token", "none algorithm",
    "information_disclosure", "cloud", "metadata", "aws", "gcp",
    "rce", "remote code", "command injection",
    "xxe", "xml external entity",
    "deserialization",
}
