"""AI-Assisted Analysis — LLM-powered triage, scope suggestions, exploit gen, reports.

Uses security LLM finetune or falls back to manual heuristics.
"""

from __future__ import annotations

import json
import logging
import subprocess
import httpx
from models import ScanFinding

log = logging.getLogger("proxy-engine.ai")

# LLM endpoint (security-llm-finetune via vLLM/LiteLLM, or local API)
LLM_ENDPOINT = "http://127.0.0.1:8000/v1/chat/completions"
LLM_MODEL = "qwen32b-security"
LLM_AVAILABLE = False


async def _llm_call(system: str, user: str, max_tokens: int = 2000) -> str | None:
    """Call LLM endpoint. Returns None if unavailable."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(LLM_ENDPOINT, json={
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.2,
            })
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
    except Exception as e:
        log.debug(f"LLM call failed: {e}")
    return None


async def triage_finding(finding: dict) -> dict:
    """AI-powered finding triage: severity, exploitability, business impact."""
    system = """You are an expert security analyst. Analyze this vulnerability finding and provide:
1. severity_assessment: Your assessment of the true severity (critical/high/medium/low/info)
2. exploitability: How easy it is to exploit (trivial/easy/moderate/difficult/theoretical)
3. business_impact: Potential business impact description
4. false_positive_likelihood: Probability this is a false positive (low/medium/high)
5. recommended_action: What to do about this finding
6. additional_tests: Suggested follow-up tests

Respond in JSON format."""

    user = json.dumps(finding, indent=2, default=str)

    llm_result = await _llm_call(system, user)
    if llm_result:
        try:
            return {"ai_triage": json.loads(llm_result), "source": "llm"}
        except json.JSONDecodeError:
            return {"ai_triage": {"raw_analysis": llm_result}, "source": "llm"}

    # Heuristic fallback
    return _heuristic_triage(finding)


def _heuristic_triage(finding: dict) -> dict:
    """Rule-based triage when LLM is unavailable."""
    severity = finding.get("severity", "info").lower()
    name = finding.get("name", "").lower()
    url = finding.get("url", "")

    exploitability = "moderate"
    fp_likelihood = "medium"

    if any(k in name for k in ("sql injection", "sqli", "command injection", "rce", "remote code")):
        exploitability = "easy"
        fp_likelihood = "low"
    elif any(k in name for k in ("xss", "cross-site scripting")):
        exploitability = "easy"
        fp_likelihood = "medium"
    elif any(k in name for k in ("information disclosure", "version", "header")):
        exploitability = "trivial"
        fp_likelihood = "low"
    elif any(k in name for k in ("csrf", "cors")):
        exploitability = "moderate"
        fp_likelihood = "medium"

    if finding.get("confidence") == "confirmed":
        fp_likelihood = "low"
    elif finding.get("confidence") == "tentative":
        fp_likelihood = "high"

    return {
        "ai_triage": {
            "severity_assessment": severity,
            "exploitability": exploitability,
            "false_positive_likelihood": fp_likelihood,
            "recommended_action": f"Verify and exploit {name}" if severity in ("critical", "high") else f"Review {name}",
            "additional_tests": [],
        },
        "source": "heuristic",
    }


async def suggest_scope(flows: list[dict]) -> dict:
    """Analyze traffic patterns and suggest scope rules."""
    # Count hosts
    host_counts: dict[str, int] = {}
    for f in flows:
        host = f.get("host", "")
        host_counts[host] = host_counts.get(host, 0) + 1

    # Sort by frequency
    sorted_hosts = sorted(host_counts.items(), key=lambda x: -x[1])

    # Group by domain
    domains: dict[str, list[str]] = {}
    for host, _ in sorted_hosts:
        parts = host.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
            domains.setdefault(domain, []).append(host)

    suggestions = []
    for domain, hosts in domains.items():
        total = sum(host_counts[h] for h in hosts)
        if total >= 3:
            escaped_domain = domain.replace(".", r"\.")
            escaped_host = hosts[0].replace(".", r"\.")
            pattern = rf".*\.{escaped_domain}$" if len(hosts) > 1 else escaped_host
            suggestions.append({
                "pattern": pattern,
                "target": "host",
                "hosts": hosts,
                "flow_count": total,
                "reason": f"High-traffic domain ({total} flows across {len(hosts)} hosts)",
            })

    # Try LLM for smarter suggestions
    llm_result = await _llm_call(
        "You are a security tester. Given these hosts and flow counts, suggest scope include/exclude rules. Respond in JSON with 'include' and 'exclude' arrays.",
        json.dumps(sorted_hosts[:30]),
        max_tokens=500,
    )

    return {
        "suggestions": suggestions[:20],
        "host_summary": sorted_hosts[:50],
        "domains": {k: v for k, v in list(domains.items())[:20]},
        "ai_suggestion": json.loads(llm_result) if llm_result else None,
    }


async def generate_exploit(finding: dict) -> dict:
    """Generate a Python exploit script from a finding."""
    system = """You are a security researcher. Generate a complete, working Python exploit script for this vulnerability.
The script should:
- Use the requests library
- Include proper error handling
- Print clear output showing exploitation success/failure
- Be safe to run (no destructive actions)
- Include comments explaining each step

Output ONLY the Python code, no markdown."""

    user = json.dumps(finding, indent=2, default=str)

    llm_result = await _llm_call(system, user, max_tokens=3000)
    if llm_result:
        return {"exploit": llm_result, "source": "llm", "language": "python"}

    # Template-based fallback
    return _template_exploit(finding)


def _template_exploit(finding: dict) -> dict:
    """Generate a template exploit when LLM is unavailable."""
    name = finding.get("name", "").lower()
    url = finding.get("url", "")
    curl = finding.get("curl_command", "")

    if "sql" in name:
        template = "sqli"
    elif "xss" in name:
        template = "xss"
    elif "ssrf" in name:
        template = "ssrf"
    elif "idor" in name or "authorization" in name:
        template = "idor"
    else:
        template = "generic"

    exploit = f'''#!/usr/bin/env python3
"""Exploit for: {finding.get("name", "Unknown")}
URL: {url}
Severity: {finding.get("severity", "unknown")}
"""

import requests
import sys

TARGET_URL = "{url}"

def exploit():
    print(f"[*] Testing: {finding.get("name", "vulnerability")}")
    print(f"[*] Target: {{TARGET_URL}}")

    # Original curl command for reference:
    # {curl}

    try:
        resp = requests.get(TARGET_URL, verify=False, timeout=10)
        print(f"[*] Status: {{resp.status_code}}")
        print(f"[*] Length: {{len(resp.text)}}")

        # TODO: Add exploit-specific logic here
        print("[!] Review the response manually to confirm exploitation")
        print(resp.text[:500])

    except Exception as e:
        print(f"[-] Error: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()
'''

    return {"exploit": exploit, "source": "template", "template": template, "language": "python"}


async def generate_report_section(findings: list[dict], target: str = "") -> dict:
    """Generate a narrative report section with context."""
    system = """You are a professional security consultant writing a vulnerability assessment report.
Generate a clear, concise narrative section covering:
1. Executive summary
2. Key findings overview
3. Risk assessment
4. Prioritized remediation recommendations

Write in professional tone suitable for C-level and technical audiences."""

    user = json.dumps({
        "target": target,
        "total_findings": len(findings),
        "by_severity": _count_by_severity(findings),
        "findings": findings[:20],
    }, indent=2, default=str)

    llm_result = await _llm_call(system, user, max_tokens=3000)
    if llm_result:
        return {"report": llm_result, "source": "llm"}

    # Basic template
    counts = _count_by_severity(findings)
    report = f"""# Security Assessment Report

## Target: {target or 'Unknown'}

## Executive Summary
A total of {len(findings)} findings were identified during the assessment.

### Findings by Severity
- Critical: {counts.get('critical', 0)}
- High: {counts.get('high', 0)}
- Medium: {counts.get('medium', 0)}
- Low: {counts.get('low', 0)}
- Info: {counts.get('info', 0)}

## Recommendations
Address critical and high severity findings immediately.
"""
    return {"report": report, "source": "template"}


def _count_by_severity(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
