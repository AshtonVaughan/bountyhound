"""Vulnerability report generator — HTML reports with OWASP/CWE/CVSS mapping."""

from __future__ import annotations

import csv
import html
import io
import json
import logging
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from models import ScanFinding, PassiveFinding

log = logging.getLogger("proxy-engine.report")


# ── CWE / OWASP / CVSS mapping ─────────────────────────────────────────────

_VULN_META: dict[str, dict] = {
    "sqli": {
        "cwe": "CWE-89", "cwe_name": "SQL Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 8.6, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    },
    "timing_sqli": {
        "cwe": "CWE-89", "cwe_name": "SQL Injection (Blind)",
        "owasp": "A03:2021 Injection",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "xss": {
        "cwe": "CWE-79", "cwe_name": "Cross-Site Scripting",
        "owasp": "A03:2021 Injection",
        "cvss_base": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "dom_xss": {
        "cwe": "CWE-79", "cwe_name": "DOM-Based Cross-Site Scripting",
        "owasp": "A03:2021 Injection",
        "cvss_base": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "open_redirect": {
        "cwe": "CWE-601", "cwe_name": "Open Redirect",
        "owasp": "A01:2021 Broken Access Control",
        "cvss_base": 4.7, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
    },
    "ssrf": {
        "cwe": "CWE-918", "cwe_name": "Server-Side Request Forgery",
        "owasp": "A10:2021 SSRF",
        "cvss_base": 9.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "crlf": {
        "cwe": "CWE-113", "cwe_name": "HTTP Response Splitting",
        "owasp": "A03:2021 Injection",
        "cvss_base": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "header_injection": {
        "cwe": "CWE-644", "cwe_name": "Host Header Injection",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 5.4, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    },
    "path_traversal": {
        "cwe": "CWE-22", "cwe_name": "Path Traversal",
        "owasp": "A01:2021 Broken Access Control",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "ssti": {
        "cwe": "CWE-1336", "cwe_name": "Server-Side Template Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "command_injection": {
        "cwe": "CWE-78", "cwe_name": "OS Command Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "verb_tampering": {
        "cwe": "CWE-650", "cwe_name": "HTTP Verb Tampering",
        "owasp": "A01:2021 Broken Access Control",
        "cvss_base": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "web_cache_deception": {
        "cwe": "CWE-525", "cwe_name": "Web Cache Deception",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "cors": {
        "cwe": "CWE-942", "cwe_name": "CORS Misconfiguration",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "prototype_pollution": {
        "cwe": "CWE-1321", "cwe_name": "Prototype Pollution",
        "owasp": "A03:2021 Injection",
        "cvss_base": 7.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    },
    # Passive findings
    "missing_security_headers": {
        "cwe": "CWE-693", "cwe_name": "Missing Security Headers",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 3.7, "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
    },
    "cookie_no_httponly": {
        "cwe": "CWE-1004", "cwe_name": "Cookie Without HttpOnly Flag",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 4.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    "cookie_no_secure": {
        "cwe": "CWE-614", "cwe_name": "Cookie Without Secure Flag",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 4.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    "info_disclosure": {
        "cwe": "CWE-200", "cwe_name": "Information Disclosure",
        "owasp": "A01:2021 Broken Access Control",
        "cvss_base": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    # Extended checks
    "http_smuggling": {
        "cwe": "CWE-444", "cwe_name": "HTTP Request Smuggling",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 9.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "hpp": {
        "cwe": "CWE-235", "cwe_name": "HTTP Parameter Pollution",
        "owasp": "A03:2021 Injection",
        "cvss_base": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    },
    "mass_assignment": {
        "cwe": "CWE-915", "cwe_name": "Mass Assignment",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    },
    "bola": {
        "cwe": "CWE-639", "cwe_name": "Broken Object Level Authorization",
        "owasp": "A01:2021 Broken Access Control",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    "idor": {
        "cwe": "CWE-639", "cwe_name": "Insecure Direct Object Reference",
        "owasp": "A01:2021 Broken Access Control",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    "graphql": {
        "cwe": "CWE-200", "cwe_name": "GraphQL Information Disclosure",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "ldap_injection": {
        "cwe": "CWE-90", "cwe_name": "LDAP Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "xxe": {
        "cwe": "CWE-611", "cwe_name": "XML External Entity",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 9.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "xml_injection": {
        "cwe": "CWE-91", "cwe_name": "XML Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "email_header_injection": {
        "cwe": "CWE-93", "cwe_name": "Email Header Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 5.4, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    },
    "ssi_injection": {
        "cwe": "CWE-97", "cwe_name": "Server-Side Include Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "xpath_injection": {
        "cwe": "CWE-643", "cwe_name": "XPath Injection",
        "owasp": "A03:2021 Injection",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "jwt": {
        "cwe": "CWE-345", "cwe_name": "JWT Signature Bypass",
        "owasp": "A02:2021 Cryptographic Failures",
        "cvss_base": 9.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "deserialization": {
        "cwe": "CWE-502", "cwe_name": "Insecure Deserialization",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "cvss_base": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "file_upload": {
        "cwe": "CWE-434", "cwe_name": "Unrestricted File Upload",
        "owasp": "A04:2021 Insecure Design",
        "cvss_base": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "cors_subdomain": {
        "cwe": "CWE-942", "cwe_name": "CORS Subdomain Misconfiguration",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "api_version": {
        "cwe": "CWE-1059", "cwe_name": "Deprecated API Version Accessible",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 3.7, "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "differential": {
        "cwe": "CWE-209", "cwe_name": "Response Anomaly (Differential Analysis)",
        "owasp": "A03:2021 Injection",
        "cvss_base": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "http_method_override": {
        "cwe": "CWE-650", "cwe_name": "HTTP Method Override",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 5.3, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    },
    "cache_poisoning": {
        "cwe": "CWE-349", "cwe_name": "Web Cache Poisoning",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 7.5, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    },
    "host_header_injection": {
        "cwe": "CWE-644", "cwe_name": "Host Header Injection",
        "owasp": "A05:2021 Security Misconfiguration",
        "cvss_base": 5.4, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    },
    "blind_ssrf": {
        "cwe": "CWE-918", "cwe_name": "Blind Server-Side Request Forgery",
        "owasp": "A10:2021 SSRF",
        "cvss_base": 9.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "stored_xss_probe": {
        "cwe": "CWE-79", "cwe_name": "Stored Cross-Site Scripting",
        "owasp": "A03:2021 Injection",
        "cvss_base": 8.0, "cvss_vector": "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
    },
}


def _classify(template_id: str) -> dict:
    """Map a finding template ID to CWE/OWASP/CVSS metadata."""
    for key, meta in _VULN_META.items():
        if key in template_id.lower():
            return meta
    return {
        "cwe": "CWE-Unknown", "cwe_name": "Unknown",
        "owasp": "Unknown", "cvss_base": 0.0, "cvss_vector": "",
    }


def _risk_gauge_svg(score: int) -> str:
    """Generate an inline SVG risk gauge (0-100 scale)."""
    # Determine color based on score
    if score >= 75:
        color, label = "#d32f2f", "Critical"
    elif score >= 50:
        color, label = "#e65100", "High"
    elif score >= 25:
        color, label = "#f57f17", "Medium"
    elif score > 0:
        color, label = "#1565c0", "Low"
    else:
        color, label = "#4caf50", "Clean"

    # Arc calculation for gauge (180-degree arc)
    angle = 180 * score / 100
    rad = angle * 3.14159 / 180
    # SVG arc endpoint (center=100,90, radius=70)
    import math
    ex = 100 - 70 * math.cos(rad)
    ey = 90 - 70 * math.sin(rad)
    large_arc = 1 if angle > 90 else 0

    return f'''<svg width="200" height="120" viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg">
  <path d="M 30 90 A 70 70 0 0 1 170 90" fill="none" stroke="#e0e0e0" stroke-width="12" stroke-linecap="round"/>
  <path d="M 30 90 A 70 70 0 {large_arc} 1 {ex:.1f} {ey:.1f}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"/>
  <text x="100" y="80" text-anchor="middle" font-size="28" font-weight="bold" fill="{color}">{score}</text>
  <text x="100" y="105" text-anchor="middle" font-size="14" fill="#666">{label}</text>
</svg>'''


# PDF-specific CSS for page breaks, headers, footers, page numbers
_PDF_CSS = """
@page {
    size: A4;
    margin: 2cm 1.5cm 2.5cm 1.5cm;
    @top-center {
        content: "Vulnerability Scan Report";
        font-size: 9px;
        color: #999;
    }
    @bottom-left {
        content: "Confidential";
        font-size: 9px;
        color: #999;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #999;
    }
}
@page :first {
    @top-center { content: none; }
}
.finding { page-break-inside: avoid; }
.summary { page-break-after: always; }
h2 { page-break-before: always; }
h2:first-of-type { page-break-before: avoid; }
table { page-break-inside: avoid; }
"""


def _severity_badge(severity: str) -> str:
    colors = {
        "critical": "#d32f2f", "high": "#e65100",
        "medium": "#f57f17", "low": "#1565c0", "info": "#616161",
    }
    bg = colors.get(severity.lower(), "#616161")
    return f'<span style="background:{bg};color:white;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:bold">{html.escape(severity.upper())}</span>'


def _confidence_badge(confidence: str) -> str:
    colors = {"confirmed": "#2e7d32", "firm": "#f57f17", "tentative": "#e65100"}
    bg = colors.get(confidence.lower(), "#616161")
    return f'<span style="background:{bg};color:white;padding:2px 8px;border-radius:3px;font-size:12px">{html.escape(confidence or "unknown")}</span>'


# ── Report generation ───────────────────────────────────────────────────────

def generate_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
    title: str = "Vulnerability Scan Report",
    target: str = "",
) -> str:
    """Generate an HTML vulnerability report."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # Count by severity
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in scan_findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1

    passive_list = passive_findings or []
    for pf in passive_list:
        sev = pf.severity.lower()
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())

    # Sort findings: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_scan = sorted(scan_findings, key=lambda f: severity_order.get(f.severity.lower(), 5))

    # Build HTML
    findings_html = ""
    for i, f in enumerate(sorted_scan, 1):
        meta = _classify(f.template_id)
        findings_html += _render_finding(i, f, meta)

    passive_html = ""
    if passive_list:
        passive_html = '<h2>Passive Findings</h2><table class="findings-table"><thead><tr><th>Check</th><th>Severity</th><th>URL</th><th>Details</th></tr></thead><tbody>'
        for pf in passive_list:
            passive_html += f"""<tr>
                <td>{html.escape(pf.name)}</td>
                <td>{_severity_badge(pf.severity)}</td>
                <td><code>{html.escape(pf.url)}</code></td>
                <td>{html.escape(pf.description)}</td>
            </tr>"""
        passive_html += "</tbody></table>"

    # Generate executive summary with risk gauge
    exec_summary = generate_executive_summary(scan_findings, passive_list)
    risk_gauge = _risk_gauge_svg(exec_summary["risk_score"])
    priorities_html = ""
    for p in exec_summary.get("priorities", []):
        if p:
            priorities_html += f"<li>{html.escape(p)}</li>"
    exec_section = ""
    if total > 0:
        exec_section = f'''
    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="exec-row">
            <div class="risk-gauge">{risk_gauge}</div>
            <div class="exec-details">
                <p>Overall risk rating: <strong>{html.escape(exec_summary["rating"])}</strong></p>
                <p>Total findings: <strong>{total}</strong> ({counts["critical"]} critical, {counts["high"]} high, {counts["medium"]} medium)</p>
                {"<h4>Priorities</h4><ul>" + priorities_html + "</ul>" if priorities_html else ""}
            </div>
        </div>
    </div>'''

    return _HTML_TEMPLATE.format(
        title=html.escape(title),
        target=html.escape(target),
        timestamp=timestamp,
        total=total,
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        executive_summary=exec_section,
        findings=findings_html,
        passive=passive_html,
    )


def _render_finding(idx: int, f: ScanFinding, meta: dict) -> str:
    extracted_html = ""
    if f.extracted:
        extracted_html = "<h4>Extracted Evidence</h4><ul>" + "".join(
            f"<li><code>{html.escape(str(e))}</code></li>" for e in f.extracted
        ) + "</ul>"

    curl_html = ""
    if f.curl_command:
        curl_html = f'<h4>cURL Command</h4><pre class="code">{html.escape(f.curl_command)}</pre>'

    remediation_html = ""
    if f.remediation:
        remediation_html = f'<h4>Remediation</h4><p>{html.escape(f.remediation)}</p>'

    return f"""
    <div class="finding">
        <div class="finding-header">
            <h3>#{idx} — {html.escape(f.name)}</h3>
            <div class="badges">
                {_severity_badge(f.severity)}
                {_confidence_badge(f.confidence)}
                <span class="badge-info">{html.escape(meta.get('cwe', ''))}</span>
            </div>
        </div>
        <table class="meta-table">
            <tr><td><strong>URL</strong></td><td><code>{html.escape(f.url)}</code></td></tr>
            <tr><td><strong>Matched At</strong></td><td><code>{html.escape(f.matched_at)}</code></td></tr>
            <tr><td><strong>CWE</strong></td><td>{html.escape(meta.get('cwe', ''))} — {html.escape(meta.get('cwe_name', ''))}</td></tr>
            <tr><td><strong>OWASP</strong></td><td>{html.escape(meta.get('owasp', ''))}</td></tr>
            <tr><td><strong>CVSS 3.1</strong></td><td>{meta.get('cvss_base', 0.0)} ({html.escape(meta.get('cvss_vector', ''))})</td></tr>
            <tr><td><strong>Source</strong></td><td>{html.escape(f.source)}</td></tr>
            <tr><td><strong>Template</strong></td><td><code>{html.escape(f.template_id)}</code></td></tr>
        </table>
        <h4>Description</h4>
        <p>{html.escape(f.description)}</p>
        {extracted_html}
        {curl_html}
        {remediation_html}
    </div>
    """


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
    header {{ background: linear-gradient(135deg, #1a237e, #283593); color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
    header h1 {{ font-size: 24px; margin-bottom: 8px; }}
    header p {{ opacity: 0.85; font-size: 14px; }}
    .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }}
    .summary-card {{ background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .summary-card .count {{ font-size: 32px; font-weight: bold; }}
    .summary-card .label {{ font-size: 12px; text-transform: uppercase; opacity: 0.7; }}
    .sc-critical .count {{ color: #d32f2f; }}
    .sc-high .count {{ color: #e65100; }}
    .sc-medium .count {{ color: #f57f17; }}
    .sc-low .count {{ color: #1565c0; }}
    .sc-info .count {{ color: #616161; }}
    .finding {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }}
    .finding-header h3 {{ font-size: 16px; }}
    .badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
    .badge-info {{ background: #e3f2fd; color: #1565c0; padding: 2px 8px; border-radius: 3px; font-size: 12px; }}
    .meta-table {{ width: 100%; border-collapse: collapse; margin-bottom: 12px; font-size: 14px; }}
    .meta-table td {{ padding: 6px 10px; border-bottom: 1px solid #eee; }}
    .meta-table td:first-child {{ width: 140px; white-space: nowrap; }}
    code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 13px; word-break: break-all; }}
    pre.code {{ background: #263238; color: #eeffff; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; margin: 8px 0; }}
    h2 {{ font-size: 20px; margin: 24px 0 12px; }}
    h4 {{ font-size: 14px; margin: 12px 0 6px; color: #555; }}
    .findings-table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .findings-table th {{ background: #f5f5f5; padding: 10px; text-align: left; font-size: 13px; }}
    .findings-table td {{ padding: 10px; border-bottom: 1px solid #eee; font-size: 13px; }}
    footer {{ text-align: center; margin-top: 30px; padding: 20px; color: #999; font-size: 12px; }}
    .executive-summary {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .exec-row {{ display: flex; align-items: center; gap: 24px; }}
    .risk-gauge {{ flex-shrink: 0; }}
    .exec-details {{ flex: 1; }}
    .exec-details ul {{ margin: 8px 0; padding-left: 20px; }}
    .exec-details li {{ margin: 4px 0; font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>{title}</h1>
        <p>Target: {target} &nbsp;|&nbsp; Generated: {timestamp} &nbsp;|&nbsp; Total findings: {total}</p>
    </header>

    <div class="summary">
        <div class="summary-card sc-critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
        <div class="summary-card sc-high"><div class="count">{high}</div><div class="label">High</div></div>
        <div class="summary-card sc-medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
        <div class="summary-card sc-low"><div class="count">{low}</div><div class="label">Low</div></div>
        <div class="summary-card sc-info"><div class="count">{info}</div><div class="label">Info</div></div>
    </div>

    {executive_summary}

    <h2>Active Scan Findings</h2>
    {findings}

    {passive}

    <footer>
        Generated by Proxy Engine &mdash; proxy-engine report generator
    </footer>
</div>
</body>
</html>"""


def save_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
    output_path: str | None = None,
    title: str = "Vulnerability Scan Report",
    target: str = "",
) -> str:
    """Generate and save an HTML report. Returns the file path."""
    report_html = generate_report(scan_findings, passive_findings, title, target)

    if not output_path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_path = f"reports/vuln_report_{ts}.html"

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_html, encoding="utf-8")
    log.info(f"[report] Saved report to {path}")
    return str(path.resolve())


# ── Multiple export formats ──────────────────────────────────────────────────

def generate_json_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
    title: str = "Vulnerability Scan Report",
    target: str = "",
) -> str:
    """Generate a machine-readable JSON report."""
    import json as _json
    import time as _time

    findings_data = []
    for f in scan_findings:
        meta = _classify(f.template_id)
        findings_data.append({
            "name": f.name,
            "severity": f.severity,
            "confidence": f.confidence,
            "url": f.url,
            "matched_at": f.matched_at,
            "description": f.description,
            "template_id": f.template_id,
            "source": f.source,
            "cwe": meta.get("cwe", ""),
            "owasp": meta.get("owasp", ""),
            "cvss_base": meta.get("cvss_base", 0),
            "remediation": f.remediation,
            "extracted": f.extracted,
            "curl_command": f.curl_command,
        })

    passive_data = []
    for pf in (passive_findings or []):
        passive_data.append({
            "check_id": pf.check_id,
            "name": pf.name,
            "severity": pf.severity,
            "url": pf.url,
            "description": pf.description,
            "evidence": pf.evidence,
        })

    report = {
        "title": title,
        "target": target,
        "generated_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        "summary": {
            "total_findings": len(findings_data) + len(passive_data),
            "active_findings": len(findings_data),
            "passive_findings": len(passive_data),
        },
        "findings": findings_data,
        "passive_findings": passive_data,
    }
    return _json.dumps(report, indent=2)


def generate_xml_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
    title: str = "Vulnerability Scan Report",
    target: str = "",
) -> str:
    """Generate a structured XML report."""
    root = ET.Element("report")
    ET.SubElement(root, "title").text = title
    ET.SubElement(root, "target").text = target
    ET.SubElement(root, "generated_at").text = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    findings_el = ET.SubElement(root, "findings")
    for f in scan_findings:
        meta = _classify(f.template_id)
        finding_el = ET.SubElement(findings_el, "finding")
        ET.SubElement(finding_el, "name").text = f.name
        ET.SubElement(finding_el, "severity").text = f.severity
        ET.SubElement(finding_el, "confidence").text = f.confidence
        ET.SubElement(finding_el, "url").text = f.url
        ET.SubElement(finding_el, "description").text = f.description
        ET.SubElement(finding_el, "cwe").text = meta.get("cwe", "")
        ET.SubElement(finding_el, "owasp").text = meta.get("owasp", "")
        ET.SubElement(finding_el, "cvss").text = str(meta.get("cvss_base", 0))
        ET.SubElement(finding_el, "remediation").text = f.remediation

    passive_el = ET.SubElement(root, "passive_findings")
    for pf in (passive_findings or []):
        pf_el = ET.SubElement(passive_el, "finding")
        ET.SubElement(pf_el, "check_id").text = pf.check_id
        ET.SubElement(pf_el, "name").text = pf.name
        ET.SubElement(pf_el, "severity").text = pf.severity
        ET.SubElement(pf_el, "url").text = pf.url
        ET.SubElement(pf_el, "description").text = pf.description

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def generate_csv_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
) -> str:
    """Generate a CSV report."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Name", "Severity", "Confidence", "URL", "Description", "CWE", "OWASP", "Remediation"])

    for f in scan_findings:
        meta = _classify(f.template_id)
        writer.writerow([
            "active", f.name, f.severity, f.confidence, f.url,
            f.description, meta.get("cwe", ""), meta.get("owasp", ""), f.remediation,
        ])

    for pf in (passive_findings or []):
        writer.writerow([
            "passive", pf.name, pf.severity, "", pf.url,
            pf.description, "", "", "",
        ])

    return output.getvalue()


def generate_markdown_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
    title: str = "Vulnerability Scan Report",
    target: str = "",
) -> str:
    """Generate a Markdown report."""
    lines = [f"# {title}", ""]
    if target:
        lines.append(f"**Target:** {target}")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append("")

    # Summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in scan_findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1

    lines.append("## Summary")
    lines.append(f"| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in counts.items():
        lines.append(f"| {sev.capitalize()} | {count} |")
    lines.append("")

    # Active findings
    lines.append("## Active Scan Findings")
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(scan_findings, key=lambda f: severity_order.get(f.severity.lower(), 5))

    for i, f in enumerate(sorted_findings, 1):
        meta = _classify(f.template_id)
        lines.append(f"### {i}. {f.name}")
        lines.append(f"- **Severity:** {f.severity}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **URL:** `{f.url}`")
        lines.append(f"- **CWE:** {meta.get('cwe', '')} — {meta.get('cwe_name', '')}")
        lines.append(f"- **OWASP:** {meta.get('owasp', '')}")
        lines.append(f"- **CVSS:** {meta.get('cvss_base', 0)}")
        lines.append(f"\n{f.description}")
        if f.remediation:
            lines.append(f"\n**Remediation:** {f.remediation}")
        lines.append("")

    # Passive findings
    if passive_findings:
        lines.append("## Passive Findings")
        lines.append("| Check | Severity | URL | Description |")
        lines.append("|-------|----------|-----|-------------|")
        for pf in passive_findings:
            lines.append(f"| {pf.name} | {pf.severity} | `{pf.url}` | {pf.description} |")

    return "\n".join(lines)


def generate_pdf_report(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
    title: str = "Vulnerability Scan Report",
    target: str = "",
    branding: dict | None = None,
) -> bytes:
    """Generate a PDF report via weasyprint from HTML with page breaks and headers/footers."""
    report_html = generate_report(scan_findings, passive_findings, title, target)
    if branding:
        report_html = _apply_branding(report_html, branding)
    # Inject PDF-specific CSS for paged media
    report_html = report_html.replace("</style>", _PDF_CSS + "\n</style>")
    try:
        from weasyprint import HTML
        return HTML(string=report_html).write_pdf()
    except ImportError:
        log.warning("[report] weasyprint not installed, returning empty PDF")
        return b""


def _apply_branding(report_html: str, branding: dict) -> str:
    """Inject branding (logo, company name, CSS) into HTML report."""
    if branding.get("custom_css"):
        report_html = report_html.replace("</style>", branding["custom_css"] + "\n</style>")
    if branding.get("company_name"):
        report_html = report_html.replace(
            "Generated by Proxy Engine",
            f"Generated by {html.escape(branding['company_name'])} using Proxy Engine",
        )
    if branding.get("logo_url"):
        logo_tag = f'<img src="{html.escape(branding["logo_url"])}" style="max-height:40px;margin-right:12px;vertical-align:middle">'
        report_html = report_html.replace("<h1>", f"<h1>{logo_tag}")
    if branding.get("footer_text"):
        report_html = report_html.replace(
            "proxy-engine report generator",
            html.escape(branding["footer_text"]),
        )
    return report_html


def _build_remediation_links(template_id: str) -> dict:
    """Build OWASP/CWE/MITRE links for a finding."""
    meta = _classify(template_id)
    cwe = meta.get("cwe", "")
    cwe_num = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else ""
    return {
        "owasp_url": f"https://owasp.org/Top10/{meta.get('owasp', '').replace(' ', '-').replace(':', '')}" if meta.get("owasp") else "",
        "cwe_url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num else "",
        "mitre_url": f"https://attack.mitre.org/techniques/" if meta.get("cwe") else "",
    }


def generate_executive_summary(
    scan_findings: list[ScanFinding],
    passive_findings: list[PassiveFinding] | None = None,
) -> dict:
    """Generate executive summary with risk score and top priorities."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in scan_findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
    for pf in (passive_findings or []):
        sev = pf.severity.lower()
        if sev in counts:
            counts[sev] += 1

    # Risk score: 0-100
    risk_score = min(100, (
        counts["critical"] * 25 +
        counts["high"] * 15 +
        counts["medium"] * 8 +
        counts["low"] * 3 +
        counts["info"] * 1
    ))

    # Top 5 risks
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(scan_findings, key=lambda f: severity_order.get(f.severity.lower(), 5))
    top_risks = []
    for f in sorted_findings[:5]:
        meta = _classify(f.template_id)
        top_risks.append({
            "name": f.name,
            "severity": f.severity,
            "url": f.url,
            "cwe": meta.get("cwe", ""),
            "cvss": meta.get("cvss_base", 0),
        })

    # Rating
    if risk_score >= 75:
        rating = "Critical"
    elif risk_score >= 50:
        rating = "High"
    elif risk_score >= 25:
        rating = "Medium"
    elif risk_score > 0:
        rating = "Low"
    else:
        rating = "Clean"

    return {
        "risk_score": risk_score,
        "rating": rating,
        "total_findings": sum(counts.values()),
        "by_severity": counts,
        "top_risks": top_risks,
        "priorities": [
            f"Fix {counts['critical']} critical vulnerabilities immediately" if counts["critical"] else None,
            f"Address {counts['high']} high-severity issues" if counts["high"] else None,
            f"Review {counts['medium']} medium-severity findings" if counts["medium"] else None,
            f"Consider fixing {counts['low']} low-severity issues" if counts["low"] else None,
        ],
    }


def generate_trend_analysis(current_findings: list[ScanFinding], previous_findings: list[ScanFinding]) -> dict:
    """Compare current vs previous scan findings to identify trends."""
    current_keys = {f"{f.template_id}|{f.url}" for f in current_findings}
    previous_keys = {f"{f.template_id}|{f.url}" for f in previous_findings}

    new_keys = current_keys - previous_keys
    fixed_keys = previous_keys - current_keys
    recurring_keys = current_keys & previous_keys

    return {
        "new_findings": len(new_keys),
        "fixed_findings": len(fixed_keys),
        "recurring_findings": len(recurring_keys),
        "new": [f.model_dump() for f in current_findings if f"{f.template_id}|{f.url}" in new_keys][:20],
        "fixed": [f.model_dump() for f in previous_findings if f"{f.template_id}|{f.url}" in fixed_keys][:20],
    }


# ── Compliance mapping ───────────────────────────────────────────────────────

_COMPLIANCE_MAP: dict[str, dict] = {
    "CWE-89": {"pci_dss": ["6.5.1"], "nist_800_53": ["SI-10"], "owasp_asvs": ["5.3.4"]},
    "CWE-79": {"pci_dss": ["6.5.7"], "nist_800_53": ["SI-10"], "owasp_asvs": ["5.3.3"]},
    "CWE-22": {"pci_dss": ["6.5.8"], "nist_800_53": ["AC-3"], "owasp_asvs": ["12.3.1"]},
    "CWE-78": {"pci_dss": ["6.5.1"], "nist_800_53": ["SI-10"], "owasp_asvs": ["5.3.8"]},
    "CWE-918": {"pci_dss": ["6.5.10"], "nist_800_53": ["SC-7"], "owasp_asvs": ["12.6.1"]},
    "CWE-611": {"pci_dss": ["6.5.1"], "nist_800_53": ["SI-10"], "owasp_asvs": ["5.5.2"]},
    "CWE-502": {"pci_dss": ["6.5.1"], "nist_800_53": ["SI-10"], "owasp_asvs": ["5.5.3"]},
    "CWE-601": {"pci_dss": ["6.5.10"], "nist_800_53": ["CM-7"], "owasp_asvs": ["5.1.5"]},
    "CWE-693": {"pci_dss": ["6.5.10"], "nist_800_53": ["SC-8"], "owasp_asvs": ["14.4.3"]},
    "CWE-1004": {"pci_dss": ["6.5.10"], "nist_800_53": ["SC-23"], "owasp_asvs": ["3.4.2"]},
    "CWE-614": {"pci_dss": ["6.5.10"], "nist_800_53": ["SC-23"], "owasp_asvs": ["3.4.1"]},
    "CWE-942": {"pci_dss": ["6.5.10"], "nist_800_53": ["AC-4"], "owasp_asvs": ["14.5.3"]},
    "CWE-345": {"pci_dss": ["6.5.10"], "nist_800_53": ["IA-7"], "owasp_asvs": ["3.5.3"]},
    "CWE-434": {"pci_dss": ["6.5.8"], "nist_800_53": ["SI-10"], "owasp_asvs": ["12.1.1"]},
    "CWE-1336": {"pci_dss": ["6.5.1"], "nist_800_53": ["SI-10"], "owasp_asvs": ["5.2.4"]},
}


def generate_compliance_mapping(findings: list[ScanFinding]) -> dict:
    """Map findings to compliance frameworks (PCI-DSS, NIST 800-53, OWASP ASVS)."""
    mapping = {"pci_dss": {}, "nist_800_53": {}, "owasp_asvs": {}}

    for f in findings:
        meta = _classify(f.template_id)
        cwe = meta.get("cwe", "")
        comp = _COMPLIANCE_MAP.get(cwe, {})

        for framework in ("pci_dss", "nist_800_53", "owasp_asvs"):
            for control in comp.get(framework, []):
                if control not in mapping[framework]:
                    mapping[framework][control] = []
                mapping[framework][control].append({
                    "name": f.name,
                    "severity": f.severity,
                    "url": f.url,
                    "cwe": cwe,
                })

    return mapping
