"""
HackerOne Auto-Submission Module

Automates vulnerability report submission to HackerOne.
Formats findings, attaches evidence, and submits via H1 API.
"""

import os
import json
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from engine.core.config import BountyHoundConfig


FINDINGS_BASE = BountyHoundConfig.FINDINGS_DIR


@dataclass
class H1Report:
    """Represents a HackerOne report."""
    title: str
    vulnerability_type: str
    severity: str  # none, low, medium, high, critical
    summary: str
    impact: str
    steps_to_reproduce: str
    expected_behavior: str
    actual_behavior: str
    supporting_material: List[str] = field(default_factory=list)
    weakness_id: Optional[int] = None
    structured_scope_id: Optional[str] = None


@dataclass
class SubmissionResult:
    """Result of a submission attempt."""
    success: bool
    report_id: Optional[str] = None
    report_url: Optional[str] = None
    error: Optional[str] = None
    raw_response: Optional[str] = None


class H1Submitter:
    """HackerOne API client for report submission."""

    API_BASE = "https://api.hackerone.com/v1"

    # Common weakness IDs for HackerOne
    WEAKNESS_MAP = {
        'xss': 60,               # Cross-site Scripting (XSS) - Generic
        'reflected_xss': 61,
        'stored_xss': 62,
        'sqli': 89,              # SQL Injection
        'idor': 639,             # Insecure Direct Object Reference
        'ssrf': 918,             # Server-Side Request Forgery
        'cors': 942,             # CORS Misconfiguration
        'csrf': 352,             # Cross-Site Request Forgery
        'open_redirect': 601,    # URL Redirection to Untrusted Site
        'info_disclosure': 200,  # Information Exposure
        'auth_bypass': 287,      # Improper Authentication
        'broken_auth': 306,      # Missing Authentication
        'privilege_escalation': 269,
        'rce': 94,               # Code Injection
        'xxe': 611,              # XML External Entities
        'ssti': 1336,            # Server Side Template Injection
        'path_traversal': 22,
        'command_injection': 78,
        'rate_limit': 799,       # Improper Control of Interaction Frequency
        'business_logic': 840,   # Business Logic Errors
        'subdomain_takeover': 350,
        'security_misconfiguration': 16,
        'sensitive_data': 312,   # Cleartext Storage of Sensitive Information
    }

    SEVERITY_MAP = {
        'CRITICAL': {'rating': 'critical', 'cvss_min': 9.0},
        'HIGH': {'rating': 'high', 'cvss_min': 7.0},
        'MEDIUM': {'rating': 'medium', 'cvss_min': 4.0},
        'LOW': {'rating': 'low', 'cvss_min': 0.1},
        'INFO': {'rating': 'none', 'cvss_min': 0.0},
    }

    def __init__(self):
        self.api_token = os.environ.get('H1_API_TOKEN', '')
        self.username = os.environ.get('H1_USERNAME', '')

    def _api_call(self, method: str, endpoint: str, data: dict = None, timeout: int = 30) -> Tuple[int, str]:
        """Make authenticated JSON API call to HackerOne."""
        url = f"{self.API_BASE}{endpoint}"
        # -g disables URL globbing so literal [] in query strings are not rejected on Windows
        cmd = ['curl', '-s', '-g', '-m', str(timeout), '-w', '\n%{http_code}']

        if method == 'PATCH':
            cmd.extend(['-X', 'PATCH'])
        elif method == 'POST':
            cmd.extend(['-X', 'POST'])
        elif method == 'GET':
            cmd.extend(['-X', 'GET'])

        cmd.extend([
            '-H', 'Content-Type: application/json',
            '-H', 'Accept: application/json',
            '-u', f'{self.username}:{self.api_token}',
        ])

        if data:
            cmd.extend(['-d', json.dumps(data)])

        cmd.append(url)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding='utf-8', errors='replace',
                                    timeout=timeout + 10)
            output = result.stdout.strip()
            lines = output.rsplit('\n', 1)
            body = lines[0] if len(lines) > 1 else output
            status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
            return status, body
        except Exception as e:
            return 0, str(e)

    def _upload_file(self, intent_id: str, file_path: str, timeout: int = 60) -> Tuple[int, str]:
        """Upload a single file to a report intent via multipart form-data."""
        url = f"{self.API_BASE}/hackers/report_intents/{intent_id}/attachments"
        cmd = [
            'curl', '-s', '-g', '-m', str(timeout), '-w', '\n%{http_code}',
            '-X', 'POST',
            '-H', 'Accept: application/json',
            '-u', f'{self.username}:{self.api_token}',
            '-F', f'files[]=@{file_path}',
            url,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding='utf-8', errors='replace',
                                    timeout=timeout + 10)
            output = result.stdout.strip()
            lines = output.rsplit('\n', 1)
            body = lines[0] if len(lines) > 1 else output
            status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
            return status, body
        except Exception as e:
            return 0, str(e)

    def submit_report_with_attachments(
        self,
        program_handle: str,
        report: 'H1Report',
        file_paths: List[str],
    ) -> 'SubmissionResult':
        """
        Submit via the Report Intents workflow (required for file attachments):
          1. POST /hackers/report_intents      — create draft
          2. PATCH intent                      — set title, impact, severity, weakness
          3. POST intent/attachments           — upload each file
          4. POST intent/submit                — convert to formal report
        """
        if not self.api_token or not self.username:
            return SubmissionResult(
                success=False,
                error="H1_API_TOKEN and H1_USERNAME environment variables required",
            )

        full_body = self._format_report_body(report)
        severity_info = self.SEVERITY_MAP.get(report.severity.upper(), self.SEVERITY_MAP['MEDIUM'])

        # Step 1 — create the intent
        create_payload = {
            "data": {
                "type": "report-intent",
                "attributes": {
                    "team_handle": program_handle,
                    "description": full_body,
                },
            }
        }
        status, body = self._api_call('POST', '/hackers/report_intents', create_payload)
        if status not in (200, 201):
            return SubmissionResult(
                success=False,
                error=f"Intent creation failed — HTTP {status}: {body[:300]}",
            )
        try:
            intent_id = json.loads(body)['data']['id']
        except Exception:
            return SubmissionResult(success=False, error=f"Could not parse intent ID: {body[:300]}")

        # Step 2 — PATCH to set title, impact, severity, weakness
        patch_attrs: dict = {
            "title": report.title,
            "impact": report.impact,
            "severity_rating": severity_info['rating'],
        }
        if report.weakness_id:
            patch_attrs["weakness_id"] = report.weakness_id
        if report.structured_scope_id:
            patch_attrs["structured_scope_id"] = report.structured_scope_id

        self._api_call('PATCH', f'/hackers/report_intents/{intent_id}', {
            "data": {"type": "report-intent", "attributes": patch_attrs}
        })

        # Step 3 — upload files
        upload_errors: List[str] = []
        for fp in file_paths:
            if not Path(fp).exists():
                upload_errors.append(f"File not found (skipped): {fp}")
                continue
            u_status, u_body = self._upload_file(intent_id, fp)
            if u_status not in (200, 201):
                upload_errors.append(f"Upload failed for {Path(fp).name} — HTTP {u_status}")

        # Step 4 — submit the intent
        s_status, s_body = self._api_call(
            'POST', f'/hackers/report_intents/{intent_id}/submit', {}
        )
        if s_status in (200, 201):
            try:
                data = json.loads(s_body)
                report_id = (
                    data.get('data', {}).get('id')
                    or data.get('data', {}).get('relationships', {})
                      .get('report', {}).get('data', {}).get('id', '')
                )
                return SubmissionResult(
                    success=True,
                    report_id=str(report_id),
                    report_url=f"https://hackerone.com/reports/{report_id}",
                    raw_response=s_body[:500],
                )
            except Exception:
                return SubmissionResult(success=True, raw_response=s_body[:500])
        else:
            return SubmissionResult(
                success=False,
                error=(
                    f"Intent submit failed — HTTP {s_status}: {s_body[:300]}"
                    + (f"\nUpload warnings: {upload_errors}" if upload_errors else "")
                ),
            )

    def submit_report(self, program_handle: str, report: H1Report) -> SubmissionResult:
        """Submit a vulnerability report to HackerOne."""
        if not self.api_token or not self.username:
            return SubmissionResult(
                success=False,
                error="H1_API_TOKEN and H1_USERNAME environment variables required"
            )

        # Build report body with Expected vs Actual
        full_body = self._format_report_body(report)

        # Build API payload
        severity_info = self.SEVERITY_MAP.get(report.severity.upper(), self.SEVERITY_MAP['MEDIUM'])

        # Hacker API: weakness_id and structured_scope_id go in attributes (not relationships)
        attributes: dict = {
            "team_handle": program_handle,
            "title": report.title,
            "vulnerability_information": full_body,
            "severity_rating": severity_info['rating'],
        }
        if report.weakness_id:
            attributes["weakness_id"] = report.weakness_id
        if report.structured_scope_id:
            attributes["structured_scope_id"] = report.structured_scope_id

        payload = {
            "data": {
                "type": "report",
                "attributes": attributes,
            }
        }

        # Hacker API endpoint: /hackers/reports (not /reports which is the customer API)
        status, body = self._api_call('POST', '/hackers/reports', payload)

        if status in (200, 201):
            try:
                response_data = json.loads(body)
                report_id = response_data.get('data', {}).get('id', '')
                return SubmissionResult(
                    success=True,
                    report_id=report_id,
                    report_url=f"https://hackerone.com/reports/{report_id}",
                    raw_response=body[:500]
                )
            except Exception:
                return SubmissionResult(success=True, raw_response=body[:500])
        else:
            return SubmissionResult(
                success=False,
                error=f"HTTP {status}: {body[:500]}",
                raw_response=body[:500]
            )

    def _format_report_body(self, report: H1Report) -> str:
        """Format report body with mandatory Expected vs Actual section."""
        sections = []

        # Summary
        sections.append(f"## Summary\n\n{report.summary}")

        # Expected vs Actual Behavior (MANDATORY)
        sections.append(
            f"## Expected vs Actual Behavior\n\n"
            f"**Expected Behavior:**\n{report.expected_behavior}\n\n"
            f"**Actual Behavior:**\n{report.actual_behavior}"
        )

        # Steps to Reproduce
        sections.append(f"## Steps to Reproduce\n\n{report.steps_to_reproduce}")

        # Impact
        sections.append(f"## Impact\n\n{report.impact}")

        # Supporting Material
        if report.supporting_material:
            material = '\n'.join(f"- {m}" for m in report.supporting_material)
            sections.append(f"## Supporting Material\n\n{material}")

        return '\n\n---\n\n'.join(sections)

    def get_program_weaknesses(self, program_handle: str) -> List[Dict]:
        """
        Fetch weakness objects accepted by this program.
        Returns list of {id, name, external_id (CWE)} dicts.
        Use resolve_weakness_id() instead of the static WEAKNESS_MAP for accurate IDs.
        """
        status, body = self._api_call('GET', f'/hackers/programs/{program_handle}/weaknesses')
        if status != 200:
            return []
        try:
            items = json.loads(body).get('data', [])
            return [
                {
                    'id': int(item['id']),
                    'name': item['attributes'].get('name', ''),
                    'external_id': item['attributes'].get('external_id', ''),  # e.g. "cwe-89"
                }
                for item in items
            ]
        except Exception:
            return []

    def resolve_weakness_id(self, program_handle: str, vuln_type: str) -> Optional[int]:
        """
        Look up the correct H1-internal weakness ID for a given vuln type string.
        Tries in order:
          1. Query program weaknesses and match by name or CWE keyword
          2. Fall back to static WEAKNESS_MAP (may not match the program's exact IDs)
        """
        weaknesses = self.get_program_weaknesses(program_handle)
        if weaknesses:
            # Keep underscored form for dict key lookup; use space form as fallback search term
            vt_key = vuln_type.lower().replace(' ', '_')
            vt_lower = vt_key.replace('_', ' ')
            # Build CWE lookup from WEAKNESS_MAP key → expected CWE partial match
            _CWE_KEYWORDS: Dict[str, List[str]] = {
                'xss': ['cross-site scripting', 'xss'],
                'reflected_xss': ['reflected', 'xss'],
                'stored_xss': ['stored', 'xss'],
                'sqli': ['sql injection', 'sql'],
                'idor': ['insecure direct object', 'idor', 'authorization bypass'],
                'ssrf': ['server-side request forgery', 'ssrf'],
                'cors': ['cors', 'cross-origin'],
                'csrf': ['cross-site request forgery', 'csrf'],
                'open_redirect': ['open redirect', 'url redirection'],
                'info_disclosure': ['information exposure', 'information disclosure'],
                'auth_bypass': ['improper authentication', 'authentication bypass'],
                'broken_auth': ['missing authentication', 'broken authentication'],
                'privilege_escalation': ['privilege escalation'],
                'rce': ['code injection', 'remote code execution', 'rce'],
                'xxe': ['xml external', 'xxe'],
                'ssti': ['server side template', 'ssti', 'template injection'],
                'path_traversal': ['path traversal'],
                'command_injection': ['command injection', 'os command'],
                'subdomain_takeover': ['subdomain takeover'],
                'rate_limit': ['improper control of interaction', 'rate limit'],
                'business_logic': ['business logic'],
                'security_misconfiguration': ['security misconfiguration', 'misconfiguration'],
                'sensitive_data': ['cleartext', 'sensitive information'],
            }
            keywords = _CWE_KEYWORDS.get(vt_key, _CWE_KEYWORDS.get(vt_lower, [vt_lower]))
            for w in weaknesses:
                name_lower = w['name'].lower()
                ext_lower = (w['external_id'] or '').lower()
                if any(kw in name_lower or kw in ext_lower for kw in keywords):
                    return w['id']

        # Static fallback — may not match program's internal IDs
        return self.WEAKNESS_MAP.get(vuln_type.lower().replace(' ', '_'))

    def get_structured_scopes(self, program_handle: str) -> List[Dict]:
        """
        Fetch structured scopes for this program.
        Returns list of {id, asset_identifier, asset_type, eligible_for_bounty} dicts.
        """
        status, body = self._api_call(
            'GET', f'/hackers/programs/{program_handle}/structured_scopes'
        )
        if status != 200:
            return []
        try:
            items = json.loads(body).get('data', [])
            return [
                {
                    'id': int(item['id']),
                    'asset_identifier': item['attributes'].get('asset_identifier', ''),
                    'asset_type': item['attributes'].get('asset_type', ''),
                    'eligible_for_bounty': item['attributes'].get('eligible_for_bounty', False),
                    'max_severity': item['attributes'].get('max_severity', ''),
                }
                for item in items
            ]
        except Exception:
            return []

    def resolve_scope_id(self, program_handle: str, target_url: str) -> Optional[int]:
        """
        Find the structured scope ID that best matches target_url.
        Tries multiple matching strategies:
          1. Prefix match against full URL
          2. Hostname-only match (strips protocol/path from target_url)
          3. Wildcard scope match (*.example.com)
        Returns None if no match found.
        """
        import re
        from urllib.parse import urlparse
        scopes = self.get_structured_scopes(program_handle)
        target_lower = target_url.lower().rstrip('/')

        # Extract hostname for matching against bare-domain scope entries (e.g. "grok.com")
        try:
            parsed = urlparse(target_url)
            target_host = parsed.hostname or ''
        except Exception:
            target_host = ''

        # Pass 1: prefix match against full URL or hostname match
        for scope in scopes:
            ident = scope['asset_identifier'].lower().rstrip('/')
            if (target_lower.startswith(ident)
                    or ident.startswith(target_lower)
                    or ident == target_host.lower()):
                return scope['id']

        # Pass 2: wildcard scopes like *.example.com
        for scope in scopes:
            ident = scope['asset_identifier']
            if '*' in ident:
                pattern = re.escape(ident).replace(r'\*', r'[^.]+')
                if re.search(pattern, target_lower) or re.search(pattern, target_host.lower()):
                    return scope['id']
        return None

    def get_program_info(self, program_handle: str) -> Optional[Dict]:
        """Get program information including scope."""
        status, body = self._api_call('GET', f'/hackers/programs/{program_handle}')
        if status == 200:
            try:
                return json.loads(body)
            except Exception:
                pass
        return None

    def get_my_reports(self, program_handle: str = None, state: str = None) -> List[Dict]:
        """Get my submitted reports via /hackers/me/reports (hacker API)."""
        # Hacker API supports pagination only — no program/state filter server-side
        endpoint = '/hackers/me/reports?page[size]=100'
        status, body = self._api_call('GET', endpoint)
        if status != 200:
            return []
        try:
            reports = json.loads(body).get('data', [])
        except Exception:
            return []

        # Client-side filter by program and/or state
        if program_handle or state:
            filtered = []
            for r in reports:
                attrs = r.get('attributes', {})
                rels = r.get('relationships', {})
                prog = rels.get('program', {}).get('data', {}).get('attributes', {}).get('handle', '')
                if program_handle and prog != program_handle:
                    continue
                if state and attrs.get('state', '') != state:
                    continue
                filtered.append(r)
            return filtered
        return reports

    def check_balance(self) -> Dict:
        """Verify credentials by fetching first page of /hackers/me/reports."""
        # /me doesn't exist in the hacker API — use reports endpoint as credential check
        status, body = self._api_call('GET', '/hackers/me/reports?page[size]=1')
        if status == 200:
            try:
                return {"authenticated": True, "username": self.username}
            except Exception:
                pass
        return {"authenticated": False, "username": self.username, "http_status": status}

    def prepare_report(self, finding: Dict, program_handle: str) -> H1Report:
        """
        Convert a finding dict to H1Report, resolving weakness and scope IDs dynamically.

        Preferred over the static finding_to_h1_report() — this queries the program's
        actual weakness list so the H1-internal ID is correct (not a CWE number).
        """
        report = H1Submitter.finding_to_h1_report(finding)

        # Override weakness_id with dynamically resolved H1-internal ID
        vuln_type = finding.get('vuln_type', '').lower().replace(' ', '_')
        if vuln_type:
            resolved_weakness = self.resolve_weakness_id(program_handle, vuln_type)
            if resolved_weakness is not None:
                report.weakness_id = resolved_weakness

        # Resolve scope ID from target URL if present in the finding
        target_url = finding.get('target_url', finding.get('url', finding.get('asset', '')))
        if target_url:
            resolved_scope = self.resolve_scope_id(program_handle, target_url)
            if resolved_scope is not None:
                report.structured_scope_id = str(resolved_scope)

        return report

    @staticmethod
    def finding_to_h1_report(finding: Dict) -> H1Report:
        """
        Convert a BountyHound finding to H1Report using static WEAKNESS_MAP.

        Use prepare_report() instead when you have a program_handle — it resolves
        weakness and scope IDs dynamically from the program's actual lists.
        """
        # Map vulnerability type to weakness ID (static fallback)
        vuln_type = finding.get('vuln_type', '').lower().replace(' ', '_')
        weakness_id = H1Submitter.WEAKNESS_MAP.get(vuln_type)

        # Build steps from POC
        poc = finding.get('poc', finding.get('test_command', ''))
        steps = finding.get('steps_to_reproduce', '')
        if not steps and poc:
            steps = f"1. Execute the following request:\n\n```\n{poc}\n```\n\n2. Observe the response containing sensitive data."

        # Build expected vs actual
        expected = finding.get('expected_behavior',
                              "The endpoint should require proper authorization and return 403/401 for unauthorized access.")
        actual = finding.get('actual_behavior',
                            f"The endpoint returns {finding.get('evidence', 'sensitive data')} without proper authorization checks.")

        return H1Report(
            title=finding.get('title', 'Untitled Finding'),
            vulnerability_type=finding.get('vuln_type', 'Other'),
            severity=finding.get('severity', 'MEDIUM'),
            summary=finding.get('description', finding.get('title', '')),
            impact=finding.get('impact', f"An attacker could exploit this {finding.get('severity', 'MEDIUM')} severity vulnerability to access unauthorized data."),
            steps_to_reproduce=steps,
            expected_behavior=expected,
            actual_behavior=actual,
            supporting_material=finding.get('screenshots', []),
            weakness_id=weakness_id,
        )

    @staticmethod
    def batch_prepare(target: str) -> List[Dict]:
        """Load all approved findings for a target and prepare for submission."""
        approved_dir = FINDINGS_BASE / target / "approved"
        if not approved_dir.exists():
            return []

        findings = []
        for f in sorted(approved_dir.glob("*.md")):
            try:
                content = f.read_text()
                finding = {
                    'file': str(f),
                    'title': f.stem.replace('VERIFIED-', '').replace('-', ' '),
                    'content': content,
                }
                findings.append(finding)
            except Exception:
                continue
        return findings

    def status(self) -> Dict:
        """Get submitter status."""
        return {
            'has_api_token': bool(self.api_token),
            'has_username': bool(self.username),
            'ready': bool(self.api_token and self.username),
        }
