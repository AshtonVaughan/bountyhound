"""
First-Try Reproduction Report Generator

Generates reports that triagers can reproduce on the FIRST attempt.
Mandatory format: prerequisites, fresh auth setup, atomic curl steps with
expected output, before/after diff table, and a self-contained reproduce.py.

Pulls data from RequestLogger, EvidenceVault, ResponseDiff, and PayloadTracker
to auto-build reports from actual hunt data.

Usage:
    from engine.core.report_generator import ReportGenerator

    gen = ReportGenerator('example.com')
    report = gen.generate(finding, platform='hackerone')
    gen.save(report, finding)
"""

import json
import os
import re
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from engine.core.config import BountyHoundConfig
from engine.core.evidence_vault import EvidenceVault
from engine.core.request_logger import RequestLogger
from engine.core.database import BountyHoundDB


# CWE mappings
CWE_MAP = {
    'IDOR': 'CWE-639', 'XSS': 'CWE-79', 'SQLi': 'CWE-89',
    'CSRF': 'CWE-352', 'SSRF': 'CWE-918', 'XXE': 'CWE-611',
    'RCE': 'CWE-94', 'LFI': 'CWE-22', 'Auth Bypass': 'CWE-287',
    'Info Disclosure': 'CWE-200', 'S3 Public': 'CWE-732',
    'CORS': 'CWE-942', 'Subdomain Takeover': 'CWE-350',
    'Rate Limit': 'CWE-770', 'GraphQL Auth': 'CWE-862',
    'Open Redirect': 'CWE-601', 'Command Injection': 'CWE-78',
    'Privilege Escalation': 'CWE-269', 'File Upload': 'CWE-434',
    'Race Condition': 'CWE-362', 'JWT': 'CWE-347',
    'HTTP Smuggling': 'CWE-444', 'NoSQLi': 'CWE-943',
}


def _request_to_curl(req: Dict) -> str:
    """Convert a logged request dict to a curl command string."""
    method = req.get('method', 'GET')
    url = req.get('url', '')
    headers = req.get('req_headers', '')
    body = req.get('req_body', '')

    parts = ['curl -s']

    if method != 'GET':
        parts.append(f'-X {method}')

    parts.append(f"'{url}'")

    # Parse headers
    if headers:
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except (json.JSONDecodeError, ValueError):
                headers = {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                # Parameterize auth tokens
                if k.lower() == 'authorization':
                    parts.append(f"-H 'Authorization: $AUTH_TOKEN'")
                else:
                    parts.append(f"-H '{k}: {v}'")

    # Body
    if body:
        escaped = body.replace("'", "'\\''")
        parts.append(f"-d '{escaped}'")

    return ' \\\n  '.join(parts)


def _truncate(text: str, max_len: int = 500) -> str:
    """Truncate text for display, preserving JSON structure."""
    if not text or len(text) <= max_len:
        return text or ''
    return text[:max_len] + '\n... (truncated)'


def _format_json_safe(text: str) -> str:
    """Try to pretty-print as JSON, fall back to raw text."""
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2)
    except (json.JSONDecodeError, ValueError, TypeError):
        return text or ''


class ReportGenerator:
    """Generates first-try reproduction reports from hunt data."""

    def __init__(self, target: str):
        self.target = target
        self.vault = EvidenceVault(target)
        self.logger = RequestLogger()
        self.reports_dir = BountyHoundConfig.reports_dir(target)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Main generation methods
    # ------------------------------------------------------------------

    def generate(self, finding: Dict[str, Any],
                 platform: str = 'hackerone') -> str:
        """Generate a complete first-try reproduction report.

        This is the primary entry point. It builds every mandatory section
        and returns the full markdown report.

        Args:
            finding: Finding dict with keys: title, severity, vuln_type,
                     endpoint, description, and optionally: steps, payload,
                     baseline_response, exploit_response, expected_behavior,
                     actual_behavior, auth_token_a, auth_token_b, etc.
            platform: Target platform ('hackerone', 'bugcrowd', 'intigriti')

        Returns:
            Complete markdown report string.
        """
        sections = []

        # Title
        title = finding.get('title', 'Untitled Finding')
        sections.append(f'# {title}\n')

        # Prerequisites (MANDATORY)
        sections.append(self._build_prerequisites(finding))

        # Environment
        sections.append(self._build_environment(finding))

        # Step 0: Fresh Auth Setup (MANDATORY)
        sections.append(self._build_auth_setup(finding))

        # Step 1: Baseline (MANDATORY)
        sections.append(self._build_baseline(finding))

        # Step 2: Exploit (MANDATORY)
        sections.append(self._build_exploit(finding))

        # Step 3: Verify Impact
        sections.append(self._build_verification(finding))

        # Before/After Diff Table (MANDATORY)
        sections.append(self._build_diff_table(finding))

        # Reproduction Script (MANDATORY)
        sections.append(self._build_reproduction_script(finding))

        # Impact (MANDATORY)
        sections.append(self._build_impact(finding))

        # Remediation
        sections.append(self._build_remediation(finding))

        # Platform-specific additions
        if platform == 'hackerone':
            sections.append(self._build_hackerone_extras(finding))
        elif platform == 'bugcrowd':
            sections.append(self._build_bugcrowd_extras(finding))

        # Quality checklist
        sections.append(self._build_quality_checklist(finding))

        return '\n'.join(sections)

    def generate_from_requests(self, finding: Dict[str, Any],
                               baseline_request_id: Optional[int] = None,
                               exploit_request_id: Optional[int] = None,
                               verify_request_id: Optional[int] = None,
                               platform: str = 'hackerone') -> str:
        """Generate report using actual logged request IDs.

        Pulls real request/response data from RequestLogger and builds
        the report with actual curl commands and responses.
        """
        requests = self.logger.get_requests(self.target, limit=200)
        req_by_id = {r.get('id', 0): r for r in requests}

        # Enrich finding with actual request data
        if baseline_request_id and baseline_request_id in req_by_id:
            req = req_by_id[baseline_request_id]
            finding['baseline_curl'] = _request_to_curl(req)
            finding['baseline_response'] = req.get('resp_body', '')
            finding['baseline_status'] = req.get('status_code', 0)

        if exploit_request_id and exploit_request_id in req_by_id:
            req = req_by_id[exploit_request_id]
            finding['exploit_curl'] = _request_to_curl(req)
            finding['exploit_response'] = req.get('resp_body', '')
            finding['exploit_status'] = req.get('status_code', 0)

        if verify_request_id and verify_request_id in req_by_id:
            req = req_by_id[verify_request_id]
            finding['verify_curl'] = _request_to_curl(req)
            finding['verify_response'] = req.get('resp_body', '')

        return self.generate(finding, platform)

    def save(self, report: str, finding: Dict[str, Any],
             platform: str = 'hackerone') -> str:
        """Save report to disk and return the file path."""
        vuln_type = finding.get('vuln_type', 'unknown').replace(' ', '-').lower()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_title = re.sub(r'[^\w\-]', '_', finding.get('title', 'report')[:40])
        filename = f'{timestamp}_{vuln_type}_{safe_title}_{platform}.md'
        filepath = self.reports_dir / filename
        filepath.write_text(report, encoding='utf-8')

        # Also save reproduction script separately
        script = self._generate_reproduce_py(finding)
        script_path = self.reports_dir / f'{timestamp}_{vuln_type}_reproduce.py'
        script_path.write_text(script, encoding='utf-8')

        return str(filepath)

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_prerequisites(self, finding: Dict) -> str:
        """Build the prerequisites checklist section."""
        prereqs = finding.get('prerequisites', [])
        if not prereqs:
            # Auto-detect prerequisites from finding
            prereqs = []
            vuln_type = finding.get('vuln_type', '')
            if vuln_type in ('IDOR', 'Privilege Escalation', 'Auth Bypass', 'GraphQL Auth'):
                prereqs.append('Account A (victim): Any registered user')
                prereqs.append('Account B (attacker): A different registered user')
            elif vuln_type in ('XSS', 'CSRF'):
                prereqs.append('One registered user account')
            elif vuln_type == 'S3 Public':
                prereqs.append('AWS CLI configured with any AWS account')
            elif vuln_type == 'Subdomain Takeover':
                prereqs.append('Ability to create resources on the target service')
            else:
                prereqs.append('One registered user account (minimum)')

            # Detect region requirements
            if finding.get('region_specific'):
                prereqs.append(f"Region: {finding['region_specific']}")
            else:
                prereqs.append('Region: Any (no geo-restriction detected)')

            # Special conditions
            if finding.get('special_conditions'):
                prereqs.append(f"Special: {finding['special_conditions']}")

        lines = ['## Prerequisites\n']
        for p in prereqs:
            lines.append(f'- [ ] {p}')
        lines.append('')
        return '\n'.join(lines)

    def _build_environment(self, finding: Dict) -> str:
        """Build the environment/target info section."""
        endpoint = finding.get('endpoint', f'https://{self.target}')
        tech = finding.get('tech_stack', 'Unknown')
        return f"""## Environment

- **Target:** `{self.target}`
- **Endpoint:** `{endpoint}`
- **Tech Stack:** {tech}
- **Date Tested:** {datetime.now().strftime('%Y-%m-%d')}
"""

    def _build_auth_setup(self, finding: Dict) -> str:
        """Build Step 0: Fresh auth generation.

        MANDATORY: Never embed static tokens. Always show how to get fresh ones.
        """
        lines = ['## Step 0: Setup (Get Fresh Auth Tokens)\n']
        lines.append('> Replace placeholder credentials with your test account details.\n')

        login_url = finding.get('login_url', f'https://{self.target}/api/auth/login')
        login_method = finding.get('login_method', 'POST')

        # User A (victim) login
        lines.append('**Get User A (victim) token:**')
        lines.append('```bash')
        if finding.get('auth_curl_a'):
            lines.append(finding['auth_curl_a'])
        else:
            lines.append(f'curl -s -X {login_method} {login_url} \\')
            lines.append("  -H 'Content-Type: application/json' \\")
            lines.append("  -d '{\"email\": \"$USER_A_EMAIL\", \"password\": \"$USER_A_PASSWORD\"}'")
        lines.append('```')
        lines.append('Save the returned token as `$USER_A_TOKEN`\n')

        # User B (attacker) login - for multi-user vulns
        vuln_type = finding.get('vuln_type', '')
        if vuln_type in ('IDOR', 'Privilege Escalation', 'Auth Bypass', 'GraphQL Auth', 'Race Condition'):
            lines.append('**Get User B (attacker) token:**')
            lines.append('```bash')
            if finding.get('auth_curl_b'):
                lines.append(finding['auth_curl_b'])
            else:
                lines.append(f'curl -s -X {login_method} {login_url} \\')
                lines.append("  -H 'Content-Type: application/json' \\")
                lines.append("  -d '{\"email\": \"$USER_B_EMAIL\", \"password\": \"$USER_B_PASSWORD\"}'")
            lines.append('```')
            lines.append('Save the returned token as `$USER_B_TOKEN`\n')

        lines.append('---\n')
        return '\n'.join(lines)

    def _build_baseline(self, finding: Dict) -> str:
        """Build Step 1: Baseline showing normal/expected behavior.

        MANDATORY: Always show what the NORMAL response looks like.
        """
        lines = ['## Step 1: Baseline (Normal Behavior)\n']
        lines.append('> This shows what the response looks like under NORMAL, authorized access.\n')

        # Curl command
        if finding.get('baseline_curl'):
            lines.append('```bash')
            lines.append(finding['baseline_curl'])
            lines.append('```\n')
        else:
            endpoint = finding.get('endpoint', f'https://{self.target}/api/endpoint')
            lines.append('```bash')
            lines.append(f'curl -s \\')
            lines.append(f"  -H 'Authorization: $USER_A_TOKEN' \\")
            lines.append(f"  '{endpoint}'")
            lines.append('```\n')

        # Expected output
        lines.append('**Expected output** (normal, authorized response):')
        baseline_resp = finding.get('baseline_response', '')
        if baseline_resp:
            lines.append('```json')
            lines.append(_truncate(_format_json_safe(baseline_resp), 800))
            lines.append('```')
        else:
            status = finding.get('baseline_status', 200)
            lines.append(f'```\nHTTP {status} with user\'s own data\n```')

        lines.append('')
        return '\n'.join(lines)

    def _build_exploit(self, finding: Dict) -> str:
        """Build Step 2: The exploit step.

        MANDATORY: Exact curl command with expected (vulnerable) output.
        """
        lines = ['## Step 2: Exploit (The Vulnerability)\n']

        vuln_type = finding.get('vuln_type', '')
        if vuln_type in ('IDOR', 'Privilege Escalation', 'Auth Bypass'):
            lines.append('> Access User A\'s data using User B\'s credentials.\n')
        elif vuln_type == 'XSS':
            lines.append('> Inject payload that executes in victim\'s browser.\n')
        else:
            lines.append('> Execute the exploit payload.\n')

        # Curl command
        if finding.get('exploit_curl'):
            lines.append('```bash')
            lines.append(finding['exploit_curl'])
            lines.append('```\n')
        elif finding.get('curl_command'):
            lines.append('```bash')
            lines.append(finding['curl_command'])
            lines.append('```\n')
        else:
            endpoint = finding.get('endpoint', f'https://{self.target}/api/endpoint')
            payload = finding.get('payload', '')
            lines.append('```bash')
            if payload:
                lines.append(f'curl -s -X POST \\')
                lines.append(f"  -H 'Authorization: $USER_B_TOKEN' \\")
                lines.append(f"  -H 'Content-Type: application/json' \\")
                escaped = json.dumps(payload) if isinstance(payload, dict) else str(payload)
                lines.append(f"  -d '{escaped}' \\")
                lines.append(f"  '{endpoint}'")
            else:
                lines.append(f'curl -s \\')
                lines.append(f"  -H 'Authorization: $USER_B_TOKEN' \\")
                lines.append(f"  '{endpoint}'")
            lines.append('```\n')

        # Exploit output
        lines.append('**Actual output** (THIS IS THE BUG):')
        exploit_resp = finding.get('exploit_response', '')
        if exploit_resp:
            lines.append('```json')
            lines.append(_truncate(_format_json_safe(exploit_resp), 800))
            lines.append('```')
        else:
            lines.append(f'```\nHTTP {finding.get("exploit_status", 200)} - '
                         f'Returns data that should be denied\n```')

        # Clarify ambiguous responses
        if finding.get('ambiguous_response_note'):
            lines.append(f'\n> **Note:** {finding["ambiguous_response_note"]}')

        lines.append('')
        return '\n'.join(lines)

    def _build_verification(self, finding: Dict) -> str:
        """Build Step 3: Verify the impact."""
        lines = ['## Step 3: Verify Impact\n']

        if finding.get('verify_curl'):
            lines.append('```bash')
            lines.append(finding['verify_curl'])
            lines.append('```\n')

        if finding.get('verify_response'):
            lines.append('**Verification response:**')
            lines.append('```json')
            lines.append(_truncate(_format_json_safe(finding['verify_response']), 500))
            lines.append('```')

        # State change description
        if finding.get('state_change_description'):
            lines.append(f"\n**State change confirmed:** {finding['state_change_description']}")
        elif finding.get('state_change_confirmed'):
            lines.append('\n**State change confirmed:** Yes - data was read/modified/deleted as described.')
        else:
            lines.append(
                '\n**Verification:** The response above contains data belonging to User A, '
                'accessed via User B\'s session. This proves the authorization check is missing.'
            )

        lines.append('')
        return '\n'.join(lines)

    def _build_diff_table(self, finding: Dict) -> str:
        """Build the before/after diff table.

        MANDATORY: Always show normal vs exploit responses side-by-side.
        """
        lines = ['## Before/After Diff\n']

        diff_rows = finding.get('diff_rows', [])
        if diff_rows:
            lines.append('| Field | Normal (Authorized) | Exploit (Unauthorized) | Should Be |')
            lines.append('|-------|--------------------|-----------------------|-----------|')
            for row in diff_rows:
                field = row.get('field', '')
                normal = row.get('normal', '')
                exploit = row.get('exploit', '')
                should_be = row.get('should_be', '')
                lines.append(f'| {field} | {normal} | {exploit} | {should_be} |')
        else:
            # Auto-generate from baseline/exploit responses
            baseline_status = finding.get('baseline_status', 200)
            exploit_status = finding.get('exploit_status', 200)
            expected_status = finding.get('expected_exploit_status', 403)

            lines.append('| Field | Normal (User A) | Exploit (User B) | Should Be |')
            lines.append('|-------|-----------------|------------------|-----------|')
            lines.append(f'| HTTP Status | {baseline_status} | {exploit_status} | {expected_status} |')

            # Try to extract key fields from responses
            baseline_body = finding.get('baseline_response', '')
            exploit_body = finding.get('exploit_response', '')
            if baseline_body and exploit_body:
                try:
                    b_json = json.loads(baseline_body) if isinstance(baseline_body, str) else baseline_body
                    e_json = json.loads(exploit_body) if isinstance(exploit_body, str) else exploit_body
                    if isinstance(b_json, dict) and isinstance(e_json, dict):
                        # Find overlapping keys that suggest data leak
                        for key in list(b_json.keys())[:5]:
                            b_val = str(b_json.get(key, ''))[:30]
                            e_val = str(e_json.get(key, ''))[:30]
                            lines.append(f'| body.{key} | `{b_val}` | `{e_val}` | `error/denied` |')
                except (json.JSONDecodeError, ValueError, TypeError):
                    lines.append(f'| Response body | User A data | **User A data (LEAKED)** | `error/denied` |')
            else:
                lines.append(f'| Response body | User A data | **User A data (LEAKED)** | `error/denied` |')

        lines.append('')
        return '\n'.join(lines)

    def _build_reproduction_script(self, finding: Dict) -> str:
        """Build the reproduction script section.

        MANDATORY: Every report includes a self-contained Python script.
        """
        lines = ['## Reproduction Script\n']
        lines.append('> Save as `reproduce.py` and run: `python reproduce.py`\n')
        lines.append('```python')
        lines.append(self._generate_reproduce_py(finding))
        lines.append('```\n')
        return '\n'.join(lines)

    def _generate_reproduce_py(self, finding: Dict) -> str:
        """Generate a self-contained Python reproduction script."""
        endpoint = finding.get('endpoint', f'https://{self.target}/api/endpoint')
        vuln_type = finding.get('vuln_type', 'Unknown')
        title = finding.get('title', 'Untitled')
        method = finding.get('method', 'GET').upper()
        payload = finding.get('payload', '')

        needs_two_users = vuln_type in ('IDOR', 'Privilege Escalation', 'Auth Bypass', 'GraphQL Auth')

        script_lines = [
            '#!/usr/bin/env python3',
            f'"""Reproduction script: {title}',
            f'Vulnerability: {vuln_type}',
            f'Target: {self.target}',
            f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            '',
            'Usage:',
            '  1. Fill in the credentials/tokens below',
            '  2. Run: python reproduce.py',
            '  3. Output will show VULNERABLE or NOT VULNERABLE',
            '"""',
            '',
            'import json',
            'import sys',
            'import urllib.request',
            'import urllib.error',
            '',
            '# ============================================================',
            '# FILL IN THESE VALUES BEFORE RUNNING',
            '# ============================================================',
        ]

        if needs_two_users:
            script_lines.extend([
                'USER_A_TOKEN = ""  # Victim\'s auth token (Bearer ...)',
                'USER_B_TOKEN = ""  # Attacker\'s auth token (Bearer ...)',
            ])
        else:
            script_lines.extend([
                'AUTH_TOKEN = ""  # Your auth token (Bearer ...)',
            ])

        script_lines.extend([
            '',
            '',
            'def make_request(url, method="GET", headers=None, body=None):',
            '    """Make an HTTP request and return (status, body_text)."""',
            '    if headers is None:',
            '        headers = {}',
            '    data = body.encode("utf-8") if body else None',
            '    req = urllib.request.Request(url, data=data, headers=headers, method=method)',
            '    try:',
            '        resp = urllib.request.urlopen(req, timeout=15)',
            '        return resp.status, resp.read().decode("utf-8", errors="replace")',
            '    except urllib.error.HTTPError as e:',
            '        return e.code, e.read().decode("utf-8", errors="replace")',
            '    except Exception as e:',
            '        return 0, str(e)',
            '',
            '',
            'def main():',
        ])

        if needs_two_users:
            script_lines.extend([
                '    if not USER_A_TOKEN or not USER_B_TOKEN:',
                '        print("ERROR: Fill in USER_A_TOKEN and USER_B_TOKEN before running")',
                '        sys.exit(1)',
                '',
                '    print(f"Target: {endpoint}")',
                '    print(f"Vuln: {vuln_type}")',
                '    print()',
                '',
                '    # Step 1: Baseline - User A accesses own data (normal)',
                '    print("Step 1: Baseline (User A -> own data)...")',
                f'    status_a, body_a = make_request(',
                f'        "{endpoint}",',
                f'        method="{method}",',
                '        headers={"Authorization": USER_A_TOKEN, "Content-Type": "application/json"},',
            ])
            if payload:
                p_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
                script_lines.append(f'        body={repr(p_str)},')
            script_lines.extend([
                '    )',
                '    print(f"  Status: {status_a}")',
                '    print(f"  Body: {body_a[:200]}")',
                '    print()',
                '',
                '    # Step 2: Exploit - User B accesses User A\'s data (the bug)',
                '    print("Step 2: Exploit (User B -> User A data)...")',
                f'    status_b, body_b = make_request(',
                f'        "{endpoint}",',
                f'        method="{method}",',
                '        headers={"Authorization": USER_B_TOKEN, "Content-Type": "application/json"},',
            ])
            if payload:
                script_lines.append(f'        body={repr(p_str)},')
            script_lines.extend([
                '    )',
                '    print(f"  Status: {status_b}")',
                '    print(f"  Body: {body_b[:200]}")',
                '    print()',
                '',
                '    # Step 3: Verdict',
                '    if status_b in (200, 201) and len(body_b) > 50:',
                '        # Check if User B got actual data (not an error)',
                '        try:',
                '            data = json.loads(body_b)',
                '            if "error" in data or "errors" in data:',
                '                print("RESULT: NOT VULNERABLE (error response)")',
                '                sys.exit(0)',
                '        except (json.JSONDecodeError, ValueError):',
                '            pass',
                '        print("=" * 50)',
                '        print("RESULT: VULNERABLE")',
                '        print(f"User B (attacker) received HTTP {status_b} with data")',
                '        print(f"Expected: HTTP 403 or error response")',
                '        print("=" * 50)',
                '        sys.exit(1)',
                '    elif status_b in (401, 403):',
                '        print("RESULT: NOT VULNERABLE (access denied as expected)")',
                '        sys.exit(0)',
                '    else:',
                '        print(f"RESULT: INCONCLUSIVE (HTTP {status_b}, manual review needed)")',
                '        sys.exit(2)',
            ])
        else:
            script_lines.extend([
                '    if not AUTH_TOKEN:',
                '        print("ERROR: Fill in AUTH_TOKEN before running")',
                '        sys.exit(1)',
                '',
                f'    print("Target: {endpoint}")',
                f'    print("Vuln: {vuln_type}")',
                '    print()',
                '',
                '    # Execute exploit',
                '    print("Executing exploit...")',
                f'    status, body = make_request(',
                f'        "{endpoint}",',
                f'        method="{method}",',
                '        headers={"Authorization": AUTH_TOKEN, "Content-Type": "application/json"},',
            ])
            if payload:
                p_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
                script_lines.append(f'        body={repr(p_str)},')
            script_lines.extend([
                '    )',
                '    print(f"  Status: {status}")',
                '    print(f"  Body: {body[:200]}")',
                '    print()',
                '',
                '    # Verdict',
                '    if status == 200:',
                '        print("=" * 50)',
                '        print("RESULT: POTENTIALLY VULNERABLE")',
                '        print("Manual verification required - check response data")',
                '        print("=" * 50)',
                '    else:',
                '        print(f"RESULT: HTTP {status} - review manually")',
            ])

        script_lines.extend([
            '',
            '',
            'if __name__ == "__main__":',
            '    main()',
        ])

        return '\n'.join(script_lines)

    def _build_impact(self, finding: Dict) -> str:
        """Build business-focused impact section."""
        lines = ['## Impact\n']

        if finding.get('impact'):
            lines.append(finding['impact'])
        else:
            vuln_type = finding.get('vuln_type', '')
            severity = finding.get('severity', 'MEDIUM')
            lines.append(finding.get('description', 'Unauthorized access to sensitive data.'))

        # Attack scenario
        if finding.get('attack_scenario'):
            lines.append(f"\n**Attack Scenario:**\n{finding['attack_scenario']}")

        # Affected users
        if finding.get('affected_users'):
            lines.append(f"\n**Affected Users:** {finding['affected_users']}")

        # CWE
        cwe = CWE_MAP.get(finding.get('vuln_type', ''), '')
        if cwe:
            lines.append(f'\n**CWE:** {cwe}')

        lines.append('')
        return '\n'.join(lines)

    def _build_remediation(self, finding: Dict) -> str:
        """Build remediation section."""
        lines = ['## Recommended Fix\n']
        if finding.get('remediation'):
            lines.append(finding['remediation'])
        else:
            lines.append('Implement proper authorization checks on this endpoint to verify '
                         'the requesting user owns the requested resource.')
        lines.append('')
        return '\n'.join(lines)

    def _build_hackerone_extras(self, finding: Dict) -> str:
        """Add HackerOne-specific sections."""
        lines = ['## Supporting Material\n']

        # List evidence from vault
        manifest = self.vault.get_manifest()
        if manifest:
            for item in manifest[:10]:
                lines.append(f"- `{item['filename']}` ({item['category']}, {item['size']} bytes)")
        else:
            lines.append('- HTTP request/response logs attached')
            lines.append('- Reproduction script: `reproduce.py`')

        lines.append('')
        return '\n'.join(lines)

    def _build_bugcrowd_extras(self, finding: Dict) -> str:
        """Add Bugcrowd-specific severity justification."""
        severity = finding.get('severity', 'MEDIUM')
        lines = [f'## Severity Justification\n']
        lines.append(f'**Severity:** {severity}')
        cwe = CWE_MAP.get(finding.get('vuln_type', ''), 'N/A')
        lines.append(f'**CWE:** {cwe}')
        lines.append(f'\nThis vulnerability is rated {severity} based on:')
        lines.append('- Impact to data confidentiality and integrity')
        lines.append('- Low attack complexity (no special conditions required)')
        lines.append('- Network-accessible without physical access')
        lines.append('')
        return '\n'.join(lines)

    def _build_quality_checklist(self, finding: Dict) -> str:
        """Build quality self-check at the end of the report.

        This checklist is for the REPORTER to verify before submitting.
        It should be REMOVED from the final submission.
        """
        has_baseline = bool(finding.get('baseline_response') or finding.get('baseline_curl'))
        has_exploit = bool(finding.get('exploit_response') or finding.get('exploit_curl') or finding.get('curl_command'))
        has_diff = bool(finding.get('diff_rows'))
        has_state_change = bool(finding.get('state_change_confirmed'))

        lines = [
            '---',
            '## Pre-Submission Checklist (REMOVE BEFORE SUBMITTING)\n',
            f'- [{"x" if True else " "}] Prerequisites listed',
            f'- [{"x" if True else " "}] Step 0: Fresh auth generation included',
            f'- [{"x" if has_baseline else " "}] Step 1: Baseline (normal behavior) shown',
            f'- [{"x" if has_exploit else " "}] Step 2: Exploit with expected output shown',
            f'- [{"x" if has_diff else " "}] Before/After diff table included',
            f'- [{"x" if True else " "}] Reproduction script (reproduce.py) included',
            f'- [{"x" if has_state_change else " "}] State change verified (not just HTTP 200)',
            f'- [ ] Reproduction script tested from clean state',
            f'- [ ] Screenshots/video attached',
            f'- [ ] All tokens are parameterized (no hardcoded secrets)',
            '',
        ]
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Utility: Auto-build from request log
    # ------------------------------------------------------------------

    def auto_build_finding(self, endpoint: str,
                           vuln_type: str = 'IDOR') -> Dict:
        """Auto-build a finding dict from logged requests for an endpoint.

        Searches RequestLogger for requests matching the endpoint and
        builds baseline/exploit data automatically.
        """
        requests = self.logger.get_requests_by_url(self.target, endpoint)
        if not requests:
            return {'endpoint': endpoint, 'vuln_type': vuln_type, 'title': f'{vuln_type} in {endpoint}'}

        # Use first request as baseline, look for cross-account requests
        finding: Dict[str, Any] = {
            'endpoint': endpoint,
            'vuln_type': vuln_type,
            'title': f'{vuln_type} in {endpoint}',
            'severity': 'HIGH',
        }

        if len(requests) >= 2:
            finding['baseline_curl'] = _request_to_curl(requests[0])
            finding['baseline_response'] = requests[0].get('resp_body', '')
            finding['baseline_status'] = requests[0].get('status_code', 200)
            finding['exploit_curl'] = _request_to_curl(requests[1])
            finding['exploit_response'] = requests[1].get('resp_body', '')
            finding['exploit_status'] = requests[1].get('status_code', 200)
        elif len(requests) == 1:
            finding['exploit_curl'] = _request_to_curl(requests[0])
            finding['exploit_response'] = requests[0].get('resp_body', '')
            finding['exploit_status'] = requests[0].get('status_code', 200)

        return finding
