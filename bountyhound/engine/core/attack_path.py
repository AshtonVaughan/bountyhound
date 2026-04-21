"""
Attack Path Validator - Validates complete attack paths from attacker action to victim impact.

Ensures every reported vulnerability has a clear, reproducible path from
initial access to demonstrated impact, preventing incomplete or theoretical
reports.

Usage:
    from engine.core.attack_path import AttackPath

    path = {
        'entry_point': 'Unauthenticated API call to /api/users',
        'steps': ['Enumerate user IDs via /api/users?page=1',
                  'Request /api/users/{id}/profile with victim ID',
                  'Receive full PII (email, phone, address)'],
        'impact': 'Full PII disclosure of any user',
        'requires_auth': False,
        'requires_interaction': False,
        'verified_steps': [True, True, True],
    }
    result = AttackPath.validate(path)
"""

from datetime import datetime
from typing import Dict, List, Optional


class AttackPath:
    """Validate complete attack paths from initial access to impact."""

    @staticmethod
    def validate(path: Dict) -> Dict:
        """
        Validate a complete attack path.

        Args:
            path: Dict containing:
                entry_point (str): How the attacker starts.
                steps (List[str]): Ordered steps of the attack.
                impact (str): What the attacker ultimately achieves.
                requires_auth (bool): Whether attacker needs authentication.
                requires_interaction (bool): Whether victim must do something.
                verified_steps (List[bool]): Which steps have been proven.

        Returns:
            dict with:
                valid (bool): True if all steps are verified and path is complete.
                completeness (float): 0.0 to 1.0 ratio of verified steps.
                missing_steps (List[str]): Descriptions of unverified steps.
                severity (str): Estimated severity based on path characteristics.
                reportable (bool): Whether this is ready to submit.
                issues (List[str]): Human-readable list of problems.
        """
        issues: List[str] = []
        missing_steps: List[str] = []

        entry_point = (path.get('entry_point') or '').strip()
        steps = path.get('steps') or []
        impact = (path.get('impact') or '').strip()
        requires_auth = path.get('requires_auth', False)
        requires_interaction = path.get('requires_interaction', False)
        verified_steps = path.get('verified_steps') or []

        # --- Entry point check ---
        if not entry_point:
            issues.append("Entry point is not defined")

        # --- Steps check ---
        if not steps:
            issues.append("No attack steps defined")

        # --- Impact check ---
        if not impact:
            issues.append("Impact is not defined")

        # --- Verified steps alignment ---
        if len(verified_steps) < len(steps):
            # Pad with False for any missing verification flags
            verified_steps = list(verified_steps) + [False] * (len(steps) - len(verified_steps))
        elif len(verified_steps) > len(steps):
            # Truncate to match steps count
            verified_steps = verified_steps[:len(steps)]

        # --- Check each step ---
        verified_count = 0
        for idx, step in enumerate(steps):
            is_verified = verified_steps[idx] if idx < len(verified_steps) else False
            if is_verified:
                verified_count += 1
            else:
                missing_steps.append(f"Step {idx + 1}: {step}")
                issues.append(f"Step {idx + 1} is not verified: {step}")

        # --- Completeness ---
        completeness = verified_count / len(steps) if steps else 0.0

        # --- Severity estimation ---
        severity = _estimate_severity(
            entry_point=entry_point,
            impact=impact,
            requires_auth=requires_auth,
            requires_interaction=requires_interaction,
            step_count=len(steps),
        )

        # --- Auth context ---
        if requires_auth:
            issues.append(
                "Requires authentication — ensure attacker can realistically obtain credentials"
            )

        # --- Interaction context ---
        if requires_interaction:
            issues.append(
                "Requires victim interaction — document exact user action needed"
            )

        # --- Validity ---
        has_entry = bool(entry_point)
        has_steps = len(steps) > 0
        has_impact = bool(impact)
        all_verified = (verified_count == len(steps)) and has_steps

        valid = has_entry and has_steps and has_impact and all_verified

        # --- Reportable ---
        reportable = valid and completeness >= 0.8

        return {
            'valid': valid,
            'completeness': round(completeness, 4),
            'missing_steps': missing_steps,
            'severity': severity,
            'reportable': reportable,
            'issues': issues,
        }

    @staticmethod
    def suggest_attack_path(
        vuln_type: str,
        endpoint: str,
        auth_context: str = 'unauthenticated',
    ) -> Dict:
        """
        Suggest a standard attack path template for a given vulnerability type.

        Provides a starting point that the tester fills in with real evidence.

        Args:
            vuln_type: Vulnerability type (IDOR, XSS, SQLi, Auth_Bypass, etc.).
            endpoint: The target endpoint URL or description.
            auth_context: 'unauthenticated', 'authenticated', or 'low_privilege'.

        Returns:
            dict with:
                entry_point (str): Suggested entry point.
                steps (List[str]): Template steps to follow.
                expected_impact (str): What the attacker should achieve.
                verification_needed (List[str]): What must be proven.
        """
        vuln_upper = vuln_type.upper().replace(' ', '_').replace('-', '_')
        templates = _get_attack_templates()

        template = templates.get(vuln_upper)
        if template is None:
            # Fallback generic template
            return {
                'entry_point': f'{auth_context.capitalize()} access to {endpoint}',
                'steps': [
                    f'Identify vulnerable parameter or function at {endpoint}',
                    'Craft malicious input or request',
                    'Send the crafted request',
                    'Observe the response for signs of exploitation',
                    'Verify impact by checking server-side state change',
                ],
                'expected_impact': f'Exploitation of {vuln_type} at {endpoint}',
                'verification_needed': [
                    'Confirm the request reaches the backend',
                    'Confirm actual state change or data leakage',
                    'Rule out false positive (schema validation, WAF block, etc.)',
                ],
            }

        # Substitute placeholders
        entry = template['entry_point'].format(
            endpoint=endpoint, auth_context=auth_context,
        )
        steps = [s.format(endpoint=endpoint) for s in template['steps']]
        impact = template['expected_impact'].format(endpoint=endpoint)
        verification = list(template['verification_needed'])

        return {
            'entry_point': entry,
            'steps': steps,
            'expected_impact': impact,
            'verification_needed': verification,
        }

    @staticmethod
    def format_for_report(path: Dict, validation: Dict) -> str:
        """
        Format an attack path as markdown for inclusion in a bug report.

        Args:
            path: The attack path dict (same format as validate input).
            validation: Output of AttackPath.validate().

        Returns:
            Markdown-formatted string.
        """
        lines: List[str] = []
        lines.append("## Attack Path")
        lines.append("")

        # Entry point
        entry = path.get('entry_point', '(not defined)')
        lines.append(f"**Entry Point**: {entry}")
        lines.append("")

        # Auth/interaction context
        context_parts: List[str] = []
        if path.get('requires_auth'):
            context_parts.append("Requires authentication")
        else:
            context_parts.append("No authentication required")
        if path.get('requires_interaction'):
            context_parts.append("Requires victim interaction")
        else:
            context_parts.append("No victim interaction required")
        lines.append(f"**Context**: {' | '.join(context_parts)}")
        lines.append("")

        # Steps with verification status
        lines.append("**Steps**:")
        lines.append("")
        steps = path.get('steps', [])
        verified_steps = path.get('verified_steps', [])
        for idx, step in enumerate(steps):
            is_verified = (
                verified_steps[idx] if idx < len(verified_steps) else False
            )
            check = "[x]" if is_verified else "[ ]"
            status_label = "(verified)" if is_verified else "(NOT verified)"
            lines.append(f"{idx + 1}. {check} {step} {status_label}")
        lines.append("")

        # Impact
        impact = path.get('impact', '(not defined)')
        lines.append(f"**Impact**: {impact}")
        lines.append("")

        # Validation summary
        completeness = validation.get('completeness', 0)
        severity = validation.get('severity', 'UNKNOWN')
        reportable = validation.get('reportable', False)
        lines.append(
            f"**Completeness**: {completeness:.0%} | "
            f"**Severity**: {severity} | "
            f"**Reportable**: {'Yes' if reportable else 'No'}"
        )
        lines.append("")

        # Issues
        issues = validation.get('issues', [])
        if issues:
            lines.append("**Issues to resolve**:")
            lines.append("")
            for issue in issues:
                lines.append(f"- {issue}")
            lines.append("")

        # Missing steps
        missing = validation.get('missing_steps', [])
        if missing:
            lines.append("**Unverified steps**:")
            lines.append("")
            for m in missing:
                lines.append(f"- {m}")
            lines.append("")

        lines.append(
            f"*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*"
        )

        return "\n".join(lines)


# ------------------------------------------------------------------
# Module-level helpers (private)
# ------------------------------------------------------------------

def _estimate_severity(
    entry_point: str,
    impact: str,
    requires_auth: bool,
    requires_interaction: bool,
    step_count: int,
) -> str:
    """
    Estimate severity based on attack path characteristics.

    This is a rough heuristic — the real severity should be determined
    by actual impact analysis.
    """
    impact_lower = impact.lower()

    # Critical impact indicators
    critical_indicators = (
        'remote code execution', 'rce', 'full account takeover',
        'complete database', 'admin access', 'root access',
        'all user data', 'financial loss', 'payment bypass',
    )
    high_indicators = (
        'account takeover', 'pii disclosure', 'privilege escalation',
        'authentication bypass', 'auth bypass', 'sensitive data',
        'write access', 'modify data', 'delete data',
        'stored xss', 'ssrf internal',
    )
    medium_indicators = (
        'information disclosure', 'reflected xss', 'csrf',
        'idor read', 'limited data', 'session', 'email leak',
    )
    low_indicators = (
        'open redirect', 'information leak', 'verbose error',
        'missing header', 'self-xss', 'rate limit',
    )

    # Check impact text against indicators
    if any(ind in impact_lower for ind in critical_indicators):
        base_severity = 'CRITICAL'
    elif any(ind in impact_lower for ind in high_indicators):
        base_severity = 'HIGH'
    elif any(ind in impact_lower for ind in medium_indicators):
        base_severity = 'MEDIUM'
    elif any(ind in impact_lower for ind in low_indicators):
        base_severity = 'LOW'
    else:
        base_severity = 'MEDIUM'  # Default

    # Adjustments
    severity_scores = {
        'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0,
    }
    score_to_sev = {v: k for k, v in severity_scores.items()}
    score = severity_scores.get(base_severity, 2)

    # Reduce severity if auth or interaction is required
    if requires_auth and requires_interaction:
        score = max(0, score - 2)
    elif requires_auth or requires_interaction:
        score = max(0, score - 1)

    # Complex chains (many steps) are harder to exploit
    if step_count > 5:
        score = max(0, score - 1)

    return score_to_sev.get(score, 'LOW')


def _get_attack_templates() -> Dict[str, Dict]:
    """Return standard attack path templates for common vulnerability types."""
    return {
        'IDOR': {
            'entry_point': '{auth_context.capitalize()} access to {endpoint}',
            'steps': [
                'Create account A and note resource IDs accessible to A',
                'Create account B (different role/user)',
                'As account B, request account A resource via {endpoint}',
                'Verify that account A data is returned in the response',
                'Confirm state is unchanged (read IDOR) or modified (write IDOR)',
            ],
            'expected_impact': 'Unauthorized access to other users\' data via {endpoint}',
            'verification_needed': [
                'Confirm data in response belongs to account A, not B',
                'For write IDOR: verify state change on A\'s resource',
                'Ensure this is not intended behavior (public data)',
            ],
        },
        'XSS': {
            'entry_point': 'User-controlled input at {endpoint}',
            'steps': [
                'Identify injection point (parameter, header, body field)',
                'Craft XSS payload appropriate for context (HTML/JS/attribute)',
                'Inject payload via {endpoint}',
                'Open the page in a separate browser session',
                'Verify JavaScript execution (document.title change, DOM mutation)',
            ],
            'expected_impact': 'Client-side code execution in victim\'s browser via {endpoint}',
            'verification_needed': [
                'Confirm payload executes in a DIFFERENT session (not self-XSS)',
                'Test across browsers if reflected',
                'For stored XSS: confirm persistence across page reloads',
            ],
        },
        'AUTH_BYPASS': {
            'entry_point': 'Access to {endpoint} without valid credentials',
            'steps': [
                'Identify protected endpoint that returns 401/403 normally',
                'Remove or modify authentication header/cookie',
                'Send request to {endpoint}',
                'Compare response to authenticated response',
                'Verify same data/functionality is accessible',
            ],
            'expected_impact': 'Access to protected functionality without authentication at {endpoint}',
            'verification_needed': [
                'Confirm response contains protected data (not a cached/public version)',
                'Confirm the endpoint is actually protected (check docs/scope)',
                'Test with completely different IP/session to rule out session leakage',
            ],
        },
        'SQLI': {
            'entry_point': 'User-controlled input at {endpoint}',
            'steps': [
                'Identify injectable parameter at {endpoint}',
                'Test with basic SQL syntax to trigger error or behavioral change',
                'Craft time-based or boolean-based payload to confirm injection',
                'Extract data or demonstrate impact (version(), database(), etc.)',
                'Document the injected query and its output',
            ],
            'expected_impact': 'SQL injection allowing database access via {endpoint}',
            'verification_needed': [
                'Confirm injection is real (not WAF/input validation error)',
                'Show actual data extraction or time-based confirmation',
                'Test with parameterized payload to rule out false positive',
            ],
        },
        'SSRF': {
            'entry_point': 'URL parameter or redirect at {endpoint}',
            'steps': [
                'Identify URL/host parameter at {endpoint}',
                'Point parameter to an external collaborator/OAST server',
                'Confirm server-side request by checking collaborator logs',
                'Attempt to access internal services (169.254.169.254, localhost)',
                'Verify internal data is returned in the response',
            ],
            'expected_impact': 'Server-side request forgery allowing internal network access via {endpoint}',
            'verification_needed': [
                'Confirm request originates from the target server (not client-side)',
                'Show access to internal resource (cloud metadata, internal API)',
                'Rule out open redirect (SSRF returns data, redirect does not)',
            ],
        },
        'CSRF': {
            'entry_point': 'State-changing action at {endpoint}',
            'steps': [
                'Identify state-changing endpoint that lacks CSRF protection',
                'Craft an HTML page with auto-submitting form targeting {endpoint}',
                'Host the page or use a data: URI',
                'As victim, visit the crafted page while authenticated',
                'Verify the state-changing action was performed',
            ],
            'expected_impact': 'Unauthorized state change via cross-site request forgery at {endpoint}',
            'verification_needed': [
                'Confirm no CSRF token is required',
                'Confirm SameSite cookie attribute does not prevent the attack',
                'Verify actual state change (not just form submission)',
            ],
        },
        'OPEN_REDIRECT': {
            'entry_point': 'Redirect parameter at {endpoint}',
            'steps': [
                'Identify redirect/callback URL parameter at {endpoint}',
                'Set parameter to an external domain (e.g., evil.com)',
                'Follow the redirect chain',
                'Verify browser lands on the attacker-controlled domain',
            ],
            'expected_impact': 'Open redirect allowing phishing/token theft via {endpoint}',
            'verification_needed': [
                'Confirm redirect goes to external domain (not just path-based)',
                'Test with various bypass techniques (//evil.com, \\evil.com)',
                'Demonstrate potential for token theft if OAuth/auth flow is involved',
            ],
        },
        'RCE': {
            'entry_point': 'User-controlled input at {endpoint}',
            'steps': [
                'Identify input that reaches OS command or code execution context',
                'Craft payload to execute a benign command (id, whoami, hostname)',
                'Send payload to {endpoint}',
                'Verify command output in response or via out-of-band channel',
                'Document the execution context (user, OS, permissions)',
            ],
            'expected_impact': 'Remote code execution on the server via {endpoint}',
            'verification_needed': [
                'Confirm command actually executed (not just reflected in error)',
                'Use benign commands only (never destructive)',
                'Verify via out-of-band if blind (DNS/HTTP callback)',
            ],
        },
        'XXE': {
            'entry_point': 'XML input at {endpoint}',
            'steps': [
                'Identify endpoint that accepts XML input at {endpoint}',
                'Craft XML with external entity declaration',
                'Reference a local file (e.g., /etc/hostname) in the entity',
                'Send the crafted XML',
                'Verify file contents appear in response or via OAST callback',
            ],
            'expected_impact': 'XML external entity injection allowing file read via {endpoint}',
            'verification_needed': [
                'Confirm file contents are from the server (not client-side)',
                'For blind XXE: verify via out-of-band callback',
                'Test with /etc/hostname or similar low-risk file',
            ],
        },
        'INFO_DISCLOSURE': {
            'entry_point': 'Accessible resource at {endpoint}',
            'steps': [
                'Access {endpoint} without authentication (or with low-privilege account)',
                'Examine response for sensitive information',
                'Categorize disclosed data (PII, credentials, internal IPs, etc.)',
                'Verify the data is not intentionally public',
            ],
            'expected_impact': 'Information disclosure of sensitive data at {endpoint}',
            'verification_needed': [
                'Confirm data is genuinely sensitive (not public-facing info)',
                'Confirm access should be restricted (check program scope/docs)',
                'Document exactly what is disclosed and the risk',
            ],
        },
    }
