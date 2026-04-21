"""
Reporter Agent - Professional Bug Bounty Report Generation

Generates high-quality vulnerability reports optimized for HackerOne, Bugcrowd,
and Intigriti based on analyst feedback and platform guidelines.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from engine.agents.submission_optimizer import SubmissionOptimizer



class ReporterAgent:
    """Generates professional bug bounty reports from findings."""

    # Severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    # Platforms
    PLATFORM_HACKERONE = "hackerone"
    PLATFORM_BUGCROWD = "bugcrowd"
    PLATFORM_INTIGRITI = "intigriti"

    # CWE mappings for common vulnerability types
    CWE_MAP = {
        "IDOR": "CWE-639",
        "XSS": "CWE-79",
        "SQLi": "CWE-89",
        "CSRF": "CWE-352",
        "SSRF": "CWE-918",
        "XXE": "CWE-611",
        "RCE": "CWE-94",
        "LFI": "CWE-22",
        "Auth Bypass": "CWE-287",
        "Info Disclosure": "CWE-200",
        "S3 Public": "CWE-732",
        "CORS": "CWE-942",
        "Subdomain Takeover": "CWE-350",
        "Rate Limit": "CWE-770",
        "GraphQL Auth": "CWE-862"
    }

    # CVSS base scores by severity
    CVSS_BASE_SCORES = {
        "CRITICAL": 9.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 3.0,
        "INFO": 0.0
    }

    def __init__(self):
        """Initialize reporter agent."""
        self.templates = self._load_templates()
        self.optimizer = SubmissionOptimizer()
        self._report_generator = None

    def get_report_generator(self, target: str):
        """Get the mandatory ReportGenerator for first-try reproduction reports.

        ALWAYS use this for generating submission-ready reports.
        """
        from engine.core.report_generator import ReportGenerator
        if self._report_generator is None or self._report_generator.target != target:
            self._report_generator = ReportGenerator(target)
        return self._report_generator

    def generate_first_try_report(self, finding: Dict[str, Any], target: str,
                                  platform: str = PLATFORM_HACKERONE) -> str:
        """Generate a first-try reproduction report (MANDATORY format).

        This wraps ReportGenerator to produce reports with all required sections:
        prerequisites, fresh auth setup, baseline, exploit, diff table,
        reproduce.py, and impact.

        Args:
            finding: Finding dict with vulnerability details
            target: Target domain
            platform: Target platform

        Returns:
            Complete markdown report with all mandatory sections
        """
        gen = self.get_report_generator(target)
        return gen.generate(finding, platform)

    def save_first_try_report(self, finding: Dict[str, Any], target: str,
                              platform: str = PLATFORM_HACKERONE) -> str:
        """Generate and save a first-try reproduction report + reproduce.py.

        Returns the path to the saved report.
        """
        gen = self.get_report_generator(target)
        report = gen.generate(finding, platform)
        return gen.save(report, finding, platform)

    def _load_templates(self) -> Dict[str, str]:
        """Load report templates for different platforms."""
        return {
            "hackerone": """# {title}

## Summary
{summary}

## Expected vs Actual Behavior

**Expected Behavior:**
{expected_behavior}

**Actual Behavior:**
{actual_behavior}

## Steps to Reproduce

{steps_to_reproduce}

## Impact

{impact}

## Supporting Material

{supporting_material}

## Recommended Fix

{remediation}

## Additional Context

{additional_context}
""",
            "bugcrowd": """# {title}

## Description
{description}

## Proof of Concept

### Expected vs Actual Behavior
{expected_vs_actual}

### Reproduction Steps
{reproduction_steps}

### Evidence
{evidence}

## Severity Justification
{severity_justification}

## Remediation
{remediation}
""",
            "intigriti": """# {title}

## Description
{description}

## Expected vs Actual Behavior
{expected_vs_actual}

## Reproduction Steps
{reproduction_steps}

## Impact
{impact}

## Attachments
{attachments}

## Environment
- Browser: {browser}
- OS: {os}
- Tools: {tools}
"""
        }

    def generate_report(self, finding: Dict[str, Any], target: str,
                       platform: str = PLATFORM_HACKERONE) -> str:
        """
        Generate complete bug bounty report.

        Args:
            finding: Dictionary containing vulnerability details
            target: Target domain/program
            platform: Target platform (hackerone, bugcrowd, intigriti)

        Returns:
            Formatted markdown report
        """
        # Validate finding
        required_fields = ['title', 'severity', 'vuln_type', 'description']
        for field in required_fields:
            if field not in finding:
                raise ValueError(f"Missing required field: {field}")

        # Get template for platform
        if platform not in self.templates:
            platform = self.PLATFORM_HACKERONE

        template = self.templates[platform]

        # Build report sections
        sections = {
            'title': finding['title'],
            'summary': self._generate_summary(finding),
            'expected_behavior': finding.get('expected_behavior',
                                             self._generate_expected_behavior(finding)),
            'actual_behavior': finding.get('actual_behavior',
                                           self._generate_actual_behavior(finding)),
            'steps_to_reproduce': self._generate_steps(finding),
            'impact': self._generate_impact(finding, target),
            'supporting_material': self._generate_supporting_material(finding),
            'remediation': self._generate_remediation(finding),
            'additional_context': self._generate_additional_context(finding),
            'description': finding['description'],
            'expected_vs_actual': self._generate_expected_vs_actual(finding),
            'reproduction_steps': self._generate_steps(finding),
            'evidence': self._generate_evidence(finding),
            'severity_justification': self._generate_severity_justification(finding),
            'attachments': self._generate_attachments(finding),
            'browser': finding.get('browser', 'Chrome 120'),
            'os': finding.get('os', 'Windows 11'),
            'tools': finding.get('tools', 'Burp Suite, curl')
        }

        # Fill template
        report = template.format(**sections)

        return report

    def format_finding(self, finding: Dict[str, Any]) -> str:
        """
        Format single finding with appropriate template.

        Args:
            finding: Finding dictionary

        Returns:
            Formatted finding section
        """
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵"
        }

        emoji = severity_emoji.get(finding['severity'], "⚪")

        return f"""
### {emoji} {finding['title']}

**Severity:** {finding['severity']}
**Type:** {finding['vuln_type']}
**CWE:** {self.CWE_MAP.get(finding['vuln_type'], 'N/A')}

{finding['description']}
"""

    def calculate_severity(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate CVSS score and severity.

        Args:
            finding: Finding with impact/exploitability details

        Returns:
            Dictionary with severity, cvss_score, cvss_vector
        """
        # Use provided severity or calculate
        severity = finding.get('severity', self.SEVERITY_MEDIUM)

        # Get base CVSS score
        base_score = self.CVSS_BASE_SCORES.get(severity, 5.0)

        # Adjust based on factors
        score = base_score

        # Impact factors
        if finding.get('data_exposure'):
            score += 0.5
        if finding.get('auth_bypass'):
            score += 1.0
        if finding.get('financial_loss'):
            score += 1.5

        # Exploitability factors
        if finding.get('authenticated'):
            score -= 0.5
        if finding.get('requires_user_interaction'):
            score -= 0.3
        if finding.get('network_accessible'):
            score += 0.5

        # Cap at 10.0
        score = min(score, 10.0)

        # Determine severity from score
        if score >= 9.0:
            severity = self.SEVERITY_CRITICAL
        elif score >= 7.0:
            severity = self.SEVERITY_HIGH
        elif score >= 4.0:
            severity = self.SEVERITY_MEDIUM
        elif score >= 0.1:
            severity = self.SEVERITY_LOW
        else:
            severity = self.SEVERITY_INFO

        return {
            'severity': severity,
            'cvss_score': round(score, 1),
            'cvss_vector': self._generate_cvss_vector(finding)
        }

    def generate_poc(self, finding: Dict[str, Any]) -> str:
        """
        Generate proof-of-concept section.

        Args:
            finding: Finding with PoC details

        Returns:
            Formatted PoC markdown
        """
        poc_parts = []

        # HTTP request if available
        if 'http_request' in finding:
            poc_parts.append("### HTTP Request Example:\n")
            poc_parts.append("```http")
            poc_parts.append(finding['http_request'])
            poc_parts.append("```\n")

        # Response if available
        if 'http_response' in finding:
            poc_parts.append("### Response:\n")
            poc_parts.append("```json")
            if isinstance(finding['http_response'], dict):
                poc_parts.append(json.dumps(finding['http_response'], indent=2))
            else:
                poc_parts.append(finding['http_response'])
            poc_parts.append("```\n")

        # Code example if available
        if 'code_example' in finding:
            poc_parts.append("### Code Example:\n")
            poc_parts.append(f"```{finding.get('code_language', 'python')}")
            poc_parts.append(finding['code_example'])
            poc_parts.append("```\n")

        # Command line if available
        if 'command' in finding:
            poc_parts.append("### Command:\n")
            poc_parts.append("```bash")
            poc_parts.append(finding['command'])
            poc_parts.append("```\n")

        return "\n".join(poc_parts) if poc_parts else "*(No PoC available)*"

    def generate_impact(self, finding: Dict[str, Any], target: str = "") -> str:
        """
        Generate impact analysis.

        Args:
            finding: Finding with impact details
            target: Target name for context

        Returns:
            Formatted impact section
        """
        return self._generate_impact(finding, target)

    def generate_remediation(self, finding: Dict[str, Any]) -> str:
        """
        Generate remediation advice.

        Args:
            finding: Finding with vulnerability details

        Returns:
            Formatted remediation section
        """
        return self._generate_remediation(finding)

    def _generate_summary(self, finding: Dict[str, Any]) -> str:
        """Generate 2-3 sentence summary."""
        vuln_type = finding['vuln_type']
        severity = finding['severity']

        summary_parts = []

        # First sentence: What's the bug?
        summary_parts.append(finding.get('summary', finding['description'].split('.')[0] + '.'))

        # Second sentence: Impact
        if finding.get('impact_summary'):
            summary_parts.append(finding['impact_summary'])
        else:
            summary_parts.append(f"This {severity.lower()} severity {vuln_type} vulnerability "
                               f"allows unauthorized access to sensitive data.")

        return " ".join(summary_parts)

    def _generate_expected_behavior(self, finding: Dict[str, Any]) -> str:
        """Generate expected behavior description."""
        vuln_type = finding['vuln_type']

        templates = {
            "IDOR": "The server should validate that the requesting user owns the requested resource and return 403 Forbidden if not.",
            "XSS": "The application should sanitize user input and encode output to prevent script execution.",
            "GraphQL Auth": "The GraphQL gateway should enforce authentication before forwarding mutations to backend services.",
            "CORS": "The server should only return Access-Control-Allow-Origin for trusted domains.",
            "S3 Public": "S3 buckets should be claimed and configured with proper access controls.",
            "Rate Limit": "The endpoint should implement rate limiting to prevent brute force attacks."
        }

        return finding.get('expected_behavior',
                          templates.get(vuln_type,
                                       "The application should properly validate and authorize this action."))

    def _generate_actual_behavior(self, finding: Dict[str, Any]) -> str:
        """Generate actual behavior description."""
        return finding.get('actual_behavior',
                          finding['description'])

    def _generate_steps(self, finding: Dict[str, Any]) -> str:
        """Generate reproduction steps."""
        if 'steps' in finding:
            steps = finding['steps']
            if isinstance(steps, list):
                return "\n".join(f"{i+1}. {step}" for i, step in enumerate(steps))
            return steps

        # Generate basic steps
        steps = []
        steps.append("1. Navigate to the vulnerable endpoint")
        steps.append("2. Execute the proof-of-concept")
        steps.append("3. Observe the security issue")

        # Add PoC if available
        poc = self.generate_poc(finding)
        if poc and poc != "*(No PoC available)*":
            steps.append("\n" + poc)

        return "\n".join(steps)

    def _generate_impact(self, finding: Dict[str, Any], target: str) -> str:
        """Generate business-focused impact analysis."""
        if 'impact' in finding:
            return finding['impact']

        impact_parts = []

        # Lead with what attacker can achieve
        vuln_type = finding['vuln_type']
        impact_templates = {
            "IDOR": "An attacker can access any user's sensitive data including personal information, order history, and delivery addresses.",
            "XSS": "An attacker can execute arbitrary JavaScript in victim's browser, potentially stealing credentials or performing actions as the victim.",
            "GraphQL Auth": "An attacker can call privileged mutations without authentication, potentially modifying or deleting data.",
            "S3 Public": "An attacker can host malicious content on the organization's domain, bypassing security controls.",
            "CORS": "An attacker can make cross-origin requests from a malicious site, potentially accessing sensitive data."
        }

        impact_parts.append(impact_templates.get(vuln_type,
                                                 "This vulnerability allows unauthorized access to sensitive functionality."))

        # Add business risk if available
        if finding.get('business_risk'):
            impact_parts.append(f"\n**Business Risk:**\n{finding['business_risk']}")

        # Add affected users count
        if finding.get('affected_users'):
            impact_parts.append(f"\n**Affected Users:** {finding['affected_users']}")

        # Add attack scenario
        if finding.get('attack_scenario'):
            impact_parts.append(f"\n**Attack Scenario:**\n{finding['attack_scenario']}")

        return "\n".join(impact_parts)

    def _generate_supporting_material(self, finding: Dict[str, Any]) -> str:
        """Generate supporting material/attachments section."""
        if 'attachments' in finding:
            attachments = finding['attachments']
            if isinstance(attachments, list):
                return "\n".join(f"- `{att['name']}` - {att['description']}"
                               for att in attachments)
            return attachments

        return "*(Attachments to be included)*"

    def _generate_remediation(self, finding: Dict[str, Any]) -> str:
        """Generate specific, actionable remediation advice."""
        if 'remediation' in finding:
            return finding['remediation']

        vuln_type = finding['vuln_type']

        remediation_templates = {
            "IDOR": """Implement authorization checks on all endpoints:

```python
def get_order(order_id, user_id):
    order = Order.query.get(order_id)
    if order.user_id != user_id:
        raise ForbiddenError("Not authorized")
    return order
```""",
            "XSS": """1. Sanitize user input on the server side
2. Use Content-Security-Policy headers
3. Encode output using context-appropriate encoding
4. Use frameworks' built-in XSS protection""",
            "GraphQL Auth": """Add authentication middleware to GraphQL gateway:

```javascript
const authDirective = (next) => (root, args, context) => {
  if (!context.user) {
    throw new AuthenticationError('Not authenticated');
  }
  return next(root, args, context);
};
```""",
            "CORS": """Configure CORS to only allow trusted origins:

```
Access-Control-Allow-Origin: https://trusted-domain.com
```

Do not use wildcard (*) with credentials.""",
            "S3 Public": """1. Claim all S3 buckets referenced in production
2. Configure bucket policies to deny public access
3. Use AWS Organizations SCPs to prevent public buckets"""
        }

        return remediation_templates.get(vuln_type,
                                        "Implement proper security controls for this functionality.")

    def _generate_additional_context(self, finding: Dict[str, Any]) -> str:
        """Generate additional technical context."""
        context_parts = []

        # CWE reference
        cwe = self.CWE_MAP.get(finding['vuln_type'])
        if cwe:
            context_parts.append(f"**CWE Reference:** {cwe}")

        # Architecture info
        if finding.get('architecture'):
            context_parts.append(f"\n**Architecture:** {finding['architecture']}")

        # Discovery method
        if finding.get('discovery_method'):
            context_parts.append(f"\n**Discovery Method:** {finding['discovery_method']}")

        # Related findings
        if finding.get('related_findings'):
            context_parts.append(f"\n**Related Findings:** {finding['related_findings']}")

        return "\n".join(context_parts) if context_parts else "*(No additional context)*"

    def _generate_expected_vs_actual(self, finding: Dict[str, Any]) -> str:
        """Generate expected vs actual comparison."""
        expected = self._generate_expected_behavior(finding)
        actual = self._generate_actual_behavior(finding)

        return f"""**Expected Behavior:**
{expected}

**Actual Behavior:**
{actual}"""

    def _generate_evidence(self, finding: Dict[str, Any]) -> str:
        """Generate evidence section."""
        return self.generate_poc(finding)

    def _generate_severity_justification(self, finding: Dict[str, Any]) -> str:
        """Generate severity justification for Bugcrowd."""
        severity_info = self.calculate_severity(finding)

        justification = f"""**Severity:** {severity_info['severity']}
**CVSS Score:** {severity_info['cvss_score']}
**CVSS Vector:** {severity_info['cvss_vector']}

This vulnerability is rated {severity_info['severity']} based on:
- Impact to confidentiality, integrity, and availability
- Ease of exploitation
- Number of affected users
- Business risk
"""

        return justification

    def _generate_attachments(self, finding: Dict[str, Any]) -> str:
        """Generate attachments list."""
        return self._generate_supporting_material(finding)

    def _generate_cvss_vector(self, finding: Dict[str, Any]) -> str:
        """Generate CVSS v3.1 vector string."""
        # Simplified CVSS vector generation
        av = "N" if finding.get('network_accessible', True) else "L"
        ac = "L" if finding.get('easy_exploit', True) else "H"
        pr = "N" if not finding.get('authenticated', False) else "L"
        ui = "N" if not finding.get('requires_user_interaction', False) else "R"

        c = "H" if finding.get('data_exposure') else "L"
        i = "H" if finding.get('data_modification') else "L"
        a = "L"  # Availability typically low for web vulns

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}"

    def save_report(self, report: str, output_path: Path) -> Path:
        """
        Save report to file.

        Args:
            report: Report markdown content
            output_path: Path to save report

        Returns:
            Path to saved report
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding='utf-8')
        return output_path

    def generate_batch_report(self, findings: List[Dict[str, Any]],
                             target: str,
                             platform: str = PLATFORM_HACKERONE) -> str:
        """
        Generate report for multiple findings.

        Args:
            findings: List of finding dictionaries
            target: Target domain/program
            platform: Target platform

        Returns:
            Combined report markdown
        """
        if not findings:
            return "No findings to report."

        report_parts = [f"# Vulnerability Report - {target}\n"]
        report_parts.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n")
        report_parts.append(f"**Findings:** {len(findings)}\n")

        # Summary table
        report_parts.append("## Summary\n")
        report_parts.append("| # | Title | Severity | Type |")
        report_parts.append("|---|-------|----------|------|")

        for i, finding in enumerate(findings, 1):
            report_parts.append(
                f"| {i} | {finding['title']} | {finding['severity']} | {finding['vuln_type']} |"
            )

        report_parts.append("\n---\n")

        # Individual findings
        for i, finding in enumerate(findings, 1):
            report_parts.append(f"\n## Finding #{i}\n")
            report_parts.append(self.generate_report(finding, target, platform))
            report_parts.append("\n---\n")

        return "\n".join(report_parts)

    def generate_submission_plan(self, findings: List[Dict]) -> List[Dict]:
        """
        Generate optimized submission plan for findings.

        Uses SubmissionOptimizer to:
        - Recommend best programs for each vulnerability type
        - Optimize submission timing
        - Suggest severity ratings based on historical data
        - Prioritize by expected payout

        Args:
            findings: List of finding dictionaries

        Returns:
            List of submission plan items with program, timing, severity, confidence, expected_payout
        """
        return self.optimizer.generate_submission_plan(findings)
