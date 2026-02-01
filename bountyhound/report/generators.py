"""Report generators for BountyHound."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from bountyhound.storage import Database


class ReportGenerator:
    """Generate reports in various formats from database data."""

    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

    def __init__(self, db: Database) -> None:
        """Initialize with database reference."""
        self.db = db

    def generate_markdown(self, domain: str) -> str:
        """Generate a markdown report for a target domain."""
        target = self.db.get_target(domain)
        if target is None:
            return f"# Report: {domain}\n\nNo data found for target."

        subdomains = self.db.get_subdomains(target.id)
        findings = self.db.get_findings(target.id)
        finding_counts = self.db.get_finding_count(target.id)

        lines = []
        lines.append(f"# Security Report: {domain}")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Summary section
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target:** {domain}")
        lines.append(f"- **Subdomains Discovered:** {len(subdomains)}")
        lines.append(f"- **Total Findings:** {len(findings)}")
        lines.append("")

        # Findings by severity
        if finding_counts:
            lines.append("### Findings by Severity")
            lines.append("")
            for severity in self.SEVERITY_ORDER:
                if severity in finding_counts:
                    lines.append(f"- **{severity.capitalize()}:** {finding_counts[severity]}")
            lines.append("")

        # Detailed findings section
        if findings:
            lines.append("## Findings")
            lines.append("")

            # Group findings by severity
            findings_by_severity: dict[str, list] = {}
            for finding in findings:
                sev = finding.severity.lower()
                if sev not in findings_by_severity:
                    findings_by_severity[sev] = []
                findings_by_severity[sev].append(finding)

            for severity in self.SEVERITY_ORDER:
                if severity in findings_by_severity:
                    lines.append(f"### {severity.capitalize()}")
                    lines.append("")
                    for finding in findings_by_severity[severity]:
                        lines.append(f"#### {finding.name}")
                        lines.append("")
                        if finding.url:
                            lines.append(f"- **URL:** {finding.url}")
                        if finding.template:
                            lines.append(f"- **Template:** {finding.template}")
                        if finding.evidence:
                            lines.append(f"- **Evidence:** {finding.evidence}")
                        lines.append(f"- **Found:** {finding.found_at.strftime('%Y-%m-%d %H:%M:%S')}")
                        lines.append("")

        # Subdomain table
        if subdomains:
            lines.append("## Subdomains")
            lines.append("")
            lines.append("| Hostname | IP Address | Status Code | Technologies |")
            lines.append("|----------|------------|-------------|--------------|")
            for sub in subdomains:
                ip = sub.ip_address or "-"
                status = str(sub.status_code) if sub.status_code else "-"
                techs = ", ".join(sub.technologies) if sub.technologies else "-"
                lines.append(f"| {sub.hostname} | {ip} | {status} | {techs} |")
            lines.append("")

        return "\n".join(lines)

    def generate_json(self, domain: str) -> str:
        """Generate a JSON report for a target domain."""
        target = self.db.get_target(domain)
        if target is None:
            return json.dumps({"target": domain, "error": "No data found"}, indent=2)

        subdomains = self.db.get_subdomains(target.id)
        findings = self.db.get_findings(target.id)
        finding_counts = self.db.get_finding_count(target.id)

        report_data = {
            "target": domain,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "subdomains_count": len(subdomains),
                "findings_count": len(findings),
                "findings_by_severity": finding_counts,
            },
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "url": f.url,
                    "evidence": f.evidence,
                    "template": f.template,
                    "found_at": f.found_at.isoformat(),
                }
                for f in findings
            ],
            "subdomains": [
                {
                    "hostname": s.hostname,
                    "ip_address": s.ip_address,
                    "status_code": s.status_code,
                    "technologies": s.technologies,
                    "discovered_at": s.discovered_at.isoformat(),
                }
                for s in subdomains
            ],
        }

        return json.dumps(report_data, indent=2)

    def save_report(
        self,
        domain: str,
        output_dir: Optional[Path] = None,
        format: str = "markdown",
    ) -> Path:
        """Save a report to file, returning the filepath."""
        if output_dir is None:
            output_dir = Path.cwd() / "reports"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "json":
            filename = f"{domain}_{timestamp}.json"
            content = self.generate_json(domain)
        else:
            filename = f"{domain}_{timestamp}.md"
            content = self.generate_markdown(domain)

        filepath = output_dir / filename
        filepath.write_text(content, encoding="utf-8")

        return filepath
