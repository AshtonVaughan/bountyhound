"""Campaign runner for autonomous bug bounty scanning."""

from typing import Optional

from rich.console import Console

from bountyhound.ai import AIAnalyzer
from bountyhound.browser.session import BrowserSession
from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser
from bountyhound.campaign.intigriti import IntigritiParser
from bountyhound.campaign.yeswehack import YesWeHackParser
from bountyhound.pipeline.runner import PipelineRunner
from bountyhound.storage import Database


class CampaignRunner:
    """Orchestrates autonomous bug bounty campaign scanning.

    This runner handles the full workflow:
    1. Detect platform from URL
    2. Fetch campaign page with browser session
    3. Parse scope with appropriate parser
    4. Extract domains from scope
    5. Run subdomain enumeration (recon)
    6. AI select high-value targets
    7. Run vulnerability scans on selected targets
    8. AI prioritize findings
    9. Generate report summary
    """

    def __init__(
        self,
        browser_type: str = "chrome",
        max_targets: int = 100,
        batch_mode: bool = False,
    ) -> None:
        """Initialize CampaignRunner.

        Args:
            browser_type: Browser to extract cookies from (chrome, firefox, edge)
            max_targets: Maximum number of targets to scan after AI selection
            batch_mode: If True, suppress output for scripting
        """
        self.browser_type = browser_type
        self.max_targets = max_targets
        self.batch_mode = batch_mode
        self.console = Console()

    def log(self, message: str, style: str = "") -> None:
        """Print a message if not in batch mode.

        Args:
            message: Message to print
            style: Rich style string (e.g., "bold green")
        """
        if not self.batch_mode:
            if style:
                self.console.print(message, style=style)
            else:
                self.console.print(message)

    def _get_parser(self, platform: str) -> CampaignParser:
        """Get the appropriate parser for a platform.

        Args:
            platform: Platform name (hackerone, bugcrowd, intigriti, yeswehack)

        Returns:
            CampaignParser instance for the platform

        Raises:
            ValueError: If platform is not supported
        """
        parsers = {
            "hackerone": HackerOneParser,
            "bugcrowd": BugcrowdParser,
            "intigriti": IntigritiParser,
            "yeswehack": YesWeHackParser,
        }

        if platform not in parsers:
            raise ValueError(f"Unsupported platform: {platform}")

        return parsers[platform]()

    def _run_pipeline_on_targets(
        self,
        targets: list[str],
        pipeline: PipelineRunner,
    ) -> dict:
        """Run recon and scan pipeline on selected targets.

        Args:
            targets: List of target domains to scan
            pipeline: PipelineRunner instance

        Returns:
            Dict with combined recon and scan results for all targets
        """
        combined_recon = {
            "subdomains": 0,
            "live_hosts": 0,
            "ports": 0,
        }
        combined_scan = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for target in targets:
            self.log(f"[*] Processing target: {target}", "cyan")

            # Run recon
            recon_results = pipeline.run_recon(target)
            for key in combined_recon:
                combined_recon[key] += recon_results.get(key, 0)

            # Run scan
            scan_results = pipeline.run_scan(target)
            for key in combined_scan:
                combined_scan[key] += scan_results.get(key, 0)

        return {
            "recon": combined_recon,
            "scan": combined_scan,
        }

    def run(self, campaign_url: str) -> dict:
        """Run the full autonomous campaign scan.

        Args:
            campaign_url: URL of the bug bounty campaign page

        Returns:
            Dict with structured results including:
            - program_name: Name of the program
            - platform: Detected platform
            - scope: Parsed scope dict
            - domains: List of in-scope domains
            - recon: Reconnaissance results
            - selected_targets: AI-selected high-value targets
            - scan: Vulnerability scan results
            - findings: Prioritized findings
            - summary: AI-generated report summary

        Raises:
            ValueError: If platform cannot be detected from URL
        """
        self.log(f"[*] Starting campaign scan for: {campaign_url}", "bold cyan")

        # Step 1: Detect platform
        platform = detect_platform(campaign_url)
        if not platform:
            raise ValueError(f"Could not detect platform from URL: {campaign_url}")

        self.log(f"[+] Detected platform: {platform}", "green")

        # Step 2: Initialize components
        browser = BrowserSession(browser_type=self.browser_type)
        ai = AIAnalyzer()
        db = Database()
        db.initialize()

        try:
            # Step 3: Fetch campaign page
            self.log("[*] Fetching campaign page...", "blue")
            html_content = browser.fetch_page(campaign_url)
            self.log("[+] Campaign page fetched", "green")

            # Step 4: Parse scope with appropriate parser
            self.log("[*] Parsing campaign scope...", "blue")
            parser = self._get_parser(platform)
            scope = parser.parse(html_content, campaign_url)
            program_name = scope.get("program_name", "unknown")
            self.log(f"[+] Program: {program_name}", "green")

            # Step 5: Extract domains from scope
            domains = parser.scope_to_domains(scope)
            self.log(f"[+] Found {len(domains)} in-scope domains", "green")

            if not domains:
                self.log("[!] No domains found in scope", "yellow")
                return {
                    "program_name": program_name,
                    "platform": platform,
                    "scope": scope,
                    "domains": [],
                    "recon": {},
                    "selected_targets": [],
                    "scan": {},
                    "findings": [],
                    "summary": "No domains found in scope to scan.",
                }

            # Step 6: Initialize pipeline and run recon on all domains
            pipeline = PipelineRunner(db, batch_mode=self.batch_mode)

            self.log("[*] Running reconnaissance...", "blue")
            recon_results = {"subdomains": 0, "live_hosts": 0, "ports": 0}
            all_recon_data = {"subdomains": [], "live_hosts": []}

            for domain in domains:
                result = pipeline.run_recon(domain)
                for key in recon_results:
                    recon_results[key] += result.get(key, 0)

                # Collect recon data for AI selection
                target = db.get_target(domain)
                if target is None:
                    continue
                subdomains = db.get_subdomains(target.id)
                if subdomains is None:
                    continue
                for sub in subdomains:
                    all_recon_data["subdomains"].append(sub.hostname)
                    if sub.status_code:
                        all_recon_data["live_hosts"].append({
                            "host": sub.hostname,
                            "status_code": sub.status_code,
                            "technologies": sub.technologies or [],
                            "ip": sub.ip_address,
                        })

            self.log(
                f"[+] Recon complete: {recon_results['subdomains']} subdomains, "
                f"{recon_results['live_hosts']} live hosts",
                "green",
            )

            # Step 7: AI select high-value targets
            self.log("[*] AI selecting high-value targets...", "blue")
            target_selection = ai.select_targets(all_recon_data, max_targets=self.max_targets)
            selected_targets = target_selection.get("selected", [])
            self.log(
                f"[+] AI selected {len(selected_targets)} high-value targets",
                "green",
            )

            # Step 8: Run vulnerability scans on selected targets only
            self.log("[*] Running vulnerability scans...", "blue")
            scan_results = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            # Extract target hostnames from AI selection
            selected_hostnames = {t.get("target") for t in selected_targets if t.get("target")}

            # Run scans only on selected targets
            for domain in domains:
                target = db.get_target(domain)
                if target is None:
                    continue
                subdomains = db.get_subdomains(target.id)
                if subdomains is None:
                    continue
                for sub in subdomains:
                    if sub.hostname in selected_hostnames:
                        result = pipeline.run_scan(sub.hostname)
                        for key in scan_results:
                            scan_results[key] += result.get(key, 0)

            self.log(
                f"[+] Scan complete: {scan_results.get('critical', 0)} critical, "
                f"{scan_results.get('high', 0)} high, "
                f"{scan_results.get('medium', 0)} medium findings",
                "green",
            )

            # Step 9: Collect and prioritize findings
            self.log("[*] Prioritizing findings with AI...", "blue")
            all_findings = []
            for domain in domains:
                target = db.get_target(domain)
                if target is None:
                    continue
                findings = db.get_findings(target.id)
                if findings is None:
                    continue
                for f in findings:
                    all_findings.append({
                        "name": f.name,
                        "severity": f.severity,
                        "url": f.url,
                        "evidence": f.evidence,
                        "template": f.template,
                    })

            prioritized_findings = ai.prioritize_findings(all_findings)
            self.log(f"[+] Prioritized {len(prioritized_findings)} findings", "green")

            # Step 10: Generate report summary
            self.log("[*] Generating report summary...", "blue")
            report_data = {
                "program": program_name,
                "platform": platform,
                "domains": domains,
                "recon": recon_results,
                "scan": scan_results,
                "findings": prioritized_findings,
            }
            summary = ai.generate_report_summary(report_data)
            self.log("[+] Report summary generated", "green")

            self.log(f"[+] Campaign scan complete for {program_name}", "bold green")

            return {
                "program_name": program_name,
                "platform": platform,
                "scope": scope,
                "domains": domains,
                "recon": recon_results,
                "selected_targets": selected_targets,
                "scan": scan_results,
                "findings": prioritized_findings,
                "summary": summary,
            }

        finally:
            browser.close()
            db.close()
