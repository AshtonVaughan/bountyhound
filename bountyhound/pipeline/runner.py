"""Pipeline runner for orchestrating recon and scanning stages."""

from rich.console import Console

from bountyhound.config import load_config
from bountyhound.recon import SubdomainScanner, HttpProber, PortScanner
from bountyhound.scan import NucleiScanner
from bountyhound.storage import Database
from bountyhound.utils import ToolNotFoundError


class PipelineRunner:
    """Orchestrates the full recon and scanning pipeline."""

    def __init__(self, db: Database, batch_mode: bool = False):
        """Initialize pipeline runner.

        Args:
            db: Database instance for storing results
            batch_mode: If True, suppress output for scripting
        """
        self.db = db
        self.batch_mode = batch_mode
        self.console = Console()
        self.config = load_config()

        # Initialize all scanners with tool paths from config
        tool_paths = self.config.get("tools", {})
        self.subdomain_scanner = SubdomainScanner(config_path=tool_paths.get("subfinder"))
        self.http_prober = HttpProber(config_path=tool_paths.get("httpx"))
        self.port_scanner = PortScanner(config_path=tool_paths.get("nmap"))
        self.nuclei_scanner = NucleiScanner(config_path=tool_paths.get("nuclei"))

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

    def run_recon(self, domain: str) -> dict:
        """Run the reconnaissance pipeline.

        Runs subfinder -> httpx -> nmap in sequence, storing results.

        Args:
            domain: Target domain to scan

        Returns:
            Dict with counts: subdomains, live_hosts, ports
        """
        self.log(f"[*] Starting recon for {domain}", "bold blue")

        # Ensure target exists in database
        target_id = self.db.add_target(domain)

        counts = {
            "subdomains": 0,
            "live_hosts": 0,
            "ports": 0,
        }

        # Step 1: Subdomain enumeration
        self.log("[*] Running subdomain enumeration...", "blue")
        subdomains = []
        try:
            subdomains = self.subdomain_scanner.run(domain)
            counts["subdomains"] = len(subdomains)
            self.log(f"    Found {len(subdomains)} subdomains", "green")
        except ToolNotFoundError as e:
            self.log(f"    Skipping: {e}", "yellow")

        # Store all discovered subdomains
        for hostname in subdomains:
            self.db.add_subdomain(target_id, hostname)

        # Step 2: HTTP probing
        self.log("[*] Running HTTP probing...", "blue")
        live_hosts = []
        try:
            if subdomains:
                live_hosts = self.http_prober.run(subdomains)
                counts["live_hosts"] = len(live_hosts)
                self.log(f"    Found {len(live_hosts)} live hosts", "green")
            else:
                self.log("    No subdomains to probe", "yellow")
        except ToolNotFoundError as e:
            self.log(f"    Skipping: {e}", "yellow")

        # Update subdomains with HTTP info
        for host_info in live_hosts:
            hostname = host_info.get("host", "")
            if hostname:
                self.db.add_subdomain(
                    target_id,
                    hostname,
                    ip_address=host_info.get("ip"),
                    status_code=host_info.get("status_code"),
                    technologies=host_info.get("tech", []),
                )

        # Step 3: Port scanning
        self.log("[*] Running port scanning...", "blue")
        try:
            # Get unique IPs from live hosts
            ips = list(set(
                h.get("ip") for h in live_hosts
                if h.get("ip")
            ))
            if ips:
                scan_config = self.config.get("scan", {})
                ports_spec = scan_config.get("nmap_ports", "top-1000")
                if ports_spec == "top-1000":
                    ports_spec = "--top-ports 1000"

                port_results = self.port_scanner.run(ips, ports=ports_spec)

                # Count total open ports
                for host_ports in port_results.values():
                    counts["ports"] += len(host_ports)

                self.log(f"    Found {counts['ports']} open ports", "green")
            else:
                self.log("    No IPs to scan", "yellow")
        except ToolNotFoundError as e:
            self.log(f"    Skipping: {e}", "yellow")

        # Update target recon timestamp
        self.db.update_target_recon_time(target_id)

        self.log(f"[+] Recon complete for {domain}", "bold green")
        return counts

    def run_scan(self, domain: str) -> dict:
        """Run vulnerability scanning on discovered hosts.

        Gets subdomains from database and runs nuclei.

        Args:
            domain: Target domain

        Returns:
            Dict with severity counts
        """
        self.log(f"[*] Starting scan for {domain}", "bold blue")

        target = self.db.get_target(domain)
        if not target:
            self.log(f"    Target {domain} not found in database", "red")
            return {}

        # Get subdomains with URLs
        subdomains = self.db.get_subdomains(target.id)
        urls = []
        for sub in subdomains:
            if sub.status_code:
                # Prefer HTTPS
                urls.append(f"https://{sub.hostname}")
            else:
                urls.append(f"http://{sub.hostname}")

        if not urls:
            self.log("    No URLs to scan", "yellow")
            return {}

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # Run nuclei
        self.log(f"[*] Running nuclei on {len(urls)} URLs...", "blue")
        try:
            scan_config = self.config.get("scan", {})
            findings = self.nuclei_scanner.run(
                urls,
                templates=scan_config.get("nuclei_templates"),
                severity=scan_config.get("nuclei_severity", "low,medium,high,critical"),
            )

            self.log(f"    Found {len(findings)} findings", "green")

            # Store findings and count by severity
            for finding in findings:
                # Find the subdomain for this finding
                finding_url = finding.get("url", "")
                subdomain_id = None

                for sub in subdomains:
                    if sub.hostname in finding_url:
                        subdomain_id = sub.id
                        break

                if subdomain_id:
                    self.db.add_finding(
                        subdomain_id,
                        name=finding.get("name", "Unknown"),
                        severity=finding.get("severity", "unknown"),
                        url=finding_url,
                        evidence=str(finding.get("evidence", "")),
                        template=finding.get("template", ""),
                    )

                    severity = finding.get("severity", "info").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        except ToolNotFoundError as e:
            self.log(f"    Skipping: {e}", "yellow")

        # Update target scan timestamp
        self.db.update_target_scan_time(target.id)

        self.log(f"[+] Scan complete for {domain}", "bold green")
        return severity_counts

    def run_pipeline(self, domain: str) -> dict:
        """Run the complete pipeline: recon then scan.

        Args:
            domain: Target domain

        Returns:
            Dict with combined recon and scan results
        """
        self.log(f"[*] Starting full pipeline for {domain}", "bold cyan")

        recon_results = self.run_recon(domain)
        scan_results = self.run_scan(domain)

        self.log(f"[+] Pipeline complete for {domain}", "bold cyan")

        return {
            "recon": recon_results,
            "scan": scan_results,
        }
