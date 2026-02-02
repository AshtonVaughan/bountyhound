"""CLI commands for BountyHound."""

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from bountyhound import __version__
from bountyhound.config import load_config
from bountyhound.storage import Database
from bountyhound.utils import find_tool

REQUIRED_TOOLS = ["subfinder", "httpx", "nmap", "nuclei"]
OPTIONAL_TOOLS = ["ffuf"]

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="bountyhound")
def main() -> None:
    """Bug bounty automation CLI."""
    pass


@main.command()
def doctor() -> None:
    """Check tool dependencies and system configuration."""
    console.print("\n[bold]Checking tool dependencies...[/bold]\n")

    config = load_config()
    tools_config = config.get("tools", {})

    # Check required tools
    console.print("[bold]Required tools:[/bold]")
    all_required_found = True
    for tool in REQUIRED_TOOLS:
        config_path = tools_config.get(tool)
        path = find_tool(tool, config_path)
        if path:
            console.print(f"  [green][+][/green] {tool}: {path}")
        else:
            console.print(f"  [red][x][/red] {tool}: not found")
            all_required_found = False

    # Check optional tools
    console.print("\n[bold]Optional tools:[/bold]")
    for tool in OPTIONAL_TOOLS:
        config_path = tools_config.get(tool)
        path = find_tool(tool, config_path)
        if path:
            console.print(f"  [green][+][/green] {tool}: {path}")
        else:
            console.print(f"  [yellow][-][/yellow] {tool}: not found (optional)")

    console.print()
    if all_required_found:
        console.print("[green]All required tools are installed![/green]")
    else:
        console.print(
            "[red]Some required tools are missing. "
            "Install them or configure paths in ~/.bountyhound/config.yaml[/red]"
        )


@main.group()
def target() -> None:
    """Manage bug bounty targets."""
    pass


@target.command("add")
@click.argument("domain")
def target_add(domain: str) -> None:
    """Add a target domain."""
    db_path = Path.cwd() / "bountyhound.db"
    db = Database(db_path)
    db.initialize()

    target_id = db.add_target(domain)
    db.close()

    console.print(f"[green]Added target:[/green] {domain} (id: {target_id})")


@target.command("list")
def target_list() -> None:
    """List all target domains."""
    db_path = Path.cwd() / "bountyhound.db"
    db = Database(db_path)
    db.initialize()

    targets = db.get_all_targets()
    db.close()

    if not targets:
        console.print("[yellow]No targets found. Use 'bountyhound target add <domain>' to add one.[/yellow]")
        return

    table = Table(title="Targets")
    table.add_column("ID", style="cyan")
    table.add_column("Domain", style="green")
    table.add_column("Added", style="white")
    table.add_column("Last Recon", style="white")
    table.add_column("Last Scan", style="white")

    for t in targets:
        table.add_row(
            str(t.id),
            t.domain,
            t.added_at.strftime("%Y-%m-%d %H:%M"),
            t.last_recon.strftime("%Y-%m-%d %H:%M") if t.last_recon else "-",
            t.last_scan.strftime("%Y-%m-%d %H:%M") if t.last_scan else "-",
        )

    console.print(table)


@target.command("remove")
@click.argument("domain")
def target_remove(domain: str) -> None:
    """Remove a target domain."""
    db_path = Path.cwd() / "bountyhound.db"
    db = Database(db_path)
    db.initialize()

    existing = db.get_target(domain)
    if existing is None:
        console.print(f"[red]Target not found:[/red] {domain}")
        db.close()
        return

    # Delete the target and associated data
    conn = db.connect()
    conn.execute("DELETE FROM findings WHERE subdomain_id IN (SELECT id FROM subdomains WHERE target_id = ?)", (existing.id,))
    conn.execute("DELETE FROM ports WHERE subdomain_id IN (SELECT id FROM subdomains WHERE target_id = ?)", (existing.id,))
    conn.execute("DELETE FROM subdomains WHERE target_id = ?", (existing.id,))
    conn.execute("DELETE FROM runs WHERE target_id = ?", (existing.id,))
    conn.execute("DELETE FROM targets WHERE id = ?", (existing.id,))
    conn.commit()
    db.close()

    console.print(f"[green]Removed target:[/green] {domain}")


@main.command()
def status() -> None:
    """Show status of all targets with subdomain and finding counts."""
    db_path = Path.cwd() / "bountyhound.db"
    db = Database(db_path)
    db.initialize()

    targets = db.get_all_targets()

    if not targets:
        console.print("[yellow]No targets found. Use 'bountyhound target add <domain>' to add one.[/yellow]")
        db.close()
        return

    table = Table(title="Target Status")
    table.add_column("Domain", style="cyan")
    table.add_column("Subdomains", style="green", justify="right")
    table.add_column("Critical", style="red", justify="right")
    table.add_column("High", style="yellow", justify="right")
    table.add_column("Medium", style="blue", justify="right")
    table.add_column("Low", style="white", justify="right")

    for t in targets:
        subdomain_count = db.get_subdomain_count(t.id)
        finding_counts = db.get_finding_count(t.id)

        table.add_row(
            t.domain,
            str(subdomain_count),
            str(finding_counts.get("critical", 0)),
            str(finding_counts.get("high", 0)),
            str(finding_counts.get("medium", 0)),
            str(finding_counts.get("low", 0)),
        )

    db.close()
    console.print(table)


@main.command()
@click.argument("domain")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def recon(domain: str, batch: bool):
    """Run reconnaissance on a target domain."""
    db = Database()
    db.initialize()

    # Ensure target exists
    if not db.get_target(domain):
        db.add_target(domain)
        if not batch:
            console.print(f"[green][+][/green] Added new target: {domain}")

    from bountyhound.pipeline import PipelineRunner

    runner = PipelineRunner(db, batch_mode=batch)
    results = runner.run_recon(domain)
    db.close()

    if not batch:
        console.print(f"\n[bold]Recon Summary:[/bold]")
        console.print(f"  Subdomains: {results['subdomains']}")
        console.print(f"  Live hosts: {results['live_hosts']}")
        console.print(f"  Open ports: {results['ports']}")


@main.command()
@click.argument("domain")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def scan(domain: str, batch: bool):
    """Run vulnerability scan on a target domain."""
    db = Database()
    db.initialize()

    target = db.get_target(domain)
    if not target:
        console.print(f"[red]Target {domain} not found. Add it first with 'target add'.[/red]")
        db.close()
        return

    from bountyhound.pipeline import PipelineRunner

    runner = PipelineRunner(db, batch_mode=batch)
    results = runner.run_scan(domain)
    db.close()

    if not batch:
        console.print(f"\n[bold]Scan Summary:[/bold]")
        console.print(f"  Critical: {results.get('critical', 0)}")
        console.print(f"  High: {results.get('high', 0)}")
        console.print(f"  Medium: {results.get('medium', 0)}")
        console.print(f"  Low: {results.get('low', 0)}")


@main.command()
@click.argument("domain")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def pipeline(domain: str, batch: bool):
    """Run full pipeline (recon + scan) on a target domain."""
    db = Database()
    db.initialize()

    # Ensure target exists
    if not db.get_target(domain):
        db.add_target(domain)
        if not batch:
            console.print(f"[green][+][/green] Added new target: {domain}")

    from bountyhound.pipeline import PipelineRunner

    runner = PipelineRunner(db, batch_mode=batch)
    results = runner.run_pipeline(domain)
    db.close()

    if not batch:
        console.print(f"\n[bold]Pipeline Summary for {domain}:[/bold]")
        console.print(f"  Subdomains: {results.get('subdomains', 0)}")
        console.print(f"  Live hosts: {results.get('live_hosts', 0)}")
        console.print(f"  Findings: critical={results.get('critical', 0)}, high={results.get('high', 0)}, medium={results.get('medium', 0)}")


@main.command()
@click.argument("url")
@click.option("--browser", "-b", type=click.Choice(["chrome", "firefox", "edge"]), default=None, help="Browser to extract cookies from (default: from config or chrome)")
@click.option("--max-targets", "-m", type=int, default=None, help="Maximum targets to scan after AI selection (default: from config or 100)")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def campaign(url: str, browser: str | None, max_targets: int | None, batch: bool):
    """Run autonomous campaign scan from a bug bounty program URL.

    Fetches the campaign page using browser cookies, parses scope,
    runs reconnaissance, uses AI to select high-value targets,
    performs vulnerability scanning, and generates a prioritized report.

    Supported platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack
    """
    from bountyhound.campaign import CampaignRunner

    # Load defaults from config
    config = load_config()
    campaign_config = config.get("campaign", {})

    # Use config defaults if options not provided
    if browser is None:
        browser = campaign_config.get("browser", "chrome")
    if max_targets is None:
        max_targets = campaign_config.get("max_targets", 100)

    runner = CampaignRunner(
        browser_type=browser,
        max_targets=max_targets,
        batch_mode=batch,
    )

    try:
        results = runner.run(url)

        if not batch:
            console.print(f"\n[bold]Campaign Summary for {results.get('program_name', 'Unknown')}:[/bold]")
            console.print(f"  Platform: {results.get('platform', 'unknown')}")
            console.print(f"  Domains: {len(results.get('domains', []))}")
            console.print(f"  Subdomains: {results.get('recon', {}).get('subdomains', 0)}")
            console.print(f"  Selected targets: {len(results.get('selected_targets', []))}")

            scan = results.get("scan", {})
            console.print(
                f"  Findings: critical={scan.get('critical', 0)}, "
                f"high={scan.get('high', 0)}, medium={scan.get('medium', 0)}"
            )

            console.print(f"\n[bold]AI Summary:[/bold]")
            console.print(results.get("summary", "No summary available."))
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


@main.command()
@click.argument("domain")
@click.option("--format", "-f", type=click.Choice(["markdown", "json"]), default="markdown", help="Report format")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
def report(domain: str, format: str, output: str | None):
    """Generate a report for a target domain."""
    db = Database()
    db.initialize()

    target = db.get_target(domain)
    if not target:
        console.print(f"[red]Target {domain} not found.[/red]")
        db.close()
        return

    from bountyhound.report import ReportGenerator

    generator = ReportGenerator(db)
    output_dir = Path(output) if output else None
    filepath = generator.save_report(domain, output_dir=output_dir, format=format)
    db.close()

    console.print(f"[green][+][/green] Report saved to: {filepath}")


if __name__ == "__main__":
    main()
