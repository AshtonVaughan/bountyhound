"""
BountyHound Database CLI Commands
Quick access to database queries and statistics
"""

import sys
import argparse
from datetime import date, datetime
from pathlib import Path
from typing import List, Dict, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks
from engine.core.payload_hooks import PayloadHooks
from colorama import Fore, Style, init

# Initialize colorama
init()


def format_date(date_obj) -> str:
    """Format date for display"""
    if isinstance(date_obj, str):
        date_obj = datetime.strptime(date_obj, '%Y-%m-%d').date()

    if not date_obj:
        return "Never"

    days_ago = (date.today() - date_obj).days

    if days_ago == 0:
        return "Today"
    elif days_ago == 1:
        return "Yesterday"
    elif days_ago < 7:
        return f"{days_ago} days ago"
    elif days_ago < 30:
        return f"{days_ago // 7} weeks ago"
    else:
        return f"{days_ago // 30} months ago"


def cmd_last_tested(args):
    """Show when a target was last tested"""
    db = BountyHoundDB()
    stats = db.get_target_stats(args.domain)

    if not stats:
        print(f"{Fore.YELLOW}Target '{args.domain}' not found in database{Style.RESET_ALL}")
        print(f"Run a test first to add this target.")
        return

    print(f"\n{Fore.CYAN}=== {args.domain} ==={Style.RESET_ALL}")
    print(f"Last tested: {Fore.GREEN}{format_date(stats['last_tested'])}{Style.RESET_ALL}")
    print(f"Total findings: {stats['total_findings']}")
    print(f"Accepted findings: {stats['accepted_findings']}")
    print(f"Total payouts: ${stats['total_payouts']:,.2f}")

    if stats['total_findings'] > 0:
        avg = stats['total_payouts'] / stats['total_findings']
        print(f"Average per finding: ${avg:,.2f}")


def cmd_stats(args):
    """Show overall statistics"""
    db = BountyHoundDB()

    with db._get_connection() as conn:
        cursor = conn.cursor()

        # Overall stats
        cursor.execute("SELECT COUNT(*) FROM targets")
        target_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*), SUM(payout) FROM findings WHERE status = 'accepted'")
        accepted_count, total_payouts = cursor.fetchone()
        total_payouts = total_payouts or 0

        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]

        print(f"\n{Fore.CYAN}=== BountyHound Database Statistics ==={Style.RESET_ALL}")
        print(f"Targets: {target_count}")
        print(f"Total findings: {total_findings}")
        print(f"Accepted findings: {accepted_count}")
        print(f"Total payouts: ${total_payouts:,.2f}")

        if accepted_count > 0:
            avg = total_payouts / accepted_count
            print(f"Average payout: ${avg:,.2f}")

        # Top targets by ROI
        print(f"\n{Fore.CYAN}Top 5 Targets by ROI:{Style.RESET_ALL}")
        cursor.execute("""
            SELECT domain, total_findings, total_payouts,
                   (total_payouts * 1.0 / NULLIF(total_findings, 0)) as avg_payout
            FROM targets
            WHERE total_payouts > 0
            ORDER BY avg_payout DESC
            LIMIT 5
        """)

        for i, row in enumerate(cursor.fetchall(), 1):
            domain, findings, payouts, avg = row
            print(f"{i}. {Fore.GREEN}{domain}{Style.RESET_ALL}: "
                  f"{findings} findings, ${payouts:,.2f} (${avg:,.2f} avg)")


def cmd_query(args):
    """Execute raw SQL query"""
    db = BountyHoundDB()

    try:
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(args.sql)

            # Get column names
            columns = [desc[0] for desc in cursor.description] if cursor.description else []

            # Fetch results
            rows = cursor.fetchall()

            if not rows:
                print(f"{Fore.YELLOW}No results{Style.RESET_ALL}")
                return

            # Print header
            print(f"\n{Fore.CYAN}" + " | ".join(columns) + f"{Style.RESET_ALL}")
            print("-" * 80)

            # Print rows
            for row in rows:
                values = [str(v) if v is not None else "NULL" for v in row]
                print(" | ".join(values))

            print(f"\n{len(rows)} row(s)")

    except Exception as e:
        print(f"{Fore.RED}Query error: {e}{Style.RESET_ALL}")


def cmd_check_duplicate(args):
    """Check if a finding is a duplicate"""
    keywords = args.keywords.split(',') if args.keywords else []

    result = DatabaseHooks.check_duplicate(
        args.domain,
        args.vuln_type,
        keywords
    )

    if result['is_duplicate']:
        print(f"{Fore.RED}🚨 DUPLICATE ALERT!{Style.RESET_ALL}")
        similar = result['similar_finding']
        print(f"\nSimilar finding exists:")
        print(f"  Title: {similar['title']}")
        print(f"  Status: {similar['status']}")
        print(f"  Severity: {similar['severity']}")
        print(f"  Discovered: {similar['discovered_date']}")
        if similar.get('platform_report_id'):
            print(f"  Report ID: {similar['platform_report_id']}")
        print(f"\n{Fore.YELLOW}→ DO NOT SUBMIT THIS FINDING{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✓ No duplicate found{Style.RESET_ALL}")
        print(f"This appears to be a new finding for {args.domain}")


def cmd_payloads(args):
    """List successful payloads"""
    payloads = DatabaseHooks.get_successful_payloads(
        args.vuln_type if hasattr(args, 'vuln_type') and args.vuln_type else None,
        args.tech_stack if hasattr(args, 'tech_stack') and args.tech_stack else None
    )

    if not payloads:
        print(f"{Fore.YELLOW}No payloads found{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}=== Successful Payloads ({len(payloads)}) ==={Style.RESET_ALL}\n")

    for i, p in enumerate(payloads, 1):
        print(f"{i}. {Fore.GREEN}{p['vuln_type']}{Style.RESET_ALL}")
        print(f"   Payload: {p['payload'][:80]}{'...' if len(p['payload']) > 80 else ''}")
        print(f"   Context: {p['context']}")
        print(f"   Tech stack: {p['tech_stack']}")
        print(f"   Success count: {p['success_count']}")
        if p.get('notes'):
            print(f"   Notes: {p['notes']}")
        print()


def cmd_recent(args):
    """Show recent findings for a target"""
    db = BountyHoundDB()
    findings = db.get_recent_findings(args.domain, limit=args.limit)

    if not findings:
        print(f"{Fore.YELLOW}No findings for {args.domain}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}=== Recent Findings for {args.domain} ({len(findings)}) ==={Style.RESET_ALL}\n")

    for i, f in enumerate(findings, 1):
        severity_color = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.YELLOW,
            'MEDIUM': Fore.CYAN,
            'LOW': Fore.WHITE
        }.get(f['severity'], Fore.WHITE)

        print(f"{i}. [{severity_color}{f['severity']}{Style.RESET_ALL}] {f['title']}")
        print(f"   Status: {f['status']}")
        print(f"   Discovered: {f['discovered_date']}")
        if f.get('payout'):
            print(f"   Payout: ${f['payout']:,.2f}")
        print()


def cmd_recommend(args):
    """Get recommended payloads for a target and vulnerability type"""
    from engine.core.payload_learner import PayloadRecommender

    recommender = PayloadRecommender()

    limit = getattr(args, 'limit', 5)
    recs = recommender.get_recommendations(args.domain, args.vuln_type, limit)

    if not recs:
        print(f"{Fore.YELLOW}No payloads found for {args.vuln_type}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}=== Top {min(len(recs), limit)} Payloads for {args.vuln_type} ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Target: {args.domain}{Style.RESET_ALL}\n")

    for i, rec in enumerate(recs, 1):
        score_color = Fore.GREEN if rec['score'] >= 70 else Fore.YELLOW if rec['score'] >= 50 else Fore.RED
        print(f"{i}. {score_color}Score: {rec['score']}/100{Style.RESET_ALL}")
        print(f"   Payload: {rec['payload'][:100]}{'...' if len(rec['payload']) > 100 else ''}")
        print(f"   Success Count: {rec['success_count']}")
        if rec['tech_stack']:
            print(f"   Tech Stack: {rec['tech_stack']}")
        if rec['context']:
            print(f"   Context: {rec['context']}")
        if rec['notes']:
            print(f"   Notes: {rec['notes']}")
        print()


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='BountyHound Database CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  bountyhound db last-tested doordash.com
  bountyhound db stats
  bountyhound db query "SELECT * FROM targets WHERE total_payouts > 50000"
  bountyhound db check-duplicate example.com IDOR "api,users"
  bountyhound db payloads --vuln-type XSS --tech-stack React
  bountyhound db recent doordash.com --limit 10
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # last-tested command
    parser_last = subparsers.add_parser('last-tested', help='Show when target was last tested')
    parser_last.add_argument('domain', help='Target domain')
    parser_last.set_defaults(func=cmd_last_tested)

    # stats command
    parser_stats = subparsers.add_parser('stats', help='Show overall statistics')
    parser_stats.set_defaults(func=cmd_stats)

    # query command
    parser_query = subparsers.add_parser('query', help='Execute raw SQL query')
    parser_query.add_argument('sql', help='SQL query to execute')
    parser_query.set_defaults(func=cmd_query)

    # check-duplicate command
    parser_dup = subparsers.add_parser('check-duplicate', help='Check for duplicate findings')
    parser_dup.add_argument('domain', help='Target domain')
    parser_dup.add_argument('vuln_type', help='Vulnerability type (e.g., IDOR, XSS)')
    parser_dup.add_argument('keywords', nargs='?', help='Comma-separated keywords (optional)')
    parser_dup.set_defaults(func=cmd_check_duplicate)

    # payloads command
    parser_payloads = subparsers.add_parser('payloads', help='List successful payloads')
    parser_payloads.add_argument('--vuln-type', help='Filter by vulnerability type')
    parser_payloads.add_argument('--tech-stack', help='Filter by tech stack')
    parser_payloads.set_defaults(func=cmd_payloads)

    # recent command
    parser_recent = subparsers.add_parser('recent', help='Show recent findings')
    parser_recent.add_argument('domain', help='Target domain')
    parser_recent.add_argument('--limit', type=int, default=5, help='Number of findings (default: 5)')
    parser_recent.set_defaults(func=cmd_recent)

    # recommend command
    parser_recommend = subparsers.add_parser('recommend', help='Get payload recommendations')
    parser_recommend.add_argument('domain', help='Target domain')
    parser_recommend.add_argument('vuln_type', help='Vulnerability type (e.g., XSS, SQLi, IDOR)')
    parser_recommend.add_argument('--limit', type=int, default=5, help='Number of payloads (default: 5)')
    parser_recommend.set_defaults(func=cmd_recommend)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Execute command
    args.func(args)


if __name__ == '__main__':
    main()
