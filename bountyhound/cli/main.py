#!/usr/bin/env python3
"""
BountyHound CLI - Main Entry Point
Autonomous bug bounty hunting system
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from colorama import Fore, Style, init
from cli import __version__

# Initialize colorama
init()


def print_banner():
    """Print BountyHound banner"""
    banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║                    BOUNTY HOUND v{__version__}                         ║
║              Autonomous Bug Bounty Hunting System                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Database: Ready    │  Tools: 14 integrated │  Mode: Database-First║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def cmd_doctor(args):
    """Check tool dependencies and database status"""
    from contextlib import closing
    from data.db import BountyHoundDB

    print(f"\n{Fore.CYAN}=== BountyHound Health Check ==={Style.RESET_ALL}\n")

    # Check database
    try:
        db = BountyHoundDB()
        with closing(db._conn()) as conn:
            target_count = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]

        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Database: OK ({target_count} targets)")
    except Exception as e:
        print(f"{Fore.RED}✗{Style.RESET_ALL} Database: FAILED - {e}")

    # Check Python version
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Python: {version}")
    else:
        print(f"{Fore.YELLOW}!{Style.RESET_ALL} Python: {version} (3.8+ recommended)")

    # Check key dependencies
    dependencies = [
        ('requests', 'HTTP client'),
        ('colorama', 'Terminal colors'),
        ('boto3', 'AWS testing (optional)'),
    ]

    print(f"\n{Fore.CYAN}Dependencies:{Style.RESET_ALL}")
    for module, desc in dependencies:
        try:
            __import__(module)
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {module}: OK ({desc})")
        except ImportError:
            if module in ['boto3']:
                print(f"{Fore.YELLOW}!{Style.RESET_ALL} {module}: Not installed ({desc}) - optional")
            else:
                print(f"{Fore.RED}✗{Style.RESET_ALL} {module}: Missing ({desc})")

    # Check external CLI tools via ToolChecker
    print(f"\n{Fore.CYAN}External Tools:{Style.RESET_ALL}")
    try:
        from engine.core.tool_checker import ToolChecker
        checker = ToolChecker()
        status = checker.check_all()
        for tool_name, tool_status in status.items():
            config = checker.REQUIRED_TOOLS[tool_name]
            if tool_status.available:
                ver = f" ({tool_status.version})" if tool_status.version and tool_status.version != "unknown" else ""
                print(f"{Fore.GREEN}✓{Style.RESET_ALL} {tool_name}{ver}: {config['description']}")
            else:
                print(f"{Fore.YELLOW}!{Style.RESET_ALL} {tool_name}: NOT INSTALLED "
                      f"(fallback: {config['fallback_description']})")
    except Exception as e:
        print(f"{Fore.RED}✗{Style.RESET_ALL} Tool checker error: {e}")

    print(f"\n{Fore.GREEN}BountyHound is ready!{Style.RESET_ALL}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='BountyHound - Autonomous Bug Bounty Hunting System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  doctor              Check system health and dependencies
  db                  Database commands (see 'bountyhound db --help')

Examples:
  bountyhound doctor
  bountyhound db stats
  bountyhound db last-tested doordash.com
        """
    )

    parser.add_argument('-v', '--version', action='version', version=f'BountyHound {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # doctor command
    parser_doctor = subparsers.add_parser('doctor', help='Check system health')
    parser_doctor.set_defaults(func=cmd_doctor)

    # db command - delegate to db_commands.py
    parser_db = subparsers.add_parser('db', help='Database commands')
    parser_db.add_argument('db_args', nargs=argparse.REMAINDER, help='Database command arguments')

    args = parser.parse_args()

    # Print banner
    if args.command != 'db':  # Skip banner for db commands to keep output clean
        print_banner()

    if not args.command:
        parser.print_help()
        return 0

    # Handle db command
    if args.command == 'db':
        from cli.db_commands import main as db_main
        # Replace argv with db subcommand args
        sys.argv = ['bountyhound db'] + args.db_args
        return db_main()

    # Execute other commands
    if hasattr(args, 'func'):
        args.func(args)
        return 0
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
