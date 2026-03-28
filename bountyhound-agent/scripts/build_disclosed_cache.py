#!/usr/bin/env python3
"""
Build cache of disclosed reports for common programs

Run this daily via cron/scheduled task:
python scripts/build_disclosed_cache.py

Or set up a scheduled task on Windows:
schtasks /create /tn "BountyHound Disclosed Cache" /tr "python C:\Users\vaugh\BountyHound\bountyhound-agent\scripts\build_disclosed_cache.py" /sc daily /st 03:00
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.core.h1_disclosed_checker import H1DisclosedChecker

# Top bug bounty programs with public disclosures
PROGRAMS = [
    "shopify",
    "github",
    "gitlab",
    "reddit",
    "coinbase",
    "paypal",
    "uber",
    "twitter",
    "yahoo",
    "att",
    "starbucks",
    "sony",
    "snapchat",
    "spotify",
    "dropbox",
    "airbnb",
    "slack",
    "verizonmedia",
    "booking",
    "rockstar-games"
]

def main():
    """Build cache of disclosed reports for all programs"""
    print("=" * 70)
    print("BountyHound - HackerOne Disclosed Reports Cache Builder")
    print("=" * 70)
    print()

    checker = H1DisclosedChecker()

    # Check if credentials are configured
    if not checker.api_token or not checker.username:
        print("[!] ERROR: HackerOne API credentials not configured")
        print()
        print("Set the following environment variables:")
        print("  - H1_API_TOKEN")
        print("  - H1_USERNAME")
        print()
        print("Get your API token from: https://hackerone.com/settings/api_token/edit")
        return 1

    print(f"[*] Building cache for {len(PROGRAMS)} programs...")
    print()

    cache = checker.build_cache(PROGRAMS)

    # Calculate statistics
    total_reports = sum(
        len(reports) for program, reports in cache.items()
        if program != "cached_at"
    )

    print()
    print("=" * 70)
    print(f"[+] Successfully cached {total_reports} disclosed reports")
    print(f"[+] Across {len(PROGRAMS)} programs")
    print(f"[+] Cache saved to: {checker.cache_path}")
    print(f"[+] Cache valid for 24 hours")
    print("=" * 70)

    # Display top programs by report count
    program_counts = [
        (program, len(reports))
        for program, reports in cache.items()
        if program != "cached_at"
    ]
    program_counts.sort(key=lambda x: x[1], reverse=True)

    print()
    print("Top programs by disclosed report count:")
    for i, (program, count) in enumerate(program_counts[:10], 1):
        print(f"  {i:2d}. {program:20s} - {count:4d} reports")

    return 0

if __name__ == "__main__":
    sys.exit(main())
