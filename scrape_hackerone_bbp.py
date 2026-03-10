#!/usr/bin/env python3
"""
HackerOne Bug Bounty Program Scraper
Discovers and scrapes all public BBP programs on HackerOne
"""

import json
import time
import os
from contextlib import closing
from datetime import datetime
from pathlib import Path
import subprocess
import sys


def _sync_to_bountyhound_db(program_data: dict) -> None:
    """Mirror scraped program to bountyhound.db programs table."""
    sys.path.insert(0, str(Path(__file__).parent / "bountyhound-agent"))
    from data.db import BountyHoundDB
    db = BountyHoundDB()
    handle = program_data.get('handle', '')
    if not handle:
        return
    with closing(db._conn()) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO programs
                (handle, name, platform, url, offers_bounties, min_bounty, max_bounty, policy_url)
            VALUES (?, ?, 'hackerone', ?, ?, ?, ?, ?)
        """, (
            handle,
            program_data.get('name', ''),
            program_data.get('url', ''),
            1 if program_data.get('offers_bounties') else 0,
            program_data.get('minimum_bounty_table', {}).get('value') if isinstance(program_data.get('minimum_bounty_table'), dict) else program_data.get('min_bounty'),
            program_data.get('maximum_bounty_table', {}).get('value') if isinstance(program_data.get('maximum_bounty_table'), dict) else program_data.get('max_bounty'),
            f"https://hackerone.com/{handle}",
        ))
        conn.commit()


class HackerOneScraper:
    def __init__(self, output_dir="C:/Users/vaugh/Desktop/BountyHound/recon/hackerone-programs"):
        self.output_dir = Path(output_dir)
        self.programs_dir = self.output_dir / "programs"
        self.index_file = self.output_dir / "programs_index.json"
        self.log_file = self.output_dir / "scrape_log.txt"
        self.summary_file = self.output_dir / "summary.json"

        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.programs_dir.mkdir(parents=True, exist_ok=True)

        # Load existing progress
        self.programs = self.load_index()
        self.log_entries = []

    def load_index(self):
        """Load existing program index if available"""
        if self.index_file.exists():
            with open(self.index_file) as f:
                data = json.load(f)
                return {p['handle']: p for p in data.get('programs', [])}
        return {}

    def save_index(self):
        """Save program index to file"""
        data = {
            "scraped_at": datetime.now().isoformat(),
            "total_found": len(self.programs),
            "programs": list(self.programs.values())
        }
        with open(self.index_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Saved index: {len(self.programs)} programs")

    def log(self, message):
        """Log scraping activity"""
        timestamp = datetime.now().isoformat()
        log_entry = f"{timestamp} | {message}"
        self.log_entries.append(log_entry)
        print(log_entry)

        # Append to file
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')

    def scrape_discovery_page(self):
        """
        Use JavaScript injection in Chrome to scrape all programs from discovery page.
        This will be orchestrated by Claude Code through the browser automation.
        """
        self.log("Starting discovery phase: extracting programs from HackerOne opportunities page")
        self.log(f"Target: Discover all ~453 programs via scrolling and extraction")
        print("\n📋 MANUAL ORCHESTRATION PHASE")
        print("=" * 60)
        print("Claude Code will now:")
        print("1. Use JavaScript to continuously scroll the discovery page")
        print("2. Extract all program handles and URLs as they load")
        print("3. Save to programs_index.json after each batch")
        print("4. Continue until all 453 programs are collected")
        print("=" * 60)
        return True

    def add_program(self, handle, name, url, managed=False, offers_bounties=True):
        """Add a program to the index"""
        if handle not in self.programs:
            self.programs[handle] = {
                "handle": handle,
                "name": name,
                "url": url,
                "managed": managed,
                "offers_bounties": offers_bounties,
                "status": "pending"
            }
            try:
                _sync_to_bountyhound_db(self.programs[handle])
            except Exception as e:
                print(f"  Warning: bountyhound.db sync failed: {e}")
            return True
        return False

    def mark_program_status(self, handle, status, error_reason=None):
        """Update program scraping status"""
        if handle in self.programs:
            self.programs[handle]['status'] = status
            if error_reason:
                self.programs[handle]['error'] = error_reason
            self.save_index()

    def parse_program_page(self, handle, html_content):
        """
        Parse individual program page HTML and extract structured data.
        This will be called after scraping each program detail page.
        """
        # This will be called once programs are scraped
        pass

    def generate_summary(self):
        """Generate summary statistics after scraping"""
        scraped = [p for p in self.programs.values() if p['status'] == 'scraped']
        failed = [p for p in self.programs.values() if p['status'] == 'failed']

        summary = {
            "completed_at": datetime.now().isoformat(),
            "total_programs_found": len(self.programs),
            "total_scraped": len(scraped),
            "total_failed": len(failed),
            "programs_with_bounties": len([p for p in scraped if p.get('offers_bounties')]),
            "severity_ranges": {
                "highest_critical_bounty": {"program": "", "amount": 0},
                "average_critical_bounty": 0,
                "highest_high_bounty": {"program": "", "amount": 0}
            },
            "most_common_in_scope_types": {},
            "programs_by_asset_count": []
        }

        with open(self.summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        self.log(f"✓ Generated summary: {len(scraped)} scraped, {len(failed)} failed")


def main():
    scraper = HackerOneScraper()

    print("\n🔍 HackerOne Bug Bounty Program Scraper")
    print("=" * 60)
    print(f"Output directory: {scraper.output_dir}")
    print(f"Target programs: ~453 active BBPs on HackerOne")
    print("=" * 60)

    # Start discovery
    scraper.scrape_discovery_page()
    scraper.save_index()

    print("\n✅ Scraper initialized and ready for Claude Code orchestration")
    print(f"   Index file: {scraper.index_file}")
    print(f"   Log file: {scraper.log_file}")


if __name__ == "__main__":
    main()
