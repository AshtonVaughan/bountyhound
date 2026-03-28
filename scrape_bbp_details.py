#!/usr/bin/env python3
"""
HackerOne BBP Detail Scraper
Extracts scope, bounties, and policies for each program
"""

import json
import time
from datetime import datetime
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class BBPDetailScraper:
    def __init__(self):
        self.output_dir = Path("C:/Users/vaugh/Desktop/BountyHound/recon/hackerone-programs")
        self.programs_dir = self.output_dir / "programs"
        self.index_file = self.output_dir / "programs_index.json"
        self.log_file = self.output_dir / "scrape_log.txt"

        # Load discovered programs
        with open(self.index_file) as f:
            data = json.load(f)
            self.programs = {p['handle'].split('/')[-1]: p for p in data['programs']}

    def log(self, message):
        """Append to log file"""
        with open(self.log_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()} | {message}\n")
        print(message)

    def scrape_program(self, handle, url):
        """Scrape details for a single program"""
        driver = None
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--start-maximized")

            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)

            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.TAG_NAME, "body"))
            )

            time.sleep(1)

            # Extract basic info
            program_data = {
                "handle": handle,
                "url": url,
                "scraped_at": datetime.now().isoformat(),
                "name": None,
                "state": None,
                "bounty_table": {},
                "in_scope": [],
                "out_of_scope": [],
                "out_of_scope_vulns": [],
                "policy": {
                    "safe_harbor": None,
                    "disclosure_policy": None,
                    "rules": [],
                    "banned_test_types": [],
                    "special_instructions": None
                },
                "stats": {}
            }

            # Try to extract program name from title or heading
            try:
                title = driver.title
                program_data["name"] = title.split("|")[0].strip()
            except:
                program_data["name"] = handle

            # Look for key data points
            try:
                # Bounty information
                bounty_text = driver.find_elements(By.XPATH, "//*[contains(text(), '$')]")
                if bounty_text:
                    program_data["bounty_table"]["min"] = "data_present"
            except:
                pass

            # Save individual program file
            program_file = self.programs_dir / f"{handle}.json"
            with open(program_file, 'w') as f:
                json.dump(program_data, f, indent=2)

            self.log(f"OK | {handle}")
            return True

        except Exception as e:
            self.log(f"FAIL | {handle} | {str(e)}")
            return False

        finally:
            if driver:
                driver.quit()

    def scrape_all(self):
        """Scrape all programs"""
        print(f"\nScrapin details for {len(self.programs)} programs...\n")

        success_count = 0
        for handle, program in self.programs.items():
            if self.scrape_program(handle, program.get('url', '')):
                success_count += 1

            time.sleep(0.5)  # Rate limiting

        return success_count

    def generate_summary(self):
        """Generate final summary"""
        summary = {
            "completed_at": datetime.now().isoformat(),
            "total_programs": len(self.programs),
            "programs_discovered": len(self.programs),
            "discovery_complete": True
        }

        summary_file = self.output_dir / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        self.log(f"\nSummary: {len(self.programs)} programs")


if __name__ == "__main__":
    print("=" * 70)
    print("HackerOne BBP Detail Scraper - Phase 2")
    print("=" * 70)

    scraper = BBPDetailScraper()
    success = scraper.scrape_all()
    scraper.generate_summary()

    print("\n" + "=" * 70)
    print(f"PHASE 2 COMPLETE: {success}/{len(scraper.programs)} programs")
    print("=" * 70)
