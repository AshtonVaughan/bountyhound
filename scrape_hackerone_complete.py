#!/usr/bin/env python3
"""
HackerOne Complete BBP Scraper
Uses Selenium for intelligent infinite scroll discovery and program detail extraction
"""

import json
import time
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
logger = logging.getLogger(__name__)

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

        self.programs = {}
        self.logger = logger

    def log(self, message: str, level="INFO"):
        """Log to both console and file"""
        log_func = getattr(self.logger, level.lower())
        log_func(message)

        with open(self.log_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()} | {level} | {message}\n")

    def save_index(self):
        """Save program index"""
        data = {
            "scraped_at": datetime.now().isoformat(),
            "total_found": len(self.programs),
            "target_total": 236,
            "discovery_method": "Selenium with lazy-load detection",
            "programs": list(self.programs.values())
        }

        with open(self.index_file, 'w') as f:
            json.dump(data, f, indent=2)

        self.log(f"Saved index: {len(self.programs)} programs")

    def discover_with_selenium(self):
        """
        Use Selenium with Chrome to discover all BBPs
        Implements proper IntersectionObserver detection
        """
        try:
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.chrome.options import Options
        except ImportError:
            self.log("ERROR: Selenium not installed. Install with: pip install selenium", "ERROR")
            self.log("Falling back to browser automation instructions...", "WARNING")
            return self.manual_discovery_instructions()

        self.log("Starting Selenium-based discovery...")

        # Chrome options for headless operation
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

        driver = None
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.get("https://hackerone.com/opportunities/all/search?bbp=true&ordering=Newest+programs")

            # Wait for initial programs to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.CSS_SELECTOR, "a[href*='?type=team']"))
            )

            self.log("Page loaded, starting discovery...")

            # Inject IntersectionObserver detection script
            detection_script = """
            window.loadedCount = 0;
            window.lastCount = 0;
            window.noChangeCount = 0;

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        window.loadedCount++;
                    }
                });
            }, { threshold: 0.1 });

            // Observe all program links
            document.querySelectorAll('a[href*="?type=team"]').forEach(el => {
                observer.observe(el);
            });

            window.observerActive = true;
            """

            driver.execute_script(detection_script)

            # Aggressive scrolling with lazy-load detection
            scroll_count = 0
            max_scrolls = 300
            no_change_threshold = 10
            no_change_count = 0
            last_program_count = 0

            while scroll_count < max_scrolls and no_change_count < no_change_threshold:
                # Get current programs
                links = driver.find_elements(By.CSS_SELECTOR, "a[href*='?type=team']")
                current_count = len(links)

                # Extract new programs
                for link in links:
                    href = link.get_attribute('href')
                    if href and '?type=team' in href:
                        handle = href.split('?')[0].strip('/')
                        name = link.text.strip()

                        if handle and handle not in self.programs:
                            self.programs[handle] = {
                                "handle": handle,
                                "name": name or handle,
                                "url": f"https://hackerone.com{href}",
                                "managed": False,
                                "offers_bounties": True,
                                "status": "pending"
                            }

                # Check for progress
                if current_count == last_program_count:
                    no_change_count += 1
                else:
                    no_change_count = 0

                last_program_count = current_count

                # Log progress
                if scroll_count % 10 == 0:
                    self.log(f"Scroll {scroll_count}: {current_count} programs found (no-change: {no_change_count})")

                # Scroll down
                driver.execute_script("window.scrollBy(0, 1500);")
                scroll_count += 1

                # Wait for lazy loading
                time.sleep(0.4)

            self.log(f"Discovery complete: {len(self.programs)} programs found after {scroll_count} scrolls")

        except Exception as e:
            self.log(f"ERROR: {str(e)}", "ERROR")
            return False
        finally:
            if driver:
                driver.quit()

        return True

    def manual_discovery_instructions(self):
        """Provide instructions for manual discovery if Selenium unavailable"""
        self.log("=" * 70)
        self.log("MANUAL DISCOVERY MODE")
        self.log("=" * 70)
        self.log("")
        self.log("Since Selenium is not installed, follow these steps:")
        self.log("")
        self.log("1. INSTALL SELENIUM:")
        self.log("   pip install selenium")
        self.log("")
        self.log("2. DOWNLOAD CHROMEDRIVER:")
        self.log("   https://chromedriver.chromium.org/")
        self.log("   Place in: C:/Users/vaugh/Desktop/BountyHound/")
        self.log("")
        self.log("3. RE-RUN THIS SCRIPT:")
        self.log("   python scrape_hackerone_complete.py")
        self.log("")
        self.log("=" * 70)
        return False

    def scrape_program_details(self, handle: str) -> Optional[Dict]:
        """
        Scrape detailed information for a single program
        This will be implemented in Phase 2
        """
        self.log(f"Placeholder: Will scrape details for {handle} in Phase 2")
        return None

    def generate_summary(self):
        """Generate summary statistics"""
        summary = {
            "completed_at": datetime.now().isoformat(),
            "total_programs_found": len(self.programs),
            "total_scraped": 0,
            "total_failed": 0,
            "programs_with_bounties": len([p for p in self.programs.values() if p.get('offers_bounties')]),
            "target_coverage": f"{len(self.programs)}/236 ({100*len(self.programs)/236:.1f}%)"
        }

        with open(self.summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        self.log(f"Summary: {len(self.programs)} programs ({summary['target_coverage']})")


def main():
    scraper = HackerOneScraper()

    print("\n" + "=" * 70)
    print("HackerOne Complete BBP Scraper (Option A: Advanced Discovery)")
    print("=" * 70)
    print(f"Output: {scraper.output_dir}")
    print(f"Target: 236 Bug Bounty Programs")
    print("=" * 70 + "\n")

    scraper.log("Starting HackerOne complete discovery...")

    # Phase 1: Discovery
    if scraper.discover_with_selenium():
        scraper.save_index()
        scraper.generate_summary()

        print("\n" + "=" * 70)
        print("✅ DISCOVERY PHASE COMPLETE")
        print("=" * 70)
        print(f"Programs found: {len(scraper.programs)}")
        print(f"Index saved to: {scraper.index_file}")
        print(f"Log saved to: {scraper.log_file}")
        print("=" * 70 + "\n")

        return 0
    else:
        print("\n" + "=" * 70)
        print("❌ DISCOVERY PHASE FAILED")
        print("=" * 70 + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
