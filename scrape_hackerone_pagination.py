#!/usr/bin/env python3
"""
HackerOne BBP Scraper - Pagination Method
Navigates through pages systematically to collect all programs
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

class H1PaginationScraper:
    def __init__(self):
        self.output_dir = Path("C:/Users/vaugh/Desktop/BountyHound/recon/hackerone-programs")
        self.programs = {}
        self.base_url = "https://hackerone.com/opportunities/all/search?bbp=true"

    def scrape_all_pages(self):
        """Navigate through pages and collect all programs"""
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")

        driver = webdriver.Chrome(options=chrome_options)

        try:
            page = 0
            offset = 0
            consecutive_empty = 0

            while page < 50 and consecutive_empty < 3:  # Max 50 pages or 3 empty pages in a row
                url = f"{self.base_url}&offset={offset}"
                print(f"\nPage {page + 1} (offset={offset})")
                print(f"   URL: {url}")

                driver.get(url)

                # Wait for programs to load
                try:
                    WebDriverWait(driver, 10).until(
                        EC.presence_of_all_elements_located((By.CSS_SELECTOR, "a[href*='?type=team']"))
                    )
                except:
                    print("   Timeout waiting for programs")

                # Extract programs from this page
                links = driver.find_elements(By.CSS_SELECTOR, "a[href*='?type=team']")
                page_count = 0

                for link in links:
                    href = link.get_attribute('href')
                    if href and '?type=team' in href:
                        handle = href.split('?')[0].strip('/')
                        if handle and handle not in self.programs:
                            self.programs[handle] = {
                                "handle": handle,
                                "name": link.text.strip() or handle,
                                "url": f"https://hackerone.com{href}",
                                "page": page
                            }
                            page_count += 1

                print(f"   Found {page_count} new programs (total: {len(self.programs)})")

                if page_count == 0:
                    consecutive_empty += 1
                    print(f"   No new programs ({consecutive_empty}/3)")
                else:
                    consecutive_empty = 0

                # Move to next page
                offset += 24
                page += 1

                # Small delay between pages
                time.sleep(0.5)

        finally:
            driver.quit()

        return self.programs

    def save_results(self):
        """Save discovered programs to JSON"""
        data = {
            "scraped_at": datetime.now().isoformat(),
            "total_found": len(self.programs),
            "discovery_method": "Pagination with offset parameter",
            "programs": sorted(self.programs.values(), key=lambda p: p['handle'])
        }

        output_file = self.output_dir / "programs_index.json"
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\nSaved {len(self.programs)} programs to {output_file}")
        return len(self.programs)


if __name__ == "__main__":
    scraper = H1PaginationScraper()
    print("=" * 70)
    print("HackerOne BBP Scraper - Pagination Method")
    print("=" * 70)

    scraper.scrape_all_pages()
    total = scraper.save_results()

    print("\n" + "=" * 70)
    print(f"COMPLETE: {total} programs discovered")
    print("=" * 70)
