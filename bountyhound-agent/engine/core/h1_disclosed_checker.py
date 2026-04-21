"""
HackerOne Disclosed Reports Duplicate Checker

Checks findings against publicly disclosed HackerOne reports to prevent
submitting duplicates that have already been publicly disclosed.
"""

import os
import json
import subprocess
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime, timedelta
from engine.core.semantic_dedup import SemanticDuplicateDetector
from engine.core.config import BountyHoundConfig

try:
    import requests as _requests_lib
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class H1DisclosedChecker:
    """Check findings against HackerOne's public disclosed reports"""

    def __init__(self):
        self.api_token = os.environ.get("H1_API_TOKEN", "")
        self.username = os.environ.get("H1_USERNAME", "")
        self.base_url = "https://api.hackerone.com/v1"
        self.cache_path = BountyHoundConfig.BASE_DIR / "database" / "disclosed_cache.json"
        self.cache_ttl = timedelta(hours=24)
        self.semantic_detector = SemanticDuplicateDetector()

    def _curl_get(self, url: str, params: dict = None) -> tuple:
        """Make authenticated GET request via curl (avoids requests dependency)."""
        import urllib.parse
        if params:
            url += '?' + urllib.parse.urlencode(params)
        cmd = [
            'curl', '-s', '-g', '-m', '30', '-w', '\n%{http_code}',
            '-X', 'GET',
            '-H', 'Accept: application/json',
            '-u', f'{self.username}:{self.api_token}',
            url,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', timeout=40)
            output = result.stdout.strip()
            lines = output.rsplit('\n', 1)
            body = lines[0] if len(lines) > 1 else output
            status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
            return status, body
        except Exception as e:
            return 0, str(e)

    def fetch_disclosed_reports(self, program: str) -> List[Dict]:
        """
        Fetch publicly disclosed reports for a program via /hackers/hacktivity.

        Uses the Lucene query syntax: team:<handle> AND disclosed:true
        """
        if not self.api_token or not self.username:
            return []

        try:
            # Hacktivity endpoint with Lucene query — correct hacker API endpoint
            query = f'team:{program} AND disclosed:true'
            status, body = self._curl_get(
                f"{self.base_url}/hackers/hacktivity",
                params={"queryString": query, "page[size]": "100"},
            )

            if status != 200:
                return []

            data = json.loads(body).get("data", [])

            reports = []
            for item in data:
                attrs = item.get("attributes", {})
                reports.append({
                    "id": item.get("id"),
                    "title": attrs.get("title", ""),
                    # hacktivity items don't include full vuln info — use title only for dedup
                    "vulnerability_information": attrs.get("title", ""),
                    "disclosed_at": attrs.get("disclosed_at", ""),
                    "bounty_amount": attrs.get("total_awarded_amount", "0.0"),
                    "url": attrs.get("url", ""),
                })

            return reports

        except Exception as e:
            print(f"[!] Error fetching disclosed reports: {e}")
            return []

    def check_duplicate(
        self,
        finding: Dict,
        disclosed_reports: List[Dict],
        threshold: float = 0.75
    ) -> Dict:
        """
        Check if finding matches any disclosed report using semantic similarity

        Args:
            finding: New finding dict with 'title' and 'description'
            disclosed_reports: List of disclosed report dicts
            threshold: Similarity threshold (0.0-1.0), default 0.75

        Returns:
            Dict with is_duplicate, match_type, matches, recommendation
        """
        if not disclosed_reports:
            return {
                "is_duplicate": False,
                "match_type": None,
                "matches": [],
                "recommendation": "PROCEED - no disclosed reports to check"
            }

        # Convert finding and disclosed reports to semantic format
        new_finding = {
            "title": finding.get("title", ""),
            "description": finding.get("description", "")
        }

        existing_findings = [
            {
                "title": report.get("title", ""),
                "description": report.get("vulnerability_information", ""),
                "id": report.get("id"),
                "disclosed_at": report.get("disclosed_at"),
                "bounty_amount": report.get("bounty_amount")
            }
            for report in disclosed_reports
        ]

        # Use semantic duplicate detection
        matches = self.semantic_detector.find_duplicates(
            new_finding,
            existing_findings,
            threshold=threshold
        )

        if matches:
            return {
                "is_duplicate": True,
                "match_type": "disclosed_report",
                "matches": matches,
                "recommendation": f"REJECT - {matches[0]['similarity_score']:.1%} similar to publicly disclosed report #{matches[0]['id']}"
            }

        return {
            "is_duplicate": False,
            "match_type": None,
            "matches": [],
            "recommendation": "PROCEED - no match with disclosed reports"
        }

    def build_cache(self, programs: List[str]) -> Dict:
        """
        Build local cache of disclosed reports for common programs

        Args:
            programs: List of program handles to cache

        Returns:
            Dictionary mapping program -> disclosed reports
        """
        cache = {}

        for program in programs:
            print(f"[*] Fetching disclosed reports for {program}...")
            reports = self.fetch_disclosed_reports(program)
            cache[program] = reports
            print(f"[+] Cached {len(reports)} disclosed reports for {program}")

        # Add timestamp
        cache["cached_at"] = datetime.utcnow().isoformat() + "Z"

        # Save to disk
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, 'w') as f:
            json.dump(cache, f, indent=2)

        print(f"[+] Cache saved to {self.cache_path}")
        return cache

    def load_from_cache(self, program: str) -> List[Dict]:
        """
        Load disclosed reports from cache (if not expired)

        Args:
            program: Program handle

        Returns:
            List of disclosed reports, or empty list if cache expired/missing
        """
        if not self.cache_path.exists():
            return []

        try:
            with open(self.cache_path, 'r') as f:
                cache = json.load(f)

            # Check cache age
            cached_at = datetime.fromisoformat(cache.get("cached_at", "").replace("Z", ""))
            age = datetime.utcnow() - cached_at

            if age > self.cache_ttl:
                print(f"[!] Cache expired ({age.total_seconds()/3600:.1f}h old)")
                return []

            return cache.get(program, [])

        except Exception as e:
            print(f"[!] Error loading cache: {e}")
            return []

    def check_against_disclosed(
        self,
        finding: Dict,
        program: str,
        use_cache: bool = True
    ) -> Dict:
        """
        Complete workflow: check finding against disclosed reports

        Args:
            finding: New finding to check
            program: HackerOne program handle
            use_cache: Whether to use cached data (default: True)

        Returns:
            Duplicate check result dict
        """
        # Try loading from cache first
        disclosed_reports = []
        if use_cache:
            disclosed_reports = self.load_from_cache(program)
            if disclosed_reports:
                print(f"[+] Loaded {len(disclosed_reports)} disclosed reports from cache")

        # Fetch fresh if no cache
        if not disclosed_reports:
            print(f"[*] Fetching fresh disclosed reports for {program}...")
            disclosed_reports = self.fetch_disclosed_reports(program)

        # Check for duplicates
        return self.check_duplicate(finding, disclosed_reports)
