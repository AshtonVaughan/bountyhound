"""
GAU (GetAllURLs) Agent

Fetches known URLs from Wayback Machine, CommonCrawl, OTX, and URLScan.
Falls back to direct Wayback + CommonCrawl API queries if gau is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
from typing import List, Dict, Set



class GAUUrlsAgent:
    """Agent wrapping gau for historical URL discovery."""

    def __init__(self, target: str, timeout: int = 60, max_workers: int = 4):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.gau_available = bool(shutil.which('gau'))

    def run(self) -> Dict:
        """Fetch historical URLs for the target domain."""
        if self.gau_available:
            return self._run_gau()
        return self._run_fallback()

    def _run_gau(self) -> Dict:
        """Run gau to fetch URLs from all sources."""
        cmd = [
            'gau',
            '--subs',           # Include subdomains
            '--providers', 'wayback,commoncrawl,otx,urlscan',
            '--blacklist', 'png,jpg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3',
            self.target,
        ]

        urls: Set[str] = set()
        interesting: List[str] = []

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and line.startswith('http'):
                    urls.add(line)
                    # Flag interesting patterns
                    if any(p in line for p in [
                        '?', 'api', 'admin', 'debug', 'backup', 'token',
                        'key', 'secret', 'password', 'auth', 'upload',
                        '.json', '.xml', '.yaml', '.sql', '.env', '.bak',
                        '/v1/', '/v2/', '/graphql', '/internal/',
                    ]):
                        interesting.append(line)
        except Exception as e:
            return {'agent': 'gau_urls', 'error': str(e), 'findings': []}

        url_list = sorted(urls)
        return {
            'agent': 'gau_urls',
            'tool': 'gau',
            'target': self.target,
            'urls': url_list,
            'interesting_urls': sorted(set(interesting)),
            'total_urls': len(url_list),
            'findings': [{'url': u, 'type': 'historical_url'} for u in interesting],
        }

    def _run_fallback(self) -> Dict:
        """Run direct Wayback + CommonCrawl API queries."""
        from engine.core.tool_checker import FallbackGAU
        urls = FallbackGAU.fetch_urls(self.target, timeout=self.timeout)

        interesting = [u for u in urls if any(p in u for p in [
            '?', 'api', 'admin', 'debug', 'backup', 'token', 'key',
            'secret', '.json', '.xml', '.sql', '.env', '.bak',
            '/v1/', '/v2/', '/graphql', '/internal/',
        ])]

        return {
            'agent': 'gau_urls',
            'tool': 'fallback_wayback_commoncrawl',
            'target': self.target,
            'urls': urls,
            'interesting_urls': interesting,
            'total_urls': len(urls),
            'findings': [{'url': u, 'type': 'historical_url'} for u in interesting],
            'note': 'gau not installed. Install: go install github.com/lc/gau/v2/cmd/gau@latest'
        }
