"""
Katana Crawler Agent

Runs katana for fast web crawling with JavaScript parsing and API endpoint
discovery. Falls back to Python requests-based crawler if katana is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import tempfile
import os
from typing import List, Dict, Optional



class KatanaCrawlerAgent:
    """Agent wrapping katana for web crawling and endpoint discovery."""

    def __init__(self, target: str, base_url: str = None, timeout: int = 60,
                 max_workers: int = 4, depth: int = 3):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.depth = depth
        self.katana_available = bool(shutil.which('katana'))

    def run(self) -> Dict:
        """Crawl the target and return discovered URLs and endpoints."""
        if self.katana_available:
            return self._run_katana()
        return self._run_fallback()

    def _run_katana(self) -> Dict:
        """Run katana web crawler."""
        output_file = tempfile.mktemp(suffix='.json')

        cmd = [
            'katana',
            '-u', self.base_url,
            '-d', str(self.depth),
            '-jc',           # JS crawling enabled
            '-aff',          # Auto form fill
            '-output', output_file,
            '-json',
            '-timeout', str(min(self.timeout, 30)),
            '-c', str(min(self.max_workers * 5, 20)),
            '-silent',
        ]

        urls = []
        endpoints = []
        js_files = []

        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout
            )
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            url = entry.get('endpoint', entry.get('url', ''))
                            if url:
                                urls.append(url)
                                if '.js' in url:
                                    js_files.append(url)
                                if any(p in url for p in ['/api/', '/graphql', '/v1/', '/v2/']):
                                    endpoints.append(url)
                        except json.JSONDecodeError:
                            if line.startswith('http'):
                                urls.append(line)
        except Exception as e:
            return {'agent': 'katana_crawler', 'error': str(e), 'findings': []}
        finally:
            try:
                os.unlink(output_file)
            except Exception:
                pass

        return {
            'agent': 'katana_crawler',
            'tool': 'katana',
            'target': self.target,
            'base_url': self.base_url,
            'urls': sorted(set(urls)),
            'api_endpoints': sorted(set(endpoints)),
            'js_files': sorted(set(js_files)),
            'total_urls': len(set(urls)),
            'findings': [{'url': u, 'type': 'crawled_url'} for u in set(urls)],
        }

    def _run_fallback(self) -> Dict:
        """Run Python requests-based crawler."""
        from engine.core.tool_checker import FallbackCrawler
        urls = FallbackCrawler.crawl(self.base_url, max_urls=200, timeout=10)
        js_files = [u for u in urls if '.js' in u]
        endpoints = [u for u in urls if any(p in u for p in ['/api/', '/graphql', '/v1/', '/v2/'])]
        return {
            'agent': 'katana_crawler',
            'tool': 'fallback_python_crawler',
            'target': self.target,
            'base_url': self.base_url,
            'urls': urls,
            'api_endpoints': endpoints,
            'js_files': js_files,
            'total_urls': len(urls),
            'findings': [{'url': u, 'type': 'crawled_url'} for u in urls],
            'note': 'katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest'
        }
