"""
Feroxbuster Content Discovery Agent

Runs feroxbuster for fast recursive directory and content discovery.
Falls back to Python wordlist-based directory buster if feroxbuster is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import tempfile
import os
from typing import List, Dict, Optional



class FeroxbusterDiscoveryAgent:
    """Agent wrapping feroxbuster for recursive content discovery."""

    def __init__(self, target: str, base_url: str = None, timeout: int = 120,
                 max_workers: int = 4, depth: int = 2, wordlist: str = None):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.depth = depth
        self.wordlist = wordlist
        self.feroxbuster_available = bool(shutil.which('feroxbuster'))

    def run(self) -> Dict:
        """Discover content recursively on the target."""
        if self.feroxbuster_available:
            return self._run_feroxbuster()
        return self._run_fallback()

    def _find_wordlist(self) -> Optional[str]:
        """Locate an installed wordlist."""
        if self.wordlist and os.path.exists(self.wordlist):
            return self.wordlist
        candidates = [
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
            '/opt/seclists/Discovery/Web-Content/common.txt',
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def _run_feroxbuster(self) -> Dict:
        """Run feroxbuster for recursive content discovery."""
        output_file = tempfile.mktemp(suffix='.json')
        wordlist = self._find_wordlist()

        cmd = [
            'feroxbuster',
            '--url', self.base_url,
            '--output', output_file,
            '--json',
            '--depth', str(self.depth),
            '--threads', str(min(self.max_workers * 10, 50)),
            '--timeout', str(min(self.timeout // 4, 30)),
            '--status-codes', '200,201,204,301,302,307,401,403,405',
            '--silent',
            '--no-recursion' if self.depth <= 1 else '--auto-tune',
            '--filter-status', '404',
        ]
        if wordlist:
            cmd.extend(['--wordlist', wordlist])

        findings = []
        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout
            )
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get('type') == 'response':
                                findings.append({
                                    'url': entry.get('url', ''),
                                    'status': entry.get('status', 0),
                                    'size': entry.get('content_length', 0),
                                    'words': entry.get('word_count', 0),
                                    'lines': entry.get('line_count', 0),
                                })
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            return {'agent': 'feroxbuster_discovery', 'error': str(e), 'findings': []}
        finally:
            try:
                os.unlink(output_file)
            except Exception:
                pass

        # Flag high-interest paths
        interesting = [f for f in findings if any(p in f['url'] for p in [
            'admin', 'api', 'backup', 'config', 'debug', 'internal',
            'secret', '.env', '.git', 'phpinfo', 'swagger', 'graphql',
        ])]

        return {
            'agent': 'feroxbuster_discovery',
            'tool': 'feroxbuster',
            'target': self.target,
            'base_url': self.base_url,
            'findings': findings,
            'interesting': interesting,
            'total': len(findings),
        }

    def _run_fallback(self) -> Dict:
        """Run Python curl-based content discovery."""
        from engine.core.tool_checker import FallbackContentDiscovery
        results = FallbackContentDiscovery.discover(
            self.base_url, timeout=6, depth=min(self.depth, 2)
        )
        interesting = [r for r in results if any(p in r['url'] for p in [
            'admin', 'api', 'backup', 'config', 'debug', 'internal',
            'secret', '.env', '.git', 'swagger', 'graphql',
        ])]
        return {
            'agent': 'feroxbuster_discovery',
            'tool': 'fallback_python_dirb',
            'target': self.target,
            'base_url': self.base_url,
            'findings': results,
            'interesting': interesting,
            'total': len(results),
            'note': 'feroxbuster not installed. Install: https://github.com/epi052/feroxbuster/releases'
        }
