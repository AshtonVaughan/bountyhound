"""
Dalfox XSS Scanner Agent

Runs dalfox for context-aware XSS scanning with blind XSS support.
Falls back to Python reflection-based XSS payload tester if dalfox is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import tempfile
import os
from typing import List, Dict, Optional



class DalfoxXSSAgent:
    """Agent wrapping dalfox for XSS vulnerability scanning."""

    def __init__(self, target: str, base_url: str = None, timeout: int = 60,
                 max_workers: int = 4, urls: List[str] = None,
                 blind_callback: str = None):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.urls = urls or [self.base_url]
        self.blind_callback = blind_callback  # OOB URL for blind XSS
        self.dalfox_available = bool(shutil.which('dalfox'))

    def run(self) -> Dict:
        """Run XSS scanning against target URLs."""
        if self.dalfox_available:
            return self._run_dalfox()
        return self._run_fallback()

    def _run_dalfox(self) -> Dict:
        """Run dalfox XSS scanner."""
        all_findings = []

        for url in self.urls[:20]:  # Cap at 20 URLs
            output_file = tempfile.mktemp(suffix='.json')
            cmd = [
                'dalfox', 'url', url,
                '--output', output_file,
                '--format', 'json',
                '--timeout', str(min(self.timeout, 30)),
                '--worker', str(min(self.max_workers * 5, 20)),
                '--silence',
                '--no-color',
            ]
            if self.blind_callback:
                cmd.extend(['--blind', self.blind_callback])

            try:
                subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.timeout
                )
                if os.path.exists(output_file):
                    with open(output_file) as f:
                        content = f.read().strip()
                    if content:
                        # Dalfox outputs one JSON object per line
                        for line in content.splitlines():
                            try:
                                entry = json.loads(line)
                                if entry.get('type') in ('V', 'G'):  # Vuln or GreatVuln
                                    all_findings.append({
                                        'url': entry.get('data', url),
                                        'payload': entry.get('payload', ''),
                                        'param': entry.get('param', ''),
                                        'severity': 'HIGH' if entry.get('type') == 'G' else 'MEDIUM',
                                        'evidence': entry.get('evidence', ''),
                                        'type': 'XSS',
                                    })
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue
            finally:
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

        return {
            'agent': 'dalfox_xss',
            'tool': 'dalfox',
            'target': self.target,
            'urls_tested': len(self.urls[:20]),
            'findings': all_findings,
            'total_findings': len(all_findings),
        }

    def _run_fallback(self) -> Dict:
        """Run Python reflection-based XSS tester."""
        from engine.core.tool_checker import FallbackXSSScanner
        all_findings = []

        for url in self.urls[:10]:
            results = FallbackXSSScanner.scan(url, timeout=8)
            all_findings.extend(results)

        return {
            'agent': 'dalfox_xss',
            'tool': 'fallback_python_xss',
            'target': self.target,
            'urls_tested': len(self.urls[:10]),
            'findings': all_findings,
            'total_findings': len(all_findings),
            'note': 'dalfox not installed. Install: go install github.com/hahwul/dalfox/v2@latest'
        }
