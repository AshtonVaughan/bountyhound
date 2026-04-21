"""
Arjun Parameter Discovery Agent

Runs arjun to discover hidden HTTP parameters in GET/POST endpoints.
Falls back to Python common parameter wordlist tester if arjun is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import tempfile
import os
from typing import List, Dict, Optional



class ArjunParamsAgent:
    """Agent wrapping arjun for HTTP parameter discovery."""

    def __init__(self, target: str, base_url: str = None, timeout: int = 60,
                 max_workers: int = 4, endpoints: List[str] = None):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.endpoints = endpoints or [self.base_url]
        self.arjun_available = bool(shutil.which('arjun'))

    def run(self) -> Dict:
        """Discover hidden parameters across target endpoints."""
        if self.arjun_available:
            return self._run_arjun()
        return self._run_fallback()

    def _run_arjun(self) -> Dict:
        """Run arjun parameter discovery."""
        output_file = tempfile.mktemp(suffix='.json')
        all_findings = []

        for endpoint in self.endpoints[:10]:  # Cap at 10 endpoints
            cmd = [
                'arjun',
                '-u', endpoint,
                '--output-file', output_file,
                '-t', str(min(self.max_workers * 5, 20)),
                '--timeout', str(min(self.timeout, 30)),
                '-q',  # Quiet
            ]
            try:
                subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.timeout
                )
                if os.path.exists(output_file):
                    with open(output_file) as f:
                        data = json.load(f)
                    for url, params in data.items():
                        for param in (params if isinstance(params, list) else []):
                            all_findings.append({
                                'url': url,
                                'parameter': param,
                                'type': 'hidden_parameter',
                                'severity': 'MEDIUM',
                                'note': 'Hidden parameter discovered - test for IDOR, injection, mass assignment'
                            })
            except Exception:
                continue
            finally:
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

        return {
            'agent': 'arjun_params',
            'tool': 'arjun',
            'target': self.target,
            'endpoints_tested': len(self.endpoints[:10]),
            'findings': all_findings,
            'total_params': len(all_findings),
        }

    def _run_fallback(self) -> Dict:
        """Run Python parameter wordlist tester."""
        from engine.core.tool_checker import FallbackParamMiner
        all_findings = []

        for endpoint in self.endpoints[:5]:
            params = FallbackParamMiner.discover(endpoint, timeout=8)
            for param in params:
                all_findings.append({
                    'url': endpoint,
                    'parameter': param,
                    'type': 'hidden_parameter',
                    'severity': 'MEDIUM',
                    'note': 'Response size change detected - parameter may be active'
                })

        return {
            'agent': 'arjun_params',
            'tool': 'fallback_python_param_miner',
            'target': self.target,
            'endpoints_tested': len(self.endpoints[:5]),
            'findings': all_findings,
            'total_params': len(all_findings),
            'note': 'arjun not installed. Install: pip install arjun'
        }
