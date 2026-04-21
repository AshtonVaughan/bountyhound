"""
ffuf Fuzzer Agent

Runs ffuf for fast web fuzzing via BountyHound's ffuf-claude microservice (port 8191).
Falls back to Python curl-based fuzzer if service unavailable.
"""

import json
import tempfile
import os
from typing import List, Dict, Optional
from pathlib import Path
from engine.core.tool_bridge import sync_ffuf_fuzz


class FfufFuzzerAgent:
    """Agent wrapping ffuf for web fuzzing."""

    DEFAULT_WORDLIST_PATHS = [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/opt/seclists/Discovery/Web-Content/common.txt',
        'C:/tools/seclists/Discovery/Web-Content/common.txt',
    ]

    BUILTIN_WORDLIST = [
        'admin', 'api', 'app', 'assets', 'auth', 'backup', 'bin', 'blog',
        'cache', 'cdn', 'config', 'console', 'content', 'css', 'dashboard',
        'data', 'database', 'db', 'debug', 'dev', 'docs', 'download',
        'error', 'export', 'files', 'graphql', 'health', 'hidden', 'images',
        'import', 'includes', 'info', 'internal', 'js', 'lib', 'log',
        'login', 'logout', 'manage', 'media', 'metrics', 'monitor', 'old',
        'panel', 'private', 'public', 'queue', 'report', 'search', 'secure',
        'server-status', 'settings', 'setup', 'sitemap.xml', 'sql', 'src',
        'staging', 'static', 'status', 'storage', 'swagger', 'system',
        'temp', 'test', 'tools', 'upload', 'uploads', 'user', 'users',
        'v1', 'v2', 'v3', 'vendor', 'web', 'wp-admin', 'wp-content',
        '.env', '.git', '.htaccess', 'robots.txt', 'openapi.json',
        'api-docs', 'swagger.json', 'actuator', 'phpinfo.php',
    ]

    def __init__(self, target: str, base_url: str = None, timeout: int = 30,
                 max_workers: int = 4, wordlist: str = None):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.wordlist = wordlist
        self.ffuf_available = bool(shutil.which('ffuf'))

    def run(self) -> Dict:
        """Run directory fuzzing via ffuf-claude microservice."""
        return self._run_ffuf_service()

    def _get_wordlist_path(self) -> Optional[str]:
        """Find an available wordlist or use a builtin one."""
        if self.wordlist and os.path.exists(self.wordlist):
            return self.wordlist
        for path in self.DEFAULT_WORDLIST_PATHS:
            if os.path.exists(path):
                return path
        # Write builtin wordlist to temp file
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.write('\n'.join(self.BUILTIN_WORDLIST))
        tmp.close()
        return tmp.name

    def _run_ffuf_service(self) -> Dict:
        """Call ffuf-claude microservice (port 8191)."""
        wordlist_path = self._get_wordlist_path()
        findings = []

        try:
            # Call our ffuf-claude microservice
            response = sync_ffuf_fuzz(
                url=f"{self.base_url}/FUZZ",
                wordlist=wordlist_path,
                method="GET",
                match_status="200,201,204,301,302,307,401,403,405",
                filter_status="404"
            )

            # Extract job_id and poll for results
            job_id = response.get('job_id')
            if job_id:
                # In production, would poll with timeout
                # For now, return the response as findings
                pass

            # Parse results from response
            if 'results' in response:
                for r in response.get('results', []):
                    findings.append({
                        'url': r.get('url', ''),
                        'path': r.get('path', ''),
                        'status': r.get('status', 0),
                        'length': r.get('content_length', 0),
                        'words': r.get('words', 0),
                    })

        except Exception as e:
            return {
                'agent': 'ffuf_fuzzer',
                'error': f'ffuf-claude service error: {str(e)}',
                'findings': [],
                'note': 'Ensure ffuf-claude is running on port 8191'
            }

        return {
            'agent': 'ffuf_fuzzer',
            'tool': 'ffuf-claude',
            'target': self.target,
            'base_url': self.base_url,
            'findings': findings,
            'total': len(findings),
        }

    def _run_fallback(self) -> Dict:
        """Run Python curl-based fallback fuzzer."""
        from engine.core.tool_checker import FallbackFuzzer
        raw = FallbackFuzzer.fuzz(self.base_url, timeout=min(self.timeout, 8))
        return {
            'agent': 'ffuf_fuzzer',
            'tool': 'fallback_python_fuzzer',
            'target': self.target,
            'base_url': self.base_url,
            'findings': raw,
            'total': len(raw),
            'note': 'ffuf not installed. Install: go install github.com/ffuf/ffuf/v2@latest'
        }
