"""
TruffleHog Secrets Scanner Agent

Scans JavaScript files, git repositories, and HTTP responses for leaked
secrets: API keys, tokens, credentials, private keys, database URIs.
Falls back to Python regex-based secret scanner if trufflehog is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import tempfile
import os
from typing import List, Dict, Optional



class TrufflehogSecretsAgent:
    """Agent wrapping trufflehog for secret detection."""

    def __init__(self, target: str, base_url: str = None, timeout: int = 120,
                 max_workers: int = 4, js_urls: List[str] = None,
                 git_url: str = None):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.js_urls = js_urls or []
        self.git_url = git_url  # e.g. https://github.com/org/repo
        self.trufflehog_available = bool(shutil.which('trufflehog'))

    def run(self) -> Dict:
        """Scan for secrets in JS files and git repos."""
        if self.trufflehog_available:
            return self._run_trufflehog()
        return self._run_fallback()

    def _run_trufflehog(self) -> Dict:
        """Run trufflehog against git repo or filesystem."""
        all_findings = []

        # Scan git repo if provided
        if self.git_url:
            findings = self._scan_git(self.git_url)
            all_findings.extend(findings)

        # Scan filesystem for downloaded JS files
        if self.js_urls:
            findings = self._scan_js_files_via_filesystem()
            all_findings.extend(findings)

        if not self.git_url and not self.js_urls:
            # Try to find git repo URL from target
            potential_git = f'https://github.com/{self.target}'
            findings = self._scan_git(potential_git)
            all_findings.extend(findings)

        return {
            'agent': 'trufflehog_secrets',
            'tool': 'trufflehog',
            'target': self.target,
            'findings': all_findings,
            'total_secrets': len(all_findings),
            'severity': 'CRITICAL' if all_findings else 'INFO',
        }

    def _scan_git(self, git_url: str) -> List[Dict]:
        """Scan a git repository for secrets."""
        findings = []
        cmd = [
            'trufflehog', 'git', git_url,
            '--json',
            '--no-update',
            '--concurrency', str(min(self.max_workers, 4)),
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout
            )
            for line in result.stdout.splitlines():
                try:
                    entry = json.loads(line)
                    findings.append({
                        'source': 'git',
                        'repository': git_url,
                        'detector': entry.get('DetectorName', 'unknown'),
                        'verified': entry.get('Verified', False),
                        'raw': entry.get('Raw', '')[:100],
                        'file': entry.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', ''),
                        'commit': entry.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit', ''),
                        'severity': 'CRITICAL' if entry.get('Verified') else 'HIGH',
                    })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return findings

    def _scan_js_files_via_filesystem(self) -> List[Dict]:
        """Download JS files and scan with trufflehog filesystem mode."""
        findings = []
        tmpdir = tempfile.mkdtemp()

        try:
            for i, url in enumerate(self.js_urls[:20]):
                js_file = os.path.join(tmpdir, f'file_{i}.js')
                try:
                    subprocess.run(
                        ['curl', '-s', '-L', '-m', '15', '-o', js_file, url],
                        capture_output=True, timeout=20
                    )
                except Exception:
                    continue

            if os.listdir(tmpdir):
                cmd = [
                    'trufflehog', 'filesystem', tmpdir,
                    '--json', '--no-update',
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.timeout
                )
                for line in result.stdout.splitlines():
                    try:
                        entry = json.loads(line)
                        findings.append({
                            'source': 'js_file',
                            'detector': entry.get('DetectorName', 'unknown'),
                            'verified': entry.get('Verified', False),
                            'raw': entry.get('Raw', '')[:100],
                            'severity': 'CRITICAL' if entry.get('Verified') else 'HIGH',
                        })
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        finally:
            import shutil as _shutil
            _shutil.rmtree(tmpdir, ignore_errors=True)

        return findings

    def _run_fallback(self) -> Dict:
        """Run Python regex-based secret scanner."""
        from engine.core.tool_checker import FallbackSecretScanner
        all_findings = []

        # Scan main page + JS files
        all_findings.extend(FallbackSecretScanner.scan_url(self.base_url, timeout=15))
        all_findings.extend(FallbackSecretScanner.scan_js_files(self.base_url, timeout=10))

        # Scan provided JS URLs
        for url in self.js_urls[:10]:
            all_findings.extend(FallbackSecretScanner.scan_url(url, timeout=10))

        # Deduplicate by match value
        seen = set()
        unique = []
        for f in all_findings:
            key = f.get('match', '')
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return {
            'agent': 'trufflehog_secrets',
            'tool': 'fallback_python_regex',
            'target': self.target,
            'findings': unique,
            'total_secrets': len(unique),
            'severity': 'CRITICAL' if unique else 'INFO',
            'note': 'trufflehog not installed. Install: https://github.com/trufflesecurity/trufflehog/releases'
        }
