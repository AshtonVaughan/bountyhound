"""
DNSX Resolver Agent

Runs dnsx for fast bulk DNS resolution, subdomain brute-forcing,
wildcard detection, and subdomain takeover fingerprinting.
Falls back to Python socket-based DNS resolver if dnsx is absent.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
import tempfile
import os
from typing import List, Dict, Optional



class DNSXResolverAgent:
    """Agent wrapping dnsx for DNS operations."""

    def __init__(self, target: str, timeout: int = 60, max_workers: int = 4,
                 subdomains: List[str] = None, check_takeover: bool = True):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.subdomains = subdomains or []
        self.check_takeover = check_takeover
        self.dnsx_available = bool(shutil.which('dnsx'))

    def run(self) -> Dict:
        """Resolve subdomains and detect takeover opportunities."""
        if self.dnsx_available:
            return self._run_dnsx()
        return self._run_fallback()

    def _run_dnsx(self) -> Dict:
        """Run dnsx for bulk DNS resolution."""
        if not self.subdomains:
            return {
                'agent': 'dnsx_resolver',
                'tool': 'dnsx',
                'target': self.target,
                'findings': [],
                'note': 'No subdomains provided. Run subfinder first.'
            }

        # Write subdomains to temp file
        input_file = tempfile.mktemp(suffix='.txt')
        output_file = tempfile.mktemp(suffix='.json')

        with open(input_file, 'w') as f:
            f.write('\n'.join(self.subdomains))

        cmd = [
            'dnsx',
            '-l', input_file,
            '-resp',         # Show DNS response
            '-a', '-aaaa', '-cname', '-mx', '-ns',  # Record types
            '-json',
            '-o', output_file,
            '-t', str(min(self.max_workers * 25, 100)),
            '-silent',
        ]

        resolved = []
        cnames = []
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
                            host = entry.get('host', '')
                            if host:
                                resolved.append({
                                    'host': host,
                                    'a': entry.get('a', []),
                                    'cname': entry.get('cname', []),
                                    'status_code': entry.get('status_code', ''),
                                })
                                # Collect CNAMEs for takeover check
                                for cname in entry.get('cname', []):
                                    cnames.append((host, cname))
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            return {'agent': 'dnsx_resolver', 'error': str(e), 'findings': []}
        finally:
            for f in [input_file, output_file]:
                try:
                    os.unlink(f)
                except Exception:
                    pass

        # Check for takeover fingerprints on CNAME chains
        if self.check_takeover:
            from engine.core.tool_checker import FallbackDNSResolver
            for host, cname in cnames[:20]:
                result = FallbackDNSResolver.check_takeover(host, timeout=10)
                if result:
                    result['cname'] = cname
                    findings.append(result)

        return {
            'agent': 'dnsx_resolver',
            'tool': 'dnsx',
            'target': self.target,
            'resolved': resolved,
            'total_resolved': len(resolved),
            'cnames': cnames,
            'findings': findings,
            'takeover_candidates': len(findings),
        }

    def _run_fallback(self) -> Dict:
        """Run Python socket-based DNS resolver."""
        from engine.core.tool_checker import FallbackDNSResolver

        if not self.subdomains:
            return {
                'agent': 'dnsx_resolver',
                'tool': 'fallback_python_dns',
                'target': self.target,
                'findings': [],
                'note': 'No subdomains provided. Run subfinder first.'
            }

        resolved_map = FallbackDNSResolver.resolve_bulk(self.subdomains, timeout=2.0)
        resolved = [
            {'host': h, 'ip': ip} for h, ip in resolved_map.items() if ip
        ]

        findings = []
        if self.check_takeover:
            dead = [h for h, ip in resolved_map.items() if not ip]
            for host in dead[:10]:
                result = FallbackDNSResolver.check_takeover(host, timeout=8)
                if result:
                    findings.append(result)

        return {
            'agent': 'dnsx_resolver',
            'tool': 'fallback_python_dns',
            'target': self.target,
            'resolved': resolved,
            'total_resolved': len(resolved),
            'unresolved': [h for h, ip in resolved_map.items() if not ip],
            'findings': findings,
            'takeover_candidates': len(findings),
            'note': 'dnsx not installed. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
        }
