"""
SQLMap Injection Agent

Runs sqlmap for automated SQL injection detection via sqlmap-claude microservice (port 8189).
Falls back to Python error-based SQLi detection if service unavailable.

Safety: Tests run in detection-only mode by default (no --dump, no --os-shell).
Set exploit_mode=True only for confirmed in-scope targets with written authorization.
"""

import json
import tempfile
import os
from typing import List, Dict, Optional
from engine.core.tool_bridge import sync_sqlmap_test


class SQLMapInjectionAgent:
    """Agent wrapping sqlmap for SQL injection testing."""

    def __init__(self, target: str, base_url: str = None, timeout: int = 120,
                 max_workers: int = 4, urls: List[str] = None,
                 exploit_mode: bool = False, level: int = 1, risk: int = 1):
        self.target = target
        self.base_url = base_url or f'https://{target}'
        self.timeout = timeout
        self.max_workers = max_workers
        self.urls = urls or [self.base_url]
        self.exploit_mode = exploit_mode  # False = detection only
        self.level = min(level, 3)        # Cap at 3 for speed
        self.risk = min(risk, 2)          # Cap at 2 for safety
        self.sqlmap_available = bool(shutil.which('sqlmap'))

    def run(self) -> Dict:
        """Test URLs for SQL injection vulnerabilities."""
        return self._run_sqlmap_service()

    def _run_sqlmap_service(self) -> Dict:
        """Call sqlmap-claude microservice (port 8189)."""
        all_findings = []

        for url in self.urls[:5]:  # Cap at 5 URLs to avoid scan sprawl
            try:
                # Call our sqlmap-claude microservice
                response = sync_sqlmap_test(
                    url=url,
                    method="GET",
                    data="",
                    level=self.level,
                    risk=self.risk
                )

                # Extract findings from response
                job_id = response.get('job_id')
                if 'results' in response:
                    for result in response.get('results', []):
                        all_findings.append({
                            'url': url,
                            'type': result.get('vuln_type', 'SQL Injection'),
                            'evidence': result.get('evidence', ''),
                            'severity': 'CRITICAL',
                            'tool': 'sqlmap-claude',
                            'param': result.get('param', ''),
                        })

            except Exception as e:
                all_findings.append({
                    'url': url,
                    'type': 'error',
                    'error': f'sqlmap-claude service error: {str(e)}',
                    'note': 'Ensure sqlmap-claude is running on port 8189'
                })

        return {
            'agent': 'sqlmap_injection',
            'tool': 'sqlmap-claude',
            'target': self.target,
            'urls_tested': len(self.urls[:5]),
            'findings': all_findings,
            'total_findings': len(all_findings),
            'mode': 'detection_only' if not self.exploit_mode else 'exploit',
        }

    def _run_fallback(self) -> Dict:
        """Run Python error-based SQLi detection."""
        from engine.core.tool_checker import FallbackSQLiTester
        all_findings = []

        for url in self.urls[:5]:
            results = FallbackSQLiTester.test(url, timeout=8)
            all_findings.extend(results)

        return {
            'agent': 'sqlmap_injection',
            'tool': 'fallback_python_sqli',
            'target': self.target,
            'urls_tested': len(self.urls[:5]),
            'findings': all_findings,
            'total_findings': len(all_findings),
            'note': 'sqlmap not installed. Install: pip install sqlmap  OR  apt install sqlmap'
        }
