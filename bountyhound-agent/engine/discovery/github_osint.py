"""Search GitHub for leaked secrets, internal code, and configs related to a target."""

import os
import json
import time
from typing import List, Dict, Optional

from engine.core.http_client import HttpClient
from engine.core.evidence_vault import EvidenceVault


GITHUB_API = 'https://api.github.com'

# Search queries that commonly find leaked secrets
SECRET_SEARCH_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" AWS_SECRET',
    '"{domain}" AKIA',
    '"{domain}" authorization bearer',
    '"{domain}" jdbc:',
    '"{domain}" mongodb+srv:',
    '"{domain}" redis://',
    '"{domain}" smtp_password',
    '"{domain}" private_key',
    '"{domain}" BEGIN RSA',
    '"{domain}" .env',
    '"{domain}" webhook',
    '"{domain}" internal',
]

# File extensions most likely to contain secrets
SECRET_FILE_EXTENSIONS = [
    'env', 'yml', 'yaml', 'json', 'xml', 'properties', 'conf',
    'cfg', 'ini', 'toml', 'sh', 'bash', 'py', 'js', 'ts', 'rb',
]


class GitHubOSINT:
    """Searches GitHub for leaked secrets and internal code related to target."""

    def __init__(self, target: str):
        self.target = target
        self.vault = EvidenceVault(target)
        self._token = os.environ.get('GITHUB_TOKEN', '')
        self._headers = {'Accept': 'application/vnd.github.v3+json'}
        if self._token:
            self._headers['Authorization'] = f'token {self._token}'
        self.client = HttpClient(target=target, timeout=15, headers=self._headers)
        self._rate_limit_remaining = 30 if not self._token else 30
        self._last_request_time = 0.0
        self.findings: List[Dict] = []

    def _rate_limit_wait(self):
        """Respect GitHub rate limits (30 req/min unauthenticated, 30/min for code search)."""
        now = time.time()
        elapsed = now - self._last_request_time
        # Code search: max 10 req/min unauthenticated, 30/min with token
        min_interval = 6.0 if not self._token else 2.0
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    def _search_api(self, query: str, search_type: str = 'code') -> List[Dict]:
        """Execute a GitHub search API call."""
        self._rate_limit_wait()

        from urllib.parse import quote
        url = f"{GITHUB_API}/search/{search_type}?q={quote(query)}&per_page=30"

        resp = self.client.get(url)
        if not resp.ok:
            return []

        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return []

        return data.get('items', [])

    def search_code(self, domain: str) -> List[Dict]:
        """Search GitHub code for references to the target domain.

        Returns list of findings with url, file_path, repo, match_context.
        """
        results = []

        # Direct domain search
        items = self._search_api(f'"{domain}"')
        for item in items:
            results.append({
                'url': item.get('html_url', ''),
                'file_path': item.get('path', ''),
                'repo': item.get('repository', {}).get('full_name', ''),
                'match_context': item.get('text_matches', [{}])[0].get('fragment', '') if item.get('text_matches') else '',
                'secret_type': 'domain_reference',
                'score': item.get('score', 0),
            })

        return results

    def search_repos(self, org_name: str) -> List[Dict]:
        """Search for repositories belonging to or mentioning the organization."""
        results = []

        # Search for repos by org
        items = self._search_api(org_name, search_type='repositories')
        for item in items:
            results.append({
                'url': item.get('html_url', ''),
                'name': item.get('full_name', ''),
                'description': item.get('description', ''),
                'is_fork': item.get('fork', False),
                'stars': item.get('stargazers_count', 0),
                'language': item.get('language', ''),
                'updated_at': item.get('updated_at', ''),
            })

        return results

    def find_secrets(self, domain: str) -> List[Dict]:
        """Search GitHub for leaked secrets related to the domain.

        This is the primary method - runs multiple targeted searches.
        Returns high-value findings: leaked creds, API keys, internal URLs.
        """
        all_findings = []
        seen_urls = set()

        for query_template in SECRET_SEARCH_QUERIES:
            query = query_template.replace('{domain}', domain)
            items = self._search_api(query)

            for item in items:
                url = item.get('html_url', '')
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                file_path = item.get('path', '')
                repo = item.get('repository', {}).get('full_name', '')

                # Determine secret type from query
                secret_type = 'unknown'
                query_lower = query.lower()
                if 'password' in query_lower:
                    secret_type = 'password'
                elif 'api_key' in query_lower or 'apikey' in query_lower:
                    secret_type = 'api_key'
                elif 'secret' in query_lower:
                    secret_type = 'secret'
                elif 'token' in query_lower or 'bearer' in query_lower:
                    secret_type = 'token'
                elif 'akia' in query_lower or 'aws' in query_lower:
                    secret_type = 'aws_credential'
                elif 'jdbc' in query_lower or 'mongodb' in query_lower or 'redis' in query_lower:
                    secret_type = 'database_credential'
                elif 'private_key' in query_lower or 'rsa' in query_lower:
                    secret_type = 'private_key'
                elif 'webhook' in query_lower:
                    secret_type = 'webhook_url'
                elif '.env' in query_lower:
                    secret_type = 'env_file'
                elif 'internal' in query_lower:
                    secret_type = 'internal_reference'

                # Check file extension for higher confidence
                ext = file_path.rsplit('.', 1)[-1].lower() if '.' in file_path else ''
                is_sensitive_file = ext in SECRET_FILE_EXTENSIONS

                match_context = ''
                if item.get('text_matches'):
                    match_context = item['text_matches'][0].get('fragment', '')

                finding = {
                    'url': url,
                    'file_path': file_path,
                    'repo': repo,
                    'match_context': match_context,
                    'secret_type': secret_type,
                    'is_sensitive_file': is_sensitive_file,
                    'query_used': query,
                }
                all_findings.append(finding)

        # Save to evidence vault
        if all_findings:
            self.vault.save_raw(
                'github-osint-findings.json',
                json.dumps(all_findings, indent=2),
            )

        self.findings = all_findings
        return all_findings

    def get_high_value(self) -> List[Dict]:
        """Return only high-value findings (likely real secrets)."""
        high_value_types = {'password', 'aws_credential', 'database_credential', 'private_key', 'token'}
        return [
            f for f in self.findings
            if f['secret_type'] in high_value_types or f.get('is_sensitive_file')
        ]

    def summary(self) -> Dict:
        """Return summary of OSINT findings."""
        by_type: Dict[str, int] = {}
        for f in self.findings:
            by_type[f['secret_type']] = by_type.get(f['secret_type'], 0) + 1
        return {
            'total': len(self.findings),
            'by_type': by_type,
            'high_value': len(self.get_high_value()),
            'unique_repos': len(set(f['repo'] for f in self.findings)),
            'has_token': bool(self._token),
        }
