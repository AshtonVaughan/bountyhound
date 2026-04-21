"""Mine Wayback Machine for historical endpoints, old APIs, and removed pages."""

import json
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from engine.core.http_client import HttpClient
from engine.core.recon_cache import ReconCache


CDX_API = 'https://web.archive.org/cdx/search/cdx'

# Patterns that indicate high-value archived content
INTERESTING_PATTERNS = {
    'api': ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql'],
    'admin': ['/admin', '/dashboard', '/manager', '/panel', '/console'],
    'config': ['.env', 'config.', 'settings.', '.yml', '.yaml', '.xml', '.json', '.properties'],
    'backup': ['.bak', '.old', '.backup', '.sql', '.dump', '.zip', '.tar', '.gz'],
    'auth': ['/login', '/auth', '/oauth', '/token', '/session', '/signup', '/register'],
    'debug': ['/debug', '/trace', '/test', '/phpinfo', '/status', '/health', '/actuator'],
    'docs': ['/swagger', '/openapi', '/api-docs', '/apidoc', '/redoc'],
    'upload': ['/upload', '/file', '/media', '/attachment', '/document'],
}


class WaybackMiner:
    """Mines Wayback Machine CDX API for historical endpoints and changes."""

    def __init__(self, target: str):
        self.target = target
        self.client = HttpClient(target=target, timeout=30)
        self.cache = ReconCache(target)
        self._urls: Optional[List[Dict]] = None

    def get_urls(self, domain: str, limit: int = 5000) -> List[Dict]:
        """Fetch archived URLs from the Wayback Machine CDX API.

        Returns list of dicts with keys: url, status, mimetype
        """
        if self._urls is not None:
            return self._urls

        params = (
            f'?url=*.{domain}/*'
            f'&output=json'
            f'&fl=original,statuscode,mimetype'
            f'&collapse=urlkey'
            f'&limit={limit}'
        )
        url = CDX_API + params

        resp = self.client.get(url)
        if not resp.ok:
            self._urls = []
            return []

        try:
            rows = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            self._urls = []
            return []

        # First row is header
        if not rows or len(rows) < 2:
            self._urls = []
            return []

        results = []
        seen: Set[str] = set()
        for row in rows[1:]:
            if len(row) < 3:
                continue
            original, status, mimetype = row[0], row[1], row[2]
            # Deduplicate by URL path (ignore query variations)
            parsed = urlparse(original)
            key = parsed.path.lower()
            if key in seen:
                continue
            seen.add(key)
            results.append({
                'url': original,
                'status': status,
                'mimetype': mimetype,
            })

        self._urls = results
        return results

    def find_interesting(self, domain: str) -> Dict[str, List[Dict]]:
        """Find interesting archived URLs categorized by type.

        Returns dict mapping category to list of URL records.
        """
        urls = self.get_urls(domain)
        categorized: Dict[str, List[Dict]] = {cat: [] for cat in INTERESTING_PATTERNS}

        for record in urls:
            url_lower = record['url'].lower()
            for category, patterns in INTERESTING_PATTERNS.items():
                if any(p in url_lower for p in patterns):
                    categorized[category].append(record)
                    break  # Only categorize once

        # Cache interesting findings
        for category, records in categorized.items():
            for r in records:
                self.cache.store(
                    f'wayback_{category}',
                    r['url'],
                    source='wayback',
                    ttl_days=14,
                )

        return categorized

    def find_removed_endpoints(self, domain: str) -> List[Dict]:
        """Find URLs that existed historically but are now gone (404/403).

        These are high-value targets: they existed once, so the code may still
        be deployed or partially accessible.
        """
        urls = self.get_urls(domain)

        # Find URLs that had 200 in Wayback
        previously_live = [
            r for r in urls
            if r['status'] == '200'
            and not any(ext in r['url'].lower() for ext in ['.png', '.jpg', '.gif', '.css', '.ico', '.woff', '.svg'])
        ]

        removed = []
        for record in previously_live[:100]:  # Cap at 100 checks
            current_status = self.client.get_status_code(record['url'])
            if current_status in (404, 403, 410):
                removed.append({
                    'url': record['url'],
                    'historical_status': record['status'],
                    'current_status': current_status,
                    'mimetype': record['mimetype'],
                })

        # Cache removed endpoints
        for r in removed:
            self.cache.store('wayback_removed', r['url'], source='wayback', ttl_days=14)

        return removed

    def find_api_versions(self, domain: str) -> List[str]:
        """Find all API version prefixes that existed historically."""
        urls = self.get_urls(domain)
        import re
        version_pattern = re.compile(r'/(?:api/)?v(\d+)/')
        versions: Set[str] = set()
        for record in urls:
            match = version_pattern.search(record['url'])
            if match:
                versions.add(f'v{match.group(1)}')
        return sorted(versions)

    def summary(self) -> Dict:
        """Return summary of mined data."""
        urls = self._urls or []
        by_status: Dict[str, int] = {}
        by_mimetype: Dict[str, int] = {}
        for r in urls:
            by_status[r['status']] = by_status.get(r['status'], 0) + 1
            mt = r['mimetype'].split(';')[0].strip() if r['mimetype'] else 'unknown'
            by_mimetype[mt] = by_mimetype.get(mt, 0) + 1
        return {
            'total_urls': len(urls),
            'by_status': by_status,
            'by_mimetype': dict(sorted(by_mimetype.items(), key=lambda x: -x[1])[:10]),
        }
