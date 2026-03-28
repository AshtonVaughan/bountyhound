"""Brute-force directory and file discovery with smart wordlists."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from dataclasses import dataclass

from engine.core.http_client import HttpClient
from engine.core.recon_cache import ReconCache
from engine.core.payload_tracker import PayloadTracker


@dataclass
class DiscoveredPath:
    """A discovered path on the target."""
    url: str
    status_code: int
    content_length: int = 0
    redirect_url: str = ''
    category: str = ''  # 'admin', 'api', 'config', 'backup', 'debug', etc.

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'status_code': self.status_code,
            'content_length': self.content_length,
            'redirect_url': self.redirect_url,
            'category': self.category,
        }


# High-value paths organized by category
COMMON_WORDLIST = {
    'admin': [
        '/admin', '/admin/', '/administrator', '/admin/login', '/admin/dashboard',
        '/wp-admin', '/wp-login.php', '/manager', '/cpanel', '/panel',
        '/admin/config', '/admin/settings', '/dashboard', '/console',
    ],
    'api': [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/api/docs', '/api/swagger',
        '/graphql', '/graphiql', '/api/graphql', '/playground',
        '/api/health', '/api/status', '/api/info', '/api/debug',
        '/rest', '/v1', '/v2', '/v3',
    ],
    'config': [
        '/.env', '/.env.bak', '/.env.local', '/.env.production', '/.env.development',
        '/config.json', '/config.yml', '/config.yaml', '/config.xml',
        '/settings.json', '/application.yml', '/application.properties',
        '/web.config', '/appsettings.json', '/.htaccess', '/nginx.conf',
    ],
    'backup': [
        '/backup', '/backup.sql', '/backup.zip', '/backup.tar.gz',
        '/db.sql', '/database.sql', '/dump.sql',
        '/site.zip', '/www.zip', '/web.zip', '/archive.zip',
        '/.git', '/.git/config', '/.git/HEAD', '/.svn', '/.svn/entries',
        '/.DS_Store', '/Thumbs.db',
    ],
    'debug': [
        '/debug', '/debug/', '/trace', '/test', '/testing',
        '/phpinfo.php', '/info.php', '/server-info', '/server-status',
        '/_debug', '/_profiler', '/elmah.axd', '/actuator', '/actuator/health',
        '/actuator/env', '/metrics', '/health', '/healthcheck',
    ],
    'docs': [
        '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
        '/openapi', '/openapi.json', '/openapi.yaml', '/api-docs',
        '/redoc', '/docs', '/documentation', '/apidoc',
    ],
    'auth': [
        '/login', '/signin', '/signup', '/register', '/forgot-password',
        '/reset-password', '/oauth', '/oauth/authorize', '/oauth/token',
        '/auth', '/auth/login', '/sso', '/saml', '/.well-known/openid-configuration',
    ],
    'cloud': [
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/favicon.ico', '/humans.txt', '/security.txt', '/.well-known/security.txt',
    ],
}

CMS_WORDLIST = {
    'wordpress': [
        '/wp-content/', '/wp-includes/', '/wp-json/', '/wp-json/wp/v2/users',
        '/xmlrpc.php', '/readme.html', '/license.txt',
    ],
    'drupal': [
        '/CHANGELOG.txt', '/core/CHANGELOG.txt', '/user/login',
        '/admin/content', '/node', '/jsonapi',
    ],
    'joomla': [
        '/administrator/', '/configuration.php', '/htaccess.txt',
        '/language/', '/libraries/',
    ],
}

CLOUD_WORDLIST = {
    'aws': [
        '/.aws/credentials', '/.aws/config',
        '/latest/meta-data/', '/latest/user-data/',
    ],
    'azure': [
        '/.azure/', '/metadata/instance',
    ],
    'gcp': [
        '/computeMetadata/v1/',
    ],
}

# Status codes that indicate interesting content
INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403, 405}


class ContentDiscovery:
    """Brute-force directory/file discovery with smart wordlists."""

    def __init__(self, target: str, max_workers: int = 10):
        self.target = target
        self.client = HttpClient(target=target, timeout=10)
        self.cache = ReconCache(target)
        self.tracker = PayloadTracker(target)
        self.max_workers = max_workers
        self.results: List[DiscoveredPath] = []

    def _check_path(self, base_url: str, path: str, category: str) -> Optional[DiscoveredPath]:
        """Check a single path and return DiscoveredPath if interesting."""
        url = base_url.rstrip('/') + path

        # Skip if already tested
        if self.tracker.was_tried(url, 'content_discovery'):
            return None

        try:
            resp = self.client.get(url)
            self.tracker.record_attempt(
                endpoint=url,
                payload=path,
                vuln_type='content_discovery',
                status_code=resp.status_code,
                response_snippet=resp.body[:200] if resp.body else '',
                success=resp.status_code in INTERESTING_CODES,
            )

            if resp.status_code in INTERESTING_CODES:
                return DiscoveredPath(
                    url=url,
                    status_code=resp.status_code,
                    content_length=len(resp.body) if resp.body else 0,
                    category=category,
                )
        except Exception:
            pass

        return None

    def discover(self, base_url: str, wordlist: str = 'common') -> List[DiscoveredPath]:
        """Run content discovery with a built-in wordlist.

        Args:
            base_url: Target base URL (e.g. 'https://example.com')
            wordlist: One of 'common', 'cms', 'cloud', or 'all'
        """
        paths_to_check: List[tuple] = []  # (path, category)

        if wordlist in ('common', 'all'):
            for category, paths in COMMON_WORDLIST.items():
                for path in paths:
                    paths_to_check.append((path, category))

        if wordlist in ('cms', 'all'):
            for category, paths in CMS_WORDLIST.items():
                for path in paths:
                    paths_to_check.append((path, f'cms_{category}'))

        if wordlist in ('cloud', 'all'):
            for category, paths in CLOUD_WORDLIST.items():
                for path in paths:
                    paths_to_check.append((path, f'cloud_{category}'))

        return self._run_checks(base_url, paths_to_check)

    def discover_custom(self, base_url: str, words: List[str], category: str = 'custom') -> List[DiscoveredPath]:
        """Run content discovery with a custom word list."""
        paths_to_check = [(w if w.startswith('/') else '/' + w, category) for w in words]
        return self._run_checks(base_url, paths_to_check)

    def _run_checks(self, base_url: str, paths_to_check: List[tuple]) -> List[DiscoveredPath]:
        """Run path checks concurrently."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_path, base_url, path, category): (path, category)
                for path, category in paths_to_check
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

        # Store in cache
        for r in results:
            self.cache.store('discovered_path', r.url, source='content_discovery')

        self.results.extend(results)
        return results

    def get_by_category(self, category: str) -> List[DiscoveredPath]:
        """Filter results by category."""
        return [r for r in self.results if r.category == category]

    def get_by_status(self, status_code: int) -> List[DiscoveredPath]:
        """Filter results by status code."""
        return [r for r in self.results if r.status_code == status_code]

    def get_accessible(self) -> List[DiscoveredPath]:
        """Return only directly accessible paths (200)."""
        return self.get_by_status(200)

    def get_forbidden(self) -> List[DiscoveredPath]:
        """Return forbidden paths (403) - may be accessible via bypass."""
        return self.get_by_status(403)

    def summary(self) -> Dict:
        """Return summary of discovery results."""
        by_status: Dict[int, int] = {}
        by_category: Dict[str, int] = {}
        for r in self.results:
            by_status[r.status_code] = by_status.get(r.status_code, 0) + 1
            by_category[r.category] = by_category.get(r.category, 0) + 1
        return {
            'total': len(self.results),
            'by_status': by_status,
            'by_category': by_category,
            'accessible': len(self.get_accessible()),
            'forbidden': len(self.get_forbidden()),
        }
