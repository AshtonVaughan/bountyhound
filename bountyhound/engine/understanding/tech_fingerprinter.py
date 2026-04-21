"""Identifies technologies, frameworks, versions, and WAFs from HTTP responses."""

import re
import json
from typing import Dict, List, Optional, Any

from engine.core.http_client import HttpClient


# Cookie name → technology mapping
COOKIE_FINGERPRINTS = {
    'PHPSESSID': ('PHP', 'language'),
    'JSESSIONID': ('Java', 'language'),
    'ASP.NET_SessionId': ('.NET', 'framework'),
    'ASPSESSIONID': ('ASP Classic', 'framework'),
    'csrftoken': ('Django', 'framework'),
    'django_language': ('Django', 'framework'),
    '_rails_session': ('Ruby on Rails', 'framework'),
    '_session_id': ('Ruby on Rails', 'framework'),
    'laravel_session': ('Laravel', 'framework'),
    'XSRF-TOKEN': ('Angular/Laravel', 'framework'),
    'ci_session': ('CodeIgniter', 'framework'),
    'CakeCookie': ('CakePHP', 'framework'),
    'symfony': ('Symfony', 'framework'),
    'express:sess': ('Express.js', 'framework'),
    'connect.sid': ('Express.js/Node.js', 'framework'),
    '_next': ('Next.js', 'framework'),
    'wp-settings': ('WordPress', 'cms'),
    'wordpress_logged_in': ('WordPress', 'cms'),
    'Drupal.visitor': ('Drupal', 'cms'),
    'joomla': ('Joomla', 'cms'),
}

# Header name → technology mapping
HEADER_FINGERPRINTS = {
    'X-Powered-By': {
        'PHP': ('PHP', 'language'),
        'ASP.NET': ('.NET', 'framework'),
        'Express': ('Express.js', 'framework'),
        'Next.js': ('Next.js', 'framework'),
        'Nuxt': ('Nuxt.js', 'framework'),
        'Kestrel': ('.NET Core', 'framework'),
        'JSP': ('Java JSP', 'framework'),
        'Servlet': ('Java Servlet', 'framework'),
    },
    'Server': {
        'Apache': ('Apache', 'server'),
        'nginx': ('Nginx', 'server'),
        'Microsoft-IIS': ('IIS', 'server'),
        'LiteSpeed': ('LiteSpeed', 'server'),
        'Caddy': ('Caddy', 'server'),
        'Tomcat': ('Apache Tomcat', 'server'),
        'Jetty': ('Jetty', 'server'),
        'gunicorn': ('Gunicorn/Python', 'server'),
        'uvicorn': ('Uvicorn/Python', 'server'),
        'Cowboy': ('Cowboy/Erlang', 'server'),
        'openresty': ('OpenResty', 'server'),
        'cloudflare': ('Cloudflare', 'cdn'),
        'AmazonS3': ('Amazon S3', 'cloud'),
        'gws': ('Google Web Server', 'server'),
    },
}

# WAF detection signatures
WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
        'server': ['cloudflare'],
        'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
    },
    'AWS WAF': {
        'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
        'server': ['awselb', 'amazons3'],
        'error_patterns': ['403 ERROR', 'Request blocked'],
    },
    'Akamai': {
        'headers': ['x-akamai-transformed', 'akamai-grn', 'x-akamai-session-info'],
        'server': ['akamaighost', 'akamai'],
        'cookies': ['ak_bmsc', 'bm_sv'],
    },
    'Imperva/Incapsula': {
        'headers': ['x-iinfo', 'x-cdn'],
        'cookies': ['incap_ses', 'visid_incap', 'nlbi_'],
        'error_patterns': ['Incapsula incident', 'powered by Incapsula'],
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'server': ['sucuri'],
    },
    'F5 BIG-IP': {
        'cookies': ['BIGipServer', 'TS'],
        'headers': ['x-wa-info'],
        'server': ['bigip'],
    },
    'ModSecurity': {
        'headers': ['mod_security', 'modsecurity'],
        'server': ['mod_security'],
        'error_patterns': ['ModSecurity', 'mod_security'],
    },
    'Barracuda': {
        'cookies': ['barra_counter_session'],
        'headers': ['bnmsg'],
    },
    'Fastly': {
        'headers': ['x-served-by', 'x-cache', 'x-cache-hits', 'x-timer', 'fastly-restarts'],
        'server': ['fastly'],
    },
    'Varnish': {
        'headers': ['x-varnish', 'via'],
        'server': ['varnish'],
    },
}

# HTML patterns for framework detection
HTML_PATTERNS = [
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.I), 'generator'),
    (re.compile(r'wp-content/', re.I), 'WordPress'),
    (re.compile(r'sites/default/files', re.I), 'Drupal'),
    (re.compile(r'__next', re.I), 'Next.js'),
    (re.compile(r'__nuxt', re.I), 'Nuxt.js'),
    (re.compile(r'ng-version', re.I), 'Angular'),
    (re.compile(r'data-reactroot', re.I), 'React'),
    (re.compile(r'data-react-helmet', re.I), 'React'),
    (re.compile(r'<div id="app"', re.I), 'Vue.js'),
    (re.compile(r'ember-view', re.I), 'Ember.js'),
    (re.compile(r'data-turbo', re.I), 'Hotwire/Rails'),
    (re.compile(r'data-controller', re.I), 'Stimulus/Rails'),
    (re.compile(r'_gatsby', re.I), 'Gatsby'),
    (re.compile(r'data-svelte', re.I), 'Svelte'),
]


class TechFingerprinter:
    """Identifies technologies, frameworks, versions, and WAFs from HTTP responses."""

    def __init__(self, target: str):
        self.target = target
        self.client = HttpClient(target=target, timeout=10)
        self.result: Dict[str, Any] = {
            'server': '',
            'framework': '',
            'language': '',
            'cms': '',
            'waf': [],
            'cdn': '',
            'frontend': [],
            'versions': {},
            'all_technologies': [],
        }

    def fingerprint(self, url: str) -> Dict[str, Any]:
        """Run all fingerprinting checks on a URL and return results."""
        resp = self.client.get(url)
        if not resp.ok and resp.status_code not in (403, 401):
            return self.result

        # Parse response headers
        raw_headers = {}
        # HttpClient returns body only; make a HEAD request too
        head_resp = self.client.head(url)

        # Analyze headers from body response
        self._identify_server(resp)
        self._identify_framework(resp)
        self._identify_waf(resp)
        self._identify_from_cookies(resp)
        self._identify_from_html(resp.body)

        return self.result

    def _parse_headers(self, resp) -> Dict[str, str]:
        """Extract headers from response (stored in body for curl-based client)."""
        # The HttpClient uses curl, headers may be available via different means
        # For now, return what we can extract from the response
        return {}

    def _identify_server(self, resp) -> str:
        """Identify server technology from response."""
        body_lower = resp.body.lower() if resp.body else ''

        # Check Server header patterns in the response
        for keyword, (tech, category) in HEADER_FINGERPRINTS.get('Server', {}).items():
            if keyword.lower() in body_lower:
                self.result['server'] = tech
                self._add_tech(tech, category)

                # Try to extract version
                version_pattern = re.compile(rf'{re.escape(keyword)}[/\s]+([\d.]+)', re.I)
                match = version_pattern.search(resp.body or '')
                if match:
                    self.result['versions'][tech] = match.group(1)

                return tech

        return ''

    def _identify_framework(self, resp) -> str:
        """Identify framework from response headers and patterns."""
        body = resp.body or ''

        # Check X-Powered-By patterns
        for keyword, (tech, category) in HEADER_FINGERPRINTS.get('X-Powered-By', {}).items():
            if keyword.lower() in body.lower():
                self.result['framework'] = tech
                self._add_tech(tech, category)

                # Try version extraction
                version_match = re.search(rf'{re.escape(keyword)}[/\s]+([\d.]+)', body, re.I)
                if version_match:
                    self.result['versions'][tech] = version_match.group(1)

                return tech

        # Check specific framework headers
        framework_headers = {
            'X-AspNet-Version': ('.NET', 'framework'),
            'X-AspNetMvc-Version': ('ASP.NET MVC', 'framework'),
            'X-Generator': (None, 'generator'),  # Dynamic value
            'X-Drupal-Cache': ('Drupal', 'cms'),
            'X-Drupal-Dynamic-Cache': ('Drupal', 'cms'),
            'X-Redirect-By': (None, 'cms'),
        }

        for header, (tech, category) in framework_headers.items():
            if header.lower() in body.lower():
                if tech:
                    self.result['framework'] = tech
                    self._add_tech(tech, category)
                    return tech

        return ''

    def _identify_waf(self, resp) -> List[str]:
        """Detect WAF/CDN from response characteristics."""
        body = resp.body or ''
        body_lower = body.lower()
        detected_wafs = []

        for waf_name, signatures in WAF_SIGNATURES.items():
            matched = False

            # Check headers
            for header in signatures.get('headers', []):
                if header.lower() in body_lower:
                    matched = True
                    break

            # Check server value
            if not matched:
                for server_val in signatures.get('server', []):
                    if server_val.lower() in body_lower:
                        matched = True
                        break

            # Check cookies
            if not matched:
                for cookie in signatures.get('cookies', []):
                    if cookie.lower() in body_lower:
                        matched = True
                        break

            # Check error page patterns
            if not matched:
                for pattern in signatures.get('error_patterns', []):
                    if pattern.lower() in body_lower:
                        matched = True
                        break

            if matched:
                detected_wafs.append(waf_name)
                self._add_tech(waf_name, 'waf')

        self.result['waf'] = detected_wafs
        return detected_wafs

    def _identify_from_cookies(self, resp) -> None:
        """Identify technologies from cookie names in the response."""
        body = resp.body or ''
        body_lower = body.lower()

        for cookie_name, (tech, category) in COOKIE_FINGERPRINTS.items():
            if cookie_name.lower() in body_lower:
                if category == 'language':
                    self.result['language'] = tech
                elif category == 'framework':
                    if not self.result['framework']:
                        self.result['framework'] = tech
                elif category == 'cms':
                    self.result['cms'] = tech
                self._add_tech(tech, category)

    def _identify_from_html(self, html: str) -> None:
        """Identify frontend frameworks from HTML content."""
        if not html:
            return

        for pattern, tech_name in HTML_PATTERNS:
            match = pattern.search(html)
            if match:
                if tech_name == 'generator':
                    # Extract actual generator name
                    gen = match.group(1)
                    self._add_tech(gen, 'generator')
                    # Common generators
                    if 'wordpress' in gen.lower():
                        self.result['cms'] = 'WordPress'
                    elif 'drupal' in gen.lower():
                        self.result['cms'] = 'Drupal'
                    elif 'joomla' in gen.lower():
                        self.result['cms'] = 'Joomla'
                else:
                    self.result['frontend'].append(tech_name)
                    self._add_tech(tech_name, 'frontend')

    def _add_tech(self, tech: str, category: str) -> None:
        """Add a technology to the all_technologies list."""
        entry = {'name': tech, 'category': category}
        if entry not in self.result['all_technologies']:
            self.result['all_technologies'].append(entry)

    def identify_server(self) -> str:
        """Return identified server."""
        return self.result.get('server', '')

    def identify_framework(self) -> str:
        """Return identified framework."""
        return self.result.get('framework', '')

    def identify_waf(self) -> List[str]:
        """Return identified WAFs."""
        return self.result.get('waf', [])

    def summary(self) -> Dict:
        """Return fingerprint summary."""
        return {
            'server': self.result['server'],
            'framework': self.result['framework'],
            'language': self.result['language'],
            'cms': self.result['cms'],
            'waf': self.result['waf'],
            'cdn': self.result['cdn'],
            'frontend': self.result['frontend'],
            'versions': self.result['versions'],
            'total_technologies': len(self.result['all_technologies']),
        }
