"""JavaScript file analyzer for extracting secrets, endpoints, and API keys."""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from engine.core.http_client import HttpClient
from engine.core.recon_cache import ReconCache


@dataclass
class JsFinding:
    """A secret or endpoint extracted from JavaScript."""
    type: str          # 'endpoint', 'aws_key', 'jwt', 'firebase', 's3_bucket', 'api_key', 'password', 'internal_url'
    value: str
    source_file: str
    context: str       # surrounding code snippet
    confidence: str = 'medium'  # 'high', 'medium', 'low'

    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'value': self.value,
            'source_file': self.source_file,
            'context': self.context,
            'confidence': self.confidence,
        }


# Compiled regex patterns for performance
PATTERNS = {
    'endpoint': [
        re.compile(r'''(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|XMLHttpRequest)\s*\(\s*[`'"](\/[a-zA-Z0-9_/\-{}:.]+)[`'"]'''),
        re.compile(r'''['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"](\/?api\/[a-zA-Z0-9_/\-{}:.?&=]+)['"]'''),
        re.compile(r'''(?:url|endpoint|path|route|api)\s*[:=]\s*['"`](\/[a-zA-Z0-9_/\-{}:.]+)['"`]'''),
        re.compile(r'''(?:baseURL|baseUrl|BASE_URL)\s*[:=]\s*['"`](https?://[^\s'"`,]+)['"`]'''),
    ],
    'aws_key': [
        re.compile(r'(AKIA[0-9A-Z]{16})'),
        re.compile(r'''(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]'''),
    ],
    'jwt': [
        re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'),
    ],
    'firebase': [
        re.compile(r'''(?:apiKey|firebase)\s*[:=]\s*['"](AIza[0-9A-Za-z_-]{35})['"]'''),
        re.compile(r'''(https?://[a-z0-9-]+\.firebaseio\.com)'''),
        re.compile(r'''(https?://[a-z0-9-]+\.firebaseapp\.com)'''),
    ],
    's3_bucket': [
        re.compile(r'(https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com)'),
        re.compile(r'(https?://s3[.-][a-z0-9-]*\.amazonaws\.com/[a-z0-9.-]+)'),
        re.compile(r'''['"]([a-z0-9.-]+\.s3\.amazonaws\.com)['"]'''),
    ],
    'api_key': [
        re.compile(r'''(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]''', re.IGNORECASE),
        re.compile(r'''(?:client[_-]?secret|app[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]''', re.IGNORECASE),
        re.compile(r'''(?:sk_live_|pk_live_|sk_test_|pk_test_)([a-zA-Z0-9]{24,})'''),  # Stripe
        re.compile(r'''(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}'''),  # GitHub tokens
    ],
    'password': [
        re.compile(r'''(?:password|passwd|pwd|secret)\s*[:=]\s*['"]([^'"]{6,})['"]''', re.IGNORECASE),
    ],
    'internal_url': [
        re.compile(r'''(https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s'"`,]*)'''),
        re.compile(r'''(https?://[a-z0-9-]+\.internal[^\s'"`,]*)'''),
        re.compile(r'''(https?://[a-z0-9-]+\.corp\.[^\s'"`,]*)'''),
        re.compile(r'''(https?://[a-z0-9-]+\.local[^\s'"`,]*)'''),
    ],
}

# Confidence mapping
HIGH_CONFIDENCE_TYPES = {'aws_key', 'jwt', 'firebase', 's3_bucket'}
MEDIUM_CONFIDENCE_TYPES = {'api_key', 'password', 'internal_url'}
LOW_CONFIDENCE_TYPES = {'endpoint'}


class JsAnalyzer:
    """Extracts secrets, endpoints, and API keys from JavaScript files."""

    def __init__(self, target: str):
        self.target = target
        self.client = HttpClient(target=target, timeout=15)
        self.cache = ReconCache(target)
        self.findings: List[JsFinding] = []

    def discover_js_files(self, base_url: str) -> List[str]:
        """Parse HTML page for <script src=...> tags and return JS URLs."""
        resp = self.client.get(base_url)
        if not resp.ok:
            return []

        js_urls = []
        # Match <script src="..."> tags
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(resp.body):
            src = match.group(1)
            if src.startswith('//'):
                src = 'https:' + src
            elif src.startswith('/'):
                # Relative URL - prepend base
                from urllib.parse import urlparse
                parsed = urlparse(base_url)
                src = f"{parsed.scheme}://{parsed.netloc}{src}"
            elif not src.startswith('http'):
                src = base_url.rstrip('/') + '/' + src
            js_urls.append(src)

        # Also check for common JS bundle paths
        common_paths = [
            '/static/js/main.js', '/assets/js/app.js', '/bundle.js',
            '/dist/main.js', '/build/static/js/main.js',
            '/_next/static/chunks/main.js', '/webpack-bundle.js',
        ]
        for path in common_paths:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            status = self.client.get_status_code(url)
            if status == 200:
                js_urls.append(url)

        # Cache discovered JS files
        if js_urls:
            self.cache.store_batch('js_file', js_urls, source='js_analyzer')

        return list(set(js_urls))

    def extract_endpoints(self, js_content: str) -> List[Dict]:
        """Extract API endpoints from JavaScript content."""
        results = []
        for pattern in PATTERNS['endpoint']:
            for match in pattern.finditer(js_content):
                value = match.group(1) if match.lastindex else match.group(0)
                start = max(0, match.start() - 40)
                end = min(len(js_content), match.end() + 40)
                context = js_content[start:end].strip()
                results.append({
                    'type': 'endpoint',
                    'value': value,
                    'context': context,
                    'confidence': 'low',
                })
        return results

    def extract_secrets(self, js_content: str) -> List[Dict]:
        """Extract secrets (API keys, tokens, passwords) from JavaScript content."""
        results = []
        for secret_type, patterns in PATTERNS.items():
            if secret_type == 'endpoint':
                continue
            for pattern in patterns:
                for match in pattern.finditer(js_content):
                    value = match.group(1) if match.lastindex else match.group(0)
                    start = max(0, match.start() - 40)
                    end = min(len(js_content), match.end() + 40)
                    context = js_content[start:end].strip()

                    if secret_type in HIGH_CONFIDENCE_TYPES:
                        confidence = 'high'
                    elif secret_type in MEDIUM_CONFIDENCE_TYPES:
                        confidence = 'medium'
                    else:
                        confidence = 'low'

                    results.append({
                        'type': secret_type,
                        'value': value,
                        'context': context,
                        'confidence': confidence,
                    })
        return results

    def analyze_url(self, url: str) -> List[JsFinding]:
        """Fetch a JS file and analyze it for secrets and endpoints."""
        resp = self.client.get(url)
        if not resp.ok:
            return []

        findings = []
        # Extract endpoints
        for item in self.extract_endpoints(resp.body):
            f = JsFinding(
                type=item['type'],
                value=item['value'],
                source_file=url,
                context=item['context'],
                confidence=item['confidence'],
            )
            findings.append(f)

        # Extract secrets
        for item in self.extract_secrets(resp.body):
            f = JsFinding(
                type=item['type'],
                value=item['value'],
                source_file=url,
                context=item['context'],
                confidence=item['confidence'],
            )
            findings.append(f)

        self.findings.extend(findings)

        # Cache endpoint findings
        endpoints = [f.value for f in findings if f.type == 'endpoint']
        if endpoints:
            self.cache.store_batch('api_endpoint', endpoints, source='js_analyzer')

        return findings

    def analyze_all(self, base_url: str) -> List[JsFinding]:
        """Discover JS files from a page and analyze all of them."""
        js_urls = self.discover_js_files(base_url)
        all_findings = []
        for url in js_urls:
            findings = self.analyze_url(url)
            all_findings.extend(findings)
        return all_findings

    def get_high_value_findings(self) -> List[JsFinding]:
        """Return only high-confidence findings (likely real secrets)."""
        return [f for f in self.findings if f.confidence == 'high']

    def summary(self) -> Dict:
        """Return summary of all findings by type."""
        by_type: Dict[str, int] = {}
        for f in self.findings:
            by_type[f.type] = by_type.get(f.type, 0) + 1
        return {
            'total': len(self.findings),
            'by_type': by_type,
            'high_confidence': len(self.get_high_value_findings()),
        }
