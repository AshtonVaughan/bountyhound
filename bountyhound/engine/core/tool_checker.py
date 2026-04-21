"""
Tool Checker with Graceful Degradation

Detects available external tools and provides fallback alternatives
when tools are missing. Prevents silent failures during hunts.
"""

import subprocess
import shutil
import socket
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class ToolStatus:
    name: str
    available: bool
    version: str = ""
    path: str = ""
    fallback: str = ""
    fallback_available: bool = False


class ToolChecker:
    """Check for external tool availability and provide fallbacks."""

    REQUIRED_TOOLS = {
        'subfinder': {
            'check_cmd': ['subfinder', '-version'],
            'fallback': 'dns_bruteforce',
            'description': 'Subdomain enumeration',
            'fallback_description': 'Python DNS brute force + crt.sh API'
        },
        'httpx': {
            'check_cmd': ['httpx', '-version'],
            'fallback': 'curl_probe',
            'description': 'HTTP probing',
            'fallback_description': 'curl-based HTTP probing'
        },
        'nmap': {
            'check_cmd': ['nmap', '--version'],
            'fallback': 'socket_scan',
            'description': 'Port scanning',
            'fallback_description': 'Python socket-based port scan'
        },
        'nuclei': {
            'check_cmd': ['nuclei', '-version'],
            'fallback': 'curl_templates',
            'description': 'Vulnerability scanning',
            'fallback_description': 'curl-based template testing'
        },
        'ffuf': {
            'check_cmd': ['ffuf', '-V'],
            'fallback': 'python_fuzzer',
            'description': 'Web fuzzing (directories, parameters, vhosts)',
            'fallback_description': 'Python wordlist-based path fuzzer via curl'
        },
        'katana': {
            'check_cmd': ['katana', '-version'],
            'fallback': 'python_crawler',
            'description': 'Fast web crawler with JS parsing and API discovery',
            'fallback_description': 'Python requests-based URL crawler'
        },
        'gau': {
            'check_cmd': ['gau', '--version'],
            'fallback': 'wayback_api',
            'description': 'Fetch URLs from Wayback, CommonCrawl, OTX, URLScan',
            'fallback_description': 'Direct Wayback + CommonCrawl API queries'
        },
        'interactsh-client': {
            'check_cmd': ['interactsh-client', '-version'],
            'fallback': 'manual_oob',
            'description': 'Out-of-band interaction server (blind SSRF, XXE, XSS)',
            'fallback_description': 'Placeholder OOB tokens for manual verification'
        },
        'arjun': {
            'check_cmd': ['arjun', '--help'],
            'fallback': 'python_param_miner',
            'description': 'HTTP parameter discovery',
            'fallback_description': 'Python common parameter wordlist tester'
        },
        'dalfox': {
            'check_cmd': ['dalfox', 'version'],
            'fallback': 'python_xss_scanner',
            'description': 'Context-aware XSS scanner with blind XSS support',
            'fallback_description': 'Python reflection-based XSS payload tester'
        },
        'dnsx': {
            'check_cmd': ['dnsx', '-version'],
            'fallback': 'python_dns_resolver',
            'description': 'DNS resolution, brute-force, and takeover detection',
            'fallback_description': 'Python socket-based DNS resolver'
        },
        'feroxbuster': {
            'check_cmd': ['feroxbuster', '--version'],
            'fallback': 'python_content_discovery',
            'description': 'Recursive content and directory discovery',
            'fallback_description': 'Python wordlist-based directory buster via curl'
        },
        'trufflehog': {
            'check_cmd': ['trufflehog', '--version'],
            'fallback': 'python_secret_scanner',
            'description': 'Secret scanning (API keys, tokens in JS files and git repos)',
            'fallback_description': 'Python regex-based secret pattern scanner'
        },
        'sqlmap': {
            'check_cmd': ['sqlmap', '--version'],
            'fallback': 'python_sqli_tester',
            'description': 'SQL injection detection and exploitation',
            'fallback_description': 'Python error-based SQLi detection'
        },
    }

    def __init__(self):
        self._cache: Dict[str, ToolStatus] = {}

    def check_all(self) -> Dict[str, ToolStatus]:
        """Check all required tools and return status dict."""
        results = {}
        for name, config in self.REQUIRED_TOOLS.items():
            results[name] = self._check_tool(name, config)
        self._cache = results
        return results

    def _check_tool(self, name: str, config: dict) -> ToolStatus:
        """Check if a specific tool is available."""
        path = shutil.which(name)
        if path:
            version = self._get_version(config['check_cmd'])
            return ToolStatus(
                name=name,
                available=True,
                version=version,
                path=path,
                fallback=config['fallback'],
                fallback_available=True
            )
        return ToolStatus(
            name=name,
            available=False,
            fallback=config['fallback'],
            fallback_available=True  # Built-in fallbacks always available
        )

    def _get_version(self, cmd: list) -> str:
        """Get tool version string."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip() or result.stderr.strip()
            return output.split('\n')[0][:100]
        except Exception:
            return "unknown"

    def get_available_tools(self) -> List[str]:
        """Return list of available tool names."""
        if not self._cache:
            self.check_all()
        return [name for name, status in self._cache.items() if status.available]

    def get_missing_tools(self) -> List[str]:
        """Return list of missing tool names."""
        if not self._cache:
            self.check_all()
        return [name for name, status in self._cache.items() if not status.available]

    def print_status(self) -> str:
        """Print tool status report."""
        if not self._cache:
            self.check_all()

        lines = ["Tool Status:"]
        for name, status in self._cache.items():
            config = self.REQUIRED_TOOLS[name]
            if status.available:
                lines.append(f"  [OK] {name} ({status.version})")
            else:
                lines.append(f"  [MISSING] {name} -> fallback: {config['fallback_description']}")
        return '\n'.join(lines)


class FallbackSubdomainEnum:
    """Fallback subdomain enumeration using crt.sh and DNS."""

    @staticmethod
    def enumerate(domain: str, timeout: int = 30) -> List[str]:
        """Enumerate subdomains using crt.sh certificate transparency."""
        subdomains = set()

        # Method 1: crt.sh API
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout),
                 f'https://crt.sh/?q=%.{domain}&output=json'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if result.stdout:
                entries = json.loads(result.stdout)
                for entry in entries:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and '*' not in sub:
                            subdomains.add(sub)
        except Exception:
            pass

        # Method 2: Common subdomain brute force
        common_subs = [
            'www', 'api', 'app', 'admin', 'dev', 'staging', 'test',
            'mail', 'smtp', 'pop', 'imap', 'ftp', 'ssh', 'vpn',
            'cdn', 'static', 'assets', 'media', 'img', 'images',
            'docs', 'wiki', 'blog', 'forum', 'support', 'help',
            'status', 'monitor', 'grafana', 'kibana', 'jenkins',
            'gitlab', 'github', 'ci', 'cd', 'deploy', 'build',
            'internal', 'intranet', 'portal', 'dashboard', 'panel',
            'auth', 'login', 'sso', 'oauth', 'id', 'account',
            'm', 'mobile', 'beta', 'alpha', 'preview', 'sandbox',
            'stage', 'stg', 'uat', 'qa', 'preprod', 'pre-prod',
            'db', 'database', 'redis', 'mongo', 'mysql', 'postgres',
            's3', 'storage', 'bucket', 'backup', 'backups',
            'ws', 'websocket', 'socket', 'realtime', 'graphql',
            'v1', 'v2', 'v3', 'legacy', 'old', 'new'
        ]
        def _resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
                return fqdn
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_resolve, sub): sub for sub in common_subs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)

        return sorted(subdomains)


class FallbackHTTPProbe:
    """Fallback HTTP probing using curl."""

    @staticmethod
    def probe(hosts: List[str], timeout: int = 5) -> List[Dict]:
        """Probe hosts for HTTP/HTTPS availability."""
        results = []
        for host in hosts:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{host}"
                    result = subprocess.run(
                        ['curl', '-sI', '-m', str(timeout), '-o', '/dev/null',
                         '-w', '%{http_code}|%{redirect_url}|%{content_type}',
                         url],
                        capture_output=True, text=True, timeout=timeout + 5
                    )
                    parts = result.stdout.strip().split('|')
                    status = int(parts[0]) if parts[0].isdigit() else 0
                    if status > 0 and status != 000:
                        results.append({
                            'host': host,
                            'url': url,
                            'status_code': status,
                            'redirect': parts[1] if len(parts) > 1 else '',
                            'content_type': parts[2] if len(parts) > 2 else ''
                        })
                        break  # HTTPS worked, skip HTTP
                except Exception:
                    continue
        return results


class FallbackPortScanner:
    """Fallback port scanning using Python sockets."""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
        993, 995, 1433, 1521, 2082, 2083, 2086, 2087, 3000,
        3306, 3389, 4443, 5432, 5900, 6379, 8000, 8008, 8080,
        8443, 8888, 9090, 9200, 9300, 27017
    ]

    @staticmethod
    def scan(host: str, ports: Optional[List[int]] = None, timeout: float = 1.0) -> List[Dict]:
        """Scan common ports on a host."""
        if ports is None:
            ports = FallbackPortScanner.COMMON_PORTS

        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = FallbackPortScanner._guess_service(port)
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': service
                    })
                sock.close()
            except Exception:
                continue
        return open_ports

    @staticmethod
    def _guess_service(port: int) -> str:
        """Guess service name from port number."""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
            465: 'smtps', 587: 'submission', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1521: 'oracle', 3000: 'node', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
            8080: 'http-proxy', 8443: 'https-alt', 9200: 'elasticsearch',
            27017: 'mongodb'
        }
        return services.get(port, f'unknown-{port}')


class FallbackVulnScanner:
    """Fallback vulnerability scanning using curl-based template testing."""

    TEMPLATES = [
        {
            'name': 'security-headers-missing',
            'severity': 'INFO',
            'test': lambda url: FallbackVulnScanner._check_security_headers(url)
        },
        {
            'name': 'cors-misconfiguration',
            'severity': 'MEDIUM',
            'test': lambda url: FallbackVulnScanner._check_cors(url)
        },
        {
            'name': 'open-redirect',
            'severity': 'MEDIUM',
            'test': lambda url: FallbackVulnScanner._check_open_redirect(url)
        },
        {
            'name': 'exposed-git',
            'severity': 'HIGH',
            'test': lambda url: FallbackVulnScanner._check_exposed_git(url)
        },
        {
            'name': 'exposed-env',
            'severity': 'CRITICAL',
            'test': lambda url: FallbackVulnScanner._check_exposed_env(url)
        },
        {
            'name': 'graphql-introspection',
            'severity': 'MEDIUM',
            'test': lambda url: FallbackVulnScanner._check_graphql_introspection(url)
        },
        {
            'name': 'directory-listing',
            'severity': 'LOW',
            'test': lambda url: FallbackVulnScanner._check_directory_listing(url)
        }
    ]

    @staticmethod
    def scan(url: str) -> List[Dict]:
        """Run all templates against a URL."""
        findings = []
        for template in FallbackVulnScanner.TEMPLATES:
            try:
                result = template['test'](url)
                if result:
                    findings.append({
                        'template': template['name'],
                        'severity': template['severity'],
                        'url': url,
                        'evidence': result
                    })
            except Exception:
                continue
        return findings

    @staticmethod
    def _curl(url: str, extra_args: list = None, timeout: int = 10) -> Tuple[str, str]:
        """Execute curl and return (stdout, headers)."""
        cmd = ['curl', '-s', '-m', str(timeout)]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(url)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            return result.stdout, result.stderr
        except Exception:
            return '', ''

    @staticmethod
    def _check_security_headers(url: str) -> Optional[str]:
        headers_out, _ = FallbackVulnScanner._curl(url, ['-I'])
        headers_lower = headers_out.lower()
        missing = []
        for h in ['strict-transport-security', 'x-content-type-options',
                   'x-frame-options', 'content-security-policy']:
            if h not in headers_lower:
                missing.append(h)
        if missing:
            return f"Missing headers: {', '.join(missing)}"
        return None

    @staticmethod
    def _check_cors(url: str) -> Optional[str]:
        headers_out, _ = FallbackVulnScanner._curl(
            url, ['-I', '-H', 'Origin: https://evil.com'])
        if 'access-control-allow-origin: https://evil.com' in headers_out.lower():
            if 'access-control-allow-credentials: true' in headers_out.lower():
                return "CORS reflects origin with credentials"
            return "CORS reflects arbitrary origin"
        if 'access-control-allow-origin: *' in headers_out.lower():
            return "CORS allows all origins (wildcard)"
        return None

    @staticmethod
    def _check_open_redirect(url: str) -> Optional[str]:
        payloads = ['/redirect?url=https://evil.com', '/login?next=https://evil.com',
                    '/goto?url=//evil.com', '/out?to=https://evil.com']
        base = url.rstrip('/')
        for payload in payloads:
            headers_out, _ = FallbackVulnScanner._curl(
                f"{base}{payload}", ['-I', '-o', '/dev/null', '-w', '%{redirect_url}'])
            if 'evil.com' in headers_out:
                return f"Open redirect via {payload}"
        return None

    @staticmethod
    def _check_exposed_git(url: str) -> Optional[str]:
        body, _ = FallbackVulnScanner._curl(f"{url.rstrip('/')}/.git/config")
        if '[core]' in body or '[remote' in body:
            return "Exposed .git/config"
        return None

    @staticmethod
    def _check_exposed_env(url: str) -> Optional[str]:
        body, _ = FallbackVulnScanner._curl(f"{url.rstrip('/')}/.env")
        indicators = ['DB_PASSWORD', 'API_KEY', 'SECRET_KEY', 'AWS_ACCESS',
                      'DATABASE_URL', 'REDIS_URL', 'STRIPE_']
        for ind in indicators:
            if ind in body:
                return f"Exposed .env file containing {ind}"
        return None

    @staticmethod
    def _check_graphql_introspection(url: str) -> Optional[str]:
        for path in ['/graphql', '/api/graphql', '/gql', '/query']:
            full_url = f"{url.rstrip('/')}{path}"
            body, _ = FallbackVulnScanner._curl(full_url, [
                '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-d', '{"query":"{ __schema { types { name } } }"}'
            ])
            if '__schema' in body and 'types' in body:
                return f"GraphQL introspection enabled at {path}"
        return None

    @staticmethod
    def _check_directory_listing(url: str) -> Optional[str]:
        for path in ['/assets/', '/static/', '/uploads/', '/images/', '/files/']:
            full_url = f"{url.rstrip('/')}{path}"
            body, _ = FallbackVulnScanner._curl(full_url)
            if '<title>Index of' in body or 'Directory listing for' in body:
                return f"Directory listing at {path}"
        return None


class FallbackFuzzer:
    """Fallback web fuzzer using curl against a common wordlist."""

    COMMON_PATHS = [
        'admin', 'api', 'login', 'dashboard', 'config', 'backup', 'test',
        'dev', 'staging', 'debug', 'console', 'panel', 'manage', 'manager',
        'administrator', 'wp-admin', 'phpmyadmin', 'adminer', 'setup',
        'install', 'upgrade', 'update', 'status', 'health', 'metrics',
        '.env', '.git', '.svn', '.htaccess', 'robots.txt', 'sitemap.xml',
        'swagger.json', 'openapi.json', 'api-docs', 'v1', 'v2', 'v3',
        'graphql', 'gql', 'rpc', 'soap', 'wsdl', 'actuator', 'info',
        'server-status', 'server-info', 'phpinfo.php', 'info.php',
        'upload', 'uploads', 'files', 'file', 'images', 'static', 'assets',
        'backup.sql', 'dump.sql', 'db.sql', 'database.sql', 'data.sql',
        'users', 'user', 'account', 'accounts', 'profile', 'profiles',
        'internal', 'private', 'secret', 'hidden', 'old', 'temp', 'tmp',
    ]

    @staticmethod
    def fuzz(base_url: str, wordlist: List[str] = None, timeout: int = 5) -> List[Dict]:
        """Fuzz URL paths and return findings with non-404 responses."""
        paths = wordlist or FallbackFuzzer.COMMON_PATHS
        findings = []

        def _check(path: str):
            url = f"{base_url.rstrip('/')}/{path}"
            try:
                result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                     '-m', str(timeout), '-L', url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                code = result.stdout.strip()
                if code.isdigit() and int(code) not in (404, 400, 000):
                    return {'url': url, 'status': int(code), 'path': path}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_check, p): p for p in paths}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    findings.append(r)

        return sorted(findings, key=lambda x: x['status'])


class FallbackCrawler:
    """Fallback web crawler using Python requests to discover URLs."""

    @staticmethod
    def crawl(base_url: str, max_urls: int = 200, timeout: int = 10) -> List[str]:
        """Crawl a site and return discovered URLs."""
        import re
        discovered = set()
        queue = [base_url]
        visited = set()

        while queue and len(discovered) < max_urls:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                result = subprocess.run(
                    ['curl', '-s', '-L', '-m', str(timeout), url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                body = result.stdout
                # Extract href and src links
                links = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', body)
                for link in links:
                    if link.startswith('http') and base_url in link:
                        discovered.add(link)
                        if link not in visited:
                            queue.append(link)
                    elif link.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(base_url)
                        full = f"{parsed.scheme}://{parsed.netloc}{link}"
                        discovered.add(full)
                        if full not in visited:
                            queue.append(full)
            except Exception:
                continue

        return sorted(discovered)


class FallbackGAU:
    """Fallback URL gatherer using Wayback Machine and CommonCrawl APIs."""

    @staticmethod
    def fetch_urls(domain: str, timeout: int = 30) -> List[str]:
        """Fetch historical URLs from Wayback Machine and CommonCrawl."""
        urls = set()

        # Wayback Machine CDX API
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout),
                 f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*'
                 f'&output=text&fl=original&collapse=urlkey&limit=5000'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and domain in line:
                    urls.add(line)
        except Exception:
            pass

        # CommonCrawl index API
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout),
                 f'https://index.commoncrawl.org/CC-MAIN-2024-10-index'
                 f'?url=*.{domain}/*&output=text&fl=url&limit=2000'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and domain in line:
                    urls.add(line)
        except Exception:
            pass

        return sorted(urls)


class FallbackOOB:
    """Fallback OOB: generates placeholder tokens for manual out-of-band testing."""

    @staticmethod
    def generate_token(test_name: str) -> Dict:
        """Generate a placeholder OOB token with instructions."""
        import uuid
        token_id = str(uuid.uuid4())[:8]
        return {
            'token_id': token_id,
            'test_name': test_name,
            'instructions': (
                'interactsh-client not installed. For out-of-band testing:\n'
                '1. Use https://app.interactsh.com for a free OOB server\n'
                '2. Or install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n'
                f'3. Replace OOB host with your interactsh URL + token: {token_id}'
            ),
            'canary_domains': [
                f'{token_id}.oast.fun',
                f'{token_id}.oast.live',
            ]
        }


class FallbackParamMiner:
    """Fallback parameter discovery using common parameter wordlist."""

    COMMON_PARAMS = [
        'id', 'user', 'username', 'email', 'token', 'key', 'api_key',
        'access_token', 'auth', 'password', 'pass', 'secret', 'hash',
        'file', 'path', 'url', 'redirect', 'next', 'return', 'callback',
        'action', 'cmd', 'command', 'exec', 'query', 'search', 'q',
        'debug', 'test', 'mode', 'format', 'type', 'lang', 'locale',
        'page', 'limit', 'offset', 'sort', 'order', 'filter',
        'include', 'exclude', 'expand', 'fields', 'select',
        'admin', 'role', 'permission', 'scope', 'group',
        'src', 'dest', 'target', 'host', 'ip', 'port',
        'ref', 'referrer', 'origin', 'source', 'from', 'to',
        'name', 'title', 'description', 'content', 'body', 'message',
        'data', 'payload', 'input', 'value', 'param',
        'config', 'settings', 'option', 'feature', 'flag',
        'version', 'v', 'ver', 'api_version',
        'callback_url', 'webhook', 'notify_url',
        'account_id', 'user_id', 'profile_id', 'org_id', 'team_id',
    ]

    @staticmethod
    def discover(url: str, method: str = 'GET', timeout: int = 5) -> List[str]:
        """Test URL for hidden parameters by comparing response sizes."""
        found = []
        try:
            # Baseline response with dummy param
            baseline = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{size_download}',
                 '-m', str(timeout), f'{url}?bountyhound_baseline=1'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            baseline_size = int(baseline.stdout.strip() or '0')
        except Exception:
            return []

        def _test_param(param: str) -> Optional[str]:
            try:
                result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{size_download}',
                     '-m', str(timeout), f'{url}?{param}=BOUNTYHOUND_TEST'],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                size = int(result.stdout.strip() or '0')
                if abs(size - baseline_size) > 50:
                    return param
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {pool.submit(_test_param, p): p for p in FallbackParamMiner.COMMON_PARAMS}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    found.append(r)

        return found


class FallbackXSSScanner:
    """Fallback XSS scanner using reflection-based payload testing."""

    PAYLOADS = [
        '<script>document.title="XSS-FIRED"</script>',
        '"><script>document.title="XSS-FIRED"</script>',
        "'><script>document.title='XSS-FIRED'</script>",
        '<img src=x onerror=document.title="XSS-FIRED">',
        '"><img src=x onerror=document.title=`XSS-FIRED`>',
        "javascript:document.title='XSS-FIRED'",
        '<svg onload=document.title="XSS-FIRED">',
        '{{7*7}}',  # Template injection marker
        '${7*7}',
    ]

    @staticmethod
    def scan(url: str, params: List[str] = None, timeout: int = 10) -> List[Dict]:
        """Test URL parameters for XSS reflection."""
        findings = []
        test_params = params or ['q', 'search', 'query', 'input', 'name', 'value', 'msg']

        for param in test_params:
            for payload in FallbackXSSScanner.PAYLOADS:
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-m', str(timeout),
                         f'{url}?{param}={payload}'],
                        capture_output=True, text=True, timeout=timeout + 5
                    )
                    if payload in result.stdout or 'XSS-FIRED' in result.stdout:
                        findings.append({
                            'url': url,
                            'param': param,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                        break  # Found one, move to next param
                except Exception:
                    continue

        return findings


class FallbackDNSResolver:
    """Fallback DNS resolver using Python socket + crt.sh for takeover detection."""

    TAKEOVER_PATTERNS = {
        'github.io': 'There isn\'t a GitHub Pages site here',
        'heroku': 'No such app',
        'amazonaws.com': 'NoSuchBucket',
        'azurewebsites.net': '404 Web Site not found',
        'shopify': 'Sorry, this shop is currently unavailable',
        'fastly': 'Fastly error: unknown domain',
        'pantheon': 'The gods are smiling upon you',
        'zendesk': 'Help Center Closed',
        'ghost': 'The thing you were looking for is no longer here',
        'surge.sh': 'project not found',
        'readme.io': 'Project doesnt exist',
    }

    @staticmethod
    def resolve_bulk(domains: List[str], timeout: float = 2.0) -> Dict[str, Optional[str]]:
        """Resolve a list of domains and return IP mapping."""
        results = {}

        def _resolve(domain: str) -> tuple:
            try:
                info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                ip = info[0][4][0]
                return domain, ip
            except socket.gaierror:
                return domain, None

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(_resolve, d): d for d in domains}
            for future in as_completed(futures):
                domain, ip = future.result()
                results[domain] = ip

        return results

    @staticmethod
    def check_takeover(domain: str, timeout: int = 10) -> Optional[Dict]:
        """Check if a subdomain is vulnerable to takeover."""
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), '-L', f'https://{domain}'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            body = result.stdout
            for service, fingerprint in FallbackDNSResolver.TAKEOVER_PATTERNS.items():
                if fingerprint.lower() in body.lower():
                    return {
                        'domain': domain,
                        'service': service,
                        'fingerprint': fingerprint,
                        'severity': 'HIGH'
                    }
        except Exception:
            pass
        return None


class FallbackContentDiscovery:
    """Fallback recursive content discovery using curl."""

    WORDLIST = [
        'admin', 'api', 'app', 'assets', 'auth', 'backup', 'bin', 'blog',
        'cache', 'cdn', 'config', 'console', 'content', 'cron', 'css',
        'dashboard', 'data', 'database', 'db', 'debug', 'demo', 'dev',
        'docs', 'download', 'error', 'export', 'feed', 'files', 'fonts',
        'graphql', 'health', 'hidden', 'home', 'img', 'images', 'import',
        'includes', 'info', 'internal', 'js', 'lib', 'log', 'login',
        'logout', 'manage', 'media', 'metrics', 'monitor', 'node_modules',
        'old', 'panel', 'private', 'public', 'queue', 'report', 'robots.txt',
        'search', 'secure', 'server-status', 'settings', 'setup', 'sitemap.xml',
        'sql', 'src', 'staging', 'static', 'status', 'storage', 'swagger',
        'system', 'temp', 'test', 'tools', 'upload', 'uploads', 'user',
        'users', 'v1', 'v2', 'v3', 'vendor', 'web', 'webadmin', 'wp-admin',
        'wp-content', 'wp-includes', 'xmlrpc.php', '.env', '.git', '.htaccess',
    ]

    @staticmethod
    def discover(base_url: str, timeout: int = 5, depth: int = 1) -> List[Dict]:
        """Discover content recursively."""
        found = []
        to_check = [(base_url, 0)]
        checked = set()

        while to_check:
            url, current_depth = to_check.pop(0)

            def _check(path: str, parent_url: str = url) -> Optional[Dict]:
                target = f"{parent_url.rstrip('/')}/{path}"
                if target in checked:
                    return None
                checked.add(target)
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-o', '/dev/null',
                         '-w', '%{http_code}|%{size_download}',
                         '-m', str(timeout), target],
                        capture_output=True, text=True, timeout=timeout + 5
                    )
                    parts = result.stdout.strip().split('|')
                    code = int(parts[0]) if parts[0].isdigit() else 0
                    size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    if code not in (404, 400, 000, 0):
                        return {'url': target, 'status': code, 'size': size, 'path': path}
                except Exception:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(_check, p): p for p in FallbackContentDiscovery.WORDLIST}
                for future in as_completed(futures):
                    r = future.result()
                    if r:
                        found.append(r)
                        if current_depth < depth and r['status'] in (200, 301, 302):
                            to_check.append((r['url'], current_depth + 1))

        return found


class FallbackSecretScanner:
    """Fallback secret scanner using regex patterns on JS files and responses."""

    PATTERNS = [
        (r'(?i)aws.{0,20}["\']([A-Z0-9]{20})["\']', 'AWS Access Key ID'),
        (r'(?i)aws.{0,20}["\']([A-Za-z0-9/+=]{40})["\']', 'AWS Secret Key'),
        (r'(?i)api[_-]?key["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', 'API Key'),
        (r'(?i)secret[_-]?key["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', 'Secret Key'),
        (r'(?i)access[_-]?token["\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']', 'Access Token'),
        (r'(?i)auth[_-]?token["\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']', 'Auth Token'),
        (r'Bearer\s+([A-Za-z0-9_\-\.]{20,})', 'Bearer Token'),
        (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', 'JWT Token'),
        (r'(?i)password["\s:=]+["\']([^"\']{8,})["\']', 'Password'),
        (r'(?i)stripe[_-]?(?:live|secret)[_-]?key["\s:=]+["\']([A-Za-z0-9_]{20,})["\']', 'Stripe Key'),
        (r'(?i)github[_-]?token["\s:=]+["\']([A-Za-z0-9_]{20,})["\']', 'GitHub Token'),
        (r'(?i)slack[_-]?(?:token|webhook)["\s:=]+["\']([A-Za-z0-9_\/\-\.]+)["\']', 'Slack Token'),
        (r'(?i)private[_-]?key["\s:=]+["\']([A-Za-z0-9+/=]{40,})["\']', 'Private Key'),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'PEM Private Key'),
        (r'(?i)database[_-]?(?:url|uri)["\s:=]+["\']([^"\']+)["\']', 'Database URL'),
        (r'(?i)mongodb[+a-z]*://[^"\'>\s]+', 'MongoDB URI'),
        (r'(?i)postgres(?:ql)?://[^"\'>\s]+', 'PostgreSQL URI'),
        (r'(?i)redis://[^"\'>\s]+', 'Redis URI'),
    ]

    @staticmethod
    def scan_url(url: str, timeout: int = 15) -> List[Dict]:
        """Scan a URL response body for secrets."""
        import re
        findings = []
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '-m', str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            body = result.stdout
            for pattern, secret_type in FallbackSecretScanner.PATTERNS:
                matches = re.findall(pattern, body)
                for match in matches:
                    # Skip short/placeholder values
                    if isinstance(match, str) and len(match) > 8:
                        findings.append({
                            'url': url,
                            'type': secret_type,
                            'match': match[:50] + '...' if len(match) > 50 else match,
                            'severity': 'HIGH'
                        })
        except Exception:
            pass
        return findings

    @staticmethod
    def scan_js_files(base_url: str, timeout: int = 10) -> List[Dict]:
        """Discover and scan JS files for secrets."""
        import re
        findings = []
        # Find JS files from main page
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '-m', str(timeout), base_url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', result.stdout)
            from urllib.parse import urlparse, urljoin
            base = urlparse(base_url)
            for js in js_files[:20]:  # Cap at 20 JS files
                full_url = urljoin(base_url, js)
                if base.netloc in full_url or js.startswith('/'):
                    findings.extend(FallbackSecretScanner.scan_url(full_url, timeout))
        except Exception:
            pass
        return findings


class FallbackSQLiTester:
    """Fallback SQL injection tester using error-based detection."""

    ERROR_PATTERNS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query()",
        "sql syntax",
        "mysql_fetch",
        "ora-01756",
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "sqlite_master",
        "postgresql query failed",
        "invalid query",
        "syntax error",
        "division by zero",
    ]

    PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "\" OR \"1\"=\"1",
        "1' AND SLEEP(2)--",
        "1 AND 1=1",
        "1 AND 1=2",
        "') OR ('1'='1",
        "'; DROP TABLE users--",
        "1; SELECT SLEEP(2)--",
    ]

    @staticmethod
    def test(url: str, params: List[str] = None, timeout: int = 10) -> List[Dict]:
        """Test URL parameters for SQL injection via error detection."""
        import re
        findings = []
        test_params = params or ['id', 'user_id', 'product_id', 'q', 'search',
                                  'category', 'page', 'sort', 'order', 'filter']

        for param in test_params:
            for payload in FallbackSQLiTester.PAYLOADS:
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-m', str(timeout),
                         f'{url}?{param}={payload}'],
                        capture_output=True, text=True, timeout=timeout + 5
                    )
                    body = result.stdout.lower()
                    for pattern in FallbackSQLiTester.ERROR_PATTERNS:
                        if pattern in body:
                            findings.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'evidence': f'SQL error pattern: {pattern}',
                                'severity': 'HIGH'
                            })
                            break
                except Exception:
                    continue

        return findings


def get_recon_strategy(domain: str) -> Dict:
    """Return the best available recon strategy based on installed tools."""
    checker = ToolChecker()
    status = checker.check_all()

    strategy = {
        # Core recon
        'subdomain_enum': 'subfinder' if status['subfinder'].available else 'fallback_crtsh_dns',
        'http_probe': 'httpx' if status['httpx'].available else 'fallback_curl_probe',
        'port_scan': 'nmap' if status['nmap'].available else 'fallback_socket_scan',
        'vuln_scan': 'nuclei' if status['nuclei'].available else 'fallback_curl_templates',
        # Discovery
        'url_crawl': 'katana' if status['katana'].available else 'fallback_python_crawler',
        'url_history': 'gau' if status['gau'].available else 'fallback_wayback_api',
        'content_discovery': 'feroxbuster' if status['feroxbuster'].available else 'fallback_python_dirb',
        'dns_resolve': 'dnsx' if status['dnsx'].available else 'fallback_python_dns',
        # Fuzzing & params
        'fuzzing': 'ffuf' if status['ffuf'].available else 'fallback_python_fuzzer',
        'param_discovery': 'arjun' if status['arjun'].available else 'fallback_python_params',
        # Exploitation
        'xss_scan': 'dalfox' if status['dalfox'].available else 'fallback_python_xss',
        'sqli_scan': 'sqlmap' if status['sqlmap'].available else 'fallback_python_sqli',
        'oob_testing': 'interactsh-client' if status['interactsh-client'].available else 'fallback_manual_oob',
        'secret_scan': 'trufflehog' if status['trufflehog'].available else 'fallback_python_secrets',
        # Meta
        'tools_available': checker.get_available_tools(),
        'tools_missing': checker.get_missing_tools(),
        'status_report': checker.print_status()
    }
    return strategy
