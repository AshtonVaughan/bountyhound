"""
Target Profiler - Auto-detect target type and capabilities.

Analyzes a target (URL, domain, file path) and produces a profile
with boolean flags that determine which agents the auto-dispatcher
should run.

Usage:
    profiler = TargetProfiler('example.com')
    profile = profiler.profile()
    print(profile.triggers)  # {'has_web', 'has_api', 'has_graphql', ...}

    # Or profile a local path
    profiler = TargetProfiler('/path/to/source')
    profile = profiler.profile()
    # -> has_source_code=True, has_binary=False, etc.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set, Optional, Dict, Any, List
from colorama import Fore, Style

from engine.core.http_client import HttpClient


@dataclass
class TargetProfile:
    """Profile of a target with boolean capability flags."""
    target: str
    target_type: str = 'unknown'  # 'web', 'source', 'binary', 'mobile', 'hardware'

    # Web
    has_web: bool = False
    has_api: bool = False
    has_auth: bool = False
    has_oauth: bool = False
    has_jwt: bool = False
    has_mfa: bool = False
    has_graphql: bool = False
    has_grpc: bool = False
    has_websocket: bool = False
    has_params: bool = False
    has_url_params: bool = False
    has_file_params: bool = False
    has_xml: bool = False
    has_json_body: bool = False
    has_forms: bool = False
    has_cookies: bool = False
    has_upload: bool = False
    has_serialized_data: bool = False
    has_state_changing: bool = False
    has_roles: bool = False
    has_js_frontend: bool = False
    has_proxy: bool = False
    has_cdn: bool = False
    has_gateway: bool = False
    has_subdomains: bool = False

    # Non-web
    has_source_code: bool = False
    has_semgrep: bool = False
    has_binary: bool = False
    has_apk: bool = False
    has_ipa: bool = False
    has_firmware: bool = False
    has_desktop_app: bool = False

    # Cloud
    has_aws: bool = False
    has_s3: bool = False
    has_azure: bool = False
    has_gcp: bool = False
    has_ssrf_candidate: bool = False
    has_ldap: bool = False

    # Metadata
    base_url: str = ''
    tech_stack: Dict[str, Any] = field(default_factory=dict)
    discovered_endpoints: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def triggers(self) -> Set[str]:
        """Return set of active trigger names for agent matching."""
        active = set()
        for fname in self.__dataclass_fields__:
            if fname.startswith('has_') and getattr(self, fname):
                active.add(fname)
        return active

    def set_trigger(self, trigger: str, value: bool = True):
        """Dynamically set a trigger flag."""
        if hasattr(self, trigger):
            setattr(self, trigger, value)

    def summary(self) -> str:
        """Human-readable summary."""
        active = sorted(self.triggers)
        lines = [
            f"Target: {self.target} ({self.target_type})",
            f"Active triggers ({len(active)}): {', '.join(active)}" if active else "No triggers detected",
        ]
        if self.tech_stack:
            lines.append(f"Tech: {self.tech_stack}")
        return '\n'.join(lines)


class TargetProfiler:
    """Analyzes a target and produces a TargetProfile.

    Runs lightweight probes (HTTP requests, file system checks) to
    determine what kind of target this is and what capabilities it has.
    The resulting profile drives the auto-dispatcher.
    """

    # Common GraphQL paths
    GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/gql', '/query', '/v1/graphql']

    # Common API indicator paths
    API_PATHS = ['/api', '/api/v1', '/api/v2', '/rest', '/v1', '/v2']

    # File extensions for source code
    SOURCE_EXTENSIONS = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.c', '.cpp', '.h', '.rs', '.swift', '.kt'}

    # Binary extensions
    BINARY_EXTENSIONS = {'.exe', '.dll', '.so', '.dylib', '.elf', '.bin', '.sys', '.ko'}

    def __init__(self, target: str, http_client: Optional[HttpClient] = None):
        self.target = target.strip()
        self.http = http_client or HttpClient(timeout=10, max_retries=1)
        self.profile = TargetProfile(target=self.target)
        self._verbose = True

    def _log(self, msg: str):
        if self._verbose:
            print(f"  {Fore.CYAN}[profiler]{Style.RESET_ALL} {msg}")

    def _detect_target_type(self):
        """Determine if target is a URL, domain, file path, or directory."""
        t = self.target

        # File/directory path
        p = Path(t)
        if p.exists():
            if p.is_dir():
                self._log(f"Target is a local directory: {t}")
                self.profile.target_type = 'source'
                self._profile_directory(p)
                return
            elif p.is_file():
                self._log(f"Target is a local file: {t}")
                ext = p.suffix.lower()
                if ext in self.BINARY_EXTENSIONS:
                    self.profile.target_type = 'binary'
                    self.profile.has_binary = True
                elif ext == '.apk':
                    self.profile.target_type = 'mobile'
                    self.profile.has_apk = True
                elif ext == '.ipa':
                    self.profile.target_type = 'mobile'
                    self.profile.has_ipa = True
                elif ext in ('.bin', '.img', '.fw', '.hex'):
                    self.profile.target_type = 'hardware'
                    self.profile.has_firmware = True
                elif ext in self.SOURCE_EXTENSIONS:
                    self.profile.target_type = 'source'
                    self.profile.has_source_code = True
                return

        # URL or domain -> web target
        if t.startswith('http://') or t.startswith('https://'):
            self.profile.base_url = t.rstrip('/')
        else:
            # Assume domain, try HTTPS first
            self.profile.base_url = f'https://{t}'

        self.profile.target_type = 'web'
        self.profile.has_web = True
        self._profile_web()

    def _profile_directory(self, path: Path):
        """Profile a local source directory."""
        self.profile.has_source_code = True

        # Check for semgrep
        if shutil.which('semgrep'):
            self.profile.has_semgrep = True
            self._log("semgrep available")

        # Walk directory to detect file types
        has_binary = False
        has_apk = False
        source_langs = set()

        file_count = 0
        for root, dirs, files in os.walk(str(path)):
            # Skip hidden dirs and node_modules
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules' and d != '__pycache__']
            for f in files:
                file_count += 1
                if file_count > 5000:
                    break
                ext = Path(f).suffix.lower()
                if ext in self.BINARY_EXTENSIONS:
                    has_binary = True
                elif ext == '.apk':
                    has_apk = True
                elif ext == '.ipa':
                    self.profile.has_ipa = True
                elif ext in self.SOURCE_EXTENSIONS:
                    source_langs.add(ext)
            if file_count > 5000:
                break

        if has_binary:
            self.profile.has_binary = True
        if has_apk:
            self.profile.has_apk = True

        self.profile.tech_stack['source_langs'] = list(source_langs)
        self.profile.notes.append(f"Scanned {file_count} files, langs: {source_langs}")
        self._log(f"Source directory: {file_count} files, {len(source_langs)} languages")

    def _profile_web(self):
        """Profile a web target with lightweight HTTP probes."""
        base = self.profile.base_url

        # 1. Fetch main page
        self._probe_main_page(base)

        # 2. Check for GraphQL
        self._probe_graphql(base)

        # 3. Check for common API paths
        self._probe_api(base)

        # 4. Check for WebSocket
        # (detected from main page headers/JS)

        # 5. Check cloud indicators
        self._probe_cloud(base)

        # 6. Check subdomains from recon cache
        self._check_recon_cache()

        # Assume common capabilities for any web target
        self.profile.has_params = True  # Almost all web apps have params
        self.profile.has_state_changing = True  # Most apps have state-changing ops

    def _probe_main_page(self, base_url: str):
        """Fetch main page and extract info from headers and body."""
        try:
            resp = self.http.get(base_url)
            if not resp.ok:
                self._log(f"Main page returned {resp.status_code}")
                return

            body = resp.body.lower()

            # Detect tech from response
            if 'set-cookie' in resp.body.lower():
                self.profile.has_cookies = True

            # Forms
            if '<form' in body:
                self.profile.has_forms = True
                self.profile.has_auth = True  # Forms usually mean auth

            # File upload
            if 'type="file"' in body or 'multipart' in body:
                self.profile.has_upload = True

            # JS frontend
            if any(fw in body for fw in ['react', 'angular', 'vue', 'next', 'nuxt', 'svelte', 'webpack', 'vite']):
                self.profile.has_js_frontend = True
                self._log("Detected JS frontend framework")

            # OAuth indicators
            if any(kw in body for kw in ['oauth', 'openid', 'sign in with google', 'sign in with facebook', 'login with github']):
                self.profile.has_oauth = True
                self._log("Detected OAuth/SSO indicators")

            # JWT indicators
            if 'jwt' in body or 'bearer' in body or 'eyj' in body:
                self.profile.has_jwt = True
                self._log("Detected JWT indicators")

            # WebSocket
            if 'websocket' in body or 'ws://' in body or 'wss://' in body or 'socket.io' in body:
                self.profile.has_websocket = True
                self._log("Detected WebSocket indicators")

            # XML
            if 'application/xml' in body or 'text/xml' in body or 'soap' in body:
                self.profile.has_xml = True

            # URL params
            if '?' in body and '=' in body:
                self.profile.has_url_params = True

            # CDN/Proxy detection from headers
            headers_str = resp.body[:2000]  # approximation
            if any(cdn in body for cdn in ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'incapsula']):
                self.profile.has_cdn = True
                self.profile.has_proxy = True
                self._log("Detected CDN/proxy")

            # API indicators
            if any(kw in body for kw in ['/api/', 'api-key', 'apikey', 'x-api-key', 'swagger', 'openapi']):
                self.profile.has_api = True
                self.profile.has_json_body = True
                self._log("Detected API indicators")

        except Exception as e:
            self._log(f"Main page probe failed: {e}")

    def _probe_graphql(self, base_url: str):
        """Check for GraphQL endpoints."""
        for path in self.GRAPHQL_PATHS:
            try:
                url = f"{base_url}{path}"
                resp = self.http.post(url, json_data={'query': '{__typename}'})
                if resp.ok and ('__typename' in resp.body or 'data' in resp.body or 'errors' in resp.body):
                    self.profile.has_graphql = True
                    self.profile.has_api = True
                    self.profile.has_json_body = True
                    self.profile.discovered_endpoints.append(url)
                    self._log(f"GraphQL endpoint found: {path}")
                    return
            except Exception:
                continue

    def _probe_api(self, base_url: str):
        """Check for REST API endpoints."""
        for path in self.API_PATHS:
            try:
                url = f"{base_url}{path}"
                resp = self.http.get(url)
                if resp.status_code in (200, 301, 302, 401, 403):
                    self.profile.has_api = True
                    self.profile.has_json_body = True
                    self.profile.discovered_endpoints.append(url)
                    self._log(f"API endpoint found: {path} ({resp.status_code})")

                    # Check for gateway patterns
                    if resp.status_code == 401 or 'x-amzn-apigateway' in resp.body.lower() or 'kong' in resp.body.lower():
                        self.profile.has_gateway = True

                    return
            except Exception:
                continue

    def _probe_cloud(self, base_url: str):
        """Detect cloud service usage."""
        try:
            resp = self.http.get(base_url)
            if not resp.ok:
                return

            body = resp.body.lower()

            # AWS
            if any(kw in body for kw in ['amazonaws.com', 's3.amazonaws', 'aws', 'cloudfront']):
                self.profile.has_aws = True
                if 's3' in body or 's3.amazonaws' in body:
                    self.profile.has_s3 = True
                self._log("Detected AWS indicators")

            # Azure
            if any(kw in body for kw in ['azure', 'blob.core.windows.net', 'azurewebsites.net', 'microsoft']):
                self.profile.has_azure = True
                self._log("Detected Azure indicators")

            # GCP
            if any(kw in body for kw in ['googleapis.com', 'storage.googleapis', 'appspot.com', 'firebase']):
                self.profile.has_gcp = True
                self._log("Detected GCP indicators")

            # SSRF candidates (URL params with URLs as values)
            if any(kw in body for kw in ['url=', 'redirect=', 'next=', 'dest=', 'target=', 'return=', 'callback=']):
                self.profile.has_ssrf_candidate = True
                self.profile.has_url_params = True

        except Exception:
            pass

    def _check_recon_cache(self):
        """Check if we have cached recon data for this target."""
        try:
            from engine.core.recon_cache import ReconCache
            cache = ReconCache(self.target)

            # Check for cached subdomains
            subs = cache.get('subdomain')
            if subs and len(subs) > 0:
                self.profile.has_subdomains = True
                self._log(f"Found {len(subs)} cached subdomains")

        except Exception:
            pass

    def update_from_discovery(self, key: str, value: Any):
        """Update profile as new info is discovered during the hunt.

        Called by the hunt executor when discovery agents find things.
        E.g., JS analyzer finds JWT -> set has_jwt=True
        """
        trigger_map = {
            'graphql_endpoint': 'has_graphql',
            'jwt_token': 'has_jwt',
            'oauth_flow': 'has_oauth',
            'websocket': 'has_websocket',
            'grpc_endpoint': 'has_grpc',
            'upload_form': 'has_upload',
            'xml_endpoint': 'has_xml',
            'ldap_service': 'has_ldap',
            'mfa_flow': 'has_mfa',
            'role_system': 'has_roles',
            'api_gateway': 'has_gateway',
            's3_bucket': 'has_s3',
            'azure_blob': 'has_azure',
            'gcp_storage': 'has_gcp',
            'file_param': 'has_file_params',
            'ssrf_candidate': 'has_ssrf_candidate',
        }

        trigger = trigger_map.get(key)
        if trigger:
            self.profile.set_trigger(trigger, True)
            self._log(f"Profile updated: {trigger} = True (from {key})")

    def run(self) -> TargetProfile:
        """Run all profiling probes and return the complete profile."""
        self._log(f"Profiling target: {self.target}")
        self._detect_target_type()
        self._log(f"Profile complete: {len(self.profile.triggers)} triggers active")
        return self.profile
