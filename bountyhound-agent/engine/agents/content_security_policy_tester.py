"""
Content Security Policy Tester Agent

Advanced CSP (Content Security Policy) security testing agent that identifies
misconfigurations and potential security vulnerabilities in CSP implementations.

This agent tests for:
- unsafe-inline and unsafe-eval directives  
- Missing critical directives (script-src, object-src, base-uri)
- Weak sources (http:, *, data:, blob:)
- JSONP endpoint bypass opportunities
- Base-URI bypass exploitation
- Nonce implementation weaknesses
- Wildcard subdomain risks
- Protocol downgrade vulnerabilities

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class CSPSeverity(Enum):
    """CSP vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CSPVulnType(Enum):
    """Types of CSP vulnerabilities."""
    UNSAFE_INLINE = "CSP_UNSAFE_INLINE"
    UNSAFE_EVAL = "CSP_UNSAFE_EVAL"
    MISSING_DIRECTIVE = "CSP_MISSING_DIRECTIVE"
    WEAK_SOURCE = "CSP_WEAK_SOURCE"
    JSONP_BYPASS = "CSP_JSONP_BYPASS"
    BASE_URI_BYPASS = "CSP_BASE_URI_BYPASS"
    STATIC_NONCE = "CSP_STATIC_NONCE"
    WEAK_NONCE = "CSP_WEAK_NONCE"
    WILDCARD_SUBDOMAIN = "CSP_WILDCARD_SUBDOMAIN"
    PROTOCOL_DOWNGRADE = "CSP_PROTOCOL_DOWNGRADE"
    OVERLY_PERMISSIVE = "CSP_OVERLY_PERMISSIVE"


@dataclass
class CSPFinding:
    """Represents a CSP security finding."""
    title: str
    severity: CSPSeverity
    vuln_type: CSPVulnType
    description: str
    endpoint: str
    directive: Optional[str] = None
    source: Optional[str] = None
    csp_raw: Optional[str] = None
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class CSPTestResult:
    """Result from a CSP test."""
    endpoint: str
    has_csp: bool
    csp_header: Optional[str] = None
    csp_meta: Optional[str] = None
    report_only: Optional[str] = None
    directives: Dict[str, List[str]] = field(default_factory=dict)
    is_vulnerable: bool = False
    vulnerability_types: List[CSPVulnType] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        data['vulnerability_types'] = [vt.value for vt in self.vulnerability_types]
        return data


class ContentSecurityPolicyTester:
    """
    Advanced Content Security Policy Tester.

    Performs comprehensive CSP misconfiguration testing including:
    - Dangerous directive detection (unsafe-inline, unsafe-eval)
    - Missing critical directives
    - JSONP endpoint enumeration
    - Base-URI bypass testing
    - Nonce implementation analysis
    - Wildcard subdomain risks

    Usage:
        tester = ContentSecurityPolicyTester(target_url="https://example.com")
        findings = tester.run_all_tests()
    """

    # Known JSONP endpoints that can bypass CSP
    JSONP_ENDPOINTS = {
        'www.google.com': '/complete/search?client=chrome&jsonp={callback}',
        'maps.google.com': '/maps/api/js?callback={callback}',
        'maps.googleapis.com': '/maps/api/js?callback={callback}',
        'cse.google.com': '/api?callback={callback}',
        'accounts.google.com': '/o/oauth2/revoke?callback={callback}',
        'suggest.yandex.com': '/suggest-ff.cgi?callback={callback}',
        'ac.duckduckgo.com': '/ac/?q=test&callback={callback}',
        'api.twitter.com': '/1/statuses/user_timeline.json?callback={callback}',
        'vimeo.com': '/api/v2/video/1.json?callback={callback}',
        'graph.facebook.com': '/?callback={callback}',
    }

    # CDN domains with known XSS gadgets
    CDN_GADGETS = {
        'ajax.googleapis.com': 'AngularJS (ng-app bypass)',
        'cdnjs.cloudflare.com': 'Multiple library gadgets',
        'code.jquery.com': 'jQuery source map XSS',
        'unpkg.com': 'Arbitrary package hosting',
        'jsdelivr.net': 'Arbitrary package hosting',
    }

    def __init__(self, target_url: str, timeout: int = 10,
                 verify_ssl: bool = True, nonce_tests: int = 3):
        """
        Initialize the CSP Tester.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            nonce_tests: Number of requests to test nonce randomness
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.nonce_tests = nonce_tests
        self.findings: List[CSPFinding] = []
        self.test_result: Optional[CSPTestResult] = None

        # Extract domain from target URL
        self.domain = self._extract_domain(target_url)
        self.base_domain = self._extract_base_domain(self.domain)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]

    def _extract_base_domain(self, domain: str) -> Optional[str]:
        """Extract base domain from full domain."""
        if not domain or '.' not in domain:
            return None

        # Remove port if present
        domain_clean = domain.split(':')[0]
        parts = domain_clean.split('.')

        if len(parts) >= 2:
            return '.'.join(parts[-2:])

        return None

    def _fetch_page(self) -> Optional[requests.Response]:
        """Fetch target page."""
        try:
            response = requests.get(
                self.target_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException:
            return None

    def _extract_csp(self, response: requests.Response) -> CSPTestResult:
        """Extract CSP from headers and meta tags."""
        result = CSPTestResult(
            endpoint=self.target_url,
            has_csp=False
        )

        # Check headers (preferred)
        if 'Content-Security-Policy' in response.headers:
            result.csp_header = response.headers['Content-Security-Policy']
            result.has_csp = True

        # Check report-only header
        if 'Content-Security-Policy-Report-Only' in response.headers:
            result.report_only = response.headers['Content-Security-Policy-Report-Only']

        # Check meta tags if BeautifulSoup is available
        if BS4_AVAILABLE and '<meta' in response.text.lower():
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta = soup.find('meta', attrs={'http-equiv': re.compile('Content-Security-Policy', re.I)})

                if meta and meta.get('content'):
                    result.csp_meta = meta['content']
                    if not result.has_csp:
                        result.has_csp = True
            except Exception:
                pass

        # Parse the primary CSP (prefer header over meta)
        csp_to_parse = result.csp_header or result.csp_meta

        if csp_to_parse:
            result.directives = self._parse_csp(csp_to_parse)

        return result

    def _parse_csp(self, csp_string: str) -> Dict[str, List[str]]:
        """Parse CSP string into directive dictionary."""
        directives = {}

        for directive in csp_string.split(';'):
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            directive_name = parts[0]
            sources = parts[1:] if len(parts) > 1 else []

            directives[directive_name] = sources

        return directives
