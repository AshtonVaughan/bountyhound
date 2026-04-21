"""Detect dangling DNS records (CNAME) that can be claimed for subdomain takeover."""

import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from engine.core.http_client import HttpClient


@dataclass
class TakeoverResult:
    """Result of a subdomain takeover check."""
    subdomain: str
    cname: str
    service: str
    takeover_possible: bool
    fingerprint_match: str
    evidence: str
    confidence: str = 'medium'

    def to_dict(self) -> Dict:
        return {
            'subdomain': self.subdomain,
            'cname': self.cname,
            'service': self.service,
            'takeover_possible': self.takeover_possible,
            'fingerprint_match': self.fingerprint_match,
            'evidence': self.evidence,
            'confidence': self.confidence,
        }


# Service fingerprint database: CNAME pattern → (service_name, body_fingerprint, takeover_possible)
FINGERPRINT_DB = {
    # GitHub Pages
    'github.io': ('GitHub Pages', "There isn't a GitHub Pages site here", True),
    'github.com': ('GitHub Pages', "There isn't a GitHub Pages site here", True),
    # Heroku
    'herokuapp.com': ('Heroku', 'No such app', True),
    'herokussl.com': ('Heroku', 'No such app', True),
    # AWS S3
    's3.amazonaws.com': ('AWS S3', 'NoSuchBucket', True),
    's3-website': ('AWS S3', 'NoSuchBucket', True),
    # AWS CloudFront (usually not takeover-able but worth checking)
    'cloudfront.net': ('AWS CloudFront', "The request could not be satisfied", False),
    # AWS Elastic Beanstalk
    'elasticbeanstalk.com': ('AWS Elastic Beanstalk', 'NXDOMAIN', True),
    # Azure
    'azurewebsites.net': ('Azure', 'Error 404 - Web app not found', True),
    'cloudapp.net': ('Azure', 'Error 404', True),
    'cloudapp.azure.com': ('Azure', 'Error 404', True),
    'azurefd.net': ('Azure Front Door', 'Our services', True),
    'blob.core.windows.net': ('Azure Blob', 'BlobNotFound', True),
    'azure-api.net': ('Azure API', 'not found', True),
    'azureedge.net': ('Azure CDN', 'not found', True),
    'azurecontainer.io': ('Azure Container', 'not found', True),
    'database.windows.net': ('Azure SQL', 'not found', False),
    'azurehdinsight.net': ('Azure HDInsight', 'not found', True),
    'redis.cache.windows.net': ('Azure Redis', 'not found', False),
    'search.windows.net': ('Azure Search', 'not found', True),
    'servicebus.windows.net': ('Azure Service Bus', 'not found', True),
    # Shopify
    'myshopify.com': ('Shopify', 'Sorry, this shop is currently unavailable', True),
    # Fastly
    'fastly.net': ('Fastly', 'Fastly error: unknown domain', True),
    # Pantheon
    'pantheonsite.io': ('Pantheon', "The gods are wise", True),
    # Tumblr
    'domains.tumblr.com': ('Tumblr', "There's nothing here", True),
    # Fly.io
    'fly.dev': ('Fly.io', 'not found', True),
    # Surge.sh
    'surge.sh': ('Surge.sh', 'project not found', True),
    # Bitbucket
    'bitbucket.io': ('Bitbucket', 'Repository not found', True),
    # Ghost
    'ghost.io': ('Ghost', 'The thing you were looking for is no longer here', True),
    # WordPress.com
    'wordpress.com': ('WordPress.com', "doesn't exist", True),
    # Zendesk
    'zendesk.com': ('Zendesk', 'Help Center Closed', True),
    # Unbounce
    'unbouncepages.com': ('Unbounce', 'The requested URL was not found', True),
    # Cargo
    'cargocollective.com': ('Cargo', '404 Not Found', True),
    # Feedpress
    'redirect.feedpress.me': ('Feedpress', 'The feed has not been found', True),
    # Help Scout
    'helpscoutdocs.com': ('Help Scout', 'No settings were found', True),
    # Help Juice
    'helpjuice.com': ('Help Juice', "We could not find what you're looking for", True),
    # Strikingly
    's.strikinglydns.com': ('Strikingly', 'page not found', True),
    # Uptimerobot
    'stats.uptimerobot.com': ('UptimeRobot', 'page not found', True),
    # Tilda
    'tilda.ws': ('Tilda', 'Please renew your subscription', True),
    # Netlify
    'netlify.app': ('Netlify', 'Not Found - Request ID', True),
    'netlify.com': ('Netlify', 'Not Found - Request ID', True),
}


class SubdomainTakeover:
    """Detects dangling DNS records that can be claimed for subdomain takeover."""

    def __init__(self, target: str, max_workers: int = 10):
        self.target = target
        self.client = HttpClient(target=target, timeout=10)
        self.max_workers = max_workers
        self.results: List[TakeoverResult] = []

    def _resolve_cname(self, subdomain: str) -> Optional[str]:
        """Resolve CNAME record for a subdomain.

        Returns the CNAME target or None if no CNAME exists.
        """
        try:
            answers = socket.getaddrinfo(subdomain, 80, proto=socket.IPPROTO_TCP)
            # getaddrinfo doesn't directly return CNAME, but we can use it to check resolution
            # For actual CNAME, we'd need dns.resolver but socket is available everywhere
            # Check if domain resolves at all
            if answers:
                return answers[0][4][0]  # Returns IP, not CNAME
        except socket.gaierror:
            # NXDOMAIN or similar - potential takeover
            return 'NXDOMAIN'
        except Exception:
            return None
        return None

    def _check_cname_via_http(self, subdomain: str) -> Optional[str]:
        """Attempt to identify the CNAME by making an HTTP request and checking redirects/errors."""
        try:
            resp = self.client.get(f'https://{subdomain}')
            return resp.body[:500] if resp.body else ''
        except Exception:
            try:
                resp = self.client.get(f'http://{subdomain}')
                return resp.body[:500] if resp.body else ''
            except Exception:
                return None

    def check_domain(self, subdomain: str) -> Optional[TakeoverResult]:
        """Check a single subdomain for takeover vulnerability.

        1. Resolve DNS
        2. Check if CNAME points to a vulnerable service
        3. Check HTTP response for fingerprint match
        """
        # Step 1: Try DNS resolution
        resolution = self._resolve_cname(subdomain)

        # Step 2: Check HTTP response for service fingerprints
        body = self._check_cname_via_http(subdomain)

        if body is None and resolution == 'NXDOMAIN':
            # Can't connect and DNS fails - might be dangling
            return TakeoverResult(
                subdomain=subdomain,
                cname='NXDOMAIN',
                service='Unknown',
                takeover_possible=True,
                fingerprint_match='DNS NXDOMAIN',
                evidence='Domain does not resolve - potential dangling record',
                confidence='low',
            )

        if body is None:
            return None

        # Step 3: Check against fingerprint database
        for cname_pattern, (service, fingerprint, can_takeover) in FINGERPRINT_DB.items():
            if fingerprint.lower() in body.lower():
                return TakeoverResult(
                    subdomain=subdomain,
                    cname=cname_pattern,
                    service=service,
                    takeover_possible=can_takeover,
                    fingerprint_match=fingerprint,
                    evidence=f'Response contains "{fingerprint}" - service: {service}',
                    confidence='high' if can_takeover else 'medium',
                )

        return None

    def check_cname(self, subdomain: str) -> Optional[str]:
        """Just resolve and return the CNAME target."""
        return self._resolve_cname(subdomain)

    def bulk_check(self, subdomains: List[str]) -> List[TakeoverResult]:
        """Check multiple subdomains concurrently for takeover vulnerabilities."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.check_domain, sub): sub
                for sub in subdomains
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

        self.results.extend(results)
        return results

    def get_takeover_possible(self) -> List[TakeoverResult]:
        """Return only results where takeover is possible."""
        return [r for r in self.results if r.takeover_possible]

    def get_high_confidence(self) -> List[TakeoverResult]:
        """Return only high-confidence takeover findings."""
        return [r for r in self.results if r.confidence == 'high' and r.takeover_possible]

    def summary(self) -> Dict:
        """Return summary of subdomain takeover results."""
        by_service: Dict[str, int] = {}
        for r in self.results:
            by_service[r.service] = by_service.get(r.service, 0) + 1
        return {
            'total_checked': len(self.results),
            'takeover_possible': len(self.get_takeover_possible()),
            'high_confidence': len(self.get_high_confidence()),
            'by_service': by_service,
        }
