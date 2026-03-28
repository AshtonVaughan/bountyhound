"""Subdomain Takeover — check CNAME records for dangling references to claimable services."""

from __future__ import annotations

import logging
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.subdomain-takeover")

NAME = "subdomain-takeover"
DESCRIPTION = "Resolve CNAME records and check for dangling references to claimable cloud services"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10.0,
}

# Service fingerprints: (cname_pattern, http_fingerprint, service_name)
VULNERABLE_SERVICES: list[tuple[str, list[str], str]] = [
    # GitHub Pages
    (".github.io", [
        "There isn't a GitHub Pages site here.",
        "For root URLs (like http://example.com/) you must provide an index.html file",
    ], "GitHub Pages"),

    # Heroku
    (".herokuapp.com", [
        "No such app",
        "no-such-app",
        "herokucdn.com/error-pages/no-such-app.html",
    ], "Heroku"),
    (".herokudns.com", [
        "No such app",
    ], "Heroku DNS"),

    # AWS S3
    (".s3.amazonaws.com", [
        "NoSuchBucket",
        "The specified bucket does not exist",
    ], "AWS S3"),
    (".s3-website", [
        "NoSuchBucket",
        "The specified bucket does not exist",
    ], "AWS S3 Website"),

    # AWS Elastic Beanstalk
    (".elasticbeanstalk.com", [
        "NXDOMAIN",
    ], "AWS Elastic Beanstalk"),

    # Azure
    (".azurewebsites.net", [
        "404 Web Site not found",
        "Web App - Pair Unavailable",
    ], "Azure Web Apps"),
    (".cloudapp.net", [
        "NXDOMAIN",
    ], "Azure CloudApp"),
    (".cloudapp.azure.com", [
        "NXDOMAIN",
    ], "Azure CloudApp"),
    (".azurefd.net", [
        "Our services aren't available right now",
        "404",
    ], "Azure Front Door"),
    (".blob.core.windows.net", [
        "BlobNotFound",
        "The specified blob does not exist",
    ], "Azure Blob Storage"),
    (".trafficmanager.net", [
        "NXDOMAIN",
    ], "Azure Traffic Manager"),

    # Shopify
    (".myshopify.com", [
        "Sorry, this shop is currently unavailable",
        "Only one step left!",
    ], "Shopify"),

    # Fastly
    (".fastly.net", [
        "Fastly error: unknown domain",
        "Fastly - Unknown Domain",
    ], "Fastly"),

    # Pantheon
    (".pantheonsite.io", [
        "404 error unknown site!",
        "The gods are wise",
    ], "Pantheon"),

    # Tumblr
    (".tumblr.com", [
        "Whatever you were looking for doesn't currently exist at this address",
        "There's nothing here.",
    ], "Tumblr"),

    # WordPress
    (".wordpress.com", [
        "Do you want to register",
    ], "WordPress.com"),

    # Surge
    (".surge.sh", [
        "project not found",
    ], "Surge.sh"),

    # Bitbucket
    (".bitbucket.io", [
        "Repository not found",
    ], "Bitbucket"),

    # Ghost
    (".ghost.io", [
        "The thing you were looking for is no longer here",
    ], "Ghost"),

    # Fly.io
    (".fly.dev", [
        "404 Not Found",
    ], "Fly.io"),

    # Netlify
    (".netlify.app", [
        "Not Found - Request ID",
    ], "Netlify"),
    (".netlify.com", [
        "Not Found - Request ID",
    ], "Netlify"),

    # Vercel
    (".vercel.app", [
        "DEPLOYMENT_NOT_FOUND",
    ], "Vercel"),

    # Cargo Collective
    (".cargocollective.com", [
        "404 Not Found",
    ], "Cargo Collective"),

    # Zendesk
    (".zendesk.com", [
        "Help Center Closed",
    ], "Zendesk"),

    # Unbounce
    (".unbouncepages.com", [
        "The requested URL was not found on this server",
    ], "Unbounce"),

    # Agile CRM
    (".agilecrm.com", [
        "Sorry, this page is no longer available",
    ], "Agile CRM"),

    # Tilda
    (".tilda.ws", [
        "Please renew your subscription",
    ], "Tilda"),
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config, "services_checked": len(VULNERABLE_SERVICES)}


def _resolve_cname(hostname: str) -> str | None:
    """Resolve CNAME record for a hostname."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except ImportError:
        # Fallback: use socket to check if host resolves
        log.debug("dnspython not installed; using socket fallback for CNAME checks")
        return _resolve_cname_socket(hostname)
    except Exception:
        return None


def _resolve_cname_socket(hostname: str) -> str | None:
    """Fallback CNAME check using socket module."""
    try:
        result = socket.getaddrinfo(hostname, None)
        if result:
            # Can't get actual CNAME from socket, but we can check if it resolves
            return None
    except socket.gaierror:
        # NXDOMAIN — this itself could indicate a takeover
        return "NXDOMAIN"
    return None


def _check_nxdomain(hostname: str) -> bool:
    """Check if hostname returns NXDOMAIN."""
    try:
        socket.getaddrinfo(hostname, None)
        return False
    except socket.gaierror:
        return True


async def active_check(url: str) -> list[ScanFinding]:
    """Check for subdomain takeover vulnerabilities."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 10.0)
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return findings

    # Skip IP addresses
    try:
        socket.inet_aton(hostname)
        return findings  # It's an IP, not a hostname
    except socket.error:
        pass

    # Resolve CNAME
    cname = _resolve_cname(hostname)

    # Also check NXDOMAIN for the hostname itself
    is_nxdomain = _check_nxdomain(hostname)

    if cname:
        log.debug(f"CNAME for {hostname}: {cname}")

        for cname_pattern, fingerprints, service_name in VULNERABLE_SERVICES:
            if cname_pattern in cname.lower():
                # Found a CNAME pointing to a potentially vulnerable service
                # Check if the service returns a "not found" fingerprint
                cname_nxdomain = _check_nxdomain(cname)

                if cname_nxdomain:
                    findings.append(ScanFinding(
                        template_id="subdomain_takeover_nxdomain",
                        name=f"Subdomain Takeover: {service_name} (NXDOMAIN)",
                        severity="high",
                        url=url,
                        matched_at=url,
                        description=(
                            f"CNAME for '{hostname}' points to '{cname}' ({service_name}) "
                            "which returns NXDOMAIN. The service has been deleted/unclaimed. "
                            "An attacker can claim this service name and serve content on this subdomain."
                        ),
                        extracted=[
                            f"Hostname: {hostname}",
                            f"CNAME: {cname}",
                            f"Service: {service_name}",
                            "Status: NXDOMAIN (unclaimed)",
                        ],
                        source="extension",
                        confidence="confirmed",
                        remediation=(
                            f"Remove the dangling CNAME record for '{hostname}' or "
                            f"reclaim the {service_name} resource at '{cname}'."
                        ),
                    ))
                    continue

                # Check HTTP fingerprint
                try:
                    async with httpx.AsyncClient(
                        verify=False, timeout=timeout, follow_redirects=True
                    ) as client:
                        resp = await client.get(url)
                        body = resp.text[:5000]

                        for fingerprint in fingerprints:
                            if fingerprint.lower() in body.lower():
                                findings.append(ScanFinding(
                                    template_id="subdomain_takeover_fingerprint",
                                    name=f"Subdomain Takeover: {service_name}",
                                    severity="high",
                                    url=url,
                                    matched_at=url,
                                    description=(
                                        f"CNAME for '{hostname}' points to '{cname}' ({service_name}). "
                                        f"Response contains takeover fingerprint: '{fingerprint}'. "
                                        "This subdomain can likely be claimed by an attacker."
                                    ),
                                    extracted=[
                                        f"Hostname: {hostname}",
                                        f"CNAME: {cname}",
                                        f"Service: {service_name}",
                                        f"Fingerprint: {fingerprint}",
                                    ],
                                    source="extension",
                                    confidence="firm",
                                    remediation=(
                                        f"Remove the dangling CNAME record or reclaim the "
                                        f"{service_name} resource."
                                    ),
                                ))
                                break

                except Exception as e:
                    log.debug(f"HTTP fingerprint check error for {hostname}: {e}")

    elif is_nxdomain:
        # Hostname itself is NXDOMAIN — possible stale DNS
        findings.append(ScanFinding(
            template_id="subdomain_nxdomain",
            name="Subdomain: NXDOMAIN (Possible Stale DNS)",
            severity="info",
            url=url,
            matched_at=url,
            description=(
                f"Hostname '{hostname}' returns NXDOMAIN. If this is a subdomain with "
                "a DNS record (A/AAAA/CNAME), the target resource may be unclaimed."
            ),
            extracted=[f"Hostname: {hostname}", "Status: NXDOMAIN"],
            source="extension",
            confidence="tentative",
            remediation="Investigate DNS records for stale entries. Remove unused subdomains.",
        ))

    return findings
