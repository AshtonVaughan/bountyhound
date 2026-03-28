"""API Key Scanner — detect leaked API keys and secrets in HTTP response bodies."""

from __future__ import annotations

import logging
import re
from typing import Any

from models import Flow, PassiveFinding

log = logging.getLogger("proxy-engine.ext.api-key-scanner")

NAME = "api-key-scanner"
DESCRIPTION = "Detect 30+ API key/secret patterns in response bodies (AWS, Google, Stripe, GitHub, etc.)"
CHECK_TYPE = "passive"
ENABLED = False

_config: dict[str, Any] = {}

# ── API key patterns ────────────────────────────────────────────────────────
# Each entry: (name, regex_pattern, severity)
API_KEY_PATTERNS: list[tuple[str, str, str]] = [
    # AWS
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Access Key", r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=\"']+([A-Za-z0-9/+=]{40})", "critical"),
    ("AWS MWS Auth Token", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "critical"),

    # Google
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Google OAuth Token", r"ya29\.[0-9A-Za-z\-_]+", "high"),
    ("Google Cloud Platform Key", r"(?i)google[_\-]?cloud[_\-]?key[\s:=\"']+([A-Za-z0-9\-_]{20,})", "high"),
    ("Firebase API Key", r"(?i)firebase[\s:=\"']+AIza[0-9A-Za-z\-_]{35}", "high"),

    # Stripe
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "critical"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", "medium"),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}", "critical"),

    # GitHub
    ("GitHub Personal Access Token", r"ghp_[0-9a-zA-Z]{36}", "critical"),
    ("GitHub OAuth Access Token", r"gho_[0-9a-zA-Z]{36}", "critical"),
    ("GitHub App Token", r"ghs_[0-9a-zA-Z]{36}", "high"),
    ("GitHub Fine-Grained Token", r"github_pat_[0-9a-zA-Z_]{22,}", "critical"),
    ("GitHub Classic Token", r"ghp_[A-Za-z0-9]{36}", "critical"),

    # Slack
    ("Slack Bot Token", r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}", "critical"),
    ("Slack User Token", r"xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}", "critical"),
    ("Slack Webhook URL", r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{24}", "high"),
    ("Slack OAuth Token", r"xoxa-[0-9]{10,}-[a-zA-Z0-9]{24,}", "critical"),

    # Twilio
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high"),
    ("Twilio Account SID", r"AC[0-9a-fA-F]{32}", "medium"),

    # SendGrid
    ("SendGrid API Key", r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", "critical"),

    # Mailgun
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "high"),

    # DigitalOcean
    ("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "critical"),
    ("DigitalOcean OAuth", r"doo_v1_[a-f0-9]{64}", "critical"),

    # Heroku
    ("Heroku API Key", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "medium"),

    # NPM
    ("NPM Access Token", r"npm_[A-Za-z0-9]{36}", "high"),

    # PyPI
    ("PyPI API Token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}", "high"),

    # Azure
    ("Azure Storage Key", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical"),
    ("Azure AD Client Secret", r"(?i)azure[_\-]?client[_\-]?secret[\s:=\"']+([A-Za-z0-9~.\-_]{34,})", "critical"),

    # Shopify
    ("Shopify Private App Token", r"shppa_[a-fA-F0-9]{32}", "high"),
    ("Shopify Access Token", r"shpat_[a-fA-F0-9]{32}", "high"),
    ("Shopify Custom App Token", r"shpca_[a-fA-F0-9]{32}", "high"),
    ("Shopify Shared Secret", r"shpss_[a-fA-F0-9]{32}", "high"),

    # Square
    ("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", "high"),
    ("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43}", "critical"),

    # Discord
    ("Discord Bot Token", r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}", "critical"),
    ("Discord Webhook URL", r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9\-_]{60,}", "high"),

    # Telegram
    ("Telegram Bot Token", r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "high"),

    # Twitter
    ("Twitter Bearer Token", r"AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}", "high"),
    ("Twitter API Key", r"(?i)twitter[_\-]?api[_\-]?key[\s:=\"']+([A-Za-z0-9]{25})", "high"),

    # Facebook
    ("Facebook Access Token", r"EAA[0-9A-Za-z]{100,}", "high"),
    ("Facebook App Secret", r"(?i)facebook[_\-]?(?:app[_\-]?)?secret[\s:=\"']+([0-9a-f]{32})", "critical"),

    # Mailchimp
    ("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "high"),

    # Private Keys
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical"),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical"),
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical"),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical"),
    ("SSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical"),

    # JWT
    ("JWT Token", r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "medium"),

    # Generic
    ("Generic API Key", r"(?i)(?:api[_\-]?key|apikey|api_secret|api_token)[\s:=\"']+([A-Za-z0-9\-_]{20,})", "medium"),
    ("Generic Secret", r"(?i)(?:secret|password|passwd|pwd|token)[\s]*[:=][\s]*['\"]([^'\"]{8,})['\"]", "medium"),
    ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}", "medium"),
]

# Compiled patterns for performance
_compiled_patterns: list[tuple[str, re.Pattern, str]] = []


def _ensure_compiled() -> None:
    """Compile patterns once on first use."""
    global _compiled_patterns
    if not _compiled_patterns:
        for name, pattern, severity in API_KEY_PATTERNS:
            try:
                _compiled_patterns.append((name, re.compile(pattern), severity))
            except re.error as e:
                log.debug(f"Failed to compile pattern '{name}': {e}")


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config, "pattern_count": len(API_KEY_PATTERNS)}


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Scan response body for API key patterns."""
    if not flow.response or not flow.response.body:
        return []

    # Skip binary/media responses
    ct = flow.response.headers.get("content-type", "")
    if any(t in ct for t in ["image/", "video/", "audio/", "font/", "application/octet-stream"]):
        return []

    _ensure_compiled()

    findings: list[PassiveFinding] = []
    body = flow.response.body[:100000]  # Limit scan to first 100KB
    seen: set[str] = set()  # Deduplicate within same response

    for name, pattern, severity in _compiled_patterns:
        try:
            matches = pattern.findall(body)
            for match in matches:
                # Get the actual matched string
                if isinstance(match, tuple):
                    match_str = match[0]
                else:
                    match_str = match

                # Skip short or common false positives
                if len(match_str) < 8:
                    continue

                dedup_key = f"{name}:{match_str[:30]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Mask the key for safe display
                if len(match_str) > 10:
                    masked = match_str[:6] + "..." + match_str[-4:]
                else:
                    masked = match_str[:4] + "..." + match_str[-2:]

                findings.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id=f"api-key-{name.lower().replace(' ', '-')}",
                    name=f"Exposed {name}",
                    severity=severity,
                    description=(
                        f"Detected {name} in HTTP response body. "
                        f"Leaked credentials can lead to account takeover or data breach."
                    ),
                    evidence=f"Pattern: {name} | Match: {masked}",
                    url=flow.request.url,
                ))

        except Exception as e:
            log.debug(f"Pattern match error ({name}): {e}")

    return findings
