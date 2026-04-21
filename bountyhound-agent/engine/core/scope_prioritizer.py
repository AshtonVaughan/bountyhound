"""
Scope Prioritizer - Prioritize in-scope assets by expected bounty payout.

Ranks endpoints and targets so that high-ROI items are tested first, using
a combination of asset-type heuristics and historical database statistics.

Usage:
    from engine.core.scope_prioritizer import ScopePrioritizer

    sp = ScopePrioritizer()
    ranked = sp.prioritize_endpoints([
        {'url': 'https://api.example.com/graphql', 'method': 'POST', 'asset_type': 'api', 'auth_required': True},
        {'url': 'https://example.com/docs', 'method': 'GET', 'asset_type': 'documentation', 'auth_required': False},
    ])
"""

import re
from datetime import datetime
from typing import Dict, List, Optional

from engine.core.config import BountyHoundConfig
from engine.core.database import BountyHoundDB


class ScopePrioritizer:
    """Prioritize testing targets based on bounty tables and historical ROI."""

    def __init__(self):
        # Standard bounty-table ranges keyed by asset type.
        # priority: lower is better (tested first).
        # typical_bounty: approximate median payout in USD.
        # vuln_density: qualitative estimate of how many vulns tend to live here.
        self.asset_priorities: Dict[str, Dict] = {
            'api': {
                'priority': 1,
                'typical_bounty': 5000,
                'vuln_density': 'high',
            },
            'web_app': {
                'priority': 2,
                'typical_bounty': 3000,
                'vuln_density': 'high',
            },
            'mobile_api': {
                'priority': 3,
                'typical_bounty': 4000,
                'vuln_density': 'medium',
            },
            'admin_panel': {
                'priority': 4,
                'typical_bounty': 8000,
                'vuln_density': 'high',
            },
            'auth_endpoint': {
                'priority': 5,
                'typical_bounty': 10000,
                'vuln_density': 'medium',
            },
            'payment_flow': {
                'priority': 6,
                'typical_bounty': 15000,
                'vuln_density': 'low',
            },
            'static_site': {
                'priority': 10,
                'typical_bounty': 200,
                'vuln_density': 'very_low',
            },
            'documentation': {
                'priority': 11,
                'typical_bounty': 0,
                'vuln_density': 'none',
            },
        }

        # Vuln-density multipliers applied to the base score
        self._density_multiplier: Dict[str, float] = {
            'high': 1.5,
            'medium': 1.0,
            'low': 0.6,
            'very_low': 0.2,
            'none': 0.0,
        }

    # ------------------------------------------------------------------
    # Endpoint prioritization
    # ------------------------------------------------------------------

    def prioritize_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Sort endpoints by expected bounty value.

        Each endpoint dict should contain:
            url (str): Full URL.
            method (str): HTTP method (GET, POST, etc.).
            asset_type (str): One of the keys in self.asset_priorities.
            auth_required (bool): Whether the endpoint requires authentication.

        Additional optional fields are preserved and passed through.

        Returns:
            A new list of endpoint dicts sorted by descending priority_score,
            each augmented with:
                priority_score (float): Numeric score (higher = test first).
                priority_reason (str): Human-readable explanation.
        """
        scored: List[Dict] = []

        for ep in endpoints:
            score, reasons = self._score_endpoint(ep)
            enriched = dict(ep)  # shallow copy to avoid mutating input
            enriched['priority_score'] = round(score, 2)
            enriched['priority_reason'] = '; '.join(reasons)
            scored.append(enriched)

        # Sort descending by score (highest score = test first)
        scored.sort(key=lambda e: e['priority_score'], reverse=True)
        return scored

    def _score_endpoint(self, ep: Dict) -> tuple:
        """Return (score, list_of_reasons) for a single endpoint."""
        reasons: List[str] = []

        # --- Base score from asset type ---
        asset_type = ep.get('asset_type', 'web_app')
        asset_info = self.asset_priorities.get(asset_type, self.asset_priorities['web_app'])
        # Invert priority number so lower priority num -> higher base score
        base_score = max(0, (12 - asset_info['priority'])) * 10  # 10-110 range
        density = self._density_multiplier.get(asset_info['vuln_density'], 1.0)
        base_score *= density
        reasons.append(f"Asset type '{asset_type}' (base {base_score:.0f})")

        score = base_score

        # --- Bonus: auth-related endpoints (+20) ---
        url_lower = ep.get('url', '').lower()
        if ep.get('auth_required', False) or _is_auth_related(url_lower):
            score += 20
            reasons.append("Auth-related (+20)")

        # --- Bonus: endpoints with query parameters (+10) ---
        if '?' in ep.get('url', '') or '=' in ep.get('url', ''):
            score += 10
            reasons.append("Has parameters (+10)")

        # --- Bonus: state-changing methods (+15) ---
        method = ep.get('method', 'GET').upper()
        if method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            score += 15
            reasons.append(f"State-changing method {method} (+15)")

        # --- Penalty: static assets (-30) ---
        if _is_static_asset(url_lower):
            score -= 30
            reasons.append("Static asset (-30)")

        return score, reasons

    # ------------------------------------------------------------------
    # Target prioritization (uses DB history)
    # ------------------------------------------------------------------

    def prioritize_targets(self, targets: List[Dict]) -> List[Dict]:
        """
        Prioritize multiple targets by historical ROI from the database.

        Each target dict should contain:
            domain (str): Target domain.
            program (str): Bug bounty program name.
            max_bounty (float): Maximum advertised bounty.

        Returns:
            New list sorted by descending roi_score, each augmented with:
                roi_score (float): Combined score.
                recommendation (str): Human-readable recommendation.
        """
        scored: List[Dict] = []

        try:
            db = BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)
        except Exception:
            # If DB is unavailable, fall back to max_bounty sorting
            for t in targets:
                enriched = dict(t)
                enriched['roi_score'] = t.get('max_bounty', 0)
                enriched['recommendation'] = 'DB unavailable — sorted by max_bounty'
                scored.append(enriched)
            scored.sort(key=lambda t: t['roi_score'], reverse=True)
            return scored

        for t in targets:
            domain = t.get('domain', '')
            max_bounty = t.get('max_bounty', 0)
            roi_score = 0.0
            rec_parts: List[str] = []

            stats = db.get_target_stats(domain)
            if stats:
                total_payouts = stats.get('total_payouts', 0) or 0
                accepted = stats.get('accepted_findings', 0) or 0
                total_findings = stats.get('total_findings', 0) or 0
                acceptance_rate = (
                    accepted / total_findings if total_findings > 0 else 0
                )

                # Historical payout weight
                roi_score += total_payouts * 0.5
                # Acceptance rate weight
                roi_score += acceptance_rate * max_bounty * 0.3
                # Max bounty weight (for new or untested targets)
                roi_score += max_bounty * 0.2

                if acceptance_rate > 0.5:
                    rec_parts.append(
                        f"High acceptance rate ({acceptance_rate:.0%})"
                    )
                if total_payouts > 0:
                    rec_parts.append(f"${total_payouts:,.0f} earned historically")
                if total_findings == 0:
                    rec_parts.append("Never tested — explore thoroughly")
            else:
                # No history at all — weigh by max bounty
                roi_score = max_bounty * 0.4
                rec_parts.append("New target — no historical data")

            enriched = dict(t)
            enriched['roi_score'] = round(roi_score, 2)
            enriched['recommendation'] = '; '.join(rec_parts) if rec_parts else 'Standard priority'
            scored.append(enriched)

        scored.sort(key=lambda t: t['roi_score'], reverse=True)
        return scored

    # ------------------------------------------------------------------
    # Endpoint classification
    # ------------------------------------------------------------------

    @staticmethod
    def classify_endpoint(url: str, method: str = 'GET') -> str:
        """
        Classify an endpoint into an asset_type based on URL patterns.

        Returns one of: 'api', 'admin_panel', 'auth_endpoint',
        'payment_flow', 'documentation', 'static_site', 'web_app'.
        """
        url_lower = url.lower()

        # Order matters — more specific patterns first
        if any(p in url_lower for p in ('/graphql', '/api/', '/api?', '/v1/', '/v2/', '/v3/')):
            return 'api'
        if any(p in url_lower for p in ('/admin', '/dashboard', '/manage', '/internal')):
            return 'admin_panel'
        if any(p in url_lower for p in (
            '/auth', '/login', '/signup', '/signin', '/register',
            '/oauth', '/sso', '/saml', '/token', '/session',
        )):
            return 'auth_endpoint'
        if any(p in url_lower for p in (
            '/payment', '/checkout', '/billing', '/subscribe',
            '/purchase', '/cart', '/order',
        )):
            return 'payment_flow'
        if any(p in url_lower for p in ('/docs', '/help', '/faq', '/support', '/wiki')):
            return 'documentation'
        if _is_static_asset(url_lower):
            return 'static_site'

        return 'web_app'

    # ------------------------------------------------------------------
    # Focus suggestion
    # ------------------------------------------------------------------

    def suggest_focus(self, endpoints: List[str]) -> str:
        """
        Given a list of discovered endpoint URLs, suggest what to focus on first.

        Returns a formatted text recommendation.
        """
        if not endpoints:
            return "No endpoints provided. Run recon first."

        classified: Dict[str, List[str]] = {}
        for url in endpoints:
            asset_type = self.classify_endpoint(url)
            classified.setdefault(asset_type, []).append(url)

        lines: List[str] = []
        lines.append("=== Focus Recommendation ===")
        lines.append("")

        # Sort asset types by priority (lower number = test first)
        type_order = sorted(
            classified.keys(),
            key=lambda t: self.asset_priorities.get(t, {}).get('priority', 99),
        )

        for rank, asset_type in enumerate(type_order, start=1):
            urls = classified[asset_type]
            info = self.asset_priorities.get(asset_type, {})
            bounty = info.get('typical_bounty', 0)
            density = info.get('vuln_density', 'unknown')
            lines.append(
                f"{rank}. {asset_type.upper()} ({len(urls)} endpoints) "
                f"— ~${bounty:,} avg bounty, {density} vuln density"
            )
            # Show up to 3 sample URLs
            for url in urls[:3]:
                lines.append(f"   - {url}")
            if len(urls) > 3:
                lines.append(f"   ... and {len(urls) - 3} more")
            lines.append("")

        skip_types = {'static_site', 'documentation'}
        skip_count = sum(len(classified.get(t, [])) for t in skip_types)
        if skip_count > 0:
            lines.append(
                f"SKIP: {skip_count} static/docs endpoints (low value)"
            )

        return "\n".join(lines)


# ------------------------------------------------------------------
# Module-level helpers (private)
# ------------------------------------------------------------------

def _is_auth_related(url_lower: str) -> bool:
    """Check if a URL is related to authentication."""
    auth_patterns = (
        '/auth', '/login', '/signup', '/signin', '/register',
        '/oauth', '/sso', '/token', '/session', '/password',
        '/2fa', '/mfa', '/totp', '/verify',
    )
    return any(p in url_lower for p in auth_patterns)


def _is_static_asset(url_lower: str) -> bool:
    """Check if a URL points to a static asset."""
    static_extensions = (
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
    )
    # Strip query string before checking extension
    path = url_lower.split('?')[0]
    return path.endswith(static_extensions)
