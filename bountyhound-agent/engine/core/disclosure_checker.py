"""
Disclosure Checker - Check public disclosures to avoid duplicating known findings.

Searches HackerOne hacktivity and public CVE databases so we don't waste time
reporting vulnerabilities that are already publicly known.

Usage:
    from engine.core.disclosure_checker import DisclosureChecker

    dc = DisclosureChecker('example.com')
    hacktivity = dc.check_hacktivity()
    cves = dc.check_known_cves()
    dup = dc.is_likely_duplicate('IDOR in user profile', 'IDOR')
"""

import json
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional


class DisclosureChecker:
    """Check public disclosures to avoid duplicating known findings."""

    def __init__(self, target: str):
        """
        Initialize checker for a specific target.

        Args:
            target: Domain or program name to search for (e.g. 'example.com').
        """
        self.target = target
        self._cache: Dict[str, List[Dict]] = {}  # key -> list of results

    # ------------------------------------------------------------------
    # HackerOne Hacktivity
    # ------------------------------------------------------------------

    def check_hacktivity(self) -> List[Dict]:
        """
        Search HackerOne hacktivity for public disclosures on this target.

        Uses curl to query the public hacktivity search page and attempts
        to parse disclosed reports from the JSON response.

        Returns:
            List of dicts, each containing:
                title (str): Report title.
                severity (str): Severity rating.
                vuln_type (str): Vulnerability type/category.
                disclosed_date (str): Date of disclosure (ISO format or raw).
                bounty (float): Bounty amount (0 if unknown).
                url (str): Link to the disclosed report.

        On network failure or parse errors, returns an empty list
        (graceful degradation).
        """
        cache_key = f"hacktivity:{self.target}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results: List[Dict] = []

        try:
            # HackerOne hacktivity GraphQL endpoint (public, no auth needed)
            query = json.dumps({
                "operationName": "HacktivitySearchQuery",
                "variables": {
                    "queryString": self.target,
                    "size": 25,
                    "from": 0,
                    "orderField": "popular",
                    "orderDirection": "DESC",
                },
                "query": (
                    "query HacktivitySearchQuery("
                    "$queryString: String!, $size: Int, $from: Int, "
                    "$orderField: String, $orderDirection: String"
                    ") { hacktivity_items(query_string: $queryString, "
                    "size: $size, from: $from, order_field: $orderField, "
                    "order_direction: $orderDirection) { "
                    "total_count, nodes { ... on HacktivityItemInterface { "
                    "id, databaseId, title, severity_rating, "
                    "disclosed_at, report { url, substate }, "
                    "total_awarded_amount, "
                    "reporter { username } "
                    "} } } }"
                ),
            })

            proc = subprocess.run(
                [
                    'curl', '-s', '-X', 'POST',
                    'https://hackerone.com/graphql',
                    '-H', 'Content-Type: application/json',
                    '-d', query,
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if proc.returncode != 0:
                self._cache[cache_key] = results
                return results

            data = json.loads(proc.stdout)
            nodes = (
                data.get('data', {})
                .get('hacktivity_items', {})
                .get('nodes', [])
            )

            for node in nodes:
                if not node:
                    continue
                report_url = ''
                report_info = node.get('report')
                if isinstance(report_info, dict):
                    report_url = report_info.get('url', '')

                results.append({
                    'title': node.get('title', ''),
                    'severity': (node.get('severity_rating') or 'unknown').lower(),
                    'vuln_type': _extract_vuln_type(node.get('title', '')),
                    'disclosed_date': node.get('disclosed_at', ''),
                    'bounty': float(node.get('total_awarded_amount') or 0),
                    'url': report_url,
                })

        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
            # Graceful degradation: network issues, parse errors, curl missing
            pass

        self._cache[cache_key] = results
        return results

    # ------------------------------------------------------------------
    # CVE lookup
    # ------------------------------------------------------------------

    def check_known_cves(self) -> List[Dict]:
        """
        Check for known CVEs related to this target's technology stack.

        Uses curl to query the circl.lu public CVE API.

        Returns:
            List of dicts, each containing:
                cve_id (str): CVE identifier (e.g. 'CVE-2024-12345').
                description (str): Short description.
                severity (str): CVSS-based severity or 'unknown'.
                published (str): Publication date.

        On failure, returns an empty list (graceful degradation).
        """
        cache_key = f"cves:{self.target}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results: List[Dict] = []

        # Strip common TLD suffixes to get a cleaner search term
        search_term = self.target.replace('.com', '').replace('.io', '').replace('.org', '')
        search_term = search_term.replace('.net', '').replace('.co', '')
        search_term = search_term.split('.')[0]  # Take the primary name

        if not search_term:
            self._cache[cache_key] = results
            return results

        try:
            proc = subprocess.run(
                [
                    'curl', '-s',
                    f'https://cve.circl.lu/api/search/{search_term}',
                    '-H', 'Accept: application/json',
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if proc.returncode != 0:
                self._cache[cache_key] = results
                return results

            data = json.loads(proc.stdout)

            # The API returns a dict with 'results' list or a direct list
            items: List = []
            if isinstance(data, list):
                items = data[:50]  # Limit to first 50
            elif isinstance(data, dict):
                items = data.get('results', data.get('data', []))[:50]

            for item in items:
                if not isinstance(item, dict):
                    continue

                cve_id = item.get('id', item.get('cve', {}).get('id', ''))
                description = item.get('summary', item.get('description', ''))
                if isinstance(description, list):
                    description = description[0] if description else ''

                # Extract severity from CVSS
                cvss = item.get('cvss', item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0))
                try:
                    cvss_score = float(cvss) if cvss else 0
                except (ValueError, TypeError):
                    cvss_score = 0

                severity = _cvss_to_severity(cvss_score)
                published = item.get('Published', item.get('publishedDate', ''))

                if cve_id:
                    results.append({
                        'cve_id': cve_id,
                        'description': str(description)[:500],  # Truncate
                        'severity': severity,
                        'published': published,
                    })

        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
            # Graceful degradation
            pass

        self._cache[cache_key] = results
        return results

    # ------------------------------------------------------------------
    # Duplicate likelihood check
    # ------------------------------------------------------------------

    def is_likely_duplicate(self, finding_title: str, finding_type: str) -> Dict:
        """
        Check if a finding is likely a duplicate of a public disclosure.

        Compares the finding title and type against cached hacktivity results
        using simple keyword matching.

        Args:
            finding_title: Title of the finding to check.
            finding_type: Vulnerability type (e.g. 'IDOR', 'XSS', 'SQLi').

        Returns:
            dict with:
                likely_duplicate (bool): Whether a match was found.
                similar_disclosures (List[Dict]): Matching public disclosures.
                confidence (float): 0.0 to 1.0 confidence score.
        """
        # Ensure hacktivity is loaded
        disclosures = self.check_hacktivity()

        if not disclosures:
            return {
                'likely_duplicate': False,
                'similar_disclosures': [],
                'confidence': 0.0,
            }

        title_lower = finding_title.lower()
        type_lower = finding_type.lower()

        # Extract meaningful keywords from the finding title (3+ char words)
        title_keywords = set(
            w for w in re.findall(r'[a-z0-9]+', title_lower)
            if len(w) >= 3
        )

        similar: List[Dict] = []

        for disc in disclosures:
            disc_title_lower = disc.get('title', '').lower()
            disc_type_lower = disc.get('vuln_type', '').lower()

            score = 0.0

            # Type match is a strong signal
            if type_lower and type_lower in disc_type_lower:
                score += 0.4
            elif type_lower and type_lower in disc_title_lower:
                score += 0.3

            # Keyword overlap
            disc_keywords = set(
                w for w in re.findall(r'[a-z0-9]+', disc_title_lower)
                if len(w) >= 3
            )
            if title_keywords and disc_keywords:
                overlap = title_keywords & disc_keywords
                overlap_ratio = len(overlap) / max(len(title_keywords), 1)
                score += overlap_ratio * 0.6

            if score >= 0.3:
                similar.append({
                    **disc,
                    '_match_score': round(score, 3),
                })

        # Sort by match score descending
        similar.sort(key=lambda d: d.get('_match_score', 0), reverse=True)

        # Take top 5
        similar = similar[:5]

        best_score = similar[0].get('_match_score', 0) if similar else 0.0

        return {
            'likely_duplicate': best_score >= 0.5,
            'similar_disclosures': similar,
            'confidence': round(best_score, 3),
        }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Generate a human-readable summary of known disclosures for this target.

        Returns:
            Formatted text summarizing hacktivity results and CVEs.
        """
        lines: List[str] = []
        lines.append(f"=== Disclosure Summary for {self.target} ===")
        lines.append("")

        # Hacktivity
        hacktivity = self.check_hacktivity()
        lines.append(f"### HackerOne Hacktivity: {len(hacktivity)} public reports")
        if hacktivity:
            for disc in hacktivity[:10]:
                bounty_str = f"${disc['bounty']:,.0f}" if disc.get('bounty') else "N/A"
                lines.append(
                    f"  - [{disc.get('severity', '?').upper()}] "
                    f"{disc.get('title', '(untitled)')} "
                    f"(bounty: {bounty_str})"
                )
            if len(hacktivity) > 10:
                lines.append(f"  ... and {len(hacktivity) - 10} more")
        else:
            lines.append("  No public disclosures found.")
        lines.append("")

        # CVEs
        cves = self.check_known_cves()
        lines.append(f"### Known CVEs: {len(cves)}")
        if cves:
            for cve in cves[:10]:
                desc = cve.get('description', '')
                if len(desc) > 80:
                    desc = desc[:77] + "..."
                lines.append(
                    f"  - {cve.get('cve_id', '?')} [{cve.get('severity', '?')}] {desc}"
                )
            if len(cves) > 10:
                lines.append(f"  ... and {len(cves) - 10} more")
        else:
            lines.append("  No known CVEs found.")
        lines.append("")

        lines.append(f"*Checked: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")
        return "\n".join(lines)


# ------------------------------------------------------------------
# Module-level helpers (private)
# ------------------------------------------------------------------

def _extract_vuln_type(title: str) -> str:
    """Best-effort extraction of vulnerability type from a report title."""
    title_lower = title.lower()

    vuln_map = [
        ('idor', 'IDOR'),
        ('insecure direct object', 'IDOR'),
        ('xss', 'XSS'),
        ('cross-site scripting', 'XSS'),
        ('cross site scripting', 'XSS'),
        ('sql injection', 'SQLi'),
        ('sqli', 'SQLi'),
        ('ssrf', 'SSRF'),
        ('server-side request', 'SSRF'),
        ('csrf', 'CSRF'),
        ('cross-site request forgery', 'CSRF'),
        ('rce', 'RCE'),
        ('remote code execution', 'RCE'),
        ('command injection', 'RCE'),
        ('xxe', 'XXE'),
        ('xml external entity', 'XXE'),
        ('open redirect', 'Open_Redirect'),
        ('information disclosure', 'Info_Disclosure'),
        ('info disclosure', 'Info_Disclosure'),
        ('information leak', 'Info_Disclosure'),
        ('auth bypass', 'Auth_Bypass'),
        ('authentication bypass', 'Auth_Bypass'),
        ('authorization bypass', 'Auth_Bypass'),
        ('privilege escalation', 'Privilege_Escalation'),
        ('subdomain takeover', 'Subdomain_Takeover'),
        ('account takeover', 'Account_Takeover'),
        ('rate limit', 'Rate_Limit_Bypass'),
        ('ssti', 'SSTI'),
        ('template injection', 'SSTI'),
        ('path traversal', 'Path_Traversal'),
        ('directory traversal', 'Path_Traversal'),
        ('lfi', 'LFI'),
        ('local file inclusion', 'LFI'),
    ]

    for pattern, vuln_type in vuln_map:
        if pattern in title_lower:
            return vuln_type

    return 'Unknown'


def _cvss_to_severity(score: float) -> str:
    """Convert a CVSS numeric score to a severity label."""
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    if score >= 0.1:
        return 'low'
    return 'unknown'
