"""
Phase 0.5 CveFetcher

Queries the NIST NVD API v2 for CVEs related to technology stack tokens.
Returns deduplicated CVEs with CVSS >= 7.0 published within the last 3 years.

Author: BountyHound Team
Version: 1.0.0
"""

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import List

import requests

logger = logging.getLogger("bountyhound.intel.cve")

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; security-research-tool/1.0)",
}

_MIN_CVSS = 7.0
_RATE_LIMIT_SLEEP = 0.6   # seconds between token requests
_RETRY_SLEEP = 2.0         # seconds to wait after HTTP 429 before retry
_MAX_TOKEN_LENGTH = 100
_MAX_AFFECTED_CPES = 3


class CveFetcher:
    """
    Fetches CVEs from the NIST NVD API v2 for a list of technology stack tokens.

    Usage:
        fetcher = CveFetcher(timeout=15)
        cves = fetcher.fetch(["rails", "nginx", "postgresql"])
        # Returns [{"id": ..., "description": ..., "cvss": ..., "affected": ...}, ...]

    Filters:
        - CVSS base score >= 7.0
        - Published within the last 3 years

    Deduplication:
        - CVE IDs are deduplicated across all token queries.

    Error handling:
        - Network errors, invalid JSON, and HTTP 429 (with one retry) are all
          handled gracefully. Never raises an exception; always returns a list.
    """

    def __init__(self, timeout: int = 15) -> None:
        """
        Args:
            timeout: HTTP request timeout in seconds (default 15).
        """
        self.timeout = timeout

    def fetch(self, stack_tokens: List[str]) -> List[dict]:
        """
        Query NVD for CVEs related to each stack token and return a merged,
        deduplicated list.

        Args:
            stack_tokens: Technology identifiers discovered during recon,
                          e.g. ["rails", "nginx", "postgresql"].

        Returns:
            A list of dicts with keys: id, description, cvss, affected.
            Returns an empty list if stack_tokens is empty or all requests fail.
            Never raises an exception.
        """
        if not stack_tokens:
            return []

        now = datetime.now(timezone.utc)
        three_years_ago = now - timedelta(days=3 * 365)

        pub_start = three_years_ago.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        seen_ids: set = set()
        results: List[dict] = []
        request_count = 0

        for token in stack_tokens:
            # Input validation
            if not token or len(token) > _MAX_TOKEN_LENGTH:
                logger.debug(
                    "CveFetcher: Skipping invalid token (empty or too long): %r", token
                )
                continue

            # Rate limiting between requests (skip sleep before first valid request)
            if request_count > 0:
                time.sleep(_RATE_LIMIT_SLEEP)

            cves = self._fetch_token(token, pub_start, pub_end)
            request_count += 1
            for cve in cves:
                cve_id = cve.get("id")
                if cve_id and cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    results.append(cve)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_token(
        self, token: str, pub_start: str, pub_end: str
    ) -> List[dict]:
        """
        Fetch CVEs for a single token from NVD API v2.

        Performs one retry (after 2s wait) on HTTP 429.
        Returns an empty list on any unrecoverable error.
        """
        params = {
            "keywordSearch": token,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }

        response = self._get_with_retry(token, params)
        if response is None:
            return []

        try:
            payload = response.json()
        except ValueError as exc:
            logger.warning(
                "CveFetcher: Invalid JSON response for token %r: %s", token, exc
            )
            return []

        vulnerabilities = payload.get("vulnerabilities", [])
        results: List[dict] = []

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            parsed = self._parse_cve(cve_data)
            if parsed is not None:
                results.append(parsed)

        logger.debug(
            "CveFetcher: token=%r → %d CVEs (CVSS >= %.1f)",
            token,
            len(results),
            _MIN_CVSS,
        )
        return results

    def _get_with_retry(self, token: str, params: dict):
        """
        Perform an HTTP GET with one retry on HTTP 429.

        Returns the Response object on success, or None on failure.
        """
        try:
            response = requests.get(
                _NVD_API_URL,
                params=params,
                headers=_HEADERS,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "CveFetcher: Network error for token %r: %s", token, exc
            )
            return None

        if response.status_code == 429:
            logger.warning(
                "CveFetcher: Rate limited (HTTP 429) for token %r — "
                "waiting %.1fs before retry.",
                token,
                _RETRY_SLEEP,
            )
            time.sleep(_RETRY_SLEEP)
            try:
                response = requests.get(
                    _NVD_API_URL,
                    params=params,
                    headers=_HEADERS,
                    timeout=self.timeout,
                )
            except requests.exceptions.RequestException as exc:
                logger.warning(
                    "CveFetcher: Retry failed for token %r: %s", token, exc
                )
                return None

            if response.status_code == 429:
                logger.warning(
                    "CveFetcher: Still rate limited after retry for token %r — skipping.",
                    token,
                )
                return None

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            logger.warning(
                "CveFetcher: HTTP error for token %r: %s", token, exc
            )
            return None

        return response

    @staticmethod
    def _parse_cve(cve_data: dict):
        """
        Parse a single CVE entry from the NVD response.

        Returns a dict with keys: id, description, cvss, affected.
        Returns None if the CVE does not meet the CVSS >= 7.0 threshold.
        """
        cve_id = cve_data.get("id", "")

        # Extract English description
        description = ""
        for desc_entry in cve_data.get("descriptions", []):
            if desc_entry.get("lang") == "en":
                description = desc_entry.get("value", "")
                break

        # Extract CVSS score — prefer v3.1, fall back to v2
        metrics = cve_data.get("metrics", {})
        cvss = 0.0

        cvss_v31_list = metrics.get("cvssMetricV31", [])
        if cvss_v31_list:
            try:
                cvss = float(
                    cvss_v31_list[0]
                    .get("cvssData", {})
                    .get("baseScore", 0.0)
                )
            except (TypeError, ValueError):
                cvss = 0.0
        else:
            cvss_v2_list = metrics.get("cvssMetricV2", [])
            if cvss_v2_list:
                try:
                    cvss = float(
                        cvss_v2_list[0]
                        .get("cvssData", {})
                        .get("baseScore", 0.0)
                    )
                except (TypeError, ValueError):
                    cvss = 0.0

        # Apply CVSS filter
        if cvss < _MIN_CVSS:
            return None

        # Extract affected CPE strings (first 3 only)
        affected = ""
        configurations = cve_data.get("configurations", [])
        cpe_strings: List[str] = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        cpe_strings.append(criteria)
                    if len(cpe_strings) >= _MAX_AFFECTED_CPES:
                        break
                if len(cpe_strings) >= _MAX_AFFECTED_CPES:
                    break
            if len(cpe_strings) >= _MAX_AFFECTED_CPES:
                break

        if cpe_strings:
            affected = " | ".join(cpe_strings[:_MAX_AFFECTED_CPES])

        return {
            "id": cve_id,
            "description": description,
            "cvss": cvss,
            "affected": affected,
        }
