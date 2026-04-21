"""
Phase 0.5 H1Fetcher

Fetches the last 50 disclosed vulnerability reports for a given HackerOne
program from the public HackerOne GraphQL API (no authentication required).

Author: BountyHound Team
Version: 1.0.0
"""

import logging
import re
from typing import List

import requests

logger = logging.getLogger("bountyhound.intel.h1")

_GRAPHQL_URL = "https://hackerone.com/graphql"

_QUERY_TEMPLATE = """
query FetchHacktivity($handle: String!) {
  team(handle: $handle) {
    hacktivity_items(
      first: 50
      order_by: {field: popular, direction: DESC}
      where: {
        disclosed: {_eq: true}
      }
    ) {
      edges {
        node {
          ... on HacktivityItem {
            report {
              title
              disclosed_at
              bounty_amount
              weakness {
                name
              }
              structured_scope {
                asset_identifier
              }
            }
          }
        }
      }
    }
  }
}
"""

_HANDLE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (compatible; security-research-tool/1.0)",
}


class H1Fetcher:
    """
    Fetches disclosed HackerOne vulnerability reports via the public GraphQL API.

    Usage:
        fetcher = H1Fetcher(timeout=15)
        reports = fetcher.fetch("shopify")
        # returns [{"title": ..., "cwe": ..., "endpoint": ..., "bounty": ..., "date": ...}, ...]
    """

    def __init__(self, timeout: int = 15) -> None:
        """
        Args:
            timeout: HTTP request timeout in seconds (default 15).
        """
        self.timeout = timeout

    def fetch(self, program_handle: str) -> List[dict]:
        """
        Fetch the last 50 disclosed reports for the given HackerOne program.

        Args:
            program_handle: The HackerOne program identifier (e.g. "shopify").

        Returns:
            A list of dicts with keys: title, cwe, endpoint, bounty, date.
            Returns an empty list on any error (network, JSON parse, unknown program).
            Never raises an exception.
        """
        if not _HANDLE_PATTERN.match(program_handle or ""):
            logger.warning("H1Fetcher: Invalid program handle: %r", program_handle)
            return []

        try:
            response = requests.post(
                _GRAPHQL_URL,
                json={"query": _QUERY_TEMPLATE, "variables": {"handle": program_handle}},
                headers=_HEADERS,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "H1Fetcher: HTTP request failed for program '%s': %s",
                program_handle,
                exc,
            )
            return []

        try:
            payload = response.json()
        except ValueError as exc:
            logger.warning(
                "H1Fetcher: Invalid JSON response for program '%s': %s",
                program_handle,
                exc,
            )
            return []

        # Log GraphQL-level errors but continue — partial data may still be present
        if "errors" in payload:
            logger.warning(
                "H1Fetcher: GraphQL errors for program '%s': %s",
                program_handle,
                payload["errors"],
            )

        # Guard: null team means program handle not found
        team = (payload.get("data") or {}).get("team")
        if team is None:
            logger.warning(
                "H1Fetcher: Program '%s' not found (null team in response).",
                program_handle,
            )
            return []

        edges = (
            team
            .get("hacktivity_items", {})
            .get("edges", [])
        )

        results: List[dict] = []
        for edge in edges:
            node = (edge or {}).get("node", {})
            report = (node or {}).get("report")
            if not report:
                continue

            weakness = report.get("weakness") or {}
            scope = report.get("structured_scope") or {}

            results.append(
                {
                    "title": report.get("title") or "",
                    "cwe": weakness.get("name") or "Unknown",
                    "endpoint": scope.get("asset_identifier") or "",
                    "bounty": report.get("bounty_amount") or 0,
                    "date": report.get("disclosed_at") or "",
                }
            )

        return results
