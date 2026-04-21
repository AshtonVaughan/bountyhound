"""
Phase 0.5 ChangelogFetcher

Searches GitHub for repositories belonging to a company, fetches changelogs
or release notes, and returns security-relevant lines from the last 90 days.

Author: BountyHound Team
Version: 1.0.0
"""

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

import requests

logger = logging.getLogger("bountyhound.intel.changelog")

_GITHUB_API_BASE = "https://api.github.com"
_RAW_GITHUB_BASE = "https://raw.githubusercontent.com"

_SEARCH_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; security-research-tool/1.0)",
}

_MAX_RESULTS = 50
_DATE_WINDOW_DAYS = 90
_TOP_REPOS = 5

SECURITY_KEYWORDS = [
    "fix",
    "patch",
    "auth",
    "bypass",
    "injection",
    "xss",
    "csrf",
    "vuln",
    "security",
    "cve",
    "exploit",
    "sanitize",
    "escape",
    "privilege",
    "permission",
    "access control",
    "token",
    "session",
]

# Single-word keywords use word boundaries; multi-word use substring
_SINGLE_WORD_KW_PATTERNS = [
    re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
    for kw in SECURITY_KEYWORDS if ' ' not in kw
]
_MULTI_WORD_KW = [kw for kw in SECURITY_KEYWORDS if ' ' in kw]

# Regex patterns for common changelog date formats
# Group "date_str" is the human-readable date for parsing
_DATE_PATTERNS = [
    # ## [1.2.3] - 2026-01-15
    re.compile(
        r"##\s+\[.*?\]\s*-\s*(?P<date_str>\d{4}-\d{2}-\d{2})",
        re.IGNORECASE,
    ),
    # Released: 2026-01-15
    re.compile(
        r"released\s*:?\s*(?P<date_str>\d{4}-\d{2}-\d{2})",
        re.IGNORECASE,
    ),
    # v1.2.3 (January 15, 2026) or v1.2.3 (Jan 15, 2026)
    re.compile(
        r"v[\d.]+\s+\((?P<date_str>[A-Za-z]+\s+\d{1,2},?\s+\d{4})\)",
        re.IGNORECASE,
    ),
    # ## 2026-01-15
    re.compile(
        r"^#+\s+(?P<date_str>\d{4}-\d{2}-\d{2})\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    # == 2026-01-15
    re.compile(
        r"^={2,}\s*(?P<date_str>\d{4}-\d{2}-\d{2})\s*={0,}$",
        re.IGNORECASE | re.MULTILINE,
    ),
]

_MONTH_MAP = {
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3, "mar": 3,
    "april": 4, "apr": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10,
    "november": 11, "nov": 11,
    "december": 12, "dec": 12,
}


def _parse_date_string(date_str: str) -> Optional[datetime]:
    """
    Parse a date string from a changelog header into a timezone-aware datetime.

    Handles:
      - ISO format: 2026-01-15
      - Long month: January 15, 2026 / January 15 2026
      - Short month: Jan 15, 2026 / Jan 15 2026

    Returns None if the string cannot be parsed.
    """
    date_str = date_str.strip().rstrip(",").strip()

    # ISO format
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    # Month DD, YYYY  or  Month DD YYYY
    clean = date_str.replace(",", " ")
    parts = clean.split()
    if len(parts) == 3:
        month_word, day_str, year_str = parts
        month_num = _MONTH_MAP.get(month_word.lower())
        if month_num:
            try:
                return datetime(int(year_str), month_num, int(day_str), tzinfo=timezone.utc)
            except (ValueError, TypeError):
                pass

    return None


class ChangelogFetcher:
    """
    Mines GitHub changelogs and release notes for security-relevant changes.

    Usage:
        fetcher = ChangelogFetcher(timeout=15)
        lines = fetcher.fetch("shopify")
        # Returns ["[shopify/rails] - fix: XSS in template rendering", ...]
    """

    def __init__(self, timeout: int = 15) -> None:
        """
        Args:
            timeout: HTTP request timeout in seconds (default 15).
        """
        self.timeout = timeout
        self._date_window_days = _DATE_WINDOW_DAYS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self, company_name: str) -> List[str]:
        """
        Search GitHub for repos belonging to company_name, fetch changelogs,
        and return security-relevant lines from the last 90 days.

        Args:
            company_name: The company or GitHub organisation/user name.

        Returns:
            A list of up to 50 strings, each prefixed with "[owner/repo]".
            Returns an empty list on any error.  Never raises.
        """
        if not isinstance(company_name, str) or not company_name or not company_name.strip():
            logger.warning("ChangelogFetcher: empty company_name — skipping.")
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(days=self._date_window_days)

        try:
            repos = self._find_repos(company_name)
        except Exception as exc:
            logger.warning(
                "ChangelogFetcher: unexpected error while finding repos for %r: %s",
                company_name,
                exc,
            )
            return []

        if not repos:
            logger.debug("ChangelogFetcher: no repos found for %r.", company_name)
            return []

        results: List[str] = []
        for owner, repo in repos:
            if len(results) >= _MAX_RESULTS:
                break
            try:
                lines = self._process_repo(owner, repo, cutoff)
                for line in lines:
                    if len(results) >= _MAX_RESULTS:
                        break
                    results.append(f"[{owner}/{repo}] {line}")
            except Exception as exc:
                logger.warning(
                    "ChangelogFetcher: error processing repo %s/%s: %s",
                    owner,
                    repo,
                    exc,
                )

        logger.debug(
            "ChangelogFetcher: %d security-relevant lines collected for %r.",
            len(results),
            company_name,
        )
        return results

    # ------------------------------------------------------------------
    # Step 1: Find repos
    # ------------------------------------------------------------------

    def _find_repos(self, company_name: str) -> List[Tuple[str, str]]:
        """
        Query GitHub search API for repos under the company org and user name.

        Returns a deduplicated list of (owner, repo) tuples, at most _TOP_REPOS.
        """
        seen: set = set()
        repos: List[Tuple[str, str]] = []

        for query_type in ("org", "user"):
            url = f"{_GITHUB_API_BASE}/search/repositories"
            params = {
                "q": f"{query_type}:{company_name}",
                "sort": "stars",
                "order": "desc",
                "per_page": str(_TOP_REPOS),
            }
            try:
                response = requests.get(
                    url,
                    params=params,
                    headers=_SEARCH_HEADERS,
                    timeout=self.timeout,
                )
            except requests.exceptions.RequestException as exc:
                logger.warning(
                    "ChangelogFetcher: search request failed (%s:%s): %s",
                    query_type,
                    company_name,
                    exc,
                )
                continue

            if response.status_code in (403, 429):
                logger.warning(
                    "ChangelogFetcher: GitHub rate limit hit (HTTP %d) for %s:%s — "
                    "returning empty result.",
                    response.status_code,
                    query_type,
                    company_name,
                )
                return []

            if not response.ok:
                logger.warning(
                    "ChangelogFetcher: GitHub search returned HTTP %d for %s:%s.",
                    response.status_code,
                    query_type,
                    company_name,
                )
                continue

            try:
                data = response.json()
            except ValueError as exc:
                logger.warning(
                    "ChangelogFetcher: invalid JSON from GitHub search (%s:%s): %s",
                    query_type,
                    company_name,
                    exc,
                )
                continue

            items = data.get("items") or []
            for item in items:
                full_name = item.get("full_name", "")
                if "/" not in full_name or full_name in seen:
                    continue
                seen.add(full_name)
                owner, _, repo = full_name.partition("/")
                repos.append((owner, repo))
                if len(repos) >= _TOP_REPOS:
                    break

            if len(repos) >= _TOP_REPOS:
                break

        return repos[:_TOP_REPOS]

    # ------------------------------------------------------------------
    # Step 2: Fetch changelog content for a repo
    # ------------------------------------------------------------------

    def _process_repo(self, owner: str, repo: str, cutoff: datetime) -> List[str]:
        """
        Try to fetch a changelog for the given repo and extract relevant lines.

        Returns a (possibly empty) list of security-relevant lines.
        """
        content = self._fetch_changelog_content(owner, repo)
        if content is None:
            return []
        return self._extract_recent_security_lines(content, cutoff)

    def _fetch_changelog_content(self, owner: str, repo: str) -> Optional[str]:
        """
        Try changelog URLs in priority order; return text on first success.

        Priority order:
          1. main/CHANGELOG.md
          2. master/CHANGELOG.md
          3. main/CHANGELOG.rst
          4. master/CHANGELOG.rst
          5. GitHub releases API
        """
        raw_candidates = [
            f"{_RAW_GITHUB_BASE}/{owner}/{repo}/main/CHANGELOG.md",
            f"{_RAW_GITHUB_BASE}/{owner}/{repo}/master/CHANGELOG.md",
            f"{_RAW_GITHUB_BASE}/{owner}/{repo}/main/CHANGELOG.rst",
            f"{_RAW_GITHUB_BASE}/{owner}/{repo}/master/CHANGELOG.rst",
        ]

        for url in raw_candidates:
            text = self._get_text(url)
            if text is not None:
                logger.debug(
                    "ChangelogFetcher: found changelog for %s/%s at %s",
                    owner,
                    repo,
                    url,
                )
                return text

        # Fall back to GitHub releases API
        releases_url = (
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/releases?per_page=10"
        )
        try:
            response = requests.get(
                releases_url,
                headers=_SEARCH_HEADERS,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as exc:
            logger.debug(
                "ChangelogFetcher: releases request failed for %s/%s: %s",
                owner,
                repo,
                exc,
            )
            return None

        if response.status_code in (403, 429):
            logger.warning(
                "ChangelogFetcher: GitHub rate limit hit (HTTP %d) on releases for %s/%s.",
                response.status_code,
                owner,
                repo,
            )
            return None

        if not response.ok:
            logger.debug(
                "ChangelogFetcher: releases API returned HTTP %d for %s/%s.",
                response.status_code,
                owner,
                repo,
            )
            return None

        try:
            releases = response.json()
        except ValueError as exc:
            logger.debug(
                "ChangelogFetcher: invalid JSON from releases API for %s/%s: %s",
                owner,
                repo,
                exc,
            )
            return None

        if not releases:
            return None

        # Synthesise a changelog-like text from release data
        lines: List[str] = []
        for release in releases:
            tag = release.get("tag_name") or release.get("name") or "unknown"
            published = release.get("published_at") or ""
            body = release.get("body") or ""
            # Write a header line that our date parser can understand
            if published:
                # published_at is ISO 8601: 2026-01-15T12:00:00Z
                date_part = published[:10]  # "2026-01-15"
                lines.append(f"## [{tag}] - {date_part}")
            else:
                lines.append(f"## [{tag}]")
            lines.append(body)
            lines.append("")

        return "\n".join(lines) if lines else None

    def _get_text(self, url: str) -> Optional[str]:
        """
        Perform a GET request and return response text on HTTP 200, else None.
        """
        try:
            response = requests.get(
                url,
                headers=_SEARCH_HEADERS,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as exc:
            logger.debug("ChangelogFetcher: GET %s failed: %s", url, exc)
            return None

        if response.status_code == 200:
            return response.text
        return None

    # ------------------------------------------------------------------
    # Step 3 & 4: Filter by security keywords and date
    # ------------------------------------------------------------------

    def _extract_recent_security_lines(self, content: str, cutoff: datetime) -> List[str]:
        """
        Parse the changelog content into date-sectioned blocks.

        Returns only lines that:
          a) Belong to a section whose header date is within the last 90 days.
          b) Contain at least one security keyword (case-insensitive).
        """
        lines = content.splitlines()

        # Build sections: list of (section_date_or_None, [lines])
        sections: List[Tuple[Optional[datetime], List[str]]] = []
        current_date: Optional[datetime] = None
        current_lines: List[str] = []

        for line in lines:
            detected = self._detect_date(line)
            if detected is not None:
                # Save the current section before starting a new one
                if current_lines:
                    sections.append((current_date, current_lines))
                current_date = detected
                current_lines = []
                # Keep the header line itself (may contain useful info)
                current_lines.append(line)
            else:
                current_lines.append(line)

        # Flush the last section
        if current_lines:
            sections.append((current_date, current_lines))

        # Collect security-relevant lines from recent sections
        result: List[str] = []
        for section_date, section_lines in sections:
            if section_date is None:
                # No date found; skip (cannot verify recency)
                continue
            if section_date < cutoff:
                # Section is older than 90 days
                continue
            for line in section_lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if self._is_security_relevant(stripped):
                    result.append(stripped)

        return result

    @staticmethod
    def _detect_date(line: str) -> Optional[datetime]:
        """
        Check whether `line` looks like a changelog section header containing
        a date.  Return a timezone-aware datetime if found, else None.
        """
        for pattern in _DATE_PATTERNS:
            match = pattern.search(line)
            if match:
                date_str = match.group("date_str")
                parsed = _parse_date_string(date_str)
                if parsed is not None:
                    return parsed
        return None

    @staticmethod
    def _is_security_relevant(line: str) -> bool:
        """Return True if the line contains any security keyword.

        Single-word keywords are matched with word boundaries to avoid false
        positives such as "prefix" matching "fix" or "non-security" matching
        "security".  Multi-word keywords (e.g. "access control") use plain
        substring matching because word boundaries do not apply across spaces.
        """
        lower = line.lower()
        for pat in _SINGLE_WORD_KW_PATTERNS:
            if pat.search(lower):
                return True
        for kw in _MULTI_WORD_KW:
            if kw in lower:
                return True
        return False
