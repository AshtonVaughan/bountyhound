"""
Phase 0.5 Target Brief

Pre-recon intelligence gathering that researches a target before testing begins.
Reads H1 disclosed reports, CVE data, and changelogs to make the Discovery
Engine's hypothesis generation targeted rather than generic.

Author: BountyHound Team
Version: 1.0.0
"""

import json
import logging
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

_CLAUDE_MODEL = "claude-sonnet-4-6"

# Graceful imports for fetchers that may not exist yet
try:
    from .h1_fetcher import H1Fetcher
    HAS_H1 = True
except ImportError:
    HAS_H1 = False

try:
    from .cve_fetcher import CveFetcher
    HAS_CVE = True
except ImportError:
    HAS_CVE = False

try:
    from .changelog_fetcher import ChangelogFetcher
    HAS_CHANGELOG = True
except ImportError:
    HAS_CHANGELOG = False


@dataclass
class TargetBrief:
    """
    Pre-recon threat intelligence brief for a bug bounty program.

    Fields:
        program_handle:  The H1/platform program identifier (e.g. "shopify").
        disclosed_vulns: List of previously disclosed vulnerabilities.
                         Each entry: {title, cwe, endpoint, bounty, date}.
        known_cves:      List of CVEs relevant to the target's stack.
                         Each entry: {id, description, cvss, affected}.
        recent_changes:  Security-relevant changelog lines extracted from
                         the program's public changelogs / release notes.
        summary:         Claude-generated (or fallback) 300-word threat intel
                         paragraph summarising what a researcher should know.
        cached:          True when this brief was loaded from disk cache.
        generated_at:    ISO-8601 UTC timestamp of when the brief was built.
    """

    program_handle: str
    disclosed_vulns: List[dict]
    known_cves: List[dict]
    recent_changes: List[str]
    summary: str
    cached: bool
    generated_at: str


class TargetBriefBuilder:
    """
    Builds TargetBrief objects for a given bug bounty program.

    Two-phase design:
      * build_pre_recon()  — called before recon; fetches H1 disclosures +
                             changelog data.
      * build_post_recon() — called after recon; adds CVEs discovered from
                             the identified tech stack and regenerates the
                             summary.

    Caches results to disk (JSON) at CACHE_DIR/<program_handle>.json with a
    24-hour TTL.  All fetchers degrade gracefully to empty lists on failure.
    """

    CACHE_DIR = Path.home() / ".bountyhound" / "intel"
    CACHE_TTL = 86400  # 24 hours in seconds

    def __init__(self, program_handle: str, anthropic_client=None):
        """
        Args:
            program_handle:   The bug bounty program identifier.
            anthropic_client: Optional Anthropic client for LLM summary
                              generation.  If None, a plain-text fallback
                              summary is constructed from the raw data.
        """
        self.program_handle = program_handle
        self.anthropic_client = anthropic_client
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_pre_recon(self) -> TargetBrief:
        """
        Run before recon: fetch H1 disclosures and changelog data.

        Flow:
          1. Check disk cache; return cached brief if fresh.
          2. Fetch from H1Fetcher and ChangelogFetcher (empty lists on error).
          3. Generate threat-intel summary via Claude or fallback.
          4. Persist to cache.
          5. Return TargetBrief.
        """
        cached = self._load_cache()
        if cached is not None and self._is_fresh(cached):
            logger.info(
                "TargetBrief cache hit for %s (age < %ds)",
                self.program_handle,
                self.CACHE_TTL,
            )
            cached.cached = True
            return cached

        disclosed_vulns = self._fetch_h1_disclosures()
        recent_changes = self._fetch_changelog()

        brief = TargetBrief(
            program_handle=self.program_handle,
            disclosed_vulns=disclosed_vulns,
            known_cves=[],
            recent_changes=recent_changes,
            summary="",
            cached=False,
            generated_at=self._utcnow(),
        )
        brief.summary = self._generate_summary(brief)
        self._save_cache(brief)
        return brief

    def build_post_recon(
        self,
        existing_brief: TargetBrief,
        stack_tokens: List[str],
    ) -> TargetBrief:
        """
        Run after recon: augment an existing brief with CVE data.

        Args:
            existing_brief: The TargetBrief produced by build_pre_recon().
            stack_tokens:   Technology identifiers discovered during recon
                            (e.g. ["rails", "nginx", "postgresql"]).

        Flow:
          1. Fetch CVEs for each stack token via CveFetcher.
          2. Merge CVEs into existing_brief (de-duplicate by CVE id).
          3. Regenerate summary with the full dataset.
          4. Persist updated cache.
          5. Return updated TargetBrief.
        """
        new_cves = self._fetch_cves(stack_tokens)
        merged_cves = self._merge_cves(existing_brief.known_cves, new_cves)

        updated = TargetBrief(
            program_handle=existing_brief.program_handle,
            disclosed_vulns=existing_brief.disclosed_vulns,
            known_cves=merged_cves,
            recent_changes=existing_brief.recent_changes,
            summary="",
            cached=False,
            generated_at=self._utcnow(),
        )
        updated.summary = self._generate_summary(updated)
        self._save_cache(updated)
        return updated

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_path(self) -> Path:
        safe_handle = re.sub(r'[^a-zA-Z0-9_-]', '_', self.program_handle)
        return self.CACHE_DIR / f"{safe_handle}.json"

    def _load_cache(self) -> Optional[TargetBrief]:
        """Return a TargetBrief from disk cache, or None if missing/corrupt."""
        path = self._cache_path()
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return TargetBrief(
                program_handle=data.get("program_handle", self.program_handle),
                disclosed_vulns=data.get("disclosed_vulns", []),
                known_cves=data.get("known_cves", []),
                recent_changes=data.get("recent_changes", []),
                summary=data.get("summary", ""),
                cached=True,
                generated_at=data.get("generated_at", ""),
            )
        except Exception as exc:
            logger.warning("Failed to load TargetBrief cache (%s): %s", path, exc)
            return None

    def _save_cache(self, brief: TargetBrief) -> None:
        """Persist a TargetBrief to disk as JSON."""
        path = self._cache_path()
        try:
            path.write_text(
                json.dumps(asdict(brief), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.debug("TargetBrief cached to %s", path)
        except Exception as exc:
            logger.warning("Failed to save TargetBrief cache (%s): %s", path, exc)

    def _is_fresh(self, brief: TargetBrief) -> bool:
        """Return True if the brief was generated within CACHE_TTL seconds."""
        try:
            generated = datetime.fromisoformat(brief.generated_at)
            # Ensure timezone-aware comparison
            if generated.tzinfo is None:
                generated = generated.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - generated).total_seconds()
            return age < self.CACHE_TTL
        except Exception as exc:
            logger.warning("Cannot parse generated_at timestamp: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Fetcher wrappers (all degrade gracefully to empty lists)
    # ------------------------------------------------------------------

    def _fetch_h1_disclosures(self) -> List[dict]:
        if not HAS_H1:
            logger.debug("H1Fetcher not available; disclosed_vulns will be empty.")
            return []
        try:
            fetcher = H1Fetcher()
            return fetcher.fetch(self.program_handle) or []
        except Exception as exc:
            logger.warning("H1Fetcher failed for %s: %s", self.program_handle, exc)
            return []

    def _fetch_changelog(self) -> List[str]:
        if not HAS_CHANGELOG:
            logger.debug("ChangelogFetcher not available; recent_changes will be empty.")
            return []
        try:
            fetcher = ChangelogFetcher()
            return fetcher.fetch(self.program_handle) or []
        except Exception as exc:
            logger.warning(
                "ChangelogFetcher failed for %s: %s", self.program_handle, exc
            )
            return []

    def _fetch_cves(self, stack_tokens: List[str]) -> List[dict]:
        if not HAS_CVE:
            logger.debug("CveFetcher not available; known_cves will be empty.")
            return []
        try:
            fetcher = CveFetcher()
            return fetcher.fetch(stack_tokens) or []
        except Exception as exc:
            logger.warning("CveFetcher failed for %s: %s", stack_tokens, exc)
            return []

    @staticmethod
    def _merge_cves(existing: List[dict], new: List[dict]) -> List[dict]:
        """Merge two CVE lists, de-duplicating by 'id' field."""
        seen = {cve.get("id") for cve in existing if cve.get("id")}
        merged = list(existing)
        for cve in new:
            cve_id = cve.get("id")
            if cve_id and cve_id not in seen:
                merged.append(cve)
                seen.add(cve_id)
        return merged

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    def _generate_summary(self, brief: TargetBrief) -> str:
        """
        Generate a ~300-word threat intel summary.

        Uses the Anthropic client when available; otherwise constructs a
        structured plain-text summary from the raw data fields.
        """
        if self.anthropic_client is not None:
            return self._claude_summary(brief)
        return self._fallback_summary(brief)

    def _claude_summary(self, brief: TargetBrief) -> str:
        """Call Claude to produce a 300-word threat intelligence paragraph."""
        disclosed_sample = brief.disclosed_vulns[:25]
        cves_sample = brief.known_cves[:25]
        changes_sample = brief.recent_changes[:25]
        prompt = (
            "You are a threat intelligence analyst. Based on this data about a "
            "bug bounty program, write a concise 300-word threat intel brief that "
            "a security researcher should know before testing this target. Focus "
            "on: what vulnerability types have worked historically, known CVEs to "
            "check, and recent code changes to investigate.\n\n"
            f"Program: {brief.program_handle}\n"
            f"Disclosed vulnerabilities: {json.dumps(disclosed_sample, indent=2)}\n"
            f"Known CVEs: {json.dumps(cves_sample, indent=2)}\n"
            f"Recent security-relevant changes: {json.dumps(changes_sample, indent=2)}"
        )
        try:
            response = self.anthropic_client.messages.create(
                model=_CLAUDE_MODEL,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text.strip()
        except Exception as exc:
            logger.warning(
                "Claude summary generation failed for %s: %s — using fallback.",
                brief.program_handle,
                exc,
            )
            return self._fallback_summary(brief)

    @staticmethod
    def _fallback_summary(brief: TargetBrief) -> str:
        """Build a structured plain-text summary when Claude is unavailable."""
        lines: List[str] = [
            f"Threat Intelligence Brief: {brief.program_handle}",
            f"Generated: {brief.generated_at}",
            "",
        ]

        # Historical vulnerabilities
        if brief.disclosed_vulns:
            lines.append(
                f"Historical vulnerabilities ({len(brief.disclosed_vulns)} disclosed):"
            )
            cwe_counts: dict = {}
            for v in brief.disclosed_vulns:
                cwe = v.get("cwe", "Unknown")
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            for cwe, count in sorted(
                cwe_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]:
                lines.append(f"  - {cwe}: {count} occurrence(s)")
            lines.append("")
        else:
            lines.append("No disclosed vulnerabilities on record.")
            lines.append("")

        # CVEs
        if brief.known_cves:
            lines.append(f"Known CVEs ({len(brief.known_cves)} relevant):")
            for cve in brief.known_cves[:10]:
                cve_id = cve.get("id", "N/A")
                cvss = cve.get("cvss", "N/A")
                desc = cve.get("description", "")[:100]
                lines.append(f"  - {cve_id} (CVSS {cvss}): {desc}")
            lines.append("")
        else:
            lines.append("No known CVEs identified for detected stack.")
            lines.append("")

        # Recent changes
        if brief.recent_changes:
            lines.append(
                f"Recent security-relevant changes ({len(brief.recent_changes)} entries):"
            )
            for change in brief.recent_changes[:10]:
                lines.append(f"  - {change}")
            lines.append("")
        else:
            lines.append("No recent security-relevant changelog entries found.")
            lines.append("")

        lines.append(
            "Recommendation: Focus initial testing on vulnerability classes that "
            "have historically been accepted for this program. Cross-reference any "
            "identified CVEs against the live target to confirm patch status. "
            "Review recent changes for newly introduced endpoints or modified "
            "authentication logic."
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _utcnow() -> str:
        """Return current UTC time as an ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()
