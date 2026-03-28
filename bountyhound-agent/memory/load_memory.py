"""
Compact memory loader for /hunt Step 0.
Reads all memory layers + database stats, prints a concise summary.

Usage: python load_memory.py <target>
"""

import sys
import os
import re
from datetime import datetime
from pathlib import Path

BOUNTY_DIR = Path("C:/Users/vaugh/Desktop/BountyHound")
AGENT_DIR = BOUNTY_DIR / "bountyhound-agent"
FINDINGS_DIR = BOUNTY_DIR / "findings"


def read_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None


def parse_playbook_priorities(content: str) -> list[str]:
    """Extract priority list from structured comment."""
    match = re.search(r"<!--\s*PRIORITIES:\s*(.+?)\s*-->", content)
    if match:
        return [p.strip() for p in match.group(1).split(",")]
    return []


def parse_last_verified(content: str) -> datetime | None:
    """Extract last_verified date from scope file."""
    match = re.search(r"last_verified:\s*(\d{4}-\d{2}-\d{2})", content)
    if match:
        return datetime.strptime(match.group(1), "%Y-%m-%d")
    return None


def parse_credential_status(content: str) -> str | None:
    """Extract credential line from context.md."""
    match = re.search(r"\*\*Credentials:\*\*\s*(.+)", content)
    if match:
        return match.group(1).strip()
    # Fallback: unbolded format
    match = re.search(r"Credentials:\s*(.+)", content)
    if match:
        return match.group(1).strip()
    return None


def count_hunt_entries(content: str) -> int:
    """Count hunt log entries (## Hunt #N headers)."""
    return len(re.findall(r"^## Hunt #\d+", content, re.MULTILINE))


def extract_tech_stack(content: str) -> list[str]:
    """Extract tech stack keywords from per-target context."""
    match = re.search(r"## Tech Stack\s*\n((?:- .+\n)*)", content)
    if match:
        return [line.lstrip("- ").strip().lower() for line in match.group(1).strip().split("\n") if line.strip()]
    return []


def extract_last_recommendation(content: str) -> str | None:
    """Extract 'Next hunt:' line from the most recent hunt entry."""
    matches = re.findall(r"\*\*Next hunt:\*\*\s*(.+)", content)
    if matches:
        return matches[-1].strip()
    return None


def filter_patterns_by_stack(patterns_content: str, stack: list[str]) -> list[str]:
    """Return pattern lines that match the target's tech stack."""
    if not stack:
        return []
    relevant = []
    for line in patterns_content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("<!--") or line.startswith("Max ") or line.startswith("`"):
            continue
        line_lower = line.lower()
        if any(re.search(r'\b' + re.escape(tech) + r'\b', line_lower) for tech in stack):
            relevant.append(line)
    return relevant[:5]


def load_db_stats(target: str) -> dict | None:
    """Try to load database stats for the target. Returns None if DB unavailable."""
    try:
        sys.path.insert(0, str(AGENT_DIR))
        from engine.core.db_hooks import DatabaseHooks
        from engine.core.database import BountyHoundDB

        context = DatabaseHooks.before_test(target, "hunt")
        db = BountyHoundDB()
        stats = db.get_target_stats(target)

        return {
            "should_skip": context.get("should_skip", False),
            "skip_reason": context.get("reason", ""),
            "last_tested": stats.get("last_tested"),
            "total_findings": stats.get("total_findings", 0),
            "total_payouts": stats.get("total_payouts", 0),
            "recommendations": context.get("recommendations", []),
        }
    except Exception:
        return None


def load_memory(target: str) -> None:
    target_dir = FINDINGS_DIR / target
    memory_dir = target_dir / "memory"

    print(f"{'=' * 60}")
    print(f"  HUNTING MEMORY — {target}")
    print(f"{'=' * 60}")

    # --- Database Stats ---
    db_stats = load_db_stats(target)
    if db_stats:
        print(f"\n[DB] Last tested: {db_stats['last_tested'] or 'never'}")
        print(f"[DB] Findings: {db_stats['total_findings']} | Payouts: ${db_stats['total_payouts']:.2f} AUD")
        if db_stats["should_skip"]:
            print(f"[DB] SKIP RECOMMENDED: {db_stats['skip_reason']}")
        elif db_stats["recommendations"]:
            print(f"[DB] Recommendations: {', '.join(db_stats['recommendations'][:3])}")
    else:
        print("\n[DB] Database not available — skipping stats")

    # --- Global Playbook ---
    playbook = read_file(AGENT_DIR / "memory" / "hunting-playbook.md")
    if playbook:
        priorities = parse_playbook_priorities(playbook)
        if priorities:
            print(f"\n[Playbook] Priorities: {' > '.join(priorities)}")
        else:
            print("\n[Playbook] Loaded (no structured priorities)")
        skip_count = len(re.findall(r"^- ", playbook, re.MULTILINE))
        print(f"[Playbook] Skip list: {skip_count} patterns")
    else:
        print("\n[Playbook] Not found — using defaults")

    # --- Cross-Target Patterns ---
    patterns = read_file(AGENT_DIR / "memory" / "patterns.md")
    pattern_count = 0
    if patterns:
        pattern_lines = [l for l in patterns.split("\n")
                         if l.strip() and not l.startswith("#") and not l.startswith("<!--")
                         and not l.startswith("Max ") and not l.startswith("`")
                         and "Format" not in l and "Techniques" not in l and "Loaded" not in l]
        pattern_count = len(pattern_lines)
    print(f"\n[Patterns] {pattern_count} cross-target entries")

    # --- Per-Target Memory ---
    context = read_file(memory_dir / "context.md")
    if context:
        hunt_count = count_hunt_entries(context)
        stack = extract_tech_stack(context)
        cred_status = parse_credential_status(context)
        recommendation = extract_last_recommendation(context)

        print(f"\n[Target] {hunt_count} previous hunts")
        if stack:
            print(f"[Target] Tech stack: {', '.join(stack)}")
        if cred_status:
            print(f"[Target] Credentials: {cred_status}")
            if "expired" in cred_status.lower():
                print("  >>> WARNING: Tokens expired — run /creds refresh before testing")

        # Last recommendation — most actionable piece
        if recommendation:
            print(f"\n  >>> RECOMMENDED FOCUS: {recommendation}")

        # Ruled-out items
        ruled_out_section = ""
        if "## Ruled Out" in context:
            ruled_out_section = context[context.find("## Ruled Out"):]
            # Stop at next section
            next_section = re.search(r"\n## (?!Ruled Out)", ruled_out_section)
            if next_section:
                ruled_out_section = ruled_out_section[:next_section.start()]
        ruled_out = re.findall(r"^- \[.+?\] .+", ruled_out_section, re.MULTILINE)
        if ruled_out:
            print(f"[Target] {len(ruled_out)} dead ends recorded — will skip these")
            for item in ruled_out[-3:]:  # Show last 3
                print(f"  {item}")

        # Filter cross-target patterns by this target's stack
        if patterns and stack:
            relevant = filter_patterns_by_stack(patterns, stack)
            if relevant:
                print(f"\n[Patterns] Relevant for {', '.join(stack)}:")
                for p in relevant:
                    print(f"  {p}")

        # Context rotation warning
        if hunt_count >= 5:
            print(f"\n  >>> WARNING: {hunt_count} hunt entries — rotation needed in Step 4")
    else:
        print(f"\n[Target] First hunt for {target}")
        os.makedirs(memory_dir, exist_ok=True)
        print(f"  Created: {memory_dir}")

    # --- Scope Cache ---
    scope = read_file(memory_dir / "scope.md")
    if scope:
        verified = parse_last_verified(scope)
        if verified:
            age_days = (datetime.now() - verified).days
            if age_days > 30:
                print(f"\n[Scope] BLOCKER: Stale ({age_days} days) — MUST re-parse from program page")
            elif age_days > 14:
                print(f"\n[Scope] WARNING: {age_days} days old — verify on program page")
            else:
                print(f"\n[Scope] Cached ({age_days} days old)")
        else:
            print("\n[Scope] Cached (no verification date — add last_verified: YYYY-MM-DD)")
    else:
        print("\n[Scope] Not cached — parse from program page during recon")

    # --- Defense Fingerprint ---
    defenses = read_file(memory_dir / "defenses.md")
    if defenses:
        waf_match = re.search(r"WAF:\s*(.+?)(?:\(|$)", defenses)
        waf = waf_match.group(1).strip().rstrip(" —") if waf_match else "unknown"
        blocked = re.findall(r"BLOCKED:\s*(.+?)(?:\(|$)", defenses)
        print(f"\n[Defenses] WAF: {waf}")
        if blocked:
            print(f"[Defenses] {len(blocked)} blocked patterns — avoid these payloads:")
            for b in blocked[:5]:
                print(f"  BLOCKED: {b.strip()}")
    else:
        print("\n[Defenses] No fingerprint yet")

    print(f"\n{'=' * 60}")
    print("Full files (read selectively with head/grep, don't cat):")
    print(f"  {memory_dir / 'context.md'}")
    print(f"  {memory_dir / 'scope.md'}")
    print(f"  {memory_dir / 'defenses.md'}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python load_memory.py <target>")
        sys.exit(1)
    load_memory(sys.argv[1])
