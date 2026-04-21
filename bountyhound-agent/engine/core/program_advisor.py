"""
program_advisor.py — Score and rank H1 programs from h1-programs.db.

CLI:
  python program_advisor.py [--top N] [--tech <stack>] [--min-bounty <AUD>] [--json]

Scoring (0–100 pts):
  30 pts  Payout potential   (max_bounty / 50000 * 30, capped)
  20 pts  Recently active    (updated ≤30d ago = 20, ≤90d = 10, else 0)
  15 pts  Scope size         (in-scope asset count, scaled)
  15 pts  Offers bounties    (1 if offers_bounties, else 0)
  20 pts  Stack match bonus  (if --tech and name/policy mentions it)
"""

import argparse
import json
import math
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AGENT = Path(__file__).resolve().parents[2]
H1_DB = AGENT / "data" / "h1-programs.db"

# HackerOne payouts are in USD; 1 USD ≈ 1.55 AUD (update as needed)
USD_TO_AUD = 1.55

MAX_PAYOUT_USD_FOR_SCORE = 50_000


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _detect_columns(cursor: sqlite3.Cursor, table: str) -> set[str]:
    """Return the set of column names present in *table*."""
    cursor.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cursor.fetchall()}


def _get_scope_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Return {program_id: in_scope_asset_count} from the scopes table."""
    counts: dict[str, int] = {}
    try:
        cur = conn.execute(
            "SELECT program_id, COUNT(*) FROM scopes GROUP BY program_id"
        )
        for program_id, count in cur.fetchall():
            counts[program_id] = count
    except sqlite3.OperationalError:
        pass
    return counts


def _parse_updated_at(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _recency_score(updated_at: str | None) -> int:
    dt = _parse_updated_at(updated_at)
    if dt is None:
        return 0
    now = datetime.now(timezone.utc)
    age_days = (now - dt).days
    if age_days <= 30:
        return 20
    if age_days <= 90:
        return 10
    return 0


def _payout_score(max_bounty_usd: int | None) -> int:
    if not max_bounty_usd:
        return 0
    raw = (max_bounty_usd / MAX_PAYOUT_USD_FOR_SCORE) * 30
    return int(min(raw, 30))


def _scope_score(scope_count: int) -> int:
    """Scale scope count to 0–15 pts. 50+ assets = full score."""
    if scope_count <= 0:
        return 0
    scaled = math.log1p(scope_count) / math.log1p(50) * 15
    return int(min(scaled, 15))


def _tech_match(row: dict[str, Any], tech: str) -> bool:
    """Return True if tech string appears in program name or policy text."""
    tech_lower = tech.lower()
    name = (row.get("name") or "").lower()
    policy = (row.get("policy") or "").lower()
    return tech_lower in name or tech_lower in policy


def score_program(
    row: dict[str, Any],
    scope_count: int,
    tech: str | None,
) -> int:
    total = 0
    total += _payout_score(row.get("max_bounty"))
    total += _recency_score(row.get("updated_at"))
    total += _scope_score(scope_count)
    total += 15 if row.get("offers_bounties") else 0
    if tech and _tech_match(row, tech):
        total += 20
    return min(total, 100)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _aud(usd: int | None) -> str:
    if usd is None:
        return "N/A"
    return f"AUD {int(usd * USD_TO_AUD):,}"


def _fmt_date(value: str | None) -> str:
    if not value:
        return "unknown"
    dt = _parse_updated_at(value)
    return dt.strftime("%Y-%m-%d") if dt else value[:10]


def _print_table(rows: list[dict[str, Any]]) -> None:
    header = f"{'Rank':<5} {'Score':<6} {'Program Handle':<28} {'Max Bounty':<16} {'Scope':<7} {'Updated'}"
    print(header)
    print("-" * len(header))
    for i, r in enumerate(rows, 1):
        print(
            f"{i:<5} {r['score']:<6} {r['handle']:<28} "
            f"{_aud(r['max_bounty']):<16} {r['scope_count']:<7} "
            f"{_fmt_date(r['updated_at'])}"
        )


# ---------------------------------------------------------------------------
# Main query + scoring pipeline
# ---------------------------------------------------------------------------

def load_and_score(
    top_n: int,
    tech: str | None,
    min_bounty_aud: float | None,
) -> list[dict[str, Any]]:
    if not H1_DB.exists():
        print(f"[program_advisor] ERROR: h1-programs.db not found at {H1_DB}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(H1_DB))
    conn.row_factory = sqlite3.Row

    cols = _detect_columns(conn.cursor(), "programs")
    scope_counts = _get_scope_counts(conn)

    # Build SELECT based on detected columns
    wanted = [
        "id", "handle", "name", "max_bounty", "updated_at",
        "offers_bounties", "policy", "currency", "submission_state",
    ]
    select_cols = ", ".join(c for c in wanted if c in cols)

    # Filter to programs accepting submissions
    where_clause = "WHERE submission_state IN ('open', 'soft_launched') OR submission_state IS NULL"
    query = f"SELECT {select_cols} FROM programs {where_clause}"

    cursor = conn.execute(query)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Optional min-bounty filter (convert AUD → USD for comparison)
    if min_bounty_aud is not None:
        min_usd = min_bounty_aud / USD_TO_AUD
        rows = [r for r in rows if (r.get("max_bounty") or 0) >= min_usd]

    # Optional tech filter (require match if --tech provided)
    if tech:
        rows = [r for r in rows if _tech_match(r, tech)]

    # Score every row
    for r in rows:
        sc = scope_counts.get(r.get("id", ""), 0)
        r["scope_count"] = sc
        r["score"] = score_program(r, sc, tech)

    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:top_n]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rank H1 programs by hunting value."
    )
    parser.add_argument("--top", type=int, default=20, help="Show top N programs (default 20)")
    parser.add_argument("--tech", type=str, default=None, help="Tech stack keyword to match (e.g. nextjs, rails, graphql)")
    parser.add_argument(
        "--min-bounty",
        type=float,
        default=None,
        metavar="AUD",
        help="Minimum max bounty in AUD",
    )
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output JSON to stdout")
    args = parser.parse_args()

    results = load_and_score(args.top, args.tech, args.min_bounty)

    if args.as_json:
        output = []
        for i, r in enumerate(results, 1):
            output.append(
                {
                    "rank": i,
                    "score": r["score"],
                    "handle": r.get("handle"),
                    "name": r.get("name"),
                    "max_bounty_usd": r.get("max_bounty"),
                    "max_bounty_aud": int((r.get("max_bounty") or 0) * USD_TO_AUD),
                    "scope_count": r["scope_count"],
                    "updated_at": r.get("updated_at"),
                    "offers_bounties": bool(r.get("offers_bounties")),
                }
            )
        print(json.dumps(output, indent=2))
    else:
        if not results:
            print("No programs matched your filters.")
            return
        _print_table(results)


if __name__ == "__main__":
    main()
