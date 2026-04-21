---
name: feedback
description: Record HackerOne outcome for a finding and update hunting memory
arguments:
  - name: args
    description: "<target> <slug> <outcome> [bounty_aud] — outcome: accepted|rejected|informative|duplicate|needs-more-info"
    required: true
---

# /feedback $ARGUMENTS

Records the HackerOne triage outcome for a finding. Closes the feedback loop so
auto-refinement has accurate data and memory reflects what actually works.

**Parse:** `$ARGUMENTS` = `<target> <slug> <outcome> [bounty_aud]`

Example: `/feedback shopify.com idor-user-id accepted 3400`
Example: `/feedback shopify.com xss-search-q rejected`

---

## Step 1: Update the Database

```python
import sys
sys.path.insert(0, 'C:/Users/vaugh/Desktop/BountyHound')
from engine.core.database import BountyHoundDB

target  = '<target>'
slug    = '<slug>'
outcome = '<outcome>'   # accepted | rejected | informative | duplicate | needs-more-info
bounty  = <bounty_aud>  # float, or None if not provided

db = BountyHoundDB()
with db._get_connection() as conn:
    conn.execute("""
        UPDATE findings
        SET status=?, payout=COALESCE(?, payout), updated_at=date('now')
        WHERE domain=? AND (slug=? OR title LIKE ?)
    """, (outcome, bounty, target, slug, f'%{slug}%'))

    row = conn.execute(
        "SELECT * FROM findings WHERE domain=? AND (slug=? OR title LIKE ?) LIMIT 1",
        (target, slug, f'%{slug}%')
    ).fetchone()

if row:
    print(f"Updated: {row['title']} → {outcome}" + (f" (AUD ${bounty})" if bounty else ""))
else:
    print(f"WARNING: No finding matched slug '{slug}' for target '{target}'")
    print("Check the slug against: C:/Users/vaugh/BountyHound/findings/<target>/verified/")
```

---

## Step 2: Update Per-Target Context

Append to `findings/<target>/memory/context.md` under the most recent `## Hunt #N` entry:

```
**Outcome [<YYYY-MM-DD>]:** <slug> → <outcome><bounty_note>
```

Where `<bounty_note>` is ` (AUD $<amount>)` if accepted with bounty, or empty.

---

## Step 3: If Accepted — Update Cross-Target Patterns

Read `findings/<target>/verified/<slug>.md` to get the vuln type and tech stack.

Then append to `bountyhound-agent/memory/patterns.md` if the pattern isn't already there:

```
[<tech_stack>] : [<vuln_type>] at [<endpoint_pattern>] → accepted AUD $<bounty> on <YYYY-MM-DD>
```

Example:
```
[Rails/GraphQL] : IDOR via aliased mutation → accepted AUD $3400 on 2026-03-04
```

If `patterns.md` already has 50 entries, remove the oldest entry (lowest date) before adding.

---

## Step 4: If Accepted — Update Chain Canvas

Read `findings/<target>/chain-canvas.md` if it exists.

Find the row in Capabilities Gained matching this slug. Update `Tested Further?` to `yes (accepted)`.

If this finding was part of a Confirmed Chain, add the bounty amount to that chain's entry.

---

## Step 5: If Rejected/Informative — Record Why

Ask the user: "What reason did HackerOne give?" (one line is enough)

Append to `findings/<target>/memory/context.md` under `## Ruled Out`:

```
- [<YYYY-MM-DD>] [<slug>/<vuln_type>] — rejected: <reason given> [re-test if: <condition or "never">]
```

This prevents re-submitting the same class of finding.

---

## Step 6: If Needs-More-Info — Queue Fix

Print a reminder:

```
ACTION REQUIRED: HackerOne needs more info for <slug>.
Fix the report at: C:/Users/vaugh/BountyHound/findings/<target>/reports/<slug>-report.md

Common fixes:
- Add reproduce.py if missing
- Clarify how to obtain auth token
- Explain ambiguous response (e.g., "success: false" but vuln still present)
- Add screenshot of vulnerability triggered
```

Do NOT update DB status to rejected — keep as pending until resolved.

---

**Execute now.**
