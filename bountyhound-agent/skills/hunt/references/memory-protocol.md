# Memory Update Protocol

Use this as the prompt template for the background haiku agent spawned at the end of every hunt.
Replace {TARGET} and {HUNT_SUMMARY} before spawning.

---

## Agent Prompt Template

```
You are updating hunting memory for target: {TARGET}
Base path: C:/Users/vaugh/Desktop/BountyHound
Agent path: C:/Users/vaugh/Desktop/BountyHound/bountyhound-agent

Hunt summary:
{HUNT_SUMMARY}

Complete ALL tasks below. If a file or directory is missing, create it from the relevant template.

---

## Task 1: Per-Target Context (with 5-entry rotation)

File: findings/{TARGET}/memory/context.md

If file does NOT exist: copy template from bountyhound-agent/memory/templates/context.md,
replace {TARGET} placeholders, fill in the first hunt entry.

If file EXISTS:
- Count ## Hunt #N headers. If 5 or more, move the OLDEST entry (from its ## Hunt #N
  header to the next ## Hunt header) to findings/{TARGET}/memory/context-archive.md (append).
- Append a new ## Hunt #N entry with:
  Date: {today}
  Tested: {endpoints and vuln types tested this hunt}
  Found: {findings, or "nothing reportable"}
  Skipped: {what was not tested and why}
  Tech notes: {new stack observations — also update ## Tech Stack section at top of file}
  Credentials: valid | expired | not_set (last refreshed: YYYY-MM-DD)
  Next hunt: {recommended focus for next session}

---

## Task 2: Ruled Out (dead ends only)

In context.md under ## Ruled Out, append entries ONLY for things definitively eliminated this hunt.
Format: - [YYYY-MM-DD] {endpoint/vuln_type} — {why dead} [re-test if: {condition}]

Do not add "didn't find anything here" — only add entries for confirmed non-exploitable surfaces.

---

## Task 3: Defense Fingerprint (merge, never overwrite)

File: findings/{TARGET}/memory/defenses.md

If not exists: copy from bountyhound-agent/memory/templates/defenses.md

MERGE rules:
- Update entries that were re-observed this hunt (refresh last_seen date)
- Add new observations
- Keep untested entries from prior hunts unchanged

Categories: WAF, RATE_LIMIT, BLOCKED_PAYLOAD, AUTH_PROTECTION, HEADERS
Format: CATEGORY: {detail} (last_seen: YYYY-MM-DD)

---

## Task 4: Scope Cache

File: findings/{TARGET}/memory/scope.md

If scope was parsed this hunt (program-map.md was written or updated):
- Copy template from bountyhound-agent/memory/templates/scope.md and fill in
- Set last_verified: {today}

If scope was NOT re-verified this hunt, do not touch this file.

---

## Task 5: Cross-Target Patterns

File: bountyhound-agent/memory/patterns.md

If this hunt produced a VERIFIED finding or a technique that worked (even without a report):
- Append ONE line: [{tech/infra}] : {what worked} → {accepted|verified|unconfirmed} ({YYYY-MM-DD})
- Do not duplicate existing entries
- If file has 50 entries, remove the oldest before adding

Only add if finding passed validation (curl proof confirmed). Do not add for hypotheses or unconfirmed leads.

---

## Task 6: Auto-Refinement Check

Run this Python. If it fails (DB unavailable), skip silently:

import sys
sys.path.insert(0, 'C:/Users/vaugh/Desktop/BountyHound/bountyhound-agent')
try:
    from engine.core.database import BountyHoundDB
    import re
    db = BountyHoundDB()
    with db._get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE created_at > date('now', '-90 days')"
        ).fetchone()[0]
        if total < 15:
            print(f"Auto-refinement skipped — only {total} findings in 90d (need 15+)")
        else:
            rows = conn.execute('''
                SELECT vuln_type, COUNT(*) as total,
                  SUM(CASE WHEN status='accepted' THEN 1 ELSE 0 END) as accepted,
                  ROUND(SUM(CASE WHEN status='accepted' THEN 1 ELSE 0 END)*100.0/COUNT(*),1) as pct
                FROM findings WHERE created_at > date('now','-90 days')
                GROUP BY vuln_type HAVING total >= 3 ORDER BY pct DESC
            ''').fetchall()
            playbook = open('C:/Users/vaugh/Desktop/BountyHound/bountyhound-agent/memory/hunting-playbook.md').read()
            m = re.search(r'<!-- PRIORITIES: (.+?) -->', playbook)
            prios = [p.strip().lower() for p in m.group(1).split(',')] if m else []
            for r in rows:
                vt, pct = r[0], r[3]
                if pct >= 70 and vt.lower() not in prios[:2]:
                    print(f"SUGGEST: {vt} has {pct}% acceptance rate — consider promoting in playbook")
                for i, p in enumerate(prios[:3]):
                    if p in vt.lower() and pct < 20:
                        print(f"SUGGEST: {vt} is priority #{i+1} but only {pct}% acceptance — consider demoting")
except Exception:
    pass

Print suggestions only — never auto-edit the playbook.

---

## Task 7: Chain Canvas Preservation

File: findings/{TARGET}/chain-canvas.md

If canvas does NOT exist, skip this task.

If canvas EXISTS:
- Update "Last updated:" date to today
- Do NOT reset or overwrite any existing content
- If this hunt produced new verified findings: check that each has a row in ## Capabilities Gained
- If an Active Chain Hypothesis was confirmed this hunt: move it to ## Confirmed Chains with today's date
- If an Active Chain Hypothesis was tested and failed: move it to ## Dead Chains with reason

The chain canvas is a long-lived artifact. It grows across hunts, never resets.
```

---

## HUNT_SUMMARY Format

When filling in {HUNT_SUMMARY} before spawning this agent, use this format:

```
Target: {domain}
Date: {YYYY-MM-DD}
Hunt duration: {approximate}
Tested: {list of endpoints/features tested}
Found: {list of findings, or "nothing reportable this session"}
Ruled out: {list of dead ends confirmed}
New tech observations: {any new stack info discovered}
Credentials status: {valid/expired/none}
Notable: {anything unusual — new subdomains, interesting behaviors, partial chains}
```

---

## Proactive Write Policy (Do Not Wait)

The background agent runs at end-of-hunt, but critical information must be written DURING the hunt, not after. Waiting risks context compaction overwriting or discarding the information before it can be saved.

**Write immediately (do not wait for end-of-hunt agent) when:**
- A finding is confirmed (Layer 1 passed) — write to `chain-canvas.md` Capabilities Gained
- A technique is definitively ruled out — write to `context.md` Ruled Out immediately
- A new defense is observed (rate limit threshold, WAF signature triggered) — write to `defenses.md`
- A pattern works on this target — write to `patterns.md` immediately (not at session end)
- A user preference or constraint is stated — write to `context.md` immediately

**The rule:** If losing this information would change the next hunt, write it NOW. The background agent handles rotation and cleanup, but capturing the fact is your job during the hunt.

---

## Anti-Compaction Protocol

Context compaction discards mid-context information silently. After compaction, constraints followed perfectly before may be violated. Protect against this:

**At 70% context usage (before compaction triggers):**
Write a memory checkpoint to `findings/{TARGET}/memory/session-checkpoint.md`:
```markdown
# Session Checkpoint — {YYYY-MM-DD HH:MM}
## Active Findings (do not discard)
- {finding name}: {status tag} — {brief description of what was proven}
## Hard Constraints This Hunt
- {e.g., "Do NOT race the /api/checkout endpoint — user said no"}
- {e.g., "Out of scope: *.internal.example.com"}
## Current Hypothesis Queue
- HIGH: {list}
- MED: {list}
## Established Facts
- {tech stack observations}
- {credential status}
## Next Step
- {exact next action}
```

**At session start (or after compaction):**
First action: read `findings/{TARGET}/memory/session-checkpoint.md` if it exists.
This restores constraints that compaction would have discarded.

**In CLAUDE.md / SKILL.md frontmatter:**
Critical per-target constraints (scope rules, payment endpoint restrictions) belong in `program-map.md`, not just in conversation. Conversation is ephemeral; files survive compaction.

---

## Retrieved Memory Placement (Lost-in-Middle Defense)

When you load memory files for a hunt, position matters. LLM attention degrades 30%+ for information placed in the middle of a long context.

**Placement rules:**
- Program constraints (scope, restrictions) go FIRST — before recon data, before hypothesis cards
- Current session hypothesis cards go FIRST (top of active context)
- High-importance retrieved patterns go FIRST
- Recon data and tool output go in the MIDDLE (lower priority, retrieved as needed)
- Re-state active constraints at the END of every 10 steps in long sessions (they'll have drifted into middle)

**Implementation:**
```
Step 1: Read program-map.md [critical constraints — must be at top]
Step 2: Read session-checkpoint.md [active session state]
Step 3: Run recon [results go in middle — you'll summarize them anyway]
Step 4: Generate hypothesis cards [these go at top of your working context]
# After every 10 tool calls: re-state constraints from program-map.md + hypothesis queue
```

---

## Temporal Marking (When Information Changes)

When a fact about a target changes, mark the old fact rather than silently updating:

**Format for superseded facts in context.md:**
```
UPDATED [YYYY-MM-DD]: {new fact}. Previously (until {date}): {old fact}. Old context no longer applies.
```

Example:
```
UPDATED [2026-03-22]: Target migrated to AWS Cognito auth. Previously (until 2026-01-15): custom JWT auth with HS256 signing. Old JWT attacks no longer apply; OAuth/Cognito attack surface now primary.
```

**Why this matters:** Stale facts cause context confusion. A finding that worked before may rely on infrastructure that no longer exists. The "UPDATED" marker tells the hunt skill to prefer the new fact and explicitly ignore the old one, rather than silently averaging or becoming inconsistent.

When you encounter temporal marking in context.md, the newer fact always wins. Do not try to "reconcile" old and new — treat the old as invalidated.

---

## Reflection Loop (End-of-Hunt)

Before spawning the background agent, run this reflection. The results feed Task 7 (chain canvas) and Task 5 (patterns):

```
Hunt reflection for {TARGET} — {date}
What worked (technique that succeeded OR ruled out efficiently):
  1. {technique}: {outcome in 1 sentence}
  2. {technique}: {outcome}
What failed (approach that consumed time without signal):
  1. {approach}: {why it failed} — root cause: {wrong assumption | missing context | wrong tool}
What surprised me:
  - {unexpected behavior, unexpected defense, unexpected access}
Pattern emerged:
  - {if any technique worked non-obviously}: add to patterns.md NOW (not later)
Next hunt focus:
  - If nothing found: {what did I not test that I should}
  - If findings confirmed: {what chains are now possible}
```

This reflection is for YOU before spawning the agent — it improves what you write in {HUNT_SUMMARY} and ensures high-quality pattern capture. A reflection that only says "found X, didn't find Y" is useless. The valuable insight is WHY — that's what compounds across hunts.
