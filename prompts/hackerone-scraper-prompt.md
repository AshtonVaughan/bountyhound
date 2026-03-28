# HackerOne BBP Scraper — Haiku Agent Prompt

## Task

Scrape every publicly visible, currently active Bug Bounty Program on HackerOne. Extract full program details into structured JSON files.

## Output Location

Save all output to: `C:/Users/vaugh/Desktop/BountyHound/recon/hackerone-programs/`

Create these files:
- `programs_index.json` — master list of all programs found (append as you go)
- `programs/{handle}.json` — one file per program with full details
- `scrape_log.txt` — append one line per program: `{handle} OK` or `{handle} FAIL {reason}`

## Step 1: Discover All Active Programs

Navigate to: `https://hackerone.com/opportunities/all/search?ordering=Newest+programs`

This page lists bug bounty programs. You need to:

1. Read the page content to find program cards/listings
2. For each program visible, extract: `handle` (the URL slug), `program_name`, `program_type` (bug_bounty or vdp)
3. Only collect programs marked as bug bounty (paying programs), skip VDPs unless they explicitly offer bounties
4. Scroll down or click "Load More" / pagination to get the next batch
5. Keep going until no more programs load
6. Save each batch to `programs_index.json` immediately — don't wait until the end

Expected format for `programs_index.json`:
```json
{
  "scraped_at": "2026-03-09",
  "total_found": 0,
  "programs": [
    {
      "handle": "example-corp",
      "name": "Example Corp",
      "url": "https://hackerone.com/example-corp",
      "managed": true,
      "offers_bounties": true,
      "status": "pending"
    }
  ]
}
```

Update `total_found` as you discover more. Set `status` to `"pending"` initially, update to `"scraped"` or `"failed"` after visiting each program.

## Step 2: Scrape Each Program

For each program in `programs_index.json` where `status` is `"pending"`:

1. Navigate to `https://hackerone.com/{handle}`
2. Read the program page
3. Click through all tabs/sections to find: Policy, Scope, Bounties/Rewards
4. Extract the data below into `programs/{handle}.json`
5. Update `programs_index.json` status to `"scraped"`
6. Append to `scrape_log.txt`
7. Move to next program

### Data Schema for Each Program

```json
{
  "handle": "example-corp",
  "name": "Example Corp",
  "url": "https://hackerone.com/example-corp",
  "scraped_at": "2026-03-09T14:30:00Z",
  "program_type": "bug_bounty",
  "managed": true,
  "state": "open_for_submissions",
  "response_efficiency": {
    "first_response": "",
    "triage": "",
    "bounty": "",
    "resolution": ""
  },
  "bounty_table": {
    "critical": {"min": 0, "max": 0},
    "high": {"min": 0, "max": 0},
    "medium": {"min": 0, "max": 0},
    "low": {"min": 0, "max": 0}
  },
  "in_scope": [
    {
      "asset": "*.example.com",
      "type": "URL",
      "max_severity": "critical",
      "eligible_for_bounty": true,
      "notes": ""
    }
  ],
  "out_of_scope": [
    {
      "asset": "blog.example.com",
      "type": "URL",
      "notes": ""
    }
  ],
  "out_of_scope_vulns": [],
  "policy": {
    "safe_harbor": true,
    "disclosure_policy": "",
    "rules": [],
    "banned_test_types": [],
    "special_instructions": ""
  },
  "stats": {
    "reports_resolved": 0,
    "hackers_thanked": 0,
    "bounties_paid": ""
  }
}
```

### Field Extraction Rules

For each field, here is exactly where to find it on the page:

| Field | Where to look |
|---|---|
| `bounty_table` | Look for the rewards/bounty section — usually a table showing severity tiers and dollar amounts. If ranges shown, capture min and max. If single number, set min=max. If "up to $X", set min=0 max=X. |
| `in_scope` | Look for "In Scope" or "Assets in scope" section. Each row has: asset identifier, asset type (URL, iOS app, Android app, source code, hardware, other), max severity, bounty eligibility. Copy ALL rows. |
| `out_of_scope` | Look for "Out of Scope" section listing excluded assets. Copy ALL entries. |
| `out_of_scope_vulns` | Look for vulnerability types that are excluded (e.g., "Self-XSS", "Missing rate limiting", "Best practices without demonstrated impact"). Copy ALL as strings in the array. |
| `policy.rules` | Look for program rules, guidelines, or policy text. Extract each rule as a separate string. Include: testing restrictions, disclosure rules, account rules, reporting requirements. |
| `policy.banned_test_types` | Extract any explicitly banned testing methods (e.g., "No social engineering", "No physical attacks", "No DDoS"). |
| `policy.special_instructions` | Any unique program-specific instructions that don't fit other fields. |
| `response_efficiency` | Usually shown as response time metrics on the program page — time to first response, time to triage, time to bounty, time to resolution. |
| `stats` | Reports resolved count, hackers thanked, total bounties paid — usually visible on the program overview. |

### Handling Missing Data

- If a field is not visible on the page, set it to `null` (not empty string, not 0)
- If the bounty table is not shown, set `bounty_table` to `null`
- If in_scope is empty or not visible, set to `[]` and add a note in scrape_log: `{handle} OK (no scope visible)`
- Never guess or infer — only record what you can actually read on the page

## Step 3: Summary Report

After all programs are scraped, create `summary.json`:

```json
{
  "completed_at": "2026-03-09T16:00:00Z",
  "total_programs_found": 0,
  "total_scraped": 0,
  "total_failed": 0,
  "programs_with_bounties": 0,
  "severity_ranges": {
    "highest_critical_bounty": {"program": "", "amount": 0},
    "average_critical_bounty": 0,
    "highest_high_bounty": {"program": "", "amount": 0}
  },
  "most_common_in_scope_types": {},
  "programs_by_asset_count": []
}
```

## Error Handling

- If a program page returns 404 or access denied: log as `FAIL (404)` or `FAIL (access_denied)`, move to next
- If Chrome times out: retry once, then log as `FAIL (timeout)` and move on
- If the page requires login to view scope: log as `FAIL (login_required)` and move on
- If you hit rate limiting: wait 30 seconds, then continue
- Save after EVERY program — never batch saves. If the session crashes, completed work is preserved.

## Execution Order

1. Create output directory if it doesn't exist
2. Run Step 1 (discover all programs) — save index immediately
3. Run Step 2 (scrape each program) — save after each one
4. Run Step 3 (summary) — only after all programs attempted

## Important Constraints

- Do NOT skip programs — attempt every single one
- Do NOT summarize or abbreviate scope entries — copy them verbatim
- Do NOT combine multiple programs into one file — one JSON per program
- Do NOT hold all data in memory — write to disk after each program
- If a program has 50+ in-scope assets, still capture all of them
- Work through programs alphabetically or in discovery order — don't jump around
- Estimate: HackerOne has 500-1000+ public BBPs. This will take time. That's fine.
