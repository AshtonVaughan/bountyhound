# HackerOne Programs Database

Complete local database of ALL active HackerOne bug bounty programs with scopes, policies, bounties, and disclosed reports.

---

## 📁 Database Location

```
C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db
```

---

## 📊 Database Schema

### Tables

#### 1. **programs** (Main program information)
- `id` - HackerOne program ID
- `handle` - Program handle (unique)
- `name` - Program display name
- `url` - Program URL
- `state` - Program state (public_mode, etc.)
- `submission_state` - Submission status (open, closed)
- `offers_bounties` - Boolean: offers monetary bounties
- `offers_swag` - Boolean: offers swag/merch
- `currency` - Bounty currency (USD, EUR, etc.)
- `resolved_report_count` - Number of resolved reports
- `average_time_to_bounty_awarded` - Avg time to bounty
- `average_time_to_first_program_response` - Avg response time
- `policy` - Full program policy (markdown)
- `policy_html` - Policy HTML version
- `allows_disclosure` - Boolean: allows public disclosure
- `managed_program` - Boolean: managed by Hacker One
- `scraped_at` - Timestamp of last scrape

#### 2. **scopes** (In-scope assets)
- `id` - Auto-increment ID
- `program_id` - Foreign key to programs
- `asset_type` - Type (URL, WILDCARD, DOMAIN, IP, etc.)
- `asset_identifier` - The actual asset (example.com)
- `eligible_for_bounty` - Boolean: qualifies for bounty
- `eligible_for_submission` - Boolean: accepts submissions
- `instruction` - Special instructions for this asset
- `max_severity` - Maximum allowed severity
- `created_at` - When scope was added

#### 3. **out_of_scope** (Explicitly excluded)
- `id` - Auto-increment ID
- `program_id` - Foreign key to programs
- `asset_type` - Type of excluded asset
- `asset_identifier` - The excluded asset
- `description` - Why it's out of scope

#### 4. **severity_bounties** (Bounty ranges by severity)
- `id` - Auto-increment ID
- `program_id` - Foreign key to programs
- `severity` - Severity level (critical, high, medium, low, none)
- `min_bounty` - Minimum bounty for this severity
- `max_bounty` - Maximum bounty for this severity

#### 5. **campaigns** (Active bonus campaigns)
- `id` - Campaign ID
- `program_id` - Foreign key to programs
- `name` - Campaign name
- `description` - Campaign details
- `start_date` - Campaign start
- `end_date` - Campaign end
- `bonus_percentage` - Bonus multiplier (e.g., 2.0 = 2x)

#### 6. **disclosed_reports** (Public reports for duplicate detection)
- `id` - Report ID
- `program_id` - Foreign key to programs
- `title` - Report title
- `vulnerability_information` - Vulnerability description
- `severity_rating` - Severity (critical, high, medium, low)
- `state` - Report state
- `disclosed_at` - When it was disclosed
- `created_at` - When it was submitted

---

## 🚀 Usage

### 1. Build/Update Database

```bash
cd C:/Users/vaugh/Projects/bountyhound-agent
python tools/h1-program-scraper.py
```

**Duration**: ~1-2 hours for all programs (rate-limited)
**Frequency**: Run weekly to keep data fresh

### 2. Query Database

```bash
# Search for programs
python tools/h1-program-query.py search <keyword>

# Get program scope
python tools/h1-program-query.py scope <handle>

# Get bounty ranges
python tools/h1-program-query.py bounties <handle>

# Get disclosed reports
python tools/h1-program-query.py disclosed <handle>

# Check for duplicates
python tools/h1-program-query.py duplicate "GraphQL introspection"

# Top programs by reports
python tools/h1-program-query.py top 50

# Find programs using technology
python tools/h1-program-query.py tech "GraphQL"

# Export full program details
python tools/h1-program-query.py export <handle> output.json

# Database statistics
python tools/h1-program-query.py stats
```

### 3. Direct SQL Queries

```python
import sqlite3

conn = sqlite3.connect("C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db")
c = conn.cursor()

# Find all programs with GraphQL scope
c.execute('''
    SELECT DISTINCT p.handle, p.name
    FROM programs p
    JOIN scopes s ON p.id = s.program_id
    WHERE s.asset_identifier LIKE '%graphql%'
       OR s.instruction LIKE '%graphql%'
''')

for row in c.fetchall():
    print(row)

conn.close()
```

---

## 💡 Use Cases

### 1. **Duplicate Detection**
```bash
# Before submitting a report
python tools/h1-program-query.py duplicate "XSS in search parameter"
```

Checks disclosed reports for similar vulnerabilities to avoid duplicates.

### 2. **Program Research**
```bash
# Find programs with high bounties
sqlite3 data/h1-programs.db "
SELECT handle, severity, max_bounty
FROM severity_bounties sb
JOIN programs p ON sb.program_id = p.id
WHERE severity = 'critical'
ORDER BY max_bounty DESC
LIMIT 20"
```

### 3. **Technology-Specific Hunting**
```bash
# Find all GraphQL programs
python tools/h1-program-query.py tech "GraphQL"

# Find all mobile apps
python tools/h1-program-query.py tech "iOS"
```

### 4. **Scope Validation**
```python
import sqlite3

def is_in_scope(program_handle, url):
    conn = sqlite3.connect("data/h1-programs.db")
    c = conn.cursor()

    c.execute('''
        SELECT COUNT(*) FROM scopes s
        JOIN programs p ON s.program_id = p.id
        WHERE p.handle = ?
          AND s.eligible_for_submission = 1
          AND (
              s.asset_identifier = ?
              OR s.asset_identifier LIKE '%' || ? || '%'
          )
    ''', (program_handle, url, url))

    count = c.fetchone()[0]
    conn.close()

    return count > 0

# Example
if is_in_scope('shopify', 'shopify.com'):
    print("In scope!")
```

### 5. **Campaign Tracker**
```sql
-- Find active campaigns
SELECT
    p.handle,
    c.name,
    c.bonus_percentage,
    c.end_date
FROM campaigns c
JOIN programs p ON c.program_id = p.id
WHERE date('now') BETWEEN c.start_date AND c.end_date
ORDER BY c.bonus_percentage DESC;
```

### 6. **Competition Analysis**
```sql
-- Programs with low competition (fewer reports)
SELECT
    handle,
    name,
    resolved_report_count,
    average_time_to_bounty_awarded
FROM programs
WHERE offers_bounties = 1
  AND resolved_report_count < 100
ORDER BY resolved_report_count ASC
LIMIT 20;
```

---

## 🔧 Maintenance

### Update Database

Run scraper weekly to keep data fresh:
```bash
# Full scrape (all programs)
python tools/h1-program-scraper.py

# Or create a scheduled task
# Windows: Task Scheduler
# Linux/Mac: cron
```

### Clean Old Data

```sql
-- Remove programs no longer accepting submissions
DELETE FROM programs
WHERE submission_state != 'open';

-- Vacuum to reclaim space
VACUUM;
```

---

## 📈 Expected Stats

After full scrape:
- **Programs**: 1,500-2,000+
- **Bounty Programs**: 1,000-1,500
- **In-Scope Assets**: 10,000-15,000+
- **Disclosed Reports**: 50,000-100,000+
- **Database Size**: 50-200 MB

---

## 🎯 Integration with BountyHound

The database integrates with BountyHound agents:

### duplicate-detector Agent
```python
from tools.h1_program_query import H1ProgramQuery

def check_duplicate_before_submit(title, description):
    query = H1ProgramQuery()
    duplicates = query.check_duplicate(title, description)

    if duplicates and duplicates[0]['similarity_score'] > 70:
        print(f"⚠️  WARNING: Possible duplicate!")
        print(f"   Similar to: {duplicates[0]['title']}")
        print(f"   Program: {duplicates[0]['handle']}")
        return True

    return False
```

### scope-validator Agent
```python
def validate_scope(program_handle, target_url):
    query = H1ProgramQuery()
    scopes = query.get_program_scope(program_handle)

    for scope in scopes:
        if target_url in scope['asset_identifier']:
            if not scope['eligible_for_submission']:
                print(f"⚠️  Out of scope: {target_url}")
                return False

    return True
```

### submission-optimizer Agent
```python
def get_optimal_submission_timing(program_handle):
    conn = sqlite3.connect("data/h1-programs.db")
    c = conn.cursor()

    # Check for active campaigns
    c.execute('''
        SELECT bonus_percentage, end_date
        FROM campaigns
        WHERE program_id = (SELECT id FROM programs WHERE handle = ?)
          AND date('now') BETWEEN start_date AND end_date
    ''', (program_handle,))

    campaign = c.fetchone()
    conn.close()

    if campaign:
        return {
            'submit_now': True,
            'reason': f'{campaign[0]}x bonus until {campaign[1]}'
        }

    return {'submit_now': False, 'reason': 'No active campaign'}
```

---

## ⚠️ Rate Limiting

HackerOne has rate limits:
- **GraphQL API**: ~100 requests/minute
- **Scraper respects**: 2 second delay between programs
- **Full scrape time**: 1-2 hours

---

## 🔐 Authentication

The scraper works WITHOUT authentication for:
- Public programs
- Disclosed reports
- Program policies
- Scope information

For private programs or higher rate limits, add auth:

```python
# In h1-program-scraper.py
self.session.headers.update({
    'Authorization': f'Bearer {os.getenv("H1_API_TOKEN")}'
})
```

---

## 📊 Sample Queries

### Find high-paying programs
```sql
SELECT
    p.handle,
    p.name,
    sb.severity,
    sb.max_bounty
FROM programs p
JOIN severity_bounties sb ON p.id = sb.program_id
WHERE sb.severity = 'critical'
  AND sb.max_bounty > 10000
ORDER BY sb.max_bounty DESC;
```

### Programs with fastest response times
```sql
SELECT
    handle,
    name,
    average_time_to_first_program_response
FROM programs
WHERE average_time_to_first_program_response IS NOT NULL
ORDER BY average_time_to_first_program_response ASC
LIMIT 20;
```

### Find underexploited programs
```sql
SELECT
    handle,
    name,
    resolved_report_count,
    (SELECT COUNT(*) FROM scopes WHERE program_id = p.id) as scope_count
FROM programs p
WHERE offers_bounties = 1
  AND resolved_report_count < 50
  AND scope_count > 5
ORDER BY scope_count DESC;
```

---

## 🚀 Next Steps

1. **Build the database**: Run `h1-program-scraper.py`
2. **Test queries**: Try the examples above
3. **Integrate with BountyHound**: Use in duplicate detection, scope validation
4. **Schedule updates**: Set up weekly scraping
5. **Build dashboard**: Visualize program data

---

## 📝 Notes

- Database is fully local (no external dependencies)
- Safe to version control (no credentials stored)
- Can be backed up/shared with team
- Useful for offline hunting research
- Essential for duplicate detection before submission

---

**Created**: 2026-02-11
**Updated**: Auto-updates on each scrape
**Size**: ~50-200 MB when fully populated
