# Mass Exposure — Safe PoC, Scale Calculation & Report Framing

## Table of Contents
1. What Is Mass Exposure
2. Safe Enumeration Techniques
3. Calculating Scale Without Dumping Data
4. Severity Escalation Formula
5. Report Writing for Maximum Impact
6. Common Mass Exposure Patterns
7. Evidence Collection Checklist

---

## 1. What Is Mass Exposure

Mass exposure is when a vulnerability allows access to data for *many users simultaneously* — not just one account at a time. This transforms a Medium IDOR into a Critical data breach scenario.

**The difference:**
- Single-user IDOR: "I can read this one person's email address" → Medium
- Mass exposure: "I can retrieve every user's email address in one request" → Critical

**What programs want to know about mass exposure:**
1. Does the endpoint return bulk data or require per-user enumeration?
2. How many records are potentially accessible?
3. What's the sensitivity of the data (T1-T4 tier)?
4. Is authentication required?
5. Is there rate limiting that would make bulk collection impractical?

**The golden rule:** Never actually dump the full dataset. Sample 2-5 records to prove the bug, use metadata (counts, pagination) to establish scale, and stop.

---

## 2. Safe Enumeration Techniques

### Use Total Count, Not Actual Records
Almost every pagination implementation returns a `total` count in the response:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 2847293,   ← this number is your evidence
    "total_pages": 284730
  }
}
```

Request page 1 with limit=1. Screenshot the `total` field. You now have evidence of scale without collecting any actual records beyond the first one.

### Request One Record Only
```
GET /api/admin/users?page=1&limit=1
```
One record proves the vulnerability. `total` proves the scale.

### Sample Different Data Tiers
To prove sensitivity without collecting bulk:
- Request record #1 — note what fields are present
- Request record #2 (different user) — confirm same fields
- Screenshot the sensitive field names in both responses
- Stop at two records

### Estimate From ID Range
If IDs are sequential:
- Your account ID: 847,293
- Lowest ID you can access: 1
- Estimate: ~847,000 users

Even this rough estimate establishes scale for the report.

### Use Aggregation Endpoints
```
GET /api/stats/users         → {"total_users": 2847293}
GET /api/admin/dashboard     → dashboard showing user counts
GET /api/reports/overview    → aggregate statistics
```
These often reveal scale information without exposing individual records.

---

## 3. Calculating Scale Without Dumping Data

### Pagination-Based Scale Proof
```python
# Minimal Python PoC — only pulls total count, doesn't iterate
# Includes rate limit handling and common pagination format support
import requests
import time
import sys

TARGET = 'https://target.com'
AUTH_TOKEN = 'Bearer YOUR_TOKEN_HERE'
# Or use cookie: session.cookies.set('session', 'YOUR_COOKIE')

session = requests.Session()
session.headers.update({'Authorization': AUTH_TOKEN})

def get_total(data: dict) -> int | None:
    """Extract total count from any common pagination format."""
    candidates = [
        data.get('total'),
        data.get('count'),
        data.get('totalCount'),
        data.get('total_count'),
        data.get('recordCount'),
        data.get('numResults'),
        data.get('resultCount'),
        (data.get('meta') or {}).get('total'),
        (data.get('meta') or {}).get('totalCount'),
        (data.get('pagination') or {}).get('total'),
        (data.get('pagination') or {}).get('count'),
        (data.get('_meta') or {}).get('totalCount'),
        (data.get('page_info') or {}).get('total_count'),
    ]
    return next((c for c in candidates if c is not None), None)

def get_records(data: dict) -> list:
    """Extract records array from any common response format."""
    candidates = ['data', 'results', 'items', 'records', 'users',
                  'documents', 'entries', 'objects', 'list']
    for key in candidates:
        if key in data and isinstance(data[key], list):
            return data[key]
    # If root is a list:
    if isinstance(data, list):
        return data
    return []

T1_FIELDS = {'ssn','social_security','tax_id','national_id','passport_number',
             'password','password_hash','hashed_password','card_number','full_card',
             'credit_card','bank_account','routing_number','iban','medical_record',
             'diagnosis','prescription'}
T2_FIELDS = {'dob','date_of_birth','birthdate','home_address','full_address',
             'phone','mobile','personal_email','location','latitude','longitude',
             'salary','compensation','income','private_message'}

def classify_fields(record: dict) -> tuple[list, list]:
    keys_lower = {k.lower().replace('-','_') for k in record.keys()}
    t1 = [k for k in record.keys() if k.lower().replace('-','_') in T1_FIELDS]
    t2 = [k for k in record.keys() if k.lower().replace('-','_') in T2_FIELDS]
    return t1, t2

# Make the request with rate limit handling
endpoint = f'{TARGET}/api/users'
params = {'page': 1, 'limit': 1, 'per_page': 1}

for attempt in range(3):
    r = session.get(endpoint, params=params, timeout=15)

    if r.status_code == 429:
        retry_after = int(r.headers.get('Retry-After', 10))
        print(f"[!] Rate limited. Waiting {retry_after}s...")
        time.sleep(retry_after)
        continue

    if r.status_code == 401:
        print("[!] 401 Unauthorized — check your token")
        sys.exit(1)

    if r.status_code == 403:
        print("[!] 403 Forbidden — endpoint may require higher privileges")
        sys.exit(1)

    if r.status_code == 200:
        break
else:
    print("[!] Failed after 3 attempts")
    sys.exit(1)

# Also check X-Total-Count header (used by some APIs)
header_total = r.headers.get('X-Total-Count') or r.headers.get('X-Total')

data = r.json()
total = get_total(data) or header_total
records = get_records(data)

print(f"\n{'='*50}")
print(f"Endpoint: {endpoint}")
print(f"Status: {r.status_code}")
print(f"Total records accessible: {total}")
print(f"{'='*50}")

if records:
    sample = records[0]
    t1, t2 = classify_fields(sample)
    print(f"\nAll fields in response: {list(sample.keys())}")
    print(f"\n[!] T1 SENSITIVE FIELDS (Critical): {t1}")
    print(f"[!] T2 SENSITIVE FIELDS (High): {t2}")
    print(f"\nSample record (first item only):")
    for k, v in sample.items():
        print(f"  {k}: {str(v)[:80]}")
else:
    print(f"\nRaw response: {data}")
```

### Time-Based Scale Estimation
If no count is returned:
- Request page 1: note last ID or timestamp
- Request page 100: note ID/timestamp
- Extrapolate total size
- Or: binary search to find the last valid page number

### ID Space Calculation
```python
# If IDs are sequential integers:
# Test ID 1 → works
# Test ID 1,000,000 → 404 not found
# Test ID 500,000 → works
# Binary search finds the maximum
# Report: "approximately 500,000 records accessible"
```

---

## 4. Severity Escalation Formula

Use this framework to calculate the appropriate severity for your report.

### Base Severity by Access Type
| Access Type | Base Severity |
|-------------|--------------|
| Single user, read only | Low-Medium |
| Single user, write access | Medium-High |
| Mass read (all users) | High |
| Mass write/delete | Critical |

### Severity Multipliers
Apply these on top of base severity:

| Factor | Effect |
|--------|--------|
| T1 data (SSN, financial, medical) | +2 levels |
| T2 data (DOB + address + phone) | +1 level |
| No authentication required | +1 level |
| Enables account takeover | → Critical regardless |
| PII of minors | → Critical regardless |
| Real-time location data | +1 level |
| Financial account data (not just metadata) | → Critical |
| Health/medical data | → Critical (HIPAA territory) |

### Severity Cap
Maximum is Critical. If you've applied enough multipliers, just say Critical.

### Examples
```
Mass exposure of usernames only (T4):
Base: High (mass) → no multipliers → High

Single IDOR returning email + phone (T3):
Base: Medium → no T1/T2 multipliers → Medium-High

IDOR returning SSN (T1) without authentication:
Base: Medium → +2 (T1) + 1 (no auth) → Critical

Mass export endpoint returning SSN for all users, no auth:
Base: High (mass) → +2 (T1) + 1 (no auth) → Critical
```

---

## 5. Report Writing for Maximum Impact

The difference between a $500 report and a $15,000 report on the same vulnerability is often the quality of the write-up.

### Structure That Works
```markdown
## Summary
One paragraph explaining what the vulnerability is, where it is,
and the maximum possible impact at the highest severity.

## Vulnerability Details
Technical explanation of why this is vulnerable.
What authorization check is missing.

## Steps to Reproduce
1. Numbered, exact steps
2. Include exact requests (curl or Burp format)
3. Include exact responses (trimmed to show sensitive fields)
4. Reproducible by a triager who has never seen the target

## Impact
- **Data exposed:** [exact fields — be specific: "full SSN, DOB, home address"]
- **Number of users affected:** [use your scale calculation]
- **Authentication required:** [yes/no]
- **Real-world risk:** [identity theft, fraud, account takeover — make it concrete]

## Evidence
[Screenshots / request-response pairs]
```

### How to Write the Impact Section

**Weak (gets downgraded):**
> "An attacker could access user data."

**Strong (gets escalated):**
> "An unauthenticated attacker can retrieve the full profile of any of the approximately 2.8 million registered users, including their full Social Security Number, date of birth, home address, and hashed password. This data is sufficient for identity theft, fraudulent credit applications, and account takeover via credential stuffing against other services. No rate limiting is present on this endpoint, meaning the complete database can be harvested in under 30 minutes with a simple script."

### Demonstrating Scale in the Request/Response
```
# Show page 1 with limit=1, highlight the total count:
GET /api/users?page=1&per_page=1
Authorization: Bearer [your_token]

HTTP/1.1 200 OK
{
  "users": [{
    "id": 1,
    "email": "firstuser@example.com",
    "ssn": "001-01-0001",          ← highlighted
    "dob": "1980-01-01",           ← highlighted
    "address": "..."               ← highlighted
  }],
  "total": 2847293,               ← highlighted — this is your scale proof
  "page": 1
}
```

### Proving No Auth Is Required
Always include one request with the `Authorization` header removed:
```
# Without auth:
GET /api/users?page=1&per_page=1
(no Authorization header)

HTTP/1.1 200 OK  ← auth not required
{"users": [...], "total": 2847293}
```

---

## 6. Common Mass Exposure Patterns

### Broken Admin Endpoints
```
GET /api/admin/users
GET /api/admin/customers
GET /api/admin/export
GET /api/management/users
GET /api/staff/accounts
```
Test all of these without admin credentials — just your regular user token or no token.

### Export/Download Features
```
GET /api/export/users.csv
GET /api/reports/all-users
POST /api/export {"format": "csv", "include": "all"}
GET /download/user-data.json
```
Export features often bypass the per-record auth checks that protect individual endpoints.

### Search With Wildcard
```
GET /api/search?q=
GET /api/users/search?query=
GET /api/search?email=@  (matches all emails)
GET /api/search?q=*
GET /api/users?filter=
```
Empty or wildcard queries often return all records.

### Autocomplete Endpoints
```
GET /api/autocomplete/users?q=a
GET /api/suggest/users?term=j
GET /api/typeahead?query=
```
Autocomplete is often implemented without rate limiting and can enumerate the entire user base by iterating through a-z.

### Pagination Limit Manipulation
```
# Normal:
GET /api/orders?page=1&limit=10

# Abused:
GET /api/orders?page=1&limit=999999
GET /api/orders?page=1&limit=-1
GET /api/orders?page=1&per_page=100000
GET /api/orders (no limit — defaults to all)
```

### Object Listing Without Scoping
```
GET /api/documents        ← should return MY documents
                          ← actually returns ALL documents
GET /api/messages         ← should be my inbox
                          ← returns all messages in the system
```

---

## 7. Evidence Collection Checklist

For a bulletproof report, collect all of this:

```
[ ] Screenshot of your own data (establish baseline — what you SHOULD see)
[ ] Screenshot of another user's data (evidence of the IDOR)
[ ] Request showing the exact parameter you changed
[ ] Response showing sensitive fields present
[ ] Total count from pagination metadata
[ ] Test with no auth (if applicable) — prove auth isn't required
[ ] Timestamp on all screenshots
[ ] Two different victim IDs tested (rules out coincidence)
[ ] Sensitive field names explicitly called out in report
[ ] Calculated potential impact scale (N users × T1 data = X severity)
[ ] curl-reproducible PoC command (triager can run it themselves)
```

### The curl PoC Template
Always include a one-liner the triager can run:
```bash
# Authenticated as regular user, accessing another user's T1 data:
curl -s -H "Authorization: Bearer YOUR_TOKEN" \
  "https://target.com/api/users/12345" | python3 -m json.tool

# Unauthenticated mass exposure:
curl -s "https://target.com/api/export/users?limit=1" | python3 -m json.tool
# Note "total" field in response for scale
```
