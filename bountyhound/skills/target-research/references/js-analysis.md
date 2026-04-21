# JavaScript Bundle Analysis Reference

## Download and Format a Bundle

```bash
# Download
curl -s "https://target.com/static/js/main.abc123.js" -o main.js

# Make readable (if prettier is available)
npx prettier --parser babel main.js > main_formatted.js

# Or use python to do basic formatting
python -c "
import re, sys
src = open('main.js').read()
print(re.sub(r';', ';\n', src))
" > main_formatted.js
```

## Extract API Endpoints

```bash
# REST endpoints
grep -oE '"/api/[^"]*"' main_formatted.js | sort -u

# GraphQL
grep -iE '(graphql|__schema|__type)' main_formatted.js | head -20

# WebSocket
grep -iE '(ws://|wss://|WebSocket)' main_formatted.js | head -10

# All paths starting with /
grep -oE '"(/[a-zA-Z0-9_/-]{3,})"' main_formatted.js | sort -u | grep -v 'node_modules'
```

## Extract Auth Flow Indicators

```bash
grep -iE '(token|jwt|oauth|session|auth|login|logout|refresh|bearer|authorization)' \
  main_formatted.js | head -50
```

Look for:
- `localStorage.setItem('token', ...)` → token stored client-side (look for key name)
- `Authorization: Bearer ${token}` → JWT usage
- `/oauth/authorize` or `/auth/callback` → OAuth flow
- `grant_type=password` → password grant (legacy, often poorly secured)
- `refresh_token` → token refresh logic

## Extract Feature Flags

```bash
grep -iE '(feature_flag|featureFlag|features\.|FEATURE_|ff\.)' main_formatted.js | head -30
```

Feature flags often reveal unreleased endpoints or admin-only functionality.

## Find Internal URLs and Hostnames

```bash
# Internal domains
grep -oE '"https?://[^"]*\.(internal|corp|local|dev|staging|qa)[^"]*"' main_formatted.js

# Non-production API endpoints
grep -oE '"https?://[^"]*api[^"]*"' main_formatted.js | sort -u

# AWS/GCP/Azure endpoints
grep -oE '"https?://[^"]*\.(amazonaws\.com|googleapis\.com|azure\.com)[^"]*"' main_formatted.js
```

## Find Potential Secrets (high false positive rate — verify manually)

```bash
grep -iE '(api_key|apiKey|secret|password|token|key)\s*[:=]\s*"[^"]{8,}"' \
  main_formatted.js | grep -v 'example\|placeholder\|YOUR_\|REPLACE'
```

Any hit here: verify it's real by testing the credential before reporting.

## Source Map Exploitation

If `//# sourceMappingURL=main.js.map` is present at the end of the bundle:

```bash
curl -s "https://target.com/static/js/main.js.map" | python -c "
import json, sys
data = json.load(sys.stdin)
for src in data.get('sources', []):
    print(src)
"
```

Source maps expose the original file structure and often contain comments, logic, and
variable names that make vulnerability research dramatically easier.
