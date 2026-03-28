---
name: creds
description: "Manage credentials for bug bounty targets — load, store, refresh, and create test accounts. Trigger this skill when the user runs /creds, when credentials are needed for authenticated testing, when tokens are expired, when you need to set up two test accounts for IDOR testing, or when any agent needs to authenticate to a target. Also trigger when credentials are missing and you need guidance on how to proceed without them."
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Credential Manager

## Storage Path

All credentials are stored per-target. The single path pattern:

```
C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env
```

Example: `findings/shopify/credentials/shopify-creds.env`

Create the directory if it doesn't exist:
```bash
mkdir -p "C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials"
```

---

## Standard .env Format

```bash
# Target: {target domain}
# Created: {ISO timestamp}
# Last refreshed: {ISO timestamp}

# --- User A (primary / victim) ---
USER_A_EMAIL=0xlucahackerone1@ashtonvaughan.com
USER_A_PASSWORD=<set at registration>
USER_A_USER_ID=12345
USER_A_SESSION_COOKIE=connect.sid=s%3A...
USER_A_AUTH_TOKEN=Bearer eyJhbG...
USER_A_CSRF_TOKEN=abc123...
USER_A_REFRESH_TOKEN=rt_...
USER_A_TOKEN_EXPIRY=2026-02-07T00:00:00Z

# --- User B (attacker / IDOR testing) ---
USER_B_EMAIL=0xlucahackerone2@ashtonvaughan.com
USER_B_PASSWORD=<set at registration>
USER_B_USER_ID=12346
USER_B_SESSION_COOKIE=connect.sid=s%3A...
USER_B_AUTH_TOKEN=Bearer eyJhbG...
USER_B_CSRF_TOKEN=def456...
USER_B_REFRESH_TOKEN=rt_...
USER_B_TOKEN_EXPIRY=2026-02-07T00:00:00Z

# --- Extra ---
API_KEY=
GRAPHQL_ENDPOINT=https://app.{target}/graphql
```

For single-account testing, use `0xluca@wearehackerone.com` as the primary. For IDOR/multi-account testing, use User A (`0xlucahackerone1@ashtonvaughan.com`) and User B (`0xlucahackerone2@ashtonvaughan.com`). See `memory/identity.md` for the full rules and fallback chain.

---

## /creds Commands

### /creds list

Show all targets with saved credentials:
```bash
ls C:/Users/vaugh/Desktop/BountyHound/findings/*/credentials/*.env 2>/dev/null | \
  sed 's/.*findings\///' | sed 's/\/credentials.*//'
```

### /creds show {target}

Display credentials (mask sensitive values):
```bash
CREDS="C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env"
if [ -f "$CREDS" ]; then
  grep -E "^(USER_[AB]_EMAIL|USER_[AB]_USER_ID|USER_[AB]_TOKEN_EXPIRY|GRAPHQL_ENDPOINT)" "$CREDS"
  echo "--- Sensitive values masked (AUTH_TOKEN, PASSWORD, CSRF_TOKEN, SESSION_COOKIE) ---"
else
  echo "No credentials found for {target}. Run /creds add {target}"
fi
```

### /creds add {target}

Interactive setup — walk through creating two test accounts:

1. Use the Chrome browser to navigate to the registration page
2. Read `memory/identity.md` to confirm which email to use (single account = `0xluca@wearehackerone.com`, IDOR = `0xlucahackerone1` + `0xlucahackerone2`)
3. Register the account(s), complete email verification if required
4. Log in, capture session cookie + auth token + CSRF token from the browser's network requests
5. Write to the standard .env format above
6. Set `Last refreshed` to today's date

If a target blocks the ashtonvaughan.com domain: fall back to `0xluca@wearehackerone.com` as alternate, or use a temp-mail service (mail.tm, guerrillamail).

### /creds refresh {target}

Refresh expired tokens:
```bash
CREDS="C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env"
source "$CREDS"

# Try refresh token first
if [ -n "$USER_A_REFRESH_TOKEN" ]; then
  NEW_TOKEN=$(curl -s -X POST "$GRAPHQL_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"refreshToken\": \"$USER_A_REFRESH_TOKEN\"}" | python -c "import sys,json; d=json.load(sys.stdin); print(d.get('accessToken',''))")
  if [ -n "$NEW_TOKEN" ]; then
    # Update the .env file
    sed -i "s|USER_A_AUTH_TOKEN=.*|USER_A_AUTH_TOKEN=Bearer $NEW_TOKEN|" "$CREDS"
    echo "Token refreshed for User A"
  fi
fi

# If refresh fails: re-authenticate via the Chrome browser
# Navigate to login page, sign in with USER_A_EMAIL + USER_A_PASSWORD, capture new tokens from network requests
```

---

## Loading Credentials in Testing

At the start of any authenticated test:

```bash
CREDS="C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env"

if [ -f "$CREDS" ]; then
  source "$CREDS"
  echo "Loaded credentials: User A ($USER_A_EMAIL), User B ($USER_B_EMAIL)"
else
  echo "ERROR: No credentials. Run /creds add {target}"
  exit 1
fi

# Use in curl
curl -s \
  -H "Authorization: $USER_A_AUTH_TOKEN" \
  -H "Cookie: $USER_A_SESSION_COOKIE" \
  -H "X-CSRF-Token: $USER_A_CSRF_TOKEN" \
  "https://{target}/api/me"
```

---

## If You Cannot Create Accounts

Don't block the hunt. Work unauthenticated:

1. Test all public endpoints — many IDOR bugs are unauthenticated
2. Test registration flow itself (weak password policy, enumeration, token prediction)
3. Test password reset flow without needing an active session
4. Test OAuth flows from the entry point
5. Document "auth required for further testing" in `{FINDINGS}/memory/context.md`

Only block on missing credentials if the entire program scope requires authentication.

---

## Token Expiry Check

Before any authenticated hunt phase, check if tokens are fresh:

```bash
source "$CREDS"
EXPIRY=$(date -d "$USER_A_TOKEN_EXPIRY" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$USER_A_TOKEN_EXPIRY" +%s 2>/dev/null)
NOW=$(date +%s)
if [ "$EXPIRY" -lt "$NOW" ]; then
  echo "WARN: User A token expired — run /creds refresh {target}"
fi
```
