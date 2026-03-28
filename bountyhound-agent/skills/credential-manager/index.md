---
name: credential-manager
description: "Load, store, and manage credentials for bug bounty targets. Provides standard .env format and token refresh patterns for all hunting agents."
---

# Credential Manager

## Credential Storage Location

All credentials are stored per-target at:

```
C:/Users/vaugh/BountyHound/findings/<target>/credentials/<target>-creds.env
```

Example: `C:/Users/vaugh/BountyHound/findings/shopify/credentials/shopify-creds.env`

## Standard .env Format

```bash
# Target: <target domain>
# Created: <ISO timestamp>
# Last refreshed: <ISO timestamp>

# --- User A (primary) ---
USER_A_EMAIL=bh.test.abc12345@gmail.com
USER_A_PASSWORD=BhTest!abc12345#Secure
USER_A_USER_ID=12345
USER_A_SESSION_COOKIE=connect.sid=s%3A...
USER_A_AUTH_TOKEN=Bearer eyJhbG...
USER_A_CSRF_TOKEN=abc123...
USER_A_REFRESH_TOKEN=rt_...
USER_A_TOKEN_EXPIRY=2026-02-07T00:00:00Z

# --- User B (IDOR testing) ---
USER_B_EMAIL=bh.test2.def67890@gmail.com
USER_B_PASSWORD=BhTest2!def67890#Secure
USER_B_USER_ID=12346
USER_B_SESSION_COOKIE=connect.sid=s%3A...
USER_B_AUTH_TOKEN=Bearer eyJhbG...
USER_B_CSRF_TOKEN=def456...
USER_B_REFRESH_TOKEN=rt_...
USER_B_TOKEN_EXPIRY=2026-02-07T00:00:00Z

# --- API Keys / Extras ---
API_KEY=
GRAPHQL_ENDPOINT=https://app.target.com/graphql
```

## Loading Credentials in Agents

Agents should load credentials at the start of any authenticated testing:

```bash
CREDS_FILE="C:/Users/vaugh/BountyHound/findings/<target>/credentials/<target>-creds.env"

if [ -f "$CREDS_FILE" ]; then
  source "$CREDS_FILE"
  echo "Loaded credentials for <target> (User A: $USER_A_EMAIL)"
else
  echo "No credentials found. Run /creds add <target> first."
fi

# Use in curl
curl -s -H "Authorization: $USER_A_AUTH_TOKEN" \
     -H "Cookie: $USER_A_SESSION_COOKIE" \
     -H "X-CSRF-Token: $USER_A_CSRF_TOKEN" \
     "https://app.target.com/api/me"
```

## Token Refresh Pattern

When a request returns 401, agents should refresh tokens:

```bash
# 1. Check if refresh token exists
if [ -n "$USER_A_REFRESH_TOKEN" ]; then
  # Try API refresh
  NEW_TOKEN=$(curl -s -X POST "$GRAPHQL_ENDPOINT" \
    -d "{\"refreshToken\": \"$USER_A_REFRESH_TOKEN\"}" | jq -r '.accessToken')
fi

# 2. If refresh fails, re-authenticate via browser
#    Spawn auth-manager agent with stored email/password

# 3. Update the .env file with new tokens
#    Write new values back to $CREDS_FILE
```

## How Agents Should Request Credentials

1. **Check for existing credentials** -- Read the .env file from the standard path
2. **If missing** -- Prompt the user to run `/creds add <target>` or spawn the `auth-manager` agent
3. **If expired** -- Run `/creds refresh <target>` or attempt automatic refresh
4. **Never hardcode tokens** -- Always load from the .env file at runtime

## Creating Credentials Directory

```bash
mkdir -p "C:/Users/vaugh/BountyHound/findings/<target>/credentials"
```

Agents MUST create the directory before writing credentials. The `auth-manager` agent writes credentials here after account creation.
