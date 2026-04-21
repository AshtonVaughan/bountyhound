---
name: creds
description: Manage saved credentials for bug bounty targets
arguments:
  - name: action
    description: "Action: list, show <target>, add <target>, refresh <target>"
    required: true
---

# Credentials Manager

**Action:** $ARGUMENTS

## Parse Action

Extract the action and optional target from `$ARGUMENTS`:
- `list` -- List all targets with saved credentials
- `show <target>` -- Display credentials for a target (mask sensitive values)
- `add <target>` -- Interactive setup for new target credentials
- `refresh <target>` -- Refresh expired tokens

---

## Action: list

```bash
CREDS_BASE="C:/Users/vaugh/BountyHound/findings"
echo "=== Saved Credentials ==="
for dir in "$CREDS_BASE"/*/credentials; do
  if [ -d "$dir" ]; then
    TARGET=$(basename $(dirname "$dir"))
    ENV_FILE="$dir/$TARGET-creds.env"
    if [ -f "$ENV_FILE" ]; then
      EXPIRY=$(grep "USER_A_TOKEN_EXPIRY" "$ENV_FILE" | cut -d= -f2)
      echo "  $TARGET  (expires: ${EXPIRY:-unknown})"
    fi
  fi
done
```

If no credentials found, suggest: `Run /creds add <target> to set up credentials.`

## Action: show <target>

1. Read `C:/Users/vaugh/BountyHound/findings/<target>/credentials/<target>-creds.env`
2. Display all fields but **mask sensitive values** -- show only the first 8 and last 4 characters of tokens, passwords, and cookies. Example: `Bearer eyJhbG...xY9z`
3. Show token expiry status (expired / valid / unknown)

## Action: add <target>

Interactive credential setup:

1. Create directory: `mkdir -p C:/Users/vaugh/BountyHound/findings/<target>/credentials/`
2. Ask the user for auth method:
   - **Browser login** -- Spawn `auth-manager` agent to create accounts and extract tokens automatically
   - **Manual entry** -- Prompt for email, password, auth token, session cookie, CSRF token
   - **Provided credentials** -- User pastes existing .env content
3. Write credentials to `C:/Users/vaugh/BountyHound/findings/<target>/credentials/<target>-creds.env` using the standard format from the `credential-manager` skill
4. Verify tokens work with a test request:
   ```bash
   curl -s -o /dev/null -w "%{http_code}" \
     -H "Authorization: $USER_A_AUTH_TOKEN" \
     "https://<target>/api/me"
   ```
5. Report success or failure

## Action: refresh <target>

1. Load existing credentials from `C:/Users/vaugh/BountyHound/findings/<target>/credentials/<target>-creds.env`
2. Check if `USER_A_REFRESH_TOKEN` exists:
   - **Yes** -- Attempt API-based token refresh
   - **No** -- Fall back to browser re-authentication via `auth-manager`
3. Update the .env file with new token values and new expiry timestamp
4. Update the `Last refreshed` comment at the top of the file
5. Verify the new tokens with a test request
6. Report result

---

**Execute the requested action now.**
