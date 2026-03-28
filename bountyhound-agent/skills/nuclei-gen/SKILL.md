---
name: nuclei-gen
description: |
  Generate custom nuclei templates targeting the specific tech versions found on a target.
  Use when: recon identified specific software versions, you have CVEs from the CODEX DB,
  you want targeted scanning beyond generic templates. Trigger for: "custom nuclei",
  "generate template", "CVE template", "version-specific scan", "targeted nuclei".
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


## When to Use

Use this skill when ALL of the following are true:

1. Recon has produced a `target-model.json` with a populated `tech_stack` array (each entry has `name` and `version`)
2. You want templates beyond the generic nuclei community set
3. The CODEX DB (`{AGENT}/data/CODEXDATABASE.db`) may contain matching CVEs — the generator queries it automatically

Do NOT use this skill when:
- No specific version is known (use generic nuclei templates instead)
- The tech stack is empty or version fields are missing from the target model


## Generator Invocation

```bash
# Step 1 — generate templates from target model
python {AGENT}/engine/core/nuclei_template_gen.py \
  {FINDINGS}/target-model.json \
  --out-dir {FINDINGS}/tmp/custom-templates/

# Step 2 — run them against the target
nuclei -l {FINDINGS}/tmp/targets.txt \
  -t {FINDINGS}/tmp/custom-templates/ \
  -o {FINDINGS}/phases/custom-nuclei.txt \
  -je {FINDINGS}/phases/custom-nuclei.jsonl

# Or via MCP tool (when MCP Tools are running):
# mcp__bounty-hound__nuclei_scan with templates pointing to the custom dir
```

The generator outputs a summary table of every template written. Review it before running — discard any probe templates for tech you already know is not in scope.


## What the Generator Produces

For each `tech_stack` entry with a known version, one of two outcomes:

| Outcome | Condition | Template type |
|---------|-----------|---------------|
| CVE template | CODEX DB has matching CVE | `{cve_id}.yaml` — fires on version string + status 200/302 |
| Version-probe template | No CVE found | `probe-{tech}.yaml` — fires on version string disclosure only (severity: info) |

CVE templates target up to 5 CVEs per tech, ordered by CVSS score descending. The matcher checks for the version string in the response body — this is intentionally conservative to avoid false positives. Refine the `matchers` block if you know a more reliable indicator.


## Manual Template Writing (Novel Attack Patterns)

When you have found a novel attack pattern not in CODEX, write the template directly:

### Minimal template structure

```yaml
id: custom-{target}-{vuln-slug}
info:
  name: "Short description"
  author: bountyhound
  severity: high          # critical / high / medium / low / info
  description: |
    One paragraph: what the vuln is, what an attacker can do.
  tags: custom,{tech},{vuln-type}

requests:
  - method: GET             # or POST
    path:
      - "{{BaseURL}}/vulnerable/endpoint"
    headers:
      User-Agent: "Mozilla/5.0"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "expected_string_in_response"
        part: body
      - type: status
        status:
          - 200
```

### Request with body (POST / PUT)

```yaml
requests:
  - method: POST
    path:
      - "{{BaseURL}}/api/endpoint"
    headers:
      Content-Type: application/json
    body: '{"key":"{{payload}}"}'
    payloads:
      payload:
        - "' OR 1=1--"
        - "<script>alert(1)</script>"
    matchers:
      - type: word
        words:
          - "error in your SQL"
        part: body
```

### Version detection vs exploitation

- **Detection template**: match on the version string or a known header — severity `info`
- **Exploitation template**: send a payload and match the impact (error, reflected string, SSRF callback) — severity `medium`+

Always write a detection template first. If it fires, layer the exploitation template on top.


## Testing a Template Before Running on Target

```bash
# Test against a known-good endpoint (not the target) first
nuclei -u https://httpbin.org/get -t {FINDINGS}/tmp/custom-templates/probe-nginx.yaml -debug

# Dry run on target (no actual sending — syntax check only)
nuclei -u https://target.com -t {FINDINGS}/tmp/custom-templates/ -validate

# Single-template run with verbose output
nuclei -u https://target.com \
  -t {FINDINGS}/tmp/custom-templates/cve-2024-12345.yaml \
  -debug -v
```

Fix any YAML syntax errors before running at scale. Nuclei silently skips malformed templates.


## When to Escalate to VPS

Route to VPS when **any** of the following:

- More than 20 subdomains in scope (avoid local bandwidth and rate limits)
- Templates include blind SSRF / OOB callbacks (need a clean routable IP for interactsh)
- Heavy fuzzing (>5,000 requests projected) — keeps your local IP clean

Use the `vps` skill to spin up a Vultr node, upload the templates, and run nuclei remotely:

```bash
# Via VPS skill — see skills/vps/SKILL.md for full commands
python {AGENT}/engine/vps/vultr.py status --state {FINDINGS}/tmp/vps-state.json
```

OOB callbacks: set `INTERACTSH_SERVER` env var or use nuclei's built-in `-iserver` flag on the VPS.
