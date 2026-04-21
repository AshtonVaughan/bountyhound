<h1 align="center">BountyHound v7.0</h1>

<p align="center">
  <strong>The most comprehensive bug bounty and CTF plugin for Claude Code.</strong><br>
  <em>7 autonomous agents. 41 attack skills. One command: /hunt</em>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://github.com/AshtonVaughan/bountyhound/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://claude.ai/claude-code"><img src="https://img.shields.io/badge/Claude_Code-Plugin-blueviolet?style=flat-square" alt="Claude Code"></a>
</p>

---

## What is BountyHound?

BountyHound is a Claude Code plugin that gives Claude structured offensive security methodology. It's not a scanner - it's a reasoning harness that teaches the model HOW to think about targets, not just what payloads to throw.

```
/hunt hackerone.com/program-name
```

Claude reads the program scope, fingerprints the stack, generates scored hypotheses, tests them through the browser, validates findings through a 4-layer gate, and writes H1-ready reports. Every finding must be proven with HTTP evidence before it's surfaced.

## v7.0 - What Changed

v7.0 merges three skill frameworks (BountyHound + TriageEngine + Apex Hunter) into one unified harness:

- **MENTALITY** - Never-quit reasoning engine. Failures generate new hypotheses, not defeat.
- **11 Model-Native Reasoning techniques** - Implementation inference, cross-feature state attacks, statistical oracles, crypto decision trees, cache key isolation, and more.
- **Trust boundary + developer assumption analysis** - Find WHERE authorization decisions happen, then find WHERE developers assumed wrong.
- **Non-obvious surface checklist** - Import/export, webhook handlers, legacy API versions, file processing pipelines, admin preview features.
- **Variant analysis** - One confirmed finding automatically generates 5 follow-up hypotheses.
- **Zero-day logic** - Logic flaw investigation, blast radius escalation.
- **CTF mode** - Full Pwn/Rev/Crypto/Web/Forensics/Misc methodology.
- **Anomaly hunting** - Baseline normal behavior first, then hunt deviations.
- **Confidence tags** - CONFIRMED/INFERRED/ASSUMED on every claim. No fabricated findings.

## Architecture

```
bountyhound-agent/
  agents/          7 autonomous sub-agents (recon, hypothesis, validation, reporting, auth, source audit)
  skills/          41 attack methodology skills (injection, auth, IDOR, cloud, mobile, blockchain, RE, etc.)
  engine/          Python tools (H1 API, IDOR harness, JS differ, nuclei gen, scope monitor, CVE feed)
  data/            Databases (operational DB, H1 programs, CVE reference)
  memory/          Cross-target patterns, hunting playbook, per-target history
  commands/        /hunt, /creds, /agents, /feedback, /campaign
```

## The Hunt Pipeline

```
/hunt <target>
  |
  v
  1. TARGET RESEARCH     - subdomain enum, port scan, tech fingerprint, JS crawl, CVE lookup
  2. TARGET MODEL        - structured JSON model of the target's attack surface
  3. HYPOTHESIS GEN      - scored queue: CVE baseline + novel hypotheses + cross-target patterns
  4. BROWSER TESTING     - Chrome automation + proxy capture + GIF recording per hypothesis
  5. 4-LAYER VALIDATION  - by-design check, browser repro, curl chain, impact analysis
  6. REPORT              - H1-ready markdown with reproduce.py, before/after diff, CVSS
```

## 41 Attack Skills

| Category | Skills |
|----------|--------|
| **Injection** | SQL, XSS, SSTI, XXE, OS command, blind injection (OOB) |
| **Auth** | JWT, OAuth/OIDC/SAML, session attacks, MFA bypass |
| **Access Control** | IDOR/BOLA harness, data exfiltration, business logic |
| **Network** | Request smuggling, WAF bypass, rate limit bypass, stealth mode |
| **Crypto** | Weak RNG, padding oracle, KDF audit, algorithm downgrade |
| **Advanced** | Race conditions, deserialization, side-channel, memory corruption |
| **Platform** | Cloud (AWS/GCP/Azure), mobile (Android/iOS), blockchain, IoT/hardware |
| **AI** | LLM prompt injection, jailbreak chains |
| **Binary** | Reverse engineering, kernel/anti-cheat, DLL injection |
| **Operations** | Parallel hunting, campaign planner, headless mode, nuclei template gen |
| **Reporting** | Exploit gate, report psychology, H1 API submission, feedback handling |

## Installation

Add BountyHound as a marketplace plugin in Claude Code:

```json
{
  "extraKnownMarketplaces": {
    "bountyhound-marketplace": {
      "source": {
        "source": "git",
        "url": "https://github.com/AshtonVaughan/bountyhound.git"
      }
    }
  }
}
```

Then enable `bountyhound-agent@bountyhound-marketplace` in your plugins.

### Optional: Security Tools

BountyHound adapts to what's available. Full mode uses these if installed:

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# Vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Port scanning
# apt install nmap / brew install nmap / choco install nmap
```

Without these tools, BountyHound operates in browser-only mode using Chrome automation and curl.

## Usage

```
/hunt <target>              Full autonomous hunt
/hunt <h1-program-url>      Hunt with program scope auto-parsed
/creds list                 Show saved credentials
/campaign <target>          Multi-session strategic campaign
/feedback                   Handle H1/Bugcrowd analyst response
```

## How It Thinks

BountyHound v7.0 doesn't just run tools. It reasons about targets:

1. **Classifies the target** - Web app? Browser extension? Electron? Mobile? API-first?
2. **Finds trust boundaries** - Where does the app make authorization decisions?
3. **Identifies broken assumptions** - What did the developer assume that isn't true?
4. **Applies model-native reasoning** - Implementation inference, cross-feature state, statistical oracles
5. **Hunts anomalies** - Baselines normal behavior, then investigates deviations
6. **Chains findings** - Every confirmed signal asks "what does this enable?"
7. **Never gives up** - Failed hypotheses generate new ones. The queue grows as you learn.

## Responsible Use

BountyHound is for authorized security testing only - bug bounty programs, CTF competitions, and authorized pentests. Only test in-scope assets per program rules.

## License

MIT License - see [LICENSE](LICENSE) for details.
