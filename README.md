<p align="center">
  <img src="https://raw.githubusercontent.com/AshtonVaughan/bountyhound/master/assets/logo.svg" alt="BountyHound Logo" width="400">
</p>

<h1 align="center">BountyHound</h1>

<p align="center">
  <strong>Claude Code Plugin for AI-Powered Bug Bounty Automation</strong><br>
  <em>Just tell Claude what to hunt — it handles the rest</em>
</p>

<p align="center">
  <a href="https://github.com/AshtonVaughan/bountyhound/releases"><img src="https://img.shields.io/github/v/release/AshtonVaughan/bountyhound?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://github.com/AshtonVaughan/bountyhound/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://claude.ai/claude-code"><img src="https://img.shields.io/badge/Claude_Code-Plugin-blueviolet?style=flat-square" alt="Claude Code"></a>
</p>

<p align="center">
  <a href="#-what-is-bountyhound">About</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-capabilities">Capabilities</a>
</p>

---

<br>

```
██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
```

<br>

## 🎯 What is BountyHound?

BountyHound is a **Claude Code plugin** that turns Claude into an autonomous bug bounty hunter. Instead of manually running security tools, you just describe what you want in natural language — Claude orchestrates everything.

```
You: "Scan the HackerOne program at hackerone.com/security"

Claude: *fetches program scope*
        *enumerates subdomains*
        *probes live hosts*
        *AI-selects high-value targets*
        *runs vulnerability scans*
        *prioritizes findings*
        *generates report*

Claude: "Found 2 critical, 5 high severity issues. Here's your report..."
```

**No commands to memorize. No tool flags to remember. Just talk to Claude.**

<br>

## ⚡ How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│     YOU                          CLAUDE CODE                   BOUNTYHOUND │
│   ┌─────┐                        ┌─────────┐                   ┌─────────┐ │
│   │     │  "scan this program"   │         │   orchestrates    │  Recon  │ │
│   │ 👤  │ ───────────────────▶  │  🤖 AI  │ ───────────────▶  │  Scan   │ │
│   │     │                        │         │                   │  Report │ │
│   └─────┘  ◀─────────────────── └─────────┘ ◀───────────────  └─────────┘ │
│              prioritized report              findings & data               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **You describe the task** in plain English
2. **Claude understands** your intent and context
3. **BountyHound executes** — running subfinder, httpx, nuclei, nmap
4. **AI analyzes results** — prioritizing targets and findings
5. **Claude reports back** with actionable intelligence

<br>

## 🚀 Installation

### 1. Install Security Tools

```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Port scanning
# Ubuntu/Debian: sudo apt install nmap
# macOS: brew install nmap
# Windows: choco install nmap
```

### 2. Install BountyHound Plugin

```bash
# Clone and install
git clone https://github.com/AshtonVaughan/bountyhound.git
cd bountyhound
pip install -e .
```

### 3. Configure

Create `~/.bountyhound/config.yaml`:

```yaml
api_keys:
  groq: "your-groq-api-key"  # Get free at console.groq.com

campaign:
  browser: chrome      # For cookie extraction
  max_targets: 100     # AI target selection limit
```

### 4. Add to Claude Code

Add BountyHound as a plugin in your Claude Code configuration.

<br>

## 💬 Usage

Just talk to Claude naturally. Here are some examples:

### Campaign Scanning
```
"Run a full scan on the Bugcrowd program at bugcrowd.com/tesla"

"Hunt for bugs on hackerone.com/security - focus on critical issues"

"Start a campaign against the YesWeHack program, max 50 targets"
```

### Targeted Recon
```
"Enumerate subdomains for example.com"

"Find all live hosts on target.io and check what tech they're running"

"Do a full recon on webapp.net - subdomains, ports, everything"
```

### Vulnerability Scanning
```
"Scan example.com for vulnerabilities"

"Run nuclei against the subdomains we found"

"Check api.target.com for common security issues"
```

### Reporting
```
"Generate a report of findings for example.com"

"Show me the status of all targets"

"What critical vulnerabilities have we found?"
```

<br>

## 🔧 Capabilities

<table>
<tr>
<td width="50%">

### 🤖 AI-Powered Analysis
- **Smart Target Selection** — Identifies high-value targets from thousands of subdomains
- **Finding Prioritization** — Ranks vulnerabilities by exploitability and bounty potential
- **Scope Parsing** — Extracts domains from any bug bounty program page
- **Report Generation** — Executive summaries with next steps

</td>
<td width="50%">

### 🔍 Reconnaissance
- **Subdomain Enumeration** — Subfinder integration
- **HTTP Probing** — Live host detection with httpx
- **Port Scanning** — Service discovery via Nmap
- **Tech Fingerprinting** — Identify frameworks and versions

</td>
</tr>
<tr>
<td width="50%">

### 🎯 Vulnerability Scanning
- **Nuclei Integration** — Thousands of templates
- **Intelligent Filtering** — Only scans promising targets
- **Evidence Collection** — Full PoC data for reports
- **Severity Classification** — Critical/High/Medium/Low

</td>
<td width="50%">

### 🌐 Platform Support
- **HackerOne** — Full scope parsing & auth
- **Bugcrowd** — Program extraction
- **Intigriti** — Target enumeration
- **YesWeHack** — Campaign automation

</td>
</tr>
</table>

<br>

## 🏗️ Architecture

```
bountyhound/
├── cli.py              # CLI interface (used by Claude)
├── config.py           # Configuration management
├── ai/
│   └── analyzer.py     # Groq LLM for intelligent analysis
├── browser/
│   └── session.py      # Cookie extraction & authenticated fetching
├── campaign/
│   ├── parser.py       # Base campaign parser
│   ├── hackerone.py    # HackerOne-specific parsing
│   ├── bugcrowd.py     # Bugcrowd-specific parsing
│   ├── intigriti.py    # Intigriti-specific parsing
│   └── yeswehack.py    # YesWeHack-specific parsing
├── pipeline/
│   └── runner.py       # Orchestrates recon → scan → report
├── recon/
│   ├── subdomains.py   # Subfinder wrapper
│   ├── httpx.py        # httpx wrapper
│   └── ports.py        # Nmap wrapper
├── scan/
│   └── nuclei.py       # Nuclei wrapper
├── report/
│   └── generators.py   # Markdown/JSON report generation
└── storage/
    ├── database.py     # SQLite for persistence
    └── models.py       # Data models
```


## Related Projects

- **[bountyhound-agent](https://github.com/AshtonVaughan/bountyhound-agent)** - Claude Code plugin for autonomous swarm-based hunting with parallel agents and persistent state

**How they work together:**
- **bountyhound CLI** (this repo) provides the security reconnaissance and scanning tools
- **bountyhound-agent** provides the AI orchestration, swarm methodology, and autonomous hunting capabilities

For autonomous multi-agent hunting with session persistence and parallel execution, see bountyhound-agent.

<br>
<br>

## 🛡️ Responsible Use

BountyHound is for **authorized security testing only**.

- ✅ Only test targets you have explicit permission to scan
- ✅ Respect bug bounty program scope and rules
- ✅ Follow responsible disclosure practices
- ❌ Never scan unauthorized targets
- ❌ Don't violate program terms of service

<br>

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

<br>

---

<p align="center">
  <strong>Happy Hunting! 🎯</strong><br>
  <sub>A Claude Code plugin for the bug bounty community</sub>
</p>
