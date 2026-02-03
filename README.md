<p align="center">
  <img src="https://raw.githubusercontent.com/AshtonVaughan/bountyhound/master/assets/logo.svg" alt="BountyHound Logo" width="400">
</p>

<h1 align="center">BountyHound</h1>

<p align="center">
  <strong>AI-Powered Bug Bounty Automation</strong><br>
  <em>From campaign URL to prioritized findings in a single command</em>
</p>

<p align="center">
  <a href="https://github.com/AshtonVaughan/bountyhound/releases"><img src="https://img.shields.io/github/v/release/AshtonVaughan/bountyhound?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://github.com/AshtonVaughan/bountyhound/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/AshtonVaughan/bountyhound/stargazers"><img src="https://img.shields.io/github/stars/AshtonVaughan/bountyhound?style=flat-square&color=yellow" alt="Stars"></a>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-configuration">Configuration</a>
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

BountyHound is an **autonomous bug bounty hunting CLI** that orchestrates reconnaissance, vulnerability scanning, and AI-powered analysis. Point it at a bug bounty program URL, and it handles the rest.

```bash
# One command. Full campaign automation.
bountyhound campaign https://hackerone.com/your-program
```

<br>

## ✨ Features

<table>
<tr>
<td width="50%">

### 🤖 AI-Powered Intelligence
- **Smart Target Selection** — AI analyzes recon data to identify high-value targets
- **Finding Prioritization** — ML-driven severity assessment and bounty estimation
- **Scope Parsing** — Automatically extracts domains from campaign pages
- **Report Generation** — Executive summaries with actionable insights

</td>
<td width="50%">

### 🔍 Full Recon Pipeline
- **Subdomain Enumeration** — Powered by Subfinder
- **HTTP Probing** — Live host detection with httpx
- **Port Scanning** — Service discovery via Nmap
- **Tech Detection** — Fingerprint web technologies

</td>
</tr>
<tr>
<td width="50%">

### 🎯 Vulnerability Scanning
- **Nuclei Integration** — Thousands of vulnerability templates
- **Smart Filtering** — AI selects targets worth scanning
- **Severity Classification** — Critical/High/Medium/Low findings
- **Evidence Collection** — Full proof-of-concept data

</td>
<td width="50%">

### 🌐 Platform Support
- **HackerOne** — Full scope parsing
- **Bugcrowd** — Program extraction
- **Intigriti** — Target enumeration
- **YesWeHack** — Campaign automation

</td>
</tr>
</table>

<br>

## 🚀 Quick Start

### Prerequisites

Install the required security tools:

```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Port scanning (install via package manager)
# Ubuntu/Debian: sudo apt install nmap
# macOS: brew install nmap
# Windows: choco install nmap
```

### Installation

```bash
# Clone the repository
git clone https://github.com/AshtonVaughan/bountyhound.git
cd bountyhound

# Install BountyHound
pip install -e ".[dev]"

# Verify installation
bountyhound doctor
```

### Configuration

Create your config file at `~/.bountyhound/config.yaml`:

```yaml
api_keys:
  groq: "your-groq-api-key"  # Get one free at console.groq.com

campaign:
  browser: chrome      # Browser for cookie extraction
  max_targets: 100     # Max targets for AI selection

tools:
  subfinder: null      # Auto-detect from PATH
  httpx: null
  nuclei: null
  nmap: null
```

<br>

## 📖 Usage

### Campaign Mode (Recommended)

Run a full autonomous scan on a bug bounty program:

```bash
bountyhound campaign https://hackerone.com/security
```

<details>
<summary><b>📺 Example Output</b></summary>

```
[*] Starting campaign scan for: https://hackerone.com/security
[+] Detected platform: hackerone
[*] Fetching campaign page...
[+] Campaign page fetched
[*] Parsing campaign scope...
[+] Program: HackerOne Security
[+] Found 12 in-scope domains
[*] Running reconnaissance...
[+] Recon complete: 847 subdomains, 234 live hosts
[*] AI selecting high-value targets...
[+] AI selected 100 high-value targets
[*] Running vulnerability scans...
[+] Scan complete: 2 critical, 5 high, 12 medium findings
[*] Prioritizing findings with AI...
[+] Prioritized 19 findings
[*] Generating report summary...
[+] Report summary generated

Campaign Summary for HackerOne Security:
  Platform: hackerone
  Domains: 12
  Subdomains: 847
  Selected targets: 100
  Findings: critical=2, high=5, medium=12

AI Summary:
## Executive Summary

This assessment identified 19 vulnerabilities across the HackerOne
infrastructure, including 2 critical findings with immediate exploitation
potential...
```

</details>

### Manual Workflow

For granular control, use individual commands:

```bash
# Add a target
bountyhound target add example.com

# Run reconnaissance
bountyhound recon example.com

# Run vulnerability scan
bountyhound scan example.com

# Or run the full pipeline
bountyhound pipeline example.com

# Generate report
bountyhound report example.com -f markdown -o ./reports
```

### Command Reference

| Command | Description |
|---------|-------------|
| `doctor` | Check tool dependencies and system configuration |
| `target add <domain>` | Add a target domain to the database |
| `target list` | List all tracked targets |
| `target remove <domain>` | Remove a target and its data |
| `status` | Show status overview with finding counts |
| `recon <domain>` | Run reconnaissance (subdomains, HTTP, ports) |
| `scan <domain>` | Run Nuclei vulnerability scan |
| `pipeline <domain>` | Run full recon + scan pipeline |
| `campaign <url>` | Autonomous campaign from program URL |
| `report <domain>` | Generate findings report |

<br>

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BOUNTYHOUND                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Campaign  │───▶│    Recon    │───▶│   Scanner   │───▶│   Report    │  │
│  │   Parser    │    │   Pipeline  │    │   Engine    │    │  Generator  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│        │                  │                  │                  │          │
│        ▼                  ▼                  ▼                  ▼          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         AI ANALYZER (Groq LLM)                      │   │
│  │  • Scope Parsing  • Target Selection  • Finding Priority  • Reports │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                       │
│                                    ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         STORAGE (SQLite)                            │   │
│  │       Targets  •  Subdomains  •  Ports  •  Findings  •  Runs        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  EXTERNAL TOOLS                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Subfinder│  │  httpx   │  │   Nmap   │  │  Nuclei  │  │   ffuf   │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
bountyhound/
├── cli.py              # Command-line interface
├── config.py           # Configuration management
├── ai/
│   └── analyzer.py     # Groq LLM integration
├── browser/
│   └── session.py      # Cookie extraction & page fetching
├── campaign/
│   ├── parser.py       # Base campaign parser
│   ├── hackerone.py    # HackerOne parser
│   ├── bugcrowd.py     # Bugcrowd parser
│   ├── intigriti.py    # Intigriti parser
│   └── yeswehack.py    # YesWeHack parser
├── pipeline/
│   └── runner.py       # Recon/scan orchestration
├── recon/
│   ├── subdomains.py   # Subfinder wrapper
│   ├── httpx.py        # httpx wrapper
│   └── ports.py        # Nmap wrapper
├── scan/
│   └── nuclei.py       # Nuclei wrapper
├── report/
│   └── generators.py   # Report generation
└── storage/
    ├── database.py     # SQLite operations
    └── models.py       # Data models
```

<br>

## ⚙️ Configuration

### Full Configuration Options

```yaml
# ~/.bountyhound/config.yaml

api_keys:
  groq: "gsk_..."           # Required for AI features

campaign:
  browser: chrome           # chrome | firefox | edge
  max_targets: 100          # AI will select top N targets

tools:
  # Override auto-detection with explicit paths
  subfinder: /usr/local/bin/subfinder
  httpx: /usr/local/bin/httpx
  nuclei: /usr/local/bin/nuclei
  nmap: /usr/bin/nmap
  ffuf: /usr/local/bin/ffuf  # Optional

scan:
  nuclei_templates:         # Custom template paths
    - ~/nuclei-templates/
    - ~/custom-templates/

recon:
  subfinder_sources:        # Enable specific sources
    - crtsh
    - virustotal
    - shodan
```

### Environment Variables

```bash
export GROQ_API_KEY="gsk_..."        # Alternative to config file
export BOUNTYHOUND_DB="./custom.db"  # Custom database path
```

<br>

## 📊 Sample Output

### Status Dashboard

```
                    Target Status
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━┓
┃ Domain        ┃ Subdomains ┃ Critical┃ High ┃ Medium ┃ Low ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━┩
│ example.com   │        234 │       2 │    5 │     12 │   8 │
│ target.io     │         89 │       0 │    1 │      4 │   3 │
│ webapp.net    │        156 │       1 │    3 │      7 │   5 │
└───────────────┴────────────┴─────────┴──────┴────────┴─────┘
```

### Generated Report Structure

```markdown
# Security Assessment Report: example.com

## Executive Summary
AI-generated overview of findings and recommendations...

## Critical Findings
1. **SQL Injection** — api.example.com/users?id=1
   - Bounty Estimate: $2,500
   - Next Steps: Extract database schema...

## High Severity Findings
...

## Appendix
- Full subdomain list
- Technology fingerprints
- Port scan results
```

<br>

## 🛡️ Responsible Use

BountyHound is designed for **authorized security testing only**.

- ✅ Only test targets you have permission to scan
- ✅ Respect program scope and rules
- ✅ Follow responsible disclosure practices
- ❌ Never use against unauthorized targets
- ❌ Don't violate bug bounty program terms

<br>

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=bountyhound
```

<br>

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

<br>

---

<p align="center">
  <strong>Happy Hunting! 🎯</strong><br>
  <sub>Built with ❤️ for the bug bounty community</sub>
</p>
