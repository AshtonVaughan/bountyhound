# BountyHound - Bug Bounty Automation CLI

## Overview

BountyHound is a Python CLI tool that automates the bug bounty workflow from reconnaissance to reporting. It wraps proven external security tools into a cohesive pipeline, handling orchestration, state management, and results aggregation.

## Design Goals

- **Full pipeline automation**: Target → Recon → Scan → Report
- **Dual mode operation**: Interactive for exploration, batch for automation
- **Learning-friendly**: Clean code, balanced complexity
- **Wrapper-first**: Leverage battle-tested tools, focus on workflow

## CLI Structure

```
bountyhound target add example.com        # Add a target to track
bountyhound recon example.com             # Run reconnaissance
bountyhound scan example.com              # Run vulnerability scans
bountyhound pipeline example.com          # Run full pipeline (recon → scan)
bountyhound report example.com            # Generate findings report
bountyhound status                        # Show all targets and progress
bountyhound doctor                        # Check tool dependencies
```

### Modes

- **Interactive** (default): Shows progress, prompts for decisions
- **Batch**: `--batch` flag runs silently, logs to file

## Project Structure

```
bountyhound/
├── cli.py              # Entry point, argument parsing (click)
├── recon/              # Recon modules
│   ├── __init__.py
│   ├── subdomains.py   # Subfinder wrapper
│   ├── httpx.py        # HTTP probing
│   └── ports.py        # Nmap wrapper
├── scan/               # Scanning modules
│   ├── __init__.py
│   ├── nuclei.py       # Nuclei wrapper
│   └── ffuf.py         # Directory fuzzing (optional)
├── pipeline/           # Orchestration logic
│   ├── __init__.py
│   └── runner.py       # Pipeline execution
├── storage/            # Data persistence
│   ├── __init__.py
│   ├── database.py     # SQLite operations
│   └── models.py       # Data models
├── report/             # Output generation
│   ├── __init__.py
│   └── generators.py   # Markdown, HTML, JSON
├── config.py           # Configuration management
└── utils.py            # Shared utilities
```

## External Tool Dependencies

| Stage | Tool | Purpose | Install |
|-------|------|---------|---------|
| Recon | subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Recon | httpx | HTTP probing, tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| Recon | nmap | Port scanning | Package manager or nmap.org |
| Scan | nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| Scan | ffuf | Directory fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |

## Python Dependencies

- `click` - CLI framework
- `rich` - Terminal output, progress bars, tables
- `pydantic` - Data validation
- `pyyaml` - Configuration files
- `sqlite3` - Built-in database

## Data Model

### SQLite Schema

```sql
-- Targets being tracked
CREATE TABLE targets (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_recon TIMESTAMP,
    last_scan TIMESTAMP
);

-- Discovered subdomains
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    hostname TEXT NOT NULL,
    ip_address TEXT,
    status_code INTEGER,
    technologies TEXT,  -- JSON array
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_id, hostname)
);

-- Open ports
CREATE TABLE ports (
    id INTEGER PRIMARY KEY,
    subdomain_id INTEGER REFERENCES subdomains(id),
    port INTEGER NOT NULL,
    service TEXT,
    version TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(subdomain_id, port)
);

-- Vulnerability findings
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    subdomain_id INTEGER REFERENCES subdomains(id),
    name TEXT NOT NULL,
    severity TEXT,  -- info, low, medium, high, critical
    url TEXT,
    evidence TEXT,
    template TEXT,  -- nuclei template used
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Run history for tracking
CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    stage TEXT,  -- recon, scan, pipeline
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    status TEXT  -- running, completed, failed, interrupted
);
```

## Pipeline Flow

```
TARGET
   │
   ▼
┌─────────────────────────────────────────┐
│ RECON STAGE                             │
│  1. subfinder → discover subdomains     │
│  2. httpx → probe live hosts, get tech  │
│  3. nmap → scan ports on live hosts     │
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ SCAN STAGE                              │
│  1. nuclei → run vulnerability checks   │
│  2. ffuf → directory fuzzing (optional) │
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ REPORT STAGE                            │
│  Generate: Markdown, HTML, or JSON      │
│  Includes: findings, stats, evidence    │
└─────────────────────────────────────────┘
```

## Configuration

Config stored at `~/.bountyhound/config.yaml`:

```yaml
# Tool paths (auto-detected if in PATH)
tools:
  subfinder: /usr/local/bin/subfinder
  httpx: /usr/local/bin/httpx
  nmap: /usr/bin/nmap
  nuclei: /usr/local/bin/nuclei
  ffuf: /usr/local/bin/ffuf

# Rate limiting
rate_limits:
  requests_per_second: 10
  delay_between_tools: 2

# Scan options
scan:
  nuclei_templates:
    - cves
    - vulnerabilities
    - misconfigurations
  nuclei_severity: low,medium,high,critical
  nmap_ports: top-1000  # or specific like "80,443,8080"

# Output
output:
  directory: ~/.bountyhound/results
  format: markdown  # markdown, html, json

# API keys (optional, for enhanced recon)
api_keys:
  shodan: ""
  censys: ""
  virustotal: ""
```

## Error Handling

- **Missing tools**: Warn and skip stage, don't crash the pipeline
- **Tool failures**: Log error, continue with next tool/target
- **Rate limiting**: Respect configured delays, back off on 429s
- **Interruption**: Save state, allow resume with `--resume` flag
- **Network errors**: Retry with exponential backoff (3 attempts)

## Example Usage

```bash
# First run - check dependencies
$ bountyhound doctor
✓ subfinder found (v2.6.3)
✓ httpx found (v1.3.5)
✓ nuclei found (v3.1.0)
✓ nmap found (7.94)
✗ ffuf not found (optional)

# Add and scan a target
$ bountyhound target add example.com
[+] Added target: example.com

$ bountyhound pipeline example.com
[*] Starting pipeline for example.com
[*] Stage 1/3: Reconnaissance
    ├── Running subfinder... found 47 subdomains
    ├── Running httpx... 32 live hosts
    └── Running nmap... scanned top 1000 ports
[*] Stage 2/3: Vulnerability Scanning
    ├── Running nuclei... found 3 issues
[*] Stage 3/3: Report Generation
    └── Report saved: ~/.bountyhound/results/example.com/2026-02-02-report.md

# View status
$ bountyhound status
┌─────────────┬────────────┬───────────┬──────────┐
│ Target      │ Subdomains │ Findings  │ Last Run │
├─────────────┼────────────┼───────────┼──────────┤
│ example.com │ 47         │ 3 (1 med) │ 2 min    │
└─────────────┴────────────┴───────────┴──────────┘

# Batch mode for multiple targets
$ bountyhound pipeline example.com example.org --batch
```

## Future Enhancements (Out of Scope for v1)

- Web dashboard for viewing results
- Slack/Discord notifications
- Scheduled scans (cron integration)
- Diff reports (what changed since last scan)
- Bug bounty platform integrations (HackerOne, Bugcrowd)
