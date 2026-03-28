# BountyHound Security Tools Suite

**Unified Claude-integrated security testing framework with 6 advanced tools.**

Complete system for autonomous vulnerability scanning, exploitation testing, network reconnaissance, and security analysis — all controllable from Claude Code.

## Architecture Overview

```
Claude Code
    ↓
MCP Unified Server (mcp-unified-server/)
    ├── ↓ HTTP
    ├─→ Proxy Engine (8187) — Traffic interception + scanning
    ├─→ Nuclei (8188) — Template-based vuln scanning
    ├─→ SQLMap (8189) — SQL injection testing
    ├─→ Nmap (8190) — Network reconnaissance
    ├─→ Ffuf (8191) — Web fuzzing
    └─→ Amass (8192) — Subdomain enumeration
```

Each tool runs as a standalone FastAPI server with background job processing.

## Tools

### 1. Nuclei (`nuclei-claude/`)
**Template-based vulnerability scanning**
- Scans URLs against curated Nuclei templates
- Filters by severity, tags, templates
- Port: `8188`

**MCP Tools**:
- `nuclei_scan(urls, templates, severity)` — Start scan
- `nuclei_status(job_id)` — Get results
- `nuclei_cancel(job_id)` — Cancel job
- `nuclei_server_status()` — Server stats

### 2. SQLMap (`sqlmap-claude/`)
**SQL injection testing & exploitation**
- Automated SQL injection detection
- Multiple injection types supported
- Detection levels and risk control
- Port: `8189`

**MCP Tools**:
- `sqlmap_test(url, method, data, level, risk)` — Start test
- `sqlmap_status(job_id)` — Get findings
- `sqlmap_cancel(job_id)` — Cancel job
- `sqlmap_server_status()` — Server stats

### 3. Nmap (`nmap-claude/`)
**Network reconnaissance & port scanning**
- Service version detection
- Multiple scan types (SYN, TCP, UDP)
- Port range specification
- XML parsing for structured results
- Port: `8190`

**MCP Tools**:
- `nmap_scan(targets, ports, scan_type, aggressive)` — Start scan
- `nmap_status(job_id)` — Get open ports
- `nmap_cancel(job_id)` — Cancel job
- `nmap_server_status()` — Server stats

### 4. Ffuf (`ffuf-claude/`)
**Web fuzzing & parameter discovery**
- Directory/file enumeration
- Parameter fuzzing
- Status code filtering
- JSON output parsing
- Port: `8191`

**MCP Tools**:
- `ffuf_fuzz(url, wordlist, method, match_status, filter_status)` — Start fuzz
- `ffuf_status(job_id)` — Get discovered endpoints
- `ffuf_cancel(job_id)` — Cancel job
- `ffuf_server_status()` — Server stats

### 5. Amass (`amass-claude/`)
**Subdomain enumeration & reconnaissance**
- Passive enumeration mode
- Multiple data sources
- DNS resolution included
- JSON output parsing
- Port: `8192`

**MCP Tools**:
- `amass_enum(domain, passive, include_unresolved)` — Start enum
- `amass_status(job_id)` — Get subdomains
- `amass_cancel(job_id)` — Cancel job
- `amass_server_status()` — Server stats

### 6. Proxy Engine (`proxy-engine/`)
**Web traffic interception & scanning**
- Man-in-the-middle proxy (mitmproxy-based)
- Request/response modification
- Scope management
- Intruder functionality
- Port: `8080` (proxy), `8187` (API)

## Unified MCP Server

**Single entry point for Claude Code** (`mcp-unified-server/`)

Exposes all 6 tools (24 MCP tools total) via one MCP connection.

**Startup**:
```bash
cd mcp-unified-server
python main.py
```

This proxies requests to all 6 backend services.

## Shared Foundation

**`bh-core/` — Reusable utilities**
- `models.py` — Base Pydantic models (Job, Finding, Request)
- `state.py` — BaseStateManager for job tracking
- `persistence.py` — Save/load state (JSON/pickle)
- `logger.py` — Unified logging
- `mcp_base.py` — MCP server template

All tools extend these classes.

## Installation & Running

### Setup

1. **Install bh-core**:
```bash
cd bh-core
pip install -r requirements.txt
```

2. **Install each tool** (example: nuclei-claude):
```bash
cd nuclei-claude
pip install -r requirements.txt
```

3. Repeat for: `sqlmap-claude`, `nmap-claude`, `ffuf-claude`, `amass-claude`

4. **Install unified MCP server**:
```bash
cd mcp-unified-server
pip install -r requirements.txt
```

### Running Individual Tools

Each tool runs independently on its designated port:

```bash
# Terminal 1: Nuclei
cd nuclei-claude && python main.py

# Terminal 2: SQLMap
cd sqlmap-claude && python main.py

# Terminal 3: Nmap
cd nmap-claude && python main.py

# Terminal 4: Ffuf
cd ffuf-claude && python main.py

# Terminal 5: Amass
cd amass-claude && python main.py

# Terminal 6: Proxy Engine (existing)
cd proxy-engine && python main.py
```

### Running Unified MCP Server

```bash
cd mcp-unified-server
python main.py
```

Then in Claude Code, load the MCP server as `mcp-unified-server`.

## Usage Examples

### Scan a target with Nuclei
```
nuclei_scan(urls="target.com", templates="http,cves", severity="high")
```
Returns: `{"job_id": "a3f2e1c9", "status": "running", ...}`

### Poll Nuclei results
```
nuclei_status(job_id="a3f2e1c9")
```
Returns: Full job object with findings once completed.

### Scan network with Nmap
```
nmap_scan(targets="192.168.1.0/24", ports="80,443,8080", scan_type="sV", aggressive=true)
```
Returns: `{"job_id": "b4f2e2c0", "status": "running", ...}`

### Fuzz web directory
```
ffuf_fuzz(url="http://target.com/FUZZ", wordlist="/usr/share/wordlists/dirbuster/common.txt", filter_status="404")
```
Returns: `{"job_id": "c5f2e3c1", "status": "running", ...}`

### Enumerate subdomains
```
amass_enum(domain="example.com", passive=true)
```
Returns: `{"job_id": "d6f2e4c2", "status": "running", ...}`

## Data Flow

1. **Claude calls MCP tool**: `nuclei_scan(urls="target.com", templates="http")`
2. **Unified MCP server parses**: Request → JSON payload
3. **HTTP POST to backend**: `POST http://127.0.0.1:8188/api/scan`
4. **Backend creates job**: Returns `job_id`
5. **Background task spawns**: Subprocess begins scanning
6. **Claude polls status**: `nuclei_status(job_id)`
7. **Backend returns**: Job object with results (status: completed, error, cancelled)

## API Endpoints

All tools follow the same REST pattern:

```
POST   /api/{action}              — Start job (e.g., /api/scan, /api/test)
GET    /api/{action}/{job_id}     — Get job status & results
POST   /api/cancel/{job_id}       — Cancel job
GET    /api/status                — Server stats
```

## Directory Structure

```
BountyHound/
├── bh-core/                          # Shared foundation
│   ├── __init__.py
│   ├── models.py                     # Base Job, Finding, Request
│   ├── state.py                      # BaseStateManager
│   ├── persistence.py                # Save/load utilities
│   ├── logger.py                     # Logging config
│   ├── mcp_base.py                   # MCP server template
│   └── requirements.txt
│
├── mcp-unified-server/               # Single entry point
│   ├── main.py                       # Unified MCP server
│   └── requirements.txt
│
├── nuclei-claude/                    # Template-based scanning
│   ├── main.py, api.py, mcp_server.py, scanner.py, models.py, state.py
│   └── requirements.txt
│
├── sqlmap-claude/                    # SQL injection testing
├── nmap-claude/                      # Network scanning
├── ffuf-claude/                      # Web fuzzing
├── amass-claude/                     # Subdomain enumeration
│
├── proxy-engine/                     # Existing: traffic interception
└── README.md                         # This file
```

## Job Management

All jobs follow the same state machine:

```
running → completed | cancelled | error
```

**Auto-cleanup**: Every 10 minutes, old completed jobs are removed (keeps max 100).

## Memory & Performance

- **Concurrent jobs**: Unlimited (stored in-memory)
- **Auto-cleanup**: Max 100 completed/error/cancelled jobs per tool
- **Timeouts**: Configurable per request (default 30-600 seconds)
- **Concurrency**: Per-tool setting (e.g., 10 for nuclei, 50 for ffuf)

## Error Handling

All tools return errors in the job object:
```json
{
  "job_id": "a3f2e1c9",
  "status": "error",
  "error": "Scan timed out after 300s"
}
```

## Environment Variables

Each tool respects:
```bash
API_PORT=8188          # FastAPI listen port
MCP_MODE=1             # Run as MCP-only (no FastAPI)
```

## Integration with Claude

**In Claude Code**:
1. Add MCP server: `mcp-unified-server/main.py`
2. Use MCP tools directly:
   ```
   nuclei_scan(urls="target.com", templates="http")
   ```

**Cross-tool workflows**:
```
1. nmap_scan(targets="target.com")      # Discover open ports
2. ffuf_fuzz(url="target.com:8080/FUZZ") # Enumerate directories
3. nuclei_scan(urls="target.com:8080/*") # Scan found endpoints
```

## Extensibility

To add a new tool:

1. Create `{tool-name}-claude/` directory
2. Extend models from `bh-core`:
   - `BaseJob` → `{Tool}Job`
   - `BaseFinding` → `{Tool}Finding`
   - `BaseRequest` → `{Tool}Request`
3. Create `state.py`: `{Tool}StateManager(BaseStateManager)`
4. Create `scanner.py`: `start_{tool}_task()` function
5. Create `api.py`: FastAPI endpoints (POST /api/{action}, GET /api/{action}/{job_id}, etc.)
6. Create `mcp_server.py`: MCP tool definitions (register with `@mcp.tool()`)
7. Create `main.py`: Run FastAPI + job cleanup
8. Add new tool to `mcp-unified-server/main.py`

## Future Tools

Planned additions:
- **gobuster** — Directory enumeration
- **BloodHound** — Active Directory enumeration
- **Metasploit Framework** — Exploit execution
- **Nessus** — Vulnerability scanning
- **Volatility** — Memory forensics
- **Zeek** — Network analysis

Pattern is fully extensible for any CLI tool.

## Support

For questions or issues, see: `/help`
