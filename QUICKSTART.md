# BountyHound Quick Start Guide

## 1-Minute Setup

### Prerequisites
- Python 3.10+
- nuclei, sqlmap, nmap, ffuf, amass installed system-wide
- 8 available ports (8187-8192 + 8080 for proxy)

### Install & Run

**Terminal 1 (bh-core foundation)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/bh-core
pip install -r requirements.txt
```

**Terminal 2 (Nuclei - Port 8188)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/nuclei-claude
pip install -r requirements.txt
export API_PORT=8188
python main.py
```

**Terminal 3 (SQLMap - Port 8189)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/sqlmap-claude
pip install -r requirements.txt
export API_PORT=8189
python main.py
```

**Terminal 4 (Nmap - Port 8190)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/nmap-claude
pip install -r requirements.txt
export API_PORT=8190
python main.py
```

**Terminal 5 (Ffuf - Port 8191)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/ffuf-claude
pip install -r requirements.txt
export API_PORT=8191
python main.py
```

**Terminal 6 (Amass - Port 8192)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/amass-claude
pip install -r requirements.txt
export API_PORT=8192
python main.py
```

**Terminal 7 (Unified MCP Server)**:
```bash
cd /c/Users/vaugh/Desktop/BountyHound/mcp-unified-server
pip install -r requirements.txt
python main.py
```

## Load in Claude Code

1. Open Claude Code
2. Settings → MCP Servers
3. Add: `python /c/Users/vaugh/Desktop/BountyHound/mcp-unified-server/main.py`
4. Restart Claude Code

Now you have **24 MCP tools** available!

## Test a Tool

```
nuclei_scan(urls="scanme.nmap.org", templates="http")
nuclei_status(job_id="a3f2e1c9")
nmap_scan(targets="scanme.nmap.org", ports="80,443")
ffuf_fuzz(url="http://scanme.nmap.org/FUZZ", wordlist="/usr/share/wordlists/dirbuster/common.txt")
amass_enum(domain="nmap.org", passive=true)
```

## Documentation

- `README.md` — Full documentation and architecture
- `IMPLEMENTATION_SUMMARY.md` — Extensibility for new tools (Tier 1-3 planned)
- `QUICKSTART.md` — This guide

Happy hunting! 🔐
