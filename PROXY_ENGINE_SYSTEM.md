# ProxyEngine System - Available for Bug Bounty Testing

**Status:** Fully Operational
**Location:** `C:\Users\vaugh\Desktop\BountyHound\proxy-engine`
**API Endpoint:** `http://127.0.0.1:8187`
**Proxy Port:** `127.0.0.1:8080`

---

## What is ProxyEngine?

ProxyEngine is a comprehensive security testing platform built on mitmproxy + FastAPI that integrates:

1. **Nuclei Template Runtime** - Native YAML template interpreter supporting 3000+ templates
2. **Custom Scanner Checks** - 51+ native Python security checks
3. **10 BApp-Equivalent Extensions** - Burp Professional equivalent functionality
4. **Live Audit Engine** - Real-time traffic analysis with configurable checks
5. **Cron-Based Scheduler** - Scheduled vulnerability scans
6. **Web Dashboard** - Real-time visualization of findings

---

## Quick Start

### 1. Start ProxyEngine
```bash
cd C:\Users\vaugh\Desktop\BountyHound\proxy-engine
python main.py
```

Output:
```
mitmproxy listening on 127.0.0.1:8080
FastAPI listening on http://127.0.0.1:8187
```

### 2. Configure Browser Proxy
- **HTTP Proxy:** 127.0.0.1:8080
- **HTTPS Proxy:** 127.0.0.1:8080
- **Browser:** Brave (recommended)

### 3. Monitor Traffic via API
```bash
curl http://127.0.0.1:8187/api/flows
```

Returns all captured HTTP/HTTPS flows with:
- Request/response headers
- Request/response bodies
- Status codes
- Timing information

---

## Key Capabilities for Bug Bounty Hunting

### Endpoint Discovery
Monitor `/api/flows` while browsing target to automatically capture:
- API endpoints
- Authentication endpoints
- Admin panels
- Hidden routes
- Parameter names and types

### Vulnerability Scanning
Automatically test for:
- **SQLi** - SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **XSS** - Cross-Site Scripting (WAF bypass variants)
- **SSTI** - Server-Side Template Injection (Jinja2, Twig, Freemarker, Velocity)
- **CORS** - Cross-Origin Resource Sharing misconfigurations
- **Open Redirect** - Unvalidated redirects
- **SSRF** - Server-Side Request Forgery with IP obfuscation
- **Command Injection** - OS command execution
- **Path Traversal** - Directory traversal with bypass techniques
- **JWT** - JWT token attacks (alg:none, key confusion)
- **IDOR** - Insecure Direct Object References
- **XXE** - XML External Entity injection
- **Deserialization** - Insecure deserialization gadgets

### Real-Time Live Audit
```bash
curl -X POST http://127.0.0.1:8187/api/live-audit/toggle \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

Auto-scans traffic as it flows through proxy with:
- Rate limiting (2 checks/sec per host)
- URL deduplication (10K LRU cache)
- Configurable severity filtering
- Automatic finding extraction

### Extension Testing
10 Burp Pro equivalent extensions available:
1. **Autorize** - Authorization bypass testing
2. **JWT Editor** - JWT manipulation
3. **Param Miner** - Hidden parameter discovery
4. **Active Scan++** - Host header, cache poisoning, HTTP/2 attacks
5. **Request Smuggler** - HTTP request smuggling
6. **Upload Scanner** - File upload vulnerabilities
7. **Turbo Intruder** - Race condition testing
8. **Backslash Scanner** - Path normalization attacks
9. **CORS Scanner** - CORS misconfiguration testing
10. **CSP Auditor** - Content Security Policy analysis

---

## API Endpoints for Testing

### Flows & Traffic
```
GET /api/flows                    # All captured flows
GET /api/flows?host=target.com    # Filter by host
GET /api/flows?status=200         # Filter by status code
```

### Scanner Control
```
POST /api/scanner/run             # Start manual scan
GET /api/scanner/jobs             # List scan jobs
GET /api/scanner/findings         # Get all findings
GET /api/scanner/templates        # Nuclei template stats
```

### Live Audit
```
POST /api/live-audit/toggle       # Enable/disable
GET /api/live-audit/config        # Get configuration
GET /api/live-audit/findings      # Get findings
PUT /api/live-audit/config        # Update settings
```

### Extensions
```
GET /api/extensions               # List all extensions
POST /api/extensions/{name}/enable
POST /api/extensions/{name}/disable
```

---

## Successful Hunt Examples

### Giveaways.com.au (IDOR - HIGH)
Used ProxyEngine to:
1. Capture API traffic from browser
2. Identify `/api/collect` endpoint
3. Test endpoint for authorization flaws
4. Exploit IDOR to claim arbitrary giveaways
5. Create working Python exploit script
6. Generate HackerOne-ready report

**Finding:** IDOR vulnerability - HTTP 200 on unauthorized claims (10/10 successful)

---

## Testing Workflow

### Step 1: Setup
```bash
# Terminal 1 - Start ProxyEngine
python main.py

# Terminal 2 - Monitor flows in real-time
curl http://127.0.0.1:8187/api/flows | jq '.[] | select(.host | contains("target.com"))'
```

### Step 2: Browse Target
- Configure browser proxy to 127.0.0.1:8080
- Navigate through target application
- Interact with all features, forms, buttons
- Monitor API calls in real-time

### Step 3: Enumerate Endpoints
```bash
# Get all unique endpoints
curl http://127.0.0.1:8187/api/flows | jq -r '.[] | select(.host | contains("target.com")) | "\(.method) \(.path)"' | sort -u
```

### Step 4: Identify Vulnerabilities
```bash
# Run automated scanner
curl -X POST http://127.0.0.1:8187/api/scanner/run \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://target.com"],
    "checks": ["sqli", "xss", "ssti", "idor"],
    "severity": "medium"
  }'
```

### Step 5: Create Exploit (If Applicable)
Use discovered endpoints and vulnerable parameters to create working exploit:
```python
# Similar to giveaway_exploit.py
import requests
# Send crafted request to vulnerable endpoint
# Verify vulnerability with HTTP status code
# Document finding
```

### Step 6: Document Findings
```markdown
# Target.com - Finding Summary

## VULNERABILITY-001: [Type]
- Severity: [HIGH/MEDIUM/LOW]
- Status: VERIFIED
- Endpoint: POST /api/vulnerable
- Impact: [Description]
- Remediation: [Steps]
```

---

## Proxy Configuration (Brave Browser)

### Windows Settings
1. **Settings → Network Settings → Proxy**
   - Manual proxy configuration
   - HTTP Proxy: 127.0.0.1:8080
   - HTTPS Proxy: 127.0.0.1:8080
   - No proxy for: localhost, 127.0.0.1

2. **Certificate Installation**
   - mitmproxy generates CA certificate
   - Import to Windows trusted roots
   - Browser will trust HTTPS traffic

### Verify Setup
```bash
# Test through proxy
curl -x http://127.0.0.1:8080 https://httpbin.org/get

# Check proxy flows
curl http://127.0.0.1:8187/api/flows | grep httpbin
```

---

## Performance Notes

- **Template Caching:** LRU cache of 500 templates (~2.5MB)
- **Flow Storage:** Auto-cleanup every 10 minutes
- **Rate Limiting:** 2 checks/sec per host (configurable)
- **Live Audit:** Fire-and-forget async execution

---

## Known Limitations

1. **Geoblocking:** Sites blocking by geographic location won't work from AU IP
   - Solution: Use VPN or AWS EC2 in target country
2. **JavaScript Rendering:** Basic proxy, doesn't execute JS
   - Solution: Use browser automation + proxy for dynamic sites
3. **Binary Protocols:** WebSocket support limited
   - Solution: Use custom checks for protocol-specific testing

---

## Integration with Bug Bounty Workflow

### HackerOne Integration
1. Open HackerOne program page (e.g., `https://hackerone.com/target`)
2. Note scope (URLs, features in/out of scope)
3. Configure proxy in browser
4. Browse target while ProxyEngine captures traffic
5. Run automated scans on discovered endpoints
6. Test identified vulnerabilities manually
7. Create exploits for confirmed findings
8. Submit HackerOne report with:
   - Reproduction steps from exploit
   - Evidence (screenshots, response data)
   - Impact assessment
   - CVSS score

### Documentation Output
- `/BountyHound/findings/target_reconnaissance.md` - Scope + endpoints
- `/BountyHound/findings/target_findings.json` - Structured vulnerability data
- `/BountyHound/findings/target_exploit.py` - Working exploit code
- `/BountyHound/findings/target_REPORT.md` - HackerOne-ready report

---

## Current Status

✓ **Fully Operational**
✓ **10/10 Extensions Loaded**
✓ **51+ Custom Checks Ready**
✓ **3000+ Nuclei Templates Available**
✓ **Live Dashboard Functional**

---

## Next Steps for Current Hunt

1. Run ProxyEngine (`python main.py`)
2. Configure browser proxy
3. Access target (Verily Life Sciences HackerOne program or similar)
4. Monitor `/api/flows` for endpoint discovery
5. Run automated scans on discovered endpoints
6. Create exploits for any verified findings
7. Document in findings directory

**Remember:** Only report VERIFIED findings with proof, exploitation steps, and impact assessment.

