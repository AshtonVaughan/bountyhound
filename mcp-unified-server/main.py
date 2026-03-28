"""Unified MCP server for all BountyHound security tools.

Aggregates tools from:
TIER 0 (Core):
- Proxy Engine (8187)

TIER 1 (Recon):
- Nuclei (8188), SQLMap (8189), Nmap (8190), Ffuf (8191), Amass (8192)
- Gobuster (8193), BloodHound (8194), Metasploit (8195)

TIER 2 (Analysis):
- Nessus (8196), Volatility (8197), Zeek (8198)
"""

from __future__ import annotations

import json
import logging

import httpx
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("mcp-unified-server")

mcp = FastMCP(
    "bounty-hound",
    instructions="""BountyHound Security Tools Suite - 11 Integrated Tools

TIER 1 - RECONNAISSANCE & EXPLOITATION (9 tools)
1. Nuclei - Template-based vulnerability scanning
2. SQLMap - SQL injection testing & exploitation
3. Nmap - Network port scanning & service detection
4. Ffuf - Web directory/parameter fuzzing
5. Amass - Subdomain enumeration
6. Gobuster - Directory enumeration alternative
7. BloodHound - Active Directory enumeration + graph analysis
8. Metasploit - Exploit execution & sessions

TIER 2 - ANALYSIS & FORENSICS (3 tools)
9. Nessus - Comprehensive vulnerability scanning
10. Volatility - Memory forensics & malware analysis
11. Zeek - Network traffic analysis & threat detection

Plus:
- Proxy Engine - Web traffic interception & scanning

All tools run as background jobs with status polling.""",
)

APIS = {
    # Tier 0
    "proxy": "http://127.0.0.1:8187",
    # Tier 1
    "nuclei": "http://127.0.0.1:8188",
    "sqlmap": "http://127.0.0.1:8189",
    "nmap": "http://127.0.0.1:8190",
    "ffuf": "http://127.0.0.1:8191",
    "amass": "http://127.0.0.1:8192",
    "gobuster": "http://127.0.0.1:8193",
    "bloodhound": "http://127.0.0.1:8194",
    "metasploit": "http://127.0.0.1:8195",
    # Tier 2
    "nessus": "http://127.0.0.1:8196",
    "volatility": "http://127.0.0.1:8197",
    "zeek": "http://127.0.0.1:8198",
}


async def _get(url: str, endpoint: str) -> dict:
    """Make GET request to an API."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(f"{url}{endpoint}")
        response.raise_for_status()
        return response.json()


async def _post(url: str, endpoint: str, data: dict) -> dict:
    """Make POST request to an API."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(f"{url}{endpoint}", json=data)
        response.raise_for_status()
        return response.json()


# ── Nuclei Tools ──────────────────────────────────────────────────────────

@mcp.tool()
async def nuclei_scan(urls: str, templates: str = "", severity: str = "") -> str:
    """Scan URLs with Nuclei templates.

    Args:
        urls: Comma-separated URLs to scan
        templates: Comma-separated template names (e.g., 'http,cves')
        severity: Filter by severity (critical, high, medium, low, info)

    Returns:
        JSON response with job_id and status
    """
    url_list = [u.strip() for u in urls.split(",") if u.strip()]
    template_list = [t.strip() for t in templates.split(",") if t.strip()]

    data = {"urls": url_list, "templates": template_list, "timeout": 300.0, "concurrency": 10}
    if severity:
        data["severity"] = severity

    result = await _post(APIS["nuclei"], "/api/scan", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def nuclei_status(job_id: str) -> str:
    """Get Nuclei scan status and results.

    Args:
        job_id: Job ID from nuclei_scan

    Returns:
        JSON response with job status and findings
    """
    result = await _get(APIS["nuclei"], f"/api/scan/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def nuclei_cancel(job_id: str) -> str:
    """Cancel a running Nuclei scan."""
    result = await _post(APIS["nuclei"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def nuclei_server_status() -> str:
    """Get Nuclei server status."""
    result = await _get(APIS["nuclei"], "/api/status")
    return json.dumps(result, indent=2)


# ── SQLMap Tools ──────────────────────────────────────────────────────────

@mcp.tool()
async def sqlmap_test(
    url: str,
    method: str = "GET",
    data: str = "",
    level: int = 1,
    risk: int = 1,
) -> str:
    """Test a URL for SQL injection vulnerabilities.

    Args:
        url: Target URL to test
        method: HTTP method (GET, POST, etc.)
        data: POST body data
        level: Detection level 1-5 (higher = more thorough)
        risk: Risk level 1-3 (higher = more aggressive)

    Returns:
        JSON response with job_id and status
    """
    data_dict = {
        "url": url,
        "method": method,
        "data": data,
        "level": level,
        "risk": risk,
        "timeout": 300.0,
    }
    result = await _post(APIS["sqlmap"], "/api/test", data_dict)
    return json.dumps(result, indent=2)


@mcp.tool()
async def sqlmap_status(job_id: str) -> str:
    """Get SQLMap test status and findings."""
    result = await _get(APIS["sqlmap"], f"/api/test/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def sqlmap_cancel(job_id: str) -> str:
    """Cancel a running SQLMap test."""
    result = await _post(APIS["sqlmap"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def sqlmap_server_status() -> str:
    """Get SQLMap server status."""
    result = await _get(APIS["sqlmap"], "/api/status")
    return json.dumps(result, indent=2)


# ── Nmap Tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def nmap_scan(targets: str, ports: str = "", scan_type: str = "sV", aggressive: bool = False) -> str:
    """Scan targets with Nmap.

    Args:
        targets: Comma-separated targets (IPs, hostnames, or CIDR)
        ports: Specific ports (e.g., '80,443' or '1-10000')
        scan_type: Scan type - sV (service), sS (syn), sT (connect), sU (UDP)
        aggressive: Enable aggressive scanning (-A flag)

    Returns:
        JSON response with job_id and status
    """
    target_list = [t.strip() for t in targets.split(",") if t.strip()]

    data = {
        "targets": target_list,
        "scan_type": scan_type,
        "ports": ports,
        "aggressive": aggressive,
        "timeout": 600.0,
        "concurrency": 10,
    }
    result = await _post(APIS["nmap"], "/api/scan", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def nmap_status(job_id: str) -> str:
    """Get Nmap scan status and results."""
    result = await _get(APIS["nmap"], f"/api/scan/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def nmap_cancel(job_id: str) -> str:
    """Cancel a running Nmap scan."""
    result = await _post(APIS["nmap"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def nmap_server_status() -> str:
    """Get Nmap server status."""
    result = await _get(APIS["nmap"], "/api/status")
    return json.dumps(result, indent=2)


# ── Ffuf Tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str,
    method: str = "GET",
    match_status: str = "",
    filter_status: str = "404",
) -> str:
    """Fuzz a URL with Ffuf.

    Args:
        url: Target URL (use FUZZ keyword for fuzzing position)
        wordlist: Path to wordlist or URL
        method: HTTP method (GET, POST, etc.)
        match_status: Match by status codes (e.g., '200,204')
        filter_status: Filter out status codes (e.g., '404,500')

    Returns:
        JSON response with job_id and status
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "method": method,
        "match_status": match_status,
        "filter_status": filter_status,
        "timeout": 300.0,
        "concurrency": 50,
    }
    result = await _post(APIS["ffuf"], "/api/fuzz", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def ffuf_status(job_id: str) -> str:
    """Get Ffuf fuzz status and results."""
    result = await _get(APIS["ffuf"], f"/api/fuzz/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def ffuf_cancel(job_id: str) -> str:
    """Cancel a running Ffuf fuzz."""
    result = await _post(APIS["ffuf"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def ffuf_server_status() -> str:
    """Get Ffuf server status."""
    result = await _get(APIS["ffuf"], "/api/status")
    return json.dumps(result, indent=2)


# ── Amass Tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def amass_enum(domain: str, passive: bool = False, include_unresolved: bool = False) -> str:
    """Enumerate subdomains for a domain using Amass.

    Args:
        domain: Target domain to enumerate
        passive: Passive enumeration only (no network queries)
        include_unresolved: Include DNS names that don't resolve to IPs

    Returns:
        JSON response with job_id and status
    """
    data = {
        "domain": domain,
        "passive": passive,
        "include_unresolved": include_unresolved,
        "timeout": 600.0,
        "concurrency": 10,
    }
    result = await _post(APIS["amass"], "/api/enum", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def amass_status(job_id: str) -> str:
    """Get Amass enumeration status and results."""
    result = await _get(APIS["amass"], f"/api/enum/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def amass_cancel(job_id: str) -> str:
    """Cancel a running Amass enumeration."""
    result = await _post(APIS["amass"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def amass_server_status() -> str:
    """Get Amass server status."""
    result = await _get(APIS["amass"], "/api/status")
    return json.dumps(result, indent=2)


# ── Gobuster Tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def gobuster_fuzz(
    url: str,
    wordlist: str,
    method: str = "GET",
    timeout: float = 300.0,
    concurrency: int = 50,
) -> str:
    """Directory enumeration with Gobuster.

    Args:
        url: Base URL for enumeration
        wordlist: Path to wordlist or URL
        method: HTTP method (GET, POST, etc.)
        timeout: Request timeout in seconds
        concurrency: Number of concurrent requests

    Returns:
        JSON response with job_id and status
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "method": method,
        "timeout": timeout,
        "concurrency": concurrency,
    }
    result = await _post(APIS["gobuster"], "/api/fuzz", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def gobuster_status(job_id: str) -> str:
    """Get Gobuster enumeration status and results."""
    result = await _get(APIS["gobuster"], f"/api/fuzz/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def gobuster_cancel(job_id: str) -> str:
    """Cancel a running Gobuster enumeration."""
    result = await _post(APIS["gobuster"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def gobuster_server_status() -> str:
    """Get Gobuster server status."""
    result = await _get(APIS["gobuster"], "/api/status")
    return json.dumps(result, indent=2)


# ── BloodHound Tools ──────────────────────────────────────────────────────────

@mcp.tool()
async def bloodhound_enum(domain: str, username: str = "", password: str = "") -> str:
    """Enumerate Active Directory with BloodHound.

    Args:
        domain: Target domain
        username: Domain username (optional)
        password: Domain password (optional)

    Returns:
        JSON response with job_id and status
    """
    data = {
        "domain": domain,
        "username": username,
        "password": password,
        "timeout": 600.0,
    }
    result = await _post(APIS["bloodhound"], "/api/enum", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def bloodhound_status(job_id: str) -> str:
    """Get BloodHound enumeration status and results."""
    result = await _get(APIS["bloodhound"], f"/api/enum/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def bloodhound_cancel(job_id: str) -> str:
    """Cancel a running BloodHound enumeration."""
    result = await _post(APIS["bloodhound"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def bloodhound_server_status() -> str:
    """Get BloodHound server status."""
    result = await _get(APIS["bloodhound"], "/api/status")
    return json.dumps(result, indent=2)


# ── Metasploit Tools ──────────────────────────────────────────────────────────

@mcp.tool()
async def metasploit_exploit(
    module: str,
    target: str,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> str:
    """Execute exploit with Metasploit.

    Args:
        module: Exploit module (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
        target: Target IP/hostname
        lhost: Local listener host
        lport: Local listener port

    Returns:
        JSON response with job_id and status
    """
    data = {
        "module": module,
        "target": target,
        "lhost": lhost,
        "lport": lport,
        "timeout": 600.0,
    }
    result = await _post(APIS["metasploit"], "/api/exploit", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def metasploit_status(job_id: str) -> str:
    """Get Metasploit exploit status and session info."""
    result = await _get(APIS["metasploit"], f"/api/exploit/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def metasploit_cancel(job_id: str) -> str:
    """Cancel a running Metasploit exploit."""
    result = await _post(APIS["metasploit"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def metasploit_server_status() -> str:
    """Get Metasploit server status."""
    result = await _get(APIS["metasploit"], "/api/status")
    return json.dumps(result, indent=2)


# ── Nessus Tools ──────────────────────────────────────────────────────────────

@mcp.tool()
async def nessus_scan(targets: str, scan_type: str = "basic") -> str:
    """Scan targets with Nessus.

    Args:
        targets: Comma-separated targets
        scan_type: Scan type (basic, full, discovery)

    Returns:
        JSON response with job_id and status
    """
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    data = {
        "targets": target_list,
        "scan_type": scan_type,
        "timeout": 1800.0,
    }
    result = await _post(APIS["nessus"], "/api/scan", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def nessus_status(job_id: str) -> str:
    """Get Nessus scan status and results."""
    result = await _get(APIS["nessus"], f"/api/scan/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def nessus_cancel(job_id: str) -> str:
    """Cancel a running Nessus scan."""
    result = await _post(APIS["nessus"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def nessus_server_status() -> str:
    """Get Nessus server status."""
    result = await _get(APIS["nessus"], "/api/status")
    return json.dumps(result, indent=2)


# ── Volatility Tools ──────────────────────────────────────────────────────────

@mcp.tool()
async def volatility_analyze(memory_file: str, profile: str = "auto") -> str:
    """Analyze memory dump with Volatility.

    Args:
        memory_file: Path to memory dump file
        profile: Memory profile (auto-detect by default)

    Returns:
        JSON response with job_id and status
    """
    data = {
        "memory_file": memory_file,
        "profile": profile,
        "timeout": 600.0,
    }
    result = await _post(APIS["volatility"], "/api/analyze", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def volatility_status(job_id: str) -> str:
    """Get Volatility analysis status and results."""
    result = await _get(APIS["volatility"], f"/api/analyze/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def volatility_cancel(job_id: str) -> str:
    """Cancel a running Volatility analysis."""
    result = await _post(APIS["volatility"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def volatility_server_status() -> str:
    """Get Volatility server status."""
    result = await _get(APIS["volatility"], "/api/status")
    return json.dumps(result, indent=2)


# ── Zeek Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
async def zeek_analyze(pcap_file: str, rules: str = "") -> str:
    """Analyze network traffic with Zeek.

    Args:
        pcap_file: Path to PCAP file
        rules: Custom Zeek rules (optional)

    Returns:
        JSON response with job_id and status
    """
    data = {
        "pcap_file": pcap_file,
        "rules": rules,
        "timeout": 600.0,
    }
    result = await _post(APIS["zeek"], "/api/analyze", data)
    return json.dumps(result, indent=2)


@mcp.tool()
async def zeek_status(job_id: str) -> str:
    """Get Zeek analysis status and results."""
    result = await _get(APIS["zeek"], f"/api/analyze/{job_id}")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def zeek_cancel(job_id: str) -> str:
    """Cancel a running Zeek analysis."""
    result = await _post(APIS["zeek"], f"/api/cancel/{job_id}", {})
    return json.dumps(result, indent=2)


@mcp.tool()
async def zeek_server_status() -> str:
    """Get Zeek server status."""
    result = await _get(APIS["zeek"], "/api/status")
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()
