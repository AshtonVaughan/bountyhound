"""Tool Bridge - Subprocess execution for BountyHound security tools.

Async functions build CLI commands and run them in a thread pool;
sync wrappers call asyncio.run() for blocking callers. Subprocess
primitives are imported from _subprocess.py (canonical implementation).
"""

import asyncio

from engine.core._subprocess import (
    run_tool as _run_tool,
    check_tool_available,
    ToolNotFoundError,
    ToolTimeoutError,
)

# Re-export for consumers that import from tool_bridge directly
__all__ = [
    "check_tool_available",
    "ToolNotFoundError",
    "ToolTimeoutError",
    "nuclei_scan",
    "sqlmap_test",
    "nmap_scan",
    "ffuf_fuzz",
    "amass_enum",
    "gobuster_enum",
    "bloodhound_enum",
    "metasploit_execute",
    "nessus_scan",
    "volatility_analyze",
    "zeek_analyze",
]


# ---------------------------------------------------------------------------
# Async tool functions
# ---------------------------------------------------------------------------

async def nuclei_scan(
    urls: list[str],
    templates: list[str] | None = None,
    severity: str = "",
) -> dict:
    """Run nuclei template-based vulnerability scan."""
    cmd = ["nuclei", "-json", "-silent"]
    for u in urls:
        cmd += ["-u", u]
    if templates:
        for t in templates:
            cmd += ["-t", t]
    if severity:
        cmd += ["-severity", severity]
    return await asyncio.to_thread(_run_tool, cmd, 300, True)


async def sqlmap_test(
    url: str,
    method: str = "GET",
    data: str = "",
    level: int = 1,
    risk: int = 1,
) -> dict:
    """Run sqlmap SQL injection test."""
    cmd = ["sqlmap", "-u", url, "--batch", f"--level={level}", f"--risk={risk}"]
    if method.upper() != "GET":
        cmd += ["--method", method.upper()]
    if data:
        cmd += ["--data", data]
    return await asyncio.to_thread(_run_tool, cmd, 300, False)


async def nmap_scan(
    targets: list[str],
    ports: str = "",
    scan_type: str = "sV",
    aggressive: bool = False,
) -> dict:
    """Run nmap port scan with XML output."""
    cmd = ["nmap", f"-{scan_type}", "-oX", "-"]
    if ports:
        cmd += ["-p", ports]
    if aggressive:
        cmd.append("-A")
    cmd += targets
    return await asyncio.to_thread(_run_tool, cmd, 300, False)


async def ffuf_fuzz(
    url: str,
    wordlist: str,
    method: str = "GET",
    match_status: str = "",
    filter_status: str = "404",
) -> dict:
    """Run ffuf web fuzzer."""
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-X", method, "-of", "json", "-s"]
    if match_status:
        cmd += ["-mc", match_status]
    if filter_status:
        cmd += ["-fc", filter_status]
    return await asyncio.to_thread(_run_tool, cmd, 300, True)


async def amass_enum(
    domain: str,
    passive: bool = False,
    include_unresolved: bool = False,
) -> dict:
    """Run amass subdomain enumeration."""
    cmd = ["amass", "enum", "-d", domain, "-json", "/dev/stdout"]
    if passive:
        cmd.append("-passive")
    if include_unresolved:
        cmd.append("-include-unresolvable")
    return await asyncio.to_thread(_run_tool, cmd, 600, True)


async def gobuster_enum(url: str, wordlist: str, mode: str = "dir") -> dict:
    """Run gobuster directory enumeration."""
    cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "--no-color"]
    return await asyncio.to_thread(_run_tool, cmd, 300, False)


async def bloodhound_enum(
    domain: str,
    user: str = "",
    password: str = "",
) -> dict:
    """Run BloodHound Python collector for AD enumeration."""
    cmd = ["bloodhound-python", "-d", domain, "-c", "All"]
    if user:
        cmd += ["-u", user]
    if password:
        cmd += ["-p", password]
    return await asyncio.to_thread(_run_tool, cmd, 600, False)


async def metasploit_execute(
    module: str,
    options: dict[str, str],
) -> dict:
    """Run a Metasploit module via msfconsole resource script."""
    lines = [f"use {module}"]
    for k, v in options.items():
        lines.append(f"set {k} {v}")
    lines += ["run", "exit"]
    script = "\n".join(lines) + "\n"
    cmd = ["msfconsole", "-q", "-r", "/dev/stdin"]
    return await asyncio.to_thread(_run_tool, cmd, 600, False, script)


async def nessus_scan(target: str, template: str = "basic") -> dict:
    """Run Nessus CLI scan."""
    cmd = ["nessuscli", "scan", "--targets", target, "--template", template]
    return await asyncio.to_thread(_run_tool, cmd, 600, False)


async def volatility_analyze(
    memory_file: str,
    plugin: str = "pslist",
) -> dict:
    """Run Volatility memory forensics plugin."""
    cmd = ["vol", "-f", memory_file, plugin]
    return await asyncio.to_thread(_run_tool, cmd, 300, False)


async def zeek_analyze(pcap_file: str) -> dict:
    """Run Zeek network traffic analysis on a PCAP file."""
    cmd = ["zeek", "-r", pcap_file]
    return await asyncio.to_thread(_run_tool, cmd, 300, False)


# ---------------------------------------------------------------------------
# Sync wrappers - used by agents that call sync_*(**kwargs)
# ---------------------------------------------------------------------------

def sync_nuclei_scan(**kwargs) -> dict:
    return asyncio.run(nuclei_scan(**kwargs))

def sync_sqlmap_test(**kwargs) -> dict:
    return asyncio.run(sqlmap_test(**kwargs))

def sync_nmap_scan(**kwargs) -> dict:
    return asyncio.run(nmap_scan(**kwargs))

def sync_ffuf_fuzz(**kwargs) -> dict:
    return asyncio.run(ffuf_fuzz(**kwargs))

def sync_amass_enum(**kwargs) -> dict:
    return asyncio.run(amass_enum(**kwargs))

def sync_gobuster_enum(**kwargs) -> dict:
    return asyncio.run(gobuster_enum(**kwargs))

def sync_bloodhound_enum(**kwargs) -> dict:
    return asyncio.run(bloodhound_enum(**kwargs))

def sync_metasploit_execute(**kwargs) -> dict:
    return asyncio.run(metasploit_execute(**kwargs))

def sync_nessus_scan(**kwargs) -> dict:
    return asyncio.run(nessus_scan(**kwargs))

def sync_volatility_analyze(**kwargs) -> dict:
    return asyncio.run(volatility_analyze(**kwargs))

def sync_zeek_analyze(**kwargs) -> dict:
    return asyncio.run(zeek_analyze(**kwargs))
