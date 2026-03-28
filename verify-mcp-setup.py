#!/usr/bin/env python3
"""Verify BountyHound unified MCP server setup."""

import json
import sys
from pathlib import Path

def verify_setup():
    """Verify MCP server configuration."""
    errors = []

    # Check .mcp.json exists and is valid
    mcp_json = Path("C:\\Users\\vaugh\\Desktop\\BountyHound\\.mcp.json")
    if not mcp_json.exists():
        errors.append("ERROR: .mcp.json not found in project root")
    else:
        try:
            with open(mcp_json) as f:
                mcp_config = json.load(f)
            if "mcpServers" not in mcp_config:
                errors.append("ERROR: No 'mcpServers' in .mcp.json")
            elif "bounty-hound" not in mcp_config["mcpServers"]:
                errors.append("ERROR: 'bounty-hound' server not found in .mcp.json")
            else:
                print("[OK] .mcp.json properly configured with bounty-hound server")
        except json.JSONDecodeError as e:
            errors.append(f"ERROR: Invalid JSON in .mcp.json: {e}")

    # Check unified MCP server main.py exists
    main_py = Path("C:\\Users\\vaugh\\Desktop\\BountyHound\\mcp-unified-server\\main.py")
    if not main_py.exists():
        errors.append("ERROR: mcp-unified-server/main.py not found")
    else:
        print("[OK] mcp-unified-server/main.py exists")

        # Verify syntax
        try:
            import py_compile
            py_compile.compile(str(main_py), doraise=True)
            print("[OK] mcp-unified-server/main.py syntax is valid")
        except Exception as e:
            errors.append(f"ERROR: Syntax error in main.py: {e}")

    # Check Claude Code settings
    settings_json = Path.home() / ".claude" / "settings.json"
    if settings_json.exists():
        try:
            with open(settings_json) as f:
                settings = json.load(f)
            if "enabledMcpjsonServers" in settings:
                if "bounty-hound" in settings["enabledMcpjsonServers"]:
                    print("[OK] bounty-hound enabled in Claude Code settings")
                else:
                    print("[WARN] bounty-hound not explicitly enabled in settings (still may work)")
            else:
                print("[WARN] enabledMcpjsonServers not set in settings (auto-discovery may work)")
        except json.JSONDecodeError:
            errors.append("ERROR: Invalid JSON in settings.json")
    else:
        print("[WARN] Claude Code settings.json not found")

    # Check microservices ports
    print("\nMicroservices port configuration:")
    ports = {
        "proxy-engine": 8187,
        "nuclei-claude": 8188,
        "sqlmap-claude": 8189,
        "nmap-claude": 8190,
        "ffuf-claude": 8191,
        "amass-claude": 8192,
        "gobuster-claude": 8193,
        "bloodhound-claude": 8194,
        "metasploit-claude": 8195,
        "nessus-claude": 8196,
        "volatility-claude": 8197,
        "zeek-claude": 8198,
    }

    for service, port in ports.items():
        service_dir = Path(f"C:\\Users\\vaugh\\Desktop\\BountyHound\\{service}")
        if service_dir.exists():
            print(f"  [{service}] Port {port} (service found)")
        else:
            print(f"  [{service}] Port {port} (service NOT found)")

    # Print summary
    print("\n" + "="*60)
    if errors:
        print("SETUP VERIFICATION FAILED:")
        for error in errors:
            print(f"  - {error}")
        return False
    else:
        print("SETUP VERIFICATION PASSED!")
        print("\nNext steps:")
        print("1. Ensure all microservices are running on their ports (8187-8198)")
        print("2. Restart Claude Code IDE to load the unified MCP server")
        print("3. The bounty-hound MCP tools should now be available in Claude")
        print("\nAvailable tool groups:")
        print("  - nuclei_scan, nuclei_status, nuclei_cancel, nuclei_server_status")
        print("  - sqlmap_test, sqlmap_status, sqlmap_cancel, sqlmap_server_status")
        print("  - nmap_scan, nmap_status, nmap_cancel, nmap_server_status")
        print("  - ffuf_fuzz, ffuf_status, ffuf_cancel, ffuf_server_status")
        print("  - amass_enum, amass_status, amass_cancel, amass_server_status")
        print("  - gobuster_fuzz, gobuster_status, gobuster_cancel, gobuster_server_status")
        print("  - bloodhound_enum, bloodhound_status, bloodhound_cancel, bloodhound_server_status")
        print("  - metasploit_exploit, metasploit_status, metasploit_cancel, metasploit_server_status")
        print("  - nessus_scan, nessus_status, nessus_cancel, nessus_server_status")
        print("  - volatility_analyze, volatility_status, volatility_cancel, volatility_server_status")
        print("  - zeek_analyze, zeek_status, zeek_cancel, zeek_server_status")
        return True

if __name__ == "__main__":
    success = verify_setup()
    sys.exit(0 if success else 1)
