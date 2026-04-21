"""Integration tests for the unified MCP server tool functions.

Tests each of the 11 security tools exposed by mcp-unified-server/main.py,
verifying command construction, error handling, and server status checks.
All subprocess calls are mocked - no real tool binaries required.
"""

import json
import os
import sys
from unittest.mock import patch

import pytest

# Add the MCP server directory to the path so we can import main
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp-unified-server")
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MOCK_COMPLETED = {
    "status": "completed",
    "stdout": "",
    "stderr": "",
    "returncode": 0,
}

MOCK_COMPLETED_JSON = {
    **MOCK_COMPLETED,
    "stdout": "[]",
    "parsed": [],
}


def _parse(result: str) -> dict:
    """Parse JSON string returned by an MCP tool function."""
    return json.loads(result)


# ---------------------------------------------------------------------------
# 1. Nuclei
# ---------------------------------------------------------------------------

class TestNucleiTools:
    @pytest.mark.asyncio
    async def test_nuclei_scan_command(self):
        from main import nuclei_scan

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED_JSON) as mock_run:
            result = await nuclei_scan("http://test.com", templates="cves", severity="critical")
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "nuclei"
            assert "-u" in cmd
            assert "http://test.com" in cmd
            assert "-t" in cmd
            assert "cves" in cmd
            assert "-severity" in cmd
            assert "critical" in cmd

    @pytest.mark.asyncio
    async def test_nuclei_scan_multiple_urls(self):
        from main import nuclei_scan

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED_JSON) as mock_run:
            await nuclei_scan("http://a.com, http://b.com")
            cmd = mock_run.call_args[0][0]
            assert cmd.count("-u") == 2

    @pytest.mark.asyncio
    async def test_nuclei_empty_url(self):
        from main import nuclei_scan

        result = await nuclei_scan("")
        data = _parse(result)
        assert data["status"] == "error"
        assert "No URLs" in data["message"]

    @pytest.mark.asyncio
    async def test_nuclei_tool_not_found(self):
        from main import nuclei_scan
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("nuclei not found")):
            result = await nuclei_scan("http://test.com")
            data = _parse(result)
            assert data["status"] == "error"
            assert "not found" in data["message"]

    @pytest.mark.asyncio
    async def test_nuclei_timeout(self):
        from main import nuclei_scan
        from tool_runner import ToolTimeoutError

        with patch("main.tool_runner.run_tool", side_effect=ToolTimeoutError("timed out")):
            result = await nuclei_scan("http://test.com")
            data = _parse(result)
            assert data["status"] == "error"
            assert "timed out" in data["message"]

    @pytest.mark.asyncio
    async def test_nuclei_server_status_available(self):
        from main import nuclei_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await nuclei_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "nuclei"

    @pytest.mark.asyncio
    async def test_nuclei_server_status_unavailable(self):
        from main import nuclei_server_status

        with patch("main.tool_runner.check_tool_available", return_value=False):
            result = await nuclei_server_status()
            data = _parse(result)
            assert data["available"] is False


# ---------------------------------------------------------------------------
# 2. SQLMap
# ---------------------------------------------------------------------------

class TestSqlmapTools:
    @pytest.mark.asyncio
    async def test_sqlmap_test_command(self):
        from main import sqlmap_test

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await sqlmap_test("http://test.com/page?id=1", level=3, risk=2)
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "sqlmap"
            assert "-u" in cmd
            assert "--batch" in cmd
            assert "--level=3" in cmd
            assert "--risk=2" in cmd

    @pytest.mark.asyncio
    async def test_sqlmap_post_method(self):
        from main import sqlmap_test

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            await sqlmap_test("http://test.com", method="POST", data="id=1&name=test")
            cmd = mock_run.call_args[0][0]
            assert "--method" in cmd
            assert "POST" in cmd
            assert "--data" in cmd
            assert "id=1&name=test" in cmd

    @pytest.mark.asyncio
    async def test_sqlmap_empty_url(self):
        from main import sqlmap_test

        result = await sqlmap_test("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_sqlmap_tool_not_found(self):
        from main import sqlmap_test
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await sqlmap_test("http://test.com")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_sqlmap_server_status(self):
        from main import sqlmap_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await sqlmap_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "sqlmap"


# ---------------------------------------------------------------------------
# 3. Nmap
# ---------------------------------------------------------------------------

class TestNmapTools:
    @pytest.mark.asyncio
    async def test_nmap_scan_command(self):
        from main import nmap_scan

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await nmap_scan("192.168.1.1", ports="80,443", scan_type="sS", aggressive=True)
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "nmap"
            assert "-sS" in cmd
            assert "-oX" in cmd
            assert "-p" in cmd
            assert "80,443" in cmd
            assert "-A" in cmd
            assert "192.168.1.1" in cmd

    @pytest.mark.asyncio
    async def test_nmap_multiple_targets(self):
        from main import nmap_scan

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            await nmap_scan("10.0.0.1, 10.0.0.2")
            cmd = mock_run.call_args[0][0]
            assert "10.0.0.1" in cmd
            assert "10.0.0.2" in cmd

    @pytest.mark.asyncio
    async def test_nmap_empty_targets(self):
        from main import nmap_scan

        result = await nmap_scan("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_nmap_tool_not_found(self):
        from main import nmap_scan
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await nmap_scan("192.168.1.1")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_nmap_server_status(self):
        from main import nmap_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await nmap_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "nmap"


# ---------------------------------------------------------------------------
# 4. Ffuf
# ---------------------------------------------------------------------------

class TestFfufTools:
    @pytest.mark.asyncio
    async def test_ffuf_fuzz_command(self):
        from main import ffuf_fuzz

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED_JSON) as mock_run:
            result = await ffuf_fuzz(
                "http://test.com/FUZZ", "/usr/share/wordlists/common.txt",
                method="POST", match_status="200,204", filter_status="404,500"
            )
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "ffuf"
            assert "-u" in cmd
            assert "-w" in cmd
            assert "-X" in cmd
            assert "POST" in cmd
            assert "-mc" in cmd
            assert "200,204" in cmd
            assert "-fc" in cmd
            assert "404,500" in cmd

    @pytest.mark.asyncio
    async def test_ffuf_empty_url(self):
        from main import ffuf_fuzz

        result = await ffuf_fuzz("", "/wordlist.txt")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_ffuf_tool_not_found(self):
        from main import ffuf_fuzz
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await ffuf_fuzz("http://test.com/FUZZ", "/wordlist.txt")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_ffuf_server_status(self):
        from main import ffuf_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await ffuf_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "ffuf"


# ---------------------------------------------------------------------------
# 5. Amass
# ---------------------------------------------------------------------------

class TestAmassTools:
    @pytest.mark.asyncio
    async def test_amass_enum_command(self):
        from main import amass_enum

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await amass_enum("example.com", passive=True)
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "amass"
            assert "enum" in cmd
            assert "-d" in cmd
            assert "example.com" in cmd
            assert "-passive" in cmd

    @pytest.mark.asyncio
    async def test_amass_active_no_passive_flag(self):
        from main import amass_enum

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            await amass_enum("example.com", passive=False)
            cmd = mock_run.call_args[0][0]
            assert "-passive" not in cmd

    @pytest.mark.asyncio
    async def test_amass_empty_domain(self):
        from main import amass_enum

        result = await amass_enum("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_amass_tool_not_found(self):
        from main import amass_enum
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await amass_enum("example.com")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_amass_server_status(self):
        from main import amass_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await amass_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "amass"


# ---------------------------------------------------------------------------
# 6. Gobuster
# ---------------------------------------------------------------------------

class TestGobusterTools:
    @pytest.mark.asyncio
    async def test_gobuster_fuzz_command(self):
        from main import gobuster_fuzz

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await gobuster_fuzz("http://test.com", "/wordlist.txt")
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "gobuster"
            assert "dir" in cmd
            assert "-u" in cmd
            assert "-w" in cmd
            assert "--no-color" in cmd

    @pytest.mark.asyncio
    async def test_gobuster_empty_url(self):
        from main import gobuster_fuzz

        result = await gobuster_fuzz("", "/wordlist.txt")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_gobuster_tool_not_found(self):
        from main import gobuster_fuzz
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await gobuster_fuzz("http://test.com", "/wordlist.txt")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_gobuster_server_status(self):
        from main import gobuster_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await gobuster_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "gobuster"


# ---------------------------------------------------------------------------
# 7. BloodHound
# ---------------------------------------------------------------------------

class TestBloodhoundTools:
    @pytest.mark.asyncio
    async def test_bloodhound_enum_command(self):
        from main import bloodhound_enum

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await bloodhound_enum("corp.local", username="admin", password="pass123")
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "bloodhound-python"
            assert "-d" in cmd
            assert "corp.local" in cmd
            assert "-c" in cmd
            assert "All" in cmd
            assert "-u" in cmd
            assert "admin" in cmd
            assert "-p" in cmd
            assert "pass123" in cmd

    @pytest.mark.asyncio
    async def test_bloodhound_no_credentials(self):
        from main import bloodhound_enum

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            await bloodhound_enum("corp.local")
            cmd = mock_run.call_args[0][0]
            assert "-u" not in cmd
            assert "-p" not in cmd

    @pytest.mark.asyncio
    async def test_bloodhound_empty_domain(self):
        from main import bloodhound_enum

        result = await bloodhound_enum("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_bloodhound_tool_not_found(self):
        from main import bloodhound_enum
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await bloodhound_enum("corp.local")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_bloodhound_server_status(self):
        from main import bloodhound_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await bloodhound_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "bloodhound-python"


# ---------------------------------------------------------------------------
# 8. Metasploit
# ---------------------------------------------------------------------------

class TestMetasploitTools:
    @pytest.mark.asyncio
    async def test_metasploit_exploit_command(self):
        from main import metasploit_exploit

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await metasploit_exploit(
                "exploit/windows/smb/ms17_010_eternalblue",
                "192.168.1.100",
                lhost="10.0.0.1",
                lport=5555,
            )
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "msfconsole"
            assert "-q" in cmd
            # Check stdin_data contains the resource script
            kwargs = mock_run.call_args[1]
            stdin = kwargs.get("stdin_data", "")
            assert "use exploit/windows/smb/ms17_010_eternalblue" in stdin
            assert "set RHOSTS 192.168.1.100" in stdin
            assert "set LHOST 10.0.0.1" in stdin
            assert "set LPORT 5555" in stdin

    @pytest.mark.asyncio
    async def test_metasploit_empty_module(self):
        from main import metasploit_exploit

        result = await metasploit_exploit("", "192.168.1.1")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_metasploit_empty_target(self):
        from main import metasploit_exploit

        result = await metasploit_exploit("exploit/test", "")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_metasploit_tool_not_found(self):
        from main import metasploit_exploit
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await metasploit_exploit("exploit/test", "192.168.1.1")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_metasploit_timeout(self):
        from main import metasploit_exploit
        from tool_runner import ToolTimeoutError

        with patch("main.tool_runner.run_tool", side_effect=ToolTimeoutError("timed out")):
            result = await metasploit_exploit("exploit/test", "192.168.1.1")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_metasploit_server_status(self):
        from main import metasploit_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await metasploit_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "metasploit"


# ---------------------------------------------------------------------------
# 9. Nessus
# ---------------------------------------------------------------------------

class TestNessusTools:
    @pytest.mark.asyncio
    async def test_nessus_scan_command(self):
        from main import nessus_scan

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await nessus_scan("192.168.1.0/24", scan_type="full")
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "nessuscli"
            assert "scan" in cmd
            assert "--targets" in cmd
            assert "192.168.1.0/24" in cmd
            assert "--template" in cmd
            assert "full" in cmd

    @pytest.mark.asyncio
    async def test_nessus_empty_targets(self):
        from main import nessus_scan

        result = await nessus_scan("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_nessus_tool_not_found(self):
        from main import nessus_scan
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await nessus_scan("192.168.1.1")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_nessus_server_status(self):
        from main import nessus_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await nessus_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "nessus"


# ---------------------------------------------------------------------------
# 10. Volatility
# ---------------------------------------------------------------------------

class TestVolatilityTools:
    @pytest.mark.asyncio
    async def test_volatility_analyze_command(self):
        from main import volatility_analyze

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await volatility_analyze("/tmp/memdump.raw", profile="Win10x64")
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "vol"
            assert "-f" in cmd
            assert "/tmp/memdump.raw" in cmd
            assert "--profile" in cmd
            assert "Win10x64" in cmd
            assert "pslist" in cmd

    @pytest.mark.asyncio
    async def test_volatility_auto_profile(self):
        from main import volatility_analyze

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            await volatility_analyze("/tmp/memdump.raw", profile="auto")
            cmd = mock_run.call_args[0][0]
            assert "--profile" not in cmd

    @pytest.mark.asyncio
    async def test_volatility_empty_file(self):
        from main import volatility_analyze

        result = await volatility_analyze("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_volatility_tool_not_found(self):
        from main import volatility_analyze
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await volatility_analyze("/tmp/memdump.raw")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_volatility_server_status(self):
        from main import volatility_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await volatility_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "volatility"


# ---------------------------------------------------------------------------
# 11. Zeek
# ---------------------------------------------------------------------------

class TestZeekTools:
    @pytest.mark.asyncio
    async def test_zeek_analyze_command(self):
        from main import zeek_analyze

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            result = await zeek_analyze("/tmp/capture.pcap", rules="/etc/zeek/custom.zeek")
            data = _parse(result)
            assert data["status"] == "completed"
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "zeek"
            assert "-r" in cmd
            assert "/tmp/capture.pcap" in cmd
            assert "/etc/zeek/custom.zeek" in cmd

    @pytest.mark.asyncio
    async def test_zeek_no_custom_rules(self):
        from main import zeek_analyze

        with patch("main.tool_runner.run_tool", return_value=MOCK_COMPLETED) as mock_run:
            await zeek_analyze("/tmp/capture.pcap")
            cmd = mock_run.call_args[0][0]
            # Should only be ["zeek", "-r", "/tmp/capture.pcap"]
            assert len(cmd) == 3

    @pytest.mark.asyncio
    async def test_zeek_empty_pcap(self):
        from main import zeek_analyze

        result = await zeek_analyze("")
        data = _parse(result)
        assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_zeek_tool_not_found(self):
        from main import zeek_analyze
        from tool_runner import ToolNotFoundError

        with patch("main.tool_runner.run_tool", side_effect=ToolNotFoundError("not found")):
            result = await zeek_analyze("/tmp/capture.pcap")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_zeek_timeout(self):
        from main import zeek_analyze
        from tool_runner import ToolTimeoutError

        with patch("main.tool_runner.run_tool", side_effect=ToolTimeoutError("timed out")):
            result = await zeek_analyze("/tmp/capture.pcap")
            data = _parse(result)
            assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_zeek_server_status(self):
        from main import zeek_server_status

        with patch("main.tool_runner.check_tool_available", return_value=True):
            result = await zeek_server_status()
            data = _parse(result)
            assert data["available"] is True
            assert data["tool"] == "zeek"
