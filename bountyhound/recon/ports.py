"""Port scanning using nmap."""

import re

from bountyhound.utils import run_tool, ToolNotFoundError


class PortScanner:
    """Wrapper for nmap port scanning."""

    def __init__(self, config_path: str | None = None):
        self.tool_name = "nmap"
        self.config_path = config_path

    def run(
        self,
        hosts: list[str],
        ports: str = "--top-ports 1000",
        timeout: int = 600,
    ) -> dict[str, list[dict]]:
        """Run nmap against a list of hosts.

        Args:
            hosts: List of IPs or hostnames to scan
            ports: Port specification (default: top 1000)
            timeout: Timeout in seconds

        Returns:
            Dict mapping host to list of port info dicts

        Raises:
            ToolNotFoundError: If nmap is not installed
        """
        if not hosts:
            return {}

        # Build args - use greppable output for easy parsing
        args = ["-oG", "-", "-T4"]
        if ports.startswith("--"):
            args.append(ports)
        else:
            args.extend(["-p", ports])
        args.extend(hosts)

        result = run_tool(
            self.tool_name,
            args,
            config_path=self.config_path,
            timeout=timeout,
        )

        if result.returncode != 0:
            return {}

        return self.parse_output(result.stdout)

    def parse_output(self, output: str) -> dict[str, list[dict]]:
        """Parse nmap greppable output."""
        results = {}

        for line in output.split("\n"):
            if not line.startswith("Host:"):
                continue

            # Extract host IP
            host_match = re.match(r"Host:\s+(\S+)", line)
            if not host_match:
                continue
            host = host_match.group(1)

            # Extract ports section
            ports_match = re.search(r"Ports:\s+(.+?)(?:\t|$)", line)
            if not ports_match:
                continue

            ports = []
            port_entries = ports_match.group(1).split(", ")
            for entry in port_entries:
                # Format: port/state/protocol//service//version/
                parts = entry.split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    ports.append({
                        "port": int(parts[0]),
                        "protocol": parts[2],
                        "service": parts[4] if parts[4] else None,
                        "version": parts[6] if len(parts) > 6 and parts[6] else None,
                    })

            if ports:
                results[host] = ports

        return results
