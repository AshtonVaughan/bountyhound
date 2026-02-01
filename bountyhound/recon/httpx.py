"""HTTP probing using httpx."""

import json

from bountyhound.utils import run_tool, ToolNotFoundError


class HttpProber:
    """Wrapper for httpx HTTP probing."""

    def __init__(self, config_path: str | None = None):
        self.tool_name = "httpx"
        self.config_path = config_path

    def run(self, hosts: list[str], timeout: int = 300) -> list[dict]:
        """Run httpx against a list of hosts.

        Args:
            hosts: List of hostnames to probe
            timeout: Timeout in seconds

        Returns:
            List of dicts with url, status_code, tech for live hosts

        Raises:
            ToolNotFoundError: If httpx is not installed
        """
        if not hosts:
            return []

        # httpx reads from stdin
        input_data = "\n".join(hosts)

        result = run_tool(
            self.tool_name,
            ["-silent", "-json", "-tech-detect"],
            config_path=self.config_path,
            timeout=timeout,
            input_data=input_data,
        )

        if result.returncode != 0:
            return []

        return self.parse_output(result.stdout)

    def parse_output(self, output: str) -> list[dict]:
        """Parse httpx JSON output."""
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", 0),
                    "tech": data.get("tech", []),
                    "host": data.get("host", ""),
                    "ip": data.get("a", [None])[0] if data.get("a") else None,
                })
            except json.JSONDecodeError:
                continue
        return results
