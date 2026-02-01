"""Subdomain enumeration using subfinder."""

from bountyhound.utils import run_tool, ToolNotFoundError


class SubdomainScanner:
    """Wrapper for subfinder subdomain enumeration."""

    def __init__(self, config_path: str | None = None):
        self.tool_name = "subfinder"
        self.config_path = config_path

    def run(self, domain: str, timeout: int = 300) -> list[str]:
        """Run subfinder against a domain.

        Args:
            domain: Target domain
            timeout: Timeout in seconds (default 5 minutes)

        Returns:
            List of discovered subdomains

        Raises:
            ToolNotFoundError: If subfinder is not installed
        """
        result = run_tool(
            self.tool_name,
            ["-d", domain, "-silent"],
            config_path=self.config_path,
            timeout=timeout,
        )

        if result.returncode != 0:
            return []

        return self.parse_output(result.stdout)

    def parse_output(self, output: str) -> list[str]:
        """Parse subfinder output into list of subdomains."""
        subdomains = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line and "." in line:
                subdomains.append(line)
        return subdomains
