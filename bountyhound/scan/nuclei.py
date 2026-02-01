"""Vulnerability scanning using nuclei."""

import json

from bountyhound.utils import run_tool, ToolNotFoundError


class NucleiScanner:
    """Wrapper for nuclei vulnerability scanner."""

    def __init__(self, config_path: str | None = None):
        self.tool_name = "nuclei"
        self.config_path = config_path

    def run(
        self,
        urls: list[str],
        templates: list[str] | None = None,
        severity: str = "low,medium,high,critical",
        timeout: int = 1800,
    ) -> list[dict]:
        """Run nuclei against a list of URLs.

        Args:
            urls: List of URLs to scan
            templates: List of template categories (default: common ones)
            severity: Comma-separated severity levels
            timeout: Timeout in seconds (default 30 minutes)

        Returns:
            List of finding dicts

        Raises:
            ToolNotFoundError: If nuclei is not installed
        """
        if not urls:
            return []

        # Build args
        args = ["-silent", "-json", "-severity", severity]

        if templates:
            for t in templates:
                args.extend(["-t", t])

        # nuclei reads URLs from stdin
        input_data = "\n".join(urls)

        result = run_tool(
            self.tool_name,
            args,
            config_path=self.config_path,
            timeout=timeout,
            input_data=input_data,
        )

        # nuclei returns non-zero when it finds vulns, so don't check returncode
        return self.parse_output(result.stdout)

    def parse_output(self, output: str) -> list[dict]:
        """Parse nuclei JSON output."""
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "name": data.get("name", data.get("info", {}).get("name", "Unknown")),
                    "severity": data.get("severity", data.get("info", {}).get("severity", "unknown")),
                    "url": data.get("matched-at", data.get("host", "")),
                    "template": data.get("template-id", ""),
                    "evidence": data.get("extracted-results", data.get("matcher-name", "")),
                })
            except json.JSONDecodeError:
                continue
        return results
