"""Configuration management for BountyHound."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class Config(BaseModel):
    """Configuration model with validation."""

    tools: dict[str, str | None]
    rate_limits: dict[str, int]
    output: dict[str, str]
    scan: dict[str, Any] | None = None
    campaign: dict[str, Any] | None = None
    api_keys: dict[str, str] | None = None

    model_config = {"extra": "allow"}


def get_default_config() -> dict[str, Any]:
    """Return default configuration."""
    return {
        "tools": {
            "subfinder": None,
            "httpx": None,
            "nmap": None,
            "nuclei": None,
            "ffuf": None,
        },
        "rate_limits": {
            "requests_per_second": 10,
            "delay_between_tools": 2,
        },
        "scan": {
            "nuclei_templates": ["cves", "vulnerabilities", "misconfigurations"],
            "nuclei_severity": "low,medium,high,critical",
            "nmap_ports": "top-1000",
        },
        "output": {
            "directory": "~/.bountyhound/results",
            "format": "markdown",
        },
        "campaign": {
            "browser": "chrome",
            "max_targets": 100,
        },
        "api_keys": {
            "shodan": "",
            "censys": "",
            "virustotal": "",
            "groq": "",
        },
    }


def get_config_path() -> Path:
    """Get the default config file path."""
    return Path.home() / ".bountyhound" / "config.yaml"


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load configuration from file, creating default if missing."""
    if config_path is None:
        config_path = get_config_path()

    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        default = get_default_config()
        save_config(default, config_path)
        return default

    with open(config_path) as f:
        return yaml.safe_load(f)


def save_config(config: dict[str, Any], config_path: Path | None = None) -> None:
    """Save configuration to file."""
    if config_path is None:
        config_path = get_config_path()

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
