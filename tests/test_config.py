"""Tests for configuration module."""

import tempfile
from pathlib import Path

from bountyhound.config import Config, get_default_config, load_config, save_config


def test_default_config_has_required_fields():
    config = get_default_config()
    assert "tools" in config
    assert "rate_limits" in config
    assert "output" in config


def test_config_model_validates():
    config = Config(
        tools={"subfinder": None, "httpx": None, "nmap": None, "nuclei": None},
        rate_limits={"requests_per_second": 10, "delay_between_tools": 2},
        output={"directory": "~/.bountyhound/results", "format": "markdown"},
    )
    assert config.rate_limits["requests_per_second"] == 10


def test_save_and_load_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        original = get_default_config()
        save_config(original, config_path)
        loaded = load_config(config_path)
        assert loaded["rate_limits"]["requests_per_second"] == original["rate_limits"]["requests_per_second"]


def test_load_config_creates_default_if_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "nonexistent" / "config.yaml"
        config = load_config(config_path)
        assert config is not None
        assert config_path.exists()
