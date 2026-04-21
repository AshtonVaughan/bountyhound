"""
Agent file validation tests.

Tests that all agent files have required structure and metadata.
"""
import pytest
from pathlib import Path


def get_all_agent_files():
    """Find all agent markdown files."""
    agents_dir = Path(__file__).parent.parent.parent / "agents"
    return list(agents_dir.rglob("*.md"))


@pytest.mark.parametrize("agent_file", get_all_agent_files())
def test_agent_file_exists(agent_file):
    """Test that agent file exists and is readable."""
    assert agent_file.exists(), f"Agent file {agent_file} not found"
    assert agent_file.is_file(), f"Agent path {agent_file} is not a file"


@pytest.mark.parametrize("agent_file", get_all_agent_files())
def test_agent_has_content(agent_file):
    """Test that agent file has content."""
    content = agent_file.read_text(encoding='utf-8')
    assert len(content) > 0, f"Agent file {agent_file} is empty"
    assert len(content) > 100, f"Agent file {agent_file} suspiciously short ({len(content)} chars)"


@pytest.mark.parametrize("agent_file", get_all_agent_files())
def test_agent_has_heading(agent_file):
    """Test that agent file has a markdown heading."""
    content = agent_file.read_text(encoding='utf-8')
    assert content.startswith("#"), f"Agent file {agent_file} missing markdown heading"


@pytest.mark.parametrize("agent_file", get_all_agent_files())
def test_agent_is_valid_markdown(agent_file):
    """Test basic markdown validity."""
    content = agent_file.read_text(encoding='utf-8')

    # Should not have common markdown errors
    assert "]()" not in content, f"Agent {agent_file} has empty link target"
    assert not content.strip().endswith("```"), f"Agent {agent_file} has unclosed code block"
