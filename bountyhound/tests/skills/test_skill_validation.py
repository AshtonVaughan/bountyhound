"""
Skill file validation tests.

Tests that all skill files have required structure.
"""
import pytest
from pathlib import Path


def get_all_skill_files():
    """Find all skill markdown files."""
    skills_dir = Path(__file__).parent.parent.parent / "skills"
    return list(skills_dir.rglob("*.md"))


@pytest.mark.parametrize("skill_file", get_all_skill_files())
def test_skill_file_exists(skill_file):
    """Test that skill file exists and is readable."""
    assert skill_file.exists()
    assert skill_file.is_file()


@pytest.mark.parametrize("skill_file", get_all_skill_files())
def test_skill_has_content(skill_file):
    """Test that skill file has meaningful content."""
    content = skill_file.read_text(encoding='utf-8')
    assert len(content) > 200, f"Skill {skill_file} too short ({len(content)} chars)"


@pytest.mark.parametrize("skill_file", get_all_skill_files())
def test_skill_has_structure(skill_file):
    """Test that skill has expected sections."""
    content = skill_file.read_text(encoding='utf-8').lower()

    # Should have at least one of these sections
    has_structure = any([
        "##" in content,  # Has subsections
        "example" in content,  # Has examples
        "usage" in content,  # Has usage
        "payload" in content,  # Has payloads
    ])
    assert has_structure, f"Skill {skill_file} lacks expected structure"


def test_skill_count():
    """Test that we have the expected number of skills."""
    skills = get_all_skill_files()
    assert len(skills) == 16, f"Expected 16 skill files, found {len(skills)}"
