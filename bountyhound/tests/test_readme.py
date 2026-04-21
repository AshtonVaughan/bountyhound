"""Test that README.md exists and has required sections."""

import pytest
from pathlib import Path


def test_readme_exists():
    """Test that README.md exists."""
    readme = Path("README.md")
    assert readme.exists(), "README.md must exist"


def test_readme_has_required_sections():
    """Test that README has all required sections."""
    readme = Path("README.md")
    content = readme.read_text(encoding='utf-8')

    required_sections = [
        "About",
        "Features",
        "Installation",
        "Quick Start",
        "Architecture",
        "Testing Capabilities",
        "Documentation",
        "Legal & Ethics",
        "License",
    ]

    for section in required_sections:
        # Check for section heading (case-insensitive, may have emoji before text)
        # Match patterns like "## About" or "## 🎯 About"
        section_pattern = section.lower()
        assert section_pattern in content.lower(), \
            f"README must have {section} section"


def test_readme_has_legal_warning():
    """Test that README has prominent legal warning."""
    readme = Path("README.md")
    content = readme.read_text(encoding='utf-8')

    assert "LEGAL WARNING" in content or "⚠️" in content, \
        "README must have legal warning"
    assert "AUTHORIZED" in content or "authorized" in content, \
        "README must mention authorization requirement"


def test_readme_links_to_legal_docs():
    """Test that README links to legal documentation."""
    readme = Path("README.md")
    content = readme.read_text(encoding='utf-8')

    assert "LICENSE" in content, "README must link to LICENSE"
    assert "SECURITY.md" in content, "README must link to SECURITY.md"
    assert "TERMS_OF_USE.md" in content, "README must link to TERMS_OF_USE.md"
