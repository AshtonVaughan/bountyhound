"""Test that legal disclaimers and warnings are in place."""

import pytest
from pathlib import Path


def test_license_file_exists():
    """Test that LICENSE file exists."""
    license_file = Path("LICENSE")
    assert license_file.exists(), "LICENSE file must exist"

    content = license_file.read_text(encoding="utf-8")
    assert "LEGAL DISCLAIMER" in content, "LICENSE must contain legal disclaimer"
    assert "authorized" in content.lower(), "LICENSE must mention authorization requirement"


def test_security_policy_exists():
    """Test that SECURITY.md exists with proper warnings."""
    security_file = Path("SECURITY.md")
    assert security_file.exists(), "SECURITY.md must exist"

    content = security_file.read_text(encoding="utf-8")
    assert "Acceptable Use" in content, "Must define acceptable use"
    assert "Prohibited Use" in content, "Must define prohibited use"
    assert "authorization" in content.lower(), "Must mention authorization"


def test_terms_of_use_exists():
    """Test that TERMS_OF_USE.md exists."""
    terms_file = Path("TERMS_OF_USE.md")
    assert terms_file.exists(), "TERMS_OF_USE.md must exist"

    content = terms_file.read_text(encoding="utf-8")
    assert "Disclaimer" in content, "Must have disclaimer"
    assert "Liability" in content, "Must address liability"


def test_dangerous_tools_have_warnings():
    """Test that dangerous tools display legal warnings."""
    injector_file = Path("engine/omnihack/injection/injector.py")

    if injector_file.exists():
        content = injector_file.read_text(encoding="utf-8")
        assert "LEGAL WARNING" in content or "⚠️" in content, \
            "Dangerous tools must display legal warnings"
