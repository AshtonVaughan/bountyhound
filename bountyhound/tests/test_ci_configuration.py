"""Test that CI/CD configuration files exist and are valid."""

import pytest
from pathlib import Path
import yaml


def test_github_workflows_directory_exists():
    """Test that .github/workflows directory exists."""
    workflows_dir = Path(".github/workflows")
    assert workflows_dir.exists(), ".github/workflows directory should exist"
    assert workflows_dir.is_dir(), ".github/workflows should be a directory"


def test_test_workflow_exists():
    """Test that test workflow file exists and is valid YAML."""
    test_workflow = Path(".github/workflows/test.yml")
    assert test_workflow.exists(), "test.yml workflow should exist"

    # Validate YAML syntax
    with open(test_workflow) as f:
        config = yaml.safe_load(f)

    assert "name" in config, "Workflow should have a name"
    assert "jobs" in config, "Workflow should have jobs"
    assert "test" in config["jobs"], "Should have a 'test' job"


def test_security_scan_workflow_exists():
    """Test that security scan workflow exists."""
    security_workflow = Path(".github/workflows/security-scan.yml")
    assert security_workflow.exists(), "security-scan.yml should exist"

    with open(security_workflow) as f:
        config = yaml.safe_load(f)

    assert "jobs" in config
    assert "bandit" in config["jobs"] or "codeql" in config["jobs"]


def test_lint_workflow_exists():
    """Test that lint workflow exists."""
    lint_workflow = Path(".github/workflows/lint.yml")
    assert lint_workflow.exists(), "lint.yml should exist"


def test_setup_py_exists():
    """Test that setup.py exists for package installation."""
    setup_py = Path("setup.py")
    assert setup_py.exists(), "setup.py should exist"

    content = setup_py.read_text()
    assert "setup(" in content
    assert "name=" in content


def test_requirements_core_exists():
    """Test that core requirements file exists."""
    req_file = Path("requirements/requirements-core.txt")
    assert req_file.exists(), "requirements-core.txt should exist"
