# BountyHound Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Python CLI that automates bug bounty workflows by orchestrating external security tools.

**Architecture:** Wrapper-first design using Click for CLI, SQLite for persistence, and subprocess for tool execution. Modular structure with separate packages for recon, scanning, storage, and reporting.

**Tech Stack:** Python 3.10+, Click, Rich, Pydantic, PyYAML, SQLite3

---

## Task 1: Project Setup

**Files:**
- Create: `pyproject.toml`
- Create: `bountyhound/__init__.py`
- Create: `tests/__init__.py`
- Create: `.gitignore`
- Create: `README.md`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "bountyhound"
version = "0.1.0"
description = "Bug bounty automation CLI"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "click>=8.1.0",
    "rich>=13.0.0",
    "pydantic>=2.0.0",
    "pyyaml>=6.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
]

[project.scripts]
bountyhound = "bountyhound.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v"
```

**Step 2: Create package init files**

Create `bountyhound/__init__.py`:
```python
"""BountyHound - Bug bounty automation CLI."""

__version__ = "0.1.0"
```

Create `tests/__init__.py`:
```python
"""BountyHound test suite."""
```

**Step 3: Create .gitignore**

```
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
.env
.venv
env/
venv/
.pytest_cache/
.coverage
htmlcov/
*.db
```

**Step 4: Create minimal README**

```markdown
# BountyHound

Bug bounty automation CLI that orchestrates recon and vulnerability scanning tools.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```bash
bountyhound doctor    # Check tool dependencies
bountyhound --help    # Show all commands
```
```

**Step 5: Install in development mode**

Run: `pip install -e ".[dev]"`

**Step 6: Verify installation**

Run: `python -c "import bountyhound; print(bountyhound.__version__)"`
Expected: `0.1.0`

**Step 7: Commit**

```bash
git add pyproject.toml bountyhound/__init__.py tests/__init__.py .gitignore README.md
git commit -m "feat: initialize project structure with dependencies"
```

---

## Task 2: Configuration Module

**Files:**
- Create: `bountyhound/config.py`
- Create: `tests/test_config.py`

**Step 1: Write the failing test**

Create `tests/test_config.py`:
```python
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
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with "ModuleNotFoundError" or "ImportError"

**Step 3: Write the implementation**

Create `bountyhound/config.py`:
```python
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
        "api_keys": {
            "shodan": "",
            "censys": "",
            "virustotal": "",
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
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/config.py tests/test_config.py
git commit -m "feat: add configuration module with YAML persistence"
```

---

## Task 3: Database Models and Schema

**Files:**
- Create: `bountyhound/storage/__init__.py`
- Create: `bountyhound/storage/models.py`
- Create: `tests/test_models.py`

**Step 1: Write the failing test**

Create `tests/test_models.py`:
```python
"""Tests for data models."""

from datetime import datetime

from bountyhound.storage.models import Target, Subdomain, Port, Finding, Run


def test_target_model():
    target = Target(id=1, domain="example.com", added_at=datetime.now())
    assert target.domain == "example.com"
    assert target.last_recon is None


def test_subdomain_model():
    sub = Subdomain(
        id=1,
        target_id=1,
        hostname="api.example.com",
        ip_address="1.2.3.4",
        status_code=200,
        technologies=["nginx", "php"],
    )
    assert sub.hostname == "api.example.com"
    assert "nginx" in sub.technologies


def test_finding_model():
    finding = Finding(
        id=1,
        subdomain_id=1,
        name="SQL Injection",
        severity="high",
        url="https://api.example.com/login",
        evidence="Error: SQL syntax",
        template="sqli-detection",
    )
    assert finding.severity == "high"


def test_run_model():
    run = Run(
        id=1,
        target_id=1,
        stage="recon",
        started_at=datetime.now(),
        status="running",
    )
    assert run.status == "running"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/storage/__init__.py`:
```python
"""Storage package for database operations."""

from bountyhound.storage.models import Target, Subdomain, Port, Finding, Run

__all__ = ["Target", "Subdomain", "Port", "Finding", "Run"]
```

Create `bountyhound/storage/models.py`:
```python
"""Data models for BountyHound."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Target(BaseModel):
    """A bug bounty target domain."""

    id: int
    domain: str
    added_at: datetime
    last_recon: Optional[datetime] = None
    last_scan: Optional[datetime] = None


class Subdomain(BaseModel):
    """A discovered subdomain."""

    id: int
    target_id: int
    hostname: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    technologies: list[str] = []
    discovered_at: datetime = datetime.now()


class Port(BaseModel):
    """An open port on a subdomain."""

    id: int
    subdomain_id: int
    port: int
    service: Optional[str] = None
    version: Optional[str] = None
    discovered_at: datetime = datetime.now()


class Finding(BaseModel):
    """A vulnerability finding."""

    id: int
    subdomain_id: int
    name: str
    severity: str
    url: Optional[str] = None
    evidence: Optional[str] = None
    template: Optional[str] = None
    found_at: datetime = datetime.now()


class Run(BaseModel):
    """A pipeline run record."""

    id: int
    target_id: int
    stage: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/storage/__init__.py bountyhound/storage/models.py tests/test_models.py
git commit -m "feat: add Pydantic data models for targets, subdomains, findings"
```

---

## Task 4: Database Operations

**Files:**
- Create: `bountyhound/storage/database.py`
- Create: `tests/test_database.py`

**Step 1: Write the failing test**

Create `tests/test_database.py`:
```python
"""Tests for database operations."""

import tempfile
from pathlib import Path

from bountyhound.storage.database import Database


def test_database_creates_tables():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        # Check tables exist
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t[0] for t in tables]

        assert "targets" in table_names
        assert "subdomains" in table_names
        assert "findings" in table_names
        db.close()


def test_add_and_get_target():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        target_id = db.add_target("example.com")
        assert target_id == 1

        target = db.get_target("example.com")
        assert target is not None
        assert target.domain == "example.com"
        db.close()


def test_add_subdomain():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        target_id = db.add_target("example.com")
        sub_id = db.add_subdomain(target_id, "api.example.com", ip_address="1.2.3.4")

        subs = db.get_subdomains(target_id)
        assert len(subs) == 1
        assert subs[0].hostname == "api.example.com"
        db.close()


def test_add_finding():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        target_id = db.add_target("example.com")
        sub_id = db.add_subdomain(target_id, "api.example.com")
        finding_id = db.add_finding(sub_id, "XSS", "medium", url="https://api.example.com")

        findings = db.get_findings(target_id)
        assert len(findings) == 1
        assert findings[0].name == "XSS"
        db.close()


def test_get_all_targets():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        db.add_target("example.com")
        db.add_target("example.org")

        targets = db.get_all_targets()
        assert len(targets) == 2
        db.close()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database.py -v`
Expected: FAIL with "ImportError"

**Step 3: Write the implementation**

Create `bountyhound/storage/database.py`:
```python
"""SQLite database operations for BountyHound."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from bountyhound.storage.models import Target, Subdomain, Port, Finding, Run


class Database:
    """SQLite database wrapper for BountyHound data."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".bountyhound" / "bountyhound.db"
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        return self.conn

    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a query and return cursor."""
        return self.connect().execute(query, params)

    def initialize(self) -> None:
        """Create database tables if they don't exist."""
        conn = self.connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_recon TIMESTAMP,
                last_scan TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY,
                target_id INTEGER REFERENCES targets(id),
                hostname TEXT NOT NULL,
                ip_address TEXT,
                status_code INTEGER,
                technologies TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(target_id, hostname)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY,
                subdomain_id INTEGER REFERENCES subdomains(id),
                port INTEGER NOT NULL,
                service TEXT,
                version TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(subdomain_id, port)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                subdomain_id INTEGER REFERENCES subdomains(id),
                name TEXT NOT NULL,
                severity TEXT,
                url TEXT,
                evidence TEXT,
                template TEXT,
                found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY,
                target_id INTEGER REFERENCES targets(id),
                stage TEXT,
                started_at TIMESTAMP,
                finished_at TIMESTAMP,
                status TEXT
            );
        """)
        conn.commit()

    def add_target(self, domain: str) -> int:
        """Add a new target domain. Returns target ID."""
        cursor = self.execute(
            "INSERT OR IGNORE INTO targets (domain) VALUES (?)",
            (domain,)
        )
        self.connect().commit()
        if cursor.lastrowid == 0:
            row = self.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            return row["id"]
        return cursor.lastrowid

    def get_target(self, domain: str) -> Optional[Target]:
        """Get a target by domain name."""
        row = self.execute("SELECT * FROM targets WHERE domain = ?", (domain,)).fetchone()
        if row is None:
            return None
        return Target(
            id=row["id"],
            domain=row["domain"],
            added_at=datetime.fromisoformat(row["added_at"]) if row["added_at"] else datetime.now(),
            last_recon=datetime.fromisoformat(row["last_recon"]) if row["last_recon"] else None,
            last_scan=datetime.fromisoformat(row["last_scan"]) if row["last_scan"] else None,
        )

    def get_all_targets(self) -> list[Target]:
        """Get all targets."""
        rows = self.execute("SELECT * FROM targets ORDER BY added_at DESC").fetchall()
        return [
            Target(
                id=row["id"],
                domain=row["domain"],
                added_at=datetime.fromisoformat(row["added_at"]) if row["added_at"] else datetime.now(),
                last_recon=datetime.fromisoformat(row["last_recon"]) if row["last_recon"] else None,
                last_scan=datetime.fromisoformat(row["last_scan"]) if row["last_scan"] else None,
            )
            for row in rows
        ]

    def add_subdomain(
        self,
        target_id: int,
        hostname: str,
        ip_address: str | None = None,
        status_code: int | None = None,
        technologies: list[str] | None = None,
    ) -> int:
        """Add a subdomain. Returns subdomain ID."""
        tech_json = json.dumps(technologies) if technologies else None
        cursor = self.execute(
            """INSERT OR REPLACE INTO subdomains
               (target_id, hostname, ip_address, status_code, technologies)
               VALUES (?, ?, ?, ?, ?)""",
            (target_id, hostname, ip_address, status_code, tech_json)
        )
        self.connect().commit()
        return cursor.lastrowid

    def get_subdomains(self, target_id: int) -> list[Subdomain]:
        """Get all subdomains for a target."""
        rows = self.execute(
            "SELECT * FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchall()
        return [
            Subdomain(
                id=row["id"],
                target_id=row["target_id"],
                hostname=row["hostname"],
                ip_address=row["ip_address"],
                status_code=row["status_code"],
                technologies=json.loads(row["technologies"]) if row["technologies"] else [],
                discovered_at=datetime.fromisoformat(row["discovered_at"]) if row["discovered_at"] else datetime.now(),
            )
            for row in rows
        ]

    def add_finding(
        self,
        subdomain_id: int,
        name: str,
        severity: str,
        url: str | None = None,
        evidence: str | None = None,
        template: str | None = None,
    ) -> int:
        """Add a vulnerability finding. Returns finding ID."""
        cursor = self.execute(
            """INSERT INTO findings (subdomain_id, name, severity, url, evidence, template)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (subdomain_id, name, severity, url, evidence, template)
        )
        self.connect().commit()
        return cursor.lastrowid

    def get_findings(self, target_id: int) -> list[Finding]:
        """Get all findings for a target."""
        rows = self.execute(
            """SELECT f.* FROM findings f
               JOIN subdomains s ON f.subdomain_id = s.id
               WHERE s.target_id = ?""",
            (target_id,)
        ).fetchall()
        return [
            Finding(
                id=row["id"],
                subdomain_id=row["subdomain_id"],
                name=row["name"],
                severity=row["severity"],
                url=row["url"],
                evidence=row["evidence"],
                template=row["template"],
                found_at=datetime.fromisoformat(row["found_at"]) if row["found_at"] else datetime.now(),
            )
            for row in rows
        ]

    def update_target_recon_time(self, target_id: int) -> None:
        """Update the last_recon timestamp for a target."""
        self.execute(
            "UPDATE targets SET last_recon = ? WHERE id = ?",
            (datetime.now().isoformat(), target_id)
        )
        self.connect().commit()

    def update_target_scan_time(self, target_id: int) -> None:
        """Update the last_scan timestamp for a target."""
        self.execute(
            "UPDATE targets SET last_scan = ? WHERE id = ?",
            (datetime.now().isoformat(), target_id)
        )
        self.connect().commit()

    def get_subdomain_count(self, target_id: int) -> int:
        """Get count of subdomains for a target."""
        row = self.execute(
            "SELECT COUNT(*) as count FROM subdomains WHERE target_id = ?",
            (target_id,)
        ).fetchone()
        return row["count"]

    def get_finding_count(self, target_id: int) -> dict[str, int]:
        """Get count of findings by severity for a target."""
        rows = self.execute(
            """SELECT severity, COUNT(*) as count FROM findings f
               JOIN subdomains s ON f.subdomain_id = s.id
               WHERE s.target_id = ?
               GROUP BY severity""",
            (target_id,)
        ).fetchall()
        return {row["severity"]: row["count"] for row in rows}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database.py -v`
Expected: All 5 tests PASS

**Step 5: Update storage __init__.py**

Update `bountyhound/storage/__init__.py`:
```python
"""Storage package for database operations."""

from bountyhound.storage.database import Database
from bountyhound.storage.models import Target, Subdomain, Port, Finding, Run

__all__ = ["Database", "Target", "Subdomain", "Port", "Finding", "Run"]
```

**Step 6: Commit**

```bash
git add bountyhound/storage/database.py bountyhound/storage/__init__.py tests/test_database.py
git commit -m "feat: add SQLite database operations for targets and findings"
```

---

## Task 5: Utility Functions - Tool Detection

**Files:**
- Create: `bountyhound/utils.py`
- Create: `tests/test_utils.py`

**Step 1: Write the failing test**

Create `tests/test_utils.py`:
```python
"""Tests for utility functions."""

import subprocess
from unittest.mock import patch, MagicMock

from bountyhound.utils import find_tool, run_tool, ToolNotFoundError


def test_find_tool_returns_path_when_found():
    # Test with a tool that should exist on any system
    with patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/python"
        path = find_tool("python")
        assert path == "/usr/bin/python"


def test_find_tool_returns_none_when_not_found():
    with patch("shutil.which") as mock_which:
        mock_which.return_value = None
        path = find_tool("nonexistent_tool_xyz")
        assert path is None


def test_run_tool_returns_output():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="output line 1\noutput line 2",
            stderr="",
            returncode=0
        )
        result = run_tool("echo", ["hello"])
        assert result.returncode == 0
        assert "output" in result.stdout


def test_run_tool_raises_on_missing_tool():
    with patch("bountyhound.utils.find_tool") as mock_find:
        mock_find.return_value = None
        try:
            run_tool("nonexistent_tool", [])
            assert False, "Should have raised ToolNotFoundError"
        except ToolNotFoundError as e:
            assert "nonexistent_tool" in str(e)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_utils.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/utils.py`:
```python
"""Utility functions for BountyHound."""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not found."""

    pass


@dataclass
class ToolResult:
    """Result from running an external tool."""

    stdout: str
    stderr: str
    returncode: int


def find_tool(name: str, config_path: str | None = None) -> Optional[str]:
    """Find an external tool by name.

    Args:
        name: Tool name (e.g., 'subfinder', 'nuclei')
        config_path: Optional explicit path from config

    Returns:
        Path to tool if found, None otherwise
    """
    if config_path:
        return config_path if shutil.which(config_path) else None
    return shutil.which(name)


def run_tool(
    name: str,
    args: list[str],
    config_path: str | None = None,
    timeout: int | None = None,
    input_data: str | None = None,
) -> ToolResult:
    """Run an external tool and capture output.

    Args:
        name: Tool name
        args: Command line arguments
        config_path: Optional explicit path from config
        timeout: Timeout in seconds
        input_data: Data to pass to stdin

    Returns:
        ToolResult with stdout, stderr, returncode

    Raises:
        ToolNotFoundError: If tool is not installed
    """
    tool_path = find_tool(name, config_path)
    if tool_path is None:
        raise ToolNotFoundError(
            f"Tool '{name}' not found. Install it or configure the path in ~/.bountyhound/config.yaml"
        )

    try:
        result = subprocess.run(
            [tool_path] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        return ToolResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(stdout="", stderr="Tool execution timed out", returncode=-1)


def parse_json_lines(output: str) -> list[dict]:
    """Parse newline-delimited JSON output (common format for security tools)."""
    import json

    results = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_utils.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/utils.py tests/test_utils.py
git commit -m "feat: add utility functions for tool detection and execution"
```

---

## Task 6: CLI Skeleton with Click

**Files:**
- Create: `bountyhound/cli.py`
- Create: `tests/test_cli.py`

**Step 1: Write the failing test**

Create `tests/test_cli.py`:
```python
"""Tests for CLI commands."""

from click.testing import CliRunner

from bountyhound.cli import main, doctor, target, status


def test_main_shows_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Bug bounty automation CLI" in result.output


def test_doctor_command_runs():
    runner = CliRunner()
    result = runner.invoke(doctor)
    assert result.exit_code == 0
    # Should show tool check results
    assert "subfinder" in result.output.lower() or "checking" in result.output.lower()


def test_target_add_command():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(target, ["add", "example.com"])
        assert result.exit_code == 0
        assert "example.com" in result.output


def test_status_command_runs():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(status)
        assert result.exit_code == 0
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with "ImportError"

**Step 3: Write the implementation**

Create `bountyhound/cli.py`:
```python
"""BountyHound CLI - Bug bounty automation tool."""

import click
from rich.console import Console
from rich.table import Table

from bountyhound import __version__
from bountyhound.config import load_config
from bountyhound.storage import Database
from bountyhound.utils import find_tool

console = Console()

REQUIRED_TOOLS = ["subfinder", "httpx", "nmap", "nuclei"]
OPTIONAL_TOOLS = ["ffuf"]


@click.group()
@click.version_option(version=__version__)
def main():
    """Bug bounty automation CLI.

    BountyHound orchestrates recon and vulnerability scanning tools
    into an automated pipeline for bug bounty hunting.
    """
    pass


@main.command()
def doctor():
    """Check external tool dependencies."""
    console.print("\n[bold]Checking tool dependencies...[/bold]\n")

    config = load_config()
    tool_paths = config.get("tools", {})

    all_found = True
    for tool in REQUIRED_TOOLS:
        config_path = tool_paths.get(tool)
        path = find_tool(tool, config_path)
        if path:
            console.print(f"  [green]✓[/green] {tool} found at {path}")
        else:
            console.print(f"  [red]✗[/red] {tool} not found")
            all_found = False

    console.print()
    for tool in OPTIONAL_TOOLS:
        config_path = tool_paths.get(tool)
        path = find_tool(tool, config_path)
        if path:
            console.print(f"  [green]✓[/green] {tool} found at {path} (optional)")
        else:
            console.print(f"  [yellow]○[/yellow] {tool} not found (optional)")

    console.print()
    if all_found:
        console.print("[green]All required tools are installed![/green]")
    else:
        console.print("[yellow]Some required tools are missing. Install them to use full functionality.[/yellow]")
        console.print("\nInstall with Go:")
        console.print("  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        console.print("  go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        console.print("  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")


@main.group()
def target():
    """Manage bug bounty targets."""
    pass


@target.command("add")
@click.argument("domain")
def target_add(domain: str):
    """Add a new target domain."""
    db = Database()
    db.initialize()
    target_id = db.add_target(domain)
    db.close()
    console.print(f"[green][+][/green] Added target: {domain} (id: {target_id})")


@target.command("list")
def target_list():
    """List all targets."""
    db = Database()
    db.initialize()
    targets = db.get_all_targets()
    db.close()

    if not targets:
        console.print("[yellow]No targets added yet. Use 'bountyhound target add <domain>'[/yellow]")
        return

    table = Table(title="Targets")
    table.add_column("ID", style="cyan")
    table.add_column("Domain", style="green")
    table.add_column("Added", style="dim")

    for t in targets:
        table.add_row(str(t.id), t.domain, t.added_at.strftime("%Y-%m-%d %H:%M"))

    console.print(table)


@target.command("remove")
@click.argument("domain")
def target_remove(domain: str):
    """Remove a target domain."""
    db = Database()
    db.initialize()
    db.execute("DELETE FROM targets WHERE domain = ?", (domain,))
    db.connect().commit()
    db.close()
    console.print(f"[yellow][-][/yellow] Removed target: {domain}")


@main.command()
def status():
    """Show status of all targets."""
    db = Database()
    db.initialize()
    targets = db.get_all_targets()

    if not targets:
        console.print("[yellow]No targets. Use 'bountyhound target add <domain>' to add one.[/yellow]")
        db.close()
        return

    table = Table(title="Target Status")
    table.add_column("Target", style="cyan")
    table.add_column("Subdomains", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Last Recon", style="dim")
    table.add_column("Last Scan", style="dim")

    for t in targets:
        sub_count = db.get_subdomain_count(t.id)
        finding_counts = db.get_finding_count(t.id)
        total_findings = sum(finding_counts.values())

        findings_str = str(total_findings)
        if finding_counts.get("high", 0) > 0 or finding_counts.get("critical", 0) > 0:
            high = finding_counts.get("high", 0) + finding_counts.get("critical", 0)
            findings_str = f"[red]{total_findings} ({high} high)[/red]"
        elif finding_counts.get("medium", 0) > 0:
            findings_str = f"[yellow]{total_findings} ({finding_counts['medium']} med)[/yellow]"

        last_recon = t.last_recon.strftime("%Y-%m-%d %H:%M") if t.last_recon else "-"
        last_scan = t.last_scan.strftime("%Y-%m-%d %H:%M") if t.last_scan else "-"

        table.add_row(t.domain, str(sub_count), findings_str, last_recon, last_scan)

    console.print(table)
    db.close()


if __name__ == "__main__":
    main()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: All 4 tests PASS

**Step 5: Verify CLI works directly**

Run: `python -m bountyhound.cli --help`
Expected: Shows help output

**Step 6: Commit**

```bash
git add bountyhound/cli.py tests/test_cli.py
git commit -m "feat: add CLI skeleton with doctor, target, and status commands"
```

---

## Task 7: Recon Module - Subfinder Wrapper

**Files:**
- Create: `bountyhound/recon/__init__.py`
- Create: `bountyhound/recon/subdomains.py`
- Create: `tests/test_recon_subdomains.py`

**Step 1: Write the failing test**

Create `tests/test_recon_subdomains.py`:
```python
"""Tests for subdomain enumeration."""

from unittest.mock import patch, MagicMock

from bountyhound.recon.subdomains import SubdomainScanner
from bountyhound.utils import ToolResult


def test_parse_subfinder_output():
    scanner = SubdomainScanner()
    output = "api.example.com\nwww.example.com\nmail.example.com\n"
    results = scanner.parse_output(output)
    assert len(results) == 3
    assert "api.example.com" in results


def test_run_returns_subdomains():
    scanner = SubdomainScanner()
    with patch("bountyhound.recon.subdomains.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout="api.example.com\nwww.example.com\n",
            stderr="",
            returncode=0
        )
        results = scanner.run("example.com")
        assert len(results) == 2
        assert "api.example.com" in results


def test_run_handles_empty_output():
    scanner = SubdomainScanner()
    with patch("bountyhound.recon.subdomains.run_tool") as mock_run:
        mock_run.return_value = ToolResult(stdout="", stderr="", returncode=0)
        results = scanner.run("example.com")
        assert results == []
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_recon_subdomains.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/recon/__init__.py`:
```python
"""Recon modules for BountyHound."""

from bountyhound.recon.subdomains import SubdomainScanner

__all__ = ["SubdomainScanner"]
```

Create `bountyhound/recon/subdomains.py`:
```python
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
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_recon_subdomains.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/recon/__init__.py bountyhound/recon/subdomains.py tests/test_recon_subdomains.py
git commit -m "feat: add subfinder wrapper for subdomain enumeration"
```

---

## Task 8: Recon Module - HTTPX Wrapper

**Files:**
- Create: `bountyhound/recon/httpx.py`
- Create: `tests/test_recon_httpx.py`

**Step 1: Write the failing test**

Create `tests/test_recon_httpx.py`:
```python
"""Tests for HTTP probing."""

from unittest.mock import patch

from bountyhound.recon.httpx import HttpProber
from bountyhound.utils import ToolResult


def test_parse_httpx_json_output():
    prober = HttpProber()
    output = '''{"url":"https://api.example.com","status_code":200,"tech":["nginx"]}
{"url":"https://www.example.com","status_code":301,"tech":["cloudflare"]}'''
    results = prober.parse_output(output)
    assert len(results) == 2
    assert results[0]["url"] == "https://api.example.com"
    assert results[0]["status_code"] == 200


def test_run_returns_live_hosts():
    prober = HttpProber()
    with patch("bountyhound.recon.httpx.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout='{"url":"https://api.example.com","status_code":200,"tech":["nginx"]}\n',
            stderr="",
            returncode=0
        )
        results = prober.run(["api.example.com", "www.example.com"])
        assert len(results) == 1
        assert results[0]["url"] == "https://api.example.com"


def test_run_handles_empty_output():
    prober = HttpProber()
    with patch("bountyhound.recon.httpx.run_tool") as mock_run:
        mock_run.return_value = ToolResult(stdout="", stderr="", returncode=0)
        results = prober.run(["example.com"])
        assert results == []
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_recon_httpx.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/recon/httpx.py`:
```python
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
```

**Step 4: Update recon __init__.py**

Update `bountyhound/recon/__init__.py`:
```python
"""Recon modules for BountyHound."""

from bountyhound.recon.subdomains import SubdomainScanner
from bountyhound.recon.httpx import HttpProber

__all__ = ["SubdomainScanner", "HttpProber"]
```

**Step 5: Run test to verify it passes**

Run: `pytest tests/test_recon_httpx.py -v`
Expected: All 3 tests PASS

**Step 6: Commit**

```bash
git add bountyhound/recon/httpx.py bountyhound/recon/__init__.py tests/test_recon_httpx.py
git commit -m "feat: add httpx wrapper for HTTP probing and tech detection"
```

---

## Task 9: Recon Module - Nmap Wrapper

**Files:**
- Create: `bountyhound/recon/ports.py`
- Create: `tests/test_recon_ports.py`

**Step 1: Write the failing test**

Create `tests/test_recon_ports.py`:
```python
"""Tests for port scanning."""

from unittest.mock import patch

from bountyhound.recon.ports import PortScanner
from bountyhound.utils import ToolResult


def test_parse_nmap_output():
    scanner = PortScanner()
    # Simplified nmap greppable output format
    output = """Host: 1.2.3.4 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.0/, 80/open/tcp//http//nginx/, 443/open/tcp//https//"""
    results = scanner.parse_output(output)
    assert len(results) == 1
    assert results["1.2.3.4"][0]["port"] == 22
    assert results["1.2.3.4"][0]["service"] == "ssh"


def test_run_returns_open_ports():
    scanner = PortScanner()
    with patch("bountyhound.recon.ports.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout="Host: 1.2.3.4 ()	Ports: 80/open/tcp//http//nginx/\n",
            stderr="",
            returncode=0
        )
        results = scanner.run(["1.2.3.4"])
        assert "1.2.3.4" in results
        assert results["1.2.3.4"][0]["port"] == 80
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_recon_ports.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/recon/ports.py`:
```python
"""Port scanning using nmap."""

import re

from bountyhound.utils import run_tool, ToolNotFoundError


class PortScanner:
    """Wrapper for nmap port scanning."""

    def __init__(self, config_path: str | None = None):
        self.tool_name = "nmap"
        self.config_path = config_path

    def run(
        self,
        hosts: list[str],
        ports: str = "--top-ports 1000",
        timeout: int = 600,
    ) -> dict[str, list[dict]]:
        """Run nmap against a list of hosts.

        Args:
            hosts: List of IPs or hostnames to scan
            ports: Port specification (default: top 1000)
            timeout: Timeout in seconds

        Returns:
            Dict mapping host to list of port info dicts

        Raises:
            ToolNotFoundError: If nmap is not installed
        """
        if not hosts:
            return {}

        # Build args - use greppable output for easy parsing
        args = ["-oG", "-", "-T4"]
        if ports.startswith("--"):
            args.append(ports)
        else:
            args.extend(["-p", ports])
        args.extend(hosts)

        result = run_tool(
            self.tool_name,
            args,
            config_path=self.config_path,
            timeout=timeout,
        )

        if result.returncode != 0:
            return {}

        return self.parse_output(result.stdout)

    def parse_output(self, output: str) -> dict[str, list[dict]]:
        """Parse nmap greppable output."""
        results = {}

        for line in output.split("\n"):
            if not line.startswith("Host:"):
                continue

            # Extract host IP
            host_match = re.match(r"Host:\s+(\S+)", line)
            if not host_match:
                continue
            host = host_match.group(1)

            # Extract ports section
            ports_match = re.search(r"Ports:\s+(.+?)(?:\t|$)", line)
            if not ports_match:
                continue

            ports = []
            port_entries = ports_match.group(1).split(", ")
            for entry in port_entries:
                # Format: port/state/protocol//service//version/
                parts = entry.split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    ports.append({
                        "port": int(parts[0]),
                        "protocol": parts[2],
                        "service": parts[4] if parts[4] else None,
                        "version": parts[6] if len(parts) > 6 and parts[6] else None,
                    })

            if ports:
                results[host] = ports

        return results
```

**Step 4: Update recon __init__.py**

Update `bountyhound/recon/__init__.py`:
```python
"""Recon modules for BountyHound."""

from bountyhound.recon.subdomains import SubdomainScanner
from bountyhound.recon.httpx import HttpProber
from bountyhound.recon.ports import PortScanner

__all__ = ["SubdomainScanner", "HttpProber", "PortScanner"]
```

**Step 5: Run test to verify it passes**

Run: `pytest tests/test_recon_ports.py -v`
Expected: All 2 tests PASS

**Step 6: Commit**

```bash
git add bountyhound/recon/ports.py bountyhound/recon/__init__.py tests/test_recon_ports.py
git commit -m "feat: add nmap wrapper for port scanning"
```

---

## Task 10: Scan Module - Nuclei Wrapper

**Files:**
- Create: `bountyhound/scan/__init__.py`
- Create: `bountyhound/scan/nuclei.py`
- Create: `tests/test_scan_nuclei.py`

**Step 1: Write the failing test**

Create `tests/test_scan_nuclei.py`:
```python
"""Tests for vulnerability scanning."""

from unittest.mock import patch

from bountyhound.scan.nuclei import NucleiScanner
from bountyhound.utils import ToolResult


def test_parse_nuclei_json_output():
    scanner = NucleiScanner()
    output = '''{"template-id":"cve-2021-1234","name":"Test Vuln","severity":"high","host":"https://example.com","matched-at":"https://example.com/vuln"}
{"template-id":"xss-detection","name":"XSS","severity":"medium","host":"https://example.com","matched-at":"https://example.com/search"}'''
    results = scanner.parse_output(output)
    assert len(results) == 2
    assert results[0]["severity"] == "high"
    assert results[0]["template"] == "cve-2021-1234"


def test_run_returns_findings():
    scanner = NucleiScanner()
    with patch("bountyhound.scan.nuclei.run_tool") as mock_run:
        mock_run.return_value = ToolResult(
            stdout='{"template-id":"sqli","name":"SQL Injection","severity":"critical","host":"https://example.com","matched-at":"https://example.com/login"}\n',
            stderr="",
            returncode=0
        )
        results = scanner.run(["https://example.com"])
        assert len(results) == 1
        assert results[0]["severity"] == "critical"


def test_run_handles_no_findings():
    scanner = NucleiScanner()
    with patch("bountyhound.scan.nuclei.run_tool") as mock_run:
        mock_run.return_value = ToolResult(stdout="", stderr="", returncode=0)
        results = scanner.run(["https://example.com"])
        assert results == []
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_scan_nuclei.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/scan/__init__.py`:
```python
"""Scan modules for BountyHound."""

from bountyhound.scan.nuclei import NucleiScanner

__all__ = ["NucleiScanner"]
```

Create `bountyhound/scan/nuclei.py`:
```python
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
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_scan_nuclei.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/scan/__init__.py bountyhound/scan/nuclei.py tests/test_scan_nuclei.py
git commit -m "feat: add nuclei wrapper for vulnerability scanning"
```

---

## Task 11: Pipeline Runner

**Files:**
- Create: `bountyhound/pipeline/__init__.py`
- Create: `bountyhound/pipeline/runner.py`
- Create: `tests/test_pipeline.py`

**Step 1: Write the failing test**

Create `tests/test_pipeline.py`:
```python
"""Tests for pipeline runner."""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from bountyhound.pipeline.runner import PipelineRunner
from bountyhound.storage import Database
from bountyhound.utils import ToolResult


def test_pipeline_runner_initializes():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        runner = PipelineRunner(db, batch_mode=True)
        assert runner.batch_mode is True
        db.close()


def test_run_recon_stores_subdomains():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()
        target_id = db.add_target("example.com")

        runner = PipelineRunner(db, batch_mode=True)

        with patch.object(runner.subdomain_scanner, "run") as mock_sub:
            mock_sub.return_value = ["api.example.com", "www.example.com"]
            with patch.object(runner.http_prober, "run") as mock_http:
                mock_http.return_value = [
                    {"url": "https://api.example.com", "status_code": 200, "tech": ["nginx"], "ip": "1.2.3.4", "host": "api.example.com"},
                ]
                with patch.object(runner.port_scanner, "run") as mock_port:
                    mock_port.return_value = {}

                    runner.run_recon("example.com")

        subs = db.get_subdomains(target_id)
        assert len(subs) >= 1
        db.close()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/pipeline/__init__.py`:
```python
"""Pipeline orchestration for BountyHound."""

from bountyhound.pipeline.runner import PipelineRunner

__all__ = ["PipelineRunner"]
```

Create `bountyhound/pipeline/runner.py`:
```python
"""Pipeline runner for orchestrating recon and scanning."""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from bountyhound.config import load_config
from bountyhound.recon import SubdomainScanner, HttpProber, PortScanner
from bountyhound.scan import NucleiScanner
from bountyhound.storage import Database
from bountyhound.utils import ToolNotFoundError

console = Console()


class PipelineRunner:
    """Orchestrates the full bug bounty pipeline."""

    def __init__(self, db: Database, batch_mode: bool = False):
        self.db = db
        self.batch_mode = batch_mode
        self.config = load_config()

        tool_paths = self.config.get("tools", {})
        self.subdomain_scanner = SubdomainScanner(tool_paths.get("subfinder"))
        self.http_prober = HttpProber(tool_paths.get("httpx"))
        self.port_scanner = PortScanner(tool_paths.get("nmap"))
        self.nuclei_scanner = NucleiScanner(tool_paths.get("nuclei"))

    def log(self, message: str, style: str = "") -> None:
        """Log a message unless in batch mode."""
        if not self.batch_mode:
            console.print(message, style=style)

    def run_recon(self, domain: str) -> dict:
        """Run reconnaissance stage.

        Returns dict with subdomains, live_hosts, ports counts.
        """
        target = self.db.get_target(domain)
        if not target:
            self.db.add_target(domain)
            target = self.db.get_target(domain)

        results = {"subdomains": 0, "live_hosts": 0, "ports": 0}

        # Stage 1: Subdomain enumeration
        self.log("[*] Running subfinder for subdomain enumeration...")
        try:
            subdomains = self.subdomain_scanner.run(domain)
            results["subdomains"] = len(subdomains)
            self.log(f"    Found {len(subdomains)} subdomains")
        except ToolNotFoundError:
            self.log("[yellow]    subfinder not found, skipping[/yellow]")
            subdomains = [domain]  # Fall back to just the main domain

        # Stage 2: HTTP probing
        self.log("[*] Running httpx for HTTP probing...")
        try:
            live_hosts = self.http_prober.run(subdomains)
            results["live_hosts"] = len(live_hosts)
            self.log(f"    Found {len(live_hosts)} live hosts")

            # Store subdomains with HTTP info
            for host in live_hosts:
                hostname = host.get("host") or host.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
                self.db.add_subdomain(
                    target.id,
                    hostname,
                    ip_address=host.get("ip"),
                    status_code=host.get("status_code"),
                    technologies=host.get("tech", []),
                )
        except ToolNotFoundError:
            self.log("[yellow]    httpx not found, skipping[/yellow]")
            live_hosts = []

        # Stage 3: Port scanning
        self.log("[*] Running nmap for port scanning...")
        try:
            # Get IPs from live hosts
            ips = [h.get("ip") for h in live_hosts if h.get("ip")]
            if ips:
                port_results = self.port_scanner.run(ips)
                total_ports = sum(len(ports) for ports in port_results.values())
                results["ports"] = total_ports
                self.log(f"    Found {total_ports} open ports")
            else:
                self.log("    No IPs to scan")
        except ToolNotFoundError:
            self.log("[yellow]    nmap not found, skipping[/yellow]")

        self.db.update_target_recon_time(target.id)
        return results

    def run_scan(self, domain: str) -> dict:
        """Run vulnerability scanning stage.

        Returns dict with findings count by severity.
        """
        target = self.db.get_target(domain)
        if not target:
            self.log(f"[red]Target {domain} not found. Run recon first.[/red]")
            return {}

        results = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # Get URLs to scan
        subdomains = self.db.get_subdomains(target.id)
        urls = [f"https://{s.hostname}" for s in subdomains if s.status_code]

        if not urls:
            self.log("[yellow]No live hosts to scan. Run recon first.[/yellow]")
            return results

        self.log(f"[*] Running nuclei against {len(urls)} URLs...")
        try:
            scan_config = self.config.get("scan", {})
            findings = self.nuclei_scanner.run(
                urls,
                templates=scan_config.get("nuclei_templates"),
                severity=scan_config.get("nuclei_severity", "low,medium,high,critical"),
            )

            self.log(f"    Found {len(findings)} potential vulnerabilities")

            # Store findings
            for finding in findings:
                # Find matching subdomain
                url = finding.get("url", "")
                hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

                for sub in subdomains:
                    if sub.hostname == hostname:
                        self.db.add_finding(
                            sub.id,
                            finding["name"],
                            finding["severity"],
                            url=finding.get("url"),
                            evidence=str(finding.get("evidence", "")),
                            template=finding.get("template"),
                        )
                        severity = finding["severity"].lower()
                        if severity in results:
                            results[severity] += 1
                        break

        except ToolNotFoundError:
            self.log("[red]    nuclei not found, cannot scan[/red]")

        self.db.update_target_scan_time(target.id)
        return results

    def run_pipeline(self, domain: str) -> dict:
        """Run full pipeline: recon -> scan.

        Returns combined results dict.
        """
        self.log(f"\n[bold][*] Starting pipeline for {domain}[/bold]\n")

        self.log("[bold]Stage 1/2: Reconnaissance[/bold]")
        recon_results = self.run_recon(domain)

        self.log("\n[bold]Stage 2/2: Vulnerability Scanning[/bold]")
        scan_results = self.run_scan(domain)

        self.log("\n[green][+] Pipeline complete![/green]")

        return {**recon_results, **scan_results}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline.py -v`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/pipeline/__init__.py bountyhound/pipeline/runner.py tests/test_pipeline.py
git commit -m "feat: add pipeline runner for orchestrating recon and scanning"
```

---

## Task 12: Add Pipeline CLI Commands

**Files:**
- Modify: `bountyhound/cli.py`
- Modify: `tests/test_cli.py`

**Step 1: Add test for recon command**

Add to `tests/test_cli.py`:
```python
def test_recon_command_requires_target():
    runner = CliRunner()
    result = runner.invoke(main, ["recon"])
    # Should error without domain argument
    assert result.exit_code != 0


def test_pipeline_command_requires_target():
    runner = CliRunner()
    result = runner.invoke(main, ["pipeline"])
    assert result.exit_code != 0
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_recon_command_requires_target -v`
Expected: FAIL (command doesn't exist yet)

**Step 3: Add commands to cli.py**

Add these commands to `bountyhound/cli.py` after the `status` command:

```python
@main.command()
@click.argument("domain")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def recon(domain: str, batch: bool):
    """Run reconnaissance on a target domain."""
    db = Database()
    db.initialize()

    # Ensure target exists
    if not db.get_target(domain):
        db.add_target(domain)
        if not batch:
            console.print(f"[green][+][/green] Added new target: {domain}")

    from bountyhound.pipeline import PipelineRunner

    runner = PipelineRunner(db, batch_mode=batch)
    results = runner.run_recon(domain)
    db.close()

    if not batch:
        console.print(f"\n[bold]Recon Summary:[/bold]")
        console.print(f"  Subdomains: {results['subdomains']}")
        console.print(f"  Live hosts: {results['live_hosts']}")
        console.print(f"  Open ports: {results['ports']}")


@main.command()
@click.argument("domain")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def scan(domain: str, batch: bool):
    """Run vulnerability scan on a target domain."""
    db = Database()
    db.initialize()

    target = db.get_target(domain)
    if not target:
        console.print(f"[red]Target {domain} not found. Add it first with 'target add'.[/red]")
        db.close()
        return

    from bountyhound.pipeline import PipelineRunner

    runner = PipelineRunner(db, batch_mode=batch)
    results = runner.run_scan(domain)
    db.close()

    if not batch:
        console.print(f"\n[bold]Scan Summary:[/bold]")
        console.print(f"  Critical: {results.get('critical', 0)}")
        console.print(f"  High: {results.get('high', 0)}")
        console.print(f"  Medium: {results.get('medium', 0)}")
        console.print(f"  Low: {results.get('low', 0)}")


@main.command()
@click.argument("domain")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def pipeline(domain: str, batch: bool):
    """Run full pipeline (recon + scan) on a target domain."""
    db = Database()
    db.initialize()

    # Ensure target exists
    if not db.get_target(domain):
        db.add_target(domain)
        if not batch:
            console.print(f"[green][+][/green] Added new target: {domain}")

    from bountyhound.pipeline import PipelineRunner

    runner = PipelineRunner(db, batch_mode=batch)
    results = runner.run_pipeline(domain)
    db.close()

    if not batch:
        console.print(f"\n[bold]Pipeline Summary for {domain}:[/bold]")
        console.print(f"  Subdomains: {results.get('subdomains', 0)}")
        console.print(f"  Live hosts: {results.get('live_hosts', 0)}")
        console.print(f"  Findings: critical={results.get('critical', 0)}, high={results.get('high', 0)}, medium={results.get('medium', 0)}")
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add bountyhound/cli.py tests/test_cli.py
git commit -m "feat: add recon, scan, and pipeline CLI commands"
```

---

## Task 13: Report Generator

**Files:**
- Create: `bountyhound/report/__init__.py`
- Create: `bountyhound/report/generators.py`
- Create: `tests/test_report.py`

**Step 1: Write the failing test**

Create `tests/test_report.py`:
```python
"""Tests for report generation."""

import tempfile
from pathlib import Path
from datetime import datetime

from bountyhound.report.generators import ReportGenerator
from bountyhound.storage import Database


def test_generate_markdown_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        target_id = db.add_target("example.com")
        sub_id = db.add_subdomain(target_id, "api.example.com", status_code=200)
        db.add_finding(sub_id, "SQL Injection", "high", url="https://api.example.com/login")

        generator = ReportGenerator(db)
        report = generator.generate_markdown("example.com")

        assert "example.com" in report
        assert "SQL Injection" in report
        assert "high" in report.lower()
        db.close()


def test_generate_json_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        target_id = db.add_target("example.com")
        sub_id = db.add_subdomain(target_id, "api.example.com")
        db.add_finding(sub_id, "XSS", "medium")

        generator = ReportGenerator(db)
        report = generator.generate_json("example.com")

        import json
        data = json.loads(report)
        assert data["target"] == "example.com"
        assert len(data["findings"]) == 1
        db.close()


def test_save_report_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.initialize()

        db.add_target("example.com")

        generator = ReportGenerator(db)
        output_path = Path(tmpdir) / "reports"
        filepath = generator.save_report("example.com", output_dir=output_path, format="markdown")

        assert filepath.exists()
        assert "example.com" in filepath.name
        db.close()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_report.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `bountyhound/report/__init__.py`:
```python
"""Report generation for BountyHound."""

from bountyhound.report.generators import ReportGenerator

__all__ = ["ReportGenerator"]
```

Create `bountyhound/report/generators.py`:
```python
"""Report generators for BountyHound."""

import json
from datetime import datetime
from pathlib import Path

from bountyhound.storage import Database


class ReportGenerator:
    """Generate reports from scan results."""

    def __init__(self, db: Database):
        self.db = db

    def generate_markdown(self, domain: str) -> str:
        """Generate a markdown report for a target."""
        target = self.db.get_target(domain)
        if not target:
            return f"# Report: {domain}\n\nTarget not found."

        subdomains = self.db.get_subdomains(target.id)
        findings = self.db.get_findings(target.id)
        finding_counts = self.db.get_finding_count(target.id)

        lines = [
            f"# Bug Bounty Report: {domain}",
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            "",
            f"- **Subdomains discovered:** {len(subdomains)}",
            f"- **Total findings:** {len(findings)}",
        ]

        if finding_counts:
            lines.append("- **By severity:**")
            for severity in ["critical", "high", "medium", "low", "info"]:
                count = finding_counts.get(severity, 0)
                if count > 0:
                    lines.append(f"  - {severity.capitalize()}: {count}")

        # Findings section
        lines.extend(["", "## Findings", ""])

        if not findings:
            lines.append("No vulnerabilities found.")
        else:
            # Group by severity
            for severity in ["critical", "high", "medium", "low", "info"]:
                severity_findings = [f for f in findings if f.severity == severity]
                if severity_findings:
                    lines.append(f"### {severity.capitalize()} Severity")
                    lines.append("")
                    for f in severity_findings:
                        lines.append(f"#### {f.name}")
                        lines.append("")
                        if f.url:
                            lines.append(f"- **URL:** {f.url}")
                        if f.template:
                            lines.append(f"- **Template:** {f.template}")
                        if f.evidence:
                            lines.append(f"- **Evidence:** {f.evidence}")
                        lines.append("")

        # Subdomains section
        lines.extend(["## Discovered Subdomains", ""])

        if subdomains:
            lines.append("| Hostname | IP | Status | Technologies |")
            lines.append("|----------|-------|--------|--------------|")
            for sub in subdomains:
                tech = ", ".join(sub.technologies[:3]) if sub.technologies else "-"
                lines.append(f"| {sub.hostname} | {sub.ip_address or '-'} | {sub.status_code or '-'} | {tech} |")
        else:
            lines.append("No subdomains discovered.")

        return "\n".join(lines)

    def generate_json(self, domain: str) -> str:
        """Generate a JSON report for a target."""
        target = self.db.get_target(domain)
        if not target:
            return json.dumps({"error": "Target not found", "target": domain})

        subdomains = self.db.get_subdomains(target.id)
        findings = self.db.get_findings(target.id)

        data = {
            "target": domain,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "subdomains": len(subdomains),
                "findings": len(findings),
                "by_severity": self.db.get_finding_count(target.id),
            },
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "url": f.url,
                    "template": f.template,
                    "evidence": f.evidence,
                    "found_at": f.found_at.isoformat(),
                }
                for f in findings
            ],
            "subdomains": [
                {
                    "hostname": s.hostname,
                    "ip": s.ip_address,
                    "status_code": s.status_code,
                    "technologies": s.technologies,
                }
                for s in subdomains
            ],
        }

        return json.dumps(data, indent=2)

    def save_report(
        self,
        domain: str,
        output_dir: Path | None = None,
        format: str = "markdown",
    ) -> Path:
        """Save a report to file.

        Args:
            domain: Target domain
            output_dir: Directory to save to (default: ~/.bountyhound/results)
            format: Report format ('markdown' or 'json')

        Returns:
            Path to saved report file
        """
        if output_dir is None:
            output_dir = Path.home() / ".bountyhound" / "results" / domain

        output_dir.mkdir(parents=True, exist_ok=True)

        date_str = datetime.now().strftime("%Y-%m-%d")

        if format == "json":
            content = self.generate_json(domain)
            filepath = output_dir / f"{date_str}-{domain}-report.json"
        else:
            content = self.generate_markdown(domain)
            filepath = output_dir / f"{date_str}-{domain}-report.md"

        filepath.write_text(content)
        return filepath
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_report.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add bountyhound/report/__init__.py bountyhound/report/generators.py tests/test_report.py
git commit -m "feat: add report generators for markdown and JSON output"
```

---

## Task 14: Add Report CLI Command

**Files:**
- Modify: `bountyhound/cli.py`

**Step 1: Add report command to cli.py**

Add this command after the `pipeline` command:

```python
@main.command()
@click.argument("domain")
@click.option("--format", "-f", type=click.Choice(["markdown", "json"]), default="markdown", help="Report format")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
def report(domain: str, format: str, output: str | None):
    """Generate a report for a target domain."""
    db = Database()
    db.initialize()

    target = db.get_target(domain)
    if not target:
        console.print(f"[red]Target {domain} not found.[/red]")
        db.close()
        return

    from bountyhound.report import ReportGenerator
    from pathlib import Path

    generator = ReportGenerator(db)
    output_dir = Path(output) if output else None
    filepath = generator.save_report(domain, output_dir=output_dir, format=format)
    db.close()

    console.print(f"[green][+][/green] Report saved to: {filepath}")
```

**Step 2: Run CLI to verify command works**

Run: `python -m bountyhound.cli report --help`
Expected: Shows help for report command

**Step 3: Commit**

```bash
git add bountyhound/cli.py
git commit -m "feat: add report CLI command for generating findings reports"
```

---

## Task 15: Run All Tests and Final Verification

**Step 1: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS

**Step 2: Run CLI smoke test**

Run: `bountyhound --help`
Expected: Shows all commands

Run: `bountyhound doctor`
Expected: Shows tool status (tools may be missing, that's OK)

**Step 3: Create final commit with any fixes**

If tests fail, fix issues and commit:
```bash
git add -A
git commit -m "fix: address test failures and polish"
```

**Step 4: Tag release**

```bash
git tag -a v0.1.0 -m "Initial release of BountyHound"
```

---

## Summary

This implementation plan creates BountyHound in 15 tasks:

1. **Project setup** - pyproject.toml, package structure
2. **Config module** - YAML config loading/saving
3. **Data models** - Pydantic models for targets, findings
4. **Database** - SQLite operations
5. **Utils** - Tool detection and execution
6. **CLI skeleton** - Click-based CLI with doctor, target, status
7. **Subfinder wrapper** - Subdomain enumeration
8. **HTTPX wrapper** - HTTP probing
9. **Nmap wrapper** - Port scanning
10. **Nuclei wrapper** - Vulnerability scanning
11. **Pipeline runner** - Orchestration logic
12. **Pipeline CLI** - recon, scan, pipeline commands
13. **Report generator** - Markdown/JSON reports
14. **Report CLI** - report command
15. **Final verification** - Tests and polish

Each task follows TDD: write failing test, implement, verify pass, commit.
