"""
BountyHound Centralized Configuration

Single source of truth for all paths, directories, and constants.
"""

import os
from pathlib import Path


class BountyHoundConfig:
    """Centralized configuration for all BountyHound paths and settings."""

    # Base directories
    BASE_DIR = Path("C:/Users/vaugh/BountyHound")
    AGENT_DIR = BASE_DIR / "bountyhound-agent"
    DB_PATH = str(BASE_DIR / "database" / "bountyhound.db")
    FINDINGS_DIR = BASE_DIR / "findings"
    TOOLS_DIR = BASE_DIR / "tools"
    ARCHIVES_DIR = BASE_DIR / "archives"
    DOCS_DIR = BASE_DIR / "docs"

    # Credential cache
    CRED_CACHE_DIR = BASE_DIR / "database" / "cred-cache"

    # Pattern sync
    PATTERN_SYNC_DIR = BASE_DIR / "database" / "pattern-sync"

    # Monitor
    MONITOR_DIR = BASE_DIR / "database" / "monitor"

    # Notifications
    NOTIFICATIONS_CONFIG = BASE_DIR / "database" / "notifications.json"

    # HackerOne submitter
    H1_CONFIG_DIR = BASE_DIR / "database" / "h1-config"

    # Request log directory
    REQUEST_LOG_DIR = BASE_DIR / "database" / "request-log"

    # Evidence vault
    EVIDENCE_VAULT_DIR = BASE_DIR / "database" / "evidence-vault"

    # Hunt state snapshots
    HUNT_STATE_DIR = BASE_DIR / "database" / "hunt-state"

    # False positive patterns
    FP_PATTERNS_DIR = BASE_DIR / "database" / "fp-patterns"

    # Recon cache
    RECON_CACHE_DIR = BASE_DIR / "database" / "recon-cache"

    @classmethod
    def findings_dir(cls, target: str) -> Path:
        """Get findings directory for a specific target."""
        return cls.FINDINGS_DIR / target

    @classmethod
    def creds_dir(cls, target: str) -> Path:
        """Get credentials directory for a target."""
        return cls.FINDINGS_DIR / target / "credentials"

    @classmethod
    def creds_file(cls, target: str) -> Path:
        """Get the .env credentials file for a target."""
        return cls.creds_dir(target) / f"{target}-creds.env"

    @classmethod
    def tmp_dir(cls, target: str) -> Path:
        """Get temp directory for a target (for verbose output)."""
        return cls.FINDINGS_DIR / target / "tmp"

    @classmethod
    def evidence_dir(cls, target: str) -> Path:
        """Get evidence directory for a target."""
        return cls.FINDINGS_DIR / target / "evidence"

    @classmethod
    def reports_dir(cls, target: str) -> Path:
        """Get reports directory for a target."""
        return cls.FINDINGS_DIR / target / "reports"

    @classmethod
    def screenshots_dir(cls, target: str) -> Path:
        """Get screenshots directory for a target."""
        return cls.FINDINGS_DIR / target / "screenshots"

    @classmethod
    def notebook_file(cls, target: str) -> Path:
        """Get the exploit notebook markdown file for a target."""
        return cls.FINDINGS_DIR / target / "NOTEBOOK.md"

    @classmethod
    def resume_file(cls, target: str) -> Path:
        """Get the session handoff RESUME.md file for a target."""
        return cls.FINDINGS_DIR / target / "RESUME.md"

    @classmethod
    def ensure_target_dirs(cls, target: str) -> None:
        """Create all standard directories for a target."""
        for d in [cls.findings_dir(target), cls.creds_dir(target),
                  cls.tmp_dir(target), cls.evidence_dir(target),
                  cls.reports_dir(target), cls.screenshots_dir(target)]:
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def ensure_system_dirs(cls) -> None:
        """Create all system-level directories."""
        for d in [cls.REQUEST_LOG_DIR, cls.EVIDENCE_VAULT_DIR,
                  cls.HUNT_STATE_DIR, cls.FP_PATTERNS_DIR,
                  cls.RECON_CACHE_DIR, cls.CRED_CACHE_DIR,
                  cls.PATTERN_SYNC_DIR, cls.MONITOR_DIR,
                  cls.H1_CONFIG_DIR]:
            d.mkdir(parents=True, exist_ok=True)
