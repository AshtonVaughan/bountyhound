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
