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
