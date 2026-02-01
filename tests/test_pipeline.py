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
