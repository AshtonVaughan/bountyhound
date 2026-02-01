"""Tests for campaign runner."""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from bountyhound.campaign.runner import CampaignRunner


class TestCampaignRunner:
    """Tests for CampaignRunner class."""

    def test_init_default_values(self):
        """Test default initialization values."""
        runner = CampaignRunner()
        assert runner.browser_type == "chrome"
        assert runner.max_targets == 100
        assert runner.batch_mode is False

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        runner = CampaignRunner(
            browser_type="firefox",
            max_targets=50,
            batch_mode=True,
        )
        assert runner.browser_type == "firefox"
        assert runner.max_targets == 50
        assert runner.batch_mode is True

    def test_get_parser_hackerone(self):
        """Test getting HackerOne parser."""
        runner = CampaignRunner()
        parser = runner._get_parser("hackerone")
        from bountyhound.campaign.hackerone import HackerOneParser
        assert isinstance(parser, HackerOneParser)

    def test_get_parser_bugcrowd(self):
        """Test getting Bugcrowd parser."""
        runner = CampaignRunner()
        parser = runner._get_parser("bugcrowd")
        from bountyhound.campaign.bugcrowd import BugcrowdParser
        assert isinstance(parser, BugcrowdParser)

    def test_get_parser_intigriti(self):
        """Test getting Intigriti parser."""
        runner = CampaignRunner()
        parser = runner._get_parser("intigriti")
        from bountyhound.campaign.intigriti import IntigritiParser
        assert isinstance(parser, IntigritiParser)

    def test_get_parser_yeswehack(self):
        """Test getting YesWeHack parser."""
        runner = CampaignRunner()
        parser = runner._get_parser("yeswehack")
        from bountyhound.campaign.yeswehack import YesWeHackParser
        assert isinstance(parser, YesWeHackParser)

    def test_get_parser_unknown_raises(self):
        """Test that unknown platform raises ValueError."""
        runner = CampaignRunner()
        with pytest.raises(ValueError, match="Unsupported platform"):
            runner._get_parser("unknown_platform")

    def test_log_prints_in_normal_mode(self, capsys):
        """Test that log prints output when not in batch mode."""
        runner = CampaignRunner(batch_mode=False)
        runner.log("[*] Test message")
        captured = capsys.readouterr()
        assert "Test message" in captured.out

    def test_log_silent_in_batch_mode(self, capsys):
        """Test that log is silent in batch mode."""
        runner = CampaignRunner(batch_mode=True)
        runner.log("[*] Test message")
        captured = capsys.readouterr()
        assert captured.out == ""

    @patch("bountyhound.campaign.runner.BrowserSession")
    @patch("bountyhound.campaign.runner.AIAnalyzer")
    @patch("bountyhound.campaign.runner.Database")
    @patch("bountyhound.campaign.runner.PipelineRunner")
    @patch("bountyhound.campaign.runner.detect_platform")
    def test_run_orchestrates_full_flow(
        self,
        mock_detect_platform,
        mock_pipeline_runner,
        mock_db_class,
        mock_ai_class,
        mock_browser_class,
    ):
        """Test that run() orchestrates the full campaign flow."""
        # Setup mocks
        mock_detect_platform.return_value = "hackerone"

        mock_browser = MagicMock()
        mock_browser.fetch_page.return_value = "<html>Campaign page</html>"
        mock_browser_class.return_value = mock_browser

        mock_ai = MagicMock()
        mock_ai.select_targets.return_value = {
            "selected": [
                {"target": "api.example.com", "score": 90, "reason": "API"},
            ],
            "total_analyzed": 10,
            "skipped": 9,
        }
        mock_ai.prioritize_findings.return_value = [
            {"name": "XSS", "severity": "high", "priority": 1, "bounty_estimate": 1000}
        ]
        mock_ai.generate_report_summary.return_value = "# Summary\nTest report"
        mock_ai_class.return_value = mock_ai

        mock_db = MagicMock()
        mock_db.get_subdomains.return_value = [
            MagicMock(hostname="api.example.com", status_code=200),
        ]
        mock_db.get_findings.return_value = [
            MagicMock(name="XSS", severity="high", url="https://api.example.com"),
        ]
        mock_db_class.return_value = mock_db

        mock_pipeline = MagicMock()
        mock_pipeline.run_recon.return_value = {
            "subdomains": 5,
            "live_hosts": 3,
            "ports": 10,
        }
        mock_pipeline.run_scan.return_value = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 1,
            "info": 5,
        }
        mock_pipeline_runner.return_value = mock_pipeline

        # Run the campaign
        runner = CampaignRunner(batch_mode=True)

        # Mock the parser
        with patch.object(runner, "_get_parser") as mock_get_parser:
            mock_parser = MagicMock()
            mock_parser.parse.return_value = {
                "program_name": "test-program",
                "in_scope": [
                    {"type": "domain", "target": "example.com", "wildcard": False},
                ],
                "out_of_scope": [],
                "bounty_range": {"low": 100, "high": 5000},
            }
            mock_parser.scope_to_domains.return_value = ["example.com"]
            mock_get_parser.return_value = mock_parser

            result = runner.run("https://hackerone.com/test-program")

        # Verify results structure
        assert result is not None
        assert "program_name" in result
        assert "platform" in result
        assert "scope" in result
        assert "domains" in result
        assert "recon" in result
        assert "selected_targets" in result
        assert "scan" in result
        assert "findings" in result
        assert "summary" in result

        # Verify browser was used
        mock_browser.fetch_page.assert_called_once()
        mock_browser.close.assert_called_once()

        # Verify AI was used for target selection
        mock_ai.select_targets.assert_called_once()

    @patch("bountyhound.campaign.runner.detect_platform")
    def test_run_raises_for_unknown_platform(self, mock_detect_platform):
        """Test that run raises error for unknown platform."""
        mock_detect_platform.return_value = None

        runner = CampaignRunner(batch_mode=True)
        with pytest.raises(ValueError, match="Could not detect platform"):
            runner.run("https://unknown-platform.com/program")

    @patch("bountyhound.campaign.runner.BrowserSession")
    @patch("bountyhound.campaign.runner.AIAnalyzer")
    @patch("bountyhound.campaign.runner.Database")
    @patch("bountyhound.campaign.runner.PipelineRunner")
    @patch("bountyhound.campaign.runner.detect_platform")
    def test_run_pipeline_on_targets(
        self,
        mock_detect_platform,
        mock_pipeline_runner,
        mock_db_class,
        mock_ai_class,
        mock_browser_class,
    ):
        """Test _run_pipeline_on_targets method."""
        mock_detect_platform.return_value = "hackerone"

        mock_browser = MagicMock()
        mock_browser.fetch_page.return_value = "<html>test</html>"
        mock_browser_class.return_value = mock_browser

        mock_ai = MagicMock()
        mock_ai.select_targets.return_value = {
            "selected": [{"target": "api.example.com", "score": 90, "reason": "API"}],
            "total_analyzed": 1,
            "skipped": 0,
        }
        mock_ai.prioritize_findings.return_value = []
        mock_ai.generate_report_summary.return_value = "Summary"
        mock_ai_class.return_value = mock_ai

        # Create mock subdomain that matches AI-selected target
        mock_subdomain = MagicMock()
        mock_subdomain.hostname = "api.example.com"
        mock_subdomain.status_code = 200
        mock_subdomain.technologies = []
        mock_subdomain.ip_address = "1.2.3.4"

        mock_db = MagicMock()
        mock_db.get_subdomains.return_value = [mock_subdomain]
        mock_db.get_findings.return_value = []
        mock_db_class.return_value = mock_db

        mock_pipeline = MagicMock()
        mock_pipeline.run_recon.return_value = {"subdomains": 0, "live_hosts": 0, "ports": 0}
        mock_pipeline.run_scan.return_value = {}
        mock_pipeline_runner.return_value = mock_pipeline

        runner = CampaignRunner(batch_mode=True)

        with patch.object(runner, "_get_parser") as mock_get_parser:
            mock_parser = MagicMock()
            mock_parser.parse.return_value = {
                "program_name": "test",
                "in_scope": [{"type": "domain", "target": "example.com", "wildcard": False}],
                "out_of_scope": [],
                "bounty_range": {"low": 0, "high": 0},
            }
            mock_parser.scope_to_domains.return_value = ["example.com"]
            mock_get_parser.return_value = mock_parser

            runner.run("https://hackerone.com/test")

        # Verify pipeline was called for domains
        mock_pipeline.run_recon.assert_called()
        # Verify scan was called on AI-selected target (not original domain)
        mock_pipeline.run_scan.assert_called_with("api.example.com")


class TestCampaignRunnerIntegration:
    """Integration-style tests with temporary database."""

    @patch("bountyhound.campaign.runner.BrowserSession")
    @patch("bountyhound.campaign.runner.AIAnalyzer")
    @patch("bountyhound.campaign.runner.PipelineRunner")
    @patch("bountyhound.campaign.runner.detect_platform")
    def test_run_with_real_database(
        self,
        mock_detect_platform,
        mock_pipeline_runner,
        mock_ai_class,
        mock_browser_class,
    ):
        """Test run with actual database in temp directory."""
        mock_detect_platform.return_value = "hackerone"

        mock_browser = MagicMock()
        mock_browser.fetch_page.return_value = "<html>test</html>"
        mock_browser_class.return_value = mock_browser

        mock_ai = MagicMock()
        mock_ai.select_targets.return_value = {
            "selected": [],
            "total_analyzed": 0,
            "skipped": 0,
        }
        mock_ai.prioritize_findings.return_value = []
        mock_ai.generate_report_summary.return_value = "Summary"
        mock_ai_class.return_value = mock_ai

        mock_pipeline = MagicMock()
        mock_pipeline.run_recon.return_value = {"subdomains": 0, "live_hosts": 0, "ports": 0}
        mock_pipeline.run_scan.return_value = {}
        mock_pipeline_runner.return_value = mock_pipeline

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            runner = CampaignRunner(batch_mode=True)

            with patch.object(runner, "_get_parser") as mock_get_parser:
                mock_parser = MagicMock()
                mock_parser.parse.return_value = {
                    "program_name": "test",
                    "in_scope": [],
                    "out_of_scope": [],
                    "bounty_range": {"low": 0, "high": 0},
                }
                mock_parser.scope_to_domains.return_value = []
                mock_get_parser.return_value = mock_parser

                # Patch database path
                with patch("bountyhound.campaign.runner.Database") as mock_db_class:
                    from bountyhound.storage import Database
                    real_db = Database(db_path)
                    real_db.initialize()
                    mock_db_class.return_value = real_db

                    result = runner.run("https://hackerone.com/test")

                    assert result["program_name"] == "test"
                    assert result["platform"] == "hackerone"

                    real_db.close()
