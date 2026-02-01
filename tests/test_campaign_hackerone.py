"""Tests for HackerOne campaign parser."""

import pytest
from unittest.mock import MagicMock, patch

from bountyhound.campaign.hackerone import HackerOneParser


class TestHackerOneParser:
    """Tests for HackerOne parser."""

    def test_parse_with_ai(self):
        """Test that parser uses AI analyzer for scope extraction."""
        parser = HackerOneParser()
        mock_scope = {
            "program_name": "Test Program",
            "in_scope": [{"type": "domain", "target": "example.com", "wildcard": False}],
            "out_of_scope": [],
            "bounty_range": {"low": 100, "high": 5000},
            "notes": ""
        }

        with patch.object(parser, "ai") as mock_ai:
            mock_ai.parse_campaign_scope.return_value = mock_scope
            result = parser.parse("<html>content</html>", "https://hackerone.com/test")

        assert result["program_name"] == "Test Program"
        assert len(result["in_scope"]) == 1

    def test_get_program_name_from_url(self):
        """Test extracting program name from URL."""
        parser = HackerOneParser()
        assert parser._get_program_name("https://hackerone.com/paypal") == "paypal"
        assert parser._get_program_name("https://hackerone.com/security/paypal") == "paypal"
