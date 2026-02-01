"""Tests for Bugcrowd campaign parser."""

import pytest
from unittest.mock import patch

from bountyhound.campaign.bugcrowd import BugcrowdParser


class TestBugcrowdParser:
    """Tests for Bugcrowd parser."""

    def test_parse_with_ai(self):
        parser = BugcrowdParser()
        mock_scope = {
            "program_name": "Test Program",
            "in_scope": [{"type": "domain", "target": "test.com", "wildcard": False}],
            "out_of_scope": [],
            "bounty_range": {"low": 50, "high": 2500},
            "notes": ""
        }

        with patch.object(parser, "ai") as mock_ai:
            mock_ai.parse_campaign_scope.return_value = mock_scope
            result = parser.parse("<html>content</html>", "https://bugcrowd.com/test")

        assert result["program_name"] == "Test Program"

    def test_get_program_name_from_url(self):
        parser = BugcrowdParser()
        assert parser._get_program_name("https://bugcrowd.com/paypal") == "paypal"
