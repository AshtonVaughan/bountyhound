"""Tests for Intigriti campaign parser."""

import pytest
from unittest.mock import patch

from bountyhound.campaign.intigriti import IntigritiParser


class TestIntigritiParser:
    """Tests for Intigriti parser."""

    def test_parse_with_ai(self):
        parser = IntigritiParser()
        mock_scope = {
            "program_name": "Test Program",
            "in_scope": [],
            "out_of_scope": [],
            "bounty_range": {"low": 0, "high": 0},
            "notes": ""
        }

        with patch.object(parser, "ai") as mock_ai:
            mock_ai.parse_campaign_scope.return_value = mock_scope
            result = parser.parse("<html>content</html>", "https://app.intigriti.com/programs/company/program")

        assert result["program_name"] == "Test Program"

    def test_get_program_name_from_url(self):
        parser = IntigritiParser()
        assert parser._get_program_name("https://app.intigriti.com/programs/acme/bugbounty") == "bugbounty"
