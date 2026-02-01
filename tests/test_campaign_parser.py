"""Tests for campaign parser."""

import pytest
from bountyhound.campaign import CampaignParser, detect_platform


class TestDetectPlatform:
    """Tests for platform detection."""

    def test_detect_hackerone(self):
        assert detect_platform("https://hackerone.com/paypal") == "hackerone"
        assert detect_platform("https://www.hackerone.com/paypal") == "hackerone"

    def test_detect_bugcrowd(self):
        assert detect_platform("https://bugcrowd.com/paypal") == "bugcrowd"

    def test_detect_intigriti(self):
        assert detect_platform("https://app.intigriti.com/programs/company/program") == "intigriti"

    def test_detect_yeswehack(self):
        assert detect_platform("https://yeswehack.com/programs/company") == "yeswehack"

    def test_detect_unknown(self):
        assert detect_platform("https://example.com/bounty") is None


class TestCampaignParser:
    """Tests for CampaignParser base class."""

    def test_scope_to_domains_simple(self):
        """Test extracting domains from scope."""
        parser = CampaignParser()
        scope = {
            "in_scope": [
                {"type": "domain", "target": "example.com", "wildcard": False},
                {"type": "domain", "target": "*.api.example.com", "wildcard": True},
            ]
        }
        domains = parser.scope_to_domains(scope)
        assert "example.com" in domains
        assert "*.api.example.com" in domains

    def test_scope_to_domains_filters_non_domains(self):
        """Test that non-domain assets are filtered out."""
        parser = CampaignParser()
        scope = {
            "in_scope": [
                {"type": "domain", "target": "example.com", "wildcard": False},
                {"type": "ios", "target": "com.example.app", "wildcard": False},
            ]
        }
        domains = parser.scope_to_domains(scope)
        assert "example.com" in domains
        assert "com.example.app" not in domains
        assert len(domains) == 1
