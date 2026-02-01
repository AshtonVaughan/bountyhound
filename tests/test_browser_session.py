"""Tests for browser session handling."""

import pytest
from unittest.mock import patch, MagicMock

from bountyhound.browser import BrowserSession


class TestBrowserSession:
    """Tests for BrowserSession class."""

    def test_init_default_browser(self):
        """Test initialization with default browser."""
        session = BrowserSession()
        assert session.browser_type == "chrome"

    def test_init_custom_browser(self):
        """Test initialization with custom browser."""
        session = BrowserSession(browser_type="firefox")
        assert session.browser_type == "firefox"

    def test_get_platform_domains(self):
        """Test platform domain detection."""
        session = BrowserSession()
        domains = session._get_platform_domains()
        assert "hackerone.com" in domains
        assert "bugcrowd.com" in domains
        assert "intigriti.com" in domains
        assert "yeswehack.com" in domains

    @patch("bountyhound.browser.session.browser_cookie3")
    def test_extract_cookies_filters_domains(self, mock_bc3):
        """Test that cookie extraction filters for platform domains."""
        mock_cookie = MagicMock()
        mock_cookie.domain = ".hackerone.com"
        mock_cookie.name = "session"
        mock_cookie.value = "abc123"
        mock_cookie.path = "/"
        mock_cookie.secure = True

        mock_bc3.chrome.return_value = [mock_cookie]

        session = BrowserSession(browser_type="chrome")
        cookies = session.extract_cookies()

        assert len(cookies) == 1
        assert cookies[0]["domain"] == ".hackerone.com"
