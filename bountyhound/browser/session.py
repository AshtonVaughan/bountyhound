"""Browser session handling with cookie extraction."""

import browser_cookie3
from playwright.sync_api import sync_playwright
from typing import Optional


class BrowserSession:
    """Manages browser sessions with cookie extraction from user's browser."""

    PLATFORM_DOMAINS = [
        "hackerone.com",
        "bugcrowd.com",
        "intigriti.com",
        "yeswehack.com",
    ]

    def __init__(self, browser_type: str = "chrome") -> None:
        """Initialize browser session.

        Args:
            browser_type: Browser to extract cookies from (chrome, firefox, edge)
        """
        self.browser_type = browser_type
        self._playwright = None
        self._browser = None
        self._context = None

    def _get_platform_domains(self) -> list[str]:
        """Get list of bug bounty platform domains."""
        return self.PLATFORM_DOMAINS

    def extract_cookies(self) -> list[dict]:
        """Extract cookies from user's browser for platform domains."""
        try:
            if self.browser_type == "chrome":
                jar = browser_cookie3.chrome(domain_name="")
            elif self.browser_type == "firefox":
                jar = browser_cookie3.firefox(domain_name="")
            elif self.browser_type == "edge":
                jar = browser_cookie3.edge(domain_name="")
            else:
                jar = browser_cookie3.load(domain_name="")
        except Exception:
            return []

        platform_cookies = []
        for cookie in jar:
            domain = cookie.domain.lstrip(".")
            if any(platform in domain for platform in self.PLATFORM_DOMAINS):
                platform_cookies.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                })

        return platform_cookies

    def start(self) -> None:
        """Start Playwright browser with extracted cookies."""
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)

        cookies = self.extract_cookies()
        self._context = self._browser.new_context()

        if cookies:
            pw_cookies = []
            for c in cookies:
                pw_cookies.append({
                    "name": c["name"],
                    "value": c["value"],
                    "domain": c["domain"],
                    "path": c["path"],
                    "secure": c["secure"],
                    "sameSite": "Lax",
                })
            self._context.add_cookies(pw_cookies)

    def fetch_page(self, url: str, wait_for: str = "networkidle") -> str:
        """Fetch a page and return its content."""
        if not self._context:
            self.start()

        page = self._context.new_page()
        try:
            page.goto(url, wait_until=wait_for, timeout=30000)
            content = page.content()
            return content
        finally:
            page.close()

    def close(self) -> None:
        """Close browser and cleanup."""
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
