# Campaign Automation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `bountyhound campaign <url>` command for fully autonomous bug bounty scanning from HackerOne/Bugcrowd/Intigriti/YesWeHack URLs.

**Architecture:** Browser session extracts cookies from user's browser, Playwright fetches authenticated campaign pages, AI parses scope and selects high-value targets, existing pipeline runs scans, AI prioritizes findings.

**Tech Stack:** playwright (browser automation), browser-cookie3 (cookie extraction), groq (AI), existing bountyhound modules

---

### Task 1: Add Dependencies

**Files:**
- Modify: `pyproject.toml`

**Step 1: Add new dependencies to pyproject.toml**

```toml
dependencies = [
    "click>=8.1.0",
    "rich>=13.0.0",
    "pydantic>=2.0.0",
    "pyyaml>=6.0",
    "groq>=0.4.0",
    "playwright>=1.40.0",
    "browser-cookie3>=0.19.0",
]
```

**Step 2: Install dependencies**

Run: `pip install playwright browser-cookie3`
Run: `playwright install chromium`

**Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add playwright and browser-cookie3 dependencies"
```

---

### Task 2: Create Browser Session Module

**Files:**
- Create: `bountyhound/browser/__init__.py`
- Create: `bountyhound/browser/session.py`
- Test: `tests/test_browser_session.py`

**Step 1: Write the failing test**

```python
"""Tests for browser session handling."""

import pytest
from unittest.mock import patch, MagicMock

from bountyhound.browser import BrowserSession


class TestBrowserSession:
    """Tests for BrowserSession class."""

    def test_init_default_browser(self):
        """Test initialization with default browser."""
        session = BrowserSession()
        assert session.browser_type in ["chrome", "firefox", "edge"]

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

        assert len(cookies) >= 1
        assert any(c["domain"] == ".hackerone.com" for c in cookies)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_browser_session.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'bountyhound.browser'"

**Step 3: Write the implementation**

Create `bountyhound/browser/__init__.py`:
```python
"""Browser session handling for authenticated page fetching."""

from bountyhound.browser.session import BrowserSession

__all__ = ["BrowserSession"]
```

Create `bountyhound/browser/session.py`:
```python
"""Browser session handling with cookie extraction."""

import browser_cookie3
from playwright.sync_api import sync_playwright, Page
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
        """Extract cookies from user's browser for platform domains.

        Returns:
            List of cookie dicts with keys: name, value, domain, path, secure
        """
        # Get cookies based on browser type
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

        # Filter for platform domains
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

        # Create context with cookies
        cookies = self.extract_cookies()
        self._context = self._browser.new_context()

        if cookies:
            # Convert to Playwright cookie format
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
        """Fetch a page and return its content.

        Args:
            url: URL to fetch
            wait_for: Playwright wait condition

        Returns:
            Page HTML content
        """
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
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_browser_session.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/browser/ tests/test_browser_session.py
git commit -m "feat: add browser session module for cookie extraction"
```

---

### Task 3: Create Campaign Parser Base Class

**Files:**
- Create: `bountyhound/campaign/__init__.py`
- Create: `bountyhound/campaign/parser.py`
- Test: `tests/test_campaign_parser.py`

**Step 1: Write the failing test**

```python
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
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_parser.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `bountyhound/campaign/__init__.py`:
```python
"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform

__all__ = ["CampaignParser", "detect_platform"]
```

Create `bountyhound/campaign/parser.py`:
```python
"""Base campaign parser and platform detection."""

from typing import Optional
from urllib.parse import urlparse


def detect_platform(url: str) -> Optional[str]:
    """Detect bug bounty platform from URL.

    Args:
        url: Campaign URL

    Returns:
        Platform name (hackerone, bugcrowd, intigriti, yeswehack) or None
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace("www.", "").replace("app.", "")

    if "hackerone.com" in host:
        return "hackerone"
    elif "bugcrowd.com" in host:
        return "bugcrowd"
    elif "intigriti.com" in host:
        return "intigriti"
    elif "yeswehack.com" in host:
        return "yeswehack"

    return None


class CampaignParser:
    """Base class for campaign parsers."""

    def parse(self, html_content: str, url: str) -> dict:
        """Parse campaign page HTML to extract scope.

        Args:
            html_content: Raw HTML of campaign page
            url: Original URL

        Returns:
            Scope dict with in_scope, out_of_scope, program_name, etc.
        """
        raise NotImplementedError("Subclasses must implement parse()")

    def scope_to_domains(self, scope: dict) -> list[str]:
        """Extract scannable domains from parsed scope.

        Args:
            scope: Parsed scope dict

        Returns:
            List of domain strings (may include wildcards like *.example.com)
        """
        domains = []
        for item in scope.get("in_scope", []):
            if item.get("type") == "domain":
                domains.append(item.get("target"))
        return domains
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_parser.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/campaign/ tests/test_campaign_parser.py
git commit -m "feat: add campaign parser base class with platform detection"
```

---

### Task 4: Create HackerOne Parser

**Files:**
- Create: `bountyhound/campaign/hackerone.py`
- Modify: `bountyhound/campaign/__init__.py`
- Test: `tests/test_campaign_hackerone.py`

**Step 1: Write the failing test**

```python
"""Tests for HackerOne campaign parser."""

import pytest
from unittest.mock import MagicMock, patch

from bountyhound.campaign.hackerone import HackerOneParser


class TestHackerOneParser:
    """Tests for HackerOne parser."""

    def test_parse_with_ai(self):
        """Test that parser uses AI analyzer for scope extraction."""
        parser = HackerOneParser()

        # Mock the AI analyzer
        mock_scope = {
            "program_name": "Test Program",
            "in_scope": [
                {"type": "domain", "target": "example.com", "wildcard": False}
            ],
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
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_hackerone.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `bountyhound/campaign/hackerone.py`:
```python
"""HackerOne campaign parser."""

from typing import Optional
from urllib.parse import urlparse

from bountyhound.ai import AIAnalyzer
from bountyhound.campaign.parser import CampaignParser


class HackerOneParser(CampaignParser):
    """Parser for HackerOne campaign pages."""

    def __init__(self, ai: Optional[AIAnalyzer] = None) -> None:
        """Initialize with optional AI analyzer.

        Args:
            ai: AIAnalyzer instance (created if not provided)
        """
        self.ai = ai

    def _ensure_ai(self) -> None:
        """Lazily initialize AI analyzer."""
        if self.ai is None:
            self.ai = AIAnalyzer()

    def _get_program_name(self, url: str) -> str:
        """Extract program name from HackerOne URL.

        Args:
            url: HackerOne campaign URL

        Returns:
            Program name/slug
        """
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        if path_parts:
            return path_parts[-1]
        return "unknown"

    def parse(self, html_content: str, url: str) -> dict:
        """Parse HackerOne campaign page using AI.

        Args:
            html_content: Raw HTML content
            url: Campaign URL

        Returns:
            Parsed scope dict
        """
        self._ensure_ai()
        scope = self.ai.parse_campaign_scope(html_content, url)

        # Ensure program name is set
        if not scope.get("program_name") or scope["program_name"] == "Unknown":
            scope["program_name"] = self._get_program_name(url)

        return scope
```

Update `bountyhound/campaign/__init__.py`:
```python
"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser

__all__ = ["CampaignParser", "detect_platform", "HackerOneParser"]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_hackerone.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/campaign/ tests/test_campaign_hackerone.py
git commit -m "feat: add HackerOne campaign parser"
```

---

### Task 5: Create Bugcrowd Parser

**Files:**
- Create: `bountyhound/campaign/bugcrowd.py`
- Modify: `bountyhound/campaign/__init__.py`
- Test: `tests/test_campaign_bugcrowd.py`

**Step 1: Write the failing test**

```python
"""Tests for Bugcrowd campaign parser."""

import pytest
from unittest.mock import patch

from bountyhound.campaign.bugcrowd import BugcrowdParser


class TestBugcrowdParser:
    """Tests for Bugcrowd parser."""

    def test_parse_with_ai(self):
        """Test that parser uses AI analyzer."""
        parser = BugcrowdParser()

        mock_scope = {
            "program_name": "Test Program",
            "in_scope": [
                {"type": "domain", "target": "test.com", "wildcard": False}
            ],
            "out_of_scope": [],
            "bounty_range": {"low": 50, "high": 2500},
            "notes": ""
        }

        with patch.object(parser, "ai") as mock_ai:
            mock_ai.parse_campaign_scope.return_value = mock_scope
            result = parser.parse("<html>content</html>", "https://bugcrowd.com/test")

        assert result["program_name"] == "Test Program"

    def test_get_program_name_from_url(self):
        """Test extracting program name from URL."""
        parser = BugcrowdParser()
        assert parser._get_program_name("https://bugcrowd.com/paypal") == "paypal"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_bugcrowd.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `bountyhound/campaign/bugcrowd.py`:
```python
"""Bugcrowd campaign parser."""

from typing import Optional
from urllib.parse import urlparse

from bountyhound.ai import AIAnalyzer
from bountyhound.campaign.parser import CampaignParser


class BugcrowdParser(CampaignParser):
    """Parser for Bugcrowd campaign pages."""

    def __init__(self, ai: Optional[AIAnalyzer] = None) -> None:
        self.ai = ai

    def _ensure_ai(self) -> None:
        if self.ai is None:
            self.ai = AIAnalyzer()

    def _get_program_name(self, url: str) -> str:
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        if path_parts:
            return path_parts[-1]
        return "unknown"

    def parse(self, html_content: str, url: str) -> dict:
        self._ensure_ai()
        scope = self.ai.parse_campaign_scope(html_content, url)

        if not scope.get("program_name") or scope["program_name"] == "Unknown":
            scope["program_name"] = self._get_program_name(url)

        return scope
```

Update `bountyhound/campaign/__init__.py`:
```python
"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser

__all__ = ["CampaignParser", "detect_platform", "HackerOneParser", "BugcrowdParser"]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_bugcrowd.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/campaign/ tests/test_campaign_bugcrowd.py
git commit -m "feat: add Bugcrowd campaign parser"
```

---

### Task 6: Create Intigriti Parser

**Files:**
- Create: `bountyhound/campaign/intigriti.py`
- Modify: `bountyhound/campaign/__init__.py`
- Test: `tests/test_campaign_intigriti.py`

**Step 1: Write the failing test**

```python
"""Tests for Intigriti campaign parser."""

import pytest
from unittest.mock import patch

from bountyhound.campaign.intigriti import IntigritiParser


class TestIntigritiParser:
    """Tests for Intigriti parser."""

    def test_parse_with_ai(self):
        """Test that parser uses AI analyzer."""
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
        """Test extracting program name from Intigriti URL."""
        parser = IntigritiParser()
        assert parser._get_program_name("https://app.intigriti.com/programs/acme/bugbounty") == "bugbounty"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_intigriti.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `bountyhound/campaign/intigriti.py`:
```python
"""Intigriti campaign parser."""

from typing import Optional
from urllib.parse import urlparse

from bountyhound.ai import AIAnalyzer
from bountyhound.campaign.parser import CampaignParser


class IntigritiParser(CampaignParser):
    """Parser for Intigriti campaign pages."""

    def __init__(self, ai: Optional[AIAnalyzer] = None) -> None:
        self.ai = ai

    def _ensure_ai(self) -> None:
        if self.ai is None:
            self.ai = AIAnalyzer()

    def _get_program_name(self, url: str) -> str:
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        # Intigriti URLs: /programs/company/program-name
        if len(path_parts) >= 3:
            return path_parts[-1]
        elif path_parts:
            return path_parts[-1]
        return "unknown"

    def parse(self, html_content: str, url: str) -> dict:
        self._ensure_ai()
        scope = self.ai.parse_campaign_scope(html_content, url)

        if not scope.get("program_name") or scope["program_name"] == "Unknown":
            scope["program_name"] = self._get_program_name(url)

        return scope
```

Update `bountyhound/campaign/__init__.py`:
```python
"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser
from bountyhound.campaign.intigriti import IntigritiParser

__all__ = [
    "CampaignParser",
    "detect_platform",
    "HackerOneParser",
    "BugcrowdParser",
    "IntigritiParser",
]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_intigriti.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/campaign/ tests/test_campaign_intigriti.py
git commit -m "feat: add Intigriti campaign parser"
```

---

### Task 7: Create YesWeHack Parser

**Files:**
- Create: `bountyhound/campaign/yeswehack.py`
- Modify: `bountyhound/campaign/__init__.py`
- Test: `tests/test_campaign_yeswehack.py`

**Step 1: Write the failing test**

```python
"""Tests for YesWeHack campaign parser."""

import pytest
from unittest.mock import patch

from bountyhound.campaign.yeswehack import YesWeHackParser


class TestYesWeHackParser:
    """Tests for YesWeHack parser."""

    def test_parse_with_ai(self):
        """Test that parser uses AI analyzer."""
        parser = YesWeHackParser()

        mock_scope = {
            "program_name": "Test Program",
            "in_scope": [],
            "out_of_scope": [],
            "bounty_range": {"low": 0, "high": 0},
            "notes": ""
        }

        with patch.object(parser, "ai") as mock_ai:
            mock_ai.parse_campaign_scope.return_value = mock_scope
            result = parser.parse("<html>content</html>", "https://yeswehack.com/programs/test")

        assert result["program_name"] == "Test Program"

    def test_get_program_name_from_url(self):
        """Test extracting program name from YesWeHack URL."""
        parser = YesWeHackParser()
        assert parser._get_program_name("https://yeswehack.com/programs/acme-corp") == "acme-corp"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_yeswehack.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `bountyhound/campaign/yeswehack.py`:
```python
"""YesWeHack campaign parser."""

from typing import Optional
from urllib.parse import urlparse

from bountyhound.ai import AIAnalyzer
from bountyhound.campaign.parser import CampaignParser


class YesWeHackParser(CampaignParser):
    """Parser for YesWeHack campaign pages."""

    def __init__(self, ai: Optional[AIAnalyzer] = None) -> None:
        self.ai = ai

    def _ensure_ai(self) -> None:
        if self.ai is None:
            self.ai = AIAnalyzer()

    def _get_program_name(self, url: str) -> str:
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        # YesWeHack URLs: /programs/program-name
        if len(path_parts) >= 2:
            return path_parts[-1]
        elif path_parts:
            return path_parts[-1]
        return "unknown"

    def parse(self, html_content: str, url: str) -> dict:
        self._ensure_ai()
        scope = self.ai.parse_campaign_scope(html_content, url)

        if not scope.get("program_name") or scope["program_name"] == "Unknown":
            scope["program_name"] = self._get_program_name(url)

        return scope
```

Update `bountyhound/campaign/__init__.py`:
```python
"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser
from bountyhound.campaign.intigriti import IntigritiParser
from bountyhound.campaign.yeswehack import YesWeHackParser

__all__ = [
    "CampaignParser",
    "detect_platform",
    "HackerOneParser",
    "BugcrowdParser",
    "IntigritiParser",
    "YesWeHackParser",
]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_yeswehack.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/campaign/ tests/test_campaign_yeswehack.py
git commit -m "feat: add YesWeHack campaign parser"
```

---

### Task 8: Add AI Target Selection Method

**Files:**
- Modify: `bountyhound/ai/analyzer.py`
- Test: `tests/test_ai_analyzer.py`

**Step 1: Write the failing test**

```python
"""Tests for AI analyzer."""

import pytest
from unittest.mock import patch, MagicMock

from bountyhound.ai import AIAnalyzer


class TestAIAnalyzer:
    """Tests for AIAnalyzer class."""

    @patch("bountyhound.ai.analyzer.Groq")
    @patch("bountyhound.ai.analyzer.Config")
    def test_select_targets_returns_limited_list(self, mock_config_class, mock_groq):
        """Test that select_targets returns limited high-value targets."""
        # Setup mocks
        mock_config = MagicMock()
        mock_config.api_keys = {"groq": "test-key"}
        mock_config_class.load.return_value = mock_config

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '''
        {
            "selected": [
                {"target": "admin.example.com", "score": 95, "reason": "Admin panel"},
                {"target": "api.example.com", "score": 85, "reason": "API endpoint"}
            ],
            "total_analyzed": 100,
            "skipped": 98
        }
        '''
        mock_groq.return_value.chat.completions.create.return_value = mock_response

        analyzer = AIAnalyzer()
        recon_data = {
            "subdomains": ["admin.example.com", "api.example.com", "www.example.com"],
            "live_hosts": [
                {"host": "admin.example.com", "status_code": 200, "tech": ["Apache"]},
                {"host": "api.example.com", "status_code": 200, "tech": ["nginx"]},
            ]
        }

        result = analyzer.select_targets(recon_data, max_targets=50)

        assert "selected" in result
        assert len(result["selected"]) <= 50
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_ai_analyzer.py::TestAIAnalyzer::test_select_targets_returns_limited_list -v`
Expected: FAIL with "AttributeError: 'AIAnalyzer' object has no attribute 'select_targets'"

**Step 3: Add the method to analyzer.py**

Add this method to the `AIAnalyzer` class in `bountyhound/ai/analyzer.py`:

```python
def select_targets(self, recon_data: dict, max_targets: int = 100) -> dict:
    """Select high-value targets from reconnaissance data.

    Args:
        recon_data: Dict with subdomains, live_hosts, ports info
        max_targets: Maximum number of targets to select

    Returns:
        Dict with selected targets, scores, and reasoning
    """
    system_prompt = f"""You are a bug bounty target prioritization expert. Analyze reconnaissance data and select the {max_targets} highest-value targets for vulnerability scanning.

Prioritize targets with:
1. Admin/internal keywords (admin., internal., staging., dev., test.)
2. API endpoints (api., gateway., graphql.)
3. Legacy/outdated technologies
4. Non-standard ports or multiple services
5. Error responses (500s) or access denied (403s) that might be bypassable
6. Missing security headers

Return ONLY valid JSON:
{{
    "selected": [
        {{"target": "hostname", "score": 1-100, "reason": "brief reason"}}
    ],
    "total_analyzed": number,
    "skipped": number,
    "skipped_reason": "why these were deprioritized"
}}

Select at most {max_targets} targets. Higher score = higher priority."""

    user_prompt = f"Analyze and select high-value targets:\n{json.dumps(recon_data, indent=2)}"

    response = self._chat(system_prompt, user_prompt)

    try:
        start = response.find("{")
        end = response.rfind("}") + 1
        if start != -1 and end > start:
            result = json.loads(response[start:end])
            # Ensure we don't exceed max
            if "selected" in result:
                result["selected"] = result["selected"][:max_targets]
            return result
    except json.JSONDecodeError:
        pass

    # Fallback: return all targets without scoring
    return {
        "selected": [{"target": h, "score": 50, "reason": "default"} for h in recon_data.get("subdomains", [])[:max_targets]],
        "total_analyzed": len(recon_data.get("subdomains", [])),
        "skipped": 0,
    }
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_ai_analyzer.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/ai/analyzer.py tests/test_ai_analyzer.py
git commit -m "feat: add AI target selection method"
```

---

### Task 9: Create Campaign Runner

**Files:**
- Create: `bountyhound/campaign/runner.py`
- Modify: `bountyhound/campaign/__init__.py`
- Test: `tests/test_campaign_runner.py`

**Step 1: Write the failing test**

```python
"""Tests for campaign runner."""

import pytest
from unittest.mock import MagicMock, patch

from bountyhound.campaign.runner import CampaignRunner


class TestCampaignRunner:
    """Tests for CampaignRunner."""

    @patch("bountyhound.campaign.runner.BrowserSession")
    @patch("bountyhound.campaign.runner.AIAnalyzer")
    @patch("bountyhound.campaign.runner.Database")
    def test_run_returns_results(self, mock_db, mock_ai, mock_browser):
        """Test that run() returns structured results."""
        # Setup mocks
        mock_browser_instance = MagicMock()
        mock_browser_instance.fetch_page.return_value = "<html>scope content</html>"
        mock_browser.return_value = mock_browser_instance

        mock_ai_instance = MagicMock()
        mock_ai_instance.parse_campaign_scope.return_value = {
            "program_name": "test-program",
            "in_scope": [{"type": "domain", "target": "example.com", "wildcard": False}],
            "out_of_scope": [],
            "bounty_range": {"low": 100, "high": 5000},
            "notes": ""
        }
        mock_ai_instance.select_targets.return_value = {
            "selected": [{"target": "example.com", "score": 80, "reason": "main domain"}]
        }
        mock_ai_instance.prioritize_findings.return_value = []
        mock_ai_instance.generate_report_summary.return_value = "No findings"
        mock_ai.return_value = mock_ai_instance

        mock_db_instance = MagicMock()
        mock_db.return_value = mock_db_instance

        runner = CampaignRunner()

        with patch.object(runner, "_run_pipeline_on_targets") as mock_pipeline:
            mock_pipeline.return_value = {"findings": [], "subdomains": 1}
            result = runner.run("https://hackerone.com/test-program")

        assert "program_name" in result
        assert "scope" in result
        assert result["program_name"] == "test-program"

    def test_get_parser_for_platform(self):
        """Test parser selection by platform."""
        runner = CampaignRunner.__new__(CampaignRunner)
        runner.ai = None

        from bountyhound.campaign.hackerone import HackerOneParser
        from bountyhound.campaign.bugcrowd import BugcrowdParser

        parser = runner._get_parser("hackerone")
        assert isinstance(parser, HackerOneParser)

        parser = runner._get_parser("bugcrowd")
        assert isinstance(parser, BugcrowdParser)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_campaign_runner.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `bountyhound/campaign/runner.py`:
```python
"""Campaign runner for autonomous bug bounty scanning."""

from pathlib import Path
from typing import Optional

from rich.console import Console

from bountyhound.ai import AIAnalyzer
from bountyhound.browser import BrowserSession
from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser
from bountyhound.campaign.intigriti import IntigritiParser
from bountyhound.campaign.yeswehack import YesWeHackParser
from bountyhound.config import load_config
from bountyhound.pipeline import PipelineRunner
from bountyhound.report import ReportGenerator
from bountyhound.storage import Database


class CampaignRunner:
    """Orchestrates full autonomous campaign scanning."""

    def __init__(
        self,
        browser_type: str = "chrome",
        max_targets: int = 100,
        batch_mode: bool = False,
    ) -> None:
        """Initialize campaign runner.

        Args:
            browser_type: Browser to extract cookies from
            max_targets: Maximum targets to scan after AI selection
            batch_mode: Suppress output if True
        """
        self.browser_type = browser_type
        self.max_targets = max_targets
        self.batch_mode = batch_mode
        self.console = Console()
        self.config = load_config()

        self.browser: Optional[BrowserSession] = None
        self.ai: Optional[AIAnalyzer] = None
        self.db: Optional[Database] = None

    def log(self, message: str, style: str = "") -> None:
        """Print message if not in batch mode."""
        if not self.batch_mode:
            if style:
                self.console.print(message, style=style)
            else:
                self.console.print(message)

    def _get_parser(self, platform: str) -> CampaignParser:
        """Get appropriate parser for platform.

        Args:
            platform: Platform name

        Returns:
            Parser instance
        """
        parsers = {
            "hackerone": HackerOneParser,
            "bugcrowd": BugcrowdParser,
            "intigriti": IntigritiParser,
            "yeswehack": YesWeHackParser,
        }
        parser_class = parsers.get(platform, HackerOneParser)
        return parser_class(ai=self.ai)

    def _run_pipeline_on_targets(self, targets: list[str]) -> dict:
        """Run recon and scan pipeline on selected targets.

        Args:
            targets: List of target domains/hostnames

        Returns:
            Combined results dict
        """
        results = {
            "subdomains": 0,
            "live_hosts": 0,
            "findings": [],
        }

        pipeline = PipelineRunner(self.db, batch_mode=True)

        for target in targets:
            # Add target and run pipeline
            self.db.add_target(target)
            pipeline_result = pipeline.run_pipeline(target)

            # Aggregate results
            recon = pipeline_result.get("recon", {})
            results["subdomains"] += recon.get("subdomains", 0)
            results["live_hosts"] += recon.get("live_hosts", 0)

            # Get findings from database
            target_obj = self.db.get_target(target)
            if target_obj:
                findings = self.db.get_findings(target_obj.id)
                for f in findings:
                    results["findings"].append({
                        "name": f.name,
                        "severity": f.severity,
                        "url": f.url,
                        "evidence": f.evidence,
                        "template": f.template,
                    })

        return results

    def run(self, campaign_url: str) -> dict:
        """Run full autonomous campaign scan.

        Args:
            campaign_url: Bug bounty program URL

        Returns:
            Results dict with scope, findings, summary
        """
        self.log(f"[*] Starting campaign scan: {campaign_url}", "bold cyan")

        # Detect platform
        platform = detect_platform(campaign_url)
        if not platform:
            self.log("[!] Could not detect platform from URL", "red")
            return {"error": "Unknown platform"}

        self.log(f"[*] Detected platform: {platform}", "blue")

        # Initialize components
        self.browser = BrowserSession(browser_type=self.browser_type)
        self.ai = AIAnalyzer()
        self.db = Database()
        self.db.initialize()

        try:
            # Fetch campaign page
            self.log("[*] Fetching campaign scope...", "blue")
            html_content = self.browser.fetch_page(campaign_url)

            # Parse scope
            parser = self._get_parser(platform)
            scope = parser.parse(html_content, campaign_url)
            program_name = scope.get("program_name", "unknown")

            in_scope_count = len(scope.get("in_scope", []))
            self.log(f"    Found {in_scope_count} in-scope targets", "green")

            # Extract domains from scope
            domains = parser.scope_to_domains(scope)
            if not domains:
                self.log("[!] No scannable domains in scope", "yellow")
                return {
                    "program_name": program_name,
                    "scope": scope,
                    "error": "No domains found",
                }

            # Run recon on all domains to gather data
            self.log("[*] Running subdomain enumeration...", "blue")
            recon_data = {"subdomains": [], "live_hosts": []}

            from bountyhound.recon import SubdomainScanner, HttpProber
            tool_paths = self.config.get("tools", {})
            subdomain_scanner = SubdomainScanner(config_path=tool_paths.get("subfinder"))
            http_prober = HttpProber(config_path=tool_paths.get("httpx"))

            for domain in domains:
                # Handle wildcards
                base_domain = domain.replace("*.", "")
                try:
                    subs = subdomain_scanner.run(base_domain)
                    recon_data["subdomains"].extend(subs)
                except Exception:
                    recon_data["subdomains"].append(base_domain)

            self.log(f"    Found {len(recon_data['subdomains'])} subdomains", "green")

            # Probe live hosts
            if recon_data["subdomains"]:
                try:
                    live = http_prober.run(recon_data["subdomains"])
                    recon_data["live_hosts"] = live
                    self.log(f"    Found {len(live)} live hosts", "green")
                except Exception:
                    pass

            # AI target selection
            self.log("[*] AI selecting high-value targets...", "blue")
            selection = self.ai.select_targets(recon_data, max_targets=self.max_targets)
            selected = [t["target"] for t in selection.get("selected", [])]
            self.log(f"    Selected {len(selected)} targets for scanning", "green")

            # Run vulnerability scans on selected targets
            self.log("[*] Running vulnerability scans...", "blue")
            scan_results = self._run_pipeline_on_targets(selected)

            # AI prioritize findings
            self.log("[*] AI prioritizing findings...", "blue")
            findings = scan_results.get("findings", [])
            if findings:
                prioritized = self.ai.prioritize_findings(findings)
            else:
                prioritized = []

            # Generate summary
            report_data = {
                "program_name": program_name,
                "scope": scope,
                "targets_scanned": len(selected),
                "findings": prioritized,
            }
            summary = self.ai.generate_report_summary(report_data)

            # Save report
            self.log("[*] Generating report...", "blue")
            generator = ReportGenerator(self.db)
            output_dir = Path.home() / ".bountyhound" / "results" / program_name
            output_dir.mkdir(parents=True, exist_ok=True)

            # Count by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in prioritized:
                sev = f.get("severity", "low").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            self.log(f"\n[+] Campaign scan complete!", "bold green")
            self.log(f"    Program: {program_name}")
            self.log(f"    Targets scanned: {len(selected)}")
            self.log(f"    Findings: {len(prioritized)}")
            self.log(f"      Critical: {severity_counts['critical']}")
            self.log(f"      High: {severity_counts['high']}")
            self.log(f"      Medium: {severity_counts['medium']}")
            self.log(f"      Low: {severity_counts['low']}")

            return {
                "program_name": program_name,
                "platform": platform,
                "scope": scope,
                "targets_selected": selected,
                "targets_scanned": len(selected),
                "findings": prioritized,
                "severity_counts": severity_counts,
                "summary": summary,
            }

        finally:
            if self.browser:
                self.browser.close()
            if self.db:
                self.db.close()
```

Update `bountyhound/campaign/__init__.py`:
```python
"""Campaign parsing for bug bounty platforms."""

from bountyhound.campaign.parser import CampaignParser, detect_platform
from bountyhound.campaign.hackerone import HackerOneParser
from bountyhound.campaign.bugcrowd import BugcrowdParser
from bountyhound.campaign.intigriti import IntigritiParser
from bountyhound.campaign.yeswehack import YesWeHackParser
from bountyhound.campaign.runner import CampaignRunner

__all__ = [
    "CampaignParser",
    "detect_platform",
    "HackerOneParser",
    "BugcrowdParser",
    "IntigritiParser",
    "YesWeHackParser",
    "CampaignRunner",
]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_campaign_runner.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/campaign/ tests/test_campaign_runner.py
git commit -m "feat: add campaign runner for autonomous scanning"
```

---

### Task 10: Add Campaign CLI Command

**Files:**
- Modify: `bountyhound/cli.py`
- Test: `tests/test_cli.py`

**Step 1: Write the failing test**

Add to `tests/test_cli.py`:

```python
"""Tests for CLI commands."""

from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from bountyhound.cli import main


class TestCampaignCommand:
    """Tests for campaign command."""

    def test_campaign_command_exists(self):
        """Test that campaign command is registered."""
        runner = CliRunner()
        result = runner.invoke(main, ["campaign", "--help"])
        assert result.exit_code == 0
        assert "Run autonomous scan" in result.output or "campaign" in result.output

    @patch("bountyhound.cli.CampaignRunner")
    def test_campaign_runs_with_url(self, mock_runner_class):
        """Test campaign command runs with URL."""
        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            "program_name": "test",
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        mock_runner_class.return_value = mock_runner

        runner = CliRunner()
        result = runner.invoke(main, ["campaign", "https://hackerone.com/test"])

        mock_runner.run.assert_called_once_with("https://hackerone.com/test")
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::TestCampaignCommand -v`
Expected: FAIL

**Step 3: Add the campaign command to cli.py**

Add to `bountyhound/cli.py` after the imports:

```python
from bountyhound.campaign import CampaignRunner
```

Add the command before `if __name__ == "__main__":`:

```python
@main.command()
@click.argument("url")
@click.option("--browser", "-b", default="chrome", help="Browser to extract cookies from (chrome, firefox, edge)")
@click.option("--max-targets", "-m", default=100, help="Maximum targets to scan after AI selection")
@click.option("--batch", is_flag=True, help="Run in batch mode (no interactive output)")
def campaign(url: str, browser: str, max_targets: int, batch: bool):
    """Run autonomous scan on a bug bounty campaign.

    URL should be a HackerOne, Bugcrowd, Intigriti, or YesWeHack program page.

    Example: bountyhound campaign https://hackerone.com/paypal
    """
    runner = CampaignRunner(
        browser_type=browser,
        max_targets=max_targets,
        batch_mode=batch,
    )

    result = runner.run(url)

    if "error" in result:
        console.print(f"[red]Error: {result['error']}[/red]")
        return

    if not batch:
        # Print summary
        console.print(f"\n[bold]Campaign Results: {result.get('program_name', 'Unknown')}[/bold]")
        console.print(f"Platform: {result.get('platform', 'unknown')}")
        console.print(f"Targets scanned: {result.get('targets_scanned', 0)}")

        counts = result.get("severity_counts", {})
        console.print(f"\nFindings:")
        console.print(f"  Critical: {counts.get('critical', 0)}")
        console.print(f"  High: {counts.get('high', 0)}")
        console.print(f"  Medium: {counts.get('medium', 0)}")
        console.print(f"  Low: {counts.get('low', 0)}")

        if result.get("summary"):
            console.print(f"\n[bold]AI Summary:[/bold]")
            console.print(result["summary"])
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add bountyhound/cli.py tests/test_cli.py
git commit -m "feat: add campaign CLI command for autonomous scanning"
```

---

### Task 11: Add Config Options for Campaign

**Files:**
- Modify: `bountyhound/config.py`
- Modify: `~/.bountyhound/config.yaml`

**Step 1: Update default config**

In `bountyhound/config.py`, update `get_default_config()`:

```python
def get_default_config() -> dict[str, Any]:
    """Return default configuration."""
    return {
        "tools": {
            "subfinder": None,
            "httpx": None,
            "nmap": None,
            "nuclei": None,
            "ffuf": None,
        },
        "rate_limits": {
            "requests_per_second": 10,
            "delay_between_tools": 2,
        },
        "scan": {
            "nuclei_templates": ["cves", "vulnerabilities", "misconfigurations"],
            "nuclei_severity": "low,medium,high,critical",
            "nmap_ports": "top-1000",
        },
        "output": {
            "directory": "~/.bountyhound/results",
            "format": "markdown",
        },
        "api_keys": {
            "shodan": "",
            "censys": "",
            "virustotal": "",
            "groq": "",
        },
        "browser": "chrome",
        "campaign": {
            "max_targets": 100,
            "max_subdomains_per_wildcard": 1000,
            "scan_timeout_hours": 4,
        },
    }
```

**Step 2: Commit**

```bash
git add bountyhound/config.py
git commit -m "feat: add campaign config options"
```

---

### Task 12: Run All Tests and Verify

**Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass

**Step 2: Run bountyhound doctor**

Run: `bountyhound doctor`
Expected: Shows all tools including config status

**Step 3: Test campaign help**

Run: `bountyhound campaign --help`
Expected: Shows campaign command usage

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: test and integration fixes"
```

---

### Task 13: Update Version and Tag Release

**Files:**
- Modify: `bountyhound/__init__.py`

**Step 1: Bump version**

Update `bountyhound/__init__.py`:
```python
"""BountyHound - Bug bounty automation CLI."""

__version__ = "0.2.0"
```

**Step 2: Commit and tag**

```bash
git add bountyhound/__init__.py
git commit -m "chore: bump version to 0.2.0"
git tag -a v0.2.0 -m "v0.2.0 - Campaign automation"
```

---

## Summary

This plan adds the `bountyhound campaign <url>` command with:

1. **Browser session** - Cookie extraction from Chrome/Firefox/Edge
2. **Campaign parsers** - HackerOne, Bugcrowd, Intigriti, YesWeHack
3. **AI integration** - Scope parsing, target selection, finding prioritization
4. **Campaign runner** - Full autonomous pipeline orchestration
5. **CLI command** - Easy-to-use interface

Total: 13 tasks with TDD approach.
