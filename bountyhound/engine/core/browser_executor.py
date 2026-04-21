"""BountyHound Browser Executor - Playwright automation for security testing."""
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from engine.core.config import BountyHoundConfig

try:
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    PlaywrightError = Exception

try:
    from colorama import Fore, Style
except ImportError:
    class _Stub:
        CYAN = YELLOW = RED = GREEN = RESET_ALL = ""
    Fore = Style = _Stub()

logger = logging.getLogger("bountyhound.browser")
_TAG, _WARN = f"{Fore.CYAN}[browser]{Style.RESET_ALL}", f"{Fore.YELLOW}[browser]{Style.RESET_ALL}"
_ERR, _OK = f"{Fore.RED}[browser]{Style.RESET_ALL}", f"{Fore.GREEN}[browser]{Style.RESET_ALL}"
SCREENSHOTS_DIR = BountyHoundConfig.FINDINGS_DIR / "screenshots"
DEFAULT_XSS_PAYLOADS = [
    "<img src=x onerror=document.title='XSS-FIRED'>",
    "\"><script>document.title='XSS-FIRED'</script>",
    "javascript:document.title='XSS-FIRED'",  "'-document.title='XSS-FIRED'-'"]
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")


class BrowserExecutor:
    """Playwright browser automation for security testing agents."""

    def __init__(self, headless: bool = True, timeout: int = 30000):
        self._browser = self._context = self._page = self._pw = None
        self.headless, self.timeout = headless, timeout
        self._screenshots: List[str] = []
        self._console_logs: List[Dict] = []
        self._network_requests: List[Dict] = []
        self._findings: List[Dict] = []

    def __enter__(self):
        self.start(); return self

    def __exit__(self, *exc):
        self.stop(); return False

    def __del__(self):
        try: self.stop()
        except Exception: pass

    def start(self):
        """Launch Playwright Chromium with realistic defaults."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning(f"{_WARN} playwright not installed - methods return empty results")
            return
        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(headless=self.headless)
            self._context = self._browser.new_context(
                user_agent=USER_AGENT, viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True)
            self._page = self._context.new_page()
            self._page.set_default_timeout(self.timeout)
            self._page.on("dialog", lambda d: d.dismiss())
            self._page.on("console", lambda m: self._console_logs.append(
                {"type": m.type, "text": m.text, "ts": datetime.utcnow().isoformat()}))
            self._page.on("request", lambda r: self._network_requests.append(
                {"url": r.url, "method": r.method, "headers": dict(r.headers),
                 "resource_type": r.resource_type, "ts": datetime.utcnow().isoformat()}))
            logger.info(f"{_TAG} browser started (headless={self.headless})")
        except PlaywrightError as exc:
            logger.error(f"{_ERR} failed to start browser: {exc}")
            self.stop()

    def stop(self):
        """Close browser and release resources."""
        for obj in (self._page, self._context, self._browser):
            try:
                if obj: obj.close()
            except Exception: pass
        if self._pw:
            try: self._pw.stop()
            except Exception: pass
        self._page = self._context = self._browser = self._pw = None

    def navigate(self, url: str) -> Dict:
        """Navigate to URL, wait for network idle, return page info dict."""
        empty = {"title": "", "url": url, "status": 0, "cookies": [], "console_errors": []}
        if not self._page:
            return empty
        try:
            resp = self._page.goto(url, wait_until="networkidle", timeout=self.timeout)
            status = resp.status if resp else 0
            info = {"title": self._page.title(), "url": self._page.url, "status": status,
                    "cookies": self._context.cookies() if self._context else [],
                    "console_errors": [l for l in self._console_logs if l["type"] == "error"]}
            logger.info(f"{_TAG} navigated to {url} [{status}]")
            return info
        except PlaywrightError as exc:
            logger.error(f"{_ERR} navigate({url}): {exc}")
            return empty

    # -- DOM XSS ----------------------------------------------------------

    def test_dom_xss(self, url: str, param: str, payloads: Optional[List[str]] = None) -> List[Dict]:
        """Test param for reflected/DOM XSS via document.title change detection."""
        if not self._page:
            return []
        results: List[Dict] = []
        for payload in (payloads or DEFAULT_XSS_PAYLOADS):
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                target = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                self._page.goto(target, wait_until="networkidle", timeout=self.timeout)
                if self._page.title() == "XSS-FIRED":
                    finding = {"type": "DOM_XSS", "param": param, "payload": payload,
                               "url": target, "evidence": self.capture_evidence(f"xss-{param}"),
                               "fired": True}
                    results.append(finding)
                    self._findings.append(finding)
                    logger.info(f"{_OK} XSS fired on param={param} payload={payload[:40]}")
            except PlaywrightError as exc:
                logger.error(f"{_ERR} xss test error: {exc}")
        return results

    # -- Client-side auth -------------------------------------------------

    def test_client_side_auth(self, url: str, protected_urls: List[str]) -> List[Dict]:
        """Check if protected URLs serve content without auth cookies."""
        if not self._page:
            return []
        results: List[Dict] = []
        self.navigate(url)
        saved_cookies = self._context.cookies() if self._context else []
        for target_url in protected_urls:
            try:
                self._page.goto(target_url, wait_until="networkidle", timeout=self.timeout)
                authed_len = len(self._page.content())
                self._context.clear_cookies()
                self._page.goto(target_url, wait_until="networkidle", timeout=self.timeout)
                unauthed_content = self._page.content()
                unauthed_title = self._page.title()
                if saved_cookies:
                    self._context.add_cookies(saved_cookies)
                if len(unauthed_content) > 500 and "login" not in unauthed_title.lower():
                    slug = urlparse(target_url).path.replace("/", "_")
                    finding = {"type": "CLIENT_SIDE_AUTH_BYPASS", "url": target_url,
                               "authed_length": authed_len, "unauthed_length": len(unauthed_content),
                               "evidence": self.capture_evidence(f"auth-bypass{slug}")}
                    results.append(finding)
                    self._findings.append(finding)
                    logger.info(f"{_OK} client-side auth bypass: {target_url}")
            except PlaywrightError as exc:
                logger.error(f"{_ERR} auth test error on {target_url}: {exc}")
        return results

    # -- SPA routes -------------------------------------------------------

    def test_spa_routes(self, base_url: str, routes: Optional[List[str]] = None) -> List[Dict]:
        """Discover and test SPA routes for exposed debug/admin pages."""
        if not self._page:
            return []
        if not routes:
            routes = self._discover_spa_routes(base_url)
        results: List[Dict] = []
        for route in routes:
            full = base_url.rstrip("/") + "/" + route.lstrip("/")
            try:
                self._page.goto(full, wait_until="networkidle", timeout=self.timeout)
                title = self._page.title()
                clen = len(self._page.content())
                if not any(k in title.lower() for k in ("404", "not found", "error")) and clen > 1000:
                    finding = {"type": "SPA_ROUTE_EXPOSED", "route": route, "url": full,
                               "title": title, "content_length": clen,
                               "evidence": self.capture_evidence(f"spa{route.replace('/', '_')}")}
                    results.append(finding)
                    self._findings.append(finding)
                    logger.info(f"{_OK} accessible SPA route: {route}")
            except PlaywrightError as exc:
                logger.error(f"{_ERR} spa route error ({route}): {exc}")
        return results

    def _discover_spa_routes(self, base_url: str) -> List[str]:
        """Extract SPA routes from JS bundles and framework configs."""
        routes: List[str] = []
        try:
            self.navigate(base_url)
            nd = self._page.evaluate(
                "() => window.__NEXT_DATA__ && Object.keys(window.__NEXT_DATA__.props || {})")
            if nd: routes.extend(nd)
            hrefs = self._page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href^="/"]'))
                    .map(a => a.getAttribute('href')).filter(Boolean);
            }""")
            if hrefs: routes.extend(hrefs)
        except PlaywrightError:
            pass
        routes.extend(["/admin", "/debug", "/dashboard", "/_debug", "/api-docs", "/graphql"])
        return list(set(routes))

    # -- Form injection ---------------------------------------------------

    def inject_and_check(self, url: str, selector: str, payload: str) -> Dict:
        """Fill form field with payload, submit, check for XSS firing."""
        if not self._page:
            return {"fired": False}
        try:
            self.navigate(url)
            self._page.fill(selector, payload)
            self._page.press(selector, "Enter")
            self._page.wait_for_load_state("networkidle", timeout=self.timeout)
            fired = self._page.title() == "XSS-FIRED"
            result = {"url": url, "selector": selector, "payload": payload, "fired": fired,
                      "title": self._page.title(),
                      "evidence": self.capture_evidence(f"inject{selector.replace(' ', '_')}")}
            if fired:
                self._findings.append({**result, "type": "INJECTED_XSS"})
                logger.info(f"{_OK} injection fired via {selector}")
            return result
        except PlaywrightError as exc:
            logger.error(f"{_ERR} inject_and_check error: {exc}")
            return {"fired": False, "error": str(exc)}

    # -- Evidence ---------------------------------------------------------

    def capture_evidence(self, description: str) -> str:
        """Take full-page screenshot, save to findings/screenshots/, return path."""
        if not self._page:
            return ""
        try:
            SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in description)
            path = str(SCREENSHOTS_DIR / f"{ts}_{safe}.png")
            self._page.screenshot(path=path, full_page=True)
            self._screenshots.append(path)
            logger.info(f"{_TAG} screenshot: {path}")
            return path
        except PlaywrightError as exc:
            logger.error(f"{_ERR} screenshot failed: {exc}")
            return ""

    # -- JS / cookies / storage -------------------------------------------

    def execute_js(self, script: str) -> Any:
        """Execute arbitrary JavaScript on the current page and return result."""
        if not self._page:
            return None
        try:
            return self._page.evaluate(script)
        except PlaywrightError as exc:
            logger.error(f"{_ERR} execute_js error: {exc}")
            return None

    def get_cookies(self) -> List[Dict]:
        """Return all cookies with security flags for current context."""
        if not self._context: return []
        try: return self._context.cookies()
        except PlaywrightError: return []

    def get_local_storage(self) -> Dict:
        """Return all localStorage key-value pairs (often contains tokens)."""
        if not self._page: return {}
        try:
            return self._page.evaluate("""() => {
                const o = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i); o[k] = localStorage.getItem(k); }
                return o; }""")
        except PlaywrightError: return {}

    # -- Network ----------------------------------------------------------

    def get_network_log(self) -> List[Dict]:
        """Return all captured network requests."""
        return list(self._network_requests)

    def intercept_api_calls(self, url_pattern: str = "**/api/**") -> List[Dict]:
        """Monkey-patch fetch/XHR to capture API calls with auth headers and bodies."""
        if not self._page:
            return []
        try:
            self._page.evaluate("""() => {
                window.__intercepted = [];
                const _fetch = window.fetch;
                window.fetch = async function(...a) {
                    const r = a[0] instanceof Request ? a[0] : new Request(a[0], a[1]);
                    window.__intercepted.push({url: r.url, method: r.method,
                        headers: Object.fromEntries(r.headers.entries()),
                        ts: new Date().toISOString(), type: 'fetch'});
                    return _fetch.apply(this, a);
                };
                const _open = XMLHttpRequest.prototype.open;
                const _send = XMLHttpRequest.prototype.send;
                const _setH = XMLHttpRequest.prototype.setRequestHeader;
                XMLHttpRequest.prototype.open = function(m, u) {
                    this.__m = {url: u, method: m, headers: {},
                        ts: new Date().toISOString(), type: 'xhr'};
                    return _open.apply(this, arguments);
                };
                XMLHttpRequest.prototype.setRequestHeader = function(k, v) {
                    if (this.__m) this.__m.headers[k] = v;
                    return _setH.apply(this, arguments);
                };
                XMLHttpRequest.prototype.send = function() {
                    if (this.__m) window.__intercepted.push(this.__m);
                    return _send.apply(this, arguments);
                };
            }""")
            self._page.wait_for_timeout(3000)
            return self._page.evaluate("() => window.__intercepted || []")
        except PlaywrightError as exc:
            logger.error(f"{_ERR} intercept_api_calls error: {exc}")
            return []
