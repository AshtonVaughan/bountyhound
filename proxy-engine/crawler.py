"""Crawler/Spider — discover endpoints by following links, forms, and JS references.

Supports two modes:
- Standard (httpx): fast, lightweight HTML parsing
- JS-aware (Playwright): renders pages with Chromium, discovers JS-generated links, submits forms
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from models import CrawlJob, CrawlResult
from state import state

log = logging.getLogger("proxy-engine.crawler")

_cancel_events: dict[str, asyncio.Event] = {}

# Patterns for extracting URLs from HTML and JS
_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_JS_URL_RE = re.compile(r'["\'](/[a-zA-Z0-9_/.-]+(?:\?[^"\']*)?)["\']')
_JS_FETCH_RE = re.compile(r'(?:fetch|axios\.\w+|XMLHttpRequest.*open)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_INPUT_RE = re.compile(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_WS_URL_RE = re.compile(r'["\']?(wss?://[a-zA-Z0-9._:/-]+(?:\?[^"\']*)?)["\']?', re.IGNORECASE)


def _extract_links(base_url: str, body: str, content_type: str) -> set[str]:
    """Extract links from HTML/JS content."""
    links = set()
    parsed_base = urlparse(base_url)

    # HTML links
    for match in _HREF_RE.finditer(body):
        url = match.group(1).strip()
        if url.startswith(("javascript:", "mailto:", "data:", "#")):
            continue
        absolute = urljoin(base_url, url)
        links.add(absolute)

    # JS paths
    for match in _JS_URL_RE.finditer(body):
        path = match.group(1)
        if path.startswith("/") and not path.startswith("//"):
            links.add(urljoin(base_url, path))

    # fetch/axios calls
    for match in _JS_FETCH_RE.finditer(body):
        url = match.group(1)
        absolute = urljoin(base_url, url)
        links.add(absolute)

    # Form actions
    for match in _FORM_ACTION_RE.finditer(body):
        action = match.group(1).strip()
        if action:
            links.add(urljoin(base_url, action))

    # WebSocket URLs
    for match in _WS_URL_RE.finditer(body):
        ws_url = match.group(1).strip()
        if ws_url:
            links.add(ws_url)

    # Filter to same host (or scope if enabled)
    result = set()
    for link in links:
        p = urlparse(link)
        clean = f"{p.scheme}://{p.netloc}{p.path}"
        if p.query:
            clean += f"?{p.query}"
        if p.hostname == parsed_base.hostname:
            result.add(clean)

    return result


def _extract_forms(base_url: str, body: str) -> list[dict]:
    """Extract forms with their actions and input fields."""
    forms = []
    form_re = re.compile(
        r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL
    )
    for attrs_match in form_re.finditer(body):
        attrs = attrs_match.group(1)
        form_body = attrs_match.group(2)

        method_match = re.search(r'method\s*=\s*["\'](\w+)["\']', attrs, re.IGNORECASE)
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)

        method = method_match.group(1).upper() if method_match else "GET"
        action = action_match.group(1) if action_match else ""
        action_url = urljoin(base_url, action) if action else base_url

        params = []
        for input_match in _FORM_INPUT_RE.finditer(form_body):
            params.append(input_match.group(1))

        forms.append({
            "method": method,
            "action": action_url,
            "params": params,
        })

    return forms


# ── Standard (httpx) crawl ──────────────────────────────────────────────────

async def _crawl(job: CrawlJob, base_url: str, max_depth: int,
                 concurrency: int, headers: dict[str, str],
                 follow_scope: bool, submit_forms: bool = False) -> None:
    """Main crawl loop."""
    cancel_event = _cancel_events.get(job.job_id)
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    queue.append((base_url, 0))
    sem = asyncio.Semaphore(concurrency)

    parsed_base = urlparse(base_url)
    base_host = parsed_base.hostname or ""

    async with httpx.AsyncClient(
        verify=False, timeout=15.0, follow_redirects=True,
        headers=headers,
    ) as client:

        async def fetch(url: str, depth: int) -> None:
            if cancel_event and cancel_event.is_set():
                return
            if url in visited:
                return
            if depth > max_depth:
                return

            # Normalize URL for dedup
            parsed = urlparse(url)
            if parsed.hostname != base_host:
                return
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if normalized in visited:
                return

            # Scope check (Task #30)
            if follow_scope:
                try:
                    from scope import is_in_scope
                    if not is_in_scope(parsed.hostname or "", url):
                        return
                except ImportError:
                    pass

            visited.add(normalized)
            visited.add(url)

            async with sem:
                if cancel_event and cancel_event.is_set():
                    return
                try:
                    resp = await client.get(url)
                    ct = resp.headers.get("content-type", "")
                    body = resp.text if len(resp.content) < 1_000_000 else ""

                    result = CrawlResult(
                        url=str(resp.url),
                        method="GET",
                        status_code=resp.status_code,
                        content_type=ct.split(";")[0].strip(),
                        length=len(resp.content),
                        depth=depth,
                    )

                    # Extract forms
                    if "html" in ct:
                        forms = _extract_forms(str(resp.url), body)
                        result.forms = forms
                        result.params = list(set(
                            p for form in forms for p in form["params"]
                        ))

                    # Extract query params
                    qs = parse_qs(parsed.query)
                    if qs:
                        result.params = list(set(result.params + list(qs.keys())))

                    job.results.append(result)
                    job.urls_found += 1

                    # Submit forms if enabled
                    if submit_forms and "html" in ct and forms:
                        for form in forms[:3]:  # limit to 3 forms per page
                            form_resp = await _submit_form(client, form, str(resp.url))
                            if form_resp and form_resp.status_code in (200, 201, 301, 302):
                                form_ct = form_resp.headers.get("content-type", "")
                                if "html" in form_ct:
                                    form_links = _extract_links(str(form_resp.url), form_resp.text, form_ct)
                                    for link in form_links:
                                        if link not in visited:
                                            queue.append((link, depth + 1))

                    # Extract and queue new links
                    if body and ("html" in ct or "javascript" in ct):
                        new_links = _extract_links(str(resp.url), body, ct)
                        for link in new_links:
                            if link not in visited:
                                queue.append((link, depth + 1))
                                job.urls_queued += 1

                except Exception as e:
                    log.debug(f"[crawler] Error fetching {url}: {e}")

        # BFS crawl
        while queue:
            if cancel_event and cancel_event.is_set():
                break

            batch = []
            while queue and len(batch) < concurrency * 2:
                url, depth = queue.popleft()
                if url not in visited and depth <= max_depth:
                    batch.append((url, depth))

            if not batch:
                break

            tasks = [asyncio.create_task(fetch(u, d)) for u, d in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

    if cancel_event and cancel_event.is_set():
        job.status = "cancelled"
    else:
        job.status = "completed"

    _cancel_events.pop(job.job_id, None)
    log.info(f"[crawler] Job {job.job_id}: {job.status}, {job.urls_found} URLs discovered")


# ── JS-aware (Playwright) crawl ─────────────────────────────────────────────

# JS to inject into pages to capture dynamic navigation and XHR/fetch calls
_INTERCEPT_JS = """
() => {
    window.__crawlerLinks = new Set();
    window.__crawlerForms = [];
    window.__crawlerXhr = new Set();

    // Intercept link clicks
    document.addEventListener('click', (e) => {
        const a = e.target.closest('a');
        if (a && a.href) window.__crawlerLinks.add(a.href);
    }, true);

    // Intercept fetch
    const origFetch = window.fetch;
    window.fetch = function(...args) {
        if (typeof args[0] === 'string') window.__crawlerXhr.add(args[0]);
        else if (args[0] && args[0].url) window.__crawlerXhr.add(args[0].url);
        return origFetch.apply(this, args);
    };

    // Intercept XMLHttpRequest
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        window.__crawlerXhr.add(url);
        return origOpen.apply(this, arguments);
    };

    // SPA route capture
    const origPushState = history.pushState;
    history.pushState = function(...args) {
        if (args[2]) window.__crawlerLinks.add(new URL(args[2], location.href).href);
        return origPushState.apply(this, args);
    };
    const origReplaceState = history.replaceState;
    history.replaceState = function(...args) {
        if (args[2]) window.__crawlerLinks.add(new URL(args[2], location.href).href);
        return origReplaceState.apply(this, args);
    };

    // Capture form data
    document.querySelectorAll('form').forEach(form => {
        window.__crawlerForms.push({
            method: (form.method || 'GET').toUpperCase(),
            action: form.action || window.location.href,
            params: Array.from(form.querySelectorAll('input[name], select[name], textarea[name]'))
                        .map(el => el.name)
        });
    });
}
"""

_COLLECT_JS = """
() => {
    const links = new Set();

    // Collect all href/src attributes from the rendered DOM
    document.querySelectorAll('a[href], link[href], script[src], img[src], iframe[src], form[action]').forEach(el => {
        const val = el.href || el.src || el.action;
        if (val && !val.startsWith('javascript:') && !val.startsWith('data:') && !val.startsWith('mailto:'))
            links.add(val);
    });

    // Shadow DOM traversal
    function collectFromShadow(root) {
        root.querySelectorAll('*').forEach(el => {
            if (el.shadowRoot) {
                el.shadowRoot.querySelectorAll('a[href], form[action]').forEach(inner => {
                    const val = inner.href || inner.action;
                    if (val) links.add(val);
                });
                collectFromShadow(el.shadowRoot);
            }
        });
    }
    collectFromShadow(document);

    // Collect intercepted links
    if (window.__crawlerLinks) window.__crawlerLinks.forEach(l => links.add(l));
    if (window.__crawlerXhr) window.__crawlerXhr.forEach(l => links.add(l));

    // Collect forms
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
        forms.push({
            method: (form.method || 'GET').toUpperCase(),
            action: form.action || window.location.href,
            params: Array.from(form.querySelectorAll('input[name], select[name], textarea[name]'))
                        .map(el => el.name)
        });
    });
    if (window.__crawlerForms) window.__crawlerForms.forEach(f => forms.push(f));

    return { links: Array.from(links), forms };
}
"""


async def _js_crawl(job: CrawlJob, base_url: str, max_depth: int,
                    concurrency: int, headers: dict[str, str]) -> None:
    """Playwright-based JS-aware crawl."""
    cancel_event = _cancel_events.get(job.job_id)
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    queue.append((base_url, 0))

    parsed_base = urlparse(base_url)
    base_host = parsed_base.hostname or ""

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.error("[js-crawler] playwright not installed — falling back to standard crawl")
        job.error = "playwright not installed — run: pip install playwright && playwright install chromium"
        job.status = "error"
        _cancel_events.pop(job.job_id, None)
        return

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=headers,
            # Route through the proxy for passive scanning
            proxy={"server": "http://127.0.0.1:8080"} if True else None,
        )

        sem = asyncio.Semaphore(concurrency)

        async def fetch_page(url: str, depth: int) -> None:
            if cancel_event and cancel_event.is_set():
                return
            if url in visited or depth > max_depth:
                return

            parsed = urlparse(url)
            if parsed.hostname != base_host:
                return
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if normalized in visited:
                return

            visited.add(normalized)
            visited.add(url)

            async with sem:
                if cancel_event and cancel_event.is_set():
                    return
                page = await context.new_page()
                try:
                    # Navigate and wait for network idle
                    resp = await page.goto(url, wait_until="networkidle", timeout=30000)
                    if not resp:
                        return

                    status = resp.status
                    ct = resp.headers.get("content-type", "")

                    # Inject interception JS
                    await page.evaluate(_INTERCEPT_JS)

                    # Wait for any lazy-loaded content
                    await page.wait_for_timeout(1000)

                    # Scroll to trigger lazy loading
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await page.wait_for_timeout(500)

                    # Collect all discovered links and forms
                    data = await page.evaluate(_COLLECT_JS)
                    page_links = data.get("links", [])
                    page_forms = data.get("forms", [])

                    # Also get the rendered HTML for static extraction
                    html = await page.content()
                    static_links = _extract_links(str(page.url), html, ct)

                    # Iframe traversal — extract links from same-origin iframes
                    for frame in page.frames:
                        try:
                            frame_url = frame.url
                            if not frame_url or frame_url == "about:blank":
                                continue
                            frame_host = urlparse(frame_url).hostname or ""
                            if frame_host != base_host:
                                continue
                            frame_html = await frame.content()
                            iframe_links = _extract_links(frame_url, frame_html, "text/html")
                            static_links |= iframe_links
                            # Also add the iframe URL itself
                            static_links.add(frame_url)
                        except Exception:
                            pass  # Frame may have been detached

                    result = CrawlResult(
                        url=str(page.url),
                        method="GET",
                        status_code=status,
                        content_type=ct.split(";")[0].strip(),
                        length=len(html),
                        depth=depth,
                        forms=page_forms,
                        params=list(set(
                            p for form in page_forms for p in form.get("params", [])
                        )),
                    )

                    # Extract query params
                    qs = parse_qs(parsed.query)
                    if qs:
                        result.params = list(set(result.params + list(qs.keys())))

                    job.results.append(result)
                    job.urls_found += 1

                    # Queue discovered links
                    all_links = static_links | set(page_links)
                    for link in all_links:
                        lp = urlparse(link)
                        if lp.hostname == base_host and link not in visited:
                            queue.append((link, depth + 1))
                            job.urls_queued += 1

                except Exception as e:
                    log.debug(f"[js-crawler] Error on {url}: {e}")
                finally:
                    await page.close()

        # BFS crawl
        while queue:
            if cancel_event and cancel_event.is_set():
                break

            batch = []
            while queue and len(batch) < concurrency:
                url, depth = queue.popleft()
                if url not in visited and depth <= max_depth:
                    batch.append((url, depth))

            if not batch:
                break

            tasks = [asyncio.create_task(fetch_page(u, d)) for u, d in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        await browser.close()

    if cancel_event and cancel_event.is_set():
        job.status = "cancelled"
    else:
        job.status = "completed"

    _cancel_events.pop(job.job_id, None)
    log.info(f"[js-crawler] Job {job.job_id}: {job.status}, {job.urls_found} URLs discovered")


# ── Smart form values ────────────────────────────────────────────────────────

_SMART_VALUES: dict[str, str] = {
    "email": "test@example.com",
    "e-mail": "test@example.com",
    "mail": "test@example.com",
    "name": "Test User",
    "username": "testuser",
    "user": "testuser",
    "login": "testuser",
    "password": "TestPassword123!",
    "passwd": "TestPassword123!",
    "pass": "TestPassword123!",
    "phone": "+15551234567",
    "tel": "+15551234567",
    "address": "123 Test St",
    "city": "Test City",
    "state": "TS",
    "zip": "12345",
    "zipcode": "12345",
    "country": "US",
    "firstname": "Test",
    "first_name": "Test",
    "lastname": "User",
    "last_name": "User",
    "company": "Test Corp",
    "url": "https://example.com",
    "website": "https://example.com",
    "comment": "Test comment",
    "message": "Test message",
    "subject": "Test Subject",
    "search": "test",
    "query": "test",
    "q": "test",
    "age": "25",
    "date": "2025-01-01",
}


def _get_smart_value(field_name: str) -> str:
    """Get a smart default value for a form field based on its name."""
    name_lower = field_name.lower().strip()
    for key, value in _SMART_VALUES.items():
        if key in name_lower:
            return value
    return "test"


_CSRF_FIELD_NAMES = frozenset({
    "csrf", "_token", "csrf_token", "__requestverificationtoken",
    "_csrf", "authenticity_token", "csrfmiddlewaretoken",
    "csrf-token", "xsrf_token", "__csrf_token",
})


async def _submit_form(client: httpx.AsyncClient, form: dict, base_url: str) -> httpx.Response | None:
    """Submit a form with smart default values. CSRF-aware: fetches fresh token if needed."""
    action = form.get("action", base_url)
    method = form.get("method", "GET").upper()
    params = form.get("params", [])

    form_data = {}
    for param in params:
        form_data[param] = _get_smart_value(param)

    # CSRF-aware submission: detect if any param is a CSRF token field
    csrf_field = None
    for param in params:
        if param.lower() in _CSRF_FIELD_NAMES:
            csrf_field = param
            break
        # Partial match for variations
        param_lower = param.lower()
        if any(name in param_lower for name in ("csrf", "_token", "authenticity", "xsrf")):
            csrf_field = param
            break

    # If a CSRF field exists, fetch a fresh page to extract the current token value
    if csrf_field:
        try:
            # Fetch the form page to get a fresh CSRF token
            page_resp = await client.get(base_url)
            if page_resp.status_code == 200:
                page_body = page_resp.text
                # Try to find the CSRF token value from hidden inputs
                csrf_pattern = (
                    r'<input[^>]*name\s*=\s*["\']'
                    + re.escape(csrf_field)
                    + r'["\'][^>]*value\s*=\s*["\']([^"\']+)["\']'
                )
                csrf_match = re.search(csrf_pattern, page_body, re.IGNORECASE)
                if not csrf_match:
                    # Try reversed order (value before name)
                    csrf_pattern_rev = (
                        r'<input[^>]*value\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']'
                        + re.escape(csrf_field) + r'["\']'
                    )
                    csrf_match = re.search(csrf_pattern_rev, page_body, re.IGNORECASE)
                if csrf_match:
                    form_data[csrf_field] = csrf_match.group(1)
                    log.debug(f"[crawler] Extracted fresh CSRF token for field '{csrf_field}'")
                # Also check <meta> tags for CSRF tokens (Rails, Laravel pattern)
                else:
                    meta_pattern = r'<meta[^>]*name\s*=\s*["\']csrf-token["\'][^>]*content\s*=\s*["\']([^"\']+)["\']'
                    meta_match = re.search(meta_pattern, page_body, re.IGNORECASE)
                    if not meta_match:
                        meta_pattern_rev = r'<meta[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']csrf-token["\']'
                        meta_match = re.search(meta_pattern_rev, page_body, re.IGNORECASE)
                    if meta_match:
                        form_data[csrf_field] = meta_match.group(1)
                        log.debug(f"[crawler] Extracted CSRF token from <meta> tag for '{csrf_field}'")
        except Exception as e:
            log.debug(f"[crawler] CSRF token extraction error: {e}")

    try:
        if method == "POST":
            return await client.post(action, data=form_data)
        else:
            return await client.get(action, params=form_data)
    except Exception as e:
        log.debug(f"[crawler] Form submission error: {e}")
        return None


async def _detect_and_login(
    client: httpx.AsyncClient,
    body: str,
    base_url: str,
    login_credentials: dict[str, str],
) -> dict[str, str]:
    """Detect login forms and submit with provided credentials. Returns session cookies."""
    cookies: dict[str, str] = {}

    # Find forms with password fields
    form_re = re.compile(r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    for match in form_re.finditer(body):
        form_body = match.group(2)
        if 'type="password"' not in form_body and "type='password'" not in form_body:
            continue

        # Found a login form
        attrs = match.group(1)
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        method_match = re.search(r'method\s*=\s*["\'](\w+)["\']', attrs, re.IGNORECASE)

        action = urljoin(base_url, action_match.group(1) if action_match else "")
        method = method_match.group(1).upper() if method_match else "POST"

        # Extract input names
        input_re = re.compile(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\']([^>]*)>', re.IGNORECASE)
        form_data = {}
        for inp in input_re.finditer(form_body):
            name = inp.group(1)
            rest = inp.group(2)
            # Assign credentials based on field type
            if "password" in rest.lower() or "password" in name.lower():
                form_data[name] = login_credentials.get("password", "")
            elif name.lower() in ("username", "user", "login", "email", "name"):
                form_data[name] = login_credentials.get("username", "")
            else:
                # Check for hidden fields with default values
                val_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', rest)
                if val_match:
                    form_data[name] = val_match.group(1)

        if not form_data:
            continue

        try:
            log.info(f"[crawler] Submitting login form: {action}")
            resp = await client.request(method, action, data=form_data)
            # Extract session cookies
            for cookie_header in resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []:
                if "=" in cookie_header:
                    cn, _, cv = cookie_header.partition("=")
                    cookies[cn.strip()] = cv.split(";")[0].strip()
            break
        except Exception as e:
            log.debug(f"[crawler] Login submission error: {e}")

    return cookies


# ── Public API ──────────────────────────────────────────────────────────────

async def start_crawl(
    url: str,
    max_depth: int = 3,
    concurrency: int = 5,
    headers: dict[str, str] | None = None,
    js_render: bool = False,
    submit_forms: bool = False,
    login_url: str | None = None,
    login_credentials: dict[str, str] | None = None,
) -> CrawlJob:
    """Start a crawl job. Set js_render=True for Playwright-based JS-aware crawling.
    Set submit_forms=True to auto-submit forms with smart default values.
    Provide login_url + login_credentials for login-aware crawling."""
    job_id = str(uuid.uuid4())[:8]
    job = CrawlJob(job_id=job_id, base_url=url)
    state.crawl_jobs[job_id] = job

    cancel_event = asyncio.Event()
    _cancel_events[job_id] = cancel_event

    hdrs = dict(headers or {})

    # Login-aware crawling: login first, capture session cookies
    if login_url and login_credentials:
        try:
            async with httpx.AsyncClient(verify=False, timeout=15.0, headers=hdrs) as login_client:
                resp = await login_client.get(login_url)
                session_cookies = await _detect_and_login(login_client, resp.text, login_url, login_credentials)
                if session_cookies:
                    cookie_str = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
                    hdrs["Cookie"] = cookie_str
                    log.info(f"[crawler] Login successful, {len(session_cookies)} session cookies captured")
        except Exception as e:
            log.warning(f"[crawler] Login failed: {e}")

    if js_render:
        log.info(f"[js-crawler] Starting JS-aware crawl {job_id}: {url} (depth={max_depth})")
        asyncio.create_task(_js_crawl(job, url, max_depth, concurrency, hdrs))
    else:
        log.info(f"[crawler] Starting crawl {job_id}: {url} (depth={max_depth}, submit_forms={submit_forms})")
        asyncio.create_task(_crawl(job, url, max_depth, concurrency, hdrs, False, submit_forms))
    return job


async def crawl_auth_diff(
    url: str,
    auth_headers: dict[str, str],
    max_depth: int = 3,
    concurrency: int = 5,
) -> dict:
    """Crawl with and without auth, return endpoints only available when authenticated.

    Returns a dict with:
      - auth_only: URLs found only with auth headers
      - unauth_only: URLs found only without auth headers
      - both: URLs found in both crawls
      - auth_total: total URLs with auth
      - unauth_total: total URLs without auth
    """
    # Crawl without auth
    unauth_job = await start_crawl(
        url=url,
        max_depth=max_depth,
        concurrency=concurrency,
        headers={},
    )
    # Wait for completion
    while unauth_job.status == "running":
        await asyncio.sleep(0.5)

    # Crawl with auth
    auth_job = await start_crawl(
        url=url,
        max_depth=max_depth,
        concurrency=concurrency,
        headers=auth_headers,
    )
    # Wait for completion
    while auth_job.status == "running":
        await asyncio.sleep(0.5)

    # Compare results
    unauth_urls = set()
    auth_urls = set()

    for result in unauth_job.results:
        parsed = urlparse(result.url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        unauth_urls.add(normalized)

    for result in auth_job.results:
        parsed = urlparse(result.url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        auth_urls.add(normalized)

    auth_only = auth_urls - unauth_urls
    unauth_only = unauth_urls - auth_urls
    both = auth_urls & unauth_urls

    # Build detailed result with status codes for auth-only endpoints
    auth_only_details = []
    for result in auth_job.results:
        parsed = urlparse(result.url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized in auth_only:
            auth_only_details.append({
                "url": result.url,
                "method": result.method,
                "status_code": result.status_code,
                "content_type": result.content_type,
                "params": result.params,
            })

    return {
        "auth_only": sorted(auth_only),
        "auth_only_details": auth_only_details,
        "unauth_only": sorted(unauth_only),
        "both": sorted(both),
        "auth_total": len(auth_urls),
        "unauth_total": len(unauth_urls),
    }


def cancel_crawl(job_id: str) -> bool:
    if job_id not in state.crawl_jobs:
        return False
    event = _cancel_events.get(job_id)
    if event:
        event.set()
    state.crawl_jobs[job_id].status = "cancelled"
    return True
