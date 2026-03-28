"""Content Discovery — directory brute-force / forced browsing."""

from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

import httpx

from models import DiscoveryJob, DiscoveryResult
from state import state

log = logging.getLogger("proxy-engine.discovery")

_cancel_events: dict[str, asyncio.Event] = {}

# Built-in wordlists
WORDLISTS_DIR = Path(__file__).parent / "wordlists"

BUILTIN_WORDS = {
    "common": [
        "admin", "login", "dashboard", "api", "wp-admin", "wp-login.php",
        "robots.txt", "sitemap.xml", ".env", ".git", ".git/config",
        "config", "backup", "test", "dev", "staging", "old", "new",
        "uploads", "images", "static", "assets", "css", "js", "fonts",
        "swagger", "swagger-ui", "api-docs", "graphql", "graphiql",
        "phpmyadmin", "adminer", "debug", "trace", "server-status",
        "server-info", "info.php", "phpinfo.php", "health", "healthcheck",
        "status", "metrics", "prometheus", "actuator", "console",
        ".htaccess", ".htpasswd", "web.config", "crossdomain.xml",
        "clientaccesspolicy.xml", "security.txt", ".well-known/security.txt",
        "wp-content", "wp-includes", "xmlrpc.php", "readme.html",
        "license.txt", "changelog.txt", "CHANGELOG.md", "README.md",
        "package.json", "composer.json", "Gemfile", "requirements.txt",
        "Dockerfile", "docker-compose.yml", ".dockerignore", "Makefile",
        ".aws/credentials", "id_rsa", "id_rsa.pub", ".ssh/authorized_keys",
        "error", "errors", "log", "logs", "tmp", "temp", "cache",
        "download", "file", "files", "documents", "doc", "docs",
        "internal", "private", "secret", "hidden", "portal",
        "user", "users", "account", "accounts", "profile", "register",
        "signup", "signin", "logout", "forgot", "reset", "verify",
        "v1", "v2", "v3", "api/v1", "api/v2", "api/v3",
    ],
    "api_endpoints": [
        "api/users", "api/admin", "api/login", "api/register",
        "api/token", "api/auth", "api/config", "api/settings",
        "api/upload", "api/download", "api/search", "api/export",
        "api/import", "api/webhook", "api/callback", "api/health",
        "api/debug", "api/internal", "api/graphql", "api/swagger.json",
        "api/openapi.json", "api/docs", "api/schema",
        "rest/api/latest", "api/v1/users", "api/v1/admin",
    ],
    "backup_files": [
        "backup.sql", "backup.zip", "backup.tar.gz", "db.sql",
        "database.sql", "dump.sql", "data.sql", "site.zip",
        "www.zip", "public.zip", "html.zip", "web.zip",
        "backup.bak", "index.bak", "config.bak", "web.config.bak",
        ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ],
    "extensions": [
        ".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
        ".json", ".xml", ".txt", ".cfg", ".conf", ".ini",
        ".yml", ".yaml", ".toml", ".log", ".bak", ".old",
        ".sql", ".db", ".sqlite",
    ],
    "common_params": [
        "id", "page", "q", "search", "query", "name", "email", "user", "username",
        "password", "token", "key", "api_key", "callback", "redirect", "url", "next",
        "return", "file", "path", "dir", "action", "type", "category", "sort",
        "order", "limit", "offset", "format", "lang", "locale", "debug", "test",
        "admin", "role", "status", "filter", "from", "to", "date",
    ],
}


def _load_wordlist(name: str) -> list[str]:
    """Load a wordlist by name (builtin or file path)."""
    if name.startswith("@") and name[1:] in BUILTIN_WORDS:
        return BUILTIN_WORDS[name[1:]]

    # Try as file path
    path = Path(name)
    if not path.is_absolute():
        path = WORDLISTS_DIR / name
    if path.exists():
        return [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]

    return []


async def _run_discovery(
    job: DiscoveryJob,
    base_url: str,
    words: list[str],
    extensions: list[str],
    concurrency: int,
    headers: dict[str, str],
    status_filter: list[int],
    method: str,
) -> None:
    """Run directory brute-force."""
    cancel_event = _cancel_events.get(job.job_id)
    sem = asyncio.Semaphore(concurrency)

    # Build full URL list
    base = base_url.rstrip("/")
    targets = []
    for word in words:
        targets.append(f"{base}/{word}")
        for ext in extensions:
            targets.append(f"{base}/{word}{ext}")

    job.total = len(targets)

    async with httpx.AsyncClient(
        verify=False, timeout=10.0,
        headers=headers,
        follow_redirects=False,
    ) as client:

        async def check(url: str) -> None:
            if cancel_event and cancel_event.is_set():
                return
            async with sem:
                if cancel_event and cancel_event.is_set():
                    return
                try:
                    resp = await client.request(method, url)
                    job.checked += 1

                    if status_filter and resp.status_code not in status_filter:
                        # Still count common "not found" equivalents
                        if resp.status_code not in (404, 403, 400, 500, 502, 503):
                            job.results.append(DiscoveryResult(
                                url=url,
                                status_code=resp.status_code,
                                length=len(resp.content),
                                content_type=resp.headers.get("content-type", "").split(";")[0],
                                redirect=resp.headers.get("location", ""),
                            ))
                    elif resp.status_code not in (404,):
                        job.results.append(DiscoveryResult(
                            url=url,
                            status_code=resp.status_code,
                            length=len(resp.content),
                            content_type=resp.headers.get("content-type", "").split(";")[0],
                            redirect=resp.headers.get("location", ""),
                        ))

                except Exception:
                    job.checked += 1

        # Run in batches
        for i in range(0, len(targets), concurrency * 3):
            if cancel_event and cancel_event.is_set():
                break
            batch = targets[i:i + concurrency * 3]
            tasks = [asyncio.create_task(check(url)) for url in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

    if cancel_event and cancel_event.is_set():
        job.status = "cancelled"
    else:
        job.status = "completed"

    _cancel_events.pop(job.job_id, None)
    log.info(f"[discovery] Job {job.job_id}: {job.status}, {len(job.results)} found / {job.checked} checked")


async def start_discovery(
    url: str,
    wordlist: str = "@common",
    extensions: list[str] | None = None,
    concurrency: int = 20,
    headers: dict[str, str] | None = None,
    status_filter: list[int] | None = None,
    method: str = "GET",
    recursive: bool = False,
    max_depth: int = 3,
) -> DiscoveryJob:
    """Start a content discovery job."""
    job_id = str(uuid.uuid4())[:8]
    job = DiscoveryJob(job_id=job_id, base_url=url)
    state.discovery_jobs[job_id] = job

    words = _load_wordlist(wordlist)
    if not words:
        job.status = "error"
        job.error = f"Wordlist '{wordlist}' not found or empty"
        return job

    cancel_event = asyncio.Event()
    _cancel_events[job_id] = cancel_event

    # Smart wordlist: merge discovered paths from existing flows
    if recursive:
        smart_words = _generate_smart_wordlist(url)
        words = list(set(words + smart_words))

    exts = extensions or []
    log.info(f"[discovery] Starting {job_id}: {url} ({len(words)} words, {len(exts)} extensions)")
    asyncio.create_task(_run_discovery(
        job, url, words, exts, concurrency,
        headers or {}, status_filter or [], method,
    ))
    return job


def cancel_discovery(job_id: str) -> bool:
    if job_id not in state.discovery_jobs:
        return False
    event = _cancel_events.get(job_id)
    if event:
        event.set()
    state.discovery_jobs[job_id].status = "cancelled"
    return True


# ── Smart wordlist generation (Phase 8B) ─────────────────────────────────────

def _generate_smart_wordlist(base_url: str) -> list[str]:
    """Generate wordlist from existing flow data for the same host."""
    from urllib.parse import urlparse
    host = urlparse(base_url).hostname

    words = set()
    for flow in state.flows.values():
        if flow.host != host:
            continue
        parsed = urlparse(flow.request.url)
        parts = [p for p in parsed.path.split("/") if p and len(p) < 50]
        words.update(parts)

    # Add permutations with common suffixes
    suffixes = ["_backup", "_old", "_test", "_dev", "_staging", "_bak", "_new", ".bak", ".old"]
    expanded = set(words)
    for word in list(words)[:50]:
        for suffix in suffixes:
            expanded.add(word + suffix)

    return sorted(expanded)


# ── Response fingerprinting (Phase 8C) ───────────────────────────────────────

class _ResponseFingerprinter:
    """Fingerprint 404 responses to filter false positives."""

    def __init__(self):
        self._baseline_hashes: set[str] = set()
        self._baseline_lengths: list[int] = []

    async def calibrate(self, client, base_url: str) -> None:
        """Send random paths and fingerprint 404 responses."""
        import hashlib
        import uuid as _uuid

        base = base_url.rstrip("/")
        for _ in range(3):
            random_path = _uuid.uuid4().hex[:12]
            try:
                resp = await client.get(f"{base}/{random_path}")
                body_hash = hashlib.md5(resp.content).hexdigest()
                self._baseline_hashes.add(body_hash)
                self._baseline_lengths.append(len(resp.content))
            except Exception:
                pass

    def is_false_positive(self, response) -> bool:
        """Check if a response matches 404 baseline."""
        import hashlib
        body_hash = hashlib.md5(response.content).hexdigest()
        if body_hash in self._baseline_hashes:
            return True
        if self._baseline_lengths:
            avg_len = sum(self._baseline_lengths) / len(self._baseline_lengths)
            if abs(len(response.content) - avg_len) < 10:
                return True
        return False


# ── Parameter discovery (Phase 8D) ───────────────────────────────────────────

async def discover_parameters(
    url: str,
    wordlist: str = "@common_params",
    method: str = "GET",
    concurrency: int = 20,
    headers: dict[str, str] | None = None,
) -> DiscoveryJob:
    """Fuzz for valid GET/POST parameters by detecting response differences."""
    job_id = str(uuid.uuid4())[:8]
    job = DiscoveryJob(job_id=job_id, base_url=url)
    state.discovery_jobs[job_id] = job

    params = _load_wordlist(wordlist)
    if not params:
        params = BUILTIN_WORDS.get("common_params", [])

    cancel_event = asyncio.Event()
    _cancel_events[job_id] = cancel_event

    asyncio.create_task(_run_param_discovery(job, url, params, method, concurrency, headers or {}, cancel_event))
    return job


async def _run_param_discovery(
    job: DiscoveryJob,
    url: str,
    params: list[str],
    method: str,
    concurrency: int,
    headers: dict[str, str],
    cancel_event: asyncio.Event,
) -> None:
    """Run parameter discovery."""
    sem = asyncio.Semaphore(concurrency)
    job.total = len(params)

    async with httpx.AsyncClient(verify=False, timeout=10.0, headers=headers) as client:
        # Get baseline
        try:
            if method.upper() == "GET":
                baseline = await client.get(url)
            else:
                baseline = await client.post(url)
            baseline_length = len(baseline.content)
            baseline_status = baseline.status_code
        except Exception:
            job.status = "error"
            job.error = "Failed to get baseline response"
            return

        async def check_param(param: str) -> None:
            if cancel_event.is_set():
                return
            async with sem:
                if cancel_event.is_set():
                    return
                try:
                    if method.upper() == "GET":
                        sep = "&" if "?" in url else "?"
                        test_url = f"{url}{sep}{param}=test123"
                        resp = await client.get(test_url)
                    else:
                        resp = await client.post(url, data={param: "test123"})

                    job.checked += 1
                    resp_length = len(resp.content)

                    # Detect valid parameter by response difference
                    length_diff = abs(resp_length - baseline_length)
                    if (resp.status_code != baseline_status or
                        length_diff > max(50, baseline_length * 0.1)):
                        job.results.append(DiscoveryResult(
                            url=f"{url}?{param}=test123" if method.upper() == "GET" else url,
                            status_code=resp.status_code,
                            length=resp_length,
                            content_type=resp.headers.get("content-type", "").split(";")[0],
                        ))
                except Exception:
                    job.checked += 1

        tasks = [asyncio.create_task(check_param(p)) for p in params]
        await asyncio.gather(*tasks, return_exceptions=True)

    job.status = "cancelled" if cancel_event.is_set() else "completed"
    _cancel_events.pop(job.job_id, None)
