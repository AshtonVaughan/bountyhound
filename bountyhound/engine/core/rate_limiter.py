"""Per-domain rate limiter with WAF detection and exponential backoff.

Thread-safe request throttling for the auto-dispatch system.
"""

import threading
import time
from collections import defaultdict
from typing import Dict, Optional


class WAFDetector:
    """Detect WAF block pages and rate-limit responses."""

    @staticmethod
    def detect(status_code: int, headers: dict, body: str = '') -> Optional[str]:
        """Return the WAF name if a block is detected, else None."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Explicit rate limit
        if status_code == 429:
            return 'rate-limit'

        # Cloudflare
        if 'cf-ray' in headers_lower and status_code in (403, 503):
            return 'cloudflare'
        if 'attention required' in body.lower() or 'cloudflare' in body.lower()[:2000]:
            if status_code in (403, 503):
                return 'cloudflare'

        # AWS WAF
        if 'x-amzn-waf-action' in headers_lower:
            return 'aws-waf'
        if status_code == 403 and 'awselb' in headers_lower.get('server', '').lower():
            return 'aws-waf'

        # Akamai
        if 'akamai-grn' in headers_lower:
            return 'akamai'
        if 'akamai' in headers_lower.get('server', '').lower() and status_code == 403:
            return 'akamai'

        # Imperva / Incapsula
        cookie = headers_lower.get('set-cookie', '')
        if 'incap_ses' in cookie or 'visid_incap' in cookie:
            return 'imperva'
        if status_code == 403 and 'incapsula' in body.lower()[:2000]:
            return 'imperva'

        # Generic service unavailable
        if status_code == 503:
            return 'service-unavailable'

        return None


class _DomainState:
    """Internal tracking state for a single domain."""

    __slots__ = (
        'rps', 'min_interval', 'last_request', 'backoff_until',
        'backoff_count', 'total_requests', 'total_blocks', 'last_waf',
    )

    def __init__(self, rps: float):
        self.rps = rps
        self.min_interval = 1.0 / rps
        self.last_request = 0.0
        self.backoff_until = 0.0
        self.backoff_count = 0
        self.total_requests = 0
        self.total_blocks = 0
        self.last_waf: Optional[str] = None


class RateLimiter:
    """Thread-safe per-domain rate limiter with WAF-aware backoff.

    Usage:
        limiter = RateLimiter(default_rps=5.0)
        limiter.acquire('example.com')       # blocks until allowed
        resp = requests.get(url)
        limiter.report_response('example.com', resp.status_code,
                                dict(resp.headers), resp.text)
    """

    def __init__(self, default_rps: float = 5.0, max_backoff: float = 120.0):
        self._default_rps = default_rps
        self._max_backoff = max_backoff
        self._domains: Dict[str, _DomainState] = {}
        self._lock = threading.Lock()

    # -- internal helpers --------------------------------------------------

    def _get_state(self, domain: str) -> _DomainState:
        """Return or create domain state. Caller MUST hold self._lock."""
        if domain not in self._domains:
            self._domains[domain] = _DomainState(self._default_rps)
        return self._domains[domain]

    # -- public API --------------------------------------------------------

    def acquire(self, domain: str) -> None:
        """Block the calling thread until a request is permitted."""
        while True:
            with self._lock:
                now = time.monotonic()
                state = self._get_state(domain)

                # If in backoff, calculate remaining wait
                if now < state.backoff_until:
                    wait = state.backoff_until - now
                else:
                    # Normal rate-limit spacing
                    elapsed = now - state.last_request
                    if elapsed >= state.min_interval:
                        state.last_request = now
                        state.total_requests += 1
                        return
                    wait = state.min_interval - elapsed

            # Sleep outside the lock so other domains aren't blocked
            time.sleep(wait)

    def report_response(
        self, domain: str, status_code: int, headers: dict, body: str = ''
    ) -> None:
        """Analyze a response and trigger backoff if WAF/rate-limit detected."""
        waf = WAFDetector.detect(status_code, headers, body)
        if waf is None:
            # Successful request -- reset backoff counter
            with self._lock:
                state = self._get_state(domain)
                state.backoff_count = 0
                state.last_waf = None
            return

        with self._lock:
            state = self._get_state(domain)
            state.total_blocks += 1
            state.last_waf = waf
            state.backoff_count += 1

            # Honour Retry-After header if present
            retry_after = None
            for k, v in headers.items():
                if k.lower() == 'retry-after':
                    try:
                        retry_after = float(v)
                    except ValueError:
                        pass
                    break

            if retry_after is not None:
                delay = min(retry_after, self._max_backoff)
            else:
                delay = min(2 ** state.backoff_count, self._max_backoff)

            state.backoff_until = time.monotonic() + delay

    def is_blocked(self, domain: str) -> bool:
        """Return True if the domain is currently in a backoff window."""
        with self._lock:
            state = self._get_state(domain)
            return time.monotonic() < state.backoff_until

    def set_rps(self, domain: str, rps: float) -> None:
        """Override the requests-per-second limit for a specific domain."""
        if rps <= 0:
            raise ValueError('rps must be positive')
        with self._lock:
            state = self._get_state(domain)
            state.rps = rps
            state.min_interval = 1.0 / rps

    def get_stats(self, domain: str) -> dict:
        """Return rate-limit statistics for a domain."""
        with self._lock:
            state = self._get_state(domain)
            now = time.monotonic()
            return {
                'domain': domain,
                'rps': state.rps,
                'total_requests': state.total_requests,
                'total_blocks': state.total_blocks,
                'in_backoff': now < state.backoff_until,
                'backoff_remaining': max(0.0, state.backoff_until - now),
                'backoff_count': state.backoff_count,
                'last_waf': state.last_waf,
            }
