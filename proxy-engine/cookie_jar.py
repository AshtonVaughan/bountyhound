"""Cookie Jar — global automatic cookie management across all tools.

Tracks Set-Cookie headers from responses, provides cookies for requests,
and integrates with repeater, intruder, and scanner.
"""

from __future__ import annotations

import logging
import time
from http.cookiejar import CookieJar as StdCookieJar
from urllib.parse import urlparse

log = logging.getLogger("proxy-engine.cookie_jar")


class CookieEntry:
    __slots__ = ("name", "value", "domain", "path", "secure", "httponly", "expires", "samesite")

    def __init__(
        self, name: str, value: str, domain: str = "",
        path: str = "/", secure: bool = False, httponly: bool = False,
        expires: float = 0.0, samesite: str = "",
    ):
        self.name = name
        self.value = value
        self.domain = domain.lower().lstrip(".")
        self.path = path
        self.secure = secure
        self.httponly = httponly
        self.expires = expires
        self.samesite = samesite

    def is_expired(self) -> bool:
        if self.expires <= 0:
            return False  # session cookie
        return self.expires < time.time()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "httponly": self.httponly,
            "expires": self.expires,
            "samesite": self.samesite,
        }


class CookieJar:
    """Global cookie jar with domain + path matching."""

    def __init__(self) -> None:
        self._cookies: list[CookieEntry] = []

    def update_from_response(self, url: str, headers: dict[str, str]) -> None:
        """Extract Set-Cookie headers from a response and store.

        Handles both single and multiple Set-Cookie headers, including
        comma-separated values (RFC 6265 allows multiple cookies per header).
        """
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue
            # Handle potential comma-separated cookies (but not within expires date)
            # Simple heuristic: split on comma only if next segment has '='
            parts = [value]
            if "," in value:
                # Check if comma is in expires value (e.g., "Thu, 01 Dec 2025")
                # If so, don't split there
                import re
                # Split on commas not within date-like patterns
                segments = re.split(r",\s*(?=[A-Za-z_][A-Za-z0-9_]*=)", value)
                if len(segments) > 1:
                    parts = segments
            for part in parts:
                self._parse_set_cookie(part.strip(), domain, parsed.path or "/")

    def _parse_set_cookie(self, header: str, default_domain: str, default_path: str) -> None:
        """Parse a single Set-Cookie header value."""
        parts = header.split(";")
        if not parts:
            return

        # First part: name=value
        name_val = parts[0].strip()
        if "=" not in name_val:
            return
        name, _, value = name_val.partition("=")
        name = name.strip()
        value = value.strip()

        entry = CookieEntry(name=name, value=value, domain=default_domain, path=default_path)

        for attr in parts[1:]:
            attr = attr.strip()
            if "=" in attr:
                aname, _, aval = attr.partition("=")
                aname = aname.strip().lower()
                aval = aval.strip()
                if aname == "domain":
                    entry.domain = aval.lower().lstrip(".")
                elif aname == "path":
                    entry.path = aval
                elif aname == "max-age":
                    try:
                        entry.expires = time.time() + int(aval)
                    except ValueError:
                        pass
                elif aname == "expires":
                    try:
                        from email.utils import parsedate_to_datetime
                        dt = parsedate_to_datetime(aval)
                        entry.expires = dt.timestamp()
                    except Exception:
                        pass
                elif aname == "samesite":
                    entry.samesite = aval.lower()
            else:
                al = attr.lower()
                if al == "secure":
                    entry.secure = True
                elif al == "httponly":
                    entry.httponly = True

        # Remove existing cookie with same name+domain+path
        self._cookies = [
            c for c in self._cookies
            if not (c.name == entry.name and c.domain == entry.domain and c.path == entry.path)
        ]
        self._cookies.append(entry)

        # Cap cookies at 10,000 (evict oldest)
        if len(self._cookies) > 10_000:
            self._cookies = self._cookies[-5_000:]

    def get_cookies_for(self, url: str) -> list[CookieEntry]:
        """Get all cookies matching a URL (domain + path matching)."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        scheme = parsed.scheme or "http"

        result: list[CookieEntry] = []
        for c in self._cookies:
            if c.is_expired():
                continue
            # Domain match: exact or subdomain
            if not (host == c.domain or host.endswith("." + c.domain)):
                continue
            # Path match
            if not path.startswith(c.path):
                continue
            # Secure flag
            if c.secure and scheme != "https":
                continue
            result.append(c)

        return result

    def inject_cookies(self, url: str, headers: dict[str, str]) -> dict[str, str]:
        """Merge jar cookies into a request's Cookie header."""
        cookies = self.get_cookies_for(url)
        if not cookies:
            return headers

        # Build cookie string
        jar_pairs = [f"{c.name}={c.value}" for c in cookies]

        # Merge with existing Cookie header
        existing = ""
        for k in list(headers.keys()):
            if k.lower() == "cookie":
                existing = headers[k]
                break

        if existing:
            existing_names = set()
            for pair in existing.split(";"):
                if "=" in pair:
                    n = pair.split("=", 1)[0].strip()
                    existing_names.add(n)
            # Only add cookies not already in the request
            new_pairs = [p for c, p in zip(cookies, jar_pairs) if c.name not in existing_names]
            if new_pairs:
                combined = existing.rstrip("; ") + "; " + "; ".join(new_pairs)
                headers = dict(headers)
                for k in list(headers.keys()):
                    if k.lower() == "cookie":
                        headers[k] = combined
                        break
        else:
            headers = dict(headers)
            headers["Cookie"] = "; ".join(jar_pairs)

        return headers

    def get_all(self) -> list[dict]:
        """Get all cookies as dicts."""
        return [c.to_dict() for c in self._cookies if not c.is_expired()]

    def set_cookie(
        self, name: str, value: str, domain: str, path: str = "/",
        secure: bool = False, httponly: bool = False, expires: float | None = None,
    ) -> None:
        """Manually set a cookie."""
        self._cookies = [
            c for c in self._cookies
            if not (c.name == name and c.domain == domain.lower() and c.path == path)
        ]
        self._cookies.append(CookieEntry(
            name=name, value=value, domain=domain.lower(), path=path,
            secure=secure, httponly=httponly, expires=expires or 0.0,
        ))

    def clear(self, domain: str | None = None) -> int:
        """Clear cookies, optionally for a specific domain."""
        if domain:
            before = len(self._cookies)
            self._cookies = [c for c in self._cookies if c.domain != domain.lower()]
            return before - len(self._cookies)
        count = len(self._cookies)
        self._cookies.clear()
        return count

    def remove(self, name: str, domain: str = "") -> bool:
        """Remove a specific cookie."""
        before = len(self._cookies)
        if domain:
            self._cookies = [c for c in self._cookies if not (c.name == name and c.domain == domain.lower())]
        else:
            self._cookies = [c for c in self._cookies if c.name != name]
        return len(self._cookies) < before


# Global singleton
jar = CookieJar()
