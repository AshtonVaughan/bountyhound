"""HTTP Logger — centralized traffic logger for all proxy engine components."""

from __future__ import annotations

import time
import uuid


class HTTPLogger:
    """Log HTTP requests and responses from repeater, intruder, scanner."""

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self.enabled: bool = False
        self._max_entries: int = 10_000

    def log_request(
        self,
        method: str,
        url: str,
        headers: dict,
        body: str | None,
        source: str,
    ) -> str:
        """Log an outgoing request. Returns entry ID."""
        if not self.enabled:
            return ""

        entry_id = uuid.uuid4().hex[:8]
        self._entries.append({
            "id": entry_id,
            "method": method,
            "url": url,
            "request_headers": dict(headers),
            "request_body": (body or "")[:5000],
            "source": source,
            "timestamp": time.time(),
            "status_code": None,
            "response_headers": {},
            "response_body": "",
            "duration_ms": 0,
        })

        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries // 2:]

        return entry_id

    def log_response(
        self,
        entry_id: str,
        status: int,
        headers: dict,
        body: str | None,
        duration_ms: float,
    ) -> None:
        """Log the response for a previously logged request."""
        if not self.enabled or not entry_id:
            return

        for entry in reversed(self._entries):
            if entry["id"] == entry_id:
                entry["status_code"] = status
                entry["response_headers"] = dict(headers)
                entry["response_body"] = (body or "")[:5000]
                entry["duration_ms"] = round(duration_ms, 2)
                break

    def get_entries(
        self,
        source: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get log entries, optionally filtered by source."""
        entries = self._entries
        if source:
            entries = [e for e in entries if e["source"] == source]
        return list(reversed(entries[:limit]))

    def clear(self) -> int:
        """Clear all log entries."""
        count = len(self._entries)
        self._entries.clear()
        return count

    def toggle(self, enabled: bool) -> bool:
        """Enable or disable logging."""
        self.enabled = enabled
        return self.enabled


# Singleton
logger = HTTPLogger()
