"""
BountyHound Request Logger

Auto-logs every HTTP request and response to both the SQLite database
and individual files on disk. Ensures no request data is ever lost
between sessions.

Usage:
    from engine.core.request_logger import RequestLogger

    logger = RequestLogger()
    logger.log_request(
        target="example.com",
        method="POST",
        url="https://example.com/api/graphql",
        req_headers={"Authorization": "Bearer ..."},
        req_body='{"query": "{ me { id } }"}',
        status_code=200,
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"data": {"me": {"id": "123"}}}',
        duration_ms=342,
        phase="testing",
        agent="api-tester",
        tags=["graphql", "auth"]
    )
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from engine.core.config import BountyHoundConfig
from engine.core.database import BountyHoundDB


class RequestLogger:
    """Logs HTTP requests/responses to database and disk for persistence."""

    # Response bodies larger than this threshold are saved to individual files
    BODY_FILE_THRESHOLD = 1024  # 1 KB

    def __init__(self, db: Optional[BountyHoundDB] = None):
        """
        Initialize the request logger.

        Args:
            db: Optional BountyHoundDB instance. If not provided,
                uses the singleton via get_instance().
        """
        self._db = db or BountyHoundDB.get_instance(BountyHoundConfig.DB_PATH)

    def log_request(
        self,
        target: str,
        method: str,
        url: str,
        req_headers: Optional[Union[Dict, str]] = None,
        req_body: Optional[str] = None,
        status_code: Optional[int] = None,
        resp_headers: Optional[Union[Dict, str]] = None,
        resp_body: Optional[str] = None,
        duration_ms: Optional[int] = None,
        phase: Optional[str] = None,
        agent: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> int:
        """
        Log an HTTP request/response pair to database and optionally to disk.

        Args:
            target: Target domain (e.g. "example.com").
            method: HTTP method (GET, POST, etc.).
            url: Full request URL.
            req_headers: Request headers as dict or JSON string.
            req_body: Request body text.
            status_code: HTTP response status code.
            resp_headers: Response headers as dict or JSON string.
            resp_body: Response body text.
            duration_ms: Round-trip time in milliseconds.
            phase: Hunt phase (recon, testing, exploit, etc.).
            agent: Agent name that made the request.
            tags: List of string tags for categorization.

        Returns:
            The row ID of the inserted request_log record.
        """
        now = datetime.utcnow()

        # Serialize headers/tags to JSON strings if they are dicts/lists
        req_headers_str = self._serialize(req_headers)
        resp_headers_str = self._serialize(resp_headers)
        tags_str = json.dumps(tags) if tags else None

        # Determine response size
        resp_size = len(resp_body.encode("utf-8", errors="replace")) if resp_body else 0

        # Save large response bodies to disk
        resp_body_file = None
        if resp_body and resp_size > self.BODY_FILE_THRESHOLD:
            resp_body_file = self._save_response_body(
                target, url, resp_body, now
            )

        # Insert into database
        with self._db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO request_log
                    (target, method, url, request_headers, request_body,
                     status_code, response_headers, response_body_file,
                     response_size, duration_ms, timestamp, phase, agent, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target,
                    method,
                    url,
                    req_headers_str,
                    req_body,
                    status_code,
                    resp_headers_str,
                    resp_body_file,
                    resp_size,
                    duration_ms,
                    now.strftime("%Y-%m-%d %H:%M:%S"),
                    phase,
                    agent,
                    tags_str,
                ),
            )
            return cursor.lastrowid

    def get_requests(
        self, target: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get recent requests for a target, ordered by newest first.

        Args:
            target: Target domain.
            limit: Maximum number of records to return (default 50).

        Returns:
            List of request_log rows as dicts.
        """
        with self._db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, target, method, url, request_headers, request_body,
                       status_code, response_headers, response_body_file,
                       response_size, duration_ms, timestamp, phase, agent, tags
                FROM request_log
                WHERE target = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (target, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_requests_by_url(
        self, target: str, url_pattern: str
    ) -> List[Dict[str, Any]]:
        """
        Search requests by URL pattern using SQL LIKE.

        Args:
            target: Target domain.
            url_pattern: SQL LIKE pattern (e.g. '%/api/graphql%').

        Returns:
            List of matching request_log rows as dicts.
        """
        with self._db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, target, method, url, request_headers, request_body,
                       status_code, response_headers, response_body_file,
                       response_size, duration_ms, timestamp, phase, agent, tags
                FROM request_log
                WHERE target = ? AND url LIKE ?
                ORDER BY timestamp DESC
                """,
                (target, url_pattern),
            )
            return [dict(row) for row in cursor.fetchall()]

    def export_har(self, target: str) -> Dict[str, Any]:
        """
        Export all requests for a target as a simplified HAR-like JSON structure.

        The structure follows a simplified version of the HAR 1.2 spec:
        {
            "log": {
                "version": "1.2",
                "creator": {"name": "BountyHound", "version": "3.0"},
                "entries": [
                    {
                        "startedDateTime": "...",
                        "time": <duration_ms>,
                        "request": {
                            "method": "POST",
                            "url": "https://...",
                            "headers": [...],
                            "postData": {"text": "..."}
                        },
                        "response": {
                            "status": 200,
                            "headers": [...],
                            "content": {
                                "size": <bytes>,
                                "text": "..." or null,
                                "bodyFile": "..." or null
                            }
                        },
                        "_meta": {
                            "phase": "...",
                            "agent": "...",
                            "tags": [...]
                        }
                    }
                ]
            }
        }

        Args:
            target: Target domain.

        Returns:
            HAR-like dict structure, JSON-serializable.
        """
        with self._db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, target, method, url, request_headers, request_body,
                       status_code, response_headers, response_body_file,
                       response_size, duration_ms, timestamp, phase, agent, tags
                FROM request_log
                WHERE target = ?
                ORDER BY timestamp ASC
                """,
                (target,),
            )
            rows = [dict(row) for row in cursor.fetchall()]

        entries = []
        for row in rows:
            # Parse stored JSON strings back into structures
            req_headers = self._parse_json_safe(row.get("request_headers"))
            resp_headers = self._parse_json_safe(row.get("response_headers"))
            tags = self._parse_json_safe(row.get("tags"))

            # Convert headers dict to HAR-style list of {name, value}
            req_header_list = self._headers_to_list(req_headers)
            resp_header_list = self._headers_to_list(resp_headers)

            # Try to read body from file if present
            resp_body_text = None
            body_file = row.get("response_body_file")
            if body_file and os.path.isfile(body_file):
                try:
                    with open(body_file, "r", encoding="utf-8", errors="replace") as f:
                        resp_body_text = f.read()
                except OSError:
                    resp_body_text = None

            entry = {
                "startedDateTime": row.get("timestamp", ""),
                "time": row.get("duration_ms") or 0,
                "request": {
                    "method": row.get("method", ""),
                    "url": row.get("url", ""),
                    "headers": req_header_list,
                },
                "response": {
                    "status": row.get("status_code"),
                    "headers": resp_header_list,
                    "content": {
                        "size": row.get("response_size", 0),
                        "text": resp_body_text,
                        "bodyFile": body_file,
                    },
                },
                "_meta": {
                    "phase": row.get("phase"),
                    "agent": row.get("agent"),
                    "tags": tags if isinstance(tags, list) else [],
                },
            }

            # Include postData only if there was a request body
            if row.get("request_body"):
                entry["request"]["postData"] = {"text": row["request_body"]}

            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "BountyHound", "version": "3.0"},
                "entries": entries,
            }
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _save_response_body(
        self, target: str, url: str, body: str, timestamp: datetime
    ) -> str:
        """
        Save a response body to an individual file on disk.

        File is stored at:
            REQUEST_LOG_DIR / target / {timestamp}-{hash}.txt

        Args:
            target: Target domain (used as subdirectory).
            url: Request URL (used in hash for uniqueness).
            body: Response body text.
            timestamp: When the request was made.

        Returns:
            Absolute file path as a string.
        """
        target_dir = BountyHoundConfig.REQUEST_LOG_DIR / target
        target_dir.mkdir(parents=True, exist_ok=True)

        # Build a unique filename from timestamp + URL hash
        ts_str = timestamp.strftime("%Y%m%d_%H%M%S_%f")
        url_hash = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()[:12]
        filename = f"{ts_str}-{url_hash}.txt"
        filepath = target_dir / filename

        filepath.write_text(body, encoding="utf-8", errors="replace")
        return str(filepath)

    @staticmethod
    def _serialize(value: Optional[Union[Dict, str, list]]) -> Optional[str]:
        """Convert a dict/list to a JSON string, or pass through a string."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        return json.dumps(value, default=str)

    @staticmethod
    def _parse_json_safe(value: Optional[str]) -> Any:
        """Attempt to parse a JSON string; return the original on failure."""
        if not value:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    @staticmethod
    def _headers_to_list(
        headers: Optional[Union[Dict, list]]
    ) -> List[Dict[str, str]]:
        """
        Convert headers to HAR-style list of {"name": ..., "value": ...}.

        Accepts a dict, a list (already in HAR format), or None.
        """
        if not headers:
            return []
        if isinstance(headers, list):
            return headers
        if isinstance(headers, dict):
            return [
                {"name": str(k), "value": str(v)} for k, v in headers.items()
            ]
        return []
