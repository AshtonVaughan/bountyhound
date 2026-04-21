"""
BountyHound Evidence Vault

Auto-saves raw evidence files (responses, screenshots, tokens, raw data)
to an organized directory structure on disk. Every piece of evidence is
preserved with metadata so it can be referenced in reports later.

Usage:
    from engine.core.evidence_vault import EvidenceVault

    vault = EvidenceVault("example.com")
    path = vault.save_response(
        url="https://example.com/api/users/123",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"id": 123, "email": "admin@example.com"}',
        label="idor-user-data"
    )
    vault.save_token("session_cookie", "abc123def456", metadata={"user": "attacker"})
    vault.save_raw("recon-output.txt", "subfinder results here...")
    manifest = vault.get_manifest()
"""

import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from engine.core.config import BountyHoundConfig


class EvidenceVault:
    """Organized disk-based storage for all evidence collected during a hunt."""

    # Subdirectory names within the evidence directory
    RESPONSES_DIR = "responses"
    SCREENSHOTS_DIR = "screenshots"
    TOKENS_DIR = "tokens"
    RAW_DIR = "raw"

    def __init__(self, target: str):
        """
        Initialize the evidence vault for a specific target.

        Args:
            target: Target domain (e.g. "example.com"). Used to determine
                    the base evidence directory via BountyHoundConfig.
        """
        self.target = target
        self.base_dir = BountyHoundConfig.evidence_dir(target)

    def _ensure_subdir(self, subdir: str) -> Path:
        """
        Ensure a subdirectory exists under the evidence base directory.

        Args:
            subdir: Name of the subdirectory (e.g. "responses").

        Returns:
            Absolute Path to the subdirectory.
        """
        path = self.base_dir / subdir
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_response(
        self,
        url: str,
        status_code: int,
        headers: Optional[Union[Dict, str]] = None,
        body: Optional[str] = None,
        label: str = "",
    ) -> str:
        """
        Save an HTTP response as evidence.

        The file contains a structured text representation:
        - URL and status code on the first lines
        - Headers section
        - Body section

        Args:
            url: The request URL that produced this response.
            status_code: HTTP status code.
            headers: Response headers (dict or pre-formatted string).
            body: Response body text.
            label: Human-readable label for the filename (e.g. "idor-leak").

        Returns:
            Absolute file path to the saved evidence file.
        """
        directory = self._ensure_subdir(self.RESPONSES_DIR)
        now = datetime.utcnow()

        # Build filename: {timestamp}_{label}_{hash}.txt
        ts_str = now.strftime("%Y%m%d_%H%M%S")
        content_for_hash = f"{url}{status_code}{body or ''}"
        short_hash = hashlib.sha256(
            content_for_hash.encode("utf-8", errors="replace")
        ).hexdigest()[:10]

        # Sanitize the label for filesystem safety
        safe_label = self._sanitize_filename(label) if label else "resp"
        filename = f"{ts_str}_{safe_label}_{short_hash}.txt"
        filepath = directory / filename

        # Format headers for storage
        if isinstance(headers, dict):
            headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif isinstance(headers, str):
            headers_text = headers
        else:
            headers_text = ""

        # Write structured evidence file
        content_parts = [
            f"URL: {url}",
            f"Status: {status_code}",
            f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Target: {self.target}",
            "",
            "--- HEADERS ---",
            headers_text,
            "",
            "--- BODY ---",
            body or "(empty)",
        ]
        filepath.write_text(
            "\n".join(content_parts), encoding="utf-8", errors="replace"
        )
        return str(filepath)

    def save_screenshot(
        self,
        data_or_path: Union[str, bytes, Path],
        label: str = "",
    ) -> str:
        """
        Save a screenshot as evidence.

        If data_or_path is a path to an existing file, it is copied.
        If it is raw bytes, they are written directly.

        Args:
            data_or_path: Either an existing file path (str/Path) or raw
                          image bytes.
            label: Human-readable label for the filename.

        Returns:
            Absolute file path to the saved screenshot.
        """
        directory = self._ensure_subdir(self.SCREENSHOTS_DIR)
        now = datetime.utcnow()
        ts_str = now.strftime("%Y%m%d_%H%M%S")
        safe_label = self._sanitize_filename(label) if label else "screenshot"

        if isinstance(data_or_path, bytes):
            # Raw bytes -- write directly
            filename = f"{ts_str}_{safe_label}.png"
            filepath = directory / filename
            filepath.write_bytes(data_or_path)
            return str(filepath)

        # Treat as a file path
        source_path = Path(str(data_or_path))
        if source_path.is_file():
            ext = source_path.suffix or ".png"
            filename = f"{ts_str}_{safe_label}{ext}"
            filepath = directory / filename
            shutil.copy2(str(source_path), str(filepath))
            return str(filepath)

        # Fallback: treat the value as text content (e.g. base64 string)
        filename = f"{ts_str}_{safe_label}.txt"
        filepath = directory / filename
        filepath.write_text(
            str(data_or_path), encoding="utf-8", errors="replace"
        )
        return str(filepath)

    def save_token(
        self,
        token_name: str,
        token_value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Save a token (JWT, session cookie, API key, etc.) as a JSON file.

        Args:
            token_name: Descriptive name (e.g. "session_cookie", "jwt_user_a").
            token_value: The raw token string.
            metadata: Optional dict of extra metadata to store alongside.

        Returns:
            Absolute file path to the saved token JSON file.
        """
        directory = self._ensure_subdir(self.TOKENS_DIR)
        now = datetime.utcnow()
        ts_str = now.strftime("%Y%m%d_%H%M%S")
        safe_name = self._sanitize_filename(token_name)
        filename = f"{ts_str}_{safe_name}.json"
        filepath = directory / filename

        token_data = {
            "token_name": token_name,
            "token_value": token_value,
            "target": self.target,
            "saved_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        if metadata:
            token_data["metadata"] = metadata

        filepath.write_text(
            json.dumps(token_data, indent=2, default=str),
            encoding="utf-8",
        )
        return str(filepath)

    def save_raw(self, filename: str, content: Union[str, bytes]) -> str:
        """
        Save arbitrary content to the raw/ subdirectory.

        Args:
            filename: Desired filename (will be sanitized).
            content: Text string or raw bytes to save.

        Returns:
            Absolute file path to the saved file.
        """
        directory = self._ensure_subdir(self.RAW_DIR)
        safe_name = self._sanitize_filename(filename)
        filepath = directory / safe_name

        if isinstance(content, bytes):
            filepath.write_bytes(content)
        else:
            filepath.write_text(
                content, encoding="utf-8", errors="replace"
            )
        return str(filepath)

    def list_evidence(self) -> Dict[str, Any]:
        """
        Return a summary of all evidence stored for this target.

        Returns:
            Dict with keys per category, each containing:
                - count: number of files
                - size: total bytes
            Plus a "total_count" and "total_size" across all categories.
        """
        categories = [
            self.RESPONSES_DIR,
            self.SCREENSHOTS_DIR,
            self.TOKENS_DIR,
            self.RAW_DIR,
        ]
        result = {}
        total_count = 0
        total_size = 0

        for cat in categories:
            cat_dir = self.base_dir / cat
            count = 0
            size = 0
            if cat_dir.is_dir():
                for entry in cat_dir.iterdir():
                    if entry.is_file():
                        count += 1
                        size += entry.stat().st_size
            result[cat] = {"count": count, "size": size}
            total_count += count
            total_size += size

        result["total_count"] = total_count
        result["total_size"] = total_size
        return result

    def get_manifest(self) -> List[Dict[str, Any]]:
        """
        Return a JSON-serializable list of all saved evidence files.

        Each entry contains:
            - path: absolute file path
            - category: which subdirectory (responses, screenshots, etc.)
            - filename: just the file name
            - size: file size in bytes
            - modified: last modified timestamp as ISO string

        Returns:
            List of file metadata dicts, sorted by modification time (newest first).
        """
        categories = [
            self.RESPONSES_DIR,
            self.SCREENSHOTS_DIR,
            self.TOKENS_DIR,
            self.RAW_DIR,
        ]
        manifest = []

        for cat in categories:
            cat_dir = self.base_dir / cat
            if not cat_dir.is_dir():
                continue
            for entry in cat_dir.iterdir():
                if not entry.is_file():
                    continue
                stat = entry.stat()
                manifest.append(
                    {
                        "path": str(entry),
                        "category": cat,
                        "filename": entry.name,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )

        # Sort newest first
        manifest.sort(key=lambda x: x["modified"], reverse=True)
        return manifest

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        """
        Remove or replace characters that are unsafe in filenames.

        Keeps alphanumerics, hyphens, underscores, and dots.
        """
        safe = []
        for ch in name:
            if ch.isalnum() or ch in ("-", "_", "."):
                safe.append(ch)
            else:
                safe.append("_")
        result = "".join(safe).strip("._")
        return result if result else "unnamed"
