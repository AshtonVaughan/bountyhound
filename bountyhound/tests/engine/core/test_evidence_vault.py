"""Unit tests for engine.core.evidence_vault.EvidenceVault."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def vault(tmp_path):
    """Create an EvidenceVault whose base_dir points at tmp_path."""
    with patch("engine.core.evidence_vault.BountyHoundConfig") as mock_cfg:
        mock_cfg.evidence_dir.return_value = tmp_path
        from engine.core.evidence_vault import EvidenceVault

        v = EvidenceVault("example.com")
    # base_dir is set in __init__ from the mocked config
    assert v.base_dir == tmp_path
    return v


# ------------------------------------------------------------------ #
# save_response
# ------------------------------------------------------------------ #

def test_save_response_basic(vault, tmp_path):
    """Save an HTTP response and verify file content structure."""
    path = vault.save_response(
        url="https://example.com/api/users/1",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"id":1}',
        label="idor-leak",
    )
    p = Path(path)
    assert p.exists()
    assert p.parent == tmp_path / "responses"
    content = p.read_text(encoding="utf-8")
    assert "URL: https://example.com/api/users/1" in content
    assert "Status: 200" in content
    assert "Content-Type: application/json" in content
    assert '{"id":1}' in content


def test_save_response_no_body(vault):
    """Body defaults to '(empty)' when None."""
    path = vault.save_response(
        url="https://example.com/health",
        status_code=204,
    )
    content = Path(path).read_text(encoding="utf-8")
    assert "(empty)" in content


def test_save_response_string_headers(vault):
    """Headers passed as a pre-formatted string are stored verbatim."""
    raw_headers = "X-Custom: yes\nX-Other: no"
    path = vault.save_response(
        url="https://example.com/x",
        status_code=200,
        headers=raw_headers,
        body="ok",
    )
    content = Path(path).read_text(encoding="utf-8")
    assert "X-Custom: yes" in content
    assert "X-Other: no" in content


# ------------------------------------------------------------------ #
# save_screenshot
# ------------------------------------------------------------------ #

def test_save_screenshot_bytes(vault, tmp_path):
    """Raw bytes are written as a .png file."""
    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    path = vault.save_screenshot(fake_png, label="xss-popup")
    p = Path(path)
    assert p.exists()
    assert p.suffix == ".png"
    assert p.parent == tmp_path / "screenshots"
    assert p.read_bytes() == fake_png


def test_save_screenshot_copies_file(vault, tmp_path):
    """An existing file path is copied into the vault."""
    src = tmp_path / "orig.gif"
    src.write_bytes(b"GIF89a")
    path = vault.save_screenshot(str(src), label="evidence")
    p = Path(path)
    assert p.exists()
    assert p.suffix == ".gif"
    assert p.read_bytes() == b"GIF89a"
    # Should be a copy, not the original
    assert p != src


# ------------------------------------------------------------------ #
# save_token
# ------------------------------------------------------------------ #

def test_save_token_basic(vault, tmp_path):
    """Token JSON includes name, value, target, and optional metadata."""
    path = vault.save_token(
        "session_cookie",
        "abc123",
        metadata={"user": "attacker"},
    )
    p = Path(path)
    assert p.exists()
    assert p.parent == tmp_path / "tokens"
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["token_name"] == "session_cookie"
    assert data["token_value"] == "abc123"
    assert data["target"] == "example.com"
    assert data["metadata"]["user"] == "attacker"


def test_save_token_no_metadata(vault):
    """Token without metadata omits the metadata key."""
    path = vault.save_token("api_key", "secret-value")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert "metadata" not in data
    assert data["token_value"] == "secret-value"


# ------------------------------------------------------------------ #
# get_manifest / list_evidence
# ------------------------------------------------------------------ #

def test_get_manifest_empty(vault):
    """Empty vault returns an empty manifest list."""
    assert vault.get_manifest() == []


def test_get_manifest_lists_all(vault):
    """Manifest includes entries from multiple categories."""
    vault.save_response(url="https://a.com", status_code=200, body="x")
    vault.save_token("tok", "val")
    vault.save_raw("notes.txt", "recon data")

    manifest = vault.get_manifest()
    assert len(manifest) == 3
    categories = {e["category"] for e in manifest}
    assert categories == {"responses", "tokens", "raw"}
    for entry in manifest:
        assert "path" in entry
        assert "size" in entry
        assert "filename" in entry


def test_list_evidence_counts(vault):
    """list_evidence returns per-category counts and sizes."""
    vault.save_response(url="https://a.com", status_code=200, body="body1")
    vault.save_response(url="https://b.com", status_code=404, body="body2")
    vault.save_token("t", "v")

    summary = vault.list_evidence()
    assert summary["responses"]["count"] == 2
    assert summary["tokens"]["count"] == 1
    assert summary["screenshots"]["count"] == 0
    assert summary["total_count"] == 3
    assert summary["total_size"] > 0


# ------------------------------------------------------------------ #
# Special characters in label
# ------------------------------------------------------------------ #

def test_special_characters_in_label(vault):
    """Labels with special chars are sanitized to safe filenames."""
    path = vault.save_response(
        url="https://example.com",
        status_code=200,
        body="test",
        label="../../etc/passwd",
    )
    p = Path(path)
    assert p.exists()
    # The filename should not contain slashes or path traversal
    assert "/" not in p.name
    assert "\\" not in p.name
