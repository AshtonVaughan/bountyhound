"""Decoder — encode/decode transforms with smart detection and hash recognition."""

from __future__ import annotations

import base64
import codecs
import gzip
import hashlib
import html
import json
import re
from urllib.parse import quote, unquote

import quopri

from models import CodecRequest, CodecOperation


def encode(req: CodecRequest) -> str:
    """Encode text with the specified operation."""
    text = req.text

    match req.operation:
        case CodecOperation.base64:
            return base64.b64encode(text.encode("utf-8")).decode("ascii")
        case CodecOperation.base32:
            return base64.b32encode(text.encode("utf-8")).decode("ascii")
        case CodecOperation.url:
            return quote(text, safe="")
        case CodecOperation.hex:
            return text.encode("utf-8").hex()
        case CodecOperation.html:
            return html.escape(text)
        case CodecOperation.unicode_escape:
            return text.encode("unicode_escape").decode("ascii")
        case CodecOperation.gzip:
            compressed = gzip.compress(text.encode("utf-8"))
            return base64.b64encode(compressed).decode("ascii")
        case CodecOperation.rot13:
            return codecs.encode(text, "rot_13")
        case CodecOperation.ascii85:
            return base64.a85encode(text.encode("utf-8")).decode("ascii")
        case CodecOperation.punycode:
            try:
                return text.encode("idna").decode("ascii")
            except Exception:
                return text.encode("punycode").decode("ascii")
        case CodecOperation.quoted_printable:
            return quopri.encodestring(text.encode("utf-8")).decode("ascii")
        case CodecOperation.jwt_decode:
            return "[jwt_decode is a decode-only operation]"

    return text


def decode(req: CodecRequest) -> str:
    """Decode text with the specified operation."""
    text = req.text

    match req.operation:
        case CodecOperation.base64:
            try:
                padded = text + "=" * (-len(text) % 4)
                return base64.b64decode(padded).decode("utf-8", errors="replace")
            except Exception as e:
                return f"[base64 decode error: {e}]"
        case CodecOperation.base32:
            try:
                padded = text + "=" * (-len(text) % 8)
                return base64.b32decode(padded.upper()).decode("utf-8", errors="replace")
            except Exception as e:
                return f"[base32 decode error: {e}]"
        case CodecOperation.url:
            return unquote(text)
        case CodecOperation.hex:
            try:
                clean = text.replace(" ", "").replace("0x", "").replace("\\x", "")
                return bytes.fromhex(clean).decode("utf-8", errors="replace")
            except Exception as e:
                return f"[hex decode error: {e}]"
        case CodecOperation.html:
            return html.unescape(text)
        case CodecOperation.unicode_escape:
            try:
                return text.encode("ascii").decode("unicode_escape")
            except Exception as e:
                return f"[unicode decode error: {e}]"
        case CodecOperation.gzip:
            try:
                raw = base64.b64decode(text + "=" * (-len(text) % 4))
                return gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception as e:
                return f"[gzip decode error: {e}]"
        case CodecOperation.rot13:
            return codecs.encode(text, "rot_13")
        case CodecOperation.ascii85:
            try:
                return base64.a85decode(text.encode("ascii")).decode("utf-8", errors="replace")
            except Exception as e:
                return f"[ascii85 decode error: {e}]"
        case CodecOperation.punycode:
            try:
                return text.encode("ascii").decode("idna")
            except Exception:
                try:
                    return text.encode("ascii").decode("punycode")
                except Exception as e:
                    return f"[punycode decode error: {e}]"
        case CodecOperation.quoted_printable:
            try:
                return quopri.decodestring(text.encode("ascii")).decode("utf-8", errors="replace")
            except Exception as e:
                return f"[quoted-printable decode error: {e}]"
        case CodecOperation.jwt_decode:
            return _decode_jwt(text)

    return text


def _decode_jwt(token: str) -> str:
    """Decode a JWT token without verification (for inspection only)."""
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return "[Not a valid JWT: expected 2 or 3 parts]"

    result = {}
    labels = ["header", "payload", "signature"]

    for i, part in enumerate(parts):
        if i < 2:
            try:
                padded = part + "=" * (-len(part) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                result[labels[i]] = json.loads(decoded)
            except Exception as e:
                result[labels[i]] = f"[decode error: {e}]"
        else:
            result[labels[i]] = part

    return json.dumps(result, indent=2)


# ── Smart decode (Task #26) ────────────────────────────────────────────────

def smart_decode(text: str) -> list[dict]:
    """Auto-detect encoding and return decoded results with confidence scores."""
    results = []

    # JWT detection
    if re.match(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', text):
        results.append({
            "encoding": "jwt",
            "decoded": _decode_jwt(text),
            "confidence": 0.99,
        })

    # Base64 detection
    if re.match(r'^[A-Za-z0-9+/=]{4,}$', text) and len(text) % 4 == 0:
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="replace")
            # Check if result is printable
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t') / max(len(decoded), 1)
            if printable_ratio > 0.8:
                results.append({
                    "encoding": "base64",
                    "decoded": decoded,
                    "confidence": min(0.9, 0.5 + printable_ratio * 0.4),
                })
        except Exception:
            pass

    # URL encoding detection
    if "%" in text:
        decoded = unquote(text)
        if decoded != text:
            results.append({
                "encoding": "url",
                "decoded": decoded,
                "confidence": 0.85,
            })

    # Hex detection
    if re.match(r'^[0-9a-fA-F]{4,}$', text) and len(text) % 2 == 0:
        try:
            decoded = bytes.fromhex(text).decode("utf-8", errors="replace")
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t') / max(len(decoded), 1)
            if printable_ratio > 0.7:
                results.append({
                    "encoding": "hex",
                    "decoded": decoded,
                    "confidence": min(0.8, 0.3 + printable_ratio * 0.5),
                })
        except Exception:
            pass

    # HTML entity detection
    if "&" in text and ";" in text:
        decoded = html.unescape(text)
        if decoded != text:
            results.append({
                "encoding": "html",
                "decoded": decoded,
                "confidence": 0.85,
            })

    # Unicode escape detection
    if "\\u" in text or "\\x" in text:
        try:
            decoded = text.encode("ascii").decode("unicode_escape")
            if decoded != text:
                results.append({
                    "encoding": "unicode_escape",
                    "decoded": decoded,
                    "confidence": 0.80,
                })
        except Exception:
            pass

    # Base32 detection
    if re.match(r'^[A-Z2-7=]{8,}$', text):
        try:
            padded = text + "=" * (-len(text) % 8)
            decoded = base64.b32decode(padded).decode("utf-8", errors="replace")
            printable_ratio = sum(1 for c in decoded if c.isprintable()) / max(len(decoded), 1)
            if printable_ratio > 0.7:
                results.append({
                    "encoding": "base32",
                    "decoded": decoded,
                    "confidence": 0.6,
                })
        except Exception:
            pass

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


# ── Hash recognition (Task #26) ────────────────────────────────────────────

_HASH_PATTERNS = {
    "MD5": (r'^[a-fA-F0-9]{32}$', 32),
    "SHA-1": (r'^[a-fA-F0-9]{40}$', 40),
    "SHA-224": (r'^[a-fA-F0-9]{56}$', 56),
    "SHA-256": (r'^[a-fA-F0-9]{64}$', 64),
    "SHA-384": (r'^[a-fA-F0-9]{96}$', 96),
    "SHA-512": (r'^[a-fA-F0-9]{128}$', 128),
    "NTLM": (r'^[a-fA-F0-9]{32}$', 32),
    "bcrypt": (r'^\$2[aby]?\$\d{2}\$.{53}$', None),
    "scrypt": (r'^\$s0\$', None),
    "argon2": (r'^\$argon2(id|i|d)\$', None),
    "MySQL 4.1+": (r'^\*[A-F0-9]{40}$', None),
    "PostgreSQL MD5": (r'^md5[a-f0-9]{32}$', None),
    "CRC32": (r'^[a-fA-F0-9]{8}$', 8),
}


def identify_hash(text: str) -> list[dict]:
    """Identify possible hash types for a given string."""
    text = text.strip()
    results = []

    for name, (pattern, expected_len) in _HASH_PATTERNS.items():
        if re.match(pattern, text):
            confidence = 0.7
            if expected_len and len(text) == expected_len:
                confidence = 0.85
            # MD5 and NTLM are both 32 hex chars
            if name == "NTLM" and len(text) == 32:
                confidence = 0.5  # Lower for NTLM since MD5 is more common
            if name in ("bcrypt", "scrypt", "argon2"):
                confidence = 0.95  # Very distinctive formats
            results.append({
                "type": name,
                "length": len(text),
                "confidence": confidence,
            })

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


# ── Auto-detect chain ────────────────────────────────────────────────────

def auto_detect_chain(text: str, max_depth: int = 5) -> list[dict]:
    """Recursively decode through multiple encoding layers.

    Returns a chain of decode steps, e.g.:
    [{"encoding": "base64", "decoded": "..."}, {"encoding": "url", "decoded": "..."}]
    """
    chain: list[dict] = []
    current = text

    for _ in range(max_depth):
        results = smart_decode(current)
        if not results:
            break
        # Take the highest-confidence detection
        best = results[0]
        if best["confidence"] < 0.6:
            break
        decoded = best["decoded"]
        if decoded == current:
            break  # No progress
        chain.append({
            "encoding": best["encoding"],
            "decoded": decoded,
            "confidence": best["confidence"],
        })
        current = decoded

    return chain


# ── Character inspector ──────────────────────────────────────────────────

def character_inspector(text: str) -> dict:
    """Inspect individual characters — codepoints, categories, and hidden chars."""
    import unicodedata

    chars: list[dict] = []
    hidden_count = 0
    non_ascii_count = 0
    categories: dict[str, int] = {}

    for ch in text[:500]:  # Cap at 500 chars
        cp = ord(ch)
        cat = unicodedata.category(ch)
        name = unicodedata.name(ch, f"U+{cp:04X}")
        categories[cat] = categories.get(cat, 0) + 1

        is_hidden = cat in ("Cc", "Cf", "Zs", "Zl", "Zp") and ch not in ("\n", "\r", "\t", " ")
        if is_hidden:
            hidden_count += 1
        if cp > 127:
            non_ascii_count += 1

        chars.append({
            "char": ch if ch.isprintable() else f"\\x{cp:02x}" if cp < 256 else f"\\u{cp:04x}",
            "codepoint": f"U+{cp:04X}",
            "decimal": cp,
            "hex": f"0x{cp:02X}",
            "category": cat,
            "name": name,
            "hidden": is_hidden,
        })

    # Detect homoglyph/confusable issues
    homoglyphs = []
    confusable_pairs = [
        ("a", "\u0430"), ("e", "\u0435"), ("o", "\u043e"), ("p", "\u0440"),
        ("c", "\u0441"), ("x", "\u0445"), ("y", "\u0443"), ("A", "\u0410"),
        ("B", "\u0412"), ("E", "\u0415"), ("H", "\u041d"), ("K", "\u041a"),
        ("M", "\u041c"), ("O", "\u041e"), ("P", "\u0420"), ("T", "\u0422"),
    ]
    for latin, cyrillic in confusable_pairs:
        if cyrillic in text:
            homoglyphs.append({
                "found": cyrillic,
                "looks_like": latin,
                "codepoint": f"U+{ord(cyrillic):04X}",
                "script": "Cyrillic",
            })

    return {
        "length": len(text),
        "characters": chars,
        "categories": categories,
        "hidden_count": hidden_count,
        "non_ascii_count": non_ascii_count,
        "homoglyphs": homoglyphs,
        "has_bom": text.startswith("\ufeff"),
        "has_null_bytes": "\x00" in text,
        "has_rtl_override": any(ord(c) in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069) for c in text),
    }
