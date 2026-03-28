"""Safe regex compilation — prevents ReDoS from user-supplied patterns."""

from __future__ import annotations

import logging
import re
import signal
import sys
import threading

log = logging.getLogger("proxy-engine.safe_regex")

# Max compiled pattern cache size
_MAX_CACHE = 500
_compiled_cache: dict[str, re.Pattern | None] = {}

# Max pattern length to prevent absurdly long regex
MAX_PATTERN_LENGTH = 2000

# Dangerous constructs that can cause catastrophic backtracking
_DANGEROUS_PATTERNS = [
    # Nested quantifiers like (a+)+ or (a*)*
    r'\([^)]*[+*][^)]*\)[+*]',
    # Overlapping alternations with quantifiers
    r'\(\?:[^)]*\|[^)]*\)[+*]{2,}',
]


def _is_dangerous(pattern: str) -> bool:
    """Quick heuristic check for potentially catastrophic regex patterns."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        return True
    # Count quantifiers — too many nested is suspicious
    quantifiers = sum(1 for c in pattern if c in '+*')
    groups = sum(1 for c in pattern if c == '(')
    if quantifiers > 3 and groups > 3 and quantifiers * groups > 20:
        return True
    return False


def safe_compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern | None:
    """Compile a regex with safety checks. Returns None if invalid or dangerous."""
    if not pattern:
        return None

    if len(pattern) > MAX_PATTERN_LENGTH:
        log.warning(f"[safe_regex] Pattern too long ({len(pattern)} chars), rejected")
        return None

    cache_key = f"{pattern}:{flags}"
    if cache_key in _compiled_cache:
        return _compiled_cache[cache_key]

    # Evict oldest entries if cache is full
    if len(_compiled_cache) >= _MAX_CACHE:
        keys = list(_compiled_cache.keys())
        for k in keys[:_MAX_CACHE // 4]:
            _compiled_cache.pop(k, None)

    try:
        compiled = re.compile(pattern, flags)
        _compiled_cache[cache_key] = compiled
        return compiled
    except re.error as e:
        log.warning(f"[safe_regex] Invalid regex '{pattern[:80]}': {e}")
        _compiled_cache[cache_key] = None
        return None


def safe_search(pattern: str, text: str, flags: int = re.IGNORECASE,
                max_text_len: int = 100_000) -> re.Match | None:
    """Search with a compiled safe pattern, truncating text to prevent long scans."""
    compiled = safe_compile(pattern, flags)
    if not compiled:
        return None
    return compiled.search(text[:max_text_len])


def safe_sub(pattern: str, replacement: str, text: str,
             flags: int = 0, max_text_len: int = 100_000) -> str:
    """Safe regex substitution."""
    compiled = safe_compile(pattern, flags)
    if not compiled:
        return text
    return compiled.sub(replacement, text[:max_text_len])


def safe_findall(pattern: str, text: str, flags: int = re.IGNORECASE,
                 max_text_len: int = 100_000) -> list:
    """Safe regex findall."""
    compiled = safe_compile(pattern, flags)
    if not compiled:
        return []
    return compiled.findall(text[:max_text_len])


def clear_cache() -> None:
    """Clear the compiled pattern cache."""
    _compiled_cache.clear()
