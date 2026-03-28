"""Differential analysis — blind vulnerability detection via response comparison.

Burp's core "smart scanner" technique: establish a baseline, inject payloads,
compare response signatures to detect deviations.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.differential")


@dataclass
class ResponseSignature:
    """Signature of an HTTP response for comparison."""
    status_code: int = 0
    body_length: int = 0
    word_count: int = 0
    structure_hash: str = ""  # hash of HTML tag sequence
    timing_ms: float = 0.0
    word_frequency: dict[str, int] = field(default_factory=dict)


def compute_signature(
    status_code: int,
    headers: dict[str, str],
    body: str,
    timing_ms: float,
) -> ResponseSignature:
    """Compute a response signature from raw response data."""
    # Word count and frequency
    words = re.findall(r'\b\w+\b', body.lower()[:50000])
    freq = dict(Counter(words).most_common(50))

    # Structure hash — HTML tag sequence
    tags = re.findall(r'<(/?\w+)', body[:50000])
    tag_seq = " ".join(tags[:200])
    structure_hash = hashlib.md5(tag_seq.encode()).hexdigest()[:12]

    return ResponseSignature(
        status_code=status_code,
        body_length=len(body),
        word_count=len(words),
        structure_hash=structure_hash,
        timing_ms=timing_ms,
        word_frequency=freq,
    )


def compare_signatures(baseline: ResponseSignature, injected: ResponseSignature) -> float:
    """Compare two signatures and return 0-1 similarity score (1 = identical)."""
    scores: list[float] = []

    # Status code match
    scores.append(1.0 if baseline.status_code == injected.status_code else 0.0)

    # Body length similarity
    if baseline.body_length > 0:
        ratio = min(baseline.body_length, injected.body_length) / max(baseline.body_length, injected.body_length)
        scores.append(ratio)
    else:
        scores.append(1.0 if injected.body_length == 0 else 0.0)

    # Word count similarity
    if baseline.word_count > 0:
        ratio = min(baseline.word_count, injected.word_count) / max(baseline.word_count, injected.word_count)
        scores.append(ratio)
    else:
        scores.append(1.0 if injected.word_count == 0 else 0.0)

    # Structure hash match
    scores.append(1.0 if baseline.structure_hash == injected.structure_hash else 0.3)

    # Timing similarity (within 2x is normal)
    if baseline.timing_ms > 0:
        ratio = min(baseline.timing_ms, injected.timing_ms) / max(baseline.timing_ms, injected.timing_ms, 1)
        scores.append(min(ratio, 1.0))
    else:
        scores.append(0.8)

    # Word frequency overlap (Jaccard-like)
    if baseline.word_frequency:
        all_words = set(baseline.word_frequency) | set(injected.word_frequency)
        if all_words:
            common = set(baseline.word_frequency) & set(injected.word_frequency)
            scores.append(len(common) / len(all_words))
        else:
            scores.append(1.0)
    else:
        scores.append(0.8)

    return sum(scores) / len(scores) if scores else 1.0


async def _send_and_sign(
    client: httpx.AsyncClient,
    method: str, url: str, headers: dict[str, str],
    body: str | None,
) -> ResponseSignature | None:
    """Send a request and compute its response signature."""
    try:
        start = time.monotonic()
        resp = await client.request(
            method, url, headers=headers,
            content=body.encode("utf-8") if body else None,
            follow_redirects=True,
        )
        timing = (time.monotonic() - start) * 1000
        return compute_signature(
            resp.status_code,
            dict(resp.headers),
            resp.text,
            timing,
        )
    except Exception as e:
        log.debug(f"[differential] Request error: {e}")
        return None


async def differential_scan_point(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    point_name: str,
    point_location: str,
    inject_fn,
    payloads: list[str],
    threshold: float = 0.7,
) -> list[ScanFinding]:
    """Perform differential analysis on a single insertion point.

    Args:
        client: HTTP client
        method, url, headers, body: base request
        point_name: parameter name
        point_location: e.g. "url_param", "body_param"
        inject_fn: async callable(payload) -> httpx.Response | None
        payloads: payloads to test
        threshold: similarity threshold below which a deviation is flagged

    Returns:
        List of findings where response deviated significantly from baseline.
    """
    findings: list[ScanFinding] = []

    # Step 1: Establish baseline with 3 identical requests
    baselines: list[ResponseSignature] = []
    for _ in range(3):
        sig = await _send_and_sign(client, method, url, headers, body)
        if sig:
            baselines.append(sig)

    if len(baselines) < 2:
        return findings

    # Compute baseline variance
    baseline_lengths = [b.body_length for b in baselines]
    baseline_timings = [b.timing_ms for b in baselines]
    length_stddev = statistics.stdev(baseline_lengths) if len(baseline_lengths) > 1 else 0
    timing_stddev = statistics.stdev(baseline_timings) if len(baseline_timings) > 1 else 0

    # Use the median baseline for comparison
    median_baseline = baselines[len(baselines) // 2]

    # Step 2: Test each payload
    for payload in payloads:
        try:
            resp = await inject_fn(payload)
            if not resp:
                continue

            timing = getattr(resp, '_timing_ms', 0)
            if not timing:
                timing = 0  # no timing available from inject_fn

            injected_sig = compute_signature(
                resp.status_code, dict(resp.headers), resp.text, timing,
            )

            similarity = compare_signatures(median_baseline, injected_sig)

            if similarity < threshold:
                # Determine deviation type
                deviation_types = []
                if injected_sig.status_code != median_baseline.status_code:
                    deviation_types.append(f"status: {median_baseline.status_code}→{injected_sig.status_code}")
                if abs(injected_sig.body_length - median_baseline.body_length) > length_stddev * 3 + 100:
                    deviation_types.append(f"length: {median_baseline.body_length}→{injected_sig.body_length}")
                if injected_sig.structure_hash != median_baseline.structure_hash:
                    deviation_types.append("structure changed")
                if injected_sig.timing_ms > median_baseline.timing_ms + timing_stddev * 3 + 2000:
                    deviation_types.append(f"timing: {median_baseline.timing_ms:.0f}ms→{injected_sig.timing_ms:.0f}ms")

                if not deviation_types:
                    deviation_types.append(f"similarity: {similarity:.2f}")

                # Confirm with retry
                resp2 = await inject_fn(payload)
                if resp2:
                    retry_sig = compute_signature(resp2.status_code, dict(resp2.headers), resp2.text, 0)
                    retry_sim = compare_signatures(median_baseline, retry_sig)
                    if retry_sim >= threshold:
                        continue  # Not consistent, skip

                # Map deviation to severity
                severity = "medium"
                if "status" in str(deviation_types) and injected_sig.status_code in (500, 503):
                    severity = "high"
                if "timing" in str(deviation_types):
                    severity = "high"  # potential blind injection
                if abs(injected_sig.body_length - median_baseline.body_length) > median_baseline.body_length * 0.5:
                    severity = "high"  # significant data extraction

                findings.append(ScanFinding(
                    template_id="differential-anomaly",
                    name=f"Differential Anomaly — {point_name}",
                    severity=severity,
                    url=url,
                    matched_at=f"{point_location}:{point_name}",
                    description=f"Response deviated significantly (similarity={similarity:.2f}) with payload '{payload}' at {point_location}:{point_name}. Deviations: {', '.join(deviation_types)}",
                    extracted=deviation_types,
                    confidence="firm",
                    source="differential",
                ))

        except Exception as e:
            log.debug(f"[differential] Error testing payload '{payload}': {e}")

    return findings


async def _check_differential(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Run differential analysis as a standalone scanner check against URL params."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)

    # Generic payloads for differential testing
    diff_payloads = [
        "'", '"', "\\", "<>", "{{7*7}}", "${7*7}",
        "../../../etc/passwd", "; sleep 3", "| id",
        "0", "-1", "999999999", "null", "undefined",
        "AAAA" * 100,
    ]

    for param_name, values in params.items():
        async def inject(payload, _name=param_name):
            new_params = dict(params)
            new_params[_name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                start = time.monotonic()
                resp = await client.get(test_url)
                resp._timing_ms = (time.monotonic() - start) * 1000
                return resp
            except Exception:
                return None

        point_findings = await differential_scan_point(
            client, "GET", url, {}, None,
            point_name=param_name,
            point_location="url_param",
            inject_fn=inject,
            payloads=diff_payloads,
        )
        findings.extend(point_findings)

    return findings


# Export for scanner.py integration
DIFFERENTIAL_CHECK = {"differential": _check_differential}
