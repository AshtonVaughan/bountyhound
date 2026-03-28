"""Sequencer — token entropy and randomness analysis with FIPS 140-2 tests."""

from __future__ import annotations

import asyncio
import logging
import math
import uuid
from collections import Counter

import httpx

from models import SequencerRequest, SequencerResult
from state import state
from safe_regex import safe_search

log = logging.getLogger("proxy-engine.sequencer")

_cancel_events: dict[str, asyncio.Event] = {}


def _calculate_entropy(tokens: list[str]) -> dict:
    """Calculate entropy metrics for a set of tokens."""
    if not tokens:
        return {
            "entropy_bits": 0, "char_entropy": 0, "rating": "poor",
            "char_frequency": {}, "length_min": 0, "length_max": 0,
            "length_avg": 0, "analysis": "No tokens collected",
            "fips_results": {},
        }

    all_chars = "".join(tokens)
    char_freq = Counter(all_chars)
    total_chars = len(all_chars)

    # Shannon entropy per character
    char_entropy = 0.0
    for count in char_freq.values():
        p = count / total_chars
        if p > 0:
            char_entropy -= p * math.log2(p)

    lengths = [len(t) for t in tokens]
    avg_len = sum(lengths) / len(lengths) if lengths else 0

    unique_chars = len(char_freq)
    bits_per_char = math.log2(unique_chars) if unique_chars > 1 else 0
    entropy_bits = bits_per_char * avg_len

    unique_ratio = len(set(tokens)) / len(tokens) if tokens else 0
    sequential = _check_sequential(tokens)

    # FIPS 140-2 tests (Task #33)
    fips_results = _fips_tests(all_chars)

    # Rating
    fips_pass = all(v.get("pass", False) for v in fips_results.values()) if fips_results else True
    if entropy_bits >= 128 and unique_ratio >= 0.99 and not sequential and fips_pass:
        rating = "excellent"
    elif entropy_bits >= 64 and unique_ratio >= 0.95 and fips_pass:
        rating = "good"
    elif entropy_bits >= 32 and unique_ratio >= 0.80:
        rating = "fair"
    else:
        rating = "poor"

    analysis_parts = [
        f"Collected {len(tokens)} tokens",
        f"Character set size: {unique_chars} unique characters",
        f"Entropy per character: {char_entropy:.2f} bits",
        f"Estimated entropy per token: {entropy_bits:.1f} bits",
        f"Unique tokens: {len(set(tokens))}/{len(tokens)} ({unique_ratio*100:.1f}%)",
        f"Length range: {min(lengths)}-{max(lengths)} (avg {avg_len:.1f})",
    ]
    if sequential:
        analysis_parts.append("WARNING: Sequential/predictable patterns detected")
    if fips_results:
        passed = sum(1 for v in fips_results.values() if v.get("pass"))
        total = len(fips_results)
        analysis_parts.append(f"FIPS 140-2 tests: {passed}/{total} passed")

    autocorrelation = _autocorrelation_test(tokens)
    block_freq = _block_frequency_test(all_chars)
    format_info = _token_format_analysis(tokens)
    predict = _predictability_score(tokens)

    # NIST SP 800-22 additional tests
    bits = _to_bits(all_chars)
    nist_results = {}
    cusum = _nist_cumulative_sums(bits)
    if cusum:
        nist_results["cumulative_sums"] = cusum
    longest_run = _nist_longest_run(bits)
    if longest_run:
        nist_results["longest_run"] = longest_run
    matrix_rank = _nist_binary_matrix_rank(bits)
    if matrix_rank:
        nist_results["binary_matrix_rank"] = matrix_rank

    # Bit-level analysis
    bit_independence = _bit_position_independence(tokens)
    hamming = _hamming_distance_analysis(tokens)

    if nist_results:
        nist_passed = sum(1 for v in nist_results.values() if v.get("pass"))
        nist_total = len(nist_results)
        analysis_parts.append(f"NIST SP 800-22 tests: {nist_passed}/{nist_total} passed")

    return {
        "entropy_bits": round(entropy_bits, 2),
        "char_frequency": dict(char_freq.most_common(30)),
        "char_entropy": round(char_entropy, 4),
        "length_min": min(lengths) if lengths else 0,
        "length_max": max(lengths) if lengths else 0,
        "length_avg": round(avg_len, 2),
        "rating": rating,
        "analysis": "\n".join(analysis_parts),
        "fips_results": fips_results,
        "nist_results": nist_results,
        "autocorrelation": autocorrelation,
        "block_frequency": block_freq,
        "format_analysis": format_info,
        "predictability": predict,
        "bit_independence": bit_independence,
        "hamming_distance": hamming,
    }


def _autocorrelation_test(tokens: list[str]) -> dict:
    """Test autocorrelation at lags 1-5."""
    if len(tokens) < 10:
        return {}

    # Convert tokens to numeric values
    nums = []
    for t in tokens:
        val = sum(ord(c) for c in t)
        nums.append(val)

    mean = sum(nums) / len(nums)
    variance = sum((x - mean) ** 2 for x in nums) / len(nums)
    if variance == 0:
        return {"lag_1": 1.0, "lag_2": 1.0, "lag_3": 1.0, "lag_4": 1.0, "lag_5": 1.0}

    results = {}
    for lag in range(1, 6):
        if lag >= len(nums):
            break
        covariance = sum((nums[i] - mean) * (nums[i + lag] - mean) for i in range(len(nums) - lag)) / (len(nums) - lag)
        results[f"lag_{lag}"] = round(covariance / variance, 4)

    return results


def _block_frequency_test(data: str, block_size: int = 8) -> dict:
    """Sliding block entropy test."""
    if len(data) < block_size * 2:
        return {}

    blocks = [data[i:i + block_size] for i in range(len(data) - block_size + 1)]
    from collections import Counter
    freq = Counter(blocks)
    total = len(blocks)

    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    max_entropy = math.log2(min(total, 256 ** block_size))

    return {
        "block_size": block_size,
        "unique_blocks": len(freq),
        "total_blocks": total,
        "block_entropy": round(entropy, 4),
        "max_entropy": round(max_entropy, 4),
        "ratio": round(entropy / max_entropy, 4) if max_entropy > 0 else 0,
    }


def _token_format_analysis(tokens: list[str]) -> dict:
    """Detect structure in tokens: timestamps, counters, MAC components."""
    import re

    if not tokens:
        return {}

    analysis = {
        "avg_length": round(sum(len(t) for t in tokens) / len(tokens), 1),
        "charset": "",
        "structure": "unknown",
        "components": [],
    }

    # Detect charset
    all_chars = set("".join(tokens))
    if all_chars <= set("0123456789"):
        analysis["charset"] = "numeric"
    elif all_chars <= set("0123456789abcdef"):
        analysis["charset"] = "hex"
    elif all_chars <= set("0123456789abcdefABCDEF"):
        analysis["charset"] = "hex_mixed"
    elif all_chars <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="):
        analysis["charset"] = "base64"
    elif all_chars <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"):
        analysis["charset"] = "base64url"
    else:
        analysis["charset"] = "mixed"

    # Check for timestamp component
    sample = tokens[0]
    if re.match(r"^\d{10}", sample):
        analysis["components"].append("unix_timestamp_prefix")
    if re.match(r"^\d{13}", sample):
        analysis["components"].append("millis_timestamp_prefix")

    # Check for sequential counter
    if analysis["charset"] in ("numeric", "hex"):
        try:
            vals = [int(t, 16) if analysis["charset"].startswith("hex") else int(t) for t in tokens[:10]]
            diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
            if len(set(diffs)) == 1:
                analysis["components"].append(f"sequential_counter(step={diffs[0]})")
                analysis["structure"] = "sequential"
        except (ValueError, IndexError):
            pass

    # Check for delimiter-separated structure
    for delim in ["-", ".", ":"]:
        parts_counts = [len(t.split(delim)) for t in tokens[:5]]
        if len(set(parts_counts)) == 1 and parts_counts[0] > 1:
            analysis["components"].append(f"delimited({delim}, {parts_counts[0]} parts)")
            analysis["structure"] = "delimited"
            break

    return analysis


def _predictability_score(tokens: list[str]) -> dict:
    """Attempt linear extrapolation on numeric portions of tokens."""
    import re

    if len(tokens) < 5:
        return {"predictable": False, "score": 0}

    # Extract numeric portions
    nums = []
    for t in tokens:
        digits = re.sub(r"[^0-9]", "", t)
        if digits:
            nums.append(int(digits))

    if len(nums) < 5:
        return {"predictable": False, "score": 0}

    # Check if linear extrapolation works
    diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
    if not diffs:
        return {"predictable": False, "score": 0}

    avg_diff = sum(diffs) / len(diffs)
    variance = sum((d - avg_diff) ** 2 for d in diffs) / len(diffs)

    if variance == 0:
        return {"predictable": True, "score": 100, "pattern": "constant_increment", "increment": avg_diff}

    # Low variance = more predictable
    cv = (variance ** 0.5) / abs(avg_diff) if avg_diff != 0 else float("inf")
    score = max(0, min(100, int(100 * (1 - min(cv, 1)))))

    return {
        "predictable": score > 70,
        "score": score,
        "avg_increment": round(avg_diff, 2),
        "coefficient_of_variation": round(cv, 4),
    }


def _check_sequential(tokens: list[str]) -> bool:
    """Check if tokens appear sequential."""
    if len(tokens) < 5:
        return False

    import re
    nums = []
    for t in tokens:
        digits = re.sub(r"[^0-9]", "", t)
        if digits:
            nums.append(int(digits))

    if len(nums) < 5:
        return False

    diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
    if len(set(diffs)) <= 2:
        return True

    return False


# ── FIPS 140-2 statistical tests (Task #33) ─────────────────────────────────

def _to_bits(data: str) -> list[int]:
    """Convert character data to a bit stream based on char values."""
    bits = []
    for c in data:
        val = ord(c)
        for i in range(7, -1, -1):
            bits.append((val >> i) & 1)
    return bits


def _fips_tests(data: str) -> dict:
    """Run FIPS 140-2 statistical randomness tests."""
    if len(data) < 100:
        return {}

    bits = _to_bits(data)
    n = len(bits)
    results = {}

    # 1. Monobit test: count of 1s should be roughly n/2
    ones = sum(bits)
    zeros = n - ones
    # For FIPS 140-2, with 20000 bits: 9725 < ones < 10275
    # We scale proportionally for our sample size
    expected = n / 2
    tolerance = 2.576 * math.sqrt(n / 4)  # 99% confidence interval
    monobit_pass = abs(ones - expected) < tolerance
    results["monobit"] = {
        "pass": monobit_pass,
        "ones": ones,
        "zeros": zeros,
        "expected": round(expected),
        "deviation": round(abs(ones - expected) / max(expected, 1) * 100, 2),
        "description": "Count of 1-bits should be close to 50%",
    }

    # 2. Poker test (nibble frequency)
    if n >= 64:
        nibble_size = 4
        num_nibbles = n // nibble_size
        nibbles = []
        for i in range(num_nibbles):
            val = 0
            for j in range(nibble_size):
                val = (val << 1) | bits[i * nibble_size + j]
            nibbles.append(val)

        freq = Counter(nibbles)
        # Chi-squared statistic
        k = 2 ** nibble_size  # 16 possible nibble values
        chi_sq = (k / num_nibbles) * sum(f * f for f in freq.values()) - num_nibbles
        # For 15 degrees of freedom, 99% critical value is 30.58
        poker_pass = chi_sq < 30.58
        results["poker"] = {
            "pass": poker_pass,
            "chi_squared": round(chi_sq, 2),
            "threshold": 30.58,
            "description": "Nibble (4-bit) frequency should be roughly uniform",
        }

    # 3. Runs test: count consecutive sequences of same bit
    if n >= 100:
        runs = {"1": Counter(), "0": Counter()}
        current_bit = bits[0]
        current_run = 1

        for i in range(1, n):
            if bits[i] == current_bit:
                current_run += 1
            else:
                runs[str(current_bit)][min(current_run, 6)] += 1
                current_bit = bits[i]
                current_run = 1
        runs[str(current_bit)][min(current_run, 6)] += 1

        total_runs = sum(sum(c.values()) for c in runs.values())
        expected_runs = (2 * ones * zeros) / n + 1
        variance = (2 * ones * zeros * (2 * ones * zeros - n)) / (n * n * (n - 1))
        runs_z = abs(total_runs - expected_runs) / max(math.sqrt(abs(variance)), 0.001)
        runs_pass = runs_z < 2.576  # 99% confidence
        results["runs"] = {
            "pass": runs_pass,
            "total_runs": total_runs,
            "expected": round(expected_runs, 1),
            "z_score": round(runs_z, 3),
            "description": "Number of bit runs should match expected distribution",
        }

    # 4. Chi-squared test on character frequency
    if len(data) >= 50:
        char_freq = Counter(data)
        unique = len(char_freq)
        expected_freq = len(data) / max(unique, 1)
        chi_sq = sum((count - expected_freq) ** 2 / max(expected_freq, 1)
                     for count in char_freq.values())
        # Critical value depends on degrees of freedom (unique - 1)
        # Approximate: for large df, use normal approximation
        df = unique - 1
        chi_threshold = df + 2.576 * math.sqrt(2 * df) if df > 0 else 999
        chi_pass = chi_sq < chi_threshold
        results["chi_squared"] = {
            "pass": chi_pass,
            "statistic": round(chi_sq, 2),
            "threshold": round(chi_threshold, 2),
            "degrees_of_freedom": df,
            "description": "Character frequency should be roughly uniform",
        }

    return results


# ── NIST SP 800-22 additional tests ───────────────────────────────────────

def _nist_cumulative_sums(bits: list[int]) -> dict:
    """NIST SP 800-22 Cumulative Sums (Cusums) test."""
    n = len(bits)
    if n < 100:
        return {}
    # Convert 0/1 to -1/+1
    x = [2 * b - 1 for b in bits]
    # Forward cusum
    s_fwd = []
    running = 0
    for v in x:
        running += v
        s_fwd.append(abs(running))
    z_fwd = max(s_fwd) if s_fwd else 0
    # Backward cusum
    s_bwd = []
    running = 0
    for v in reversed(x):
        running += v
        s_bwd.append(abs(running))
    z_bwd = max(s_bwd) if s_bwd else 0
    # P-value approximation using normal distribution
    z = min(z_fwd, z_bwd)
    # For large n, z/sqrt(n) should be moderate
    ratio = z / math.sqrt(n) if n > 0 else 0
    passed = ratio < 2.5  # Approximate threshold
    return {
        "pass": passed,
        "z_forward": z_fwd,
        "z_backward": z_bwd,
        "z_ratio": round(ratio, 4),
        "description": "Maximum excursion of cumulative sum should be moderate",
    }


def _nist_longest_run(bits: list[int]) -> dict:
    """NIST SP 800-22 Longest Run of Ones in a Block test."""
    n = len(bits)
    if n < 128:
        return {}
    block_size = 8
    num_blocks = n // block_size
    longest_runs = []
    for i in range(num_blocks):
        block = bits[i * block_size:(i + 1) * block_size]
        max_run = 0
        current = 0
        for b in block:
            if b == 1:
                current += 1
                max_run = max(max_run, current)
            else:
                current = 0
        longest_runs.append(max_run)
    # Expected distribution for block_size=8: bins for runs 0-1, 2, 3, 4+
    bins = [0, 0, 0, 0]
    for r in longest_runs:
        if r <= 1:
            bins[0] += 1
        elif r == 2:
            bins[1] += 1
        elif r == 3:
            bins[2] += 1
        else:
            bins[3] += 1
    # Expected proportions for M=8: π = [0.2148, 0.3672, 0.2305, 0.1875]
    pi = [0.2148, 0.3672, 0.2305, 0.1875]
    chi_sq = sum((bins[i] - num_blocks * pi[i]) ** 2 / max(num_blocks * pi[i], 0.001) for i in range(4))
    passed = chi_sq < 9.21  # df=3, alpha=0.025
    return {
        "pass": passed,
        "chi_squared": round(chi_sq, 4),
        "threshold": 9.21,
        "bin_counts": bins,
        "num_blocks": num_blocks,
        "description": "Longest run of ones in blocks should match expected distribution",
    }


def _nist_binary_matrix_rank(bits: list[int]) -> dict:
    """NIST SP 800-22 Binary Matrix Rank test (simplified)."""
    n = len(bits)
    m = 6  # Matrix size 6x6
    q = 6
    num_matrices = n // (m * q)
    if num_matrices < 10:
        return {}
    ranks = []
    for k in range(num_matrices):
        offset = k * m * q
        # Build matrix
        matrix = []
        for i in range(m):
            row = bits[offset + i * q:offset + (i + 1) * q]
            matrix.append(list(row))
        # Gaussian elimination to find rank
        rank = _matrix_rank_gf2(matrix, m, q)
        ranks.append(rank)
    # Count full rank, full-1, and other
    full = sum(1 for r in ranks if r == min(m, q))
    full_minus_1 = sum(1 for r in ranks if r == min(m, q) - 1)
    other = num_matrices - full - full_minus_1
    # Expected proportions for 6x6: 0.2888, 0.5776, 0.1336
    pi = [0.2888, 0.5776, 0.1336]
    observed = [full, full_minus_1, other]
    chi_sq = sum((observed[i] - num_matrices * pi[i]) ** 2 / max(num_matrices * pi[i], 0.001) for i in range(3))
    passed = chi_sq < 5.99  # df=2, alpha=0.05
    return {
        "pass": passed,
        "chi_squared": round(chi_sq, 4),
        "threshold": 5.99,
        "full_rank": full,
        "full_rank_minus_1": full_minus_1,
        "other": other,
        "num_matrices": num_matrices,
        "description": "Rank of random binary matrices should follow expected distribution",
    }


def _matrix_rank_gf2(matrix: list[list[int]], m: int, q: int) -> int:
    """Compute rank of a binary matrix over GF(2)."""
    mat = [row[:] for row in matrix]
    rank = 0
    for col in range(min(m, q)):
        # Find pivot
        pivot = -1
        for row in range(rank, m):
            if mat[row][col] == 1:
                pivot = row
                break
        if pivot == -1:
            continue
        mat[rank], mat[pivot] = mat[pivot], mat[rank]
        for row in range(m):
            if row != rank and mat[row][col] == 1:
                mat[row] = [(mat[row][j] ^ mat[rank][j]) for j in range(q)]
        rank += 1
    return rank


# ── Bit-level analysis ────────────────────────────────────────────────────

def _bit_position_independence(tokens: list[str]) -> dict:
    """Test if each bit position is independent (unbiased)."""
    if len(tokens) < 10:
        return {}
    # Find max token length in bits
    max_bits = max(len(t) * 8 for t in tokens)
    max_bits = min(max_bits, 128)  # Cap at 128 bits
    n = len(tokens)
    results = []
    biased_count = 0
    for pos in range(max_bits):
        ones = 0
        for t in tokens:
            byte_idx = pos // 8
            bit_idx = 7 - (pos % 8)
            if byte_idx < len(t):
                if (ord(t[byte_idx]) >> bit_idx) & 1:
                    ones += 1
        proportion = ones / n
        # Chi-squared for single bit: (ones - n/2)^2 / (n/4)
        expected = n / 2
        chi = (ones - expected) ** 2 / max(expected / 2, 0.001)
        biased = chi > 6.635  # alpha=0.01
        if biased:
            biased_count += 1
        results.append({"position": pos, "ones_ratio": round(proportion, 4), "biased": biased})
    return {
        "total_positions": max_bits,
        "biased_positions": biased_count,
        "pass": biased_count <= max_bits * 0.05,  # Allow 5% biased
        "details": results[:32],  # First 32 for brevity
        "description": "Each bit position should be approximately 50/50",
    }


def _hamming_distance_analysis(tokens: list[str]) -> dict:
    """Analyze Hamming distances between consecutive tokens."""
    if len(tokens) < 5:
        return {}
    distances = []
    for i in range(len(tokens) - 1):
        a, b = tokens[i], tokens[i + 1]
        min_len = min(len(a), len(b))
        dist = 0
        for j in range(min_len):
            xor = ord(a[j]) ^ ord(b[j])
            dist += bin(xor).count("1")
        # Add remaining bits from longer string
        dist += abs(len(a) - len(b)) * 4  # Approximate
        distances.append(dist)
    avg_dist = sum(distances) / len(distances) if distances else 0
    min_dist = min(distances) if distances else 0
    max_dist = max(distances) if distances else 0
    variance = sum((d - avg_dist) ** 2 for d in distances) / len(distances) if distances else 0
    # Good randomness: high average distance, low variance relative to mean
    max_possible = max(len(t) for t in tokens) * 8
    ratio = avg_dist / max_possible if max_possible > 0 else 0
    return {
        "avg_distance": round(avg_dist, 2),
        "min_distance": min_dist,
        "max_distance": max_dist,
        "variance": round(variance, 2),
        "distance_ratio": round(ratio, 4),
        "pass": ratio > 0.3,  # At least 30% of bits should change
        "description": "Hamming distance between consecutive tokens should be high and consistent",
    }


# ── Token source comparison ──────────────────────────────────────────────

def compare_token_sources(results: list[dict]) -> dict:
    """Compare entropy metrics across multiple token sources."""
    if len(results) < 2:
        return {"error": "Need at least 2 sources to compare"}
    comparison = []
    for r in results:
        comparison.append({
            "source": r.get("source", "unknown"),
            "entropy_bits": r.get("entropy_bits", 0),
            "char_entropy": r.get("char_entropy", 0),
            "rating": r.get("rating", "unknown"),
            "unique_ratio": r.get("unique_ratio", 0),
        })
    # Sort by entropy
    comparison.sort(key=lambda x: x["entropy_bits"], reverse=True)
    best = comparison[0]
    worst = comparison[-1]
    return {
        "sources": comparison,
        "best": best["source"],
        "worst": worst["source"],
        "entropy_range": round(best["entropy_bits"] - worst["entropy_bits"], 2),
        "recommendation": f"Use '{best['source']}' (highest entropy: {best['entropy_bits']} bits)" if best["entropy_bits"] > worst["entropy_bits"] else "All sources have similar entropy",
    }


async def _extract_token(
    response: httpx.Response,
    req: SequencerRequest,
) -> str | None:
    """Extract a token from an HTTP response."""
    if req.token_location == "header":
        return response.headers.get(req.token_name)

    elif req.token_location == "cookie":
        for cookie_header in response.headers.get_list("set-cookie"):
            if cookie_header.startswith(req.token_name + "="):
                value = cookie_header.split("=", 1)[1].split(";")[0]
                return value
        return None

    elif req.token_location == "body_regex":
        match = safe_search(req.token_name, response.text)
        if match:
            return match.group(1) if match.groups() else match.group(0)
        return None

    return None


async def _collect_tokens(job: SequencerResult, req: SequencerRequest) -> None:
    """Collect tokens by repeatedly sending the request."""
    cancel_event = _cancel_events.get(job.job_id)
    sem = asyncio.Semaphore(req.concurrency)

    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
        async def fetch_one():
            if cancel_event and cancel_event.is_set():
                return
            async with sem:
                if cancel_event and cancel_event.is_set():
                    return
                try:
                    response = await client.request(
                        method=req.method,
                        url=req.url,
                        headers=req.headers or {},
                        content=req.body.encode() if req.body else None,
                    )
                    token = await _extract_token(response, req)
                    if token:
                        job.tokens.append(token)
                    job.collected += 1
                except Exception as e:
                    log.warning(f"[sequencer] Token collection error: {e}")
                    job.collected += 1

        tasks = [asyncio.create_task(fetch_one()) for _ in range(req.sample_count)]
        await asyncio.gather(*tasks, return_exceptions=True)

    if cancel_event and cancel_event.is_set():
        job.status = "cancelled"
    else:
        metrics = _calculate_entropy(job.tokens)
        job.entropy_bits = metrics["entropy_bits"]
        job.char_frequency = metrics["char_frequency"]
        job.char_entropy = metrics["char_entropy"]
        job.length_min = metrics["length_min"]
        job.length_max = metrics["length_max"]
        job.length_avg = metrics["length_avg"]
        job.rating = metrics["rating"]
        job.analysis = metrics["analysis"]
        job.status = "completed"

    _cancel_events.pop(job.job_id, None)
    log.info(f"[sequencer] Job {job.job_id}: {job.status}, {len(job.tokens)} tokens collected")


async def start_sequencer(req: SequencerRequest) -> SequencerResult:
    job_id = str(uuid.uuid4())[:8]
    job = SequencerResult(job_id=job_id, sample_count=req.sample_count)
    state.sequencer_jobs[job_id] = job

    cancel_event = asyncio.Event()
    _cancel_events[job_id] = cancel_event

    log.info(f"[sequencer] Starting {job_id}: {req.sample_count} samples from {req.url}")
    asyncio.create_task(_collect_tokens(job, req))
    return job


def cancel_sequencer(job_id: str) -> bool:
    if job_id not in state.sequencer_jobs:
        return False
    event = _cancel_events.get(job_id)
    if event:
        event.set()
    state.sequencer_jobs[job_id].status = "cancelled"
    return True
