"""
Response Diff Engine - Compare baseline vs exploit HTTP responses.

Detects whether an exploit attempt caused a meaningful behavioral difference
in the target application by comparing response status codes, headers, body
content, and exposed data tokens.

Used by validators and agents to distinguish real vulnerabilities from
noise (HTTP 200 does NOT mean success, especially with GraphQL).
"""

import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple


class ResponseDiff:
    """Compare baseline vs exploit HTTP responses to detect real vulnerabilities."""

    # Minimum similarity threshold below which bodies are considered "different"
    SIMILARITY_THRESHOLD = 0.85

    # Minimum confidence to declare an exploit worked
    CONFIDENCE_THRESHOLD = 0.6

    # Headers that commonly vary between requests (ignore for diff purposes)
    NOISE_HEADERS = frozenset({
        'date', 'x-request-id', 'x-trace-id', 'x-amzn-requestid',
        'x-amzn-trace-id', 'cf-ray', 'set-cookie', 'age',
        'x-cache', 'x-served-by', 'x-timer', 'x-runtime',
        'x-response-time', 'etag', 'last-modified', 'expires',
        'content-length', 'transfer-encoding',
    })

    # ---------- Primary API ----------

    @staticmethod
    def diff_responses(baseline: Dict, exploit: Dict) -> Dict:
        """
        Compare two HTTP responses and determine if the exploit caused a
        meaningful difference.

        Args:
            baseline: {'status_code': int, 'headers': dict, 'body': str}
            exploit:  {'status_code': int, 'headers': dict, 'body': str}

        Returns:
            {
                'is_different': bool,
                'confidence': float,           # 0-1
                'differences': List[str],      # human-readable diffs
                'status_changed': bool,
                'body_similarity': float,      # 0=completely different, 1=identical
                'new_data_exposed': bool,      # exploit has data not in baseline
                'assessment': str,             # 'exploit_worked' | 'no_effect' | 'inconclusive'
            }
        """
        try:
            differences: List[str] = []
            confidence = 0.0

            b_status = baseline.get('status_code', 0)
            e_status = exploit.get('status_code', 0)
            b_headers = {k.lower(): v for k, v in (baseline.get('headers') or {}).items()}
            e_headers = {k.lower(): v for k, v in (exploit.get('headers') or {}).items()}
            b_body = baseline.get('body', '') or ''
            e_body = exploit.get('body', '') or ''

            # --- Status code ---
            status_changed = (b_status != e_status)
            if status_changed:
                differences.append(f"Status code changed: {b_status} -> {e_status}")
                # Meaningful status transitions boost confidence
                if b_status in (401, 403) and e_status == 200:
                    confidence += 0.5
                elif b_status == 200 and e_status in (500, 502, 503):
                    confidence += 0.2
                elif b_status == 404 and e_status == 200:
                    confidence += 0.3
                else:
                    confidence += 0.15

            # --- Headers ---
            header_diffs = ResponseDiff._diff_headers(b_headers, e_headers)
            if header_diffs:
                differences.extend(header_diffs)
                confidence += min(0.1 * len(header_diffs), 0.2)

            # --- Body similarity ---
            body_similarity = ResponseDiff._body_similarity(b_body, e_body)
            if body_similarity < 0.5:
                differences.append(
                    f"Response body significantly different (similarity: {body_similarity:.2f})"
                )
                confidence += 0.3
            elif body_similarity < ResponseDiff.SIMILARITY_THRESHOLD:
                differences.append(
                    f"Response body partially different (similarity: {body_similarity:.2f})"
                )
                confidence += 0.15

            # --- New data exposed ---
            baseline_tokens = ResponseDiff._extract_data_tokens(b_body)
            exploit_tokens = ResponseDiff._extract_data_tokens(e_body)
            new_tokens = exploit_tokens - baseline_tokens
            new_data_exposed = len(new_tokens) > 0

            if new_data_exposed:
                # Cap the list so we don't dump hundreds of tokens
                sample = sorted(new_tokens)[:10]
                differences.append(
                    f"New data tokens in exploit response ({len(new_tokens)} total): "
                    f"{sample}"
                )
                confidence += min(0.05 * len(new_tokens), 0.3)

            # --- GraphQL special case ---
            # GraphQL always returns 200; must inspect errors array
            if _looks_like_graphql(e_body):
                gql_diff = ResponseDiff._diff_graphql_bodies(b_body, e_body)
                if gql_diff:
                    differences.extend(gql_diff)
                    confidence += 0.15

            # Clamp confidence
            confidence = min(confidence, 1.0)

            is_different = len(differences) > 0

            # Assessment
            if confidence >= ResponseDiff.CONFIDENCE_THRESHOLD and is_different:
                assessment = 'exploit_worked'
            elif is_different and confidence > 0.2:
                assessment = 'inconclusive'
            else:
                assessment = 'no_effect'

            return {
                'is_different': is_different,
                'confidence': round(confidence, 3),
                'differences': differences,
                'status_changed': status_changed,
                'body_similarity': round(body_similarity, 4),
                'new_data_exposed': new_data_exposed,
                'assessment': assessment,
            }

        except Exception as exc:
            return {
                'is_different': False,
                'confidence': 0.0,
                'differences': [f"Error during diff: {exc}"],
                'status_changed': False,
                'body_similarity': 0.0,
                'new_data_exposed': False,
                'assessment': 'inconclusive',
            }

    @staticmethod
    def diff_for_idor(
        auth_user_response: Dict,
        victim_user_response: Dict,
        cross_access_response: Dict,
    ) -> Dict:
        """
        Specialized IDOR comparison.

        Args:
            auth_user_response:   User A accessing their OWN resource.
            victim_user_response: User B accessing their OWN resource (expected baseline).
            cross_access_response: User A accessing User B's resource (exploit attempt).

        Returns:
            {'is_idor': bool, 'evidence': str, 'data_leaked': List[str]}
        """
        try:
            victim_body = victim_user_response.get('body', '') or ''
            cross_body = cross_access_response.get('body', '') or ''
            auth_body = auth_user_response.get('body', '') or ''

            # Quick fail: if cross-access got an error status, no IDOR
            cross_status = cross_access_response.get('status_code', 0)
            if cross_status in (401, 403, 404):
                return {
                    'is_idor': False,
                    'evidence': f"Cross-access returned HTTP {cross_status} (access denied).",
                    'data_leaked': [],
                }

            # Extract data tokens from each response
            victim_tokens = ResponseDiff._extract_data_tokens(victim_body)
            auth_tokens = ResponseDiff._extract_data_tokens(auth_body)
            cross_tokens = ResponseDiff._extract_data_tokens(cross_body)

            # IDOR tokens = data present in BOTH victim's response and cross-access
            # but NOT in the auth user's own response
            leaked_tokens = (cross_tokens & victim_tokens) - auth_tokens

            # Also check body similarity between cross-access and victim
            similarity = ResponseDiff._body_similarity(cross_body, victim_body)

            if leaked_tokens:
                sample = sorted(leaked_tokens)[:15]
                evidence = (
                    f"Cross-access response contains {len(leaked_tokens)} data token(s) "
                    f"from victim's response that are NOT in attacker's own data. "
                    f"Body similarity to victim: {similarity:.2f}. "
                    f"Leaked tokens (sample): {sample}"
                )
                return {
                    'is_idor': True,
                    'evidence': evidence,
                    'data_leaked': sorted(leaked_tokens),
                }
            elif similarity > 0.9 and cross_status == 200:
                # Very similar bodies and success status -- likely IDOR even if
                # token extraction didn't catch specific items
                evidence = (
                    f"Cross-access body is {similarity:.2f} similar to victim's response "
                    f"(HTTP {cross_status}). High probability of IDOR but no unique "
                    f"victim-only tokens extracted. Manual review recommended."
                )
                return {
                    'is_idor': True,
                    'evidence': evidence,
                    'data_leaked': [],
                }
            else:
                evidence = (
                    f"No victim-specific data found in cross-access response. "
                    f"Body similarity to victim: {similarity:.2f}. "
                    f"HTTP status: {cross_status}."
                )
                return {
                    'is_idor': False,
                    'evidence': evidence,
                    'data_leaked': [],
                }

        except Exception as exc:
            return {
                'is_idor': False,
                'evidence': f"Error during IDOR diff: {exc}",
                'data_leaked': [],
            }

    @staticmethod
    def diff_for_auth_bypass(
        authenticated_response: Dict,
        unauthenticated_response: Dict,
    ) -> Dict:
        """
        Check if unauthenticated access returns the same data as authenticated.

        Returns:
            {'is_bypass': bool, 'evidence': str, 'data_similarity': float}
        """
        try:
            auth_body = authenticated_response.get('body', '') or ''
            unauth_body = unauthenticated_response.get('body', '') or ''
            auth_status = authenticated_response.get('status_code', 0)
            unauth_status = unauthenticated_response.get('status_code', 0)

            # If unauth got a clear denial, no bypass
            if unauth_status in (401, 403):
                return {
                    'is_bypass': False,
                    'evidence': f"Unauthenticated request returned HTTP {unauth_status}.",
                    'data_similarity': 0.0,
                }

            similarity = ResponseDiff._body_similarity(auth_body, unauth_body)

            auth_tokens = ResponseDiff._extract_data_tokens(auth_body)
            unauth_tokens = ResponseDiff._extract_data_tokens(unauth_body)
            shared = auth_tokens & unauth_tokens

            # GraphQL special case: HTTP 200 with errors is NOT a bypass
            if _looks_like_graphql(unauth_body):
                try:
                    parsed = json.loads(unauth_body)
                    if parsed.get('errors') and not parsed.get('data'):
                        return {
                            'is_bypass': False,
                            'evidence': (
                                "GraphQL returned HTTP 200 but with errors[] and no data. "
                                "This is NOT an auth bypass."
                            ),
                            'data_similarity': similarity,
                        }
                    if parsed.get('data') is None:
                        return {
                            'is_bypass': False,
                            'evidence': "GraphQL data field is null. Not a bypass.",
                            'data_similarity': similarity,
                        }
                except (json.JSONDecodeError, TypeError):
                    pass

            if similarity > 0.9 and auth_tokens and shared:
                evidence = (
                    f"Auth bypass likely: unauthenticated response is {similarity:.2f} "
                    f"similar to authenticated. {len(shared)} shared data tokens. "
                    f"HTTP status: auth={auth_status}, unauth={unauth_status}."
                )
                return {
                    'is_bypass': True,
                    'evidence': evidence,
                    'data_similarity': round(similarity, 4),
                }
            elif similarity > 0.7 and len(shared) > 3:
                evidence = (
                    f"Possible auth bypass: similarity {similarity:.2f}, "
                    f"{len(shared)} shared tokens. Needs manual verification."
                )
                return {
                    'is_bypass': True,
                    'evidence': evidence,
                    'data_similarity': round(similarity, 4),
                }
            else:
                evidence = (
                    f"No auth bypass detected. Similarity: {similarity:.2f}. "
                    f"Shared tokens: {len(shared)}. "
                    f"HTTP status: auth={auth_status}, unauth={unauth_status}."
                )
                return {
                    'is_bypass': False,
                    'evidence': evidence,
                    'data_similarity': round(similarity, 4),
                }

        except Exception as exc:
            return {
                'is_bypass': False,
                'evidence': f"Error during auth bypass diff: {exc}",
                'data_similarity': 0.0,
            }

    # ---------- Internal helpers ----------

    @staticmethod
    def _body_similarity(body1: str, body2: str) -> float:
        """Compute similarity ratio between two response bodies (0-1)."""
        if not body1 and not body2:
            return 1.0
        if not body1 or not body2:
            return 0.0

        # For very large bodies, compare a truncated version to keep it fast
        max_len = 50_000
        b1 = body1[:max_len]
        b2 = body2[:max_len]

        return SequenceMatcher(None, b1, b2).ratio()

    @staticmethod
    def _extract_data_tokens(body: str) -> Set[str]:
        """
        Extract meaningful data tokens from a response body.

        Looks for: emails, UUIDs, JWT fragments, numeric IDs, and
        quoted strings longer than 5 characters.
        """
        if not body:
            return set()

        tokens: Set[str] = set()

        # Emails
        tokens.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body))

        # UUIDs
        tokens.update(re.findall(
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            body,
        ))

        # JWT tokens (header.payload.signature)
        tokens.update(re.findall(
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
            body,
        ))

        # Numeric IDs (standalone integers >= 3 digits, not inside larger words)
        for m in re.findall(r'(?<![a-zA-Z0-9_])\d{3,18}(?![a-zA-Z0-9_])', body):
            tokens.add(m)

        # Quoted strings longer than 5 characters (both single and double quotes)
        for m in re.findall(r'"([^"]{6,120})"', body):
            # Filter out common noise
            if not _is_noise_string(m):
                tokens.add(m)

        return tokens

    @staticmethod
    def _diff_headers(
        baseline_headers: Dict[str, str],
        exploit_headers: Dict[str, str],
    ) -> List[str]:
        """Compare response headers, ignoring known-noisy ones."""
        diffs: List[str] = []
        all_keys = set(baseline_headers.keys()) | set(exploit_headers.keys())

        for key in sorted(all_keys):
            if key in ResponseDiff.NOISE_HEADERS:
                continue
            b_val = baseline_headers.get(key)
            e_val = exploit_headers.get(key)
            if b_val != e_val:
                if b_val is None:
                    diffs.append(f"New header in exploit: {key}: {e_val}")
                elif e_val is None:
                    diffs.append(f"Header removed in exploit: {key}")
                else:
                    diffs.append(f"Header changed: {key}: '{b_val}' -> '{e_val}'")

        return diffs

    @staticmethod
    def _diff_graphql_bodies(baseline_body: str, exploit_body: str) -> List[str]:
        """
        Compare two GraphQL response bodies, focusing on errors and data fields.
        """
        diffs: List[str] = []
        try:
            b_parsed = json.loads(baseline_body) if baseline_body else {}
            e_parsed = json.loads(exploit_body) if exploit_body else {}
        except (json.JSONDecodeError, TypeError):
            return diffs

        b_errors = b_parsed.get('errors', [])
        e_errors = e_parsed.get('errors', [])

        if b_errors and not e_errors:
            diffs.append("Baseline had GraphQL errors but exploit did not (possible bypass)")
        elif not b_errors and e_errors:
            diffs.append("Exploit triggered GraphQL errors that baseline did not have")

        b_data = b_parsed.get('data')
        e_data = e_parsed.get('data')

        if b_data is None and e_data is not None:
            diffs.append("Exploit returned GraphQL data where baseline returned null")
        elif b_data is not None and e_data is None:
            diffs.append("Exploit returned null data where baseline had data")

        return diffs


# ---------- Module-level helpers ----------

def _looks_like_graphql(body: str) -> bool:
    """Heuristic: does the body look like a GraphQL JSON response?"""
    if not body:
        return False
    # Quick check before trying to parse
    if '"data"' not in body and '"errors"' not in body:
        return False
    try:
        parsed = json.loads(body)
        return isinstance(parsed, dict) and ('data' in parsed or 'errors' in parsed)
    except (json.JSONDecodeError, TypeError):
        return False


def _is_noise_string(s: str) -> bool:
    """Filter out common noise strings that aren't meaningful data."""
    noise_prefixes = (
        'application/', 'text/', 'image/', 'multipart/',
        'http://', 'https://', 'charset=',
    )
    noise_exact = {
        'Content-Type', 'content-type', 'Accept', 'accept',
        'null', 'undefined', 'true', 'false', 'object Object',
    }
    if s in noise_exact:
        return True
    for prefix in noise_prefixes:
        if s.startswith(prefix):
            return True
    # Pure hex or base64-ish gibberish shorter than 10 chars
    if len(s) < 10 and re.match(r'^[a-fA-F0-9]+$', s):
        return True
    return False
