"""
Unit tests for engine.core.response_diff - ResponseDiff class.

Covers:
  - diff_responses() general HTTP comparison
  - diff_for_idor() IDOR-specific detection
  - diff_for_auth_bypass() auth bypass detection
  - _extract_data_tokens() PII/secret extraction
  - _diff_graphql_bodies() GraphQL-specific comparison
"""

import json
import pytest
from engine.core.response_diff import ResponseDiff, _looks_like_graphql, _is_noise_string


# ---------------------------------------------------------------------------
# Fixtures - sample HTTP responses
# ---------------------------------------------------------------------------

def _resp(status: int = 200, headers: dict = None, body: str = "") -> dict:
    return {
        "status_code": status,
        "headers": headers or {},
        "body": body,
    }


BASELINE_200 = _resp(200, {"Content-Type": "application/json"}, '{"ok": true}')
EXPLOIT_200_DIFFERENT = _resp(
    200,
    {"Content-Type": "application/json", "X-Debug": "1"},
    '{"ok": true, "user": "admin@example.com", "id": "d290f1ee-6c54-4b01-90e6-d701748f0851"}',
)
DENIED_403 = _resp(403, {}, '{"error": "forbidden"}')
DENIED_401 = _resp(401, {}, '{"error": "unauthorized"}')
SERVER_ERROR_500 = _resp(500, {}, "Internal Server Error")

GRAPHQL_OK = _resp(200, {}, json.dumps({"data": {"user": {"name": "Alice"}}}))
GRAPHQL_ERROR = _resp(200, {}, json.dumps({"errors": [{"message": "not authorized"}]}))
GRAPHQL_ERROR_WITH_DATA = _resp(
    200, {}, json.dumps({"errors": [{"message": "partial"}], "data": {"user": None}})
)


# ---------------------------------------------------------------------------
# diff_responses tests
# ---------------------------------------------------------------------------

class TestDiffResponses:
    def test_identical_responses_no_effect(self):
        result = ResponseDiff.diff_responses(BASELINE_200, BASELINE_200)
        assert result["is_different"] is False
        assert result["assessment"] == "no_effect"
        assert result["body_similarity"] == 1.0

    def test_status_change_401_to_200_high_confidence(self):
        result = ResponseDiff.diff_responses(DENIED_401, BASELINE_200)
        assert result["status_changed"] is True
        assert result["confidence"] >= 0.5
        assert result["assessment"] == "exploit_worked"

    def test_status_change_200_to_500(self):
        result = ResponseDiff.diff_responses(BASELINE_200, SERVER_ERROR_500)
        assert result["status_changed"] is True
        assert "500" in result["differences"][0]

    def test_new_data_exposed_detected(self):
        result = ResponseDiff.diff_responses(BASELINE_200, EXPLOIT_200_DIFFERENT)
        assert result["new_data_exposed"] is True
        # Should find the email and/or UUID in new tokens
        token_diff = " ".join(result["differences"])
        assert "admin@example.com" in token_diff or "d290f1ee" in token_diff

    def test_header_change_detected(self):
        baseline = _resp(200, {"X-Custom": "a"}, "body")
        exploit = _resp(200, {"X-Custom": "b"}, "body")
        result = ResponseDiff.diff_responses(baseline, exploit)
        assert result["is_different"] is True
        assert any("x-custom" in d.lower() for d in result["differences"])

    def test_error_handling_returns_inconclusive(self):
        # Pass garbage that will cause attribute errors inside
        result = ResponseDiff.diff_responses(None, None)  # type: ignore
        assert result["assessment"] == "inconclusive"
        assert result["is_different"] is False


# ---------------------------------------------------------------------------
# diff_for_idor tests
# ---------------------------------------------------------------------------

class TestDiffForIdor:
    def test_idor_detected_when_victim_data_leaks(self):
        auth_user = _resp(200, {}, '{"email": "attacker@test.com", "id": 111}')
        victim_user = _resp(200, {}, '{"email": "victim@secret.com", "id": 222}')
        cross_access = _resp(200, {}, '{"email": "victim@secret.com", "id": 222}')

        result = ResponseDiff.diff_for_idor(auth_user, victim_user, cross_access)
        assert result["is_idor"] is True
        assert len(result["data_leaked"]) > 0

    def test_no_idor_when_access_denied(self):
        auth_user = _resp(200, {}, '{"email": "attacker@test.com"}')
        victim_user = _resp(200, {}, '{"email": "victim@secret.com"}')
        cross_access = _resp(403, {}, '{"error": "forbidden"}')

        result = ResponseDiff.diff_for_idor(auth_user, victim_user, cross_access)
        assert result["is_idor"] is False

    def test_idor_by_high_similarity(self):
        """When body is nearly identical to victim but token extraction misses specifics."""
        body = '{"status": "ok", "data": [1, 2, 3, 4, 5]}'
        auth_user = _resp(200, {}, '{"status": "ok", "data": [9, 8, 7]}')
        victim_user = _resp(200, {}, body)
        cross_access = _resp(200, {}, body)  # exact match to victim

        result = ResponseDiff.diff_for_idor(auth_user, victim_user, cross_access)
        assert result["is_idor"] is True


# ---------------------------------------------------------------------------
# diff_for_auth_bypass tests
# ---------------------------------------------------------------------------

class TestDiffForAuthBypass:
    def test_bypass_detected_when_bodies_match(self):
        auth_body = json.dumps({
            "user": "admin@corp.com",
            "role": "admin",
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "secret_key": "sk_live_aBcDeFgHiJkLmNoPqRsT",
        })
        authenticated = _resp(200, {}, auth_body)
        unauthenticated = _resp(200, {}, auth_body)

        result = ResponseDiff.diff_for_auth_bypass(authenticated, unauthenticated)
        assert result["is_bypass"] is True
        assert result["data_similarity"] > 0.9

    def test_no_bypass_when_unauth_gets_401(self):
        authenticated = _resp(200, {}, '{"data": "secret"}')
        unauthenticated = _resp(401, {}, '{"error": "unauthorized"}')

        result = ResponseDiff.diff_for_auth_bypass(authenticated, unauthenticated)
        assert result["is_bypass"] is False

    def test_graphql_200_with_errors_not_bypass(self):
        authenticated = _resp(200, {}, json.dumps({"data": {"user": "Alice"}}))
        unauthenticated = _resp(
            200, {},
            json.dumps({"errors": [{"message": "not authorized"}]}),
        )

        result = ResponseDiff.diff_for_auth_bypass(authenticated, unauthenticated)
        assert result["is_bypass"] is False


# ---------------------------------------------------------------------------
# _extract_data_tokens tests
# ---------------------------------------------------------------------------

class TestExtractDataTokens:
    def test_extracts_emails(self):
        tokens = ResponseDiff._extract_data_tokens("contact us at user@example.com")
        assert "user@example.com" in tokens

    def test_extracts_uuids(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        tokens = ResponseDiff._extract_data_tokens(f'{{"id": "{uuid}"}}')
        assert uuid in tokens

    def test_extracts_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        tokens = ResponseDiff._extract_data_tokens(f"token={jwt}")
        assert jwt in tokens

    def test_extracts_numeric_ids(self):
        tokens = ResponseDiff._extract_data_tokens('{"user_id": 123456}')
        assert "123456" in tokens

    def test_empty_body_returns_empty_set(self):
        assert ResponseDiff._extract_data_tokens("") == set()
        assert ResponseDiff._extract_data_tokens(None) == set()  # type: ignore


# ---------------------------------------------------------------------------
# _diff_graphql_bodies tests
# ---------------------------------------------------------------------------

class TestDiffGraphqlBodies:
    def test_baseline_errors_exploit_none(self):
        baseline = json.dumps({"errors": [{"message": "denied"}]})
        exploit = json.dumps({"data": {"user": "Alice"}})
        diffs = ResponseDiff._diff_graphql_bodies(baseline, exploit)
        assert any("bypass" in d.lower() for d in diffs)

    def test_exploit_triggers_new_errors(self):
        baseline = json.dumps({"data": {"user": "Alice"}})
        exploit = json.dumps({"errors": [{"message": "crash"}]})
        diffs = ResponseDiff._diff_graphql_bodies(baseline, exploit)
        assert any("triggered" in d.lower() for d in diffs)

    def test_null_data_to_real_data(self):
        baseline = json.dumps({"data": None})
        exploit = json.dumps({"data": {"secret": "value"}})
        diffs = ResponseDiff._diff_graphql_bodies(baseline, exploit)
        assert any("returned GraphQL data" in d for d in diffs)

    def test_invalid_json_returns_empty(self):
        diffs = ResponseDiff._diff_graphql_bodies("not json", "also not json")
        assert diffs == []


# ---------------------------------------------------------------------------
# Module-level helper tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_looks_like_graphql_true(self):
        assert _looks_like_graphql(json.dumps({"data": {"x": 1}})) is True
        assert _looks_like_graphql(json.dumps({"errors": []})) is True

    def test_looks_like_graphql_false(self):
        assert _looks_like_graphql("") is False
        assert _looks_like_graphql('{"ok": true}') is False
        assert _looks_like_graphql("not json at all") is False

    def test_is_noise_string(self):
        assert _is_noise_string("application/json") is True
        assert _is_noise_string("https://example.com") is True
        assert _is_noise_string("Content-Type") is True
        assert _is_noise_string("abc123") is True  # short hex
        assert _is_noise_string("real_user_data_here") is False
