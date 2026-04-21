"""Tests for engine.core.quality_gates module.

Covers ErrorClassifier, CORSValidator, StateChangeVerifier,
SubmissionGatekeeper, and ConfidenceScorer.
"""

import pytest

from engine.core.quality_gates import (
    ConfidenceScorer,
    CORSValidator,
    ErrorClassifier,
    InfoDisclosureClassifier,
    StateChangeVerifier,
    SubmissionGatekeeper,
    run_all_gates,
)


# ---------------------------------------------------------------------------
# ErrorClassifier.classify
# ---------------------------------------------------------------------------

class TestErrorClassifier:
    """Tests for ErrorClassifier.classify across HTTP, gRPC, and GraphQL."""

    def test_http_403_not_vulnerability(self):
        result = ErrorClassifier.classify(403, "", protocol="http")
        assert result["is_vulnerability"] is False
        assert result["category"] == "http_access_denied"
        assert result["confidence"] >= 0.9

    def test_http_500_with_stack_trace_is_vuln(self):
        body = 'Traceback (most recent call last):\n  File "/app/views.py", line 42'
        result = ErrorClassifier.classify(500, body, protocol="http")
        assert result["is_vulnerability"] is True
        assert result["category"] == "info_disclosure_stack_trace"

    def test_http_500_without_trace_not_vuln(self):
        result = ErrorClassifier.classify(500, "Internal Server Error", protocol="http")
        assert result["is_vulnerability"] is False
        assert result["category"] == "http_server_error"

    def test_grpc_permission_denied_not_vuln(self):
        result = ErrorClassifier.classify(7, "", protocol="grpc")
        assert result["is_vulnerability"] is False
        assert result["category"] == "grpc_permission_denied"

    def test_grpc_unauthenticated_not_vuln(self):
        result = ErrorClassifier.classify(16, "", protocol="grpc")
        assert result["is_vulnerability"] is False
        assert result["category"] == "grpc_unauthenticated"

    def test_graphql_auth_error_not_vuln(self):
        body = '{"errors": [{"message": "Unauthenticated - please log in"}], "data": null}'
        result = ErrorClassifier.classify(200, body, protocol="graphql")
        assert result["is_vulnerability"] is False
        assert result["category"] == "graphql_auth_enforced"

    def test_graphql_typename_only_not_vuln(self):
        body = '{"data": {"user": {"__typename": "User"}}}'
        result = ErrorClassifier.classify(200, body, protocol="graphql")
        assert result["is_vulnerability"] is False
        assert result["category"] == "graphql_typename_only"

    def test_graphql_null_data_not_vuln(self):
        body = '{"data": null}'
        result = ErrorClassifier.classify(200, body, protocol="graphql")
        assert result["is_vulnerability"] is False
        assert result["category"] == "graphql_null_data"


# ---------------------------------------------------------------------------
# CORSValidator.is_exploitable
# ---------------------------------------------------------------------------

class TestCORSValidator:
    """Tests for CORSValidator.is_exploitable."""

    def test_wildcard_with_credentials_blocked_by_browser(self):
        result = CORSValidator.is_exploitable("*", "true", "https://evil.com")
        assert result["exploitable"] is False
        assert result["severity"] == "INFO"

    def test_reflected_origin_with_credentials_exploitable(self):
        origin = "https://evil.com"
        result = CORSValidator.is_exploitable(origin, "true", origin)
        assert result["exploitable"] is True
        assert result["severity"] == "HIGH"

    def test_null_origin_with_credentials_exploitable(self):
        result = CORSValidator.is_exploitable("null", "true", "https://evil.com")
        assert result["exploitable"] is True
        assert result["severity"] == "MEDIUM"

    def test_reflected_origin_without_credentials_not_exploitable(self):
        origin = "https://evil.com"
        result = CORSValidator.is_exploitable(origin, "", origin)
        assert result["exploitable"] is False
        assert result["severity"] == "LOW"


# ---------------------------------------------------------------------------
# StateChangeVerifier.verify_state_change
# ---------------------------------------------------------------------------

class TestStateChangeVerifier:
    """Tests for StateChangeVerifier.verify_state_change."""

    def test_identical_states_not_verified(self):
        state = {"user": "alice", "balance": 100}
        result = StateChangeVerifier.verify_state_change(state, state, "idor")
        assert result["verified"] is False
        assert "No change" in result["evidence"]

    def test_dict_state_change_verified(self):
        before = {"user": "alice", "role": "user"}
        after = {"user": "alice", "role": "admin"}
        result = StateChangeVerifier.verify_state_change(before, after, "privilege_escalation")
        assert result["verified"] is True
        assert "role" in result["evidence"]

    def test_string_state_change_verified(self):
        result = StateChangeVerifier.verify_state_change(
            "logged out", "logged in as admin", "auth_bypass"
        )
        assert result["verified"] is True

    def test_xss_state_change_has_context_note(self):
        before = "<div>Hello</div>"
        after = '<div><script>alert(1)</script></div>'
        result = StateChangeVerifier.verify_state_change(before, after, "xss")
        assert result["verified"] is True
        assert "executable" in result["explanation"].lower()


# ---------------------------------------------------------------------------
# SubmissionGatekeeper.evaluate
# ---------------------------------------------------------------------------

class TestSubmissionGatekeeper:
    """Tests for SubmissionGatekeeper.evaluate."""

    def test_unverified_finding_rejected(self):
        finding = {
            "title": "IDOR on /api/users",
            "severity": "HIGH",
            "vuln_type": "idor",
            "evidence": "Got 200 OK",
            "target": "example.com",
            "verified": False,
            "state_change_proven": False,
        }
        result = SubmissionGatekeeper.evaluate(finding)
        assert result["submit"] is False
        assert result["confidence"] == 0.0

    def test_verified_high_with_state_change_submitted(self):
        finding = {
            "title": "IDOR on /api/users",
            "severity": "HIGH",
            "vuln_type": "idor",
            "evidence": "User A read User B private profile data including email, SSN, address",
            "target": "example.com",
            "verified": True,
            "state_change_proven": True,
        }
        result = SubmissionGatekeeper.evaluate(finding)
        assert result["submit"] is True
        assert result["confidence"] >= 0.7

    def test_info_severity_non_sensitive_rejected(self):
        finding = {
            "title": "Server version disclosed",
            "severity": "INFO",
            "vuln_type": "server_version",
            "evidence": "Apache/2.4.52",
            "target": "example.com",
            "verified": True,
            "state_change_proven": False,
        }
        result = SubmissionGatekeeper.evaluate(finding)
        assert result["submit"] is False

    def test_error_code_only_evidence_rejected(self):
        finding = {
            "title": "Some finding",
            "severity": "MEDIUM",
            "vuln_type": "idor",
            "evidence": "HTTP status code 200 returned, response code 200",
            "target": "example.com",
            "verified": True,
            "state_change_proven": True,
        }
        result = SubmissionGatekeeper.evaluate(finding)
        assert result["submit"] is False

    def test_verified_no_state_change_held(self):
        finding = {
            "title": "Potential CSRF",
            "severity": "MEDIUM",
            "vuln_type": "csrf",
            "evidence": "Cross-origin request was accepted without CSRF token but state not confirmed changed",
            "target": "example.com",
            "verified": True,
            "state_change_proven": False,
        }
        result = SubmissionGatekeeper.evaluate(finding)
        assert result["submit"] is False
        assert any("HOLD" in r for r in result["reasons"])


# ---------------------------------------------------------------------------
# ConfidenceScorer.score
# ---------------------------------------------------------------------------

class TestConfidenceScorer:
    """Tests for ConfidenceScorer.score."""

    def test_perfect_score_grade_a(self):
        finding = {
            "verified_with_curl": 1.0,
            "state_change_proven": 1.0,
            "severity_appropriate": 1.0,
            "not_false_positive_pattern": 1.0,
            "clear_impact": 1.0,
        }
        result = ConfidenceScorer.score(finding)
        assert result["score"] == 1.0
        assert result["grade"] == "A"
        assert "submission" in result["recommendation"].lower()

    def test_zero_score_grade_f(self):
        result = ConfidenceScorer.score({})
        assert result["score"] == 0.0
        assert result["grade"] == "F"
        assert "do not submit" in result["recommendation"].lower()

    def test_partial_score_grade_c(self):
        finding = {
            "verified_with_curl": 1.0,
            "state_change_proven": 0.5,
            "severity_appropriate": 0.5,
            "not_false_positive_pattern": 0.0,
            "clear_impact": 0.5,
        }
        result = ConfidenceScorer.score(finding)
        # 0.30*1 + 0.25*0.5 + 0.15*0.5 + 0.15*0 + 0.15*0.5 = 0.30+0.125+0.075+0+0.075 = 0.575
        assert 0.55 <= result["score"] <= 0.60
        assert result["grade"] == "C"

    def test_values_clamped_to_0_1(self):
        finding = {
            "verified_with_curl": 5.0,
            "state_change_proven": -1.0,
            "severity_appropriate": 1.0,
            "not_false_positive_pattern": 1.0,
            "clear_impact": 1.0,
        }
        result = ConfidenceScorer.score(finding)
        assert result["factors"]["verified_with_curl"] == 1.0
        assert result["factors"]["state_change_proven"] == 0.0
