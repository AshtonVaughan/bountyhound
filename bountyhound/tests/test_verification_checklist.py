"""
Unit tests for engine.verification.checklist — Stage A 5-gate deterministic check.

Coverage
--------
TestGateReproducibility  (6 tests)  — Gate 1
TestGateScope            (7 tests)  — Gate 2
TestGateImpact           (5 tests)  — Gate 3
TestGateSeverity         (6 tests)  — Gate 4
TestGateDuplicate        (7 tests)  — Gate 5
TestFullChecklist        (5 tests)  — end-to-end checklist run
TestNormalisation        (4 tests)  — normalise_url / normalise_vuln_type helpers

Total: 43 tests
"""

import pytest

from engine.verification import (
    ChecklistInput,
    ChecklistResult,
    GateResult,
    VerificationChecklist,
)


# ---------------------------------------------------------------------------
# Shared helpers / factories
# ---------------------------------------------------------------------------

def make_finding(**kwargs) -> ChecklistInput:
    """
    Return a fully valid ChecklistInput with sensible defaults.

    Any keyword argument overrides the corresponding field, allowing each test
    to introduce exactly one defect at a time.
    """
    defaults = dict(
        url="https://example.com/api/users/42",
        vuln_type="IDOR",
        request_method="GET",
        request_body="",
        response_snippet='{"id":42,"email":"victim@example.com"}',
        impact_statement="An attacker can read any user profile without authorisation.",
        cvss_score=7.5,
        severity_label="high",
        clean_state_verified=True,
    )
    defaults.update(kwargs)
    return ChecklistInput(**defaults)


def make_checklist(**kwargs) -> VerificationChecklist:
    """
    Return a VerificationChecklist with sensible defaults.

    Defaults: allowed_scope covers example.com, blocked_scope is empty,
    no known_findings or disclosed_patterns.
    """
    defaults = dict(
        allowed_scope=["example.com", "*.example.com"],
        blocked_scope=[],
        known_findings=[],
        disclosed_patterns=[],
    )
    defaults.update(kwargs)
    return VerificationChecklist(**defaults)


# ---------------------------------------------------------------------------
# Gate 1 — REPRODUCIBILITY
# ---------------------------------------------------------------------------

class TestGateReproducibility:
    """Gate 1: evidence completeness."""

    def test_passes_with_complete_evidence(self):
        """A finding with all required fields and clean_state=True must pass."""
        checklist = make_checklist()
        finding = make_finding()
        result = checklist.run(finding)

        repro_gate = next(g for g in result.gates if g.gate_name == "REPRODUCIBILITY")
        assert repro_gate.passed, f"Expected REPRODUCIBILITY to pass: {repro_gate.reason}"

    def test_fails_when_response_snippet_missing(self):
        """Empty response_snippet must fail Gate 1."""
        checklist = make_checklist()
        finding = make_finding(response_snippet="")

        result = checklist.run(finding)
        repro_gate = next(g for g in result.gates if g.gate_name == "REPRODUCIBILITY")
        assert not repro_gate.passed
        assert "response_snippet" in repro_gate.reason.lower()

    def test_fails_when_clean_state_not_verified(self):
        """clean_state_verified=False must fail Gate 1."""
        checklist = make_checklist()
        finding = make_finding(clean_state_verified=False)

        result = checklist.run(finding)
        repro_gate = next(g for g in result.gates if g.gate_name == "REPRODUCIBILITY")
        assert not repro_gate.passed
        assert "clean_state" in repro_gate.reason.lower()

    def test_fails_when_request_method_empty(self):
        """Empty request_method must fail Gate 1."""
        checklist = make_checklist()
        finding = make_finding(request_method="")

        result = checklist.run(finding)
        repro_gate = next(g for g in result.gates if g.gate_name == "REPRODUCIBILITY")
        assert not repro_gate.passed
        assert "request_method" in repro_gate.reason.lower()

    def test_fails_when_url_empty(self):
        """Empty URL must fail Gate 1."""
        checklist = make_checklist()
        finding = make_finding(url="")

        result = checklist.run(finding)
        repro_gate = next(g for g in result.gates if g.gate_name == "REPRODUCIBILITY")
        assert not repro_gate.passed
        assert "url" in repro_gate.reason.lower()

    def test_fails_when_response_snippet_whitespace_only(self):
        """Whitespace-only response_snippet must fail Gate 1 (treated as empty)."""
        checklist = make_checklist()
        finding = make_finding(response_snippet="   ")

        result = checklist.run(finding)
        repro_gate = next(g for g in result.gates if g.gate_name == "REPRODUCIBILITY")
        assert not repro_gate.passed


# ---------------------------------------------------------------------------
# Gate 2 — SCOPE
# ---------------------------------------------------------------------------

class TestGateScope:
    """Gate 2: URL scope enforcement."""

    def test_passes_for_exact_domain_match(self):
        """URL whose host exactly matches an allowed_scope entry must pass."""
        checklist = make_checklist(allowed_scope=["example.com"])
        finding = make_finding(url="https://example.com/api/data")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        assert scope_gate.passed, scope_gate.reason

    def test_passes_for_wildcard_subdomain(self):
        """URL on api.example.com must match the '*.example.com' wildcard entry."""
        checklist = make_checklist(allowed_scope=["*.example.com"])
        finding = make_finding(url="https://api.example.com/v1/endpoint")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        assert scope_gate.passed, scope_gate.reason

    def test_passes_for_url_prefix_match(self):
        """URL that starts with an https:// prefix entry must pass."""
        checklist = make_checklist(allowed_scope=["https://api.example.com/"])
        finding = make_finding(url="https://api.example.com/v1/users")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        assert scope_gate.passed, scope_gate.reason

    def test_fails_for_out_of_scope_url(self):
        """URL on an entirely different domain must fail Gate 2."""
        checklist = make_checklist(allowed_scope=["example.com", "*.example.com"])
        finding = make_finding(url="https://attacker.com/evil")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        assert not scope_gate.passed

    def test_fails_for_blocked_scope_even_if_allowed(self):
        """A URL in blocked_scope must fail even if it also matches allowed_scope."""
        checklist = make_checklist(
            allowed_scope=["example.com", "*.example.com"],
            blocked_scope=["staging.example.com"],
        )
        finding = make_finding(url="https://staging.example.com/api/users")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        assert not scope_gate.passed

    def test_passes_when_no_allowed_scope_configured(self):
        """No allowed_scope configured = open scope mode, any URL is accepted."""
        checklist = make_checklist(allowed_scope=[])
        finding = make_finding(url="https://anything.io/endpoint")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        assert scope_gate.passed, scope_gate.reason

    def test_wildcard_does_not_match_parent_domain(self):
        """
        '*.example.com' should NOT match the bare 'example.com' domain itself.
        The wildcard requires at least one subdomain label.
        """
        checklist = make_checklist(allowed_scope=["*.example.com"])
        # bare domain without subdomain — should NOT match *.example.com
        finding = make_finding(url="https://example.com/api/data")

        result = checklist.run(finding)
        scope_gate = next(g for g in result.gates if g.gate_name == "SCOPE")
        # example.com does not have a subdomain prefix, so wildcard should not match
        assert not scope_gate.passed, (
            "*.example.com should not match bare example.com"
        )


# ---------------------------------------------------------------------------
# Gate 3 — IMPACT
# ---------------------------------------------------------------------------

class TestGateImpact:
    """Gate 3: impact statement quality."""

    def test_passes_with_attacker_framing(self):
        """A statement containing 'attacker' and >= 15 chars must pass."""
        checklist = make_checklist()
        finding = make_finding(
            impact_statement="An attacker can exfiltrate all user PII without authentication."
        )
        result = checklist.run(finding)
        impact_gate = next(g for g in result.gates if g.gate_name == "IMPACT")
        assert impact_gate.passed, impact_gate.reason

    def test_passes_with_user_keyword(self):
        """Impact containing 'user' must pass."""
        checklist = make_checklist()
        finding = make_finding(
            impact_statement="This vulnerability allows user account takeover at scale."
        )
        result = checklist.run(finding)
        impact_gate = next(g for g in result.gates if g.gate_name == "IMPACT")
        assert impact_gate.passed, impact_gate.reason

    def test_passes_with_system_keyword(self):
        """Impact containing 'system' must pass."""
        checklist = make_checklist()
        finding = make_finding(
            impact_statement="Full system compromise is achievable via this vector."
        )
        result = checklist.run(finding)
        impact_gate = next(g for g in result.gates if g.gate_name == "IMPACT")
        assert impact_gate.passed, impact_gate.reason

    def test_fails_with_empty_impact(self):
        """Empty impact_statement must fail Gate 3."""
        checklist = make_checklist()
        finding = make_finding(impact_statement="")

        result = checklist.run(finding)
        impact_gate = next(g for g in result.gates if g.gate_name == "IMPACT")
        assert not impact_gate.passed
        assert "empty" in impact_gate.reason.lower()

    def test_fails_with_too_short_impact(self):
        """Impact statement shorter than 15 characters must fail Gate 3."""
        checklist = make_checklist()
        finding = make_finding(impact_statement="Bad vuln")  # 8 chars

        result = checklist.run(finding)
        impact_gate = next(g for g in result.gates if g.gate_name == "IMPACT")
        assert not impact_gate.passed
        assert "short" in impact_gate.reason.lower() or "minimum" in impact_gate.reason.lower()

    def test_fails_when_no_harm_keyword_present(self):
        """
        Impact >= 15 chars but missing 'attacker'/'user'/'system' must fail Gate 3.
        """
        checklist = make_checklist()
        # Long enough but no required keyword
        finding = make_finding(impact_statement="This is a serious vulnerability that causes harm.")

        result = checklist.run(finding)
        impact_gate = next(g for g in result.gates if g.gate_name == "IMPACT")
        assert not impact_gate.passed
        assert any(
            kw in impact_gate.reason.lower()
            for kw in ("attacker", "user", "system", "framing", "keyword")
        )


# ---------------------------------------------------------------------------
# Gate 4 — SEVERITY FLOOR
# ---------------------------------------------------------------------------

class TestGateSeverity:
    """Gate 4: CVSS score >= 4.0 enforcement."""

    def test_passes_at_boundary_cvss_4_0(self):
        """CVSS exactly 4.0 is the minimum acceptable value — must pass."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=4.0, severity_label="")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert sev_gate.passed, sev_gate.reason

    def test_passes_for_high_cvss(self):
        """CVSS 9.8 (critical) must pass."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=9.8, severity_label="")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert sev_gate.passed, sev_gate.reason

    def test_fails_for_cvss_below_floor(self):
        """CVSS 3.9 is below the 4.0 floor — must fail."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=3.9, severity_label="")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert not sev_gate.passed
        assert "3.9" in sev_gate.reason or "below" in sev_gate.reason.lower()

    def test_infers_cvss_from_critical_label(self):
        """severity_label='critical' should infer CVSS 9.0 → pass."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=None, severity_label="critical")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert sev_gate.passed, sev_gate.reason
        assert "critical" in sev_gate.reason.lower() or "9.0" in sev_gate.reason

    def test_infers_cvss_from_medium_label(self):
        """severity_label='medium' should infer CVSS 5.0 → pass."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=None, severity_label="medium")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert sev_gate.passed, sev_gate.reason

    def test_fails_for_low_severity_label(self):
        """severity_label='low' infers CVSS 2.0 → fails Gate 4."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=None, severity_label="low")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert not sev_gate.passed

    def test_fails_for_info_severity_label(self):
        """severity_label='info' infers CVSS 0.0 → fails Gate 4."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=None, severity_label="info")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert not sev_gate.passed

    def test_fails_for_unknown_label_and_no_cvss(self):
        """No cvss_score and unrecognised severity_label must fail Gate 4."""
        checklist = make_checklist()
        finding = make_finding(cvss_score=None, severity_label="")

        result = checklist.run(finding)
        sev_gate = next(g for g in result.gates if g.gate_name == "SEVERITY FLOOR")
        assert not sev_gate.passed
        assert "recognised" in sev_gate.reason.lower() or "no cvss" in sev_gate.reason.lower()


# ---------------------------------------------------------------------------
# Gate 5 — DUPLICATE CHECK
# ---------------------------------------------------------------------------

class TestGateDuplicate:
    """Gate 5: novelty enforcement."""

    def test_passes_for_novel_finding(self):
        """A (url, vuln_type) pair not in any set must pass Gate 5."""
        checklist = make_checklist(
            known_findings=[("https://example.com/api/posts", "XSS")],
            disclosed_patterns=[("https://example.com/api/posts", "SQLI")],
        )
        finding = make_finding(
            url="https://example.com/api/users/42",
            vuln_type="IDOR",
        )
        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert dup_gate.passed, dup_gate.reason

    def test_fails_on_known_findings_duplicate(self):
        """Exact (normalised_url, vuln_type) match in known_findings must fail Gate 5."""
        norm_url = VerificationChecklist.normalise_url("https://example.com/api/users/42")
        norm_vuln = VerificationChecklist.normalise_vuln_type("IDOR")
        checklist = make_checklist(
            known_findings=[(norm_url, norm_vuln)],
        )
        finding = make_finding(
            url="https://example.com/api/users/42",
            vuln_type="IDOR",
        )
        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert not dup_gate.passed
        assert "known" in dup_gate.reason.lower() or "duplicate" in dup_gate.reason.lower()

    def test_fails_on_disclosed_patterns_duplicate(self):
        """Exact match in disclosed_patterns must fail Gate 5."""
        norm_url = VerificationChecklist.normalise_url("https://example.com/login")
        norm_vuln = VerificationChecklist.normalise_vuln_type("XSS")
        checklist = make_checklist(
            disclosed_patterns=[(norm_url, norm_vuln)],
        )
        finding = make_finding(
            url="https://example.com/login",
            vuln_type="XSS",
        )
        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert not dup_gate.passed
        assert "disclosed" in dup_gate.reason.lower()

    def test_url_normalisation_trailing_slash(self):
        """
        URL with and without trailing slash should resolve to the same normalised URL,
        triggering the duplicate check correctly.
        """
        norm_url = VerificationChecklist.normalise_url("https://example.com/api/users")
        norm_vuln = VerificationChecklist.normalise_vuln_type("IDOR")
        checklist = make_checklist(known_findings=[(norm_url, norm_vuln)])

        # Finding URL has trailing slash — should still be caught as duplicate
        finding = make_finding(
            url="https://example.com/api/users/",
            vuln_type="IDOR",
        )
        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert not dup_gate.passed, "Trailing slash should not bypass duplicate detection"

    def test_url_normalisation_query_string_stripped(self):
        """
        URL with a query string should normalise to the same base URL,
        triggering the duplicate check.
        """
        norm_url = VerificationChecklist.normalise_url("https://example.com/search")
        norm_vuln = VerificationChecklist.normalise_vuln_type("SQLI")
        checklist = make_checklist(known_findings=[(norm_url, norm_vuln)])

        # Finding URL includes ?q=test — base URL must still match
        finding = make_finding(
            url="https://example.com/search?q=test&page=2",
            vuln_type="SQLI",
        )
        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert not dup_gate.passed, "Query string should be stripped during normalisation"

    def test_vuln_type_case_normalisation(self):
        """
        vuln_type matching is case-insensitive after normalisation.
        'xss' and 'XSS' should be treated as identical.
        """
        norm_url = VerificationChecklist.normalise_url("https://example.com/comment")
        checklist = make_checklist(
            known_findings=[(norm_url, "XSS")],
        )
        # Finding uses lowercase vuln_type
        finding = make_finding(url="https://example.com/comment", vuln_type="xss")

        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert not dup_gate.passed, "Case normalisation should make 'xss' == 'XSS'"

    def test_detects_duplicate_from_raw_known_findings(self):
        """
        Duplicate is detected even when known_findings contains raw (un-normalised)
        data — mixed case URL, trailing slash, and lowercase vuln_type.

        This exercises the fix that applies normalise_url/normalise_vuln_type to
        stored tuples at comparison time rather than assuming callers pre-normalise.
        """
        raw_known = [("https://Example.com/api/users/42/", "idor")]
        checklist = make_checklist(known_findings=raw_known)
        finding = make_finding(
            url="https://example.com/api/users/42",
            vuln_type="IDOR",
        )
        result = checklist.run(finding)
        dup_gate = next(g for g in result.gates if g.gate_name == "DUPLICATE CHECK")
        assert not dup_gate.passed, (
            "Raw un-normalised known_findings entry should still be detected as duplicate"
        )
        assert "known" in dup_gate.reason.lower() or "duplicate" in dup_gate.reason.lower()


# ---------------------------------------------------------------------------
# End-to-end: Full Checklist
# ---------------------------------------------------------------------------

class TestFullChecklist:
    """Integration tests that exercise the full 5-gate pipeline."""

    def test_all_gates_pass(self):
        """A perfectly valid finding must return result.passed=True."""
        checklist = make_checklist()
        finding = make_finding()

        result = checklist.run(finding)

        assert result.passed is True
        assert result.failed_gates == []
        assert len(result.gates) == 5
        assert all(g.passed for g in result.gates)

    def test_first_gate_failure_sets_passed_false(self):
        """Failing Gate 1 (reproducibility) must result in result.passed=False."""
        checklist = make_checklist()
        finding = make_finding(clean_state_verified=False)

        result = checklist.run(finding)

        assert result.passed is False
        assert "REPRODUCIBILITY" in result.failed_gates

    def test_multiple_failures_all_recorded(self):
        """
        Multiple gate failures must all be recorded in failed_gates.
        Here Gate 1 fails (clean_state) and Gate 3 fails (empty impact).
        """
        checklist = make_checklist()
        finding = make_finding(
            clean_state_verified=False,
            impact_statement="",
        )
        result = checklist.run(finding)

        assert result.passed is False
        assert "REPRODUCIBILITY" in result.failed_gates
        assert "IMPACT" in result.failed_gates
        assert len(result.failed_gates) >= 2

    def test_finding_id_format(self):
        """finding_id must be 'normalised_url::NORMALISED_VULN_TYPE'."""
        checklist = make_checklist()
        finding = make_finding(
            url="https://Example.com/API/Users/42/?session=abc",
            vuln_type="  idor  ",
        )
        result = checklist.run(finding)

        # URL normalised: lowercase, no query, no trailing slash
        expected_url = "https://example.com/api/users/42"
        expected_vuln = "IDOR"
        expected_id = f"{expected_url}::{expected_vuln}"

        assert result.finding_id == expected_id, (
            f"Expected finding_id '{expected_id}', got '{result.finding_id}'"
        )

    def test_all_5_gates_present_in_result(self):
        """ChecklistResult.gates must always contain exactly 5 GateResult objects."""
        checklist = make_checklist()
        finding = make_finding()
        result = checklist.run(finding)

        assert len(result.gates) == 5
        gate_names = {g.gate_name for g in result.gates}
        expected_names = {
            "REPRODUCIBILITY",
            "SCOPE",
            "IMPACT",
            "SEVERITY FLOOR",
            "DUPLICATE CHECK",
        }
        assert gate_names == expected_names


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

class TestNormalisation:
    """Unit tests for normalise_url and normalise_vuln_type static methods."""

    def test_normalise_url_strips_query_string(self):
        url = "https://example.com/api/users?page=1&limit=20"
        assert VerificationChecklist.normalise_url(url) == "https://example.com/api/users"

    def test_normalise_url_strips_trailing_slash(self):
        url = "https://example.com/api/v1/"
        assert VerificationChecklist.normalise_url(url) == "https://example.com/api/v1"

    def test_normalise_url_lowercases(self):
        url = "HTTPS://EXAMPLE.COM/API/Users"
        normalised = VerificationChecklist.normalise_url(url)
        assert normalised == normalised.lower()

    def test_normalise_vuln_type_uppercases_and_strips(self):
        assert VerificationChecklist.normalise_vuln_type("  xss  ") == "XSS"
        assert VerificationChecklist.normalise_vuln_type("sql injection") == "SQL INJECTION"
        assert VerificationChecklist.normalise_vuln_type("IDOR") == "IDOR"
