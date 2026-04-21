"""
Unit tests for engine.verification.challenger — Stage B self-challenge agent.

Coverage
--------
TestHeuristicMode     (9 tests)  — rule-based challenge (primary testable path)
TestAIMode            (5 tests)  — AI mode with mocked API
TestChallengeResult   (4 tests)  — ChallengeResult data contract
TestIntegration       (3 tests)  — Stage A + Stage B combined paths

Total: 21 tests
"""

import pytest
from unittest.mock import MagicMock, patch

from engine.verification import (
    ChecklistInput,
    Challenger,
    ChallengeResult,
    VerificationChecklist,
)


# ---------------------------------------------------------------------------
# Shared factory helpers
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


def make_challenger(**kwargs) -> Challenger:
    """Return a Challenger in heuristic mode (no api_key)."""
    defaults = dict(api_key=None)
    defaults.update(kwargs)
    return Challenger(**defaults)


# ---------------------------------------------------------------------------
# TestHeuristicMode — 9 tests
# ---------------------------------------------------------------------------


class TestHeuristicMode:
    """Rule-based challenge mode — no API key required."""

    def test_mode_is_heuristic_without_api_key(self):
        """Challenger without api_key must report mode == 'heuristic'."""
        c = Challenger(api_key=None)
        assert c.mode == "heuristic"

    def test_mode_is_heuristic_when_anthropic_not_installed(self):
        """If api_key is None (regardless of anthropic availability) mode is heuristic."""
        c = Challenger(api_key=None)
        assert c.mode == "heuristic"

    def test_clean_finding_returns_verified_submit(self):
        """A fully valid finding with specific impact → VERIFIED, SUBMIT."""
        c = make_challenger()
        finding = make_finding(
            vuln_type="IDOR",
            response_snippet='{"id":42,"email":"victim@example.com"}',
            impact_statement="An attacker can read any user profile without authorisation.",
            cvss_score=7.5,
            severity_label="high",
            clean_state_verified=True,
        )
        result = c.challenge(finding)
        assert result.verdict == "VERIFIED"
        assert result.verified is True
        assert result.recommendation == "SUBMIT"
        assert result.confidence == pytest.approx(0.85)

    def test_xss_no_execution_context_raises_challenge(self):
        """XSS finding with no script execution context in snippet → challenge raised."""
        c = make_challenger()
        finding = make_finding(
            vuln_type="XSS",
            # Snippet has the value echoed but no <script>/JS execution indicators
            response_snippet="<p>Hello, <b>user input here</b></p>",
            impact_statement="An attacker can steal user session cookies.",
            cvss_score=6.0,
            severity_label="medium",
            clean_state_verified=True,
        )
        result = c.challenge(finding)
        # Should have at least one challenge raised (the XSS heuristic)
        assert len(result.challenges_raised) >= 1
        assert any("reflection" in r.lower() or "xss" in r.lower() for r in result.challenges_raised)

    def test_xss_with_execution_context_passes_heuristic(self):
        """XSS snippet containing <script tag does NOT trigger reflection challenge."""
        c = make_challenger()
        finding = make_finding(
            vuln_type="XSS",
            response_snippet='<script>alert(1)</script> injected here',
            impact_statement="An attacker can execute arbitrary JavaScript in user browsers.",
            cvss_score=6.5,
            severity_label="medium",
            clean_state_verified=True,
        )
        result = c.challenge(finding)
        # Reflection challenge should NOT be raised
        assert not any(
            "reflection" in r.lower() for r in result.challenges_raised
        ), f"Unexpected XSS challenge: {result.challenges_raised}"

    def test_cvss_mismatch_low_score_high_label_raises_challenge(self):
        """CVSS <= 4.0 with severity_label='high' → challenge raised."""
        c = make_challenger()
        finding = make_finding(
            cvss_score=3.5,
            severity_label="high",
            clean_state_verified=True,
            impact_statement="An attacker can read any user profile without authorisation.",
        )
        result = c.challenge(finding)
        assert any(
            "cvss" in r.lower() or "mislabel" in r.lower() or "<= 4.0" in r or "label" in r.lower()
            for r in result.challenges_raised
        )

    def test_two_challenges_returns_drop(self):
        """Two or more challenges raised → CHALLENGED verdict, DROP recommendation."""
        c = make_challenger()
        # Trigger: XSS no context + low CVSS / high label
        finding = make_finding(
            vuln_type="XSS",
            response_snippet="<p>echoed value</p>",  # no execution context
            cvss_score=2.0,
            severity_label="high",  # CVSS mismatch
            impact_statement="An attacker can steal user cookies and hijack sessions.",
            clean_state_verified=True,
        )
        result = c.challenge(finding)
        assert result.verified is False
        assert result.verdict == "CHALLENGED"
        assert result.recommendation == "DROP"
        assert result.confidence == pytest.approx(0.30)

    def test_challenges_raised_list_populated_correctly(self):
        """challenges_raised should contain at least the triggered reason strings."""
        c = make_challenger()
        finding = make_finding(
            vuln_type="IDOR",
            clean_state_verified=False,  # triggers heuristic 3
            cvss_score=7.5,
            severity_label="high",
            impact_statement="An attacker can read any user profile without authorisation.",
        )
        result = c.challenge(finding)
        # The "no clean state" heuristic must be present
        assert any("clean_state" in r.lower() for r in result.challenges_raised)

    def test_failed_challenges_populated_when_no_issues(self):
        """When no challenges are raised, failed_challenges should be non-empty."""
        c = make_challenger()
        finding = make_finding(
            vuln_type="IDOR",
            response_snippet='{"id":42,"email":"victim@example.com"}',
            impact_statement="An attacker can read any user profile without authorisation.",
            cvss_score=7.5,
            severity_label="high",
            clean_state_verified=True,
        )
        result = c.challenge(finding)
        # Expect at least some "ruled out" entries from the 4 heuristics
        assert len(result.failed_challenges) > 0

    def test_verdict_is_verified_or_challenged_only(self):
        """verdict must always be exactly 'VERIFIED' or 'CHALLENGED'."""
        c = make_challenger()
        for finding in [
            make_finding(),
            make_finding(clean_state_verified=False),
            make_finding(vuln_type="XSS", response_snippet="<p>echo</p>"),
        ]:
            result = c.challenge(finding)
            assert result.verdict in ("VERIFIED", "CHALLENGED"), (
                f"Unexpected verdict: {result.verdict!r}"
            )


# ---------------------------------------------------------------------------
# TestAIMode — 5 tests
# ---------------------------------------------------------------------------


class TestAIMode:
    """AI mode with Anthropic Claude — mocked to avoid real API calls."""

    def test_mode_is_ai_with_fake_api_key(self):
        """Challenger with a non-empty api_key must report mode == 'ai'."""
        # Ensure HAS_ANTHROPIC is True for this test
        with patch("engine.verification.challenger.HAS_ANTHROPIC", True):
            c = Challenger(api_key="sk-fake-key-for-testing")
            assert c.mode == "ai"

    def test_build_challenge_prompt_contains_url(self):
        """_build_challenge_prompt must include the finding URL."""
        c = Challenger(api_key=None)  # mode doesn't matter for this unit test
        finding = make_finding(url="https://victim.example.com/api/secret")
        prompt = c._build_challenge_prompt(finding)
        assert "https://victim.example.com/api/secret" in prompt

    def test_build_challenge_prompt_contains_vuln_type(self):
        """_build_challenge_prompt must include the vulnerability type."""
        c = Challenger(api_key=None)
        finding = make_finding(vuln_type="SQLI")
        prompt = c._build_challenge_prompt(finding)
        assert "SQLI" in prompt

    def test_build_challenge_prompt_contains_impact_statement(self):
        """_build_challenge_prompt must include the impact statement."""
        c = Challenger(api_key=None)
        finding = make_finding(
            impact_statement="An attacker can dump the entire user database."
        )
        prompt = c._build_challenge_prompt(finding)
        assert "An attacker can dump the entire user database." in prompt

    def test_parse_challenge_response_extracts_raised_challenges(self):
        """_parse_challenge_response correctly extracts RAISED challenges."""
        c = Challenger(api_key=None)
        raw = (
            "CHALLENGE_1: [RAISED] — The payload is reflected but there is no execution context.\n"
            "CHALLENGE_2: [RULED_OUT] — The impact is clearly in-scope per the program policy.\n"
            "CHALLENGE_3: [RULED_OUT] — No benign explanation found for the behaviour.\n"
            "CHALLENGE_4: [RAISED] — Reproduction requires special internal network access.\n"
            "VERDICT: [CHALLENGED]\n"
            "CONFIDENCE: [0.45]\n"
            "RECOMMENDATION: [REVIEW]\n"
            "SUMMARY: The finding needs further investigation.\n"
        )
        result = c._parse_challenge_response(raw)
        assert len(result.challenges_raised) == 2
        assert len(result.failed_challenges) == 2
        assert result.verified is False
        assert result.verdict == "CHALLENGED"
        assert result.confidence == pytest.approx(0.45)
        assert result.recommendation == "REVIEW"
        assert result.raw_response == raw

    def test_parse_challenge_response_verified_verdict(self):
        """_parse_challenge_response sets verified=True for VERDICT: VERIFIED."""
        c = Challenger(api_key=None)
        raw = (
            "CHALLENGE_1: [RULED_OUT] — The XSS is clearly executable in-browser context.\n"
            "CHALLENGE_2: [RULED_OUT] — In-scope harm confirmed.\n"
            "CHALLENGE_3: [RULED_OUT] — No benign explanation.\n"
            "CHALLENGE_4: [RULED_OUT] — Any attacker can reproduce via simple HTTP request.\n"
            "VERDICT: [VERIFIED]\n"
            "CONFIDENCE: [0.90]\n"
            "RECOMMENDATION: [SUBMIT]\n"
            "SUMMARY: Finding is credible and ready to submit.\n"
        )
        result = c._parse_challenge_response(raw)
        assert result.verified is True
        assert result.verdict == "VERIFIED"
        assert result.recommendation == "SUBMIT"

    def test_parse_challenge_response_handles_malformed_gracefully(self):
        """Malformed LLM response must not crash — should return a ChallengeResult."""
        c = Challenger(api_key=None)
        malformed = "I cannot determine anything about this finding. It looks interesting."
        result = c._parse_challenge_response(malformed)
        # Should not raise; should return a ChallengeResult
        assert isinstance(result, ChallengeResult)
        assert result.verdict in ("VERIFIED", "CHALLENGED")
        assert result.raw_response == malformed

    def test_ai_mode_falls_back_to_heuristic_on_api_error(self):
        """If the Claude API call raises, the challenger falls back to heuristic mode."""
        with patch("engine.verification.challenger.HAS_ANTHROPIC", True):
            with patch("anthropic.Anthropic") as mock_anthropic_cls:
                mock_client = MagicMock()
                mock_anthropic_cls.return_value = mock_client
                mock_client.messages.create.side_effect = RuntimeError("Network error")

                c = Challenger(api_key="sk-fake-key")
                finding = make_finding()
                result = c.challenge(finding)

                # Should still return a valid ChallengeResult from heuristic fallback
                assert isinstance(result, ChallengeResult)
                assert result.verdict in ("VERIFIED", "CHALLENGED")


# ---------------------------------------------------------------------------
# TestChallengeResult — 4 tests
# ---------------------------------------------------------------------------


class TestChallengeResult:
    """Data contract tests for ChallengeResult."""

    def test_verified_true_only_when_verdict_is_verified(self):
        """verified=True must correspond to verdict='VERIFIED'."""
        result_verified = ChallengeResult(
            verified=True,
            verdict="VERIFIED",
            challenges_raised=[],
            failed_challenges=["Benign explanation ruled out"],
            confidence=0.85,
            recommendation="SUBMIT",
            raw_response="VERDICT: VERIFIED",
        )
        result_challenged = ChallengeResult(
            verified=False,
            verdict="CHALLENGED",
            challenges_raised=["Payload is only reflected"],
            failed_challenges=[],
            confidence=0.40,
            recommendation="REVIEW",
            raw_response="VERDICT: CHALLENGED",
        )
        assert result_verified.verified is True and result_verified.verdict == "VERIFIED"
        assert result_challenged.verified is False and result_challenged.verdict == "CHALLENGED"

    def test_recommendation_is_valid_value(self):
        """recommendation must be one of SUBMIT, REVIEW, DROP."""
        for rec in ("SUBMIT", "REVIEW", "DROP"):
            result = ChallengeResult(
                verified=(rec == "SUBMIT"),
                verdict="VERIFIED" if rec == "SUBMIT" else "CHALLENGED",
                challenges_raised=[],
                failed_challenges=[],
                confidence=0.8,
                recommendation=rec,
                raw_response="",
            )
            assert result.recommendation in ("SUBMIT", "REVIEW", "DROP")

    def test_confidence_is_within_range(self):
        """confidence must be between 0.0 and 1.0 inclusive."""
        c = make_challenger()
        result = c.challenge(make_finding())
        assert 0.0 <= result.confidence <= 1.0

    def test_raw_response_preserved_in_result(self):
        """raw_response must be stored exactly as passed."""
        raw = "Some raw LLM response text\nwith multiple lines."
        result = ChallengeResult(
            verified=True,
            verdict="VERIFIED",
            challenges_raised=[],
            failed_challenges=[],
            confidence=0.9,
            recommendation="SUBMIT",
            raw_response=raw,
        )
        assert result.raw_response == raw


# ---------------------------------------------------------------------------
# TestIntegration — 3 tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """Combine Stage A (ChecklistInput) with Stage B (Challenger)."""

    def test_stage_a_passthrough_runs_stage_b_correctly(self):
        """A finding produced by Stage A input runs through Stage B without error."""
        finding = make_finding()

        # Stage A
        checklist = VerificationChecklist(allowed_scope=["example.com", "*.example.com"])
        stage_a_result = checklist.run(finding)
        assert stage_a_result.passed, f"Stage A failed: {stage_a_result.failed_gates}"

        # Stage B
        challenger = make_challenger()
        stage_b_result = challenger.challenge(finding)

        assert isinstance(stage_b_result, ChallengeResult)
        assert stage_b_result.verdict in ("VERIFIED", "CHALLENGED")

    def test_finding_passes_stage_a_but_fails_stage_b(self):
        """
        A finding can pass all Stage A gates yet still be challenged by Stage B.

        Example: An XSS finding with no execution context in the snippet — Stage A
        passes (clean evidence, in-scope, etc.) but Stage B raises an XSS challenge.
        """
        finding = make_finding(
            vuln_type="XSS",
            # No execution context in snippet — Stage B will raise a challenge
            response_snippet="<div>Hello world</div>",
            impact_statement="An attacker can execute scripts in user browsers.",
            cvss_score=6.0,
            severity_label="medium",
            clean_state_verified=True,
        )

        # Stage A
        checklist = VerificationChecklist(allowed_scope=["example.com", "*.example.com"])
        stage_a_result = checklist.run(finding)
        assert stage_a_result.passed, f"Stage A failed unexpectedly: {stage_a_result.failed_gates}"

        # Stage B
        challenger = make_challenger()
        stage_b_result = challenger.challenge(finding)

        # The XSS heuristic should raise a challenge
        assert stage_b_result.verdict == "CHALLENGED", (
            "Expected Stage B to challenge this XSS finding with no execution context"
        )

    def test_empty_response_snippet_handled_gracefully(self):
        """
        Stage B should handle an empty response_snippet without crashing.

        (An empty snippet would fail Stage A Gate 1, but Stage B must still
        be robust if called independently.)
        """
        finding = make_finding(
            response_snippet="",
            vuln_type="IDOR",
            clean_state_verified=True,
            impact_statement="An attacker can read any user profile without authorisation.",
        )
        challenger = make_challenger()
        result = challenger.challenge(finding)

        # Should not raise; must return a valid ChallengeResult
        assert isinstance(result, ChallengeResult)
        assert result.verdict in ("VERIFIED", "CHALLENGED")
        assert 0.0 <= result.confidence <= 1.0
