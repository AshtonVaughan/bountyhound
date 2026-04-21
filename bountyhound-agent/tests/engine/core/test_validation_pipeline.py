"""Unit tests for engine.core.validation_pipeline."""

import json
import time
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from engine.core.validation_pipeline import (
    ValidationPipeline,
    ValidationResult,
    STATE_CHANGE_REQUIRED,
    LOW_VALUE_TYPES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_finding(**overrides) -> dict:
    """Return a minimal valid finding dict, with optional overrides."""
    finding = {
        "vulnerability_type": "xss",
        "vuln_type": "xss",
        "url": "https://example.com/search?q=test",
        "target_domain": "example.com",
        "severity": "HIGH",
        "title": "Reflected XSS in search",
        "evidence": "The <script>alert(1)</script> payload executed in the response body.",
        "description": "Reflected XSS via the q parameter on the search endpoint.",
        "status_code": 200,
        "response_body": "<html><script>alert(1)</script></html>",
    }
    finding.update(overrides)
    return finding


# ---------------------------------------------------------------------------
# ValidationResult dataclass
# ---------------------------------------------------------------------------

class TestValidationResult:
    def test_default_values(self):
        r = ValidationResult(finding={})
        assert r.verdict == "PENDING"
        assert r.confidence_score == 0.0
        assert r.confidence_grade == "F"
        assert r.stages_passed == []
        assert r.stages_failed == []
        assert r.poc_verified is False
        assert r.state_change_verified is False

    def test_to_dict_includes_all_keys(self):
        r = ValidationResult(finding={"id": 1}, verdict="SUBMIT", confidence_score=0.85)
        d = r.to_dict()
        expected_keys = {
            "verdict", "confidence_score", "confidence_grade",
            "stages_passed", "stages_failed", "rejection_reason",
            "poc_verified", "state_change_verified", "estimated_bounty",
            "curl_command",
        }
        assert set(d.keys()) == expected_keys
        assert d["verdict"] == "SUBMIT"
        assert d["confidence_score"] == 0.85


# ---------------------------------------------------------------------------
# ValidationPipeline - full validate()
# ---------------------------------------------------------------------------

class TestValidateFull:
    """Tests for ValidationPipeline.validate() exercising the full 6-stage pipeline."""

    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_submission_gate")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_confidence")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_state_change")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_poc_validation")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_error_classification")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_fp_check")
    def test_validate_submit_path(
        self, mock_fp, mock_err, mock_poc, mock_state, mock_conf, mock_gate
    ):
        """All stages pass - finding should reach SUBMIT."""
        mock_fp.return_value = (True, "ok")
        mock_err.return_value = (True, "ok")
        mock_poc.return_value = (True, "confirmed", True)
        mock_state.return_value = (True, "not required", False)
        mock_conf.return_value = (0.9, "A", "submit")
        mock_gate.return_value = ("SUBMIT", "$500")

        pipeline = ValidationPipeline(skip_poc=False, verbose=False)
        result = pipeline.validate(_base_finding())

        assert result.verdict == "SUBMIT"
        assert result.poc_verified is True
        assert result.estimated_bounty == "$500"
        assert "fp_check" in result.stages_passed
        assert "poc_validation" in result.stages_passed
        assert result.confidence_score == 0.9

    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_fp_check")
    def test_validate_reject_on_fp(self, mock_fp):
        """Stage 1 FP check failure should short-circuit to REJECT."""
        mock_fp.return_value = (False, "Known FP: default Apache page")

        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        result = pipeline.validate(_base_finding())

        assert result.verdict == "REJECT"
        assert "fp_check" in result.stages_failed
        assert "Apache" in result.rejection_reason

    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_error_classification")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_fp_check")
    def test_validate_reject_on_error_classification(self, mock_fp, mock_err):
        """Stage 2 error classification failure should REJECT."""
        mock_fp.return_value = (True, "ok")
        mock_err.return_value = (False, "Error classification: 403 is access denied, not a vuln")

        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        result = pipeline.validate(_base_finding())

        assert result.verdict == "REJECT"
        assert "error_classification" in result.stages_failed

    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_state_change")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_poc_validation")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_error_classification")
    @patch("engine.core.validation_pipeline.ValidationPipeline._stage_fp_check")
    def test_validate_hold_on_state_change_failure(
        self, mock_fp, mock_err, mock_poc, mock_state
    ):
        """Stage 4 state change failure should HOLD (not REJECT)."""
        mock_fp.return_value = (True, "ok")
        mock_err.return_value = (True, "ok")
        mock_poc.return_value = (True, "confirmed", True)
        mock_state.return_value = (False, "idor requires state change proof", False)

        pipeline = ValidationPipeline(skip_poc=False, verbose=False)
        result = pipeline.validate(_base_finding(vulnerability_type="idor"))

        assert result.verdict == "HOLD"
        assert "state_change" in result.stages_failed

    def test_validate_routes_source_audit(self):
        """Source audit findings should be routed to _validate_source_audit."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(source="source_audit")

        with patch.object(pipeline, "_validate_source_audit") as mock_sa:
            mock_sa.return_value = ValidationResult(finding=finding, verdict="HOLD")
            result = pipeline.validate(finding)
            mock_sa.assert_called_once()
            assert result.verdict == "HOLD"


# ---------------------------------------------------------------------------
# ValidationPipeline.validate_batch()
# ---------------------------------------------------------------------------

class TestValidateBatch:
    def test_batch_processes_all_findings(self):
        """validate_batch should return one result per input finding."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        findings = [_base_finding(title=f"Finding {i}") for i in range(3)]

        with patch.object(pipeline, "validate") as mock_v:
            mock_v.side_effect = [
                ValidationResult(finding=f, verdict=v)
                for f, v in zip(findings, ["SUBMIT", "HOLD", "REJECT"])
            ]
            results = pipeline.validate_batch(findings)

        assert len(results) == 3
        assert results[0].verdict == "SUBMIT"
        assert results[1].verdict == "HOLD"
        assert results[2].verdict == "REJECT"

    def test_batch_empty_list(self):
        """Empty input should return empty output."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        assert pipeline.validate_batch([]) == []


# ---------------------------------------------------------------------------
# _stage_poc_validation()
# ---------------------------------------------------------------------------

class TestStagePocValidation:
    def test_skip_poc_returns_true(self):
        """When skip_poc=True, stage should pass without verification."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        passed, reason, verified = pipeline._stage_poc_validation(_base_finding())
        assert passed is True
        assert verified is False
        assert "skipped" in reason.lower()

    def test_no_url_passes(self):
        """Finding with no URL should pass (nothing to validate)."""
        pipeline = ValidationPipeline(skip_poc=False, verbose=False)
        passed, reason, verified = pipeline._stage_poc_validation({"vulnerability_type": "xss"})
        assert passed is True
        assert verified is False

    def test_poc_confirmed(self):
        """POCValidator.CONFIRMED should set verified=True."""
        pipeline = ValidationPipeline(skip_poc=False, verbose=False)

        mock_validator_cls = MagicMock()
        mock_validator_cls.CONFIRMED = "CONFIRMED"
        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = {"verdict": "CONFIRMED", "reason": "200 with payload reflected"}
        mock_validator_cls.return_value = mock_validator_instance
        # The class attribute CONFIRMED is accessed on the class, not instance
        # but we need it on the class mock too
        mock_validator_cls.CONFIRMED = "CONFIRMED"

        import sys
        mock_module = MagicMock()
        mock_module.POCValidator = mock_validator_cls
        with patch.dict(sys.modules, {"engine.agents.poc_validator": mock_module}):
            passed, reason, verified = pipeline._stage_poc_validation(_base_finding())

        assert passed is True
        assert verified is True

    def test_poc_import_error_passes(self):
        """If POCValidator cannot be imported, stage should pass gracefully."""
        pipeline = ValidationPipeline(skip_poc=False, verbose=False)

        with patch.dict("sys.modules", {"engine.agents.poc_validator": None}):
            # The import inside the method will raise ImportError
            passed, reason, verified = pipeline._stage_poc_validation(_base_finding())
            # Should pass due to the except Exception handler
            assert passed is True
            assert verified is False


# ---------------------------------------------------------------------------
# _stage_state_change()
# ---------------------------------------------------------------------------

class TestStageStateChange:
    def test_non_required_type_passes(self):
        """Vuln types NOT in STATE_CHANGE_REQUIRED should pass automatically."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(vulnerability_type="xss")
        passed, reason, verified = pipeline._stage_state_change(finding)
        assert passed is True
        assert verified is False

    def test_idor_without_evidence_fails(self):
        """IDOR finding with no state change evidence should fail."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(vulnerability_type="idor")
        passed, reason, verified = pipeline._stage_state_change(finding)
        assert passed is False
        assert verified is False
        assert "state change proof" in reason.lower()

    def test_idor_with_verified_flag_and_states(self):
        """IDOR finding with state_change_verified + before/after should attempt verification."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(
            vulnerability_type="idor",
            state_change_verified=True,
            before_state=json.dumps({"owner": "user_a"}),
            after_state=json.dumps({"owner": "user_b"}),
            mutation_response=json.dumps({"status": "ok"}),
        )

        mock_result = MagicMock()
        mock_result.changed = True
        mock_result.reason = "owner field changed"

        mock_verifier = MagicMock()
        mock_verifier.verify_mutation.return_value = mock_result

        with patch("engine.core.state_verifier.StateVerifier", return_value=mock_verifier):
            passed, reason, verified = pipeline._stage_state_change(finding)

        assert passed is True
        assert verified is True

    def test_all_state_change_required_types(self):
        """Every type in STATE_CHANGE_REQUIRED should fail without evidence."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        for vuln_type in STATE_CHANGE_REQUIRED:
            finding = _base_finding(vulnerability_type=vuln_type)
            passed, _, _ = pipeline._stage_state_change(finding)
            assert passed is False, f"{vuln_type} should require state change proof"


# ---------------------------------------------------------------------------
# _stage_submission_gate()
# ---------------------------------------------------------------------------

class TestStageSubmissionGate:
    def test_gate_submit(self):
        """When SubmissionGatekeeper says submit=True, verdict should be SUBMIT."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)

        mock_result = {"submit": True, "estimated_bounty": "$1000"}
        with patch("engine.core.quality_gates.SubmissionGatekeeper") as MockGK:
            MockGK.evaluate.return_value = mock_result
            verdict, bounty = pipeline._stage_submission_gate(
                _base_finding(), poc_verified=True, state_verified=False
            )

        assert verdict == "SUBMIT"
        assert bounty == "$1000"

    def test_gate_hold(self):
        """When SubmissionGatekeeper says submit=False, verdict should be HOLD."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)

        mock_result = {"submit": False, "estimated_bounty": "$0"}
        with patch("engine.core.quality_gates.SubmissionGatekeeper") as MockGK:
            MockGK.evaluate.return_value = mock_result
            verdict, bounty = pipeline._stage_submission_gate(
                _base_finding(), poc_verified=False, state_verified=False
            )

        assert verdict == "HOLD"

    def test_gate_import_error_defaults_hold(self):
        """If quality_gates cannot be imported, default to HOLD."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)

        with patch.dict("sys.modules", {"engine.core.quality_gates": None}):
            verdict, bounty = pipeline._stage_submission_gate(
                _base_finding(), poc_verified=True, state_verified=False
            )

        assert verdict == "HOLD"
        assert bounty == "$0"


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

class TestScoringHelpers:
    def test_severity_match_inflated(self):
        """Low-value vuln type with CRITICAL severity should score low."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(vulnerability_type="missing_headers", severity="CRITICAL")
        assert pipeline._assess_severity_match(finding) == 0.2

    def test_severity_match_deflated(self):
        """High-impact vuln type with LOW severity should score low."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(vulnerability_type="sqli", severity="LOW")
        assert pipeline._assess_severity_match(finding) == 0.3

    def test_severity_match_reasonable(self):
        """Normal severity for vuln type should score 0.8."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(vulnerability_type="xss", severity="HIGH")
        assert pipeline._assess_severity_match(finding) == 0.8

    def test_impact_clarity_detailed(self):
        """Long evidence + description should score high."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(evidence="A" * 150, description="B" * 100)
        assert pipeline._assess_impact_clarity(finding) == 0.8

    def test_impact_clarity_sparse(self):
        """Very short evidence should score low."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        finding = _base_finding(evidence="xss", description="")
        assert pipeline._assess_impact_clarity(finding) == 0.2


# ---------------------------------------------------------------------------
# get_stats()
# ---------------------------------------------------------------------------

class TestGetStats:
    def test_initial_stats(self):
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)
        s = pipeline.get_stats()
        assert s["total_validated"] == 0
        assert s["acceptance_rate"] == 0

    def test_stats_after_validations(self):
        """Stats should accumulate across multiple validate() calls."""
        pipeline = ValidationPipeline(skip_poc=True, verbose=False)

        with patch.object(pipeline, "_stage_fp_check", return_value=(True, "ok")), \
             patch.object(pipeline, "_stage_error_classification", return_value=(True, "ok")), \
             patch.object(pipeline, "_stage_poc_validation", return_value=(True, "ok", True)), \
             patch.object(pipeline, "_stage_state_change", return_value=(True, "ok", False)), \
             patch.object(pipeline, "_stage_confidence", return_value=(0.9, "A", "go")), \
             patch.object(pipeline, "_stage_submission_gate", return_value=("SUBMIT", "$100")):
            pipeline.validate(_base_finding())
            pipeline.validate(_base_finding())

        s = pipeline.get_stats()
        assert s["total_validated"] == 2
        assert s["submitted"] == 2
        assert s["acceptance_rate"] == 100.0
