"""
Unit tests for engine.core.scope_validator module.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from engine.core.scope_validator import (
    ScopeRule,
    ProgramScope,
    ScopeValidator,
    create_scope_from_dict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scope(
    in_scope: list[ScopeRule] | None = None,
    out_of_scope: list[ScopeRule] | None = None,
    excluded_vuln_types: list[str] | None = None,
) -> ProgramScope:
    return ProgramScope(
        program_name="test-program",
        platform="hackerone",
        in_scope=in_scope or [],
        out_of_scope=out_of_scope or [],
        excluded_vuln_types=excluded_vuln_types or [],
    )


def _validator_with_scope(scope: ProgramScope) -> ScopeValidator:
    """Create a ScopeValidator with an injected scope (no file I/O)."""
    with patch.object(ScopeValidator, "_load_scope"):
        sv = ScopeValidator("test-target")
    sv.scope = scope
    return sv


# ---------------------------------------------------------------------------
# is_domain_in_scope
# ---------------------------------------------------------------------------

class TestIsDomainInScope:
    def test_exact_domain_match(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, reason = sv.is_domain_in_scope("example.com")
        assert in_scope is True
        assert "IN SCOPE" in reason

    def test_subdomain_of_domain_rule(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, _ = sv.is_domain_in_scope("sub.example.com")
        assert in_scope is True

    def test_domain_not_in_scope(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, reason = sv.is_domain_in_scope("evil.com")
        assert in_scope is False
        assert "NOT IN SCOPE" in reason

    def test_wildcard_matches_subdomain(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="*.example.com", rule_type="wildcard"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, _ = sv.is_domain_in_scope("api.example.com")
        assert in_scope is True

    def test_wildcard_matches_base_domain(self):
        """*.example.com should also match example.com itself per implementation."""
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="*.example.com", rule_type="wildcard"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, _ = sv.is_domain_in_scope("example.com")
        assert in_scope is True

    def test_out_of_scope_takes_priority(self):
        scope = _make_scope(
            in_scope=[ScopeRule(pattern="*.example.com", rule_type="wildcard")],
            out_of_scope=[ScopeRule(pattern="staging.example.com", rule_type="domain", in_scope=False)],
        )
        sv = _validator_with_scope(scope)
        in_scope, reason = sv.is_domain_in_scope("staging.example.com")
        assert in_scope is False
        assert "OUT OF SCOPE" in reason

    def test_no_scope_defined_returns_true(self):
        with patch.object(ScopeValidator, "_load_scope"):
            sv = ScopeValidator("test-target")
        sv.scope = None
        in_scope, reason = sv.is_domain_in_scope("anything.com")
        assert in_scope is True
        assert "No scope defined" in reason

    def test_case_insensitive(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="Example.COM", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, _ = sv.is_domain_in_scope("EXAMPLE.com")
        assert in_scope is True


# ---------------------------------------------------------------------------
# is_url_in_scope
# ---------------------------------------------------------------------------

class TestIsUrlInScope:
    def test_url_with_in_scope_domain(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, _ = sv.is_url_in_scope("https://example.com/api/v1")
        assert in_scope is True

    def test_url_with_out_of_scope_domain(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, _ = sv.is_url_in_scope("https://evil.com/test")
        assert in_scope is False

    def test_url_path_exclusion(self):
        scope = _make_scope(
            in_scope=[ScopeRule(pattern="example.com", rule_type="domain")],
            out_of_scope=[ScopeRule(pattern="/admin", rule_type="url", in_scope=False)],
        )
        sv = _validator_with_scope(scope)
        in_scope, reason = sv.is_url_in_scope("https://example.com/admin/settings")
        assert in_scope is False
        assert "OUT OF SCOPE" in reason

    def test_invalid_url(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        in_scope, reason = sv.is_url_in_scope("not-a-url")
        assert in_scope is False
        assert "Invalid URL" in reason


# ---------------------------------------------------------------------------
# validate_target_list
# ---------------------------------------------------------------------------

class TestValidateTargetList:
    def test_mixed_targets(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
            ScopeRule(pattern="10.0.0.0/8", rule_type="ip_range"),
        ])
        sv = _validator_with_scope(scope)
        results = sv.validate_target_list([
            "example.com",
            "evil.com",
            "https://example.com/test",
            "10.0.0.5",
        ])
        assert results["example.com"]["in_scope"] is True
        assert results["evil.com"]["in_scope"] is False
        assert results["https://example.com/test"]["in_scope"] is True
        assert results["10.0.0.5"]["in_scope"] is True

    def test_empty_list(self):
        scope = _make_scope()
        sv = _validator_with_scope(scope)
        results = sv.validate_target_list([])
        assert results == {}


# ---------------------------------------------------------------------------
# is_vuln_type_allowed
# ---------------------------------------------------------------------------

class TestIsVulnTypeAllowed:
    def test_allowed(self):
        scope = _make_scope(excluded_vuln_types=["rate limiting"])
        sv = _validator_with_scope(scope)
        allowed, _ = sv.is_vuln_type_allowed("XSS")
        assert allowed is True

    def test_excluded_exact(self):
        scope = _make_scope(excluded_vuln_types=["rate limiting"])
        sv = _validator_with_scope(scope)
        allowed, reason = sv.is_vuln_type_allowed("rate limiting")
        assert allowed is False
        assert "EXCLUDED" in reason

    def test_excluded_substring(self):
        scope = _make_scope(excluded_vuln_types=["social engineering"])
        sv = _validator_with_scope(scope)
        allowed, _ = sv.is_vuln_type_allowed("social engineering via phishing")
        assert allowed is False

    def test_no_scope_allows_all(self):
        with patch.object(ScopeValidator, "_load_scope"):
            sv = ScopeValidator("test-target")
        sv.scope = None
        allowed, _ = sv.is_vuln_type_allowed("anything")
        assert allowed is True


# ---------------------------------------------------------------------------
# get_max_severity
# ---------------------------------------------------------------------------

class TestGetMaxSeverity:
    def test_severity_cap_present(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain", max_severity="medium"),
        ])
        sv = _validator_with_scope(scope)
        assert sv.get_max_severity("example.com") == "medium"

    def test_severity_cap_absent(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain"),
        ])
        sv = _validator_with_scope(scope)
        assert sv.get_max_severity("example.com") is None

    def test_severity_no_scope(self):
        with patch.object(ScopeValidator, "_load_scope"):
            sv = ScopeValidator("test-target")
        sv.scope = None
        assert sv.get_max_severity("example.com") is None

    def test_severity_subdomain_inherits(self):
        scope = _make_scope(in_scope=[
            ScopeRule(pattern="*.example.com", rule_type="wildcard", max_severity="low"),
        ])
        sv = _validator_with_scope(scope)
        assert sv.get_max_severity("api.example.com") == "low"


# ---------------------------------------------------------------------------
# create_scope_from_dict helper
# ---------------------------------------------------------------------------

class TestCreateScopeFromDict:
    def test_string_items(self):
        scope = create_scope_from_dict("test", {
            "program_name": "Test",
            "platform": "hackerone",
            "in_scope": ["example.com", "*.api.example.com"],
            "out_of_scope": ["staging.example.com"],
            "excluded_vuln_types": ["DoS"],
        })
        assert scope.program_name == "Test"
        assert len(scope.in_scope) == 2
        assert scope.in_scope[0].rule_type == "domain"
        assert scope.in_scope[1].rule_type == "wildcard"
        assert len(scope.out_of_scope) == 1
        assert scope.excluded_vuln_types == ["DoS"]

    def test_dict_items(self):
        scope = create_scope_from_dict("test", {
            "in_scope": [{"pattern": "10.0.0.0/8", "type": "ip_range", "max_severity": "high"}],
        })
        assert scope.in_scope[0].rule_type == "ip_range"
        assert scope.in_scope[0].max_severity == "high"
