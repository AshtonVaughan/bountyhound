import pytest
from engine.agents.rejection_filter import RejectionFilter, Finding, Verdict

class TestRejectionFilter:
    def setup_method(self):
        self.filter = RejectionFilter()

    def test_rejects_intended_functionality(self):
        """Access to own resources is intended, not a vulnerability."""
        finding = Finding(
            title="User can view their own orders",
            description="User A can access /api/orders with their own token",
            evidence="HTTP 200 with order data",
            auth_context="own_account",
        )
        result = self.filter.evaluate(finding)
        assert result.verdict == Verdict.REJECT
        assert "intended functionality" in result.reason.lower()

    def test_rejects_ambiguous_exploitation(self):
        """GraphQL 200 with errors is not exploitation."""
        finding = Finding(
            title="IDOR in GraphQL mutation",
            description="Mutation returned HTTP 200",
            evidence='{"data":null,"errors":[{"message":"Not authorized"}]}',
            auth_context="cross_account",
        )
        result = self.filter.evaluate(finding)
        assert result.verdict == Verdict.REJECT
        assert "ambiguous" in result.reason.lower() or "no state change" in result.reason.lower()

    def test_approves_verified_cross_account_access(self):
        """Cross-account data access with state change proof is valid."""
        finding = Finding(
            title="IDOR: User B can read User A orders",
            description="User B token accessing /api/orders/123 returns User A data",
            evidence="Before: order belongs to User A. After: User B can read it. Different user IDs confirmed.",
            auth_context="cross_account",
            state_change_verified=True,
        )
        result = self.filter.evaluate(finding)
        assert result.verdict in (Verdict.SUBMIT, Verdict.AUTO_SUBMIT)
        assert result.score >= 70

    def test_score_calculation(self):
        """Score follows the formula: auth_violation*40 + clear_exploitation*30 + impact*20 + scope*10."""
        finding = Finding(
            title="Critical IDOR",
            description="Full account takeover via IDOR",
            evidence="Changed email of another user's account",
            auth_context="cross_account",
            state_change_verified=True,
            impact="critical",
            in_scope=True,
        )
        result = self.filter.evaluate(finding)
        assert result.score >= 90  # All factors present

    def test_manual_review_for_borderline(self):
        """Borderline findings go to manual review."""
        finding = Finding(
            title="Information disclosure via error message",
            description="Stack trace leaks internal paths",
            evidence="HTTP 500 with full stack trace",
            auth_context="unauthenticated",
        )
        result = self.filter.evaluate(finding)
        assert result.verdict == Verdict.MANUAL_REVIEW
