import pytest
import json
from unittest.mock import patch, MagicMock
from engine.core.state_verifier import StateVerifier, StateCheckResult

class TestStateVerifier:
    def setup_method(self):
        self.verifier = StateVerifier()

    def test_detects_actual_state_change(self):
        """When before != after, state change is confirmed."""
        before = {"user": {"email": "alice@test.com", "name": "Alice"}}
        after = {"user": {"email": "evil@hacker.com", "name": "Alice"}}
        result = self.verifier.compare_states(before, after)
        assert result.changed is True
        assert "email" in str(result.diff)

    def test_detects_no_state_change(self):
        """When before == after, no state change."""
        before = {"user": {"email": "alice@test.com"}}
        after = {"user": {"email": "alice@test.com"}}
        result = self.verifier.compare_states(before, after)
        assert result.changed is False

    def test_graphql_error_is_not_state_change(self):
        """GraphQL returning errors in data means mutation failed."""
        before = {"user": {"email": "alice@test.com"}}
        mutation_response = {"data": None, "errors": [{"message": "Not authorized"}]}
        after = {"user": {"email": "alice@test.com"}}
        result = self.verifier.verify_mutation(
            before_state=before,
            mutation_response=mutation_response,
            after_state=after,
        )
        assert result.changed is False
        assert result.mutation_succeeded is False

    def test_graphql_success_with_state_change(self):
        """GraphQL mutation that actually changes data."""
        before = {"user": {"email": "alice@test.com"}}
        mutation_response = {"data": {"updateUser": {"email": "evil@hacker.com"}}}
        after = {"user": {"email": "evil@hacker.com"}}
        result = self.verifier.verify_mutation(
            before_state=before,
            mutation_response=mutation_response,
            after_state=after,
        )
        assert result.changed is True
        assert result.mutation_succeeded is True

    def test_http_200_alone_is_not_proof(self):
        """HTTP 200 without state comparison is insufficient."""
        result = self.verifier.verify_from_status_code(200)
        assert result.changed is False
        assert "insufficient" in result.reason.lower()
