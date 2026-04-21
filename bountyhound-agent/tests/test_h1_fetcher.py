"""
Tests for engine.intel.h1_fetcher — H1Fetcher.

Covers:
  1. Valid GraphQL response with 2 reports → 2 dicts with correct keys
  2. Null team in response → []
  3. ConnectionError → []
  4. JSON parse error → []
  5. Invalid handle (path traversal) → []
  6. POST body uses variables dict, not string interpolation
"""

from unittest.mock import patch, MagicMock

import pytest
import requests

from engine.intel.h1_fetcher import H1Fetcher


# ---------------------------------------------------------------------------
# Shared fixture: a valid GraphQL response payload
# ---------------------------------------------------------------------------

def _make_graphql_response(edges):
    """Build a minimal H1 GraphQL payload with given edge list."""
    return {
        "data": {
            "team": {
                "hacktivity_items": {
                    "edges": edges
                }
            }
        }
    }


def _make_edge(title, disclosed_at="2025-06-01", bounty=500, weakness_name="XSS", asset="*.example.com"):
    return {
        "node": {
            "report": {
                "title": title,
                "disclosed_at": disclosed_at,
                "bounty_amount": bounty,
                "weakness": {"name": weakness_name},
                "structured_scope": {"asset_identifier": asset},
            }
        }
    }


def _mock_post_success(payload):
    """Return a Mock HTTP response that serialises `payload` as JSON."""
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status = MagicMock()
    response.json.return_value = payload
    return response


# ---------------------------------------------------------------------------
# Test 1: Valid response with 2 reports
# ---------------------------------------------------------------------------

class TestFetchValidResponse:
    def test_fetch_valid_response(self):
        """Mock a valid GraphQL response with 2 reports; verify list length and keys."""
        edges = [
            _make_edge("SQL Injection in login", weakness_name="CWE-89"),
            _make_edge("XSS in search", weakness_name="CWE-79"),
        ]
        mock_resp = _mock_post_success(_make_graphql_response(edges))

        with patch("engine.intel.h1_fetcher.requests.post", return_value=mock_resp) as mock_post:
            fetcher = H1Fetcher()
            results = fetcher.fetch("shopify")

        assert len(results) == 2
        expected_keys = {"title", "cwe", "endpoint", "bounty", "date"}
        for result in results:
            assert set(result.keys()) == expected_keys

        assert results[0]["title"] == "SQL Injection in login"
        assert results[0]["cwe"] == "CWE-89"
        assert results[1]["title"] == "XSS in search"
        assert results[1]["cwe"] == "CWE-79"


# ---------------------------------------------------------------------------
# Test 2: Null team
# ---------------------------------------------------------------------------

class TestFetchProgramNotFound:
    def test_fetch_program_not_found(self):
        """When data.team is null, fetch() must return []."""
        payload = {"data": {"team": None}}
        mock_resp = _mock_post_success(payload)

        with patch("engine.intel.h1_fetcher.requests.post", return_value=mock_resp):
            fetcher = H1Fetcher()
            results = fetcher.fetch("nonexistent-program")

        assert results == []


# ---------------------------------------------------------------------------
# Test 3: Network error
# ---------------------------------------------------------------------------

class TestFetchNetworkError:
    def test_fetch_network_error(self):
        """When requests.post raises ConnectionError, fetch() must return []."""
        with patch(
            "engine.intel.h1_fetcher.requests.post",
            side_effect=requests.exceptions.ConnectionError("No route to host"),
        ):
            fetcher = H1Fetcher()
            results = fetcher.fetch("shopify")

        assert results == []


# ---------------------------------------------------------------------------
# Test 4: Invalid JSON
# ---------------------------------------------------------------------------

class TestFetchInvalidJson:
    def test_fetch_invalid_json(self):
        """When response.json() raises ValueError, fetch() must return []."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.side_effect = ValueError("No JSON object could be decoded")

        with patch("engine.intel.h1_fetcher.requests.post", return_value=mock_resp):
            fetcher = H1Fetcher()
            results = fetcher.fetch("shopify")

        assert results == []


# ---------------------------------------------------------------------------
# Test 5: Invalid handle (path traversal)
# ---------------------------------------------------------------------------

class TestFetchInvalidHandle:
    @pytest.mark.parametrize("bad_handle", [
        "../../etc/passwd",
        "../secret",
        "handle with spaces",
        "handle!@#",
        "",
        None,
    ])
    def test_fetch_invalid_handle(self, bad_handle):
        """Path-traversal and non-alphanumeric handles must return [] without an HTTP call."""
        with patch("engine.intel.h1_fetcher.requests.post") as mock_post:
            fetcher = H1Fetcher()
            results = fetcher.fetch(bad_handle)

        assert results == []
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Test 6: POST body uses variables dict
# ---------------------------------------------------------------------------

class TestFetchUsesGraphqlVariables:
    def test_fetch_uses_graphql_variables(self):
        """
        The requests.post call must pass json={"query": ..., "variables": {"handle": ...}}
        rather than interpolating the handle directly into the query string.
        """
        edges = [_make_edge("Test Report")]
        mock_resp = _mock_post_success(_make_graphql_response(edges))

        with patch("engine.intel.h1_fetcher.requests.post", return_value=mock_resp) as mock_post:
            fetcher = H1Fetcher()
            fetcher.fetch("shopify")

        assert mock_post.call_count == 1
        call_kwargs = mock_post.call_args

        # Normalise: could be positional arg 2 or keyword 'json'
        if call_kwargs.kwargs.get("json") is not None:
            body = call_kwargs.kwargs["json"]
        else:
            # positional: post(url, json=...) → args[1] or kwargs
            body = call_kwargs[1].get("json") if len(call_kwargs[0]) < 2 else None

        # Prefer keyword
        body = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")

        assert body is not None, "requests.post was not called with a 'json' keyword argument"
        assert "query" in body
        assert "variables" in body
        assert isinstance(body["variables"], dict)
        assert body["variables"].get("handle") == "shopify"
        # The handle must NOT appear literally interpolated in the raw query string
        assert "shopify" not in body["query"]
