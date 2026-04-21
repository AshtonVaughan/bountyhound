"""
Tests for engine.intel.cve_fetcher — CveFetcher.

Covers:
  1. Empty / None tokens → []
  2. Valid NVD response with 1 CVE (CVSS 8.0) → correct dict keys
  3. CVE with CVSS 5.0 is excluded (below 7.0 threshold)
  4. Duplicate CVE IDs across two tokens → only 1 result
  5. Network error (ConnectionError) → []
  6. HTTP 429 first call → retry → valid result returned
"""

from unittest.mock import patch, MagicMock, call
import requests

import pytest

from engine.intel.cve_fetcher import CveFetcher


# ---------------------------------------------------------------------------
# NVD response builders
# ---------------------------------------------------------------------------

def _nvd_response(cve_id: str, cvss: float, description: str = "Test CVE") -> dict:
    """Build a minimal NVD API v2 response payload with one CVE."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": cvss,
                                }
                            }
                        ]
                    },
                    "configurations": [],
                }
            }
        ]
    }


def _mock_get_success(payload: dict):
    """Return a Mock GET response that yields `payload` from .json()."""
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status = MagicMock()
    response.json.return_value = payload
    return response


def _mock_get_429():
    """Return a Mock response with status_code 429."""
    response = MagicMock()
    response.status_code = 429
    response.raise_for_status = MagicMock()
    return response


# ---------------------------------------------------------------------------
# Test 1: Empty / None tokens
# ---------------------------------------------------------------------------

class TestFetchEmptyTokens:
    @pytest.mark.parametrize("tokens", [[], None])
    def test_fetch_empty_tokens(self, tokens):
        """fetch([]) and fetch(None) must both return [] without any HTTP call."""
        with patch("engine.intel.cve_fetcher.requests.get") as mock_get:
            fetcher = CveFetcher()
            results = fetcher.fetch(tokens)

        assert results == []
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2: Valid CVE response
# ---------------------------------------------------------------------------

class TestFetchValidCve:
    def test_fetch_valid_cve(self):
        """A response with 1 CVE at CVSS 8.0 must be included and have correct keys."""
        payload = _nvd_response("CVE-2024-9999", cvss=8.0, description="Critical RCE vulnerability")
        mock_resp = _mock_get_success(payload)

        with patch("engine.intel.cve_fetcher.requests.get", return_value=mock_resp):
            with patch("engine.intel.cve_fetcher.time.sleep"):  # suppress rate-limit sleeps
                fetcher = CveFetcher()
                results = fetcher.fetch(["rails"])

        assert len(results) == 1
        cve = results[0]
        assert set(cve.keys()) == {"id", "description", "cvss", "affected"}
        assert cve["id"] == "CVE-2024-9999"
        assert cve["cvss"] == 8.0
        assert "Critical RCE" in cve["description"]


# ---------------------------------------------------------------------------
# Test 3: Low CVSS → excluded
# ---------------------------------------------------------------------------

class TestFetchFiltersLowCvss:
    def test_fetch_filters_low_cvss(self):
        """CVE with CVSS 5.0 (below 7.0 threshold) must not appear in results."""
        payload = _nvd_response("CVE-2024-0001", cvss=5.0, description="Low severity issue")
        mock_resp = _mock_get_success(payload)

        with patch("engine.intel.cve_fetcher.requests.get", return_value=mock_resp):
            with patch("engine.intel.cve_fetcher.time.sleep"):
                fetcher = CveFetcher()
                results = fetcher.fetch(["nginx"])

        assert results == []


# ---------------------------------------------------------------------------
# Test 4: Deduplication across tokens
# ---------------------------------------------------------------------------

class TestFetchDeduplication:
    def test_fetch_deduplication(self):
        """
        Two tokens that both return the same CVE ID must yield only 1 result.
        """
        shared_cve = _nvd_response("CVE-2024-SHARED", cvss=9.1, description="Shared CVE")
        mock_resp = _mock_get_success(shared_cve)

        with patch("engine.intel.cve_fetcher.requests.get", return_value=mock_resp):
            with patch("engine.intel.cve_fetcher.time.sleep"):
                fetcher = CveFetcher()
                results = fetcher.fetch(["token-a", "token-b"])

        assert len(results) == 1
        assert results[0]["id"] == "CVE-2024-SHARED"


# ---------------------------------------------------------------------------
# Test 5: Network error
# ---------------------------------------------------------------------------

class TestFetchNetworkError:
    def test_fetch_network_error(self):
        """When requests.get raises ConnectionError, fetch() must return []."""
        with patch(
            "engine.intel.cve_fetcher.requests.get",
            side_effect=requests.exceptions.ConnectionError("unreachable"),
        ):
            with patch("engine.intel.cve_fetcher.time.sleep"):
                fetcher = CveFetcher()
                results = fetcher.fetch(["rails"])

        assert results == []


# ---------------------------------------------------------------------------
# Test 6: HTTP 429 → retry → valid result
# ---------------------------------------------------------------------------

class TestFetch429Retry:
    def test_fetch_429_retry(self):
        """
        First GET returns HTTP 429; second (retry) returns valid CVE data.
        The result must contain the CVE from the second call.
        """
        payload = _nvd_response("CVE-2024-RETRY", cvss=7.5, description="Retry CVE")
        good_resp = _mock_get_success(payload)

        side_effects = [_mock_get_429(), good_resp]

        with patch(
            "engine.intel.cve_fetcher.requests.get",
            side_effect=side_effects,
        ) as mock_get:
            with patch("engine.intel.cve_fetcher.time.sleep"):  # suppress sleep delays
                fetcher = CveFetcher()
                results = fetcher.fetch(["rails"])

        # Two GET calls: original + retry
        assert mock_get.call_count == 2
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2024-RETRY"
