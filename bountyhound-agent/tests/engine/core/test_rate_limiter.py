"""Unit tests for engine.core.rate_limiter module."""

import unittest
from unittest.mock import patch

from engine.core.rate_limiter import RateLimiter, WAFDetector


class TestWAFDetector(unittest.TestCase):
    """Tests for WAFDetector.detect()."""

    def test_429_returns_rate_limit(self):
        result = WAFDetector.detect(429, {})
        assert result == 'rate-limit'

    def test_cloudflare_cf_ray_header_403(self):
        result = WAFDetector.detect(403, {'CF-Ray': 'abc123'})
        assert result == 'cloudflare'

    def test_cloudflare_cf_ray_header_503(self):
        result = WAFDetector.detect(503, {'CF-Ray': 'abc123'})
        assert result == 'cloudflare'

    def test_cloudflare_body_pattern_403(self):
        result = WAFDetector.detect(403, {}, body='Attention Required! | Cloudflare')
        assert result == 'cloudflare'

    def test_aws_waf_header(self):
        result = WAFDetector.detect(403, {'X-Amzn-WAF-Action': 'BLOCK'})
        assert result == 'aws-waf'

    def test_aws_waf_server_header(self):
        result = WAFDetector.detect(403, {'Server': 'awselb/2.0'})
        assert result == 'aws-waf'

    def test_akamai_grn_header(self):
        result = WAFDetector.detect(200, {'Akamai-GRN': 'abc'})
        assert result == 'akamai'

    def test_akamai_server_header_403(self):
        result = WAFDetector.detect(403, {'Server': 'AkamaiGHost'})
        assert result == 'akamai'

    def test_imperva_incap_ses_cookie(self):
        result = WAFDetector.detect(200, {'Set-Cookie': 'incap_ses_123=abc'})
        assert result == 'imperva'

    def test_imperva_body_pattern_403(self):
        result = WAFDetector.detect(403, {}, body='Powered by Incapsula')
        assert result == 'imperva'

    def test_generic_503_service_unavailable(self):
        result = WAFDetector.detect(503, {})
        assert result == 'service-unavailable'

    def test_normal_200_returns_none(self):
        result = WAFDetector.detect(200, {'Content-Type': 'text/html'})
        assert result is None

    def test_normal_403_no_waf_signatures(self):
        result = WAFDetector.detect(403, {'Content-Type': 'text/html'}, body='Forbidden')
        assert result is None


class TestRateLimiterAcquire(unittest.TestCase):
    """Tests for RateLimiter.acquire() token bucket behavior."""

    @patch('engine.core.rate_limiter.time')
    def test_first_request_passes_immediately(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        mock_time.sleep = lambda x: None

        limiter = RateLimiter(default_rps=5.0)
        limiter.acquire('example.com')

        state = limiter._domains['example.com']
        assert state.total_requests == 1
        assert state.last_request == 100.0

    @patch('engine.core.rate_limiter.time')
    def test_request_within_interval_waits(self, mock_time):
        """Second request within min_interval should trigger a sleep."""
        call_count = [0]
        sleep_called_with = []

        def fake_monotonic():
            call_count[0] += 1
            # Call 1: acquire #1 checks time (100.0), passes immediately
            # Call 2: acquire #2 checks time (100.05), too soon -> sleep
            # Call 3: acquire #2 retries (100.25), enough time passed
            if call_count[0] == 1:
                return 100.0
            elif call_count[0] == 2:
                return 100.05  # only 0.05s elapsed, interval is 0.2s
            else:
                return 100.25  # now enough time has passed

        def fake_sleep(duration):
            sleep_called_with.append(duration)

        mock_time.monotonic = fake_monotonic
        mock_time.sleep = fake_sleep

        limiter = RateLimiter(default_rps=5.0)  # min_interval = 0.2s
        limiter.acquire('example.com')
        limiter.acquire('example.com')

        assert len(sleep_called_with) == 1
        assert sleep_called_with[0] > 0

    @patch('engine.core.rate_limiter.time')
    def test_request_after_interval_passes(self, mock_time):
        """Request after min_interval should pass without sleeping."""
        call_count = [0]

        def fake_monotonic():
            call_count[0] += 1
            if call_count[0] <= 2:
                return 100.0
            return 101.0  # 1 second later, well past the 0.2s interval

        mock_time.monotonic = fake_monotonic
        mock_time.sleep = lambda x: None

        limiter = RateLimiter(default_rps=5.0)
        limiter.acquire('example.com')
        limiter.acquire('example.com')

        assert limiter._domains['example.com'].total_requests == 2


class TestRateLimiterReportResponse(unittest.TestCase):
    """Tests for RateLimiter.report_response() and backoff behavior."""

    @patch('engine.core.rate_limiter.time')
    def test_success_resets_backoff(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter()
        # Trigger a backoff first
        limiter.report_response('example.com', 429, {})
        state = limiter._domains['example.com']
        assert state.backoff_count == 1

        # Successful response resets
        limiter.report_response('example.com', 200, {})
        assert state.backoff_count == 0
        assert state.last_waf is None

    @patch('engine.core.rate_limiter.time')
    def test_429_triggers_exponential_backoff(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter()

        limiter.report_response('example.com', 429, {})
        state = limiter._domains['example.com']
        assert state.backoff_count == 1
        assert state.total_blocks == 1
        assert state.last_waf == 'rate-limit'
        # backoff_until = 100.0 + 2^1 = 102.0
        assert state.backoff_until == 102.0

        limiter.report_response('example.com', 429, {})
        assert state.backoff_count == 2
        # backoff_until = 100.0 + 2^2 = 104.0
        assert state.backoff_until == 104.0

    @patch('engine.core.rate_limiter.time')
    def test_retry_after_header_honored(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter()

        limiter.report_response('example.com', 429, {'Retry-After': '30'})
        state = limiter._domains['example.com']
        assert state.backoff_until == 130.0

    @patch('engine.core.rate_limiter.time')
    def test_retry_after_capped_by_max_backoff(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter(max_backoff=60.0)

        limiter.report_response('example.com', 429, {'Retry-After': '300'})
        state = limiter._domains['example.com']
        # Should be capped at 60
        assert state.backoff_until == 160.0

    @patch('engine.core.rate_limiter.time')
    def test_exponential_backoff_capped(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter(max_backoff=120.0)

        # Trigger many consecutive blocks
        for _ in range(20):
            limiter.report_response('example.com', 429, {})

        state = limiter._domains['example.com']
        # 2^20 = 1048576, but capped at 120
        assert state.backoff_until == 220.0


class TestRateLimiterIsBlocked(unittest.TestCase):
    """Tests for RateLimiter.is_blocked()."""

    @patch('engine.core.rate_limiter.time')
    def test_not_blocked_initially(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter()
        assert limiter.is_blocked('example.com') is False

    @patch('engine.core.rate_limiter.time')
    def test_blocked_during_backoff(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter()
        limiter.report_response('example.com', 429, {})

        # Still within backoff window
        mock_time.monotonic.return_value = 101.0
        assert limiter.is_blocked('example.com') is True

    @patch('engine.core.rate_limiter.time')
    def test_unblocked_after_backoff_expires(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        limiter = RateLimiter()
        limiter.report_response('example.com', 429, {})

        # After backoff window (2^1 = 2 seconds)
        mock_time.monotonic.return_value = 103.0
        assert limiter.is_blocked('example.com') is False


class TestRateLimiterSetRps(unittest.TestCase):
    """Tests for RateLimiter.set_rps()."""

    def test_set_rps_updates_interval(self):
        limiter = RateLimiter(default_rps=5.0)
        limiter.set_rps('example.com', 10.0)

        state = limiter._domains['example.com']
        assert state.rps == 10.0
        assert abs(state.min_interval - 0.1) < 1e-9

    def test_set_rps_zero_raises(self):
        limiter = RateLimiter()
        with self.assertRaises(ValueError):
            limiter.set_rps('example.com', 0)

    def test_set_rps_negative_raises(self):
        limiter = RateLimiter()
        with self.assertRaises(ValueError):
            limiter.set_rps('example.com', -1.0)


class TestDomainIsolation(unittest.TestCase):
    """Tests for domain-specific state isolation."""

    @patch('engine.core.rate_limiter.time')
    def test_domains_have_independent_state(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        mock_time.sleep = lambda x: None

        limiter = RateLimiter(default_rps=5.0)
        limiter.acquire('a.com')
        limiter.report_response('a.com', 429, {})

        # b.com should be unaffected
        limiter.acquire('b.com')
        assert limiter._domains['a.com'].total_blocks == 1
        assert limiter._domains['b.com'].total_blocks == 0
        assert limiter.is_blocked('a.com') is True
        mock_time.monotonic.return_value = 100.5
        assert limiter.is_blocked('b.com') is False

    @patch('engine.core.rate_limiter.time')
    def test_set_rps_only_affects_target_domain(self, mock_time):
        mock_time.monotonic.return_value = 100.0
        mock_time.sleep = lambda x: None

        limiter = RateLimiter(default_rps=5.0)
        limiter.acquire('a.com')
        limiter.acquire('b.com')
        limiter.set_rps('a.com', 20.0)

        assert limiter._domains['a.com'].rps == 20.0
        assert limiter._domains['b.com'].rps == 5.0


if __name__ == '__main__':
    unittest.main()
