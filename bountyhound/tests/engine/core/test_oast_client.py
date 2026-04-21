import pytest
from unittest.mock import patch, MagicMock
from engine.core.oast_client import OASTClient


class TestOASTClient:
    def test_generates_unique_callback_url(self):
        """Each payload should get a unique callback URL."""
        client = OASTClient(server="interact.sh")
        url1 = client.generate_callback("test1")
        url2 = client.generate_callback("test2")
        assert url1 != url2
        assert "interact.sh" in url1

    def test_checks_for_callbacks(self):
        """Should poll for received callbacks."""
        client = OASTClient(server="interact.sh")
        # Without real server, should return empty
        callbacks = client.poll_callbacks(timeout=1)
        assert isinstance(callbacks, list)

    def test_generates_ssrf_payloads(self):
        """Should generate SSRF payloads pointing to callback URL."""
        client = OASTClient(server="interact.sh")
        payloads = client.generate_ssrf_payloads("ssrf-test-1")
        assert len(payloads) > 0
        assert any("interact.sh" in p for p in payloads)

    def test_generates_xxe_payloads(self):
        """Should generate XXE payloads with callback URL."""
        client = OASTClient(server="interact.sh")
        payloads = client.generate_xxe_payloads("xxe-test-1")
        assert len(payloads) > 0
        assert any("ENTITY" in p for p in payloads)
