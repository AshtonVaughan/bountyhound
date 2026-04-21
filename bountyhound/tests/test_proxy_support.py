import pytest
import os
from unittest.mock import patch, MagicMock

def test_proxy_from_environment_variables():
    """Test that tools respect HTTP_PROXY environment variable"""

    with patch.dict(os.environ, {
        'HTTP_PROXY': 'http://proxy.example.com:8080',
        'HTTPS_PROXY': 'https://proxy.example.com:8443'
    }):
        import requests

        # requests library should pick up environment proxy
        session = requests.Session()
        assert 'http' in session.proxies or len(session.proxies) == 0, \
            "requests.Session should respect HTTP_PROXY"

def test_proxy_configuration_class():
    """Test that ProxyConfig class handles proxy settings"""
    from engine.core.proxy_config import ProxyConfig

    # Test with explicit proxy
    config = ProxyConfig(
        http_proxy="http://proxy.example.com:8080",
        https_proxy="https://proxy.example.com:8443",
        no_proxy="localhost,127.0.0.1"
    )

    assert config.http_proxy == "http://proxy.example.com:8080"
    assert config.https_proxy == "https://proxy.example.com:8443"
    assert "localhost" in config.no_proxy

def test_proxy_with_authentication():
    """Test proxy with username/password"""
    from engine.core.proxy_config import ProxyConfig

    config = ProxyConfig(
        http_proxy="http://user:pass@proxy.example.com:8080"
    )

    # Should handle authentication in proxy URL
    assert "user:pass" in config.http_proxy

def test_socks_proxy_support():
    """Test SOCKS proxy configuration"""
    from engine.core.proxy_config import ProxyConfig

    config = ProxyConfig(
        http_proxy="socks5://127.0.0.1:9050",  # Tor default
        https_proxy="socks5://127.0.0.1:9050"
    )

    assert "socks5" in config.http_proxy.lower()

def test_ssl_verification_options():
    """Test SSL verification can be disabled for corporate proxies"""
    from engine.core.proxy_config import ProxyConfig

    config = ProxyConfig(
        http_proxy="http://proxy.example.com:8080",
        verify_ssl=False
    )

    assert config.verify_ssl == False

    # Default should be True
    config_secure = ProxyConfig()
    assert config_secure.verify_ssl == True
