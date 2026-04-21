"""
Proxy configuration helper for BountyHound scanning tools.

Supports HTTP, HTTPS, and SOCKS proxies with authentication.
"""

import os
from typing import Optional, Dict
from colorama import Fore, Style, init

init(autoreset=True)


class ProxyConfig:
    """
    Centralized proxy configuration for all scanning tools.

    Supports:
    - HTTP/HTTPS proxies
    - SOCKS4/SOCKS5 proxies
    - Proxy authentication
    - SSL verification control
    - Environment variable fallback
    """

    def __init__(
        self,
        http_proxy: Optional[str] = None,
        https_proxy: Optional[str] = None,
        no_proxy: Optional[str] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize proxy configuration.

        Args:
            http_proxy: HTTP proxy URL (e.g., http://proxy.example.com:8080)
            https_proxy: HTTPS proxy URL
            no_proxy: Comma-separated list of hosts to exclude from proxy
            verify_ssl: Whether to verify SSL certificates (default: True)

        Examples:
            # Basic proxy
            config = ProxyConfig(http_proxy="http://127.0.0.1:8080")

            # Proxy with authentication
            config = ProxyConfig(
                http_proxy="http://user:pass@proxy.example.com:8080"
            )

            # SOCKS proxy (Tor)
            config = ProxyConfig(
                http_proxy="socks5://127.0.0.1:9050",
                https_proxy="socks5://127.0.0.1:9050"
            )

            # Corporate proxy (disable SSL verification)
            config = ProxyConfig(
                http_proxy="http://corporate-proxy:8080",
                verify_ssl=False
            )
        """
        # Use provided values or fall back to environment
        self.http_proxy = http_proxy or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        self.https_proxy = https_proxy or os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
        self.no_proxy = no_proxy or os.environ.get('NO_PROXY') or os.environ.get('no_proxy') or ''
        self.verify_ssl = verify_ssl

        # Print configuration
        if self.http_proxy or self.https_proxy:
            print(f"{Fore.CYAN}[*] Proxy configuration loaded:{Style.RESET_ALL}")
            if self.http_proxy:
                print(f"    HTTP: {self._sanitize_proxy_url(self.http_proxy)}")
            if self.https_proxy:
                print(f"    HTTPS: {self._sanitize_proxy_url(self.https_proxy)}")
            if not self.verify_ssl:
                print(f"{Fore.YELLOW}[!] SSL verification disabled{Style.RESET_ALL}")

    def _sanitize_proxy_url(self, url: str) -> str:
        """Hide credentials in proxy URL for display"""
        if '@' in url:
            # Hide credentials: http://user:pass@host:port -> http://***:***@host:port
            proto, rest = url.split('://', 1)
            creds, host = rest.split('@', 1)
            return f"{proto}://***:***@{host}"
        return url

    def to_dict(self) -> Dict[str, str]:
        """
        Convert to dictionary for requests library.

        Returns:
            dict: Proxy configuration for requests.Session.proxies

        Example:
            session = requests.Session()
            session.proxies = config.to_dict()
        """
        proxies = {}
        if self.http_proxy:
            proxies['http'] = self.http_proxy
        if self.https_proxy:
            proxies['https'] = self.https_proxy
        return proxies

    def to_boto3_config(self):
        """
        Convert to boto3 ProxyConfiguration.

        Returns:
            boto3.config.Config: Configuration for boto3 clients

        Example:
            s3 = boto3.client('s3', config=proxy_config.to_boto3_config())
        """
        from botocore.config import Config

        proxy_config = {}
        if self.http_proxy:
            proxy_config['proxy'] = self.http_proxy

        return Config(
            proxies=proxy_config if proxy_config else None,
            proxies_config={'proxy_use_forwarding_for_https': True}
        )
