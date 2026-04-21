"""
BountyHound Authentication Manager

Creates and manages authenticated sessions for testing agents.
Handles multi-user authentication for IDOR testing.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import os
import json
import time
import jwt
import base64
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from colorama import Fore, Style
from dotenv import load_dotenv, set_key



class AuthManager:
    """Manages authentication for bug bounty testing"""

    def __init__(self, target: str, hunt_id: Optional[str] = None):
        """
        Initialize authentication manager.

        Args:
            target: Target domain (e.g., "app.example.com")
            hunt_id: Hunt identifier (defaults to H-{timestamp})
        """
        self.target = target
        self.hunt_id = hunt_id or f"H-{int(time.time())}"

        # Setup paths
        self.base_dir = Path.home() / ".bountyhound" / "hunts" / self.hunt_id
        self.auth_dir = self.base_dir / "auth"
        self.auth_dir.mkdir(parents=True, exist_ok=True)

        # User storage
        self.users = {}
        self.credentials = {}
        self.tokens = {}

        print(f"{Fore.CYAN}[*] Auth Manager initialized for {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Hunt ID: {self.hunt_id}{Style.RESET_ALL}")

    def generate_test_identity(self, user_id: str) -> Dict[str, str]:
        """
        Generate disposable test identity.

        Args:
            user_id: User identifier (e.g., "user_a", "user_b")

        Returns:
            Dict with email, password, username, name
        """
        random_str = secrets.token_hex(4)

        suffix = ""
        if user_id == "user_b":
            suffix = "2"

        identity = {
            "email": f"bh.test{suffix}.{random_str}@gmail.com",
            "password": f"BhTest{suffix}!{random_str}#Secure",
            "username": f"bhtest{suffix}_{random_str}",
            "name": f"Test User {user_id.split('_')[1].upper()}"
        }

        print(f"{Fore.GREEN}[+] Generated identity for {user_id}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    Email: {identity['email']}{Style.RESET_ALL}")

        return identity

    def load_credentials(self, creds_file: str) -> bool:
        """
        Load credentials from .env file.

        Args:
            creds_file: Path to .env file

        Returns:
            True if successful, False otherwise
        """
        if not os.path.exists(creds_file):
            print(f"{Fore.YELLOW}[!] Credentials file not found: {creds_file}{Style.RESET_ALL}")
            return False

        try:
            load_dotenv(creds_file)

            # Load User A credentials
            self.credentials["user_a"] = {
                "email": os.getenv("USER_A_EMAIL"),
                "password": os.getenv("USER_A_PASSWORD"),
                "auth_token": os.getenv("USER_A_AUTH_TOKEN"),
                "session_cookie": os.getenv("USER_A_SESSION_COOKIE"),
                "csrf_token": os.getenv("USER_A_CSRF_TOKEN"),
                "refresh_token": os.getenv("USER_A_REFRESH_TOKEN"),
                "token_expiry": os.getenv("USER_A_TOKEN_EXPIRY")
            }

            # Load User B credentials
            self.credentials["user_b"] = {
                "email": os.getenv("USER_B_EMAIL"),
                "password": os.getenv("USER_B_PASSWORD"),
                "auth_token": os.getenv("USER_B_AUTH_TOKEN"),
                "session_cookie": os.getenv("USER_B_SESSION_COOKIE"),
                "csrf_token": os.getenv("USER_B_CSRF_TOKEN"),
                "refresh_token": os.getenv("USER_B_REFRESH_TOKEN"),
                "token_expiry": os.getenv("USER_B_TOKEN_EXPIRY")
            }

            print(f"{Fore.GREEN}[+] Loaded credentials from {creds_file}{Style.RESET_ALL}")
            return True

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load credentials: {e}{Style.RESET_ALL}")
            return False

    def save_credentials(self, user_id: str, creds: Dict[str, str], tokens: Dict[str, Any]) -> str:
        """
        Save user credentials and tokens to files.

        Args:
            user_id: User identifier (e.g., "user_a")
            creds: User credentials dict
            tokens: Token dict with cookies, headers, storage

        Returns:
            Path to saved credentials file
        """
        # Save detailed JSON
        user_file = self.auth_dir / f"{user_id}.json"

        user_data = {
            "hunt_id": self.hunt_id,
            "target": self.target,
            "user_id": user_id,
            "created_at": datetime.now().isoformat(),
            "credentials": creds,
            "tokens": tokens,
            "profile": self._extract_profile(tokens),
            "curl_template": self._generate_curl_template(tokens),
            "token_expiry": self._calculate_token_expiry(tokens),
            "needs_refresh_at": self._calculate_refresh_time(tokens)
        }

        with open(user_file, 'w') as f:
            json.dump(user_data, f, indent=2)

        print(f"{Fore.GREEN}[+] Saved {user_id} data to {user_file}{Style.RESET_ALL}")

        # Save to .env format for easy sourcing
        env_file = Path.home() / "BountyHound" / "bountyhound-agent" / "findings" / self.target / "credentials" / f"{self.target}-creds.env"
        env_file.parent.mkdir(parents=True, exist_ok=True)

        # Append to .env file
        prefix = user_id.upper()
        env_vars = {
            f"{prefix}_EMAIL": creds.get("email", ""),
            f"{prefix}_PASSWORD": creds.get("password", ""),
            f"{prefix}_AUTH_TOKEN": tokens.get("headers", {}).get("Authorization", ""),
            f"{prefix}_SESSION_COOKIE": self._format_cookies(tokens.get("cookies", [])),
            f"{prefix}_CSRF_TOKEN": tokens.get("headers", {}).get("X-CSRF-Token", ""),
            f"{prefix}_REFRESH_TOKEN": tokens.get("refresh_token", ""),
            f"{prefix}_TOKEN_EXPIRY": user_data["token_expiry"]
        }

        for key, value in env_vars.items():
            if value:
                set_key(str(env_file), key, value)

        print(f"{Fore.GREEN}[+] Updated .env file: {env_file}{Style.RESET_ALL}")

        return str(user_file)

    def authenticate(self, method: str, **kwargs) -> Dict[str, Any]:
        """
        Authenticate using specified method.

        Args:
            method: Auth method (jwt, oauth2, session, api_key)
            **kwargs: Method-specific parameters

        Returns:
            Dict with authentication tokens
        """
        if method == "jwt":
            return self._authenticate_jwt(**kwargs)
        elif method == "oauth2":
            return self._authenticate_oauth2(**kwargs)
        elif method == "session":
            return self._authenticate_session(**kwargs)
        elif method == "api_key":
            return self._authenticate_api_key(**kwargs)
        else:
            raise ValueError(f"Unknown auth method: {method}")

    def _authenticate_jwt(self, username: str, password: str, endpoint: str) -> Dict[str, Any]:
        """Authenticate and extract JWT token"""
        import requests

        try:
            response = requests.post(
                endpoint,
                json={"username": username, "password": password}
            )

            if response.status_code == 200:
                data = response.json()
                token = data.get("token") or data.get("access_token")

                if token:
                    # Decode JWT to get expiry
                    try:
                        decoded = jwt.decode(token, options={"verify_signature": False})
                        exp = decoded.get("exp")

                        return {
                            "headers": {
                                "Authorization": f"Bearer {token}"
                            },
                            "token": token,
                            "expires_at": datetime.fromtimestamp(exp).isoformat() if exp else None,
                            "payload": decoded
                        }
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Could not decode JWT: {e}{Style.RESET_ALL}")
                        return {
                            "headers": {
                                "Authorization": f"Bearer {token}"
                            },
                            "token": token
                        }

            print(f"{Fore.RED}[!] JWT auth failed: {response.status_code}{Style.RESET_ALL}")
            return {}

        except Exception as e:
            print(f"{Fore.RED}[!] JWT auth error: {e}{Style.RESET_ALL}")
            return {}

    def _authenticate_oauth2(self, client_id: str, client_secret: str, token_endpoint: str) -> Dict[str, Any]:
        """Authenticate using OAuth2 client credentials"""
        import requests

        try:
            response = requests.post(
                token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret
                }
            )

            if response.status_code == 200:
                data = response.json()
                access_token = data.get("access_token")

                return {
                    "headers": {
                        "Authorization": f"Bearer {access_token}"
                    },
                    "access_token": access_token,
                    "refresh_token": data.get("refresh_token"),
                    "expires_in": data.get("expires_in"),
                    "token_type": data.get("token_type", "Bearer")
                }

            print(f"{Fore.RED}[!] OAuth2 auth failed: {response.status_code}{Style.RESET_ALL}")
            return {}

        except Exception as e:
            print(f"{Fore.RED}[!] OAuth2 auth error: {e}{Style.RESET_ALL}")
            return {}

    def _authenticate_session(self, cookies: List[Dict]) -> Dict[str, Any]:
        """Create session from cookies"""
        return {
            "cookies": cookies,
            "headers": {
                "Cookie": self._format_cookies(cookies)
            }
        }

    def _authenticate_api_key(self, api_key: str, header_name: str = "X-API-Key") -> Dict[str, Any]:
        """Authenticate using API key"""
        return {
            "headers": {
                header_name: api_key
            },
            "api_key": api_key
        }

    def get_token(self, user: str) -> Optional[str]:
        """
        Get authentication token for user.

        Args:
            user: User identifier (user_a, user_b)

        Returns:
            Token string or None
        """
        if user not in self.credentials:
            return None

        return self.credentials[user].get("auth_token")

    def refresh_token(self, user: str) -> Optional[str]:
        """
        Refresh expired authentication token.

        Args:
            user: User identifier

        Returns:
            New token or None
        """
        if user not in self.credentials:
            print(f"{Fore.YELLOW}[!] No credentials for {user}{Style.RESET_ALL}")
            return None

        refresh_token = self.credentials[user].get("refresh_token")
        if not refresh_token:
            print(f"{Fore.YELLOW}[!] No refresh token for {user}{Style.RESET_ALL}")
            return None

        # Implement refresh logic (depends on auth type)
        # This is a placeholder - real implementation would call refresh endpoint
        print(f"{Fore.CYAN}[*] Refreshing token for {user}...{Style.RESET_ALL}")

        return None

    def test_auth(self, endpoint: str, token: str, method: str = "GET") -> bool:
        """
        Test if authentication token works.

        Args:
            endpoint: API endpoint to test
            token: Authentication token
            method: HTTP method (default: GET)

        Returns:
            True if auth works, False otherwise
        """
        import requests

        try:
            headers = {"Authorization": f"Bearer {token}"}

            if method == "GET":
                response = requests.get(endpoint, headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(endpoint, headers=headers, timeout=10)
            else:
                response = requests.request(method, endpoint, headers=headers, timeout=10)

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Auth test passed: {endpoint}{Style.RESET_ALL}")
                return True
            elif response.status_code == 401:
                print(f"{Fore.RED}[!] Auth test failed: 401 Unauthorized{Style.RESET_ALL}")
                return False
            else:
                print(f"{Fore.YELLOW}[*] Auth test returned: {response.status_code}{Style.RESET_ALL}")
                return response.status_code < 400

        except Exception as e:
            print(f"{Fore.RED}[!] Auth test error: {e}{Style.RESET_ALL}")
            return False

    def create_session(self, user: str) -> Dict[str, Any]:
        """
        Create authenticated session for user.

        Args:
            user: User identifier

        Returns:
            Session dict with headers and cookies
        """
        if user not in self.credentials:
            print(f"{Fore.YELLOW}[!] No credentials for {user}{Style.RESET_ALL}")
            return {}

        creds = self.credentials[user]

        session = {
            "headers": {},
            "cookies": {}
        }

        # Add auth token if present
        if creds.get("auth_token"):
            session["headers"]["Authorization"] = creds["auth_token"]

        # Add CSRF token if present
        if creds.get("csrf_token"):
            session["headers"]["X-CSRF-Token"] = creds["csrf_token"]

        # Add session cookie if present
        if creds.get("session_cookie"):
            session["cookies"]["session"] = creds["session_cookie"]

        return session

    def extract_tokens_from_browser(self, browser_cookies: List[Dict],
                                   local_storage: Dict[str, str],
                                   session_storage: Dict[str, str],
                                   network_requests: List[Dict]) -> Dict[str, Any]:
        """
        Extract all authentication tokens from browser automation.

        Args:
            browser_cookies: List of cookie dicts from browser
            local_storage: localStorage data
            session_storage: sessionStorage data
            network_requests: Captured network requests

        Returns:
            Structured token dict
        """
        tokens = {
            "cookies": browser_cookies,
            "headers": {},
            "local_storage": local_storage,
            "session_storage": session_storage
        }

        # Extract tokens from localStorage/sessionStorage
        for key, value in local_storage.items():
            if "token" in key.lower() or "jwt" in key.lower():
                try:
                    # Try to decode as JWT
                    decoded = jwt.decode(value, options={"verify_signature": False})
                    tokens["headers"]["Authorization"] = f"Bearer {value}"
                    print(f"{Fore.GREEN}[+] Found JWT in localStorage: {key}{Style.RESET_ALL}")
                except:
                    pass

        # Extract from network requests
        for req in network_requests:
            headers = req.get("request", {}).get("headers", {})

            # Look for Authorization header
            if "authorization" in headers or "Authorization" in headers:
                auth = headers.get("authorization") or headers.get("Authorization")
                tokens["headers"]["Authorization"] = auth
                print(f"{Fore.GREEN}[+] Found Authorization header in network request{Style.RESET_ALL}")

            # Look for CSRF tokens
            if "x-csrf-token" in headers or "X-CSRF-Token" in headers:
                csrf = headers.get("x-csrf-token") or headers.get("X-CSRF-Token")
                tokens["headers"]["X-CSRF-Token"] = csrf
                print(f"{Fore.GREEN}[+] Found CSRF token in network request{Style.RESET_ALL}")

        return tokens

    def _extract_profile(self, tokens: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user profile from tokens"""
        profile = {}

        # Try to extract from JWT
        auth_header = tokens.get("headers", {}).get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                profile["user_id"] = decoded.get("sub") or decoded.get("userId")
                profile["username"] = decoded.get("username")
                profile["role"] = decoded.get("role")
            except:
                pass

        return profile

    def _generate_curl_template(self, tokens: Dict[str, Any]) -> str:
        """Generate curl command template"""
        parts = ["curl"]

        # Add headers
        for key, value in tokens.get("headers", {}).items():
            parts.append(f"-H '{key}: {value}'")

        # Add cookies
        cookies = self._format_cookies(tokens.get("cookies", []))
        if cookies:
            parts.append(f"-H 'Cookie: {cookies}'")

        return " ".join(parts)

    def _format_cookies(self, cookies: List[Dict]) -> str:
        """Format cookies for Cookie header"""
        if not cookies:
            return ""

        cookie_parts = []
        for cookie in cookies:
            if isinstance(cookie, dict):
                name = cookie.get("name")
                value = cookie.get("value")
                if name and value:
                    cookie_parts.append(f"{name}={value}")

        return "; ".join(cookie_parts)

    def _calculate_token_expiry(self, tokens: Dict[str, Any]) -> Optional[str]:
        """Calculate when token expires"""
        auth_header = tokens.get("headers", {}).get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                exp = decoded.get("exp")
                if exp:
                    return datetime.fromtimestamp(exp).isoformat()
            except:
                pass

        # Default: 1 hour from now
        return (datetime.now() + timedelta(hours=1)).isoformat()

    def _calculate_refresh_time(self, tokens: Dict[str, Any]) -> Optional[str]:
        """Calculate when to refresh token (10 min before expiry)"""
        expiry_str = self._calculate_token_expiry(tokens)
        if expiry_str:
            try:
                expiry = datetime.fromisoformat(expiry_str)
                refresh_time = expiry - timedelta(minutes=10)
                return refresh_time.isoformat()
            except:
                pass

        return None

    def generate_summary(self, users: List[str]) -> str:
        """
        Generate authentication summary report.

        Args:
            users: List of user IDs to include

        Returns:
            Markdown formatted summary
        """
        lines = [
            "## Auth Manager Report",
            "",
            f"**Target:** {self.target}",
            f"**Hunt ID:** {self.hunt_id}",
            f"**Status:** SUCCESS",
            "",
            "### Accounts Created",
            "| User | Email | User ID | Role | Auth Type |",
            "|------|-------|---------|------|-----------|"
        ]

        for user_id in users:
            user_file = self.auth_dir / f"{user_id}.json"
            if user_file.exists():
                with open(user_file, 'r') as f:
                    data = json.load(f)

                email = data.get("credentials", {}).get("email", "N/A")
                uid = data.get("profile", {}).get("user_id", "N/A")
                role = data.get("profile", {}).get("role", "user")
                auth_type = "JWT" if "Bearer" in data.get("curl_template", "") else "Session"

                lines.append(f"| {user_id.upper()} | {email} | {uid} | {role} | {auth_type} |")

        lines.extend([
            "",
            "### Files Saved",
        ])

        for user_id in users:
            user_file = self.auth_dir / f"{user_id}.json"
            if user_file.exists():
                lines.append(f"- {user_file}")

        return "\n".join(lines)
