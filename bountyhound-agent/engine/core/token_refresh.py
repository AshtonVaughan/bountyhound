"""
Automatic Token Refresh System

Monitors token expiry times and proactively refreshes tokens before they expire.
Supports JWT, session cookies, OAuth refresh tokens, and API keys.
"""

import json
import time
import base64
import subprocess
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from pathlib import Path
from dataclasses import dataclass, field
from engine.core.config import BountyHoundConfig


FINDINGS_BASE = BountyHoundConfig.FINDINGS_DIR


@dataclass
class TokenInfo:
    """Represents a tracked authentication token."""
    name: str
    value: str
    token_type: str  # jwt, cookie, oauth, api_key
    user: str  # user_a or user_b
    target: str
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None
    refresh_url: Optional[str] = None
    last_refreshed: Optional[datetime] = None
    auto_refresh: bool = True

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now() >= self.expires_at

    @property
    def needs_refresh(self) -> bool:
        """Check if token needs refresh (within 10% of remaining lifetime or < 5 min)."""
        if self.expires_at is None:
            return False
        remaining = (self.expires_at - datetime.now()).total_seconds()
        if remaining <= 0:
            return True
        # Refresh when < 5 minutes remaining or < 10% of original lifetime
        if remaining < 300:
            return True
        if self.last_refreshed:
            total_lifetime = (self.expires_at - self.last_refreshed).total_seconds()
            if total_lifetime > 0 and remaining / total_lifetime < 0.1:
                return True
        return False

    @property
    def time_remaining(self) -> Optional[timedelta]:
        if self.expires_at is None:
            return None
        return self.expires_at - datetime.now()


class TokenRefreshManager:
    """Manages token lifecycle: tracking, monitoring, and refreshing."""

    def __init__(self, target: str):
        self.target = target
        self.tokens: Dict[str, TokenInfo] = {}
        self._creds_dir = FINDINGS_BASE / target / "credentials"
        self._creds_file = self._creds_dir / f"{target}-creds.env"
        self._token_state_file = self._creds_dir / "token-state.json"
        self._refresh_callbacks: List[Callable] = []

    def load_tokens_from_env(self) -> int:
        """Load tokens from the standard .env credentials file."""
        if not self._creds_file.exists():
            return 0

        count = 0
        env_vars = {}
        with open(self._creds_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    env_vars[key.strip()] = value.strip()

        # Parse User A tokens
        for user_prefix in ['USER_A', 'USER_B']:
            user_label = user_prefix.lower().replace('_', '_')

            auth_token = env_vars.get(f'{user_prefix}_AUTH_TOKEN', '')
            if auth_token:
                expiry = self._parse_expiry(
                    env_vars.get(f'{user_prefix}_TOKEN_EXPIRY', ''),
                    auth_token
                )
                self.track_token(TokenInfo(
                    name=f'{user_prefix}_AUTH_TOKEN',
                    value=auth_token,
                    token_type=self._detect_token_type(auth_token),
                    user=user_label,
                    target=self.target,
                    expires_at=expiry,
                    refresh_token=env_vars.get(f'{user_prefix}_REFRESH_TOKEN'),
                ))
                count += 1

            session_cookie = env_vars.get(f'{user_prefix}_SESSION_COOKIE', '')
            if session_cookie:
                self.track_token(TokenInfo(
                    name=f'{user_prefix}_SESSION_COOKIE',
                    value=session_cookie,
                    token_type='cookie',
                    user=user_label,
                    target=self.target,
                ))
                count += 1

            csrf_token = env_vars.get(f'{user_prefix}_CSRF_TOKEN', '')
            if csrf_token:
                self.track_token(TokenInfo(
                    name=f'{user_prefix}_CSRF_TOKEN',
                    value=csrf_token,
                    token_type='csrf',
                    user=user_label,
                    target=self.target,
                ))
                count += 1

        # Load saved state
        self._load_state()
        return count

    def track_token(self, token: TokenInfo) -> None:
        """Add or update a token in the tracking system."""
        token.last_refreshed = datetime.now()
        self.tokens[token.name] = token

    def _detect_token_type(self, value: str) -> str:
        """Detect token type from its value."""
        clean = value.replace('Bearer ', '').strip()
        parts = clean.split('.')
        if len(parts) == 3:
            return 'jwt'
        if clean.startswith('sk-') or clean.startswith('pk-'):
            return 'api_key'
        if 'session' in value.lower() or 's%3A' in value:
            return 'cookie'
        return 'bearer'

    def _parse_expiry(self, expiry_str: str, token_value: str = '') -> Optional[datetime]:
        """Parse expiry from env var or JWT payload."""
        # Try parsing from env var
        if expiry_str:
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
                        '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    return datetime.strptime(expiry_str, fmt)
                except ValueError:
                    continue

        # Try extracting from JWT
        if token_value:
            clean = token_value.replace('Bearer ', '').strip()
            parts = clean.split('.')
            if len(parts) == 3:
                try:
                    payload = parts[1]
                    # Add padding
                    payload += '=' * (4 - len(payload) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload))
                    exp = decoded.get('exp')
                    if exp:
                        return datetime.fromtimestamp(exp)
                except Exception:
                    pass

        return None

    def check_all(self) -> Dict[str, Dict]:
        """Check status of all tracked tokens."""
        report = {}
        for name, token in self.tokens.items():
            remaining = token.time_remaining
            report[name] = {
                'user': token.user,
                'type': token.token_type,
                'is_expired': token.is_expired,
                'needs_refresh': token.needs_refresh,
                'time_remaining': str(remaining) if remaining else 'unknown',
                'has_refresh_token': bool(token.refresh_token),
                'auto_refresh': token.auto_refresh,
            }
        return report

    def get_expiring_soon(self, minutes: int = 10) -> List[TokenInfo]:
        """Get tokens expiring within N minutes."""
        threshold = datetime.now() + timedelta(minutes=minutes)
        expiring = []
        for token in self.tokens.values():
            if token.expires_at and token.expires_at <= threshold and not token.is_expired:
                expiring.append(token)
        return expiring

    def refresh_token_via_api(self, token_name: str) -> Optional[str]:
        """Refresh a token using its refresh_token via API call."""
        token = self.tokens.get(token_name)
        if not token or not token.refresh_token:
            return None

        refresh_url = token.refresh_url or f"https://{self.target}/api/auth/refresh"

        try:
            result = subprocess.run([
                'curl', '-s', '-m', '15',
                '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps({'refresh_token': token.refresh_token}),
                refresh_url
            ], capture_output=True, text=True, timeout=20)

            if result.stdout:
                data = json.loads(result.stdout)
                new_token = (
                    data.get('access_token') or
                    data.get('token') or
                    data.get('data', {}).get('access_token')
                )
                if new_token:
                    token.value = new_token
                    token.expires_at = self._parse_expiry('', new_token)
                    token.last_refreshed = datetime.now()

                    new_refresh = data.get('refresh_token')
                    if new_refresh:
                        token.refresh_token = new_refresh

                    self._update_env_file(token)
                    self._save_state()
                    return new_token
        except Exception:
            pass
        return None

    def refresh_token_via_relogin(self, token_name: str) -> Optional[str]:
        """Refresh by re-authenticating with stored credentials."""
        token = self.tokens.get(token_name)
        if not token:
            return None

        # Read credentials from env file
        env_vars = {}
        if self._creds_file.exists():
            with open(self._creds_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, _, value = line.partition('=')
                        env_vars[key.strip()] = value.strip()

        user_prefix = token.user.upper().replace('_', '_')
        email = env_vars.get(f'{user_prefix}_EMAIL')
        password = env_vars.get(f'{user_prefix}_PASSWORD')

        if not email or not password:
            return None

        # Try common login endpoints
        login_urls = [
            f"https://{self.target}/api/auth/login",
            f"https://{self.target}/api/v1/auth/login",
            f"https://{self.target}/api/login",
            f"https://{self.target}/auth/login",
        ]

        for login_url in login_urls:
            try:
                result = subprocess.run([
                    'curl', '-s', '-m', '15',
                    '-X', 'POST',
                    '-H', 'Content-Type: application/json',
                    '-d', json.dumps({'email': email, 'password': password}),
                    login_url
                ], capture_output=True, text=True, timeout=20)

                if result.stdout:
                    data = json.loads(result.stdout)
                    new_token = (
                        data.get('access_token') or
                        data.get('token') or
                        data.get('data', {}).get('token') or
                        data.get('data', {}).get('access_token')
                    )
                    if new_token:
                        token.value = new_token
                        token.expires_at = self._parse_expiry('', new_token)
                        token.last_refreshed = datetime.now()

                        new_refresh = data.get('refresh_token')
                        if new_refresh:
                            token.refresh_token = new_refresh

                        self._update_env_file(token)
                        self._save_state()
                        return new_token
            except Exception:
                continue
        return None

    def auto_refresh_all(self) -> Dict[str, str]:
        """Attempt to refresh all tokens that need it."""
        results = {}
        for name, token in self.tokens.items():
            if not token.needs_refresh or not token.auto_refresh:
                continue

            # Try refresh token first, then re-login
            new_value = self.refresh_token_via_api(name)
            if new_value:
                results[name] = 'refreshed_via_api'
                continue

            new_value = self.refresh_token_via_relogin(name)
            if new_value:
                results[name] = 'refreshed_via_relogin'
                continue

            results[name] = 'refresh_failed'

        return results

    def _update_env_file(self, token: TokenInfo) -> None:
        """Update the .env file with new token value and expiry in a single read-modify-write."""
        if not self._creds_file.exists():
            return

        with open(self._creds_file) as f:
            lines = f.readlines()

        expiry_key = token.name.replace('AUTH_TOKEN', 'TOKEN_EXPIRY').replace('SESSION_COOKIE', 'COOKIE_EXPIRY')
        modified = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(f'{token.name}='):
                lines[i] = f'{token.name}={token.value}\n'
                modified = True
            elif token.expires_at and stripped.startswith(f'{expiry_key}='):
                lines[i] = f'{expiry_key}={token.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")}\n'
                modified = True

        if modified:
            with open(self._creds_file, 'w') as f:
                f.writelines(lines)

    def _save_state(self) -> None:
        """Save token tracking state to JSON."""
        os.makedirs(self._creds_dir, exist_ok=True)
        state = {}
        for name, token in self.tokens.items():
            state[name] = {
                'name': token.name,
                'token_type': token.token_type,
                'user': token.user,
                'target': token.target,
                'expires_at': token.expires_at.isoformat() if token.expires_at else None,
                'has_refresh_token': bool(token.refresh_token),
                'last_refreshed': token.last_refreshed.isoformat() if token.last_refreshed else None,
                'auto_refresh': token.auto_refresh,
            }
        with open(self._token_state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def _load_state(self) -> None:
        """Load token tracking state from JSON."""
        if not self._token_state_file.exists():
            return
        try:
            with open(self._token_state_file) as f:
                state = json.load(f)
            for name, data in state.items():
                if name in self.tokens:
                    if data.get('last_refreshed'):
                        self.tokens[name].last_refreshed = datetime.fromisoformat(data['last_refreshed'])
                    self.tokens[name].auto_refresh = data.get('auto_refresh', True)
        except Exception:
            pass

    def status_report(self) -> str:
        """Generate human-readable status report."""
        lines = [f"Token Status for {self.target}:", ""]
        for name, token in self.tokens.items():
            remaining = token.time_remaining
            status = "EXPIRED" if token.is_expired else (
                "REFRESH NEEDED" if token.needs_refresh else "OK"
            )
            remaining_str = str(remaining).split('.')[0] if remaining else "unknown"
            lines.append(f"  [{status}] {name}")
            lines.append(f"    Type: {token.token_type} | User: {token.user}")
            lines.append(f"    Remaining: {remaining_str}")
            if token.refresh_token:
                lines.append(f"    Refresh token: available")
            lines.append("")
        return '\n'.join(lines)
