"""
Credential Cache System

Provides persistent credential storage that survives session restarts.
Credentials are stored with TTL and automatically loaded when hunts resume.
Uses file-based storage with base64 encoding (not true encryption,
but prevents casual exposure in logs/screenshots).
"""

import json
import os
import base64
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from engine.core.config import BountyHoundConfig


CACHE_DIR = BountyHoundConfig.CRED_CACHE_DIR
FINDINGS_BASE = BountyHoundConfig.FINDINGS_DIR


@dataclass
class CachedCredential:
    """A cached credential entry."""
    target: str
    user: str  # user_a, user_b
    key: str  # e.g. AUTH_TOKEN, SESSION_COOKIE
    value: str
    token_type: str  # jwt, cookie, api_key, password
    created_at: str
    expires_at: Optional[str] = None
    last_used: Optional[str] = None
    refresh_token: Optional[str] = None
    metadata: Optional[Dict] = None


class CredentialCache:
    """File-based credential cache with TTL, auto-reload, and in-memory batching."""

    def __init__(self):
        self._cache_dir = CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._index_file = self._cache_dir / "index.json"
        self._index: Dict[str, Dict] = {}
        self._target_caches: Dict[str, Dict] = {}  # In-memory cache per target
        self._dirty_targets: set = set()  # Targets with unsaved changes
        self._load_index()

    def _load_index(self) -> None:
        """Load the cache index from disk."""
        if self._index_file.exists():
            try:
                with open(self._index_file) as f:
                    self._index = json.load(f)
            except Exception:
                self._index = {}

    def _save_index(self) -> None:
        """Save the cache index to disk."""
        with open(self._index_file, 'w') as f:
            json.dump(self._index, f, indent=2)

    def _target_file(self, target: str) -> Path:
        """Get cache file path for a target."""
        safe_name = target.replace('/', '_').replace(':', '_').replace('.', '_')
        return self._cache_dir / f"{safe_name}.json"

    def _encode(self, value: str) -> str:
        """Encode a value for storage (base64 to prevent log exposure)."""
        return base64.b64encode(value.encode()).decode()

    def _decode(self, encoded: str) -> str:
        """Decode a stored value."""
        try:
            return base64.b64decode(encoded.encode()).decode()
        except Exception:
            return encoded

    def _load_target_cache(self, target: str) -> Dict:
        """Load target cache from memory or disk (lazy load, cached)."""
        if target in self._target_caches:
            return self._target_caches[target]

        cache_file = self._target_file(target)
        target_cache = {}
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    target_cache = json.load(f)
            except Exception:
                target_cache = {}

        self._target_caches[target] = target_cache
        return target_cache

    def flush(self) -> int:
        """Write all dirty target caches to disk in a single pass. Returns count flushed."""
        flushed = 0
        for target in list(self._dirty_targets):
            cache_file = self._target_file(target)
            target_cache = self._target_caches.get(target, {})
            with open(cache_file, 'w') as f:
                json.dump(target_cache, f, indent=2)
            flushed += 1
        self._dirty_targets.clear()
        if flushed:
            self._save_index()
        return flushed

    def store(self, target: str, user: str, key: str, value: str,
              token_type: str = 'bearer', expires_at: Optional[str] = None,
              refresh_token: Optional[str] = None,
              metadata: Optional[Dict] = None) -> None:
        """Store a credential in the cache (batched - call flush() to persist)."""
        target_cache = self._load_target_cache(target)

        # Create credential entry
        cred = CachedCredential(
            target=target,
            user=user,
            key=key,
            value=self._encode(value),
            token_type=token_type,
            created_at=datetime.now().isoformat(),
            expires_at=expires_at,
            refresh_token=self._encode(refresh_token) if refresh_token else None,
            metadata=metadata
        )

        # Store by user+key combo
        cache_key = f"{user}_{key}"
        target_cache[cache_key] = asdict(cred)
        self._dirty_targets.add(target)

        # Update index
        if target not in self._index:
            self._index[target] = {'keys': [], 'last_updated': ''}
        if cache_key not in self._index[target]['keys']:
            self._index[target]['keys'].append(cache_key)
        self._index[target]['last_updated'] = datetime.now().isoformat()

        # Auto-flush for backwards compatibility
        self.flush()

    def retrieve(self, target: str, user: str, key: str) -> Optional[str]:
        """Retrieve a credential from cache (uses in-memory cache after first load)."""
        target_cache = self._load_target_cache(target)
        if not target_cache:
            return None

        try:
            cache_key = f"{user}_{key}"
            entry = target_cache.get(cache_key)
            if not entry:
                return None

            # Check expiry
            if entry.get('expires_at'):
                try:
                    expiry = datetime.fromisoformat(entry['expires_at'])
                    if datetime.now() >= expiry:
                        return None  # Expired
                except Exception:
                    pass

            # Update last_used in memory (lazy write via flush)
            entry['last_used'] = datetime.now().isoformat()
            self._dirty_targets.add(target)

            return self._decode(entry['value'])
        except Exception:
            return None

    def retrieve_all(self, target: str) -> Dict[str, str]:
        """Retrieve all non-expired credentials for a target."""
        cache_file = self._target_file(target)
        if not cache_file.exists():
            return {}

        try:
            with open(cache_file) as f:
                target_cache = json.load(f)

            result = {}
            for cache_key, entry in target_cache.items():
                # Skip expired
                if entry.get('expires_at'):
                    try:
                        expiry = datetime.fromisoformat(entry['expires_at'])
                        if datetime.now() >= expiry:
                            continue
                    except Exception:
                        pass
                result[cache_key] = self._decode(entry['value'])
            return result
        except Exception:
            return {}

    def sync_from_env(self, target: str) -> int:
        """Import credentials from .env file into cache."""
        env_file = FINDINGS_BASE / target / "credentials" / f"{target}-creds.env"
        if not env_file.exists():
            return 0

        count = 0
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()

                if not value:
                    continue

                # Determine user and credential key
                user = None
                cred_key = key
                if key.startswith('USER_A_'):
                    user = 'user_a'
                    cred_key = key[7:]  # Remove USER_A_ prefix
                elif key.startswith('USER_B_'):
                    user = 'user_b'
                    cred_key = key[7:]  # Remove USER_B_ prefix
                else:
                    continue

                # Determine token type
                token_type = 'bearer'
                if 'PASSWORD' in key:
                    token_type = 'password'
                elif 'COOKIE' in key:
                    token_type = 'cookie'
                elif 'CSRF' in key:
                    token_type = 'csrf'
                elif 'REFRESH' in key:
                    token_type = 'refresh'
                elif 'JWT' in key or 'TOKEN' in key:
                    token_type = 'jwt'

                # Get expiry if available
                expiry_key = key.replace('AUTH_TOKEN', 'TOKEN_EXPIRY')
                expires_at = None
                # Re-read env for expiry (simplified)

                self.store(target, user, cred_key, value, token_type, expires_at)
                count += 1

        return count

    def sync_to_env(self, target: str) -> bool:
        """Export cached credentials to .env file."""
        creds = self.retrieve_all(target)
        if not creds:
            return False

        env_dir = FINDINGS_BASE / target / "credentials"
        env_dir.mkdir(parents=True, exist_ok=True)
        env_file = env_dir / f"{target}-creds.env"

        lines = [f"# Auto-generated from credential cache at {datetime.now().isoformat()}\n"]

        for cache_key, value in sorted(creds.items()):
            # Convert cache_key back to env var name
            parts = cache_key.split('_', 1)
            if len(parts) == 2:
                user_prefix = parts[0].upper()
                cred_suffix = parts[1].upper()
                env_key = f"{user_prefix}_{cred_suffix}"
            else:
                env_key = cache_key.upper()
            lines.append(f"{env_key}={value}\n")

        with open(env_file, 'w') as f:
            f.writelines(lines)
        return True

    def list_targets(self) -> List[Dict]:
        """List all targets with cached credentials."""
        result = []
        for target, info in self._index.items():
            result.append({
                'target': target,
                'credential_count': len(info.get('keys', [])),
                'last_updated': info.get('last_updated', 'unknown')
            })
        return result

    def clear_target(self, target: str) -> bool:
        """Clear all cached credentials for a target."""
        cache_file = self._target_file(target)
        if cache_file.exists():
            cache_file.unlink()
        if target in self._index:
            del self._index[target]
            self._save_index()
            return True
        return False

    def clear_expired(self) -> int:
        """Remove all expired credentials from cache."""
        removed = 0
        for target in list(self._index.keys()):
            cache_file = self._target_file(target)
            if not cache_file.exists():
                continue
            try:
                with open(cache_file) as f:
                    target_cache = json.load(f)
                original = len(target_cache)
                target_cache = {
                    k: v for k, v in target_cache.items()
                    if not v.get('expires_at') or
                    datetime.fromisoformat(v['expires_at']) > datetime.now()
                }
                removed += original - len(target_cache)
                with open(cache_file, 'w') as f:
                    json.dump(target_cache, f, indent=2)
            except Exception:
                continue
        return removed

    def status_report(self) -> str:
        """Generate cache status report."""
        targets = self.list_targets()
        lines = [f"Credential Cache Status:", f"  Targets: {len(targets)}", ""]
        for t in targets:
            lines.append(f"  {t['target']}: {t['credential_count']} credentials (updated: {t['last_updated']})")
        return '\n'.join(lines)
