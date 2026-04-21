"""
Unified Cache Manager for BountyHound Optimization

Coordinates persistent caching across:
- Recon data (subdomains, IPs, ports, services)
- Stack fingerprints (frameworks, CMS, languages, auth methods)
- Credentials (working logins, API keys, tokens)
- Findings (historical record, never expires)
- Tested methods (which agents tested what and when)
- Real-time streaming (findings_live.json updated every 10s)

This enables:
- 2nd hunt on same target: ~7 min (skip recon, use cached data)
- 3rd+ hunts: ~5 min (most methods cached)
- No duplicate findings (MD5-based deduplication)
- Smart cache invalidation (TTL rules per cache type)

Usage:
    cache_mgr = CacheManager('example.com')

    # Check if cache is fresh
    if cache_mgr.is_recon_fresh():
        recon_data = cache_mgr.load_recon()
    else:
        cache_mgr.save_recon(new_recon_data)

    # Save findings with deduplication
    cache_mgr.add_finding({
        'title': 'SQL Injection in /api/login',
        'severity': 'CRITICAL',
        'endpoint': '/api/login'
    }, source_agent='sqlmap_injection')

    # Stream results in real-time
    cache_mgr.stream_findings()  # Updates findings_live.json

    # Track method execution
    cache_mgr.record_method_run('ffuf_fuzzer', endpoints_tested=12, findings=2)
"""

import json
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
import threading
from enum import Enum

from engine.core.config import BountyHoundConfig
from engine.core.recon_cache import ReconCache
from engine.core.cred_cache import CredentialCache


class CacheTTL(Enum):
    """Cache Time-To-Live rules (in days)."""
    RECON = 30              # IPs, subdomains rarely change
    STACK = 30              # Tech stack rarely changes
    CREDENTIALS = 7         # Tokens/sessions expire
    METHOD_RESULTS = 7      # Retest methods weekly
    FINDINGS = float('inf') # Historical record never expires


@dataclass
class CachedFinding:
    """A cached finding with metadata."""
    id: str                 # Unique ID (MD5 hash of endpoint + title)
    title: str
    severity: str
    endpoint: str
    description: str = ""
    remediation: str = ""
    source_agent: str = ""
    timestamp: str = ""
    status: str = "open"    # open, accepted, rejected, duplicate
    finding_hash: str = ""  # MD5(endpoint + title)


@dataclass
class MethodExecution:
    """Tracking for method/agent execution."""
    method: str
    last_run: str           # ISO timestamp
    endpoints_tested: int = 0
    findings: int = 0
    duration_seconds: float = 0.0
    success: bool = True
    error: str = ""


class CacheManager:
    """Unified cache management for BountyHound."""

    def __init__(self, target: str):
        """Initialize cache manager for target."""
        self.target = target
        self.recon_cache = ReconCache(target)
        self.cred_cache = CredentialCache()

        # Findings cache directory
        self.cache_dir = Path(BountyHoundConfig.FINDINGS_DIR) / target / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Cache files
        self.cache_file = self.cache_dir / "cache.json"
        self.findings_live_file = self.cache_dir / "findings_live.json"
        self.method_hashes_file = self.cache_dir / "method_hashes.json"

        # In-memory state
        self._cache: Dict[str, Any] = self._load_cache()
        self._finding_hashes: Set[str] = self._load_finding_hashes()
        self._lock = threading.RLock()  # For thread-safe operations
        self._last_stream_time = 0.0

    # ========================================================================
    # CACHE LOADING/SAVING
    # ========================================================================

    def _load_cache(self) -> Dict[str, Any]:
        """Load cache from disk or initialize if missing."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    return json.load(f)
            except Exception:
                pass

        # Initialize new cache
        return {
            "target": self.target,
            "created_at": datetime.now().isoformat(),
            "last_hunt": None,
            "hunt_count": 0,
            "recon": {
                "subdomains": [],
                "ips": [],
                "ports": [],
                "urls": [],
                "services": {},
                "last_updated": None,
            },
            "stack": {
                "framework": None,
                "cms": None,
                "language": None,
                "auth_type": None,
                "api_style": None,
                "dependencies": [],
                "last_updated": None,
            },
            "findings": {
                "previous": [],
            },
            "tested_methods": {},
        }

    def _load_finding_hashes(self) -> Set[str]:
        """Load hash set of all previously found findings."""
        if self.method_hashes_file.exists():
            try:
                with open(self.method_hashes_file) as f:
                    data = json.load(f)
                    return set(data.get("hashes", []))
            except Exception:
                pass
        return set()

    def _save_cache(self) -> None:
        """Persist cache to disk."""
        with self._lock:
            try:
                with open(self.cache_file, 'w') as f:
                    json.dump(self._cache, f, indent=2)
            except Exception as e:
                print(f"Error saving cache: {e}")

    def _save_finding_hashes(self) -> None:
        """Persist finding hashes to disk."""
        with self._lock:
            try:
                with open(self.method_hashes_file, 'w') as f:
                    json.dump({"hashes": list(self._finding_hashes)}, f, indent=2)
            except Exception as e:
                print(f"Error saving finding hashes: {e}")

    # ========================================================================
    # DEDUPLICATION
    # ========================================================================

    @staticmethod
    def _hash_finding(endpoint: str, title: str) -> str:
        """Generate MD5 hash of endpoint + title for deduplication."""
        key = f"{endpoint}_{title}".lower()
        return hashlib.md5(key.encode()).hexdigest()

    def is_duplicate_finding(self, endpoint: str, title: str) -> bool:
        """Check if finding was already discovered."""
        finding_hash = self._hash_finding(endpoint, title)
        return finding_hash in self._finding_hashes

    # ========================================================================
    # RECON CACHE MANAGEMENT
    # ========================================================================

    def is_recon_fresh(self) -> bool:
        """Check if recon cache is still valid."""
        last_updated = self._cache["recon"].get("last_updated")
        if not last_updated:
            return False

        last_time = datetime.fromisoformat(last_updated)
        age = datetime.now() - last_time
        ttl = timedelta(days=CacheTTL.RECON.value)

        return age < ttl

    def load_recon(self) -> Optional[Dict[str, Any]]:
        """Load recon data from cache."""
        if self.is_recon_fresh():
            return self._cache.get("recon")
        return None

    def save_recon(self, recon_data: Dict[str, Any]) -> None:
        """Save recon data to cache."""
        with self._lock:
            self._cache["recon"] = {
                **recon_data,
                "last_updated": datetime.now().isoformat(),
            }
            self._save_cache()

    # ========================================================================
    # STACK FINGERPRINT MANAGEMENT
    # ========================================================================

    def is_stack_fresh(self) -> bool:
        """Check if stack fingerprint cache is still valid."""
        last_updated = self._cache["stack"].get("last_updated")
        if not last_updated:
            return False

        last_time = datetime.fromisoformat(last_updated)
        age = datetime.now() - last_time
        ttl = timedelta(days=CacheTTL.STACK.value)

        return age < ttl

    def load_stack(self) -> Optional[Dict[str, Any]]:
        """Load stack fingerprint from cache."""
        if self.is_stack_fresh():
            return self._cache.get("stack")
        return None

    def save_stack(self, stack_data: Dict[str, Any]) -> None:
        """Save stack fingerprint to cache."""
        with self._lock:
            self._cache["stack"] = {
                **stack_data,
                "last_updated": datetime.now().isoformat(),
            }
            self._save_cache()

    # ========================================================================
    # FINDINGS MANAGEMENT
    # ========================================================================

    def add_finding(self, finding: Dict[str, Any], source_agent: str = "") -> bool:
        """
        Add finding to cache with deduplication.

        Returns:
            True if finding was added, False if duplicate.
        """
        endpoint = finding.get("endpoint", "")
        title = finding.get("title", "")

        # Check for duplicates
        if self.is_duplicate_finding(endpoint, title):
            return False

        # Add to cache
        with self._lock:
            finding_entry = {
                **finding,
                "source_agent": source_agent,
                "timestamp": datetime.now().isoformat(),
                "status": "open",
            }
            self._cache["findings"]["previous"].append(finding_entry)

            # Record hash for deduplication
            finding_hash = self._hash_finding(endpoint, title)
            self._finding_hashes.add(finding_hash)

            self._save_cache()
            self._save_finding_hashes()

        return True

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all cached findings."""
        return self._cache.get("findings", {}).get("previous", [])

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get findings filtered by severity."""
        findings = self.get_findings()
        return [f for f in findings if f.get("severity") == severity.upper()]

    # ========================================================================
    # TESTED METHODS TRACKING
    # ========================================================================

    def should_retest_method(self, method: str) -> bool:
        """Check if method should be re-tested (cache is stale)."""
        method_data = self._cache.get("tested_methods", {}).get(method)
        if not method_data:
            return True  # Never tested

        last_run = method_data.get("last_run")
        if not last_run:
            return True

        last_time = datetime.fromisoformat(last_run)
        age = datetime.now() - last_time
        ttl = timedelta(days=CacheTTL.METHOD_RESULTS.value)

        return age >= ttl

    def record_method_run(
        self,
        method: str,
        endpoints_tested: int = 0,
        findings: int = 0,
        duration_seconds: float = 0.0,
        success: bool = True,
        error: str = "",
    ) -> None:
        """Record method/agent execution."""
        with self._lock:
            if "tested_methods" not in self._cache:
                self._cache["tested_methods"] = {}

            self._cache["tested_methods"][method] = {
                "last_run": datetime.now().isoformat(),
                "endpoints_tested": endpoints_tested,
                "findings": findings,
                "duration_seconds": duration_seconds,
                "success": success,
                "error": error,
            }
            self._save_cache()

    def get_method_stats(self, method: str) -> Optional[Dict[str, Any]]:
        """Get execution stats for a method."""
        return self._cache.get("tested_methods", {}).get(method)

    def get_all_method_stats(self) -> Dict[str, Any]:
        """Get stats for all tested methods."""
        return self._cache.get("tested_methods", {})

    # ========================================================================
    # REAL-TIME STREAMING
    # ========================================================================

    def stream_findings(self) -> None:
        """Update findings_live.json for real-time visibility."""
        # Throttle updates to max once per 10 seconds
        now = time.time()
        if now - self._last_stream_time < 10.0:
            return

        with self._lock:
            findings = self.get_findings()

            # Calculate severity breakdown
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }

            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1

            # Build live findings report
            live_report = {
                "timestamp": datetime.now().isoformat(),
                "target": self.target,
                "findings_count": len(findings),
                "by_severity": severity_counts,
                "latest_findings": findings[-10:] if findings else [],  # Last 10
            }

            try:
                with open(self.findings_live_file, 'w') as f:
                    json.dump(live_report, f, indent=2)
                self._last_stream_time = now
            except Exception as e:
                print(f"Error streaming findings: {e}")

    # ========================================================================
    # HUNT METADATA
    # ========================================================================

    def record_hunt_start(self) -> None:
        """Record hunt start time."""
        with self._lock:
            self._cache["last_hunt"] = datetime.now().isoformat()
            self._cache["hunt_count"] = self._cache.get("hunt_count", 0) + 1
            self._save_cache()

    def get_hunt_count(self) -> int:
        """Get number of hunts performed on this target."""
        return self._cache.get("hunt_count", 0)

    def get_last_hunt_time(self) -> Optional[str]:
        """Get last hunt timestamp."""
        return self._cache.get("last_hunt")

    # ========================================================================
    # CACHE STATS
    # ========================================================================

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        return {
            "target": self.target,
            "hunt_count": self.get_hunt_count(),
            "last_hunt": self.get_last_hunt_time(),
            "recon": {
                "subdomains": len(self._cache["recon"].get("subdomains", [])),
                "ips": len(self._cache["recon"].get("ips", [])),
                "ports": len(self._cache["recon"].get("ports", [])),
                "urls": len(self._cache["recon"].get("urls", [])),
                "fresh": self.is_recon_fresh(),
            },
            "stack": {
                "framework": self._cache["stack"].get("framework"),
                "cms": self._cache["stack"].get("cms"),
                "fresh": self.is_stack_fresh(),
            },
            "findings": {
                "total": len(self.get_findings()),
                "critical": len(self.get_findings_by_severity("CRITICAL")),
                "high": len(self.get_findings_by_severity("HIGH")),
                "medium": len(self.get_findings_by_severity("MEDIUM")),
                "low": len(self.get_findings_by_severity("LOW")),
            },
            "tested_methods": len(self._cache.get("tested_methods", {})),
            "method_stats": self.get_all_method_stats(),
        }

    # ========================================================================
    # CLEANUP & MAINTENANCE
    # ========================================================================

    def cleanup_old_findings(self, max_kept: int = 1000) -> int:
        """Remove oldest findings if cache exceeds limit."""
        findings = self._cache["findings"]["previous"]
        if len(findings) <= max_kept:
            return 0

        with self._lock:
            # Keep newest max_kept findings
            removed_count = len(findings) - max_kept
            self._cache["findings"]["previous"] = findings[-max_kept:]
            self._save_cache()

        return removed_count

    def invalidate_stale_cache(self) -> Dict[str, bool]:
        """Invalidate stale cache sections."""
        result = {
            "recon_invalidated": not self.is_recon_fresh(),
            "stack_invalidated": not self.is_stack_fresh(),
        }

        # If stale, clear the data
        if result["recon_invalidated"]:
            with self._lock:
                self._cache["recon"]["last_updated"] = None
                self._save_cache()

        if result["stack_invalidated"]:
            with self._lock:
                self._cache["stack"]["last_updated"] = None
                self._save_cache()

        return result

    def clear_cache(self) -> None:
        """Clear all cache (used for fresh start)."""
        with self._lock:
            self._cache = self._load_cache()  # Reinitialize
            self._finding_hashes.clear()
            self._save_cache()
            self._save_finding_hashes()

    # ========================================================================
    # CONTEXT FOR AGENTS
    # ========================================================================

    def get_hunt_context(self) -> Dict[str, Any]:
        """Get context info for agents about previous hunts."""
        stats = self.get_cache_stats()

        return {
            "hunt_number": stats["hunt_count"],
            "is_first_hunt": stats["hunt_count"] == 1,
            "is_repeat_hunt": stats["hunt_count"] > 1,
            "previous_findings_count": stats["findings"]["total"],
            "recon_cached": stats["recon"]["fresh"],
            "stack_cached": stats["stack"]["fresh"],
            "methods_to_skip": [
                m for m, should_skip in [
                    (method, not self.should_retest_method(method))
                    for method in self._cache.get("tested_methods", {}).keys()
                ] if should_skip
            ],
        }
