"""
Background Target Monitor

Extends the existing ContinuousMonitor to provide background change detection
on previously-tested targets. Watches for new subdomains, certificate changes,
technology stack changes, DNS record changes, and HTTP behavior changes. Alerts
when re-testing is recommended.

Persistence is stored in C:/Users/vaugh/BountyHound/database/target-monitor/

All HTTP calls use subprocess + curl (no requests library).
"""

import json
import os
import subprocess
import ssl
import socket
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
from enum import Enum
from engine.core.config import BountyHoundConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = BountyHoundConfig.BASE_DIR
MONITOR_DIR = BASE_DIR / "database" / "target-monitor"
WATCHLIST_FILE = MONITOR_DIR / "watchlist.json"
CHANGES_DIR = MONITOR_DIR / "changes"
ALERTS_FILE = MONITOR_DIR / "alerts.json"
BASELINES_DIR = MONITOR_DIR / "baselines"

# How many seconds curl is allowed before we give up
CURL_TIMEOUT = 30

# Default interval for checking targets (hours)
DEFAULT_INTERVAL_HOURS = 24


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Represents a change-detection alert for a watched target."""
    target: str
    alert_type: str          # e.g. "new_subdomains", "cert_change", "tech_change"
    description: str
    severity: str            # one of AlertSeverity values
    detected_at: str         # ISO-8601 timestamp
    acknowledged: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        return cls(**data)


@dataclass
class WatchEntry:
    """A single target on the watch list."""
    target: str
    interval_hours: float
    added_at: str            # ISO-8601
    last_checked: Optional[str] = None  # ISO-8601 or None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WatchEntry":
        return cls(**data)


# ---------------------------------------------------------------------------
# Helper: curl-based HTTP
# ---------------------------------------------------------------------------

def _curl_get(url: str, *, headers_only: bool = False, timeout: int = CURL_TIMEOUT) -> Dict[str, Any]:
    """
    Perform an HTTP GET via subprocess + curl.

    Returns a dict with keys:
        status_code (int | None), headers (str), body (str), error (str | None)
    """
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-L"]
    if headers_only:
        cmd += ["-I"]
    else:
        cmd += ["-i"]
    cmd.append(url)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,  # grace period beyond curl's own timeout
        )
        raw = result.stdout
        error = result.stderr.strip() if result.returncode != 0 else None

        # Split headers from body (for -i mode)
        status_code = None
        headers_text = ""
        body_text = raw

        if not headers_only:
            # curl -i puts headers then blank line then body
            parts = raw.split("\r\n\r\n", 1)
            if len(parts) == 2:
                headers_text, body_text = parts
            else:
                # Try Unix-style line endings
                parts = raw.split("\n\n", 1)
                if len(parts) == 2:
                    headers_text, body_text = parts
        else:
            headers_text = raw
            body_text = ""

        # Extract status code from first header line
        for line in headers_text.splitlines():
            if line.upper().startswith("HTTP/"):
                try:
                    status_code = int(line.split()[1])
                except (IndexError, ValueError):
                    pass

        return {
            "status_code": status_code,
            "headers": headers_text,
            "body": body_text,
            "error": error,
        }
    except subprocess.TimeoutExpired:
        return {"status_code": None, "headers": "", "body": "", "error": "curl timeout"}
    except FileNotFoundError:
        return {"status_code": None, "headers": "", "body": "", "error": "curl not found"}
    except Exception as exc:
        return {"status_code": None, "headers": "", "body": "", "error": str(exc)}


def _curl_json(url: str, timeout: int = CURL_TIMEOUT) -> Any:
    """GET a URL and parse JSON body.  Returns parsed object or None on error."""
    resp = _curl_get(url, timeout=timeout)
    if resp["error"] or not resp["body"]:
        return None
    try:
        return json.loads(resp["body"])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Helper: DNS resolution via socket
# ---------------------------------------------------------------------------

def _resolve_dns(domain: str) -> Dict[str, List[str]]:
    """
    Resolve A and AAAA records for *domain* using the stdlib socket module.
    Returns {"A": [...], "AAAA": [...]}.
    """
    records: Dict[str, List[str]] = {"A": [], "AAAA": []}
    for family, key in [(socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")]:
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            records[key] = sorted(set(info[4][0] for info in infos))
        except socket.gaierror:
            pass
    return records


# ---------------------------------------------------------------------------
# Helper: TLS certificate info via ssl
# ---------------------------------------------------------------------------

def _get_cert_info(domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """
    Connect to *domain*:*port* with TLS and return a summary dict of the
    server certificate, or None on failure.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                # Build a stable fingerprint from the DER form
                der = ssock.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(der).hexdigest() if der else ""
                return {
                    "subject": str(cert.get("subject", "")),
                    "issuer": str(cert.get("issuer", "")),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "serialNumber": cert.get("serialNumber", ""),
                    "sha256_fingerprint": fingerprint,
                    "subjectAltName": [entry[1] for entry in cert.get("subjectAltName", [])],
                }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _ensure_dirs() -> None:
    """Create monitor directories if they do not exist."""
    for d in [MONITOR_DIR, CHANGES_DIR, BASELINES_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default: Any = None) -> Any:
    """Load JSON from *path*, returning *default* if the file is missing or corrupt."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def _write_json(path: Path, data: Any) -> None:
    """Atomically-ish write *data* as JSON to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _sanitize_filename(name: str) -> str:
    """Turn a domain/target into a safe filename component."""
    return name.replace("://", "_").replace("/", "_").replace(":", "_").replace("*", "_")


# ---------------------------------------------------------------------------
# TargetMonitor
# ---------------------------------------------------------------------------

class TargetMonitor:
    """
    Background change-detection monitor for previously-tested targets.

    Watches for:
      - New subdomains (via crt.sh Certificate Transparency logs)
      - TLS certificate renewals / changes
      - Technology stack changes (response headers)
      - DNS record changes (A / AAAA)
      - HTTP behaviour changes (status codes, redirects)

    Usage::

        mon = TargetMonitor()
        mon.add_watch("example.com", interval_hours=12)
        results = mon.check_all()
        alerts  = mon.get_alerts()
    """

    def __init__(self) -> None:
        _ensure_dirs()
        self._watchlist: Dict[str, WatchEntry] = self._load_watchlist()

    # ------------------------------------------------------------------
    # Watch-list management
    # ------------------------------------------------------------------

    def add_watch(self, target: str, interval_hours: float = DEFAULT_INTERVAL_HOURS) -> WatchEntry:
        """
        Add *target* to the watch list.

        If the target is already watched, its interval is updated.

        Args:
            target: Domain or hostname to monitor (e.g. ``"example.com"``).
            interval_hours: How often to re-check, in hours.  Default 24.

        Returns:
            The created or updated :class:`WatchEntry`.
        """
        now = datetime.utcnow().isoformat()
        if target in self._watchlist:
            entry = self._watchlist[target]
            entry.interval_hours = interval_hours
            logger.info("Updated watch interval for %s to %.1fh", target, interval_hours)
        else:
            entry = WatchEntry(
                target=target,
                interval_hours=interval_hours,
                added_at=now,
                last_checked=None,
            )
            self._watchlist[target] = entry
            logger.info("Added %s to watch list (interval %.1fh)", target, interval_hours)

        self._save_watchlist()
        return entry

    def remove_watch(self, target: str) -> bool:
        """
        Remove *target* from the watch list.

        Returns:
            ``True`` if the target was present and removed, ``False`` otherwise.
        """
        if target in self._watchlist:
            del self._watchlist[target]
            self._save_watchlist()
            logger.info("Removed %s from watch list", target)
            return True
        logger.warning("Target %s is not on the watch list", target)
        return False

    def list_watches(self) -> List[WatchEntry]:
        """Return all current watch entries."""
        return list(self._watchlist.values())

    # ------------------------------------------------------------------
    # Checking
    # ------------------------------------------------------------------

    def check_target(self, target: str) -> Dict[str, Any]:
        """
        Run all change-detection checks against *target*.

        This compares the current state against the stored baseline.  If no
        baseline exists yet, the current state becomes the baseline and no
        alerts are generated.

        Returns:
            A dict summarising the results, with a ``changes`` key listing
            every detected difference and an ``alerts_generated`` count.
        """
        logger.info("Checking target: %s", target)
        now = datetime.utcnow()
        baseline = self._load_baseline(target)
        is_first_run = baseline is None

        # Gather current state from all probes
        current_state: Dict[str, Any] = {}
        current_state["subdomains"] = self._check_new_subdomains(target)
        current_state["certificate"] = self._check_certificate_changes(target)
        current_state["technology"] = self._check_technology_changes(target)
        current_state["dns"] = self._check_dns_changes(target)
        current_state["http"] = self._check_http_changes(target)
        current_state["collected_at"] = now.isoformat()

        if is_first_run:
            # Save as the first baseline; no comparison possible yet.
            self._save_baseline(target, current_state)
            self._mark_checked(target, now)
            logger.info("Baseline established for %s (first run)", target)
            return {
                "target": target,
                "first_run": True,
                "changes": [],
                "alerts_generated": 0,
                "checked_at": now.isoformat(),
            }

        # Compare current state against baseline
        changes = self._diff_states(target, baseline, current_state)

        # Persist changes
        self._save_changes(target, changes, now)

        # Generate alerts from changes
        alerts_generated = self._generate_alerts(target, changes, now)

        # Update baseline to current state
        self._save_baseline(target, current_state)
        self._mark_checked(target, now)

        return {
            "target": target,
            "first_run": False,
            "changes": changes,
            "alerts_generated": alerts_generated,
            "checked_at": now.isoformat(),
        }

    def check_all(self) -> List[Dict[str, Any]]:
        """
        Check every watched target whose interval has elapsed.

        Returns:
            A list of per-target result dicts (same shape as
            :meth:`check_target` returns).
        """
        results: List[Dict[str, Any]] = []
        now = datetime.utcnow()

        for target, entry in self._watchlist.items():
            if entry.last_checked:
                last = datetime.fromisoformat(entry.last_checked)
                next_check = last + timedelta(hours=entry.interval_hours)
                if now < next_check:
                    logger.debug(
                        "Skipping %s (next check at %s)", target, next_check.isoformat()
                    )
                    continue

            try:
                result = self.check_target(target)
                results.append(result)
            except Exception as exc:
                logger.error("Error checking %s: %s", target, exc, exc_info=True)
                results.append({
                    "target": target,
                    "error": str(exc),
                    "checked_at": now.isoformat(),
                })

        return results

    # ------------------------------------------------------------------
    # Change and alert retrieval
    # ------------------------------------------------------------------

    def get_changes(self, target: str, *, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return the most recent detected changes for *target*.

        Args:
            target: The domain to query.
            limit: Maximum number of change records to return.
        """
        safe = _sanitize_filename(target)
        changes_file = CHANGES_DIR / f"{safe}.json"
        history: List[Dict[str, Any]] = _read_json(changes_file, [])
        # Most recent first
        return list(reversed(history[-limit:]))

    def get_alerts(self, *, unacknowledged_only: bool = True) -> List[Alert]:
        """
        Return outstanding alerts.

        Args:
            unacknowledged_only: If ``True`` (default), return only alerts that
                have not been acknowledged yet.
        """
        raw: List[Dict[str, Any]] = _read_json(ALERTS_FILE, [])
        alerts = [Alert.from_dict(a) for a in raw]
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        return alerts

    def acknowledge_alert(self, target: str, alert_type: str) -> int:
        """
        Mark all matching alerts as acknowledged.

        Returns:
            Number of alerts acknowledged.
        """
        raw: List[Dict[str, Any]] = _read_json(ALERTS_FILE, [])
        count = 0
        for entry in raw:
            if entry["target"] == target and entry["alert_type"] == alert_type and not entry["acknowledged"]:
                entry["acknowledged"] = True
                count += 1
        if count:
            _write_json(ALERTS_FILE, raw)
        return count

    def acknowledge_all(self) -> int:
        """Mark every alert as acknowledged. Returns count acknowledged."""
        raw: List[Dict[str, Any]] = _read_json(ALERTS_FILE, [])
        count = 0
        for entry in raw:
            if not entry["acknowledged"]:
                entry["acknowledged"] = True
                count += 1
        if count:
            _write_json(ALERTS_FILE, raw)
        return count

    # ------------------------------------------------------------------
    # Individual change-detection probes
    # ------------------------------------------------------------------

    def _check_new_subdomains(self, target: str) -> Dict[str, Any]:
        """
        Query crt.sh Certificate Transparency logs for subdomains of *target*.

        Returns:
            ``{"subdomains": [sorted list of unique names], "error": ... }``
        """
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        data = _curl_json(url, timeout=CURL_TIMEOUT)
        if data is None:
            return {"subdomains": [], "error": "crt.sh query failed or timed out"}

        names: set = set()
        if isinstance(data, list):
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.splitlines():
                    cleaned = line.strip().lower()
                    if cleaned and cleaned.endswith(target.lower()):
                        # Strip any leading wildcard for consistency
                        cleaned = cleaned.lstrip("*.")
                        names.add(cleaned)

        return {"subdomains": sorted(names), "error": None}

    def _check_certificate_changes(self, target: str) -> Dict[str, Any]:
        """
        Retrieve the current TLS certificate for *target* and return a
        summary dict suitable for diffing.
        """
        info = _get_cert_info(target)
        if info is None:
            return {"certificate": None, "error": "Could not retrieve certificate"}
        return {"certificate": info, "error": None}

    def _check_technology_changes(self, target: str) -> Dict[str, Any]:
        """
        Fetch HTTP response headers from *target* and extract technology
        indicators (Server, X-Powered-By, X-Generator, etc.).
        """
        url = f"https://{target}/"
        resp = _curl_get(url, headers_only=True)
        if resp["error"]:
            return {"technologies": {}, "error": resp["error"]}

        tech: Dict[str, str] = {}
        interesting_headers = {
            "server",
            "x-powered-by",
            "x-generator",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-drupal-cache",
            "x-varnish",
            "x-cache",
            "x-framework",
            "x-runtime",
            "x-request-id",
            "via",
            "x-cdn",
            "x-amz-cf-id",
            "x-amz-cf-pop",
            "cf-ray",
            "x-shopify-stage",
            "x-shopid",
            "x-envoy-upstream-service-time",
        }

        for line in resp["headers"].splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                key_lower = key.strip().lower()
                if key_lower in interesting_headers:
                    tech[key_lower] = value.strip()

        return {"technologies": tech, "error": None}

    def _check_dns_changes(self, target: str) -> Dict[str, Any]:
        """
        Resolve A and AAAA records for *target*.
        """
        records = _resolve_dns(target)
        return {"dns": records, "error": None}

    def _check_http_changes(self, target: str) -> Dict[str, Any]:
        """
        Make an HTTPS request to *target* and record the final status code,
        any redirects observed, and a hash of selected response headers to
        detect behavioural changes.
        """
        url = f"https://{target}/"
        # Use curl with -I (HEAD) and -L (follow redirects) to capture final state
        cmd = [
            "curl", "-sS", "--max-time", str(CURL_TIMEOUT),
            "-o", "/dev/null",       # discard body
            "-w", json.dumps({
                "status_code": "%{http_code}",
                "redirect_url": "%{redirect_url}",
                "url_effective": "%{url_effective}",
                "num_redirects": "%{num_redirects}",
                "time_total": "%{time_total}",
            }),
            "-L", url,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=CURL_TIMEOUT + 10,
            )
            info = json.loads(result.stdout)
            # Normalise types
            info["status_code"] = int(info.get("status_code", 0))
            info["num_redirects"] = int(info.get("num_redirects", 0))
            return {"http": info, "error": None}
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
            return {"http": {}, "error": str(exc)}
        except Exception as exc:
            return {"http": {}, "error": str(exc)}

    # ------------------------------------------------------------------
    # Diffing / comparison
    # ------------------------------------------------------------------

    def _diff_states(
        self,
        target: str,
        old: Dict[str, Any],
        new: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Compare *old* baseline state with *new* current state and return a
        list of change records.

        Each change record is a dict with keys:
            category, description, old_value, new_value, severity
        """
        changes: List[Dict[str, Any]] = []

        # --- Subdomains ---
        old_subs = set(old.get("subdomains", {}).get("subdomains", []))
        new_subs = set(new.get("subdomains", {}).get("subdomains", []))
        added_subs = sorted(new_subs - old_subs)
        removed_subs = sorted(old_subs - new_subs)

        if added_subs:
            # New subdomains are high-value because they may introduce new
            # attack surface that has not been hardened yet.
            severity = AlertSeverity.CRITICAL if len(added_subs) >= 5 else AlertSeverity.WARNING
            changes.append({
                "category": "new_subdomains",
                "description": f"{len(added_subs)} new subdomain(s) discovered: {', '.join(added_subs[:10])}",
                "old_value": sorted(old_subs),
                "new_value": sorted(new_subs),
                "severity": severity.value,
                "added": added_subs,
            })
        if removed_subs:
            changes.append({
                "category": "removed_subdomains",
                "description": f"{len(removed_subs)} subdomain(s) no longer seen: {', '.join(removed_subs[:10])}",
                "old_value": sorted(old_subs),
                "new_value": sorted(new_subs),
                "severity": AlertSeverity.INFO.value,
                "removed": removed_subs,
            })

        # --- Certificate ---
        old_cert = old.get("certificate", {}).get("certificate")
        new_cert = new.get("certificate", {}).get("certificate")
        if old_cert and new_cert:
            if old_cert.get("sha256_fingerprint") != new_cert.get("sha256_fingerprint"):
                changes.append({
                    "category": "cert_change",
                    "description": (
                        f"TLS certificate changed. "
                        f"Old serial: {old_cert.get('serialNumber', 'N/A')}, "
                        f"New serial: {new_cert.get('serialNumber', 'N/A')}. "
                        f"New expiry: {new_cert.get('notAfter', 'N/A')}"
                    ),
                    "old_value": old_cert,
                    "new_value": new_cert,
                    "severity": AlertSeverity.INFO.value,
                })

            # Check if the SAN list changed -- new SANs may reveal new hosts
            old_sans = set(old_cert.get("subjectAltName", []))
            new_sans = set(new_cert.get("subjectAltName", []))
            added_sans = sorted(new_sans - old_sans)
            if added_sans:
                changes.append({
                    "category": "cert_new_sans",
                    "description": f"New SAN entries on certificate: {', '.join(added_sans[:10])}",
                    "old_value": sorted(old_sans),
                    "new_value": sorted(new_sans),
                    "severity": AlertSeverity.WARNING.value,
                    "added": added_sans,
                })
        elif old_cert is None and new_cert is not None:
            changes.append({
                "category": "cert_change",
                "description": "TLS certificate now available (was previously unreachable)",
                "old_value": None,
                "new_value": new_cert,
                "severity": AlertSeverity.INFO.value,
            })
        elif old_cert is not None and new_cert is None:
            changes.append({
                "category": "cert_change",
                "description": "TLS certificate is no longer reachable",
                "old_value": old_cert,
                "new_value": None,
                "severity": AlertSeverity.WARNING.value,
            })

        # --- Technology stack ---
        old_tech = old.get("technology", {}).get("technologies", {})
        new_tech = new.get("technology", {}).get("technologies", {})
        tech_added = {k: new_tech[k] for k in new_tech if k not in old_tech}
        tech_removed = {k: old_tech[k] for k in old_tech if k not in new_tech}
        tech_changed = {
            k: {"old": old_tech[k], "new": new_tech[k]}
            for k in old_tech
            if k in new_tech and old_tech[k] != new_tech[k]
        }

        if tech_added or tech_removed or tech_changed:
            parts = []
            if tech_added:
                parts.append(f"Added headers: {', '.join(f'{k}={v}' for k, v in tech_added.items())}")
            if tech_removed:
                parts.append(f"Removed headers: {', '.join(tech_removed.keys())}")
            if tech_changed:
                parts.append(
                    "Changed: " + ", ".join(
                        f"{k}: {v['old']} -> {v['new']}" for k, v in tech_changed.items()
                    )
                )
            severity = AlertSeverity.WARNING
            # Server software version change is more significant
            if "server" in tech_changed or "x-powered-by" in tech_changed:
                severity = AlertSeverity.CRITICAL
            changes.append({
                "category": "tech_change",
                "description": "; ".join(parts),
                "old_value": old_tech,
                "new_value": new_tech,
                "severity": severity.value,
                "added": tech_added,
                "removed": tech_removed,
                "changed": tech_changed,
            })

        # --- DNS ---
        old_dns = old.get("dns", {}).get("dns", {})
        new_dns = new.get("dns", {}).get("dns", {})
        for rtype in ("A", "AAAA"):
            old_records = set(old_dns.get(rtype, []))
            new_records = set(new_dns.get(rtype, []))
            if old_records != new_records:
                added = sorted(new_records - old_records)
                removed = sorted(old_records - new_records)
                desc_parts = []
                if added:
                    desc_parts.append(f"added {rtype}: {', '.join(added)}")
                if removed:
                    desc_parts.append(f"removed {rtype}: {', '.join(removed)}")
                changes.append({
                    "category": "dns_change",
                    "description": f"DNS {rtype} records changed: {'; '.join(desc_parts)}",
                    "old_value": sorted(old_records),
                    "new_value": sorted(new_records),
                    "severity": AlertSeverity.WARNING.value,
                    "record_type": rtype,
                    "added": added,
                    "removed": removed,
                })

        # --- HTTP behaviour ---
        old_http = old.get("http", {}).get("http", {})
        new_http = new.get("http", {}).get("http", {})
        if old_http and new_http:
            old_status = old_http.get("status_code")
            new_status = new_http.get("status_code")
            if old_status and new_status and old_status != new_status:
                # A status code flip can indicate deployment changes, new WAF, etc.
                severity = AlertSeverity.INFO
                if new_status in (403, 401):
                    severity = AlertSeverity.WARNING
                elif new_status >= 500:
                    severity = AlertSeverity.CRITICAL
                changes.append({
                    "category": "http_status_change",
                    "description": f"HTTP status changed from {old_status} to {new_status}",
                    "old_value": old_status,
                    "new_value": new_status,
                    "severity": severity.value,
                })

            old_effective = old_http.get("url_effective", "")
            new_effective = new_http.get("url_effective", "")
            if old_effective and new_effective and old_effective != new_effective:
                changes.append({
                    "category": "http_redirect_change",
                    "description": f"Final redirect URL changed: {old_effective} -> {new_effective}",
                    "old_value": old_effective,
                    "new_value": new_effective,
                    "severity": AlertSeverity.WARNING.value,
                })

        return changes

    # ------------------------------------------------------------------
    # Alert generation
    # ------------------------------------------------------------------

    def _generate_alerts(
        self,
        target: str,
        changes: List[Dict[str, Any]],
        when: datetime,
    ) -> int:
        """
        Turn change records into Alert objects and persist them.

        Returns:
            Number of alerts created.
        """
        if not changes:
            return 0

        raw_alerts: List[Dict[str, Any]] = _read_json(ALERTS_FILE, [])

        count = 0
        for change in changes:
            alert = Alert(
                target=target,
                alert_type=change["category"],
                description=change["description"],
                severity=change.get("severity", AlertSeverity.INFO.value),
                detected_at=when.isoformat(),
                acknowledged=False,
                details={
                    "old_value": change.get("old_value"),
                    "new_value": change.get("new_value"),
                },
            )
            raw_alerts.append(alert.to_dict())
            count += 1
            logger.info(
                "[ALERT][%s][%s] %s", alert.severity.upper(), target, alert.description
            )

        _write_json(ALERTS_FILE, raw_alerts)
        return count

    # ------------------------------------------------------------------
    # Persistence: baselines
    # ------------------------------------------------------------------

    def _load_baseline(self, target: str) -> Optional[Dict[str, Any]]:
        safe = _sanitize_filename(target)
        path = BASELINES_DIR / f"{safe}.json"
        return _read_json(path, None)

    def _save_baseline(self, target: str, state: Dict[str, Any]) -> None:
        safe = _sanitize_filename(target)
        path = BASELINES_DIR / f"{safe}.json"
        _write_json(path, state)

    # ------------------------------------------------------------------
    # Persistence: change history
    # ------------------------------------------------------------------

    def _save_changes(
        self,
        target: str,
        changes: List[Dict[str, Any]],
        when: datetime,
    ) -> None:
        if not changes:
            return
        safe = _sanitize_filename(target)
        path = CHANGES_DIR / f"{safe}.json"
        history: List[Dict[str, Any]] = _read_json(path, [])
        history.append({
            "checked_at": when.isoformat(),
            "changes": changes,
        })
        # Keep history bounded (last 500 entries)
        if len(history) > 500:
            history = history[-500:]
        _write_json(path, history)

    # ------------------------------------------------------------------
    # Persistence: watch list
    # ------------------------------------------------------------------

    def _load_watchlist(self) -> Dict[str, WatchEntry]:
        raw: List[Dict[str, Any]] = _read_json(WATCHLIST_FILE, [])
        entries: Dict[str, WatchEntry] = {}
        for item in raw:
            try:
                entry = WatchEntry.from_dict(item)
                entries[entry.target] = entry
            except (TypeError, KeyError):
                logger.warning("Skipping malformed watchlist entry: %s", item)
        return entries

    def _save_watchlist(self) -> None:
        data = [entry.to_dict() for entry in self._watchlist.values()]
        _write_json(WATCHLIST_FILE, data)

    def _mark_checked(self, target: str, when: datetime) -> None:
        if target in self._watchlist:
            self._watchlist[target].last_checked = when.isoformat()
            self._save_watchlist()

    # ------------------------------------------------------------------
    # Convenience: summary report
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """
        Return a high-level summary of the monitor state.

        Useful for displaying status in the CLI.
        """
        watched = self.list_watches()
        alerts = self.get_alerts(unacknowledged_only=True)
        return {
            "watched_targets": len(watched),
            "targets": [
                {
                    "target": w.target,
                    "interval_hours": w.interval_hours,
                    "last_checked": w.last_checked,
                }
                for w in watched
            ],
            "unacknowledged_alerts": len(alerts),
            "alerts_by_severity": {
                sev.value: len([a for a in alerts if a.severity == sev.value])
                for sev in AlertSeverity
            },
        }

    # ------------------------------------------------------------------
    # Recommendation engine
    # ------------------------------------------------------------------

    def should_retest(self, target: str) -> Dict[str, Any]:
        """
        Evaluate whether *target* should be retested based on accumulated
        changes and their severity.

        Returns:
            ``{"recommend_retest": bool, "reason": str, "urgency": str, "changes_since_last_test": int}``
        """
        changes_list = self.get_changes(target, limit=100)
        if not changes_list:
            return {
                "recommend_retest": False,
                "reason": "No changes detected since last baseline.",
                "urgency": "none",
                "changes_since_last_test": 0,
            }

        total = sum(len(record.get("changes", [])) for record in changes_list)
        has_critical = any(
            c.get("severity") == AlertSeverity.CRITICAL.value
            for record in changes_list
            for c in record.get("changes", [])
        )
        has_warning = any(
            c.get("severity") == AlertSeverity.WARNING.value
            for record in changes_list
            for c in record.get("changes", [])
        )
        has_new_subs = any(
            c.get("category") == "new_subdomains"
            for record in changes_list
            for c in record.get("changes", [])
        )
        has_tech_change = any(
            c.get("category") == "tech_change"
            for record in changes_list
            for c in record.get("changes", [])
        )

        if has_critical or (has_new_subs and has_tech_change):
            return {
                "recommend_retest": True,
                "reason": "Critical changes detected (new attack surface or major infrastructure change).",
                "urgency": "high",
                "changes_since_last_test": total,
            }

        if has_warning or has_new_subs:
            return {
                "recommend_retest": True,
                "reason": "Notable changes detected that may expose new vulnerabilities.",
                "urgency": "medium",
                "changes_since_last_test": total,
            }

        if total >= 3:
            return {
                "recommend_retest": True,
                "reason": f"Multiple minor changes accumulated ({total} total).",
                "urgency": "low",
                "changes_since_last_test": total,
            }

        return {
            "recommend_retest": False,
            "reason": "Changes detected are minor and unlikely to introduce new vulnerabilities.",
            "urgency": "none",
            "changes_since_last_test": total,
        }
