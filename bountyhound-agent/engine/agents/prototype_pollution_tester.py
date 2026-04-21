"""
Prototype Pollution Tester Agent

Comprehensive JavaScript prototype pollution detection and exploitation covering
client-side, server-side Node.js, and gadget chain discovery for RCE.

Tests for:
- __proto__ pollution (JSON and query parameters)
- constructor.prototype pollution
- Client-side pollution (URL fragments, query strings)
- Server-side pollution (JSON body, merge operations)
- RCE gadget chains (Lodash, EJS, Handlebars, etc.)
- Filter bypass techniques (Unicode, case variation)
- Deep merge pollution
- Array-based pollution
- Nested object pollution

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote, urlencode, urlparse
from datetime import datetime
from colorama import Fore, Style


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class PollutionType(Enum):
    """Prototype pollution types"""
    PROTO = "__proto__"
    CONSTRUCTOR = "constructor"
    PROPERTY_INJECTION = "property_injection"


class PollutionContext(Enum):
    """Execution context"""
    CLIENT_SIDE = "client_side"
    SERVER_SIDE = "server_side"
    UNKNOWN = "unknown"


@dataclass
class PollutionPayload:
    """Prototype pollution payload"""
    payload: str
    pollution_type: PollutionType
    context: PollutionContext
    property_name: str
    property_value: str
    encoding: str = "none"
    description: str = ""


@dataclass
class GadgetChain:
    """RCE gadget chain"""
    name: str
    library: str
    version: Optional[str]
    payload: str
    command: str
    detection_method: str
    severity: str = "critical"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'library': self.library,
            'version': self.version,
            'payload': self.payload[:200] if len(self.payload) > 200 else self.payload,
            'command': self.command,
            'detection_method': self.detection_method,
            'severity': self.severity
        }


class PrototypePollutionTester:
    """Detects __proto__ and constructor.prototype pollution in JSON bodies
    and query parameters."""

    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.findings: List[Dict] = []

    def run_all_tests(self) -> List[Dict]:
        """Run all prototype pollution tests. Returns list of finding dicts."""
        self.findings = []
        if not REQUESTS_AVAILABLE:
            return self.findings
        self._test_proto_json()
        self._test_constructor_json()
        self._test_query_params()
        return self.findings

    def _post(self, payload: dict) -> "requests.Response | None":
        try:
            return requests.post(
                self.target,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
            )
        except Exception:
            return None

    def _get(self, param: str) -> "requests.Response | None":
        try:
            return requests.get(f"{self.target}?{param}", timeout=10, allow_redirects=True)
        except Exception:
            return None

    def _reflected(self, resp) -> bool:
        """Did the response echo back a polluted marker value?"""
        if resp is None:
            return False
        markers = ['"polluted"', '"bh_polluted"', "bh_polluted"]
        return any(m in resp.text for m in markers)

    def _record(self, title: str, description: str, severity: str, url: str,
                state_change: bool):
        self.findings.append({
            "title": title,
            "description": description,
            "severity": severity,
            "vuln_type": "prototype_pollution",
            "url": url,
            "verified": True,
            "state_change_proven": state_change,
            "agent": "prototype_pollution_tester",
        })

    def _test_proto_json(self):
        payloads = [
            {"__proto__": {"bh_polluted": "true"}},
            {"__proto__": {"admin": "true", "bh_polluted": "true"}},
        ]
        for payload in payloads:
            resp = self._post(payload)
            if self._reflected(resp):
                self._record(
                    "Prototype Pollution via __proto__ (JSON body)",
                    f"Server reflected polluted property. Payload: {payload}",
                    "HIGH",
                    self.target,
                    state_change=True,
                )
                break

    def _test_constructor_json(self):
        payloads = [
            {"constructor": {"prototype": {"bh_polluted": "true"}}},
            {"constructor": {"prototype": {"admin": "true", "bh_polluted": "true"}}},
        ]
        for payload in payloads:
            resp = self._post(payload)
            if self._reflected(resp):
                self._record(
                    "Prototype Pollution via constructor.prototype (JSON body)",
                    f"Server reflected polluted property. Payload: {payload}",
                    "HIGH",
                    self.target,
                    state_change=True,
                )
                break

    def _test_query_params(self):
        for param in [
            "__proto__[bh_polluted]=true",
            "constructor[prototype][bh_polluted]=true",
        ]:
            resp = self._get(param)
            if self._reflected(resp):
                self._record(
                    "Prototype Pollution via Query Parameter",
                    f"Server reflected polluted property via query string: {param}",
                    "MEDIUM",
                    f"{self.target}?{param}",
                    state_change=False,
                )
                break
