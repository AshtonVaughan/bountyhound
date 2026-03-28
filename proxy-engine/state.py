"""Shared in-memory state for the proxy engine.

All mitmproxy addon and FastAPI routes access this single module.
Uses asyncio.Lock for safe concurrent access.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict

from models import (
    Flow, IntruderJob, ScanJob, WebSocketMessage,
    RepeaterHistoryEntry, SequencerResult, PassiveFinding,
    CrawlJob, DiscoveryJob, BreakpointRule, ScheduledScan,
    CollaboratorInteraction, CollaboratorPayload, CollaboratorConfig,
    ResourcePool, TLSClientConfig,
)
from safe_regex import safe_compile, safe_search


class ProxyState:
    """Central state store shared between mitmproxy addon and FastAPI."""

    def __init__(self, max_flows: int = 50_000) -> None:
        self.max_flows = max_flows

        # Flow storage
        self.flows: OrderedDict[str, Flow] = OrderedDict()
        self._flow_counter: int = 0

        # WebSocket messages
        self.ws_messages: list[WebSocketMessage] = []

        # Intercept
        self.intercept_enabled: bool = False
        self.intercept_queue: OrderedDict[str, Flow] = OrderedDict()
        self._intercept_events: dict[str, asyncio.Event] = {}
        self._intercept_actions: dict[str, dict] = {}

        # Conditional breakpoints (Task #20)
        self.breakpoint_rules: list[BreakpointRule] = []

        # Repeater history
        self.repeater_history: list[RepeaterHistoryEntry] = []
        self._repeater_counter: int = 0

        # Intruder jobs
        self.intruder_jobs: dict[str, IntruderJob] = {}

        # Scanner jobs
        self.scanner_jobs: dict[str, ScanJob] = {}

        # Sequencer jobs
        self.sequencer_jobs: dict[str, SequencerResult] = {}

        # Collaborator state
        self.collaborator_server_url: str | None = None
        self.collaborator_secret: str | None = None
        self.collaborator_payloads_legacy: list[dict] = []
        self.collaborator_interactions: list[CollaboratorInteraction] = []
        self.collaborator_payloads: dict[str, CollaboratorPayload] = {}
        self.collaborator_config: CollaboratorConfig = CollaboratorConfig()

        # Crawler / Discovery jobs
        self.crawl_jobs: dict[str, CrawlJob] = {}
        self.discovery_jobs: dict[str, DiscoveryJob] = {}

        # WebSocket intercept
        self.ws_intercept_enabled: bool = False
        self.ws_intercept_queue: OrderedDict[str, WebSocketMessage] = OrderedDict()
        self._ws_intercept_events: dict[str, asyncio.Event] = {}
        self._ws_intercept_actions: dict[str, dict] = {}
        self._ws_counter: int = 0

        # Response intercept
        self.response_intercept_enabled: bool = False
        self._response_intercept_events: dict[str, asyncio.Event] = {}
        self._response_intercept_actions: dict[str, dict] = {}
        self.response_intercept_queue: OrderedDict[str, Flow] = OrderedDict()

        # Project name
        self.current_project: str = ""

        # Scheduled scans (Task #36)
        self.scheduled_scans: list[ScheduledScan] = []

        # Incremental scanning — track scanned endpoints
        self.scanned_endpoints: dict[str, float] = {}  # url+check -> last_scan_ts

        # Resource pools for intruder
        self.resource_pools: dict[str, ResourcePool] = {}

        # TLS client certificate config
        self.tls_client_config: TLSClientConfig | None = None

        # Macro recording state (Phase 2)
        self.macro_recording: bool = False
        self.macro_recorded_flow_ids: list[str] = []

        # CSRF tracking (Phase 2)
        self.csrf_tracking_enabled: bool = True
        self.csrf_tokens: dict[str, dict[str, str]] = {}  # host -> {param_name: value}

        # Collaboration clients (Phase 3)
        self.collab_clients: dict[str, dict] = {}  # client_id -> {username, connected_at, ...}

        # Lock for state mutations (Task #31)
        self._lock = asyncio.Lock()

        # Shared httpx client for connection pooling (Phase 8)
        self._shared_client: "httpx.AsyncClient | None" = None

        # Queue caps
        self._max_intercept_queue: int = 1000

    def get_shared_client(self) -> "httpx.AsyncClient":
        """Get or create a shared httpx.AsyncClient for connection pooling."""
        import httpx
        if self._shared_client is None or self._shared_client.is_closed:
            self._shared_client = httpx.AsyncClient(
                verify=False, timeout=15.0,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
        return self._shared_client

    def next_flow_id(self) -> str:
        self._flow_counter += 1
        return str(self._flow_counter)

    def add_flow(self, flow: Flow) -> None:
        if len(self.flows) >= self.max_flows:
            self.flows.popitem(last=False)
        self.flows[flow.id] = flow

    def get_flow(self, flow_id: str) -> Flow | None:
        return self.flows.get(flow_id)

    def clear_flows(self) -> int:
        count = len(self.flows)
        self.flows.clear()
        self._flow_counter = 0
        return count

    # ── Breakpoint matching (Task #20) ─────────────────────────────────

    def should_intercept(self, host: str, path: str, method: str,
                         direction: str = "request") -> bool:
        """Check if a request/response should be intercepted based on breakpoint rules.
        If no breakpoint rules exist, use global intercept_enabled flag."""
        if direction == "request" and not self.intercept_enabled:
            return False
        if direction == "response" and not self.response_intercept_enabled:
            return False

        # If no breakpoint rules, intercept everything (old behavior)
        active_rules = [r for r in self.breakpoint_rules if r.enabled]
        if not active_rules:
            return True

        # Must match at least one active breakpoint rule
        for rule in active_rules:
            if rule.direction not in (direction, "both"):
                continue
            if rule.method and rule.method.upper() != method.upper():
                continue
            if rule.host_pattern:
                compiled = safe_compile(rule.host_pattern)
                if not compiled or not compiled.search(host):
                    continue
            if rule.path_pattern:
                compiled = safe_compile(rule.path_pattern)
                if not compiled or not compiled.search(path):
                    continue
            return True

        return False

    # ── Intercept queue ────────────────────────────────────────────────

    def add_to_intercept_queue(self, flow: Flow) -> asyncio.Event:
        # Auto-forward oldest if queue is at capacity
        while len(self.intercept_queue) >= self._max_intercept_queue:
            oldest_id, _ = self.intercept_queue.popitem(last=False)
            old_event = self._intercept_events.pop(oldest_id, None)
            if old_event:
                self._intercept_actions[oldest_id] = {"action": "forward", "modifications": {}}
                old_event.set()
        self.intercept_queue[flow.id] = flow
        event = asyncio.Event()
        self._intercept_events[flow.id] = event
        return event

    def resolve_intercept(self, flow_id: str, action: str, modifications: dict | None = None) -> bool:
        if flow_id not in self._intercept_events:
            self.intercept_queue.pop(flow_id, None)
            return False
        self._intercept_actions[flow_id] = {
            "action": action,
            "modifications": modifications or {},
        }
        self._intercept_events[flow_id].set()
        return True

    def get_intercept_action(self, flow_id: str) -> dict | None:
        action = self._intercept_actions.pop(flow_id, None)
        self._intercept_events.pop(flow_id, None)
        self.intercept_queue.pop(flow_id, None)
        return action

    # ── Response intercept ─────────────────────────────────────────────
    def add_to_response_intercept(self, flow: Flow) -> asyncio.Event:
        self.response_intercept_queue[flow.id] = flow
        event = asyncio.Event()
        self._response_intercept_events[flow.id] = event
        return event

    def resolve_response_intercept(self, flow_id: str, action: str, modifications: dict | None = None) -> bool:
        if flow_id not in self._response_intercept_events:
            self.response_intercept_queue.pop(flow_id, None)
            return False
        self._response_intercept_actions[flow_id] = {
            "action": action,
            "modifications": modifications or {},
        }
        self._response_intercept_events[flow_id].set()
        return True

    def get_response_intercept_action(self, flow_id: str) -> dict | None:
        action = self._response_intercept_actions.pop(flow_id, None)
        self._response_intercept_events.pop(flow_id, None)
        self.response_intercept_queue.pop(flow_id, None)
        return action

    # ── WebSocket intercept ───────────────────────────────────────────

    def add_to_ws_intercept(self, msg: WebSocketMessage) -> asyncio.Event:
        self._ws_counter += 1
        msg_id = f"ws_{self._ws_counter}"
        self.ws_intercept_queue[msg_id] = msg
        event = asyncio.Event()
        self._ws_intercept_events[msg_id] = event
        return event

    def resolve_ws_intercept(self, msg_id: str, action: str, content: str | None = None) -> bool:
        if msg_id not in self._ws_intercept_events:
            self.ws_intercept_queue.pop(msg_id, None)
            return False
        self._ws_intercept_actions[msg_id] = {
            "action": action,
            "content": content,
        }
        self._ws_intercept_events[msg_id].set()
        return True

    def get_ws_intercept_action(self, msg_id: str) -> dict | None:
        action = self._ws_intercept_actions.pop(msg_id, None)
        self._ws_intercept_events.pop(msg_id, None)
        self.ws_intercept_queue.pop(msg_id, None)
        return action

    def add_repeater_entry(self, req, resp: dict) -> RepeaterHistoryEntry:
        self._repeater_counter += 1
        entry = RepeaterHistoryEntry(id=self._repeater_counter, request=req, response=resp)
        self.repeater_history.append(entry)
        if len(self.repeater_history) > 5000:
            self.repeater_history = self.repeater_history[-2500:]
        return entry

    def add_ws_message(self, msg: WebSocketMessage) -> None:
        self.ws_messages.append(msg)
        if len(self.ws_messages) > 10_000:
            self.ws_messages = self.ws_messages[-5000:]

    # ── Bounded job cleanup (Task #31) ─────────────────────────────────

    def cleanup_completed_jobs(self, max_completed: int = 100) -> None:
        """Remove oldest completed jobs to bound memory usage."""
        for store in (self.intruder_jobs, self.scanner_jobs, self.crawl_jobs,
                      self.discovery_jobs, self.sequencer_jobs):
            completed = [k for k, v in store.items()
                         if getattr(v, 'status', '') in ('completed', 'cancelled', 'error')]
            if len(completed) > max_completed:
                for k in completed[:len(completed) - max_completed]:
                    store.pop(k, None)

        # Cleanup stale collab clients (no heartbeat in 5 minutes)
        import time
        stale_cutoff = time.time() - 300
        stale_ids = [cid for cid, info in self.collab_clients.items()
                     if info.get("last_seen", 0) < stale_cutoff]
        for cid in stale_ids:
            self.collab_clients.pop(cid, None)

    def list_flows(
        self,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        content_type: str | None = None,
        search: str | None = None,
        search_body: bool = False,
        search_headers: bool = False,
        search_regex: bool = False,
        scope_only: bool = False,
        filter_expr: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Flow]:
        """Filter and paginate flows with advanced search."""
        from scope import is_in_scope

        results = []
        for flow in reversed(self.flows.values()):
            if scope_only and not is_in_scope(flow.host, flow.request.url):
                continue
            if host and host.lower() not in flow.host.lower():
                continue
            if method and flow.request.method.upper() != method.upper():
                continue
            if status_code and flow.response and flow.response.status_code != status_code:
                continue
            if status_code and not flow.response:
                continue
            if content_type and flow.response:
                ct = flow.response.headers.get("content-type", "")
                if content_type.lower() not in ct.lower():
                    continue
            if search:
                if not _matches_search(flow, search, search_body, search_headers, search_regex):
                    continue
            if filter_expr:
                if not _evaluate_filter_expr(flow, filter_expr):
                    continue
            results.append(flow)

        return results[offset:offset + limit]


def _get_flow_field(flow: Flow, field: str):
    """Extract a field value from a flow for filter expression evaluation."""
    field = field.lower().strip()
    if field == "status_code":
        return flow.response.status_code if flow.response else 0
    elif field == "method":
        return flow.request.method.upper()
    elif field == "host":
        return flow.host
    elif field == "path":
        return flow.path
    elif field == "content_type":
        if flow.response:
            return flow.response.headers.get("content-type", "")
        return ""
    elif field == "length":
        if flow.response and flow.response.body:
            return len(flow.response.body)
        return 0
    elif field == "has_params":
        return "?" in flow.request.url
    elif field == "url":
        return flow.request.url
    return ""


def _evaluate_filter_expr(flow: Flow, expr: str) -> bool:
    """Evaluate a boolean filter expression against a flow.

    Supports: field OP value, AND, OR, NOT, parentheses.
    Operators: ==, !=, >, <, >=, <=, CONTAINS, MATCHES
    Fields: status_code, method, host, path, content_type, length, has_params, url
    """
    expr = expr.strip()
    if not expr:
        return True

    try:
        return _parse_or(expr, flow)[0]
    except Exception:
        return True  # if expression is malformed, don't filter


def _parse_or(expr: str, flow: Flow) -> tuple[bool, str]:
    """Parse OR expressions."""
    result, remaining = _parse_and(expr, flow)
    while remaining.strip().upper().startswith("OR "):
        remaining = remaining.strip()[3:]
        right, remaining = _parse_and(remaining, flow)
        result = result or right
    return result, remaining


def _parse_and(expr: str, flow: Flow) -> tuple[bool, str]:
    """Parse AND expressions."""
    result, remaining = _parse_not(expr, flow)
    while remaining.strip().upper().startswith("AND "):
        remaining = remaining.strip()[4:]
        right, remaining = _parse_not(remaining, flow)
        result = result and right
    return result, remaining


def _parse_not(expr: str, flow: Flow) -> tuple[bool, str]:
    """Parse NOT expressions."""
    stripped = expr.strip()
    if stripped.upper().startswith("NOT "):
        result, remaining = _parse_atom(stripped[4:], flow)
        return not result, remaining
    return _parse_atom(stripped, flow)


def _parse_atom(expr: str, flow: Flow) -> tuple[bool, str]:
    """Parse atomic expressions (comparisons or parenthesized expressions)."""
    stripped = expr.strip()

    # Parenthesized expression
    if stripped.startswith("("):
        result, remaining = _parse_or(stripped[1:], flow)
        remaining = remaining.strip()
        if remaining.startswith(")"):
            remaining = remaining[1:]
        return result, remaining

    # Comparison: field OP value
    # Find the operator
    ops = [">=", "<=", "!=", "==", ">", "<", "CONTAINS", "MATCHES"]
    for op in ops:
        # Case-insensitive operator search
        upper_stripped = stripped.upper()
        idx = -1
        # Find operator surrounded by spaces for CONTAINS/MATCHES
        if op in ("CONTAINS", "MATCHES"):
            search_str = f" {op} "
            idx = upper_stripped.find(search_str)
            if idx >= 0:
                field_part = stripped[:idx].strip()
                rest = stripped[idx + len(search_str):]
            else:
                continue
        else:
            idx = stripped.find(op)
            if idx < 0:
                continue
            field_part = stripped[:idx].strip()
            rest = stripped[idx + len(op):]

        # Parse value — may be quoted or unquoted
        rest = rest.strip()
        value_str, remaining = _parse_value(rest)

        flow_val = _get_flow_field(flow, field_part)
        result = _compare(flow_val, op, value_str)
        return result, remaining

    # Bare boolean field (e.g., "has_params")
    parts = stripped.split(None, 1)
    field = parts[0]
    remaining = parts[1] if len(parts) > 1 else ""
    return bool(_get_flow_field(flow, field)), remaining


def _parse_value(expr: str) -> tuple[str, str]:
    """Parse a value from the expression, handling quotes."""
    expr = expr.strip()
    if expr.startswith('"'):
        end = expr.find('"', 1)
        if end >= 0:
            return expr[1:end], expr[end + 1:]
        return expr[1:], ""
    if expr.startswith("'"):
        end = expr.find("'", 1)
        if end >= 0:
            return expr[1:end], expr[end + 1:]
        return expr[1:], ""
    # Unquoted: take until whitespace or end
    parts = expr.split(None, 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _compare(flow_val, op: str, value_str: str) -> bool:
    """Compare a flow field value against a target using the given operator."""
    op = op.upper()
    if op == "CONTAINS":
        return value_str.lower() in str(flow_val).lower()
    if op == "MATCHES":
        return bool(safe_search(value_str, str(flow_val)))

    # Numeric comparison if possible
    try:
        fv = float(flow_val) if not isinstance(flow_val, (int, float)) else flow_val
        tv = float(value_str)
        if op == "==": return fv == tv
        if op == "!=": return fv != tv
        if op == ">": return fv > tv
        if op == "<": return fv < tv
        if op == ">=": return fv >= tv
        if op == "<=": return fv <= tv
    except (ValueError, TypeError):
        pass

    # String comparison
    sv = str(flow_val)
    if op == "==": return sv.lower() == value_str.lower()
    if op == "!=": return sv.lower() != value_str.lower()
    return False


def _matches_search(flow: Flow, search: str, body: bool, headers: bool, use_regex: bool) -> bool:
    """Check if a flow matches a search query."""
    haystack_parts = [flow.request.url, flow.request.method, flow.host, flow.path]

    if headers:
        for k, v in flow.request.headers.items():
            haystack_parts.append(f"{k}: {v}")
        if flow.response:
            for k, v in flow.response.headers.items():
                haystack_parts.append(f"{k}: {v}")

    if body:
        if flow.request.body:
            haystack_parts.append(flow.request.body[:5000])
        if flow.response and flow.response.body:
            haystack_parts.append(flow.response.body[:5000])

    haystack = "\n".join(haystack_parts)

    if use_regex:
        return bool(safe_search(search, haystack))
    else:
        return search.lower() in haystack.lower()


# Singleton
state = ProxyState()
