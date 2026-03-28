"""Pydantic models for the proxy engine."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Flow models ──────────────────────────────────────────────────────────────

class FlowRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    http_version: str = "HTTP/1.1"
    timestamp: float = 0.0

class FlowResponse(BaseModel):
    status_code: int
    reason: str = ""
    headers: dict[str, str] = {}
    body: str | None = None
    timestamp: float = 0.0

class Flow(BaseModel):
    id: str
    request: FlowRequest
    response: FlowResponse | None = None
    host: str = ""
    path: str = ""
    timestamp: float = Field(default_factory=time.time)
    tags: list[str] = []
    notes: str = ""
    highlight: str = ""  # color name for row highlighting


# ── WebSocket models ─────────────────────────────────────────────────────────

class WebSocketMessage(BaseModel):
    flow_id: str
    direction: str  # "send" or "receive"
    content: str
    is_text: bool = True
    timestamp: float = Field(default_factory=time.time)
    length: int = 0


class WebSocketModification(BaseModel):
    """Modification to apply to an intercepted WebSocket message."""
    content: str | None = None
    action: str = "forward"  # "forward" or "drop"


# ── Intercept models ─────────────────────────────────────────────────────────

class InterceptAction(str, Enum):
    forward = "forward"
    drop = "drop"

class InterceptModification(BaseModel):
    method: str | None = None
    url: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None


# ── Scope models ─────────────────────────────────────────────────────────────

class ScopeRule(BaseModel):
    """A single scope rule — regex pattern matched against host or URL."""
    pattern: str
    target: str = "host"  # "host" or "url"
    enabled: bool = True
    protocol: str = ""    # "http", "https", or "" for any
    port: int | None = None  # specific port, or None for any
    path_pattern: str = ""  # regex for path, or "" for any

class ScopeConfig(BaseModel):
    enabled: bool = False
    include: list[ScopeRule] = []
    exclude: list[ScopeRule] = []


# ── Repeater models ──────────────────────────────────────────────────────────

class RepeaterRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    follow_redirects: bool = False

class RepeaterModification(BaseModel):
    method: str | None = None
    url: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    follow_redirects: bool = False

class RepeaterHistoryEntry(BaseModel):
    id: int
    request: RepeaterRequest
    response: dict = {}
    timestamp: float = Field(default_factory=time.time)


# ── Intruder models ──────────────────────────────────────────────────────────

class AttackType(str, Enum):
    sniper = "sniper"
    battering_ram = "battering_ram"
    pitchfork = "pitchfork"
    cluster_bomb = "cluster_bomb"

class PayloadProcessing(str, Enum):
    none = "none"
    url_encode = "url_encode"
    url_encode_all = "url_encode_all"
    double_url_encode = "double_url_encode"
    triple_url_encode = "triple_url_encode"
    base64_encode = "base64_encode"
    base64_decode = "base64_decode"
    hex_encode = "hex_encode"
    md5_hash = "md5_hash"
    sha1_hash = "sha1_hash"
    sha256_hash = "sha256_hash"
    html_encode = "html_encode"
    lowercase = "lowercase"
    uppercase = "uppercase"
    reverse = "reverse"
    prefix = "prefix"
    suffix = "suffix"
    unicode_escape = "unicode_escape"
    jwt_sign = "jwt_sign"
    case_mutations = "case_mutations"

class PayloadProcessingRule(BaseModel):
    operation: PayloadProcessing
    value: str = ""  # for prefix/suffix

class GrepRule(BaseModel):
    """Rule to match/flag in intruder responses."""
    pattern: str  # regex
    location: str = "body"  # "body", "headers", "status"
    negate: bool = False  # if True, flag when NOT matched

class IntruderPosition(BaseModel):
    """A position in the request to fuzz. start/end are character indices in the raw value."""
    field: str  # "url", "header:<name>", "body"
    start: int
    end: int

class IntruderRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    positions: list[IntruderPosition]
    payloads: list[list[str]]  # one list per position (or shared for battering_ram); prefix "file:" to load from file
    attack_type: AttackType = AttackType.sniper
    concurrency: int = 10
    delay_ms: int = 0  # delay between requests in ms (rate limiting)
    follow_redirects: bool = False
    timeout: float = 10.0
    payload_processing: list[PayloadProcessingRule] = []
    grep_rules: list[GrepRule] = []
    recursive_grep: str | None = None  # regex to extract from response and feed as next payload
    resource_pool: str | None = None  # named resource pool for shared throttling

class ResourcePool(BaseModel):
    name: str = "default"
    max_concurrent_requests: int = 10
    max_connections_per_host: int = 5
    delay_ms: int = 0
    timeout: float = 10.0
    follow_redirects: bool = False

class IntruderResult(BaseModel):
    index: int
    payload: str | list[str]
    status_code: int
    length: int
    duration_ms: float
    headers: dict[str, str] = {}
    body_preview: str = ""
    error: str | None = None
    grep_matches: dict[str, bool] = {}  # rule_pattern -> matched
    cluster_id: int = 0
    is_anomaly: bool = False

class IntruderJob(BaseModel):
    job_id: str
    status: str = "running"  # running, completed, cancelled, error
    attack_type: AttackType
    total: int = 0
    completed: int = 0
    results: list[IntruderResult] = []
    error: str | None = None
    grep_rules: list[GrepRule] = []
    timing_stats: dict = {}
    timing_anomalies: list[int] = []


# ── Scanner models ───────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    urls: list[str]
    templates: list[str] | None = None
    custom_checks: list[str] | None = None
    severity: str | None = None
    concurrency: int = 10
    profile: str | None = None  # use a named scan profile
    crawl_first: bool = False   # crawl target before scanning

class ScanFinding(BaseModel):
    template_id: str = ""
    name: str = ""
    severity: str = ""
    url: str = ""
    matched_at: str = ""
    description: str = ""
    extracted: list[str] = []
    curl_command: str = ""
    raw: str = ""
    source: str = ""  # "nuclei", "passive", "custom"
    confidence: str = ""  # "confirmed", "tentative", "firm"
    remediation: str = ""
    dedup_key: str = ""  # for grouping duplicate findings
    related_urls: list[str] = []
    occurrence_count: int = 1

class ScanTask(BaseModel):
    task_id: str = ""
    scan_id: str = ""
    check_name: str = ""
    url: str = ""
    insertion_point: str = ""
    status: str = "pending"  # pending, running, paused, completed, cancelled, error
    findings: list[ScanFinding] = []
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str | None = None

class ScanJob(BaseModel):
    scan_id: str
    status: str = "running"
    urls: list[str] = []
    findings: list[ScanFinding] = []
    tasks: list[ScanTask] = []
    error: str | None = None


# ── Passive scanner models ───────────────────────────────────────────────────

class PassiveFinding(BaseModel):
    flow_id: str
    check_id: str
    name: str
    severity: str  # info, low, medium, high
    description: str
    evidence: str = ""
    url: str = ""
    false_positive: bool = False
    fp_reason: str = ""


# ── Comparer models ──────────────────────────────────────────────────────────

class CompareRequest(BaseModel):
    left_flow_id: str | None = None
    right_flow_id: str | None = None
    left_content: str | None = None
    right_content: str | None = None
    diff_mode: str = "line"  # "line", "word", "char", "json"

class DiffResult(BaseModel):
    diff: str
    left_lines: int = 0
    right_lines: int = 0
    changes: int = 0


# ── Decoder models ───────────────────────────────────────────────────────────

class CodecOperation(str, Enum):
    base64 = "base64"
    base32 = "base32"
    url = "url"
    hex = "hex"
    html = "html"
    jwt_decode = "jwt_decode"
    unicode_escape = "unicode_escape"
    gzip = "gzip"
    rot13 = "rot13"
    ascii85 = "ascii85"
    punycode = "punycode"
    quoted_printable = "quoted_printable"

class CodecRequest(BaseModel):
    text: str
    operation: CodecOperation


# ── Collaborator models ──────────────────────────────────────────────────────

class CollaboratorInteraction(BaseModel):
    id: str = ""
    correlation_id: str = ""
    protocol: str = ""  # dns, http, smtp
    remote_address: str = ""
    timestamp: float = Field(default_factory=time.time)
    raw_request: str | None = None
    raw_response: str | None = None
    dns_query: str = ""
    http_method: str = ""
    http_path: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_data: str = ""
    context: str = ""

class CollaboratorConfig(BaseModel):
    domain: str = "collab.localhost"
    dns_port: int = 5354
    http_port: int = 9999
    smtp_port: int = 2525
    enabled: bool = False
    response_ip: str = "127.0.0.1"
    persist_path: str = "collaborator_data.jsonl"

class CollaboratorPayload(BaseModel):
    id: str = ""
    correlation_id: str = ""
    subdomain: str = ""
    full_dns: str = ""
    full_url: str = ""
    https_url: str = ""
    smtp_address: str = ""
    context: str = ""
    created_at: float = Field(default_factory=time.time)

class Interaction(BaseModel):
    protocol: str
    full_id: str
    remote_address: str
    timestamp: str
    raw_request: str | None = None
    raw_response: str | None = None


# ── Sitemap models ───────────────────────────────────────────────────────────

class SitemapNode(BaseModel):
    name: str
    path: str
    methods: list[str] = []
    status_codes: list[int] = []
    children: dict[str, SitemapNode] = {}
    flow_count: int = 0


# ── Sequencer models ─────────────────────────────────────────────────────────

class SequencerRequest(BaseModel):
    """Collect tokens from a request for entropy analysis."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = {}
    body: str | None = None
    token_location: str = "header"  # "header", "cookie", "body_regex"
    token_name: str = ""  # header name, cookie name, or regex with capture group
    sample_count: int = 100
    concurrency: int = 5

class SequencerResult(BaseModel):
    job_id: str
    status: str = "running"
    tokens: list[str] = []
    sample_count: int = 0
    collected: int = 0
    entropy_bits: float = 0.0
    char_frequency: dict[str, int] = {}
    char_entropy: float = 0.0
    length_min: int = 0
    length_max: int = 0
    length_avg: float = 0.0
    rating: str = ""  # "excellent", "good", "fair", "poor"
    analysis: str = ""
    autocorrelation: dict = {}
    block_frequency: dict = {}
    format_analysis: dict = {}
    predictability: dict = {}


# ── Session handler models ───────────────────────────────────────────────────

class SessionRule(BaseModel):
    """Rule for automatic session handling."""
    name: str
    enabled: bool = True
    scope_pattern: str = ".*"  # regex for which hosts this applies to
    trigger: str = "status_403"  # "status_403", "status_401", "regex:<pattern>"
    action: str = "macro"  # "macro" or "replace_header"
    macro_method: str = "GET"
    macro_url: str = ""
    macro_headers: dict[str, str] = {}
    macro_body: str | None = None
    extract_from: str = "header"  # "header", "cookie", "body_regex"
    extract_name: str = ""  # header/cookie name or regex
    inject_as: str = "header"  # "header" or "cookie"
    inject_name: str = ""  # header/cookie name to set


# ── Macro chain models ──────────────────────────────────────────────────────

class MacroStep(BaseModel):
    """A single step in a macro chain."""
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    extract_from: str = ""  # "header", "cookie", "body_regex"
    extract_name: str = ""  # header/cookie name or regex
    extract_var: str = ""   # variable name to store extracted value

class MacroChain(BaseModel):
    """Multi-step macro with variable extraction/substitution between steps."""
    name: str
    steps: list[MacroStep]
    trigger: str = "manual"  # "manual", "status_401", "status_403", "regex:<pattern>"
    final_inject_as: str = ""  # "header" or "cookie"
    final_extract_var: str = ""  # which var to use as the final token


# ── Organizer models ───────────────────────────────────────────────────────

class OrganizerItem(BaseModel):
    """Manual testing notebook item."""
    id: str = ""
    title: str
    category: str = "note"  # "vulnerability", "interesting", "todo", "note"
    severity: str = ""      # "critical", "high", "medium", "low", "info"
    description: str = ""
    linked_flow_ids: list[str] = []
    linked_finding_ids: list[str] = []
    tags: list[str] = []
    status: str = "open"    # "open", "confirmed", "false_positive", "fixed"
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


# ── Export models ────────────────────────────────────────────────────────────

class ExportFormat(str, Enum):
    har = "har"
    curl = "curl"
    raw = "raw"
    python = "python"
    javascript = "javascript"
    powershell = "powershell"
    postman = "postman"
    openapi = "openapi"
    nuclei_template = "nuclei_template"


# ── Extension/Plugin models ──────────────────────────────────────────────────

class ExtensionInfo(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    check_type: str = "passive"  # "passive" or "active"
    file_path: str = ""
    priority: int = 100
    config: dict = {}
    version: str = "1.0"
    author: str = ""
    hooks: list[str] = []


# ── Status model ─────────────────────────────────────────────────────────────

# ── Match & Replace models ──────────────────────────────────────────────────

class MatchReplaceRule(BaseModel):
    """Rule for auto-modifying requests/responses."""
    name: str
    enabled: bool = True
    phase: str = "request"  # "request", "response", "both"
    target: str = "header"  # "url", "method", "header", "body", "add_header", "remove_header"
    target_name: str = ""   # specific header name (for header target)
    match: str = ""
    replace: str = ""
    is_regex: bool = False
    scope_pattern: str = ""  # regex to match host — empty means all hosts


# ── Crawler models ──────────────────────────────────────────────────────────

class CrawlResult(BaseModel):
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    length: int = 0
    depth: int = 0
    params: list[str] = []
    forms: list[dict] = []

class CrawlJob(BaseModel):
    job_id: str
    status: str = "running"
    base_url: str = ""
    urls_found: int = 0
    urls_queued: int = 0
    results: list[CrawlResult] = []
    error: str | None = None


# ── Discovery models ────────────────────────────────────────────────────────

class DiscoveryResult(BaseModel):
    url: str
    status_code: int
    length: int = 0
    content_type: str = ""
    redirect: str = ""

class DiscoveryJob(BaseModel):
    job_id: str
    status: str = "running"
    base_url: str = ""
    total: int = 0
    checked: int = 0
    results: list[DiscoveryResult] = []
    error: str | None = None


# ── Scan Profile models ─────────────────────────────────────────────────────

class ScanProfile(BaseModel):
    name: str
    description: str = ""
    nuclei_severity: str = ""      # e.g. "critical,high,medium"
    nuclei_templates: list[str] = []
    custom_checks: list[str] = []  # which custom checks to run
    concurrency: int = 10
    timeout: int = 300


# ── Status model ────────────────────────────────────────────────────────────

# ── Breakpoint models ──────────────────────────────────────────────────────

class BreakpointRule(BaseModel):
    """Conditional intercept rule — only hold requests matching criteria."""
    name: str = ""
    enabled: bool = True
    host_pattern: str = ""   # regex for host
    path_pattern: str = ""   # regex for path
    method: str = ""         # exact match, empty = any
    direction: str = "request"  # "request", "response", "both"


# ── Scheduled scan models ──────────────────────────────────────────────────

class ScheduledScan(BaseModel):
    """A scan scheduled to run periodically."""
    name: str
    urls: list[str]
    profile: str = ""
    interval_minutes: int = 60
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    last_scan_id: str = ""
    cron_expr: str = ""         # 5-field cron expression (alternative to interval_minutes)
    webhook_url: str = ""       # POST findings to this URL on completion


class LiveAuditConfig(BaseModel):
    """Configuration for live audit engine."""
    enabled: bool = False
    checks: list[str] = ["sqli", "xss", "ssti", "cors", "open_redirect"]
    severity_threshold: str = "medium"
    rate_limit_per_host: float = 2.0


# ── Status model ────────────────────────────────────────────────────────────

# ── Report models ──────────────────────────────────────────────────────────

class ReportFormat(str, Enum):
    html = "html"
    pdf = "pdf"
    xml = "xml"
    json = "json"
    csv = "csv"
    markdown = "markdown"

class ReportBranding(BaseModel):
    logo_url: str = ""
    company_name: str = ""
    custom_css: str = ""
    footer_text: str = ""

class ReportRequest(BaseModel):
    scan_id: str | None = None
    format: ReportFormat = ReportFormat.html
    title: str = "Vulnerability Scan Report"
    target: str = ""
    include_passive: bool = True
    include_executive_summary: bool = False
    include_remediation_links: bool = False
    include_compliance: bool = False
    compliance_frameworks: list[str] = []
    branding: ReportBranding | None = None
    compare_scan_id: str | None = None


# ── TLS Client Certificate models ─────────────────────────────────────────

class TLSClientConfig(BaseModel):
    cert_path: str = ""
    key_path: str = ""
    ca_bundle: str = ""


# ── Status model ────────────────────────────────────────────────────────────

# ── GraphQL models ─────────────────────────────────────────────────────────

class GraphQLField(BaseModel):
    name: str
    type_name: str = ""
    args: list[dict[str, str]] = []
    description: str = ""

class GraphQLType(BaseModel):
    name: str
    kind: str = ""  # OBJECT, INPUT_OBJECT, ENUM, SCALAR, INTERFACE, UNION
    fields: list[GraphQLField] = []
    enum_values: list[str] = []
    description: str = ""

class GraphQLSchema(BaseModel):
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    types: list[GraphQLType] = []


# ── Search models ──────────────────────────────────────────────────────────

class SearchResult(BaseModel):
    type: str  # "flow", "finding", "passive"
    id: str
    title: str
    snippet: str = ""
    url: str = ""
    severity: str = ""
    timestamp: float = 0.0


# ── Collaboration models ──────────────────────────────────────────────────

class CollabClient(BaseModel):
    client_id: str
    username: str = "anonymous"
    connected_at: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    active_tab: str = ""

class CollabMessage(BaseModel):
    type: str  # "annotation", "scope_change", "finding_shared", "cursor", "chat"
    sender: str = ""
    data: dict[str, Any] = {}
    timestamp: float = Field(default_factory=time.time)


# ── Status model ────────────────────────────────────────────────────────

class ProxyStatus(BaseModel):
    proxy_running: bool = True
    proxy_port: int = 8080
    api_port: int = 8187
    flow_count: int = 0
    intercept_enabled: bool = False
    intercept_queue_size: int = 0
    response_intercept_enabled: bool = False
    active_intruder_jobs: int = 0
    active_scans: int = 0
    active_crawls: int = 0
    active_discoveries: int = 0
    scope_enabled: bool = False
    websocket_messages: int = 0
    passive_findings: int = 0
    extensions_loaded: int = 0
    match_replace_rules: int = 0
    session_rules: int = 0
    project_name: str = ""
    breakpoint_rules: int = 0
    scheduled_scans: int = 0
    collab_clients: int = 0
    csrf_tracking_enabled: bool = False
    macro_recording: bool = False
