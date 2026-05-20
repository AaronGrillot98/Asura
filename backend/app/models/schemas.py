from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanMode(str, Enum):
    passive = "passive"
    active = "active"
    lab = "lab"


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    confirmed = "confirmed"


class FindingStatus(str, Enum):
    open = "open"
    accepted = "accepted"
    false_positive = "false_positive"
    fixed = "fixed"
    risk_accepted = "risk_accepted"


class AssetType(str, Enum):
    repo = "repo"
    domain = "domain"
    url = "url"
    ip = "ip"
    cidr = "cidr"
    container = "container"
    api_spec = "api_spec"
    host = "host"
    web_app = "web_app"
    dependency = "dependency"


class EvidenceType(str, Enum):
    scanner_output = "scanner_output"
    code_snippet = "code_snippet"
    http_response = "http_response"
    log = "log"
    config = "config"
    screenshot = "screenshot"
    manual_note = "manual_note"


class ScopeRules(BaseModel):
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    repos: list[str] = Field(default_factory=list)
    containers: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)
    allow_active: bool = False
    allow_lab: bool = False
    max_requests_per_second: int = Field(default=2, ge=1, le=50)
    timeout_seconds: int = Field(default=900, ge=30, le=7200)


class Workspace(BaseModel):
    id: str
    name: str
    created_at: datetime


class Role(str, Enum):
    """Role within a Workspace. Owners can do everything including deleting
    the workspace; admins manage members + tokens; members can read/write
    project data; viewers are read-only."""
    owner = "owner"
    admin = "admin"
    member = "member"
    viewer = "viewer"


class User(BaseModel):
    """Account record. Password storage is delegated to security.auth; the
    `password_hash` field carries an opaque PBKDF2 digest, never plaintext."""
    id: str
    email: str
    display_name: str
    password_hash: str | None = None     # null when the user signed up via SSO
    sso_subject: str | None = None       # opaque issuer-sub identifier when SSO
    sso_issuer: str | None = None        # e.g. https://accounts.google.com
    is_active: bool = True
    created_at: datetime
    last_login_at: datetime | None = None


class UserPublic(BaseModel):
    """User record minus secrets — what /api/auth/me and member listings return."""
    id: str
    email: str
    display_name: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class Membership(BaseModel):
    """Join row between a User and a Workspace, carrying their role."""
    id: str
    workspace_id: str
    user_id: str
    role: Role
    created_at: datetime


class WorkspaceMember(BaseModel):
    """Workspace membership inflated for API responses (user + role)."""
    user: UserPublic
    role: Role
    joined_at: datetime


class ApiToken(BaseModel):
    """Long-lived service token for CI/automation. The plaintext token is
    only returned once at creation time; afterwards we only retain the
    `token_hash` and the last-4 prefix for UI display."""
    id: str
    user_id: str
    workspace_id: str
    name: str
    token_hash: str          # PBKDF2 of the plaintext token
    prefix: str              # first 8 chars of the token for visual matching
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiTokenPublic(BaseModel):
    """Token metadata for listings (never includes plaintext or hash)."""
    id: str
    name: str
    workspace_id: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiTokenCreated(BaseModel):
    """Returned ONCE when a token is minted — `token` is plaintext, store it now."""
    token: str
    record: ApiTokenPublic


class RegisterRequest(BaseModel):
    email: str
    password: str
    display_name: str
    workspace_name: str | None = None    # used on first-user bootstrap


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int                      # seconds
    user: UserPublic


class InviteRequest(BaseModel):
    email: str
    role: Role = Role.member


class TokenCreateRequest(BaseModel):
    name: str
    workspace_id: str
    expires_in_days: int | None = None   # None == no expiry


class Project(BaseModel):
    id: str
    workspace_id: str = "workspace-demo"
    name: str
    description: str
    scope_rules: ScopeRules = Field(default_factory=ScopeRules)
    risk_score: int = Field(ge=0, le=100)
    targets: list[str]
    created_at: datetime
    is_demo_data: bool = False


class Target(BaseModel):
    """A distinct, addressable target (host / repo / url / container)."""

    id: str
    project_id: str
    kind: Literal["host", "repo", "url", "domain", "ip", "cidr", "container", "api_spec"]
    value: str
    authorized: bool = False
    lab_mode_enabled: bool = False
    owned_internal: bool = False
    notes: str | None = None
    created_at: datetime | None = None
    is_demo_data: bool = False


class AuthorizedScope(BaseModel):
    """An explicit grant of authorization tying scope rules to a project + grantor."""

    id: str
    project_id: str
    name: str
    scope_rules: ScopeRules
    explicit_authorization_grant: bool = False
    grantor: str | None = None
    granted_at: datetime | None = None
    revoked_at: datetime | None = None
    audit_note: str | None = None
    is_demo_data: bool = False


class Asset(BaseModel):
    id: str
    project_id: str
    kind: Literal["host", "repo", "container", "web_app", "dependency", "domain", "url", "ip", "cidr", "api_spec"]
    type: AssetType | None = None
    name: str
    address: str
    value: str | None = None
    tags: list[str] = Field(default_factory=list)
    exposure: Literal["public", "internal", "private"]
    criticality: Literal["critical", "high", "medium", "low"]
    created_at: datetime | None = None


class Evidence(BaseModel):
    id: str
    finding_id: str
    evidence_type: EvidenceType = EvidenceType.scanner_output
    scanner: str
    raw: dict[str, Any]
    summary: str
    content: str | None = None
    source_tool: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    captured_at: datetime
    created_at: datetime | None = None
    raw_output_path: str | None = None
    content_hash: str | None = None
    command_metadata: dict[str, Any] | None = None
    is_demo_data: bool = False


class Finding(BaseModel):
    id: str
    project_id: str
    workspace_id: str | None = None
    scan_id: str | None = None
    asset_id: str
    target_id: str | None = None
    scanner: str
    title: str
    category: str = "security"
    severity: Severity
    confidence: int | Confidence = Field(default=Confidence.medium)
    status: Literal["new", "triaged", "accepted", "resolved", "false_positive", "open", "fixed", "risk_accepted"] = "open"
    affected_asset: str | None = None
    affected_component: str | None = None
    description: str | None = None
    impact: str
    remediation: str | None = None
    reproduction: str
    false_positive_reasoning: str
    recommendation: str
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    owasp_mapping: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    resolved_at: datetime | None = None
    related_finding_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    fingerprint_hash: str | None = None
    attack_tags: list[str] = Field(default_factory=list)
    exploitability_assessment: str | None = None
    false_positive_notes: str | None = None
    is_demo_data: bool = False


class Scan(BaseModel):
    id: str
    project_id: str
    scan_type: str
    mode: ScanMode
    status: Literal["queued", "running", "completed", "failed", "blocked"]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_by: str = "demo-user"


class ScannerRun(BaseModel):
    id: str
    project_id: str
    scan_id: str | None = None
    scanner: str
    tool_name: str | None = None
    command_summary: str | None = None
    mode: ScanMode
    status: Literal["queued", "running", "completed", "failed", "blocked"]
    target: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    completed_at: datetime | None = None
    raw_output_path: str | None = None
    error_log: str | None = None
    message: str
    args: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    findings_created: int = 0
    is_demo_data: bool = False


AttackPathNodeKind = Literal[
    "asset",
    "finding",
    "evidence",
    "identity",
    "service",
    "package",
    "repository",
    "container",
    "cloud_resource",
    "host",
    "url",
]

AttackPathEdgeKind = Literal[
    "enables",
    "increases_impact_of",
    "depends_on",
    "validates",
    "related_to",
    "mitigated_by",
]


class AttackPathNode(BaseModel):
    id: str
    label: str
    kind: str  # AttackPathNodeKind values, kept str for back-compat with existing seed
    severity: Severity | None = None
    ref_id: str | None = None  # id of the underlying finding/evidence/asset
    metadata: dict[str, Any] | None = None


class AttackPathEdge(BaseModel):
    source: str
    target: str
    label: str
    kind: str | None = None  # AttackPathEdgeKind values


class AttackPath(BaseModel):
    id: str
    project_id: str
    title: str
    summary: str
    narrative: str | None = None
    confidence: Confidence = Confidence.medium
    risk_score: int
    severity: Severity | None = None
    status: Literal["hypothesis", "likely", "confirmed", "mitigated"] = "hypothesis"
    finding_ids: list[str]
    evidence_refs: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]
    remediation_order: list[str]
    remediation_priority: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    safe_validation_needed: list[str] = Field(default_factory=list)
    remediation_summary: str | None = None
    created_at: datetime | None = None
    is_demo_data: bool = False


class RemediationTask(BaseModel):
    id: str
    project_id: str
    finding_ids: list[str] = Field(default_factory=list)
    priority: Literal["critical", "high", "medium", "low"] = "medium"
    title: str
    description: str
    owner: str | None = None
    due_date: datetime | None = None
    status: Literal["open", "in_progress", "done", "wont_fix"] = "open"
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    is_demo_data: bool = False


class AuditLog(BaseModel):
    id: str
    workspace_id: str | None = None
    actor: str
    action: str
    event_type: str | None = None
    target: str
    result: str
    decision: Literal["allow", "block", "info"] | None = None
    reason: str | None = None
    reason_code: str | None = None
    payload: dict[str, Any] | None = None
    timestamp: datetime
    created_at: datetime | None = None


class AgentOutput(BaseModel):
    agent: str
    summary: str
    confidence: Confidence
    supporting_finding_ids: list[str] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    attack_path: dict[str, Any] | None = None
    recommended_next_steps: list[str] = Field(default_factory=list)
    limitations: str | None = None


# ---------------------------------------------------------------------------
# LLM-assisted triage — see services/llm.py and pentest_brain.triage_findings.
# Each item is grounded in real evidence ids; the citation guard discards
# anything claiming to cite ids the brain never saw.
# ---------------------------------------------------------------------------

class TriageCluster(BaseModel):
    """A group of related findings that should be triaged together."""
    id: str
    title: str
    summary: str
    reasoning: str
    finding_ids: list[str] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    severity: Severity = Severity.medium
    confidence: Confidence = Confidence.medium
    fix_recommendation: str | None = None


class FalsePositiveCandidate(BaseModel):
    """A finding the brain considers likely-noise (still requires human sign-off)."""
    finding_id: str
    reasoning: str
    confidence: Confidence = Confidence.medium
    cited_evidence_ids: list[str] = Field(default_factory=list)


class TriagePriorityItem(BaseModel):
    """A finding placed at a specific rank in the recommended fix order."""
    finding_id: str
    rank: int
    reasoning: str
    cited_evidence_ids: list[str] = Field(default_factory=list)


class TriageReport(BaseModel):
    """The whole triage output for a project.

    `engine` is `llm` when an LLMClient produced the response, `deterministic`
    when PentestBrain produced it from rules alone. `claims_dropped` reports
    how many LLM items the citation guard rejected — surfaced to the UI as a
    transparency signal.
    """
    project_id: str
    engine: Literal["deterministic", "llm"] = "deterministic"
    model: str | None = None
    summary: str
    clusters: list[TriageCluster] = Field(default_factory=list)
    false_positive_candidates: list[FalsePositiveCandidate] = Field(default_factory=list)
    priority_order: list[TriagePriorityItem] = Field(default_factory=list)
    findings_considered: int = 0
    claims_dropped: int = 0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Report(BaseModel):
    id: str
    project_id: str
    report_type: Literal["executive", "technical", "json", "markdown"]
    kind: Literal["markdown", "json", "pdf"] | None = None
    title: str
    generated_at: datetime
    sections: dict[str, Any]
    scope_statement: str | None = None
    authorization_statement: str | None = None
    safety_statement: str | None = None
    content_ref: str | None = None
    content_hash: str | None = None
    pdf_status: Literal["not_generated", "queued", "ready"] = "not_generated"
    is_demo_data: bool = False


class ScanSchedule(BaseModel):
    id: str
    project_id: str
    name: str
    cron: str
    scanners: list[str] = Field(default_factory=list)
    enabled: bool = False
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime | None = None
    is_demo_data: bool = False


class ScopeDecision(BaseModel):
    """Structured decision returned by the scope guard."""

    allowed: bool
    reason: str | None = None
    reason_code: str
    audit_log_id: str | None = None
    requires_explicit_high_noise_confirm: bool = False
    target: str | None = None
    mode: ScanMode | None = None


class DashboardSummary(BaseModel):
    workspace: Workspace | None = None
    project: Project
    assets: list[Asset]
    findings: list[Finding]
    scanner_runs: list[ScannerRun]
    attack_paths: list[AttackPath]
    agent_outputs: list[AgentOutput] = Field(default_factory=list)
    risk_trend: list[dict[str, Any]]
    fix_first: list[Finding]
    is_demo_data: bool = False


class ToolCommand(BaseModel):
    mode: ScanMode
    command: str


class ToolDefinition(BaseModel):
    id: str
    name: str
    pack: str
    category: str
    execution: Literal["core_runner", "optional_pack", "reference", "blocked", "importer", "analyzer"]
    modes: list[ScanMode] = Field(default_factory=list)
    install_status: Literal["bundled", "available", "not_installed", "external", "blocked"]
    integration_status: Literal["runner", "parser", "planned", "reference", "blocked", "importer", "analyzer"]
    license: str
    official_url: str
    executable: str | None = None
    installed: bool = False
    install_hint: str | None = None
    input_types: list[str] = Field(default_factory=list)
    output_formats: list[str] = Field(default_factory=list)
    parser: str | None = None
    safe_default: bool = False
    requires_authorized_scope: bool = False
    requires_lab_mode: bool = False
    docker_available: bool = False
    docker_image: str | None = None
    target_kind: Literal["url", "host", "filesystem", "image", "cluster", "mixed"] = "url"
    supported_os: list[str] = Field(default_factory=list)
    commands: list[ToolCommand] = Field(default_factory=list)
    recommended_use: str
    risk_warning: str | None = None
    risk_level: Literal["low", "medium", "high", "restricted", "blocked"] = "low"
    tags: list[str] = Field(default_factory=list)


class ToolPackSummary(BaseModel):
    name: str
    total: int
    core_runners: int
    optional: int
    reference: int
    blocked: int
    installed: int


class RegistryContractReport(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    registry_hash: str
    contract_version: str
    tool_count: int
    core_runner_count: int
    optional_count: int
    reference_count: int
    executable_count: int
    blocked_count: int


class ArsenalSummary(BaseModel):
    tools: list[ToolDefinition]
    packs: list[str]
    pack_summaries: list[ToolPackSummary]
    blocked_policy: list[str]
    blocked_capabilities: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    project_id: str
    target: str
    scanners: list[str]
    mode: ScanMode = ScanMode.passive
    authorized_scope: str | None = None
    explicit_authorization: bool = False
    confirm_high_noise: bool = False
    # IDs of NucleiTemplate records uploaded via /api/templates. Only applied
    # to scanners that natively accept template files (currently: nuclei).
    template_ids: list[str] = Field(default_factory=list)
    # Filesystem path to a wordlist for fuzzers (ffuf, gobuster, dirsearch).
    # Substituted into command templates that contain `{{wordlist}}`.
    wordlist: str | None = None
    # Cloud provider for prowler / scoutsuite (e.g. "aws", "azure", "gcp").
    provider: str | None = None
    # Optional AuthProfile id. Applied to scanners that accept custom headers
    # (currently nuclei + httpx). The runner injects the right `-H` flags;
    # secrets never travel through the API back to the client.
    auth_profile_id: str | None = None


class FindingStatusPatch(BaseModel):
    status: Literal["new", "triaged", "accepted", "resolved", "false_positive", "open", "fixed", "risk_accepted"] | None = None
    false_positive_notes: str | None = None


class ReportRequest(BaseModel):
    kind: Literal["markdown", "json"] = "markdown"


# ---------------------------------------------------------------------------
# Jobs (async scans + pipelines)
# ---------------------------------------------------------------------------

JobStatus = Literal["queued", "running", "completed", "failed", "blocked", "partial"]


class ScanJob(BaseModel):
    """Background job covering a single scan submission or a multi-stage pipeline.

    Persisted alongside the actual ScannerRun records so the UI can poll
    one endpoint for overall progress while individual runs accumulate on
    /scans.
    """

    id: str
    project_id: str
    kind: Literal["scan", "pipeline"] = "scan"
    pipeline_id: str | None = None
    status: JobStatus = "queued"
    scan_request: dict[str, Any] | None = None
    run_ids: list[str] = Field(default_factory=list)
    findings_created: int = 0
    error: str | None = None
    progress_text: str | None = None
    progress_percent: int = 0
    backend: Literal["inline_thread", "rq"] = "inline_thread"
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    is_demo_data: bool = False


class PipelineStage(BaseModel):
    """A single stage inside a recon / audit pipeline."""

    name: str
    scanner: str
    mode: ScanMode = ScanMode.passive
    input_source: Literal["target", "previous_assets"] = "target"
    max_followups: int = Field(default=20, ge=1, le=200)
    description: str | None = None


class Pipeline(BaseModel):
    """A named chain of scanner stages."""

    id: str
    name: str
    description: str
    stages: list[PipelineStage]
    requires_authorized_scope: bool = False
    risk_level: Literal["low", "medium", "high"] = "low"
    tags: list[str] = Field(default_factory=list)


class PipelineRunRequest(BaseModel):
    project_id: str
    pipeline_id: str
    target: str
    authorized_scope: str | None = None
    explicit_authorization: bool = False
    confirm_high_noise: bool = False


class AsyncScanResponse(BaseModel):
    job_id: str
    status: JobStatus
    backend: Literal["inline_thread", "rq"]
    poll_url: str
    message: str | None = None


# ---------------------------------------------------------------------------
# Auth profiles — credentials injected into scanner runs via -H flags.
# Secrets never leave the backend; the API only exposes a 4-char preview.
# ---------------------------------------------------------------------------

AuthType = Literal["bearer", "basic", "header", "cookie"]


class AuthProfile(BaseModel):
    """Stored auth profile.

    The actual credential values (token / password / header value) are
    *never* returned by API responses. The on-disk form is Fernet-encrypted
    and only decrypted by the runner at scan time. `credential_preview` is
    the last 4 chars so the UI can confirm "which one did I save?".
    """

    id: str
    name: str
    workspace_id: str = "workspace-demo"
    auth_type: AuthType
    target_match: str | None = None
    description: str | None = None
    credential_preview: str
    created_at: datetime
    is_demo_data: bool = False


class AuthProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    auth_type: AuthType
    target_match: str | None = Field(default=None, max_length=400)
    description: str | None = Field(default=None, max_length=400)
    # Per-type secret fields. Validated server-side.
    token: str | None = None        # bearer
    username: str | None = None     # basic
    password: str | None = None     # basic
    header_name: str | None = None  # header
    header_value: str | None = None # header
    cookie: str | None = None       # cookie


# ---------------------------------------------------------------------------
# LLM triage settings (Fernet-encrypted file storage, never returned raw)
# ---------------------------------------------------------------------------

class LLMSettings(BaseModel):
    """Public view of the configured LLM client. Never carries the raw
    API key — only a trailing-4-char preview."""
    enabled: bool = False
    provider: Literal["anthropic"] = "anthropic"
    model: str = "claude-haiku-4-5-20251001"
    api_key_preview: str | None = None
    api_key_configured: bool = False
    updated_at: datetime | None = None


class LLMSettingsUpdate(BaseModel):
    """Request body for PUT /api/settings/llm. The api_key field is
    write-only; the API never echoes it back."""
    enabled: bool = False
    model: str = "claude-haiku-4-5-20251001"
    # When None, the existing stored key is preserved (so users can toggle
    # enabled / change model without re-pasting the key).
    api_key: str | None = None


# ---------------------------------------------------------------------------
# Custom Nuclei templates
# ---------------------------------------------------------------------------


class NucleiTemplate(BaseModel):
    """User-uploaded Nuclei template.

    The template content lives on disk under
    `templates/<workspace_id>/<template_id>__<safe_filename>.yaml`; this
    record is the index entry the API returns.
    """

    id: str
    workspace_id: str = "workspace-demo"
    filename: str
    display_name: str
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    template_id: str | None = None  # the `id:` field inside the template
    severity: str | None = None  # the `info.severity` value inside the template
    info_name: str | None = None  # `info.name`
    size_bytes: int
    content_hash: str
    uploaded_at: datetime
    is_demo_data: bool = False


class ProjectCreate(BaseModel):
    """Request body for `POST /api/projects`.

    `scope_rules` is the source of truth for what the scope guard will
    allow. `grantor` is captured into an auto-created `AuthorizedScope`
    so the project carries an audit trail from day one.
    """

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    workspace_id: str = "workspace-demo"
    scope_rules: ScopeRules = Field(default_factory=ScopeRules)
    grantor: str | None = None
    risk_score: int = Field(default=0, ge=0, le=100)


class ProjectUpdate(BaseModel):
    """Request body for `PATCH /api/projects/{id}`. All fields optional."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    scope_rules: ScopeRules | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)


class TargetCreate(BaseModel):
    kind: Literal["host", "repo", "url", "domain", "ip", "cidr", "container", "api_spec"]
    value: str = Field(min_length=1, max_length=2048)
    authorized: bool = False
    lab_mode_enabled: bool = False
    owned_internal: bool = False
    notes: str | None = None


# ---------------------------------------------------------------------------
# HAR (HTTP Archive) traffic ingestion — Burp + mitmproxy + DevTools all
# export this format. See services/har_import.py.
# ---------------------------------------------------------------------------


class HarEndpoint(BaseModel):
    """One unique (method, host, path) seen in the captured traffic."""
    method: str
    host: str
    path: str
    sample_url: str
    status_codes: list[int] = Field(default_factory=list)
    param_names: list[str] = Field(default_factory=list)
    seen_count: int = 1


class SarifImportSummary(BaseModel):
    """Result of `POST /api/projects/{id}/imports/sarif`.

    Counts at the top so CI consumers can fail/succeed at a glance, then
    the per-run driver list. `skipped` collects human-readable reasons
    (unparseable result, malformed level, etc.) — never raised as an
    error so a partial batch still imports cleanly.
    """
    project_id: str
    runs_processed: int
    results_processed: int
    findings_created: int
    findings_updated: int
    tool_drivers: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)


class HarImportSummary(BaseModel):
    """Result of `POST /api/projects/{id}/imports/har`.

    Counts at the top, then the structured catalog. `new_targets`
    contains the Target rows the importer actually created (existing
    hosts are skipped, not duplicated)."""
    project_id: str
    entries_processed: int
    hosts: list[str] = Field(default_factory=list)
    endpoints: list[HarEndpoint] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    auth_required_paths: list[str] = Field(default_factory=list)
    status_buckets: dict[str, int] = Field(default_factory=dict)
    skipped: list[str] = Field(default_factory=list)
    new_targets: list[Target] = Field(default_factory=list)
    respect_scope: bool = False
