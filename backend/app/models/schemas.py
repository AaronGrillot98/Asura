from datetime import datetime
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


class FindingStatusPatch(BaseModel):
    status: Literal["new", "triaged", "accepted", "resolved", "false_positive", "open", "fixed", "risk_accepted"] | None = None
    false_positive_notes: str | None = None


class ReportRequest(BaseModel):
    kind: Literal["markdown", "json"] = "markdown"
