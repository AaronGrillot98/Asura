"""API routes.

Backed by `app.repositories.get_repos()`. Existing routes preserve their
response shapes; new routes power the dashboard pages.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Response

from app.models.schemas import (
    ArsenalSummary,
    AttackPath,
    AuditLog,
    AuthorizedScope,
    DashboardSummary,
    Evidence,
    Finding,
    FindingStatusPatch,
    Project,
    ProjectCreate,
    ProjectUpdate,
    RegistryContractReport,
    Report,
    ReportRequest,
    ScanRequest,
    ScannerRun,
    ScopeRules,
    Target,
    TargetCreate,
)
from app.repositories import get_repos
from app.security.blocked_capabilities import as_dicts as blocked_capabilities_dicts
from app.security.scope_guard import decide_scope, validate_scan_scope
from app.services.demo_store import RISK_TREND
from app.services.pentest_brain import PentestBrain
from app.services.reporting import build_report, render_markdown
from app.services.runner import run_scanner
from app.services.scanner_registry import SCANNERS
from app.services.tool_registry import load_contract_report, query_arsenal

router = APIRouter()

severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_ALLOWED_EXECUTION_FILTERS = {"core_runner", "optional_pack", "reference", "blocked", "importer", "analyzer"}


def _confidence_int(value) -> int:
    """Findings carry either an int or a Confidence enum; normalize for sort."""
    if isinstance(value, int):
        return value
    return {"low": 25, "medium": 50, "high": 80, "confirmed": 95}.get(getattr(value, "value", str(value)), 0)


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "asura-api"}


@router.get("/scanners")
def scanners() -> list[dict[str, object]]:
    return [
        {
            "name": scanner.name,
            "description": scanner.description,
            "passive": scanner.passive_allowed,
            "active": scanner.active_allowed,
            "lab": scanner.lab_allowed,
            "output_format": scanner.output_format,
            "parser": scanner.parser,
        }
        for scanner in SCANNERS.values()
    ]


@router.get("/projects", response_model=list[Project])
def projects() -> list[Project]:
    return get_repos().projects.list()


@router.get("/projects/{project_id}", response_model=Project)
def project_detail(project_id: str) -> Project:
    project = get_repos().projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post("/projects", response_model=Project, status_code=201)
def create_project(request: ProjectCreate) -> Project:
    """Create a new project + record an implicit AuthorizedScope grant.

    `is_demo_data` is hard-set to False — only the seeded `demo` project
    carries the demo flag, ever.
    """
    repos = get_repos()
    # Soft uniqueness check on name within workspace.
    existing = repos.projects.find(
        lambda p: p.workspace_id == request.workspace_id and p.name.lower() == request.name.lower()
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"A project named '{request.name}' already exists in this workspace.",
        )
    now = datetime.now(timezone.utc)
    project_id = f"proj-{uuid4().hex[:10]}"
    project = Project(
        id=project_id,
        workspace_id=request.workspace_id,
        name=request.name,
        description=request.description,
        scope_rules=request.scope_rules,
        risk_score=request.risk_score,
        targets=[],
        created_at=now,
        is_demo_data=False,
    )
    repos.projects.add(project)
    # Auto-create an AuthorizedScope record so the audit trail starts now.
    scope = AuthorizedScope(
        id=f"scope-{uuid4().hex[:10]}",
        project_id=project_id,
        name=f"{request.name} initial authorization",
        scope_rules=request.scope_rules,
        explicit_authorization_grant=bool(request.grantor),
        grantor=request.grantor,
        granted_at=now if request.grantor else None,
        audit_note="Created with project.",
        is_demo_data=False,
    )
    repos.scopes.add(scope)
    # Audit the creation.
    repos.audit.add(
        AuditLog(
            id=f"audit-{uuid4().hex[:12]}",
            workspace_id=request.workspace_id,
            actor=request.grantor or "demo-user",
            action="project.create",
            event_type="project_lifecycle",
            target=project_id,
            result="allow",
            decision="allow",
            reason=None,
            reason_code="project_created",
            payload={"name": request.name, "scope": request.scope_rules.model_dump()},
            timestamp=now,
        )
    )
    return project


@router.patch("/projects/{project_id}", response_model=Project)
def update_project(project_id: str, request: ProjectUpdate) -> Project:
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.is_demo_data and (request.scope_rules is not None or request.name is not None):
        # The demo project is read-only for name/scope; users can still tweak
        # risk_score / description if they want.
        if request.scope_rules is not None or request.name is not None:
            raise HTTPException(
                status_code=400,
                detail="The seeded demo project is read-only. Create a new project instead.",
            )
    data = project.model_dump()
    for field in ("name", "description", "scope_rules", "risk_score"):
        value = getattr(request, field)
        if value is not None:
            data[field] = value.model_dump() if hasattr(value, "model_dump") else value
    updated = Project.model_validate(data)
    repos.projects.update(updated)
    repos.audit.add(
        AuditLog(
            id=f"audit-{uuid4().hex[:12]}",
            workspace_id=project.workspace_id,
            actor="demo-user",
            action="project.update",
            event_type="project_lifecycle",
            target=project_id,
            result="allow",
            decision="allow",
            reason_code="project_updated",
            payload={"fields": [f for f in ("name", "description", "scope_rules", "risk_score") if getattr(request, f) is not None]},
            timestamp=datetime.now(timezone.utc),
        )
    )
    return updated


@router.delete("/projects/{project_id}", status_code=204, response_class=Response)
def delete_project(project_id: str) -> Response:
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.is_demo_data or project_id == "demo":
        raise HTTPException(
            status_code=400,
            detail="The seeded demo project cannot be deleted. Create a new project to use Asura against your own systems.",
        )
    # Cascade delete: targets, scopes, scans, findings, evidence, attack paths,
    # remediations, schedules, and any reports.
    for repo, attr in (
        (repos.targets, "project_id"),
        (repos.scopes, "project_id"),
        (repos.runs, "project_id"),
        (repos.findings, "project_id"),
        (repos.attack_paths, "project_id"),
        (repos.remediations, "project_id"),
        (repos.schedules, "project_id"),
        (repos.reports, "project_id"),
        (repos.assets, "project_id"),
    ):
        for item in list(repo.list()):
            if getattr(item, attr, None) == project_id:
                repo.delete(item.id)
    # Evidence is attached to findings, which we just deleted — clean orphans.
    for ev in list(repos.evidence.list()):
        if ev.finding_id and not repos.findings.get(ev.finding_id):
            repos.evidence.delete(ev.id)
    repos.projects.delete(project_id)
    repos.audit.add(
        AuditLog(
            id=f"audit-{uuid4().hex[:12]}",
            workspace_id=project.workspace_id,
            actor="demo-user",
            action="project.delete",
            event_type="project_lifecycle",
            target=project_id,
            result="allow",
            decision="allow",
            reason_code="project_deleted",
            timestamp=datetime.now(timezone.utc),
        )
    )
    return Response(status_code=204)


@router.get("/projects/{project_id}/targets", response_model=list[Target])
def project_targets(project_id: str) -> list[Target]:
    return [t for t in get_repos().targets.list() if t.project_id == project_id]


@router.post("/projects/{project_id}/targets", response_model=Target, status_code=201)
def add_project_target(project_id: str, request: TargetCreate) -> Target:
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    target = Target(
        id=f"target-{uuid4().hex[:10]}",
        project_id=project_id,
        kind=request.kind,
        value=request.value.strip(),
        authorized=request.authorized,
        lab_mode_enabled=request.lab_mode_enabled,
        owned_internal=request.owned_internal,
        notes=request.notes,
        created_at=datetime.now(timezone.utc),
        is_demo_data=False,
    )
    repos.targets.add(target)
    return target


@router.delete("/projects/{project_id}/targets/{target_id}", status_code=204, response_class=Response)
def delete_project_target(project_id: str, target_id: str) -> Response:
    repos = get_repos()
    target = repos.targets.get(target_id)
    if target is None or target.project_id != project_id:
        raise HTTPException(status_code=404, detail="Target not found")
    repos.targets.delete(target_id)
    return Response(status_code=204)


@router.get("/projects/{project_id}/scopes", response_model=list[AuthorizedScope])
def project_scopes(project_id: str) -> list[AuthorizedScope]:
    return [s for s in get_repos().scopes.list() if s.project_id == project_id]


@router.get("/arsenal", response_model=ArsenalSummary)
def arsenal(
    search: str | None = None,
    pack: str | None = None,
    execution: str | None = None,
    risk: str | None = None,
    tag: str | None = None,
    lab_only: bool | None = None,
    installed: bool | None = None,
) -> ArsenalSummary:
    if execution and execution not in _ALLOWED_EXECUTION_FILTERS:
        raise HTTPException(status_code=400, detail="Invalid execution filter")
    if risk and risk not in {"low", "medium", "high", "restricted", "blocked"}:
        raise HTTPException(status_code=400, detail="Invalid risk filter")
    return query_arsenal(
        search=search,
        pack=pack,
        execution=execution,
        risk=risk,
        tag=tag,
        lab_only=lab_only,
        installed=installed,
    )


@router.get("/arsenal/contract", response_model=RegistryContractReport)
def arsenal_contract() -> RegistryContractReport:
    return load_contract_report()


@router.get("/safety/blocked")
def safety_blocked() -> dict[str, object]:
    return {
        "capabilities": blocked_capabilities_dicts(),
        "explanation": (
            "Asura refuses to ship these capabilities even with explicit authorization. "
            "They are out of scope for authorized security testing."
        ),
    }


@router.get("/audit", response_model=list[AuditLog])
def audit(limit: int = Query(default=50, ge=1, le=500)) -> list[AuditLog]:
    rows = sorted(get_repos().audit.list(), key=lambda r: r.timestamp, reverse=True)
    return rows[:limit]


@router.get("/dashboard/{project_id}", response_model=DashboardSummary)
def dashboard(project_id: str) -> DashboardSummary:
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    findings = [f for f in repos.findings.list() if f.project_id == project_id]
    sorted_findings = sorted(
        findings,
        key=lambda item: (-severity_rank[item.severity.value], -_confidence_int(item.confidence)),
    )
    runs = [r for r in repos.runs.list() if r.project_id == project_id]
    paths = [p for p in repos.attack_paths.list() if p.project_id == project_id]
    brain = PentestBrain(repos)
    agent_outputs = [brain.correlate_findings(project_id), brain._scope_summary(project_id)]  # noqa: SLF001
    # The seeded risk trend belongs to the demo project. Real user projects
    # start with an empty trend and gain history as scans accumulate (the
    # per-project trend computation lands in a later slice).
    risk_trend = RISK_TREND if project.is_demo_data else []
    return DashboardSummary(
        workspace=repos.workspaces.list()[0] if repos.workspaces.count() else None,
        project=project,
        assets=[a for a in repos.assets.list() if a.project_id == project_id],
        findings=findings,
        scanner_runs=runs,
        attack_paths=paths,
        agent_outputs=agent_outputs,
        risk_trend=risk_trend,
        fix_first=sorted_findings[:5],
        is_demo_data=any(f.is_demo_data for f in findings) or project.is_demo_data,
    )


@router.get("/findings", response_model=list[Finding])
def list_findings(
    project_id: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    tool: str | None = None,
    status: str | None = None,
    demo: bool | None = None,
) -> list[Finding]:
    findings = get_repos().findings.list()
    if project_id:
        findings = [f for f in findings if f.project_id == project_id]
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    if confidence:
        findings = [f for f in findings if getattr(f.confidence, "value", str(f.confidence)) == confidence]
    if tool:
        findings = [f for f in findings if f.scanner == tool]
    if status:
        findings = [f for f in findings if f.status == status]
    if demo is not None:
        findings = [f for f in findings if f.is_demo_data == demo]
    return findings


@router.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str) -> Finding:
    f = get_repos().findings.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@router.patch("/findings/{finding_id}", response_model=Finding)
def patch_finding(finding_id: str, patch: FindingStatusPatch) -> Finding:
    repos = get_repos()
    f = repos.findings.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = f.model_dump()
    if patch.status:
        data["status"] = patch.status
    if patch.false_positive_notes is not None:
        data["false_positive_notes"] = patch.false_positive_notes
    updated = Finding.model_validate(data)
    repos.findings.update(updated)
    return updated


@router.get("/attack-paths", response_model=list[AttackPath])
def list_attack_paths(project_id: str | None = None) -> list[AttackPath]:
    paths = get_repos().attack_paths.list()
    if project_id:
        paths = [p for p in paths if p.project_id == project_id]
    return paths


@router.get("/attack-paths/{attack_path_id}", response_model=AttackPath)
def get_attack_path(attack_path_id: str) -> AttackPath:
    p = get_repos().attack_paths.get(attack_path_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return p


@router.get("/scans", response_model=list[ScannerRun])
def list_scans(project_id: str | None = None) -> list[ScannerRun]:
    runs = get_repos().runs.list()
    if project_id:
        runs = [r for r in runs if r.project_id == project_id]
    return sorted(runs, key=lambda r: r.started_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)


@router.get("/scans/{scan_id}", response_model=ScannerRun)
def get_scan(scan_id: str) -> ScannerRun:
    run = get_repos().runs.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return run


@router.get("/evidence/{evidence_id}", response_model=Evidence)
def get_evidence(evidence_id: str) -> Evidence:
    ev = get_repos().evidence.get(evidence_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev


@router.post("/scans", response_model=list[ScannerRun])
def start_scan(request: ScanRequest) -> list[ScannerRun]:
    repos = get_repos()
    project = repos.projects.get(request.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    # Back-compat: legacy callers still expect a string reason raised as 400.
    scope_error = validate_scan_scope(project, request.target, request.mode, request.explicit_authorization)
    if scope_error:
        # Mirror the audit-logged decision for visibility.
        decide_scope(
            project=project,
            target=request.target,
            mode=request.mode,
            explicit_authorization=request.explicit_authorization,
            audit_repo=repos.audit,
        )
        raise HTTPException(status_code=400, detail=scope_error)
    if request.mode.value in {"active", "lab"} and not request.authorized_scope:
        raise HTTPException(status_code=400, detail="Authorized scope is required for active or lab mode")
    decide_scope(
        project=project,
        target=request.target,
        mode=request.mode,
        explicit_authorization=request.explicit_authorization,
        confirm_high_noise=request.confirm_high_noise,
        audit_repo=repos.audit,
    )
    runs: list[ScannerRun] = []
    for scanner in request.scanners:
        run = run_scanner(
            project_id=request.project_id,
            scanner=scanner,
            target=request.target,
            mode=request.mode.value,
            authorized=request.explicit_authorization,
            repos=repos,
        )
        repos.runs.add(run)
        runs.append(run)
    return runs


@router.post("/reports/{project_id}", response_model=Report)
def generate_report(project_id: str, request: ReportRequest) -> Report:
    repos = get_repos()
    if repos.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    report = build_report(repos=repos, project_id=project_id, kind=request.kind)
    repos.reports.add(report)
    return report


@router.get("/reports/{project_id}/json", response_model=Report)
def json_report(project_id: str) -> Report:
    repos = get_repos()
    if repos.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return build_report(repos=repos, project_id=project_id, kind="json")


@router.get("/reports/{project_id}/markdown")
def markdown_report(project_id: str) -> Response:
    repos = get_repos()
    if repos.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    report = build_report(repos=repos, project_id=project_id, kind="markdown")
    body = render_markdown(report)
    return Response(
        body,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=asura-{uuid4()}.md"},
    )
