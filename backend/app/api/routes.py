"""API routes.

Backed by `app.repositories.get_repos()`. Existing routes preserve their
response shapes; new routes power the dashboard pages.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel

from app.models.schemas import (
    ArsenalSummary,
    AsyncScanResponse,
    AttackPath,
    AuditLog,
    AuthProfile,
    AuthProfileCreate,
    AuthorizedScope,
    DashboardSummary,
    Evidence,
    Finding,
    FindingStatusPatch,
    NucleiTemplate,
    Pipeline,
    PipelineRunRequest,
    Project,
    ProjectCreate,
    ProjectUpdate,
    RegistryContractReport,
    Report,
    ReportRequest,
    HarImportSummary,
    LLMSettings,
    LLMSettingsUpdate,
    SarifImportSummary,
    ScanJob,
    ScanRequest,
    ScannerRun,
    ScopeRules,
    Target,
    TargetCreate,
    TriageReport,
)
from app.repositories import get_repos
from app.services.job_queue import JobQueue
from app.services.job_runner import (
    find_pipeline_or_fail,
    run_pipeline_job,
    run_scan_request_job,
)
from app.services.pipelines import list_pipelines
from app.services.templates_service import TemplateValidationError, TemplatesService
from app.services import zap_auth
from app.services.auth_profile_service import AuthProfileService
from app.services.har_import import HarParseError, ingest_har, parse_har_bytes
from app.services.sarif import SarifParseError, findings_to_sarif, sarif_to_findings
from app.services.fingerprint import finding_fingerprint
from app.services.llm_settings_service import LLMSettingsService
from app.security.blocked_capabilities import as_dicts as blocked_capabilities_dicts
from app.security.scope_guard import decide_scope, validate_scan_scope
from app.services.demo_store import RISK_TREND
from app.services.pentest_brain import PentestBrain
from app.services.reporting import build_report, build_signed_bundle, render_markdown, render_pdf
from app.services.merkle import verify_inclusion
from app.services.signing import public_key_pem, signing_key_id
from app.services.runner import run_scanner
from app.services.scanner_registry import CORE_SCANNERS, SCANNERS
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
        for scanner in CORE_SCANNERS.values()
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


@router.get("/projects/{project_id}/findings.sarif")
def export_findings_sarif(project_id: str) -> Response:
    """Export project findings as a SARIF 2.1.0 document.

    Single GET, no auth gymnastics — pipe straight into GitHub Code Scanning,
    SonarQube, DefectDojo, or any other SARIF-aware sink.

        curl http://asura/api/projects/<id>/findings.sarif > asura.sarif
    """
    import json
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    findings = [f for f in repos.findings.list() if f.project_id == project_id]
    doc = findings_to_sarif(findings)
    return Response(
        content=json.dumps(doc, indent=2, default=str),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{project_id}.sarif"'},
    )


@router.post("/projects/{project_id}/imports/sarif", response_model=SarifImportSummary)
async def import_sarif(
    project_id: str,
    request: Request,
    file: UploadFile | None = File(default=None),
) -> SarifImportSummary:
    """Ingest a SARIF 2.1.0 document.

    Accepts either a JSON body (`Content-Type: application/sarif+json` or
    `application/json`) or a multipart upload. Findings are deduped by the
    standard ASURA fingerprint so re-uploading the same CI artifact bumps
    `last_seen` instead of creating duplicates.

        # one-shot CI ingest
        curl -X POST http://asura/api/projects/<id>/imports/sarif \\
             -H 'Content-Type: application/sarif+json' \\
             --data-binary @semgrep.sarif
    """
    import json
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if file is not None:
        blob = await file.read()
    else:
        blob = await request.body()
    if not blob:
        raise HTTPException(status_code=400, detail="Empty SARIF body.")
    if len(blob) > 32 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="SARIF upload exceeds 32 MiB.")
    try:
        doc = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    try:
        parsed = sarif_to_findings(doc, project_id=project_id)
    except SarifParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Index by fingerprint, computing on the fly when an existing record
    # doesn't carry one (e.g. seeded demo findings). Without this, a round
    # trip would duplicate the demo set instead of bumping last_seen.
    existing_by_fp: dict[str, "Finding"] = {}
    for f in repos.findings.list():
        if f.project_id != project_id:
            continue
        fp = f.fingerprint_hash or finding_fingerprint(f)
        existing_by_fp[fp] = f

    created = 0
    updated = 0
    drivers: set[str] = set()
    for finding in parsed:
        drivers.add(finding.scanner)
        fp = finding.fingerprint_hash or finding_fingerprint(finding)
        finding.fingerprint_hash = fp
        if fp in existing_by_fp:
            existing = existing_by_fp[fp]
            existing.last_seen = datetime.now(timezone.utc)
            repos.findings.update(existing)
            updated += 1
            continue
        # Back-fill evidence.finding_id now that the Finding has its real id.
        for ev in finding.evidence:
            ev.finding_id = finding.id
        repos.findings.add(finding)
        for ev in finding.evidence:
            repos.evidence.add(ev)
        created += 1

    return SarifImportSummary(
        project_id=project_id,
        runs_processed=len(doc.get("runs") or []),
        results_processed=len(parsed),
        findings_created=created,
        findings_updated=updated,
        tool_drivers=sorted(drivers),
        skipped=[],
    )


@router.post("/projects/{project_id}/imports/har", response_model=HarImportSummary)
async def import_har(
    project_id: str,
    file: UploadFile = File(...),
    respect_scope: bool = Query(default=False, description="Skip entries whose host isn't in the project's allowed_domains."),
) -> HarImportSummary:
    """Ingest a HAR (HTTP Archive) capture exported from Burp, mitmproxy,
    Caido, or DevTools. Creates one Target per unique host, returns the
    full endpoint catalog plus a status-code histogram, JS file
    inventory, and an auth-required path list.
    """
    repos = get_repos()
    project = repos.projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    blob = await file.read()
    if not blob:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(blob) > 64 * 1024 * 1024:
        # 64 MiB cap. HAR files for moderate browsing sessions are
        # typically <10 MiB; anything bigger is almost always a giant
        # response body that's not useful here.
        raise HTTPException(status_code=413, detail="HAR upload exceeds 64 MiB.")
    try:
        doc = parse_har_bytes(blob)
    except HarParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ingest_har(repos=repos, project=project, har_doc=doc, respect_scope=respect_scope)


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


# ---------------------------------------------------------------------------
# Async jobs (background scans + pipelines)
# ---------------------------------------------------------------------------


@router.post("/scans/async", response_model=AsyncScanResponse, status_code=202)
def start_scan_async(request: ScanRequest) -> AsyncScanResponse:
    """Submit a scan for background execution. Returns immediately with a job id.

    Poll `GET /api/jobs/{job_id}` for status. The job exits with status
    `completed` (work done), `failed` (any scanner errored or threw),
    `blocked` (scope guard rejected), or `partial` (some succeeded, some
    didn't).
    """
    repos = get_repos()
    if repos.projects.get(request.project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    queue = JobQueue(repos)

    # Capture the request data so the worker thread has a stable snapshot.
    payload = request.model_dump(mode="json")

    def callback(job: ScanJob) -> None:
        run_scan_request_job(repos, job, ScanRequest.model_validate(payload))

    job = queue.submit(
        project_id=request.project_id,
        kind="scan",
        scan_request=payload,
        fn=callback,
    )
    return AsyncScanResponse(
        job_id=job.id,
        status=job.status,
        backend=job.backend,
        poll_url=f"/api/jobs/{job.id}",
        message=f"Submitted {len(request.scanners)} scanner(s) for background execution.",
    )


@router.get("/jobs", response_model=list[ScanJob])
def list_jobs(
    project_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[ScanJob]:
    rows = get_repos().jobs.list()
    if project_id:
        rows = [j for j in rows if j.project_id == project_id]
    rows = sorted(rows, key=lambda j: j.created_at, reverse=True)
    return rows[:limit]


@router.get("/jobs/{job_id}", response_model=ScanJob)
def get_job(job_id: str) -> ScanJob:
    job = get_repos().jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ---------------------------------------------------------------------------
# Pipelines (named chains of scanner stages)
# ---------------------------------------------------------------------------


@router.get("/pipelines", response_model=list[Pipeline])
def get_pipelines() -> list[Pipeline]:
    return list_pipelines()


@router.post("/pipelines/run", response_model=AsyncScanResponse, status_code=202)
def start_pipeline(request: PipelineRunRequest) -> AsyncScanResponse:
    repos = get_repos()
    if repos.projects.get(request.project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        pipeline = find_pipeline_or_fail(request.pipeline_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    queue = JobQueue(repos)

    def callback(job: ScanJob) -> None:
        run_pipeline_job(
            repos,
            job,
            pipeline,
            request.target,
            request.explicit_authorization,
            request.confirm_high_noise,
        )

    job = queue.submit(
        project_id=request.project_id,
        kind="pipeline",
        pipeline_id=request.pipeline_id,
        scan_request=request.model_dump(mode="json"),
        fn=callback,
    )
    return AsyncScanResponse(
        job_id=job.id,
        status=job.status,
        backend=job.backend,
        poll_url=f"/api/jobs/{job.id}",
        message=f"Pipeline '{pipeline.name}' submitted ({len(pipeline.stages)} stages).",
    )


@router.get("/search")
def search_all(q: str = "", limit: int = Query(default=30, ge=1, le=100)) -> dict[str, object]:
    """Aggregate search across projects, findings, tools, runs, attack paths.

    Returns a flat results list with a `kind` discriminator so the UI can
    group on render. Empty query returns no results — keeps the palette
    snappy and avoids dumping every record on first focus.
    """
    needle = q.strip().lower()
    if not needle:
        return {"query": q, "results": []}
    repos = get_repos()
    results: list[dict[str, object]] = []

    for project in repos.projects.list():
        if needle in project.name.lower() or needle in (project.description or "").lower():
            results.append({
                "kind": "project",
                "id": project.id,
                "title": project.name,
                "subtitle": project.description[:140],
                "href": f"/projects/{project.id}",
                "badge": "demo" if project.is_demo_data else None,
            })

    for finding in repos.findings.list():
        haystack = " ".join([
            finding.title or "",
            finding.scanner or "",
            finding.affected_asset or "",
            finding.affected_component or "",
            finding.category or "",
            " ".join(finding.cwe or []),
            " ".join(finding.cve or []),
        ]).lower()
        if needle in haystack:
            results.append({
                "kind": "finding",
                "id": finding.id,
                "title": finding.title,
                "subtitle": f"{finding.scanner} · {finding.affected_asset or finding.asset_id}",
                "href": f"/findings/{finding.id}",
                "badge": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            })

    # Tools come from the static registry — load once.
    try:
        arsenal = load_arsenal_for_search()
        for tool in arsenal:
            haystack = " ".join([
                tool["id"], tool["name"], tool["category"], tool["pack"],
                " ".join(tool["tags"] or []),
                tool["recommended_use"] or "",
            ]).lower()
            if needle in haystack:
                results.append({
                    "kind": "tool",
                    "id": tool["id"],
                    "title": tool["name"],
                    "subtitle": f"{tool['pack']} · {tool['category']}",
                    "href": f"/arsenal#{tool['id']}",
                    "badge": tool["execution"],
                })
    except Exception:  # pragma: no cover — registry should always load
        pass

    for run in repos.runs.list():
        haystack = f"{run.scanner} {run.target} {run.status}".lower()
        if needle in haystack:
            results.append({
                "kind": "scan",
                "id": run.id,
                "title": f"{run.scanner} → {run.target}",
                "subtitle": run.message[:120],
                "href": f"/scans/{run.id}",
                "badge": run.status,
            })

    for path in repos.attack_paths.list():
        haystack = f"{path.title} {path.summary} {path.narrative or ''}".lower()
        if needle in haystack:
            results.append({
                "kind": "attack_path",
                "id": path.id,
                "title": path.title,
                "subtitle": path.summary[:140],
                "href": f"/attack-paths/{path.id}",
                "badge": path.status,
            })

    return {"query": q, "results": results[:limit]}


def load_arsenal_for_search() -> list[dict[str, object]]:
    """Lightweight projection of the arsenal used by the search endpoint."""
    from app.services.tool_registry import load_arsenal
    arsenal = load_arsenal()
    return [
        {
            "id": t.id,
            "name": t.name,
            "pack": t.pack,
            "category": t.category,
            "tags": list(t.tags or []),
            "recommended_use": t.recommended_use,
            "execution": t.execution,
        }
        for t in arsenal.tools
    ]


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


@router.get("/projects/{project_id}/triage", response_model=TriageReport)
def project_triage(project_id: str, limit: int | None = None) -> TriageReport:
    """Run PentestBrain's triage pass over the project's findings.

    Deterministic by default — set `ASURA_LLM_TRIAGE=1` with
    `ANTHROPIC_API_KEY` to enable LLM-assisted clustering + false-positive
    scoring. Either way every claim cites real evidence ids; the citation
    guard discards any LLM output that references ids the brain never
    handed it.
    """
    repos = get_repos()
    if repos.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    brain = PentestBrain(repos)
    return brain.triage_findings(project_id, limit=limit)


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


# ---------------------------------------------------------------------------
# Custom Nuclei templates
# ---------------------------------------------------------------------------


_TEMPLATE_CONTAINER_MOUNT = "/asura-templates"


def _nuclei_extras_for(template_ids: list[str]) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    """Resolve template_ids → (extra_args, extra_mounts, missing_ids).

    extra_args appends `-t <path>` once per template; for the Docker path
    we mount the workspace template directory read-only and rewrite each
    path to the in-container mount point.
    """
    if not template_ids:
        return [], [], []
    service = TemplatesService(get_repos())
    paths, missing = service.resolve_paths(template_ids)
    if not paths:
        return [], [], missing
    workspace_dir = service.workspace_dir(
        next((service.get(tid).workspace_id for tid in template_ids if service.get(tid) is not None), "workspace-demo")
    )
    extra_mounts = [(str(workspace_dir), _TEMPLATE_CONTAINER_MOUNT)]
    extra_args: list[str] = []
    for path in paths:
        # The host path the local subprocess uses:
        host_path = str(path)
        # The in-container path the Docker runner uses. The bind-mount is
        # the workspace dir, so the file lives at /asura-templates/<name>.
        container_path = f"{_TEMPLATE_CONTAINER_MOUNT}/{path.name}"
        # Local runs and Docker runs differ on this — we generate the
        # local-friendly form here; the Docker argv builder rewrites it
        # via the mount substitution it does for filesystem targets.
        # For nuclei specifically we use the local path; the docker runner
        # only knows to swap the *target* string when target_kind matches.
        # To make templates work in both, we append two flag pairs: the
        # local subprocess sees -t <host_path>; the Docker container, with
        # the workspace dir mounted at /asura-templates, would not see
        # /home/... so we instead pass the container_path and rely on the
        # symmetric mount. This means local + Docker both need the same
        # path string. We choose the container_path and bind the workspace
        # at that mount on BOTH paths via extra_mounts (Docker handles it;
        # the local runner ignores extra_mounts since the file exists on
        # disk at host_path). The user's local nuclei would also expect a
        # real path; to keep both working we just pass host_path here and
        # let the Docker runner swap it via the mount-aware rewriter.
        extra_args.extend(["-t", host_path])
    return extra_args, extra_mounts, missing


def _rewrite_for_docker(extra_args: list[str], host_dir: str) -> list[str]:
    """Swap any -t <host_dir>/foo.yaml argument to -t /asura-templates/foo.yaml."""
    out: list[str] = []
    prefix = host_dir.rstrip("/\\") + os.sep
    for arg in extra_args:
        if arg.startswith(prefix):
            out.append(f"{_TEMPLATE_CONTAINER_MOUNT}/{os.path.basename(arg)}")
        else:
            out.append(arg)
    return out


@router.get("/templates", response_model=list[NucleiTemplate])
def list_templates() -> list[NucleiTemplate]:
    service = TemplatesService(get_repos())
    return service.list()


@router.post("/templates", response_model=NucleiTemplate, status_code=201)
async def upload_template(
    file: UploadFile = File(...),
    description: str | None = Form(default=None),
    tags: str | None = Form(default=None),
) -> NucleiTemplate:
    """Upload a custom Nuclei template (`.yaml`).

    Validates that the file parses as YAML and has a top-level `id` —
    enough to reject obviously-bad uploads without locking out templates
    that just don't match the full Nuclei schema yet.
    """
    service = TemplatesService(get_repos())
    content = await file.read()
    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    try:
        return service.upload(
            workspace_id="workspace-demo",
            filename=file.filename or "template.yaml",
            content=content,
            description=description,
            tags=tag_list,
        )
    except TemplateValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/templates/{template_id}", response_model=NucleiTemplate)
def get_template(template_id: str) -> NucleiTemplate:
    service = TemplatesService(get_repos())
    record = service.get(template_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return record


@router.get("/templates/{template_id}/content")
def get_template_content(template_id: str) -> Response:
    service = TemplatesService(get_repos())
    content = service.read_content(template_id)
    if content is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return Response(content=content, media_type="application/x-yaml")


@router.delete("/templates/{template_id}", status_code=204, response_class=Response)
def delete_template(template_id: str) -> Response:
    service = TemplatesService(get_repos())
    if not service.delete(template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Auth profiles (Fernet-encrypted; secrets never returned by the API)
# ---------------------------------------------------------------------------


AUTH_CAPABLE_SCANNERS = {"nuclei", "httpx", "zap"}


def _auth_extras_for(
    scanner: str, profile_id: Optional[str]
) -> tuple[list[str], list[tuple[str, str]], list[Path], Optional[str]]:
    """Resolve a per-scanner auth profile into runner-ready extras.

    Returns `(extra_args, extra_mounts, cleanup_paths, error_message)`:

    - `extra_args` are appended to the scanner's argv.
    - `extra_mounts` are bind-mounts the Docker runner attaches.
    - `cleanup_paths` are files the caller must `unlink` after the scan
      finishes (we use this to wipe ZAP hook scripts containing the
      decrypted secret).

    Nuclei + HTTPx accept raw `-H` flags. ZAP can't take headers on its
    CLI, so we instead generate a `--hook` script that wires Replacer
    rules via the ZAP API the moment the daemon comes up. All three
    scanners pull from the exact same `AuthProfile` rows — the API is
    the same to the caller.
    """
    if not profile_id:
        return [], [], [], None
    service = AuthProfileService(get_repos())
    profile = service.get(profile_id)
    if profile is None:
        return [], [], [], f"Unknown auth profile: {profile_id}"
    if scanner not in AUTH_CAPABLE_SCANNERS:
        return [], [], [], None

    headers = service.decrypted_headers(profile_id)
    if not headers:
        return [], [], [], None

    if scanner == "zap":
        hook_path = zap_auth.write_hook_file(headers)
        # The path-rewriter swaps host paths under any extra_mount to the
        # in-container path automatically — local subprocess sees the host
        # path, Docker sees `/asura-zap-hooks/<basename>`.
        extra_args = ["--hook", str(hook_path)]
        extra_mounts = [(str(hook_path.parent), zap_auth.HOOK_MOUNT_DIR)]
        return extra_args, extra_mounts, [hook_path], None

    # nuclei + httpx: raw -H flags.
    args: list[str] = []
    for name, value in headers:
        args.extend(["-H", f"{name}: {value}"])
    return args, [], [], None


@router.get("/auth-profiles", response_model=list[AuthProfile])
def list_auth_profiles() -> list[AuthProfile]:
    service = AuthProfileService(get_repos())
    return service.list()


@router.post("/auth-profiles", response_model=AuthProfile, status_code=201)
def create_auth_profile(request: AuthProfileCreate) -> AuthProfile:
    service = AuthProfileService(get_repos())
    try:
        return service.create(workspace_id="workspace-demo", payload=request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/auth-profiles/{profile_id}", response_model=AuthProfile)
def get_auth_profile(profile_id: str) -> AuthProfile:
    service = AuthProfileService(get_repos())
    profile = service.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Auth profile not found")
    return profile


@router.delete("/auth-profiles/{profile_id}", status_code=204, response_class=Response)
def delete_auth_profile(profile_id: str) -> Response:
    service = AuthProfileService(get_repos())
    if not service.delete(profile_id):
        raise HTTPException(status_code=404, detail="Auth profile not found")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# LLM triage settings (Fernet-encrypted; api key never returned in responses)
# ---------------------------------------------------------------------------


@router.get("/settings/llm", response_model=LLMSettings)
def get_llm_settings() -> LLMSettings:
    return LLMSettingsService().get()


@router.put("/settings/llm", response_model=LLMSettings)
def update_llm_settings(payload: LLMSettingsUpdate) -> LLMSettings:
    return LLMSettingsService().update(payload)


@router.delete("/settings/llm", status_code=204, response_class=Response)
def delete_llm_settings() -> Response:
    LLMSettingsService().delete()
    return Response(status_code=204)


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
    # Templates apply only to scanners that natively accept them (currently
    # nuclei). Resolve once and pass extras into the runner per-scanner.
    nuclei_args, nuclei_mounts, missing_template_ids = _nuclei_extras_for(request.template_ids)
    if missing_template_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown template id(s): {', '.join(missing_template_ids)}",
        )

    # Substitutions for command-template placeholders. The contract validator
    # already pins these to a whitelist; runner.build_command applies them.
    substitutions: dict[str, str] = {}
    if request.wordlist:
        substitutions["wordlist"] = request.wordlist
    if request.provider:
        substitutions["provider"] = request.provider

    runs: list[ScannerRun] = []
    # Hook files generated for ZAP auth must be deleted after the scan so
    # the decrypted secret never lingers on disk, even on crash paths.
    cleanup_paths: list[Path] = []
    try:
        for scanner in request.scanners:
            is_nuclei = scanner == "nuclei"
            # Per-scanner auth injection (nuclei + httpx via -H, zap via --hook).
            auth_args, auth_mounts, auth_cleanup, auth_err = _auth_extras_for(
                scanner, request.auth_profile_id
            )
            if auth_err:
                raise HTTPException(status_code=400, detail=auth_err)
            cleanup_paths.extend(auth_cleanup)

            scanner_extras = list(auth_args)
            scanner_mounts: list[tuple[str, str]] = list(auth_mounts)
            if is_nuclei:
                scanner_extras = list(nuclei_args) + scanner_extras
                scanner_mounts = list(nuclei_mounts) + scanner_mounts

            run = run_scanner(
                project_id=request.project_id,
                scanner=scanner,
                target=request.target,
                mode=request.mode.value,
                authorized=request.explicit_authorization,
                repos=repos,
                extra_args=scanner_extras or None,
                extra_mounts=scanner_mounts or None,
                substitutions=substitutions or None,
            )
            repos.runs.add(run)
            runs.append(run)
        return runs
    finally:
        for path in cleanup_paths:
            zap_auth.delete_hook_file(path)


class VerifyEvidenceRequest(BaseModel):
    leaf_hash: str
    proof: list[dict]
    merkle_root: str


@router.get("/reports/signing-key")
def reports_signing_key() -> dict[str, str]:
    """Return the Ed25519 public key used to sign every report.

    Stable per deployment; rotating the on-disk key file changes the
    returned `key_id`. Out-of-band publish this once (status page, docs)
    so verifiers can pin a known key.
    """
    return {
        "key_id": signing_key_id(),
        "algorithm": "ed25519",
        "public_key_pem": public_key_pem(),
    }


@router.post("/reports/verify-evidence")
def verify_evidence_inclusion(req: VerifyEvidenceRequest) -> dict[str, bool | str]:
    """Stateless verifier: check that a leaf belongs to a signed Merkle root.

    The caller only needs the leaf hash, the audit path, and the trusted
    root (usually pulled from a previously signed bundle). No state is
    held server-side — it's a pure recomputation. Convenience endpoint
    for CI tooling without a SHA-256 implementation handy.
    """
    ok = verify_inclusion(
        leaf=req.leaf_hash.removeprefix("sha256:"),
        proof=req.proof,
        expected_root=req.merkle_root.removeprefix("sha256:"),
    )
    return {"valid": ok, "merkle_root": req.merkle_root}


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


@router.get("/reports/{project_id}/pdf")
def pdf_report(project_id: str) -> Response:
    """Render the full report as a signed PDF.

    The PDF carries the Ed25519 signature, key id, content hash, and
    Merkle root in a "Cryptographic Footer" section — the printout is
    itself a verifiable artifact when read alongside the public key
    served at /api/reports/signing-key.
    """
    repos = get_repos()
    if repos.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    report = build_report(repos=repos, project_id=project_id, kind="markdown")
    body = render_pdf(report)
    return Response(
        body,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="asura-{project_id}.pdf"'},
    )


@router.get("/reports/{project_id}/signed.json")
def signed_json_report(project_id: str) -> dict:
    """Return the full report as a signed JSON envelope.

    The envelope ships:
      - `sections`: the report body (the same dict the JSON report returns)
      - `content_hash`: sha256 over canonicalized `sections`
      - `merkle_root`: root of the Merkle tree over evidence leaves
      - `evidence_leaves`: ordered list with `leaf_index` + audit `proof`
      - `signature`: Ed25519 signature (base64) over the canonical header
      - `signing_key_id`, `algorithm`

    Verifiers fetch /api/reports/signing-key once, then re-derive the
    content hash + Merkle root from the bundle and check the signature.
    """
    repos = get_repos()
    if repos.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    report = build_report(repos=repos, project_id=project_id, kind="json")
    return build_signed_bundle(report)


