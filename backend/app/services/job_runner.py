"""Job callbacks for the JobQueue.

Each function takes a `ScanJob` and a `repos` container, mutates the job's
status/progress fields in place, and persists intermediate `ScannerRun`s
to the runs repository. The thread-pool runner in `app.services.job_queue`
handles status transitions and error capture around these callbacks.
"""
from __future__ import annotations

from typing import Iterable, Optional

from app.models.schemas import Pipeline, ScanJob, ScanMode, ScanRequest
from app.security.scope_guard import decide_scope
from app.services.job_queue import update_progress
from app.services.pipelines import get_pipeline
from app.services.runner import run_scanner


def _audit(repos, job: ScanJob, message: str) -> None:
    """Append a one-liner to the job's progress_text history."""
    history = job.progress_text or ""
    if history:
        history += "\n"
    job.progress_text = history + message
    repos.jobs.update(job)


def run_scan_request_job(repos, job: ScanJob, request: ScanRequest) -> None:
    """Background callback: execute a single ScanRequest, persist runs/findings."""
    project = repos.projects.get(request.project_id)
    if project is None:
        job.status = "failed"
        job.error = f"Project {request.project_id} not found."
        repos.jobs.update(job)
        return

    decision = decide_scope(
        project=project,
        target=request.target,
        mode=request.mode,
        explicit_authorization=request.explicit_authorization,
        confirm_high_noise=request.confirm_high_noise,
        audit_repo=repos.audit,
    )
    if not decision.allowed:
        job.status = "blocked"
        job.error = decision.reason or decision.reason_code
        _audit(repos, job, f"Scope blocked: {decision.reason_code}")
        return

    total = len(request.scanners) or 1
    for index, scanner in enumerate(request.scanners):
        update_progress(
            repos,
            job,
            percent=int((index / total) * 100),
            text=f"Running {scanner} ({index + 1}/{total})…",
        )
        run = run_scanner(
            project_id=request.project_id,
            scanner=scanner,
            target=request.target,
            mode=request.mode.value,
            authorized=request.explicit_authorization,
            repos=repos,
        )
        repos.runs.add(run)
        job.run_ids.append(run.id)
        job.findings_created += run.findings_created or 0
        repos.jobs.update(job)

    job.status = "completed"
    job.progress_percent = 100
    job.progress_text = (
        f"Completed {len(request.scanners)} scanner(s); "
        f"{job.findings_created} finding(s) created."
    )
    repos.jobs.update(job)


def run_pipeline_job(
    repos,
    job: ScanJob,
    pipeline: Pipeline,
    initial_target: str,
    explicit_authorization: bool,
    confirm_high_noise: bool,
) -> None:
    """Walk every stage in the pipeline, chaining outputs forward."""
    project = repos.projects.get(job.project_id)
    if project is None:
        job.status = "failed"
        job.error = f"Project {job.project_id} not found."
        repos.jobs.update(job)
        return

    stage_count = len(pipeline.stages) or 1
    last_stage_run_ids: list[str] = []

    for stage_index, stage in enumerate(pipeline.stages):
        update_progress(
            repos,
            job,
            percent=int((stage_index / stage_count) * 100),
            text=f"Stage {stage_index + 1}/{stage_count}: {stage.name} ({stage.scanner})",
        )

        if stage.input_source == "target":
            targets: Iterable[str] = [initial_target]
        else:
            targets = _targets_from_runs(repos, last_stage_run_ids, stage.max_followups)
            if not targets:
                _audit(
                    repos,
                    job,
                    f"Stage '{stage.name}' has no upstream assets; skipping.",
                )
                continue

        stage_run_ids: list[str] = []
        for target in targets:
            decision = decide_scope(
                project=project,
                target=target,
                mode=stage.mode,
                explicit_authorization=explicit_authorization,
                confirm_high_noise=confirm_high_noise,
                audit_repo=repos.audit,
            )
            if not decision.allowed:
                _audit(
                    repos,
                    job,
                    f"Stage '{stage.name}' skipped {target}: {decision.reason_code}",
                )
                continue
            run = run_scanner(
                project_id=job.project_id,
                scanner=stage.scanner,
                target=target,
                mode=stage.mode.value,
                authorized=explicit_authorization,
                repos=repos,
            )
            repos.runs.add(run)
            job.run_ids.append(run.id)
            stage_run_ids.append(run.id)
            job.findings_created += run.findings_created or 0
        last_stage_run_ids = stage_run_ids
        repos.jobs.update(job)

    if not job.run_ids:
        job.status = "blocked"
        job.error = "No runs produced — every stage was blocked or had no inputs."
    else:
        job.status = "completed"
    job.progress_percent = 100
    job.progress_text = (
        (job.progress_text or "")
        + f"\nPipeline finished: {len(job.run_ids)} run(s), "
        + f"{job.findings_created} finding(s)."
    )
    repos.jobs.update(job)


def _targets_from_runs(repos, run_ids: list[str], cap: int) -> list[str]:
    """Pull unique affected_asset values from findings produced by those runs."""
    if not run_ids:
        return []
    seen: list[str] = []
    in_run = set(run_ids)
    for finding in repos.findings.list():
        if finding.scan_id not in in_run:
            continue
        asset = finding.affected_asset or finding.asset_id
        if asset and asset not in seen:
            seen.append(asset)
            if len(seen) >= cap:
                break
    return seen


def find_pipeline_or_fail(pipeline_id: str) -> Pipeline:
    pipeline = get_pipeline(pipeline_id)
    if pipeline is None:
        raise ValueError(f"Unknown pipeline: {pipeline_id}")
    return pipeline
