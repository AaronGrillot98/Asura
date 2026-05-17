"""Scanner runner.

The runner is real-by-default: when a scan request arrives, Asura tries to
execute the registered command for the scanner and parse the output into
normalized Findings + Evidence.

`SubprocessRunner` is the default. `DemoRunner` returns clearly-labelled
seeded output and is only used when `ASURA_DEMO_MODE=1` is set (handy for
screenshots, training, and air-gapped review where you don't want a process
to run).

`run_scanner()` is the public entry point. When called with a `repos`
container it completes the loop end-to-end: executes the tool, writes the
raw payload to the evidence vault with a sha256 `content_hash`, invokes the
parser registered for the tool, deduplicates findings by fingerprint, and
persists `Finding` + `Evidence` records to the repositories.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from app.models.schemas import Evidence, Finding, ScannerRun
from app.services.parsers import PARSERS
from app.services.scanner_registry import SCANNERS, scanner_allowed
from app.services.fingerprint import finding_fingerprint
from app.services.evidence_store import write_evidence_file, content_hash
from app.services.tool_registry import load_arsenal

DEMO_MODE_ENV_VAR = "ASURA_DEMO_MODE"


def demo_mode_enabled() -> bool:
    """True when the operator has explicitly chosen seeded demo output."""
    return os.environ.get(DEMO_MODE_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def validate_target(target: str) -> str | None:
    if not target or not target.strip():
        return "Target is required."
    if len(target) > 2048:
        return "Target is too long."
    if any(character in target for character in ("\x00", "\r", "\n")):
        return "Target contains control characters."
    if target.strip().startswith("-"):
        return "Target cannot start with a command option prefix."
    return None


def build_command(scanner: str, target: str, mode: str) -> list[str]:
    definition = SCANNERS[scanner]
    command = definition.commands[mode]
    return [part.replace("{{target}}", target) for part in command]


def _new_run(
    project_id: str,
    scanner: str,
    target: str,
    mode: str,
    *,
    status: str,
    message: str,
    args: list[str] | None = None,
    exit_code: int | None = None,
    evidence_ids: list[str] | None = None,
    findings_created: int = 0,
    is_demo_data: bool = False,
) -> ScannerRun:
    now = datetime.now(timezone.utc)
    return ScannerRun(
        id=str(uuid4()),
        project_id=project_id,
        scanner=scanner,
        mode=mode,
        status=status,
        target=target,
        started_at=now,
        finished_at=now,
        args=args or [],
        exit_code=exit_code,
        evidence_ids=evidence_ids or [],
        findings_created=findings_created,
        message=message,
        is_demo_data=is_demo_data,
    )


def _decode_output(stdout: str) -> Any:
    """Try JSON first, fall back to raw string.

    Several core parsers (nmap XML, nuclei JSONL, etc.) tolerate either a
    parsed structure or the raw text, so we don't have to dispatch on output
    format here.
    """
    stripped = (stdout or "").strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return stdout


def _install_hint_for(scanner: str) -> str:
    """Pull the registry's install hint (and docker note if available)."""
    try:
        arsenal = load_arsenal()
    except Exception:  # pragma: no cover — defensive
        return ""
    for tool in arsenal.tools:
        if tool.id != scanner:
            continue
        parts: list[str] = []
        if tool.install_hint:
            parts.append(tool.install_hint)
        if tool.docker_available:
            parts.append(
                "A Docker image is registered for this tool — pull it from the project's official image and re-run."
            )
        if tool.official_url:
            parts.append(f"Docs: {tool.official_url}")
        return " ".join(parts)
    return ""


def _persist_results(
    *,
    repos,
    run: ScannerRun,
    findings: list[Finding],
    raw_payload: Any,
    args: list[str],
) -> ScannerRun:
    """Write raw output + each finding's evidence to disk and repos.

    Returns the run with `evidence_ids` and `findings_created` stamped.
    """
    evidence_ids: list[str] = []

    # 1) Persist the raw scanner output as a top-level evidence file for the run.
    raw_path: str | None = None
    raw_hash: str | None = None
    if raw_payload is not None:
        path, raw_hash = write_evidence_file(
            workspace_id=getattr(repos.projects.get(run.project_id), "workspace_id", "workspace-demo"),
            project_id=run.project_id,
            scan_id=run.id,
            tool=run.scanner,
            payload=raw_payload,
        )
        raw_path = str(path)

    # 2) Persist each finding + its evidence, with dedupe by fingerprint.
    existing_by_fp = {
        f.fingerprint_hash: f
        for f in repos.findings.list()
        if f.project_id == run.project_id and f.fingerprint_hash
    }

    persisted_findings = 0
    for finding in findings:
        finding.project_id = run.project_id
        finding.scan_id = run.id
        for ev in finding.evidence:
            ev.finding_id = finding.id
            ev.raw_output_path = raw_path
            if not ev.content_hash:
                ev.content_hash = content_hash(ev.raw)
            ev.command_metadata = {"args": args, "scanner": run.scanner, "mode": run.mode}

        fp = finding_fingerprint(finding)
        finding.fingerprint_hash = fp
        if fp in existing_by_fp:
            # Recurrence — just bump last_seen on the existing record.
            existing = existing_by_fp[fp]
            existing.last_seen = datetime.now(timezone.utc)
            repos.findings.update(existing)
            continue

        repos.findings.add(finding)
        persisted_findings += 1
        for ev in finding.evidence:
            repos.evidence.add(ev)
            evidence_ids.append(ev.id)

    run.evidence_ids = evidence_ids
    run.findings_created = persisted_findings
    return run


def _demo_run(project_id: str, scanner: str, target: str, mode: str) -> ScannerRun:
    return _new_run(
        project_id=project_id,
        scanner=scanner,
        target=target,
        mode=mode,
        status="completed",
        message=(
            f"DEMO MODE — {scanner} did not execute. Unset {DEMO_MODE_ENV_VAR} "
            f"to run the real scanner."
        ),
        args=[],
        exit_code=0,
        is_demo_data=True,
    )


def _subprocess_run(
    *,
    repos,
    project_id: str,
    scanner: str,
    target: str,
    mode: str,
) -> ScannerRun:
    executable = SCANNERS[scanner].executable
    if shutil.which(executable) is None:
        hint = _install_hint_for(scanner)
        message = f"{executable} is not installed on this host."
        if hint:
            message = f"{message} {hint}"
        message = f"{message} Set {DEMO_MODE_ENV_VAR}=1 to view the dashboard with seeded data while you install."
        return _new_run(
            project_id=project_id,
            scanner=scanner,
            target=target,
            mode=mode,
            status="failed",
            message=message,
        )

    args = build_command(scanner, target, mode)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=900, check=False)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover — defensive
        return _new_run(
            project_id=project_id,
            scanner=scanner,
            target=target,
            mode=mode,
            status="failed",
            message=f"{scanner} timed out after {exc.timeout}s.",
            args=args,
        )
    except FileNotFoundError as exc:  # pragma: no cover — defensive
        return _new_run(
            project_id=project_id,
            scanner=scanner,
            target=target,
            mode=mode,
            status="failed",
            message=f"{scanner} could not be launched: {exc}.",
            args=args,
        )

    raw_payload = _decode_output(result.stdout)
    status = "completed" if result.returncode == 0 else "failed"

    # If the scanner failed and produced nothing, surface stderr.
    if raw_payload is None and result.returncode != 0:
        stderr_excerpt = (result.stderr or "").strip()[-1000:]
        return _new_run(
            project_id=project_id,
            scanner=scanner,
            target=target,
            mode=mode,
            status="failed",
            message=stderr_excerpt or f"{scanner} exited with {result.returncode} and produced no output.",
            args=args,
            exit_code=result.returncode,
        )

    parser_name = SCANNERS[scanner].parser
    findings: list[Finding] = []
    if parser_name and raw_payload is not None:
        parser_fn = PARSERS.get(parser_name) or PARSERS.get(scanner)
        if parser_fn is not None:
            try:
                findings = parser_fn(raw_payload, project_id=project_id, is_demo_data=False)
            except Exception as exc:  # pragma: no cover — defensive
                findings = []
                stderr_excerpt = f"Parser '{parser_name}' raised {type(exc).__name__}: {exc}"
                return _new_run(
                    project_id=project_id,
                    scanner=scanner,
                    target=target,
                    mode=mode,
                    status="failed",
                    message=stderr_excerpt,
                    args=args,
                    exit_code=result.returncode,
                )

    run = _new_run(
        project_id=project_id,
        scanner=scanner,
        target=target,
        mode=mode,
        status=status,
        message=f"{scanner} completed ({result.returncode}); {len(findings)} finding(s) parsed.",
        args=args,
        exit_code=result.returncode,
    )

    if repos is not None:
        run = _persist_results(
            repos=repos,
            run=run,
            findings=findings,
            raw_payload=raw_payload,
            args=args,
        )

    return run


def run_scanner(
    project_id: str,
    scanner: str,
    target: str,
    mode: str,
    authorized: bool,
    *,
    repos=None,
    force_demo: Optional[bool] = None,
) -> ScannerRun:
    """Execute a registered scanner.

    Real subprocess execution is the default. Set `ASURA_DEMO_MODE=1` to
    return seeded demo content instead. Tests can override via
    `force_demo=True/False`.

    When `repos` is provided, the runner persists the resulting
    `ScannerRun`, `Evidence` records, and normalized `Finding` records
    (with fingerprint-based dedupe) to the repository container.
    """
    if scanner not in SCANNERS:
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="blocked", message=f"Unknown scanner: {scanner}",
        )
    target_error = validate_target(target)
    if target_error:
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="blocked", message=target_error,
        )
    if mode in {"active", "lab"} and not authorized:
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="blocked",
            message="Active and lab scans require explicit authorization.",
        )
    if not scanner_allowed(scanner, mode):
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="blocked", message=f"{scanner} is not permitted in {mode} mode.",
        )

    use_demo = demo_mode_enabled() if force_demo is None else force_demo
    if use_demo:
        return _demo_run(project_id, scanner, target, mode)
    return _subprocess_run(
        repos=repos,
        project_id=project_id,
        scanner=scanner,
        target=target,
        mode=mode,
    )
