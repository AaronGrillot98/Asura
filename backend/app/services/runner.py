"""Scanner runner.

Two implementations:

- `DemoRunner` (default): produces clearly-labelled demo output. Never spawns
  a process. Used out-of-the-box so the dashboard, reporting, and evidence
  flows always work even without scanners installed.
- `SubprocessRunner`: gated behind `ASURA_ENABLE_REAL_SCANNERS=1`. Executes
  the registered command for the target tool. The existing argv guards are
  preserved: no shell strings, no option-prefix targets, control-char
  rejection, 900s timeout, structured argv via shlex split.

`run_scanner()` is the public entry point and keeps its previous signature so
the API route keeps working unchanged. It now also returns the evidence ids
it produced (used by the new repository-backed `/api/scans` endpoint).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from app.models.schemas import ScannerRun
from app.services.scanner_registry import SCANNERS, scanner_allowed

REAL_SCANNERS_ENV_VAR = "ASURA_ENABLE_REAL_SCANNERS"


def real_scanners_enabled() -> bool:
    """True when subprocess execution is opt-in via env."""
    return os.environ.get(REAL_SCANNERS_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


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


def _blocked_run(project_id: str, scanner: str, target: str, mode: str, message: str) -> ScannerRun:
    now = datetime.now(timezone.utc)
    return ScannerRun(
        id=str(uuid4()),
        project_id=project_id,
        scanner=scanner,
        mode=mode,
        status="blocked",
        target=target,
        started_at=now,
        finished_at=now,
        message=message,
    )


def _failed_run(project_id: str, scanner: str, target: str, mode: str, message: str) -> ScannerRun:
    now = datetime.now(timezone.utc)
    return ScannerRun(
        id=str(uuid4()),
        project_id=project_id,
        scanner=scanner,
        mode=mode,
        status="failed",
        target=target,
        started_at=now,
        finished_at=now,
        message=message,
    )


def _demo_run(project_id: str, scanner: str, target: str, mode: str) -> ScannerRun:
    """Produce a clearly-labelled demo ScannerRun.

    The demo runner never spawns a subprocess; it returns a deterministic
    completed run that downstream UI/reporting can rely on.
    """
    now = datetime.now(timezone.utc)
    return ScannerRun(
        id=str(uuid4()),
        project_id=project_id,
        scanner=scanner,
        mode=mode,
        status="completed",
        target=target,
        started_at=now,
        finished_at=now,
        args=[],
        exit_code=0,
        evidence_ids=[],
        message=f"DEMO MODE — {scanner} did not execute. Set {REAL_SCANNERS_ENV_VAR}=1 to enable real subprocess scans.",
        is_demo_data=True,
    )


def _subprocess_run(project_id: str, scanner: str, target: str, mode: str) -> ScannerRun:
    """Execute the registered command for `scanner` via subprocess."""
    now = datetime.now(timezone.utc)
    executable = SCANNERS[scanner].executable
    if shutil.which(executable) is None:
        return _failed_run(
            project_id, scanner, target, mode,
            f"{executable} is not installed in this runtime.",
        )
    command = build_command(scanner, target, mode)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover — defensive
        return _failed_run(project_id, scanner, target, mode, f"{scanner} timed out after {exc.timeout}s.")
    except FileNotFoundError as exc:  # pragma: no cover — defensive
        return _failed_run(project_id, scanner, target, mode, f"{scanner} could not be launched: {exc}.")
    status = "completed" if result.returncode == 0 else "failed"
    output = (result.stdout.strip() or result.stderr.strip())
    message = output[-1000:] if output else f"{scanner} exited with {result.returncode}"
    return ScannerRun(
        id=str(uuid4()),
        project_id=project_id,
        scanner=scanner,
        mode=mode,
        status=status,
        target=target,
        started_at=now,
        finished_at=datetime.now(timezone.utc),
        args=command,
        exit_code=result.returncode,
        evidence_ids=[],
        message=message,
        is_demo_data=False,
    )


def run_scanner(
    project_id: str,
    scanner: str,
    target: str,
    mode: str,
    authorized: bool,
    *,
    force_real: Optional[bool] = None,
) -> ScannerRun:
    """Run a registered scanner.

    Defaults to demo mode (no subprocess) unless ASURA_ENABLE_REAL_SCANNERS=1
    is set or `force_real=True` is explicitly passed (used by integration
    tests). All scope-style guards run first regardless of mode so a blocked
    scan never reaches either runner.
    """
    if scanner not in SCANNERS:
        return _blocked_run(project_id, scanner, target, mode, f"Unknown scanner: {scanner}")
    target_error = validate_target(target)
    if target_error:
        return _blocked_run(project_id, scanner, target, mode, target_error)
    if mode in {"active", "lab"} and not authorized:
        return _blocked_run(
            project_id, scanner, target, mode,
            "Active and lab scans require explicit authorization.",
        )
    if not scanner_allowed(scanner, mode):
        return _blocked_run(project_id, scanner, target, mode, f"{scanner} is not permitted in {mode} mode.")

    use_real = real_scanners_enabled() if force_real is None else force_real
    if use_real:
        return _subprocess_run(project_id, scanner, target, mode)
    return _demo_run(project_id, scanner, target, mode)
