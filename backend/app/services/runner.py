"""Scanner runner.

The runner is real-by-default and picks an execution path in this order:

1. `ASURA_DEMO_MODE=1` → return seeded output, never spawn a process.
2. `ASURA_PREFER_DOCKER=1` AND the tool has a `docker_image` AND `docker`
   is on PATH → run in a container.
3. Local binary on PATH → run as a subprocess.
4. Tool has a `docker_image` AND `docker` is on PATH → run in a container
   (automatic fallback when the local binary is missing).
5. Else → return a `failed` ScannerRun with the install hint.

For tools whose target is a local filesystem path (`target_kind:
filesystem` or `mixed` when the supplied target resolves to a path on
disk), the Docker path bind-mounts the target's parent directory at
`/scan` read-only and rewrites the command's target argument to that
mount point. URL / host targets are passed through unchanged.

`run_scanner()` is the public entry point. When called with a `repos`
container it completes the loop end-to-end: executes the tool, writes
the raw payload to the evidence vault with a sha256 `content_hash`,
invokes the parser registered for the tool, deduplicates findings by
fingerprint, and persists `Finding` + `Evidence` records to the
repositories.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from app.models.schemas import Evidence, Finding, ScannerRun
from app.services.parsers import PARSERS
from app.services.scanner_registry import SCANNERS, scanner_allowed
from app.services.fingerprint import finding_fingerprint
from app.services.evidence_store import write_evidence_file, content_hash
from app.services.tool_registry import load_arsenal

DEMO_MODE_ENV_VAR = "ASURA_DEMO_MODE"
PREFER_DOCKER_ENV_VAR = "ASURA_PREFER_DOCKER"
DOCKER_MOUNT_POINT = "/scan"


def demo_mode_enabled() -> bool:
    """True when the operator has explicitly chosen seeded demo output."""
    return os.environ.get(DEMO_MODE_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def prefer_docker_enabled() -> bool:
    """True when the operator wants Docker even if the local binary exists."""
    return os.environ.get(PREFER_DOCKER_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


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


# The shape of an in-container mount: (host_path, container_path).
ExtraMount = tuple[str, str]


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


def _arsenal_tool(scanner: str):
    """Return the registry entry for `scanner`, or None."""
    try:
        arsenal = load_arsenal()
    except Exception:  # pragma: no cover — defensive
        return None
    for tool in arsenal.tools:
        if tool.id == scanner:
            return tool
    return None


def _install_hint_for(scanner: str) -> str:
    """Pull the registry's install hint (and docker note if available)."""
    tool = _arsenal_tool(scanner)
    if tool is None:
        return ""
    parts: list[str] = []
    if tool.install_hint:
        parts.append(tool.install_hint)
    if tool.docker_image:
        parts.append(f"Or pull the registered Docker image: `docker pull {tool.docker_image}`.")
    elif tool.docker_available:
        parts.append(
            "A Docker image is registered for this tool — pull it from the project's official image and re-run."
        )
    if tool.official_url:
        parts.append(f"Docs: {tool.official_url}")
    return " ".join(parts)


def _looks_like_filesystem_target(target: str) -> bool:
    """Heuristic: is this target a local filesystem path?

    Strict — only return True when the leading character clearly indicates a
    filesystem path. URL/image refs (https://, git://, ghcr.io/...) and bare
    hostnames are treated as non-filesystem.
    """
    t = target.strip()
    if not t:
        return False
    if "://" in t:  # url-like (https://, git://, ...)
        return False
    if t.startswith(("/", "~", "./", "../", "\\\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", t):  # Windows C:\ or C:/
        return True
    return False


def _docker_mount_args(target: str) -> tuple[list[str], str]:
    """Return (mount-args, rewritten target) for a filesystem target.

    Bind-mounts the absolute resolved path of `target` (or its parent if it's
    a file) at DOCKER_MOUNT_POINT inside the container, read-only.
    """
    path = Path(target).expanduser().resolve()
    if path.is_dir():
        host_dir = path
        in_container = DOCKER_MOUNT_POINT
    else:
        host_dir = path.parent
        in_container = f"{DOCKER_MOUNT_POINT}/{path.name}"
    return (
        ["-v", f"{host_dir}:{DOCKER_MOUNT_POINT}:ro"],
        in_container,
    )


def _build_docker_argv(
    *,
    tool,
    target: str,
    inner_argv: list[str],
    extra_mounts: list[ExtraMount] | None = None,
) -> tuple[list[str], str]:
    """Return (docker argv, target-as-used-in-command) for a single scan.

    `extra_mounts` lets callers attach additional read-only bind-mounts
    (e.g. a custom-Nuclei-templates directory) without the runner having to
    know about each one. Each mount becomes `-v <host>:<container>:ro`.

    Any inner-argv value that lives under one of those host directories
    is rewritten to its in-container path — that's how custom Nuclei
    templates work the same way regardless of execution path.
    """
    target_kind = (tool.target_kind or "url")
    mount_args: list[str] = []
    final_target = target
    if target_kind in {"filesystem", "mixed"} and _looks_like_filesystem_target(target):
        mount_args, final_target = _docker_mount_args(target)

    for host, container in extra_mounts or []:
        mount_args.extend(["-v", f"{host}:{container}:ro"])

    # Substitute the rewritten target inside the inner argv where the
    # registry placeholder used to live.
    rewritten_inner = [arg.replace(target, final_target) if target != final_target else arg for arg in inner_argv]

    # Translate host paths under any extra_mount to their in-container path.
    if extra_mounts:
        rewritten_inner = _rewrite_paths_for_mounts(rewritten_inner, extra_mounts)

    # Drop the executable from inner_argv if it matches the tool executable;
    # many official images already set ENTRYPOINT.
    if rewritten_inner and tool.executable and rewritten_inner[0] == tool.executable:
        rewritten_inner = rewritten_inner[1:]

    argv = ["docker", "run", "--rm", "-i"] + mount_args + [tool.docker_image] + rewritten_inner
    return argv, final_target


def _rewrite_paths_for_mounts(argv: list[str], mounts: list[ExtraMount]) -> list[str]:
    """Rewrite any argv element that begins with a mount's host_dir to its
    in-container path. Case-insensitive on Windows because driver letters
    and forward/back slashes mix freely in subprocess.run argv."""
    out: list[str] = []
    normalised_mounts = []
    for host, container in mounts:
        host_norm = os.path.normpath(host).rstrip(os.sep) + os.sep
        normalised_mounts.append((host_norm, host_norm.lower(), container.rstrip("/")))
    for arg in argv:
        rewritten = arg
        # We don't want to corrupt URLs that happen to start with something
        # that contains the mount substring — only rewrite paths that look
        # like absolute filesystem paths.
        candidate = os.path.normpath(arg) if (arg and not arg.startswith(("-", "http://", "https://"))) else None
        if candidate is not None:
            candidate_lower = candidate.lower() + os.sep
            for _host_norm, host_lower, container in normalised_mounts:
                if candidate_lower.startswith(host_lower):
                    # The file's basename is its in-container name.
                    rewritten = f"{container}/{os.path.basename(candidate)}"
                    break
        out.append(rewritten)
    return out


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


def _execute_and_parse(
    *,
    repos,
    project_id: str,
    scanner: str,
    target: str,
    mode: str,
    args: list[str],
    path_label: str,
) -> ScannerRun:
    """Spawn the subprocess, decode output, run the parser, persist results.

    `args` is the already-built argv (for either the local binary or
    `docker run …`). `path_label` describes which execution path was taken
    and is appended to ScannerRun.message for operator visibility.
    """
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=900, check=False)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover — defensive
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="failed",
            message=f"{scanner} timed out after {exc.timeout}s ({path_label}).",
            args=args,
        )
    except FileNotFoundError as exc:  # pragma: no cover — defensive
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="failed",
            message=f"{scanner} could not be launched: {exc} ({path_label}).",
            args=args,
        )

    raw_payload = _decode_output(result.stdout)
    status = "completed" if result.returncode == 0 else "failed"

    if raw_payload is None and result.returncode != 0:
        stderr_excerpt = (result.stderr or "").strip()[-1000:]
        return _new_run(
            project_id=project_id, scanner=scanner, target=target, mode=mode,
            status="failed",
            message=stderr_excerpt or f"{scanner} exited with {result.returncode} and produced no output ({path_label}).",
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
                return _new_run(
                    project_id=project_id, scanner=scanner, target=target, mode=mode,
                    status="failed",
                    message=f"Parser '{parser_name}' raised {type(exc).__name__}: {exc} ({path_label}).",
                    args=args,
                    exit_code=result.returncode,
                )

    run = _new_run(
        project_id=project_id, scanner=scanner, target=target, mode=mode,
        status=status,
        message=f"{scanner} completed ({result.returncode}); {len(findings)} finding(s) parsed ({path_label}).",
        args=args,
        exit_code=result.returncode,
    )

    if repos is not None:
        run = _persist_results(
            repos=repos, run=run, findings=findings,
            raw_payload=raw_payload, args=args,
        )

    return run


def _local_binary_path(scanner: str) -> str | None:
    """Return the local binary path if it's on PATH, else None."""
    executable = SCANNERS[scanner].executable
    return shutil.which(executable)


def _docker_available_for(scanner: str):
    """Return (tool, docker_path) if Docker can run this scanner, else (tool, None)."""
    tool = _arsenal_tool(scanner)
    if tool is None or not tool.docker_image:
        return tool, None
    docker_path = shutil.which("docker")
    if docker_path is None:
        return tool, None
    return tool, docker_path


def _failed_no_runtime(project_id: str, scanner: str, target: str, mode: str) -> ScannerRun:
    """Both local binary and Docker are unavailable — return a helpful failure."""
    executable = SCANNERS[scanner].executable
    hint = _install_hint_for(scanner)
    message = f"{executable} is not installed on this host, and Docker is not available either."
    if hint:
        message = f"{message} {hint}"
    message = f"{message} Set {DEMO_MODE_ENV_VAR}=1 to view the dashboard with seeded data while you install."
    return _new_run(
        project_id=project_id, scanner=scanner, target=target, mode=mode,
        status="failed", message=message,
    )


def run_scanner(
    project_id: str,
    scanner: str,
    target: str,
    mode: str,
    authorized: bool,
    *,
    repos=None,
    force_demo: Optional[bool] = None,
    force_docker: Optional[bool] = None,
    extra_args: Optional[list[str]] = None,
    extra_mounts: Optional[list[ExtraMount]] = None,
) -> ScannerRun:
    """Execute a registered scanner.

    Decision tree (top to bottom):
      1. ASURA_DEMO_MODE=1 (or force_demo=True) → seeded output, no process
      2. ASURA_PREFER_DOCKER=1 (or force_docker=True) AND tool has
         docker_image AND docker on PATH → Docker
      3. Local binary on PATH → subprocess
      4. Tool has docker_image AND docker on PATH → Docker (automatic fallback)
      5. Else → failed with install hint

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

    prefer_docker = prefer_docker_enabled() if force_docker is None else force_docker
    tool, docker_path = _docker_available_for(scanner)
    local_path = _local_binary_path(scanner)
    inner_argv = build_command(scanner, target, mode)
    if extra_args:
        inner_argv = inner_argv + list(extra_args)

    # Path selection.
    if prefer_docker and docker_path and tool is not None:
        argv, _ = _build_docker_argv(
            tool=tool, target=target, inner_argv=inner_argv,
            extra_mounts=extra_mounts,
        )
        return _execute_and_parse(
            repos=repos, project_id=project_id, scanner=scanner, target=target,
            mode=mode, args=argv,
            path_label=f"via Docker image {tool.docker_image}",
        )
    if local_path:
        return _execute_and_parse(
            repos=repos, project_id=project_id, scanner=scanner, target=target,
            mode=mode, args=inner_argv,
            path_label=f"via local binary {local_path}",
        )
    if docker_path and tool is not None:
        argv, _ = _build_docker_argv(
            tool=tool, target=target, inner_argv=inner_argv,
            extra_mounts=extra_mounts,
        )
        return _execute_and_parse(
            repos=repos, project_id=project_id, scanner=scanner, target=target,
            mode=mode, args=argv,
            path_label=f"via Docker image {tool.docker_image} (local binary not installed)",
        )
    return _failed_no_runtime(project_id, scanner, target, mode)
