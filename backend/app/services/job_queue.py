"""Asura job queue.

Two implementations behind one API:

- `InlineThreadQueue` (default) — `submit()` spawns a Python thread that runs
  the work in the background. State is persisted to the `jobs` repository so
  the API can poll. No external dependencies.
- `RQQueue` — opt-in via `ASURA_USE_RQ=1`. Enqueues work onto a Redis-backed
  RQ queue. Falls back to the inline queue if Redis is unreachable, so the
  developer experience stays "click Run scan, see progress" even when the
  worker container isn't up.

The job model lives in `app.models.schemas.ScanJob`.

The functions executed by the worker are top-level (not closures) so they
remain picklable for RQ.
"""
from __future__ import annotations

import os
import threading
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

from app.models.schemas import ScanJob


JOB_QUEUE_ENV_VAR = "ASURA_USE_RQ"


def rq_requested() -> bool:
    return os.environ.get(JOB_QUEUE_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class JobQueue:
    """Submit work, persist a ScanJob, return immediately.

    `fn` is a callable that takes the ScanJob and the same repos container the
    caller uses. The function is expected to mutate the job's status / progress
    fields on the in-memory repo as it works.
    """

    def __init__(self, repos) -> None:
        self.repos = repos
        self._backend: Optional[str] = None

    def submit(
        self,
        *,
        project_id: str,
        kind: str = "scan",
        pipeline_id: Optional[str] = None,
        scan_request: Optional[dict[str, Any]] = None,
        fn: Callable[[ScanJob], None],
    ) -> ScanJob:
        """Persist a ScanJob and dispatch the work. Returns the job."""
        job_id = f"job-{uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        job = ScanJob(
            id=job_id,
            project_id=project_id,
            kind=kind,  # type: ignore[arg-type]
            pipeline_id=pipeline_id,
            status="queued",
            scan_request=scan_request,
            created_at=now,
            backend="inline_thread",
        )
        self.repos.jobs.add(job)
        if rq_requested():
            enqueued = _maybe_enqueue_via_rq(job, fn)
            if enqueued:
                job.backend = "rq"
                self.repos.jobs.update(job)
                return job
        # Fallback: run inline in a daemon thread.
        thread = threading.Thread(
            target=_inline_runner,
            args=(self.repos, job_id, fn),
            name=f"asura-job-{job_id}",
            daemon=True,
        )
        thread.start()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self.repos.jobs.get(job_id)


# ---------------------------------------------------------------------------
# Inline-thread implementation (default)
# ---------------------------------------------------------------------------


def _inline_runner(repos, job_id: str, fn: Callable[[ScanJob], None]) -> None:
    """Background-thread entry point.

    Wraps `fn` with status-transition handling: queued → running → completed
    (or failed). Persists progress mid-flight via the jobs repo. Catches
    exceptions and stamps them onto the job so the API surfaces them rather
    than silently swallowing them.
    """
    job = repos.jobs.get(job_id)
    if job is None:
        return
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    repos.jobs.update(job)
    try:
        fn(job)
        # If the callback didn't mark a terminal state, complete it.
        if job.status in {"queued", "running"}:
            job.status = "completed"
    except Exception as exc:  # pragma: no cover — defensive
        job.status = "failed"
        job.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}"
    finally:
        job.finished_at = datetime.now(timezone.utc)
        job.progress_percent = 100 if job.status == "completed" else job.progress_percent
        repos.jobs.update(job)


# ---------------------------------------------------------------------------
# Optional RQ implementation
# ---------------------------------------------------------------------------


def _maybe_enqueue_via_rq(job: ScanJob, fn: Callable[[ScanJob], None]) -> bool:
    """Try to enqueue on Redis-backed RQ. Returns True if enqueued."""
    try:
        from redis import Redis
        from rq import Queue
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        redis = Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
        redis.ping()
        queue = Queue("asura-scans", connection=redis)
        # NOTE: passing a closure (`fn`) directly will fail RQ's pickle
        # boundary. The wired pipelines use the module-level worker entry
        # point in `app.workers.scan_worker` — that path is documented in
        # docs/SCANNER_RUNNERS.md. For ad-hoc inline lambdas we fall back to
        # the in-process thread runner.
        if getattr(fn, "__module__", "").startswith("app.workers"):
            queue.enqueue(fn, job.id, job_timeout=1800)
            return True
        return False
    except Exception:
        # Redis offline / RQ not installed / import error → fall back.
        return False


# ---------------------------------------------------------------------------
# Helpers for callbacks
# ---------------------------------------------------------------------------


def update_progress(repos, job: ScanJob, *, percent: int | None = None, text: str | None = None) -> None:
    """Helper to mutate + persist progress in-place."""
    if percent is not None:
        job.progress_percent = max(0, min(100, int(percent)))
    if text is not None:
        job.progress_text = text
    repos.jobs.update(job)
