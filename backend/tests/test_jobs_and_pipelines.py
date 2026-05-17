"""Async jobs + pipelines.

The async path is single-threaded in tests (the job runs to completion
quickly because demo runners don't spawn subprocesses), so we can poll
with a short timeout and not need to coordinate threads.
"""
from __future__ import annotations

import os
import time
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.repositories import reset_repos


client = TestClient(app)


def _wait_for_job(job_id: str, *, timeout: float = 3.0) -> dict:
    """Poll the job until it leaves a non-terminal state."""
    deadline = time.time() + timeout
    last_body: dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200
        last_body = response.json()
        if last_body["status"] not in {"queued", "running"}:
            return last_body
        time.sleep(0.05)
    return last_body


def test_async_scan_submits_and_completes_in_demo_mode() -> None:
    reset_repos()
    with mock.patch.dict(os.environ, {"ASURA_DEMO_MODE": "1"}):
        response = client.post(
            "/api/scans/async",
            json={
                "project_id": "demo",
                "target": "git://demo/asura-lab",
                "scanners": ["semgrep"],
                "mode": "passive",
            },
        )
    assert response.status_code == 202
    body = response.json()
    assert body["job_id"].startswith("job-")
    assert body["backend"] == "inline_thread"

    final = _wait_for_job(body["job_id"])
    assert final["status"] == "completed"
    assert len(final["run_ids"]) == 1
    assert final["progress_percent"] == 100


def test_async_scan_blocked_by_scope_records_blocked_status() -> None:
    reset_repos()
    response = client.post(
        "/api/scans/async",
        json={
            "project_id": "demo",
            "target": "https://evil.example",
            "scanners": ["nuclei"],
            "mode": "active",
            "authorized_scope": "https://evil.example",
            "explicit_authorization": True,
        },
    )
    assert response.status_code == 202
    final = _wait_for_job(response.json()["job_id"])
    assert final["status"] == "blocked"
    assert final["error"]
    assert final["run_ids"] == []


def test_get_jobs_lists_recent_first() -> None:
    reset_repos()
    with mock.patch.dict(os.environ, {"ASURA_DEMO_MODE": "1"}):
        client.post(
            "/api/scans/async",
            json={
                "project_id": "demo",
                "target": "git://demo/asura-lab",
                "scanners": ["semgrep"],
                "mode": "passive",
            },
        )
        client.post(
            "/api/scans/async",
            json={
                "project_id": "demo",
                "target": "git://demo/asura-lab",
                "scanners": ["gitleaks"],
                "mode": "passive",
            },
        )
    time.sleep(0.2)
    response = client.get("/api/jobs", params={"project_id": "demo"})
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) >= 2
    # Most-recent first.
    assert rows[0]["created_at"] >= rows[1]["created_at"]


def test_pipelines_list_includes_presets() -> None:
    response = client.get("/api/pipelines")
    assert response.status_code == 200
    presets = {p["id"] for p in response.json()}
    assert {"passive-recon", "code-audit", "container-audit"}.issubset(presets)


def test_pipeline_run_executes_each_stage_in_demo_mode() -> None:
    reset_repos()
    with mock.patch.dict(os.environ, {"ASURA_DEMO_MODE": "1"}):
        response = client.post(
            "/api/pipelines/run",
            json={
                "project_id": "demo",
                "pipeline_id": "code-audit",
                "target": "git://demo/asura-lab",
                "explicit_authorization": False,
                "confirm_high_noise": False,
            },
        )
    assert response.status_code == 202
    final = _wait_for_job(response.json()["job_id"], timeout=4.0)
    # code-audit has 3 parallel passive stages (all input_source=target), so
    # we expect 3 runs from the same target.
    assert final["status"] == "completed"
    assert len(final["run_ids"]) == 3


def test_pipeline_with_unknown_id_returns_404() -> None:
    response = client.post(
        "/api/pipelines/run",
        json={
            "project_id": "demo",
            "pipeline_id": "does-not-exist",
            "target": "git://demo/asura-lab",
        },
    )
    assert response.status_code == 404


def test_async_scan_unknown_project_returns_404() -> None:
    response = client.post(
        "/api/scans/async",
        json={
            "project_id": "proj-does-not-exist",
            "target": "git://x",
            "scanners": ["semgrep"],
            "mode": "passive",
        },
    )
    assert response.status_code == 404


def test_job_404_for_missing_id() -> None:
    response = client.get("/api/jobs/job-missing")
    assert response.status_code == 404
