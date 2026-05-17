"""End-to-end test for the real-scanner pipeline.

Mocks `subprocess.run` so the test doesn't require Semgrep on the host, then
asserts the full loop runs: output → parser → evidence vault → findings
repository, with fingerprint-based dedupe on re-execution.
"""
from __future__ import annotations

import json
import os
from unittest import mock

from app.repositories import reset_repos
from app.services.runner import DEMO_MODE_ENV_VAR, run_scanner


SEMGREP_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "asura.test.missing-auth",
            "path": "src/routes/admin.ts",
            "start": {"line": 42},
            "extra": {
                "severity": "ERROR",
                "message": "Missing auth guard before privileged route.",
                "metadata": {"cwe": ["CWE-862"]},
            },
        }
    ]
})


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != DEMO_MODE_ENV_VAR}


def _fake_completed(stdout: str, returncode: int = 0):
    result = mock.MagicMock()
    result.stdout = stdout
    result.stderr = ""
    result.returncode = returncode
    return result


def test_real_run_writes_evidence_and_creates_findings(tmp_path) -> None:
    repos = reset_repos()
    env = _clean_env()
    env["ASURA_EVIDENCE_DIR"] = str(tmp_path)

    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/semgrep"), \
         mock.patch("app.services.runner.subprocess.run", return_value=_fake_completed(SEMGREP_OUTPUT)):
        run = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="git://demo/asura-lab",
            mode="passive",
            authorized=False,
            repos=repos,
        )

    assert run.status == "completed"
    assert run.findings_created == 1
    assert run.is_demo_data is False
    assert run.evidence_ids, "evidence_ids should be populated"

    findings = [f for f in repos.findings.list() if f.scan_id == run.id]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "semgrep"
    assert finding.title == "asura.test.missing-auth"
    assert finding.evidence, "finding must carry inline evidence"
    ev = finding.evidence[0]
    assert ev.content_hash, "evidence content_hash must be stamped"
    assert ev.raw_output_path is not None
    assert os.path.exists(ev.raw_output_path), "raw payload must be persisted to disk"


def test_repeat_run_dedupes_by_fingerprint(tmp_path) -> None:
    repos = reset_repos()
    env = _clean_env()
    env["ASURA_EVIDENCE_DIR"] = str(tmp_path)

    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/semgrep"), \
         mock.patch("app.services.runner.subprocess.run", return_value=_fake_completed(SEMGREP_OUTPUT)):
        first = run_scanner("demo", "semgrep", "git://demo/asura-lab", "passive", False, repos=repos)
        second = run_scanner("demo", "semgrep", "git://demo/asura-lab", "passive", False, repos=repos)

    assert first.findings_created == 1
    # Second run sees the same fingerprint → bumps last_seen, does not insert.
    assert second.findings_created == 0
    # Repo still has the original finding plus the seeded demo set (no duplicates).
    semgrep_findings = [f for f in repos.findings.list() if f.scanner == "semgrep" and f.scan_id == first.id]
    assert len(semgrep_findings) == 1


def test_missing_binary_returns_failed_with_install_hint() -> None:
    repos = reset_repos()
    env = _clean_env()
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value=None):
        run = run_scanner(
            project_id="demo",
            scanner="nuclei",
            target="https://flightops.acme.example",
            mode="active",
            authorized=True,
            repos=repos,
        )

    assert run.status == "failed"
    assert run.is_demo_data is False
    # The message should include the binary name and a path forward.
    assert "nuclei" in run.message
    assert ("install" in run.message.lower()) or ("docker" in run.message.lower()) or ("releases" in run.message.lower())
    assert DEMO_MODE_ENV_VAR in run.message
