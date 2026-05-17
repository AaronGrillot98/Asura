"""Docker-orchestrated runner path tests.

Exercises the decision tree in `runner.run_scanner`:
  1. ASURA_DEMO_MODE=1 -> demo
  2. ASURA_PREFER_DOCKER=1 + image present + docker on PATH -> Docker
  3. Local binary on PATH -> subprocess
  4. Docker fallback when binary missing
  5. Neither -> failed with install hint
"""
from __future__ import annotations

import json
import os
from unittest import mock

from app.repositories import reset_repos
from app.services.runner import (
    DEMO_MODE_ENV_VAR,
    DOCKER_MOUNT_POINT,
    PREFER_DOCKER_ENV_VAR,
    _build_docker_argv,
    _looks_like_filesystem_target,
    run_scanner,
)
from app.services.tool_registry import load_arsenal


SEMGREP_OUTPUT = json.dumps({
    "results": [{
        "check_id": "asura.test.rule",
        "path": "/scan/src/x.py",
        "start": {"line": 1},
        "extra": {"severity": "WARNING", "message": "test"},
    }]
})


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in {DEMO_MODE_ENV_VAR, PREFER_DOCKER_ENV_VAR}}


def _fake_completed(stdout: str, returncode: int = 0):
    result = mock.MagicMock()
    result.stdout = stdout
    result.stderr = ""
    result.returncode = returncode
    return result


def _tool(scanner: str):
    arsenal = load_arsenal()
    return next(t for t in arsenal.tools if t.id == scanner)


def test_looks_like_filesystem_target() -> None:
    assert _looks_like_filesystem_target("/home/user/repo")
    assert _looks_like_filesystem_target("./local")
    assert _looks_like_filesystem_target("../sibling/repo")
    assert _looks_like_filesystem_target("C:\\Users\\me\\code")
    assert not _looks_like_filesystem_target("https://flightops.acme.example")
    assert not _looks_like_filesystem_target("flightops.acme.example")
    assert not _looks_like_filesystem_target("ghcr.io/acme/img:latest")


def test_build_docker_argv_url_target_no_mount() -> None:
    tool = _tool("nuclei")
    argv, used_target = _build_docker_argv(
        tool=tool,
        target="https://flightops.acme.example",
        inner_argv=["nuclei", "-u", "https://flightops.acme.example", "-jsonl"],
    )
    assert argv[0] == "docker"
    assert argv[1] == "run"
    assert "-v" not in argv  # url target: no bind-mount
    assert tool.docker_image in argv
    assert used_target == "https://flightops.acme.example"


def test_build_docker_argv_filesystem_target_mounts_and_rewrites(tmp_path) -> None:
    tool = _tool("semgrep")
    target_dir = tmp_path / "repo"
    target_dir.mkdir()
    argv, used_target = _build_docker_argv(
        tool=tool,
        target=str(target_dir),
        inner_argv=["semgrep", "-r", str(target_dir), "--json"],
    )
    assert "-v" in argv
    mount_idx = argv.index("-v")
    assert argv[mount_idx + 1].endswith(f"{DOCKER_MOUNT_POINT}:ro")
    # Target rewritten to the mount point.
    assert used_target == DOCKER_MOUNT_POINT
    assert DOCKER_MOUNT_POINT in argv


def test_prefer_docker_uses_container_even_when_binary_present() -> None:
    repos = reset_repos()
    env = _clean_env()
    env[PREFER_DOCKER_ENV_VAR] = "1"
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), \
         mock.patch("app.services.runner.subprocess.run", return_value=_fake_completed(SEMGREP_OUTPUT)) as run_mock:
        run = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="https://flightops.acme.example",
            mode="passive",
            authorized=False,
            repos=repos,
        )
    # The argv that subprocess.run received should start with `docker run`.
    args_called = run_mock.call_args[0][0]
    assert args_called[:2] == ["docker", "run"]
    assert "via Docker image" in run.message


def test_docker_fallback_when_local_binary_missing() -> None:
    repos = reset_repos()
    env = _clean_env()
    def which_mock(name):
        # local binary missing, docker present
        return "/usr/bin/docker" if name == "docker" else None
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", side_effect=which_mock), \
         mock.patch("app.services.runner.subprocess.run", return_value=_fake_completed(SEMGREP_OUTPUT)) as run_mock:
        run = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="https://flightops.acme.example",
            mode="passive",
            authorized=False,
            repos=repos,
        )
    args_called = run_mock.call_args[0][0]
    assert args_called[:2] == ["docker", "run"]
    assert "local binary not installed" in run.message


def test_local_binary_preferred_over_docker_by_default() -> None:
    repos = reset_repos()
    env = _clean_env()
    def which_mock(name):
        if name == "semgrep":
            return "/usr/local/bin/semgrep"
        if name == "docker":
            return "/usr/bin/docker"
        return None
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", side_effect=which_mock), \
         mock.patch("app.services.runner.subprocess.run", return_value=_fake_completed(SEMGREP_OUTPUT)) as run_mock:
        run = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="https://flightops.acme.example",
            mode="passive",
            authorized=False,
            repos=repos,
        )
    args_called = run_mock.call_args[0][0]
    # First arg is the local executable, NOT `docker`.
    assert args_called[0] != "docker"
    assert "via local binary" in run.message


def test_failed_when_neither_binary_nor_docker_present() -> None:
    repos = reset_repos()
    env = _clean_env()
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value=None):
        run = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="https://flightops.acme.example",
            mode="passive",
            authorized=False,
            repos=repos,
        )
    assert run.status == "failed"
    # Install hint surfaces both the binary path and the Docker fallback.
    assert "Docker" in run.message or "docker" in run.message
    assert DEMO_MODE_ENV_VAR in run.message
