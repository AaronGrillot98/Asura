import os
from unittest import mock

from app.services.runner import REAL_SCANNERS_ENV_VAR, real_scanners_enabled, run_scanner


def test_default_runner_is_demo_no_subprocess() -> None:
    # Ensure the env var is not set for this test.
    env = {k: v for k, v in os.environ.items() if k != REAL_SCANNERS_ENV_VAR}
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.subprocess.run") as run_mock:
        result = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="git://demo/asura-lab",
            mode="passive",
            authorized=False,
        )
    assert run_mock.called is False
    assert result.is_demo_data is True
    assert result.status == "completed"
    assert "DEMO MODE" in result.message


def test_real_scanners_flag_toggle() -> None:
    with mock.patch.dict(os.environ, {REAL_SCANNERS_ENV_VAR: "1"}):
        assert real_scanners_enabled() is True
    with mock.patch.dict(os.environ, {REAL_SCANNERS_ENV_VAR: "0"}):
        assert real_scanners_enabled() is False


def test_blocked_modes_return_blocked_status() -> None:
    # nmap is not allowed in passive mode.
    result = run_scanner(
        project_id="demo",
        scanner="nmap",
        target="10.10.7.20",
        mode="passive",
        authorized=False,
    )
    assert result.status == "blocked"


def test_invalid_target_is_rejected_before_demo_runner() -> None:
    result = run_scanner(
        project_id="demo",
        scanner="semgrep",
        target="-rf /tmp",
        mode="passive",
        authorized=False,
    )
    assert result.status == "blocked"
    assert "control" in result.message or "option" in result.message
