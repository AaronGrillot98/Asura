import os
from unittest import mock

from app.services.runner import DEMO_MODE_ENV_VAR, demo_mode_enabled, run_scanner


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != DEMO_MODE_ENV_VAR}


def test_default_runner_is_real_execution() -> None:
    """Without ASURA_DEMO_MODE, the runner attempts a real subprocess.

    We don't require the binary to be installed for the test — we just
    confirm the demo path is not taken. The runner returns a `failed`
    status with the install hint when the binary is missing.
    """
    env = _clean_env()
    with mock.patch.dict(os.environ, env, clear=True):
        result = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="git://demo/asura-lab",
            mode="passive",
            authorized=False,
        )
    # Real attempt: never marked demo data even when the binary is missing.
    assert result.is_demo_data is False
    assert "DEMO MODE" not in result.message
    # Either it ran (semgrep installed locally) or it failed for a real reason.
    assert result.status in {"completed", "failed"}


def test_demo_mode_env_var_returns_seeded_run() -> None:
    with mock.patch.dict(os.environ, {DEMO_MODE_ENV_VAR: "1"}), \
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


def test_demo_mode_helper_toggle() -> None:
    with mock.patch.dict(os.environ, {DEMO_MODE_ENV_VAR: "1"}):
        assert demo_mode_enabled() is True
    with mock.patch.dict(os.environ, {DEMO_MODE_ENV_VAR: "0"}):
        assert demo_mode_enabled() is False


def test_blocked_modes_return_blocked_status() -> None:
    result = run_scanner(
        project_id="demo",
        scanner="nmap",
        target="10.10.7.20",
        mode="passive",
        authorized=False,
    )
    assert result.status == "blocked"
    assert "nmap is not permitted" in result.message


def test_invalid_target_is_rejected_before_runner_dispatch() -> None:
    result = run_scanner(
        project_id="demo",
        scanner="semgrep",
        target="-rf /tmp",
        mode="passive",
        authorized=False,
    )
    assert result.status == "blocked"
    assert "control" in result.message or "option" in result.message


def test_force_demo_kwarg_overrides_env() -> None:
    env = _clean_env()
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.subprocess.run") as run_mock:
        result = run_scanner(
            project_id="demo",
            scanner="semgrep",
            target="git://demo/asura-lab",
            mode="passive",
            authorized=False,
            force_demo=True,
        )
    assert run_mock.called is False
    assert result.is_demo_data is True
