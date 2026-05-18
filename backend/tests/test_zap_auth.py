"""ZAP authenticated scanning.

Parity with the nuclei/httpx auth-profile flow: a single `AuthProfile`
row drives the credential injection for ZAP via a generated `--hook`
script that wires ZAP Replacer rules at daemon-start.

We cover:

- Unit-level: hook-script generation for each AuthType produces a valid
  Python module with one `zap.replacer.add_rule(...)` call per header.
- File hygiene: write/delete pair lives under an isolated `auth/` dir
  with 0o600 perms; deletion happens automatically when the API scan
  loop's `finally` runs.
- Wiring: `_auth_extras_for("zap", ...)` returns the `--hook` arg + the
  bind-mount, and `_rewrite_paths_for_mounts` swaps the host path to the
  container path on the Docker code path.
- End-to-end: POST /api/scans with `scanners=["zap"]` and a real auth
  profile id appends `--hook <abs_path>` to the argv; non-auth-capable
  scanners are unaffected.
"""
from __future__ import annotations

import ast
import os
import stat
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.repositories import reset_repos
from app.services import zap_auth
from app.services.runner import _rewrite_paths_for_mounts


client = TestClient(app)


def _isolated_auth_dir(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "ASURA_AUTH_DIR"}
    env["ASURA_AUTH_DIR"] = str(tmp_path)
    return env


def _create_profile(env: dict[str, str], **overrides) -> dict:
    payload = {
        "name": "Acme staging bearer",
        "auth_type": "bearer",
        "token": "zap-test-token-9999",
        "description": "ZAP authenticated scan",
        "target_match": "https://staging.acme.example",
    }
    payload.update(overrides)
    reset_repos()
    with mock.patch.dict(os.environ, env, clear=True):
        return client.post("/api/auth-profiles", json=payload).json()


# ---- Unit: hook generation -------------------------------------------------


def test_generate_hook_script_bearer_includes_authorization_rule() -> None:
    headers = [("Authorization", "Bearer tok-12345")]
    src = zap_auth.generate_hook_script(headers)
    # Parses as valid Python.
    ast.parse(src)
    # Calls add_rule with the expected name + value.
    assert "zap.replacer.add_rule" in src
    assert "'Authorization'" in src
    assert "'Bearer tok-12345'" in src
    assert "matchtype='REQ_HEADER'" in src
    assert "enabled=True" in src


def test_generate_hook_script_basic_emits_basic_authorization() -> None:
    # Whatever the auth_profile_service.decrypted_headers() returned —
    # the hook should embed it verbatim.
    headers = [("Authorization", "Basic YWxpY2U6cEBzc3cwcmQh")]
    src = zap_auth.generate_hook_script(headers)
    assert "'Basic YWxpY2U6cEBzc3cwcmQh'" in src
    assert src.count("zap.replacer.add_rule") == 1


def test_generate_hook_script_custom_header_escapes_safely() -> None:
    # Values with quotes + backslashes must be embedded via repr() so the
    # hook script remains valid Python.
    headers = [("X-Acme-Token", "weird\"value\\with\nbreaks")]
    src = zap_auth.generate_hook_script(headers)
    ast.parse(src)
    assert "'X-Acme-Token'" in src
    # The replacement must round-trip through ast.literal_eval back to
    # the original value.
    tree = ast.parse(src)
    replacement_literal = None
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "replacement":
            replacement_literal = ast.literal_eval(node.value)
            break
    assert replacement_literal == "weird\"value\\with\nbreaks"


def test_generate_hook_script_cookie_uses_cookie_header() -> None:
    headers = [("Cookie", "sessionid=abc123; csrftoken=xyz789")]
    src = zap_auth.generate_hook_script(headers)
    assert "'Cookie'" in src
    assert "'sessionid=abc123; csrftoken=xyz789'" in src


def test_generate_hook_script_multiple_headers_emits_one_rule_each() -> None:
    headers = [("Authorization", "Bearer a"), ("X-Tenant", "acme")]
    src = zap_auth.generate_hook_script(headers)
    assert src.count("zap.replacer.add_rule") == 2


def test_generate_hook_script_empty_headers_emits_noop_body() -> None:
    src = zap_auth.generate_hook_script([])
    ast.parse(src)
    assert "zap.replacer.add_rule" not in src
    # Must still expose zap_started so zap-baseline doesn't crash on import.
    assert "def zap_started(zap, target):" in src
    assert "pass" in src


# ---- Unit: file lifecycle --------------------------------------------------


def test_write_hook_file_lands_under_auth_dir_with_tight_perms(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        path = zap_auth.write_hook_file([("Authorization", "Bearer xyz")])
    assert path.exists()
    assert path.is_file()
    assert path.parent == tmp_path / "zap_hooks"
    if os.name != "nt":  # chmod is a no-op on Windows
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"expected 0o600 perms, got {oct(mode)}"


def test_delete_hook_file_is_idempotent(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        path = zap_auth.write_hook_file([("Authorization", "Bearer xyz")])
    zap_auth.delete_hook_file(path)
    assert not path.exists()
    # Calling again must not raise.
    zap_auth.delete_hook_file(path)


# ---- Path rewriting for the Docker mount -----------------------------------


def test_hook_path_is_rewritten_to_container_path_for_docker(tmp_path: Path) -> None:
    """When the docker runner mounts auth/zap_hooks/ → /asura-zap-hooks, the
    runner's path-rewriter must swap the host path in argv for the
    container-side path so zap-baseline.py finds the file inside."""
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        hook = zap_auth.write_hook_file([("Authorization", "Bearer xyz")])
    argv = ["zap-baseline.py", "-t", "https://x", "--hook", str(hook)]
    rewritten = _rewrite_paths_for_mounts(
        argv,
        [(str(hook.parent), zap_auth.HOOK_MOUNT_DIR)],
    )
    # The flag itself is untouched; only the file path gets swapped.
    assert "--hook" in rewritten
    hook_arg = rewritten[rewritten.index("--hook") + 1]
    assert hook_arg == f"{zap_auth.HOOK_MOUNT_DIR}/{hook.name}"


# ---- API end-to-end --------------------------------------------------------


def test_zap_scan_with_auth_profile_appends_hook_flag(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    created = _create_profile(env)
    captured_hooks: list[Path] = []

    def fake_run(argv, *args, **kwargs):
        # Capture the hook file before the API's finally{} deletes it.
        if "--hook" in argv:
            captured_hooks.append(Path(argv[argv.index("--hook") + 1]))
        return mock.MagicMock(stdout='{"site":[]}', stderr="", returncode=0)

    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/zap-baseline.py"), \
         mock.patch("app.services.runner.subprocess.run", side_effect=fake_run) as run_mock:
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "https://flightops.acme.example",
                "scanners": ["zap"],
                "mode": "active",
                "authorized_scope": "https://flightops.acme.example",
                "explicit_authorization": True,
                "auth_profile_id": created["id"],
            },
        )

    assert response.status_code == 200, response.text
    argv = run_mock.call_args[0][0]
    assert "--hook" in argv, f"expected --hook in argv: {argv}"
    # The hook flag is followed by an absolute path under our test auth dir.
    hook_path = Path(argv[argv.index("--hook") + 1])
    assert str(tmp_path) in str(hook_path), hook_path
    # The hook file we captured during subprocess.run mock contained the secret.
    assert captured_hooks, "subprocess.run was never called with --hook"
    # After the request finished, the API cleaned up the hook file.
    assert not captured_hooks[0].exists(), \
        "hook file containing the secret was not deleted after the scan"


def test_zap_scan_without_auth_profile_emits_no_hook_flag(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    reset_repos()
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/zap-baseline.py"), \
         mock.patch("app.services.runner.subprocess.run") as run_mock:
        run_mock.return_value = mock.MagicMock(stdout='{"site":[]}', stderr="", returncode=0)
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "https://flightops.acme.example",
                "scanners": ["zap"],
                "mode": "passive",
            },
        )
    assert response.status_code == 200, response.text
    assert "--hook" not in run_mock.call_args[0][0]


def test_zap_scan_with_unknown_auth_profile_returns_400(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    reset_repos()
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "https://flightops.acme.example",
                "scanners": ["zap"],
                "mode": "active",
                "authorized_scope": "https://flightops.acme.example",
                "explicit_authorization": True,
                "auth_profile_id": "auth-does-not-exist",
            },
        )
    assert response.status_code == 400
    assert "Unknown auth profile" in response.json()["detail"]


def test_hook_file_cleanup_runs_even_on_runner_exception(tmp_path: Path) -> None:
    """If `run_scanner` raises, the API's finally{} must still wipe the
    generated hook file. Otherwise secrets would linger on disk after a
    crash."""
    env = _isolated_auth_dir(tmp_path)
    created = _create_profile(env)
    captured_hooks: list[Path] = []

    def boom(argv, *args, **kwargs):
        if "--hook" in argv:
            captured_hooks.append(Path(argv[argv.index("--hook") + 1]))
        raise RuntimeError("simulated scanner crash")

    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/zap-baseline.py"), \
         mock.patch("app.services.runner.subprocess.run", side_effect=boom):
        # TestClient re-raises unhandled exceptions; that's fine — we only
        # care that the finally{} fired *before* the exception left the API.
        try:
            client.post(
                "/api/scans",
                json={
                    "project_id": "demo",
                    "target": "https://flightops.acme.example",
                    "scanners": ["zap"],
                    "mode": "active",
                    "authorized_scope": "https://flightops.acme.example",
                    "explicit_authorization": True,
                    "auth_profile_id": created["id"],
                },
            )
        except RuntimeError:
            pass  # Expected — we crashed the subprocess.

    assert captured_hooks, "subprocess.run was never called with --hook"
    assert not captured_hooks[0].exists(), \
        f"hook file survived a crashed scan: {captured_hooks[0]}"
