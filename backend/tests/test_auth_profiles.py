"""Auth profiles — encrypted storage, secret masking, runner header injection."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.repositories import reset_repos
from app.services.auth_profile_service import AuthProfileService


client = TestClient(app)


def _isolated_auth_dir(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "ASURA_AUTH_DIR"}
    env["ASURA_AUTH_DIR"] = str(tmp_path)
    return env


def _create(env: dict[str, str], **overrides) -> dict:
    payload = {
        "name": "Acme staging bearer",
        "auth_type": "bearer",
        "token": "abc-very-secret-12345",
        "description": "Round-tripping bearer token",
        "target_match": "https://staging.acme.example",
    }
    payload.update(overrides)
    reset_repos()
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.post("/api/auth-profiles", json=payload)
    return response.json() if response.status_code < 400 else {"_status": response.status_code, "_body": response.text}


def test_create_bearer_profile_returns_only_preview(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    body = _create(env)
    # The API never returns the raw token.
    assert "abc-very-secret-12345" not in json.dumps(body)
    assert body["credential_preview"] == "…2345"
    assert body["auth_type"] == "bearer"
    assert body["id"].startswith("auth-")


def test_create_requires_type_specific_secret_field(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    body = _create(env, token=None)
    # Bearer profile without token → 400.
    assert body.get("_status") == 400


def test_basic_profile_round_trip_produces_authorization_header(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    payload = {
        "name": "Acme prod basic",
        "auth_type": "basic",
        "username": "alice",
        "password": "p@ssw0rd!",
    }
    reset_repos()
    with mock.patch.dict(os.environ, env, clear=True):
        created = client.post("/api/auth-profiles", json=payload).json()
        service = AuthProfileService(get_repos := __import__("app.repositories", fromlist=["get_repos"]).get_repos())
        headers = service.decrypted_headers(created["id"])
    name, value = headers[0]
    assert name == "Authorization"
    decoded = base64.b64decode(value.removeprefix("Basic ")).decode("utf-8")
    assert decoded == "alice:p@ssw0rd!"


def test_list_returns_preview_only(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    _create(env, token="another-secret-9999")
    with mock.patch.dict(os.environ, env, clear=True):
        rows = client.get("/api/auth-profiles").json()
    assert len(rows) >= 1
    assert "another-secret-9999" not in json.dumps(rows)


def test_delete_removes_profile_and_file(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    created = _create(env)
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.delete(f"/api/auth-profiles/{created['id']}")
        listing = client.get("/api/auth-profiles").json()
    assert response.status_code == 204
    assert all(p["id"] != created["id"] for p in listing)


def test_encrypted_file_on_disk_does_not_contain_plaintext(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    created = _create(env)
    files = list(tmp_path.rglob("*.json"))
    assert files, "an encrypted JSON file should have been written"
    for path in files:
        text = path.read_text("utf-8")
        assert "abc-very-secret-12345" not in text, f"plaintext leaked into {path}"


def test_scan_with_unknown_auth_profile_returns_400(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "https://flightops.acme.example",
                "scanners": ["nuclei"],
                "mode": "active",
                "authorized_scope": "https://flightops.acme.example",
                "explicit_authorization": True,
                "auth_profile_id": "auth-does-not-exist",
            },
        )
    assert response.status_code == 400
    assert "Unknown auth profile" in response.json()["detail"]


def test_scan_with_auth_profile_appends_authorization_header_to_nuclei(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    created = _create(env)
    env_with_auth = dict(env)
    with mock.patch.dict(os.environ, env_with_auth, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/nuclei"), \
         mock.patch("app.services.runner.subprocess.run") as run_mock:
        run_mock.return_value = mock.MagicMock(stdout="", stderr="", returncode=0)
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "https://flightops.acme.example",
                "scanners": ["nuclei"],
                "mode": "active",
                "authorized_scope": "https://flightops.acme.example",
                "explicit_authorization": True,
                "auth_profile_id": created["id"],
            },
        )
    assert response.status_code == 200, response.text
    args = run_mock.call_args[0][0]
    # The runner appended -H "Authorization: Bearer <token>".
    h_indices = [i for i, a in enumerate(args) if a == "-H"]
    assert h_indices, f"expected an -H flag in {args}"
    payloads = [args[i + 1] for i in h_indices]
    assert any(p.startswith("Authorization: Bearer ") for p in payloads)
    # The full secret is in the argv — that is expected at the runner level.
    # The point is that it's not in the API responses, not that it stays out of
    # the local subprocess argv.


def test_scan_with_auth_profile_ignored_for_non_header_scanners(tmp_path: Path) -> None:
    """semgrep doesn't accept `-H` flags — the runner should silently skip
    auth injection for it rather than corrupting the argv."""
    env = _isolated_auth_dir(tmp_path)
    created = _create(env)
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/semgrep"), \
         mock.patch("app.services.runner.subprocess.run") as run_mock:
        run_mock.return_value = mock.MagicMock(stdout='{"results":[]}', stderr="", returncode=0)
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "git://demo/asura-lab",
                "scanners": ["semgrep"],
                "mode": "passive",
                "auth_profile_id": created["id"],
            },
        )
    assert response.status_code == 200
    args = run_mock.call_args[0][0]
    assert "-H" not in args
