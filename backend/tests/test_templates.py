"""Custom Nuclei templates — upload, list, delete, scan-integration."""
from __future__ import annotations

import io
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.repositories import reset_repos
from app.services.templates_service import TemplatesService


client = TestClient(app)


GOOD_TEMPLATE = b"""\
id: asura-test-rule

info:
  name: Asura Test Rule
  author: asura-tests
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
"""


def _upload(tmp_path, content=GOOD_TEMPLATE, filename="asura-test.yaml"):
    """Upload a template using a tmp-isolated templates directory."""
    import os
    reset_repos()
    with mock.patch.dict(os.environ, {"ASURA_TEMPLATES_DIR": str(tmp_path)}):
        response = client.post(
            "/api/templates",
            files={"file": (filename, io.BytesIO(content), "application/x-yaml")},
            data={"description": "smoke", "tags": "test,demo"},
        )
    return response


def test_upload_template_returns_201_and_persists(tmp_path) -> None:
    response = _upload(tmp_path)
    assert response.status_code == 201
    body = response.json()
    assert body["id"].startswith("tpl-")
    assert body["template_id"] == "asura-test-rule"
    assert body["info_name"] == "Asura Test Rule"
    assert body["severity"] == "high"
    assert body["tags"] == ["test", "demo"]


def test_upload_rejects_non_nuclei_yaml(tmp_path) -> None:
    response = _upload(tmp_path, content=b"this: is\njust: yaml\n", filename="bad.yaml")
    assert response.status_code == 400
    assert "id" in response.json()["detail"].lower()


def test_upload_rejects_empty_file(tmp_path) -> None:
    response = _upload(tmp_path, content=b"")
    assert response.status_code == 400


def test_upload_sanitises_filename(tmp_path) -> None:
    response = _upload(tmp_path, filename="../../etc/passwd.yaml")
    assert response.status_code == 201
    body = response.json()
    # Path-separator characters get stripped via _sanitise_filename.
    assert "/" not in body["filename"]
    assert "\\" not in body["filename"]


def test_list_templates_returns_uploads(tmp_path) -> None:
    _upload(tmp_path)
    import os
    with mock.patch.dict(os.environ, {"ASURA_TEMPLATES_DIR": str(tmp_path)}):
        response = client.get("/api/templates")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) >= 1
    assert rows[0]["template_id"] == "asura-test-rule"


def test_get_template_content_returns_yaml(tmp_path) -> None:
    upload = _upload(tmp_path).json()
    import os
    with mock.patch.dict(os.environ, {"ASURA_TEMPLATES_DIR": str(tmp_path)}):
        response = client.get(f"/api/templates/{upload['id']}/content")
    assert response.status_code == 200
    assert response.content == GOOD_TEMPLATE


def test_delete_template_removes_file_and_index(tmp_path) -> None:
    upload = _upload(tmp_path).json()
    import os
    with mock.patch.dict(os.environ, {"ASURA_TEMPLATES_DIR": str(tmp_path)}):
        deletion = client.delete(f"/api/templates/{upload['id']}")
        listing = client.get("/api/templates")
    assert deletion.status_code == 204
    assert all(t["id"] != upload["id"] for t in listing.json())


def test_scan_with_template_id_passes_t_flag_to_nuclei(tmp_path) -> None:
    import os
    with mock.patch.dict(os.environ, {"ASURA_TEMPLATES_DIR": str(tmp_path), "ASURA_DEMO_MODE": ""}):
        upload = _upload(tmp_path).json()
        with mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/nuclei"), \
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
                    "template_ids": [upload["id"]],
                },
            )
        assert response.status_code == 200, response.text
        args = run_mock.call_args[0][0]
        # `-t <path>` was appended for the uploaded template.
        assert "-t" in args
        t_index = args.index("-t")
        assert upload["filename"] in args[t_index + 1]


def test_scan_with_unknown_template_id_returns_400(tmp_path) -> None:
    response = client.post(
        "/api/scans",
        json={
            "project_id": "demo",
            "target": "https://flightops.acme.example",
            "scanners": ["nuclei"],
            "mode": "active",
            "authorized_scope": "https://flightops.acme.example",
            "explicit_authorization": True,
            "template_ids": ["tpl-does-not-exist"],
        },
    )
    assert response.status_code == 400
    assert "Unknown template" in response.json()["detail"]
