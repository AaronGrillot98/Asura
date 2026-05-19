"""HAR (HTTP Archive) ingestion tests.

The HAR importer is the bridge between manual proxy browsing (Burp,
mitmproxy, DevTools) and Asura's target inventory. These tests cover
the contract:

1. **Parsing** — valid HAR documents extract endpoints + hosts +
   params; malformed JSON raises a typed error; non-HTTP schemes are
   skipped, not crashed on.
2. **Target creation** — one Target per unique host, deduped against
   the project's existing targets so re-importing is idempotent.
3. **Scope respect** — when `respect_scope=True`, hosts outside the
   project's allowed_domains are skipped (with a recorded reason).
4. **Status histogram + auth-required detection** — 401/403 surface
   on `auth_required_paths`; status codes bucket into `Nxx` keys.
5. **JS file inventory** — both content-type and `.js` suffix detection.
6. **API surface** — the route accepts multipart uploads, rejects
   empty/over-size files, and 404s on unknown projects.
"""
from __future__ import annotations

import io
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import (
    Project,
    ScopeRules,
)
from app.repositories import get_repos, reset_repos
from app.services.har_import import (
    HarParseError,
    ingest_har,
    parse_har_bytes,
)


client = TestClient(app)


def _entry(
    *,
    url: str,
    method: str = "GET",
    status: int = 200,
    mime: str = "text/html",
    query: list[dict[str, str]] | None = None,
    post_params: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {"method": method, "url": url}
    if query is not None:
        request["queryString"] = query
    if post_params is not None:
        request["postData"] = {"params": post_params}
    return {
        "startedDateTime": "2026-05-18T00:00:00Z",
        "request": request,
        "response": {
            "status": status,
            "content": {"mimeType": mime},
        },
    }


def _har(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"log": {"version": "1.2", "creator": {"name": "test"}, "entries": entries}}


def _serialize(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc).encode("utf-8")


@pytest.fixture(autouse=True)
def _reset():
    reset_repos()
    yield


# ---- parse_har_bytes -------------------------------------------------------


def test_parse_har_bytes_accepts_valid_document() -> None:
    doc = _har([_entry(url="https://example.com/")])
    parsed = parse_har_bytes(_serialize(doc))
    assert parsed["log"]["entries"][0]["request"]["url"] == "https://example.com/"


def test_parse_har_bytes_rejects_non_json() -> None:
    with pytest.raises(HarParseError):
        parse_har_bytes(b"not json at all")


def test_parse_har_bytes_rejects_array_root() -> None:
    with pytest.raises(HarParseError):
        parse_har_bytes(b'[{"log": {}}]')


def test_parse_har_bytes_rejects_missing_entries() -> None:
    with pytest.raises(HarParseError):
        parse_har_bytes(_serialize({"log": {"version": "1.2"}}))


# ---- ingest_har: target creation ------------------------------------------


def _demo_project() -> Project:
    return get_repos().projects.get("demo")  # type: ignore[return-value]


def test_ingest_creates_one_target_per_unique_host() -> None:
    doc = _har([
        _entry(url="https://acme.example/login"),
        _entry(url="https://acme.example/dashboard"),
        _entry(url="https://api.acme.example/v1/me"),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    hosts = {t.value for t in summary.new_targets}
    assert hosts == {"acme.example", "api.acme.example"}
    # Each created target is unauthorized by default; user opts in for
    # active scans via the scope rules.
    for t in summary.new_targets:
        assert t.authorized is False
        assert t.kind == "domain"


def test_ingest_is_idempotent_on_existing_hosts() -> None:
    repos = get_repos()
    project = _demo_project()
    doc = _har([_entry(url="https://acme.example/")])
    first = ingest_har(repos=repos, project=project, har_doc=doc)
    assert len(first.new_targets) == 1
    second = ingest_har(repos=repos, project=project, har_doc=doc)
    # Host already a target → no new target created on re-import.
    assert second.new_targets == []
    # But the endpoint summary is still produced.
    assert second.entries_processed == 1


def test_ingest_skips_non_http_schemes() -> None:
    doc = _har([
        _entry(url="https://acme.example/"),
        _entry(url="data:image/png;base64,iVBORw0KGgo="),
        _entry(url="ws://acme.example/socket"),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    assert summary.entries_processed == 1
    assert any("non-http scheme" in s for s in summary.skipped)


# ---- endpoint catalog + params --------------------------------------------


def test_endpoint_catalog_groups_by_method_host_path() -> None:
    doc = _har([
        _entry(url="https://acme.example/api/users?id=1", query=[{"name": "id", "value": "1"}]),
        _entry(url="https://acme.example/api/users?id=2", query=[{"name": "id", "value": "2"}]),
        _entry(url="https://acme.example/api/users", method="POST", post_params=[{"name": "name", "value": "x"}]),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    by_key = {(e.method, e.path): e for e in summary.endpoints}
    get_users = by_key[("GET", "/api/users")]
    assert get_users.seen_count == 2
    assert "id" in get_users.param_names
    post_users = by_key[("POST", "/api/users")]
    assert post_users.seen_count == 1
    assert "name" in post_users.param_names


def test_endpoint_catalog_dedupes_param_names_across_hits() -> None:
    doc = _har([
        _entry(url="https://acme.example/x?a=1", query=[{"name": "a", "value": "1"}]),
        _entry(url="https://acme.example/x?a=2", query=[{"name": "a", "value": "2"}]),
        _entry(url="https://acme.example/x?b=3", query=[{"name": "b", "value": "3"}]),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    endpoint = next(e for e in summary.endpoints if e.path == "/x")
    assert sorted(endpoint.param_names) == ["a", "b"]
    assert endpoint.seen_count == 3


# ---- status histogram + auth-required -------------------------------------


def test_status_histogram_buckets_by_nxx() -> None:
    doc = _har([
        _entry(url="https://acme.example/a", status=200),
        _entry(url="https://acme.example/b", status=201),
        _entry(url="https://acme.example/c", status=404),
        _entry(url="https://acme.example/d", status=500),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    assert summary.status_buckets == {"2xx": 2, "4xx": 1, "5xx": 1}


def test_auth_required_paths_surface_401_and_403() -> None:
    doc = _har([
        _entry(url="https://acme.example/admin", status=401),
        _entry(url="https://acme.example/billing", method="POST", status=403),
        _entry(url="https://acme.example/public", status=200),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    assert "GET acme.example/admin" in summary.auth_required_paths
    assert "POST acme.example/billing" in summary.auth_required_paths
    assert all("public" not in p for p in summary.auth_required_paths)


# ---- JS file detection ----------------------------------------------------


def test_js_files_detected_via_mime_or_suffix() -> None:
    doc = _har([
        _entry(url="https://cdn.example/app.js", mime="application/javascript"),
        _entry(url="https://cdn.example/lib.min.js", mime="text/plain"),  # suffix-only
        _entry(url="https://example.com/data.json", mime="application/json"),
    ])
    summary = ingest_har(repos=get_repos(), project=_demo_project(), har_doc=doc)
    assert "https://cdn.example/app.js" in summary.js_files
    assert "https://cdn.example/lib.min.js" in summary.js_files
    assert all("data.json" not in j for j in summary.js_files)


# ---- scope respect --------------------------------------------------------


def _project_with_scope(rules: ScopeRules) -> Project:
    project = _demo_project()
    return project.model_copy(update={"scope_rules": rules})


def test_respect_scope_skips_out_of_scope_hosts() -> None:
    project = _project_with_scope(ScopeRules(
        domains=["acme.example"],
        urls=[],
        cidrs=[],
        repos=[],
        containers=[],
    ))
    doc = _har([
        _entry(url="https://acme.example/"),
        _entry(url="https://api.acme.example/v1/"),   # subdomain — allowed
        _entry(url="https://google-analytics.com/x"),  # out of scope
    ])
    summary = ingest_har(repos=get_repos(), project=project, har_doc=doc, respect_scope=True)
    assert set(summary.hosts) == {"acme.example", "api.acme.example"}
    assert any("out of scope" in s for s in summary.skipped)
    assert summary.respect_scope is True


def test_respect_scope_off_imports_everything() -> None:
    project = _project_with_scope(ScopeRules(
        domains=["acme.example"], urls=[], cidrs=[], repos=[], containers=[],
    ))
    doc = _har([
        _entry(url="https://acme.example/"),
        _entry(url="https://google-analytics.com/x"),
    ])
    summary = ingest_har(repos=get_repos(), project=project, har_doc=doc, respect_scope=False)
    assert "google-analytics.com" in summary.hosts


# ---- API end-to-end -------------------------------------------------------


def _post_har(doc: dict[str, Any], *, respect_scope: bool = False, project_id: str = "demo"):
    blob = _serialize(doc)
    qs = "?respect_scope=true" if respect_scope else ""
    return client.post(
        f"/api/projects/{project_id}/imports/har{qs}",
        files={"file": ("capture.har", io.BytesIO(blob), "application/json")},
    )


def test_api_import_succeeds_and_returns_summary() -> None:
    response = _post_har(_har([
        _entry(url="https://acme.example/login"),
        _entry(url="https://acme.example/dashboard"),
    ]))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["project_id"] == "demo"
    assert body["entries_processed"] == 2
    assert "acme.example" in body["hosts"]
    assert len(body["new_targets"]) == 1


def test_api_import_rejects_empty_file() -> None:
    response = client.post(
        "/api/projects/demo/imports/har",
        files={"file": ("empty.har", io.BytesIO(b""), "application/json")},
    )
    assert response.status_code == 400


def test_api_import_rejects_malformed_har() -> None:
    response = client.post(
        "/api/projects/demo/imports/har",
        files={"file": ("garbage.har", io.BytesIO(b"definitely not json"), "application/json")},
    )
    assert response.status_code == 400
    assert "not valid JSON" in response.json()["detail"]


def test_api_import_404s_for_unknown_project() -> None:
    response = client.post(
        "/api/projects/does-not-exist/imports/har",
        files={"file": ("c.har", io.BytesIO(_serialize(_har([]))), "application/json")},
    )
    assert response.status_code == 404


def test_api_import_with_respect_scope_filters_hosts() -> None:
    # Mutate the demo project's scope rules in-place so the request flows
    # through the same project lookup the API uses.
    repos = get_repos()
    project = repos.projects.get("demo")
    assert project is not None
    repos.projects.update(project.model_copy(update={
        "scope_rules": ScopeRules(
            domains=["acme.example"], urls=[], cidrs=[],
            repos=[], containers=[],
        ),
    }))
    response = _post_har(
        _har([
            _entry(url="https://acme.example/"),
            _entry(url="https://google-analytics.com/x"),
        ]),
        respect_scope=True,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "acme.example" in body["hosts"]
    assert "google-analytics.com" not in body["hosts"]
    assert body["respect_scope"] is True
