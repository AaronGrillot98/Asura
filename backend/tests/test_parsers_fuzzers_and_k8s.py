"""Slice 10 — fuzzers + K8s/cloud parsers + wordlist plumbing."""
from __future__ import annotations

import json
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.repositories import reset_repos
from app.services.parsers import (
    dirsearch,
    ffuf,
    gobuster,
    kube_bench,
    kube_score,
    kubescape,
    prowler,
)
from app.services.runner import build_command
from app.services.tool_registry import load_arsenal


client = TestClient(app)


def _assert_minimum(findings, *, scanner: str) -> None:
    assert findings, f"{scanner} parser produced no findings"
    for f in findings:
        assert f.scanner == scanner
        assert f.evidence
        assert f.title
        assert f.severity is not None


# ---------- Parsers --------------------------------------------------------


def test_ffuf_parser() -> None:
    raw = {
        "results": [
            {"url": "https://flightops.acme.example/admin", "status": 200, "length": 1234, "input": {"FUZZ": "admin"}},
            {"url": "https://flightops.acme.example/login", "status": 302, "length": 256},
        ],
    }
    _assert_minimum(ffuf.parse(raw), scanner="ffuf")


def test_gobuster_parser_text() -> None:
    raw = (
        "/admin                (Status: 200) [Size: 1234]\n"
        "Found: /login        (Status: 302) [Size: 256]\n"
    )
    _assert_minimum(gobuster.parse(raw), scanner="gobuster")


def test_dirsearch_parser_text() -> None:
    raw = (
        "[14:23:45] 200 -    1KB - /admin/\n"
        "[14:23:46] 301 -    256B - /login\n"
    )
    _assert_minimum(dirsearch.parse(raw), scanner="dirsearch")


def test_kube_bench_parser_filters_pass() -> None:
    raw = {
        "Controls": [{
            "id": "1",
            "version": "1.20",
            "tests": [{
                "section": "1.1",
                "results": [
                    {"test_number": "1.1.1", "test_desc": "Ensure that the API server pod specification file permissions are restrictive", "status": "FAIL", "remediation": "Run chmod 644 ..."},
                    {"test_number": "1.1.2", "test_desc": "Some passing check", "status": "PASS", "remediation": ""},
                    {"test_number": "1.1.3", "test_desc": "Some warning", "status": "WARN", "remediation": "Investigate"},
                ],
            }],
        }],
        "totals": {"total_pass": 1, "total_fail": 1},
    }
    out = kube_bench.parse(raw)
    # PASS records should be filtered out.
    ids = [f.affected_component for f in out]
    assert "CIS 1.1.1" in ids
    assert "CIS 1.1.3" in ids
    assert "CIS 1.1.2" not in ids


def test_kubescape_parser_handles_results_shape() -> None:
    raw = {
        "results": [
            {
                "resourceID": "Deployment/nginx",
                "controls": [
                    {
                        "controlID": "C-0001",
                        "name": "Forbidden Container Registries",
                        "severity": "high",
                        "status": {"status": "failed"},
                        "description": "Container image from forbidden registry.",
                        "remediation": "Use a trusted registry.",
                    }
                ],
            }
        ],
    }
    _assert_minimum(kubescape.parse(raw), scanner="kubescape")


def test_kube_score_parser_filters_passing_grades() -> None:
    raw = [
        {
            "object_name": "Deployment/nginx",
            "file_name": "deployment.yaml",
            "checks": [
                {"check": {"name": "container-image-tag"}, "grade": 1, "comments": [{"summary": "image tag is :latest"}]},
                {"check": {"name": "container-resources"}, "grade": 10, "comments": []},  # passing — ignored
            ],
        }
    ]
    out = kube_score.parse(raw)
    assert len(out) == 1
    assert out[0].title.startswith("container-image-tag")


def test_prowler_parser_filters_pass() -> None:
    raw = [
        {
            "check_id": "iam_password_policy_minimum_length_14",
            "service_name": "iam",
            "status": "FAIL",
            "severity": "high",
            "resource_id": "AccountPasswordPolicy",
            "region": "us-east-1",
            "description": "Password policy minimum length is below 14.",
            "remediation": {"recommendation": {"text": "Set minimum length to 14."}},
        },
        {
            "check_id": "iam_root_access_keys",
            "service_name": "iam",
            "status": "PASS",  # ignored
            "severity": "high",
            "resource_id": "Root",
        },
    ]
    out = prowler.parse(raw)
    assert len(out) == 1
    assert out[0].title.startswith("iam ·")


# ---------- Wordlist + provider plumbing -----------------------------------


def test_build_command_substitutes_wordlist_and_target() -> None:
    args = build_command("ffuf", "https://x.example", "active", {"wordlist": "/tmp/wl.txt"})
    assert "/tmp/wl.txt" in args
    assert any(a.endswith("/FUZZ") for a in args)
    assert "{{wordlist}}" not in " ".join(args)


def test_build_command_substitutes_provider() -> None:
    args = build_command("prowler", "aws", "passive", {"provider": "aws"})
    assert "aws" in args
    assert "{{provider}}" not in " ".join(args)


def test_scan_with_fuzzer_rejects_when_no_wordlist_substitution() -> None:
    """The runner refuses to spawn if a placeholder is unresolved."""
    reset_repos()
    import os
    env = {k: v for k, v in os.environ.items() if k not in {"ASURA_DEMO_MODE"}}
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch("app.services.runner.shutil.which", return_value="/usr/bin/ffuf"):
        response = client.post(
            "/api/scans",
            json={
                "project_id": "demo",
                "target": "https://flightops.acme.example",
                "scanners": ["ffuf"],
                "mode": "active",
                "authorized_scope": "https://flightops.acme.example",
                "explicit_authorization": True,
                # NOTE: no wordlist — the runner should refuse before spawning.
            },
        )
    assert response.status_code == 200
    runs = response.json()
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert "wordlist" in runs[0]["message"].lower()


# ---------- Arsenal contract reflects graduation ---------------------------


def test_all_promoted_tools_appear_as_runners() -> None:
    arsenal = load_arsenal()
    by_id = {t.id: t for t in arsenal.tools}
    for tid in ("ffuf", "gobuster", "dirsearch", "kube-bench", "kubescape", "kube-score", "prowler"):
        assert by_id[tid].integration_status == "runner", f"{tid} should be a runner now"
        assert by_id[tid].commands, f"{tid} should have command templates"
        assert by_id[tid].executable, f"{tid} should have an executable"
        assert by_id[tid].docker_image, f"{tid} should have a Docker image registered"
