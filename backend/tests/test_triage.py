"""LLM-assisted triage in PentestBrain.

The triage pipeline has three concerns; this file covers all three:

1. **Deterministic baseline** — when no LLM client is available, the brain
   still produces a sensible TriageReport (clusters by scanner+category,
   priority by severity). Every claim cites real evidence ids.

2. **LLM-mode happy path** — when a mock LLMClient returns a well-formed
   triage response, the brain surfaces it as `engine="llm"` and the
   returned items match what the LLM said.

3. **Citation guard** — when the LLM hallucinates ids that weren't in the
   input (fake finding ids, fake evidence ids, wrong types, missing
   citations), those items are DROPPED before they reach the API
   response. This is the load-bearing security property of the slice.
"""
from __future__ import annotations

import os
from typing import Any, Optional
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import Confidence, Severity
from app.repositories import get_repos, reset_repos
from app.services.llm import (
    AnthropicLLMClient,
    NullLLMClient,
    _extract_tool_input,
    get_llm_client,
)
from app.services.pentest_brain import (
    PentestBrain,
    _filter_ids,
    _validate_llm_triage,
)


client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeLLM:
    """Mock client. Returns whatever dict you initialise it with (or None)."""

    name = "fake"
    model = "fake-model-1"

    def __init__(self, response: Optional[dict[str, Any]] = None) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def triage(self, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        self.calls.append(context)
        return self._response


@pytest.fixture(autouse=True)
def _reset_repos_each_test():
    reset_repos()
    yield


def _seed_findings_or_skip():
    """The demo seed always populates several findings — these tests rely
    on that. If for some reason the repo is empty, skip."""
    repos = get_repos()
    findings = [f for f in repos.findings.list() if f.project_id == "demo"]
    if not findings:
        pytest.skip("Demo seed produced no findings; nothing to triage.")
    return repos, findings


# ---------------------------------------------------------------------------
# Deterministic baseline
# ---------------------------------------------------------------------------


def test_triage_deterministic_groups_by_scanner_and_category() -> None:
    repos, findings = _seed_findings_or_skip()
    brain = PentestBrain(repos, llm_client=NullLLMClient())
    report = brain.triage_findings("demo")
    assert report.engine == "deterministic"
    assert report.model is None
    assert report.findings_considered > 0
    assert report.claims_dropped == 0
    # At least one cluster, and every cluster cites at least one real evidence id.
    assert report.clusters, "Deterministic baseline must still produce clusters"
    real_evidence_ids = {ev.id for f in findings for ev in f.evidence}
    for cluster in report.clusters:
        assert cluster.cited_evidence_ids, f"cluster {cluster.id} has no citations"
        for ev_id in cluster.cited_evidence_ids:
            assert ev_id in real_evidence_ids, f"cluster {cluster.id} cited unknown ev {ev_id}"


def test_triage_deterministic_priority_order_is_severity_first() -> None:
    repos, _ = _seed_findings_or_skip()
    brain = PentestBrain(repos, llm_client=NullLLMClient())
    report = brain.triage_findings("demo")
    # Priority items are ranked 1..N with no duplicates.
    ranks = [p.rank for p in report.priority_order]
    assert ranks == list(range(1, len(ranks) + 1))
    # Each priority item cites at least one real evidence id.
    for item in report.priority_order:
        assert item.cited_evidence_ids, f"priority {item.rank} has no citations"


def test_triage_empty_project_returns_empty_report() -> None:
    repos = get_repos()
    brain = PentestBrain(repos, llm_client=NullLLMClient())
    report = brain.triage_findings("project-with-no-findings")
    assert report.engine == "deterministic"
    assert report.clusters == []
    assert report.priority_order == []
    assert report.findings_considered == 0


# ---------------------------------------------------------------------------
# LLM happy path
# ---------------------------------------------------------------------------


def test_triage_llm_mode_surfaces_response() -> None:
    repos, findings = _seed_findings_or_skip()
    f = findings[0]
    ev_id = f.evidence[0].id
    fake = _FakeLLM(response={
        "summary": "The mock LLM clustered everything into one group.",
        "clusters": [
            {
                "title": "All findings",
                "summary": "One big cluster.",
                "reasoning": "Mock reasoning",
                "finding_ids": [f.id],
                "cited_evidence_ids": [ev_id],
                "fix_recommendation": "Fix the root cause.",
            },
        ],
        "false_positive_candidates": [],
        "priority_order": [
            {"finding_id": f.id, "rank": 1, "reasoning": "highest severity",
             "cited_evidence_ids": [ev_id]},
        ],
    })
    brain = PentestBrain(repos, llm_client=fake)
    report = brain.triage_findings("demo")
    assert report.engine == "llm"
    assert report.model == "fake-model-1"
    assert report.claims_dropped == 0
    assert len(report.clusters) == 1
    assert report.clusters[0].title == "All findings"
    assert report.clusters[0].finding_ids == [f.id]
    assert report.priority_order[0].finding_id == f.id
    # And the brain handed the LLM the same project_id.
    assert fake.calls and fake.calls[0]["project_id"] == "demo"


def test_triage_llm_returning_none_falls_back_to_deterministic() -> None:
    repos, _ = _seed_findings_or_skip()
    brain = PentestBrain(repos, llm_client=_FakeLLM(response=None))
    report = brain.triage_findings("demo")
    assert report.engine == "deterministic"


# ---------------------------------------------------------------------------
# Citation guard (the load-bearing security property)
# ---------------------------------------------------------------------------


def test_citation_guard_drops_cluster_with_hallucinated_evidence_id() -> None:
    repos, findings = _seed_findings_or_skip()
    f = findings[0]
    fake = _FakeLLM(response={
        "summary": "hostile",
        "clusters": [
            {
                "title": "Real cluster",
                "summary": "ok",
                "reasoning": "ok",
                "finding_ids": [f.id],
                "cited_evidence_ids": [f.evidence[0].id],
            },
            {
                "title": "Fake cluster",
                "summary": "ok",
                "reasoning": "ok",
                "finding_ids": [f.id],
                "cited_evidence_ids": ["ev-hallucinated-id-12345"],  # NOT in input
            },
        ],
        "false_positive_candidates": [],
        "priority_order": [],
    })
    brain = PentestBrain(repos, llm_client=fake)
    report = brain.triage_findings("demo")
    titles = [c.title for c in report.clusters]
    assert "Real cluster" in titles
    assert "Fake cluster" not in titles, "Hallucinated evidence id must be dropped"
    assert report.claims_dropped == 1


def test_citation_guard_drops_false_positive_with_unknown_finding_id() -> None:
    repos, findings = _seed_findings_or_skip()
    f = findings[0]
    fake = _FakeLLM(response={
        "summary": "ok",
        "clusters": [],
        "false_positive_candidates": [
            {
                "finding_id": "f-does-not-exist",
                "reasoning": "Made up",
                "cited_evidence_ids": [f.evidence[0].id],  # real evidence id but unknown finding
            },
            {
                "finding_id": f.id,
                "reasoning": "Real candidate",
                "cited_evidence_ids": [f.evidence[0].id],
            },
        ],
        "priority_order": [],
    })
    brain = PentestBrain(repos, llm_client=fake)
    report = brain.triage_findings("demo")
    ids = [fp.finding_id for fp in report.false_positive_candidates]
    assert ids == [f.id]
    assert report.claims_dropped == 1


def test_citation_guard_drops_priority_with_duplicate_rank() -> None:
    repos, findings = _seed_findings_or_skip()
    f1, f2 = findings[0], findings[1] if len(findings) > 1 else findings[0]
    fake = _FakeLLM(response={
        "summary": "ok",
        "clusters": [],
        "false_positive_candidates": [],
        "priority_order": [
            {"finding_id": f1.id, "rank": 1, "reasoning": "first",
             "cited_evidence_ids": [f1.evidence[0].id]},
            {"finding_id": f2.id, "rank": 1, "reasoning": "also-first",
             "cited_evidence_ids": [f2.evidence[0].id]},
        ],
    })
    brain = PentestBrain(repos, llm_client=fake)
    report = brain.triage_findings("demo")
    # Only the first item with rank=1 should land.
    assert len(report.priority_order) == 1
    assert report.priority_order[0].finding_id == f1.id
    assert report.claims_dropped >= 1


def test_citation_guard_drops_items_with_no_citations() -> None:
    repos, findings = _seed_findings_or_skip()
    f = findings[0]
    fake = _FakeLLM(response={
        "summary": "ok",
        "clusters": [
            {
                "title": "No citations cluster",
                "summary": "x",
                "reasoning": "x",
                "finding_ids": [f.id],
                "cited_evidence_ids": [],  # forbidden
            },
        ],
        "false_positive_candidates": [
            {"finding_id": f.id, "reasoning": "x", "cited_evidence_ids": []},
        ],
        "priority_order": [
            {"finding_id": f.id, "rank": 1, "reasoning": "x", "cited_evidence_ids": []},
        ],
    })
    brain = PentestBrain(repos, llm_client=fake)
    report = brain.triage_findings("demo")
    assert report.clusters == []
    assert report.false_positive_candidates == []
    assert report.priority_order == []
    assert report.claims_dropped == 3


def test_citation_guard_handles_malformed_llm_response_gracefully() -> None:
    """The LLM might return non-dict items, wrong types, or null fields.
    None of that should crash — guard yields an empty report."""
    repos, findings = _seed_findings_or_skip()
    fake = _FakeLLM(response={
        "summary": "ok",
        "clusters": [
            "this is a string, not a dict",
            {"title": None, "finding_ids": "not-a-list", "cited_evidence_ids": None},
            None,
        ],
        "false_positive_candidates": [42, [], "nope"],
        "priority_order": [
            {"finding_id": findings[0].id, "rank": "not-an-int",
             "cited_evidence_ids": [findings[0].evidence[0].id], "reasoning": "x"},
        ],
    })
    brain = PentestBrain(repos, llm_client=fake)
    report = brain.triage_findings("demo")
    assert report.engine == "llm"
    assert report.clusters == []
    assert report.false_positive_candidates == []
    assert report.priority_order == []
    assert report.claims_dropped > 0


def test_filter_ids_strips_unknowns_and_dedupes() -> None:
    valid = {"a", "b", "c"}
    assert _filter_ids(["a", "b", "evil", "a"], valid) == ["a", "b"]
    assert _filter_ids([1, 2, "a"], valid) == ["a"]
    assert _filter_ids(None, valid) == []
    assert _filter_ids("not-a-list", valid) == []


def test_validate_llm_triage_isolates_clusters_from_fps_from_priority() -> None:
    """A cluster failing validation must not drag a valid FP / priority
    item down with it."""
    response = {
        "clusters": [
            {"title": "bad", "finding_ids": ["fake"], "cited_evidence_ids": ["ev-real"]},
        ],
        "false_positive_candidates": [
            {"finding_id": "f-real", "reasoning": "ok", "cited_evidence_ids": ["ev-real"]},
        ],
        "priority_order": [
            {"finding_id": "f-real", "rank": 1, "reasoning": "ok",
             "cited_evidence_ids": ["ev-real"]},
        ],
    }
    validated, dropped = _validate_llm_triage(
        response=response,
        valid_finding_ids={"f-real"},
        valid_evidence_ids={"ev-real"},
    )
    assert dropped == 1  # cluster dropped
    assert validated["clusters"] == []
    assert len(validated["fps"]) == 1
    assert len(validated["priority"]) == 1


# ---------------------------------------------------------------------------
# Env-var factory
# ---------------------------------------------------------------------------


def test_get_llm_client_returns_null_by_default(monkeypatch) -> None:
    monkeypatch.delenv("ASURA_LLM_TRIAGE", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = get_llm_client()
    assert isinstance(client, NullLLMClient)


def test_get_llm_client_returns_null_when_flag_set_but_no_key(monkeypatch) -> None:
    monkeypatch.setenv("ASURA_LLM_TRIAGE", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = get_llm_client()
    assert isinstance(client, NullLLMClient)


def test_get_llm_client_returns_anthropic_when_both_set(monkeypatch) -> None:
    monkeypatch.setenv("ASURA_LLM_TRIAGE", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("ASURA_LLM_MODEL", "claude-test-model")
    client = get_llm_client()
    assert isinstance(client, AnthropicLLMClient)
    assert client.model == "claude-test-model"


def test_anthropic_client_returns_none_when_api_key_missing() -> None:
    """Defensive: if someone instantiates AnthropicLLMClient directly without
    the key, every triage() call must return None (deterministic fallback)
    rather than raise."""
    client = AnthropicLLMClient(api_key=None)
    assert client.triage({"project_id": "demo", "findings": []}) is None


def test_anthropic_client_catches_api_exceptions(monkeypatch) -> None:
    """Network blips / API errors fall back to None, never crash the brain."""

    class _Boom:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("simulated 503")

    client = AnthropicLLMClient(api_key="sk-test", client=_Boom())
    assert client.triage({"project_id": "demo", "findings": []}) is None


# ---------------------------------------------------------------------------
# _extract_tool_input handles both dict + object shapes
# ---------------------------------------------------------------------------


def test_extract_tool_input_pulls_submit_triage_block_from_dict() -> None:
    response = {
        "content": [
            {"type": "text", "text": "thinking..."},
            {"type": "tool_use", "name": "submit_triage", "input": {"summary": "ok", "clusters": []}},
        ]
    }
    out = _extract_tool_input(response)
    assert out == {"summary": "ok", "clusters": []}


def test_extract_tool_input_returns_none_when_no_tool_block() -> None:
    response = {"content": [{"type": "text", "text": "no tool use"}]}
    assert _extract_tool_input(response) is None
    assert _extract_tool_input(None) is None


# ---------------------------------------------------------------------------
# API end-to-end
# ---------------------------------------------------------------------------


def test_api_triage_route_returns_deterministic_report_by_default(monkeypatch) -> None:
    monkeypatch.delenv("ASURA_LLM_TRIAGE", raising=False)
    response = client.get("/api/projects/demo/triage")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["project_id"] == "demo"
    assert body["engine"] == "deterministic"
    assert body["findings_considered"] > 0
    assert body["clusters"], "Demo seed should have at least one cluster"


def test_api_triage_route_404s_for_unknown_project() -> None:
    response = client.get("/api/projects/does-not-exist/triage")
    assert response.status_code == 404


def test_api_triage_route_honours_limit_query_param() -> None:
    response = client.get("/api/projects/demo/triage?limit=2")
    assert response.status_code == 200
    body = response.json()
    assert body["findings_considered"] <= 2
