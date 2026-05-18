"""LLM client abstraction for PentestBrain.

Asura's brain stays deterministic by default — every method PentestBrain
exposes works without ever calling out to a model. This module is the
opt-in upgrade path: when `ASURA_LLM_TRIAGE=1` is set AND a non-Null
client is wired in, `PentestBrain.triage_findings()` will route the
ranked finding list through an LLM and ask it to cluster, dedupe, and
prioritize.

The contract every LLM client returns is a plain dict matching this
shape (the citation guard inside PentestBrain takes care of validation):

    {
        "summary": "...",
        "clusters": [
            {"title": "...", "summary": "...", "reasoning": "...",
             "finding_ids": [...], "cited_evidence_ids": [...]},
            ...
        ],
        "false_positive_candidates": [
            {"finding_id": "...", "reasoning": "...",
             "cited_evidence_ids": [...]},
            ...
        ],
        "priority_order": [
            {"finding_id": "...", "rank": 1, "reasoning": "...",
             "cited_evidence_ids": [...]},
            ...
        ],
    }

Returning `None` means "I have no opinion" — the brain falls back to its
deterministic baseline.

Three concrete clients ship today:

- `NullLLMClient`     — always returns None. Used in deterministic mode.
- `AnthropicLLMClient` — calls the Anthropic API with structured tool
                         use. Requires `anthropic` installed and
                         `ANTHROPIC_API_KEY` set.
- (tests inject their own callable via the `LLMClient` protocol.)
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional, Protocol


# ---------------------------------------------------------------------------
# Public protocol
# ---------------------------------------------------------------------------


class LLMClient(Protocol):
    """Anything callable that maps an Asura triage context dict to either
    a triage response dict or `None` (meaning "fall back to deterministic")."""

    def triage(self, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        ...


# ---------------------------------------------------------------------------
# Null client — used by default, never makes a network call.
# ---------------------------------------------------------------------------


class NullLLMClient:
    """Returns None for every call. PentestBrain interprets that as
    'use the deterministic path'."""

    name = "null"
    model = None

    def triage(self, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        return None


# ---------------------------------------------------------------------------
# Anthropic client
# ---------------------------------------------------------------------------


_DEFAULT_MODEL = "claude-haiku-4-5-20251001"

_TRIAGE_SYSTEM_PROMPT = """You are Asura's security triage assistant.

Your one and only job is to take a list of *already-discovered* findings
and group / score / prioritize them so a human triager can focus on the
real signal. You are running inside a tool that already gathered the
findings — do not invent new ones.

Hard rules:

1. Operate ONLY on the findings + evidence provided in the user message.
2. Every claim you submit MUST cite at least one evidence id from the
   input. Items without valid citations are discarded by the host before
   the user ever sees them.
3. You may NOT invent finding ids, evidence ids, CVEs, or vulnerability
   classes. If you are unsure, return fewer items rather than guessing.
4. Use the `submit_triage` tool to return your output. Do not return
   prose.
"""


_TRIAGE_TOOL_SCHEMA = {
    "name": "submit_triage",
    "description": (
        "Submit the triage result for the supplied findings. Every claim "
        "must cite one or more evidence ids that were in the input."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "One-paragraph overview of the triage result.",
            },
            "clusters": {
                "type": "array",
                "description": (
                    "Groups of findings that should be triaged together "
                    "(e.g. duplicates across scanners, related root causes)."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "summary": {"type": "string"},
                        "reasoning": {"type": "string"},
                        "finding_ids": {"type": "array", "items": {"type": "string"}},
                        "cited_evidence_ids": {"type": "array", "items": {"type": "string"}},
                        "fix_recommendation": {"type": "string"},
                    },
                    "required": ["title", "summary", "finding_ids", "cited_evidence_ids"],
                },
            },
            "false_positive_candidates": {
                "type": "array",
                "description": (
                    "Findings that are likely noise. Mark sparingly; only "
                    "include items you have specific evidence to discount."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "reasoning": {"type": "string"},
                        "cited_evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["finding_id", "reasoning", "cited_evidence_ids"],
                },
            },
            "priority_order": {
                "type": "array",
                "description": (
                    "Recommended fix order: rank 1 = fix first. Include only "
                    "the top 20; the rest fall back to deterministic ordering."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "rank": {"type": "integer"},
                        "reasoning": {"type": "string"},
                        "cited_evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["finding_id", "rank", "reasoning", "cited_evidence_ids"],
                },
            },
        },
        "required": ["summary", "clusters", "priority_order"],
    },
}


class AnthropicLLMClient:
    """Anthropic API client wired for structured-tool triage output.

    The Anthropic Python SDK is an optional dep (`pip install anthropic`).
    We import it lazily so the rest of Asura keeps booting on machines
    where it isn't installed. If the import fails OR the API key is
    missing, every `triage()` call returns None so PentestBrain falls back
    to its deterministic path.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        max_tokens: int = 4096,
        client: Any = None,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = client  # allow injection for tests
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._api_key:
            return None
        try:
            from anthropic import Anthropic  # type: ignore
        except ImportError:
            return None
        self._client = Anthropic(api_key=self._api_key)
        return self._client

    def triage(self, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        client = self._get_client()
        if client is None:
            return None
        user_message = (
            "Triage these findings. Use only the provided ids in citations.\n\n"
            f"```json\n{json.dumps(context, indent=2)}\n```"
        )
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=_TRIAGE_SYSTEM_PROMPT,
                tools=[_TRIAGE_TOOL_SCHEMA],
                tool_choice={"type": "tool", "name": "submit_triage"},
                messages=[{"role": "user", "content": user_message}],
            )
        except Exception:
            # Network / API errors fall back to deterministic mode; we
            # don't surface a brain crash to the user just because the
            # LLM is unreachable. Caller can inspect logs.
            return None
        return _extract_tool_input(response)


def _extract_tool_input(response: Any) -> Optional[dict[str, Any]]:
    """Pull the `submit_triage` tool's input dict out of an Anthropic
    response. Tolerates both dict-shaped responses (used by tests) and
    Anthropic SDK message objects."""
    if response is None:
        return None
    if isinstance(response, dict):
        for block in response.get("content") or []:
            if block.get("type") == "tool_use" and block.get("name") == "submit_triage":
                inp = block.get("input")
                if isinstance(inp, dict):
                    return inp
        return None
    content = getattr(response, "content", None)
    if not content:
        return None
    for block in content:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == "submit_triage":
            inp = getattr(block, "input", None)
            if isinstance(inp, dict):
                return inp
    return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def get_llm_client() -> LLMClient:
    """Return the configured client.

    `ASURA_LLM_TRIAGE=1` + `ANTHROPIC_API_KEY=...` → AnthropicLLMClient.
    Anything else → NullLLMClient (deterministic).
    """
    if _env_truthy("ASURA_LLM_TRIAGE") and os.environ.get("ANTHROPIC_API_KEY"):
        model = os.environ.get("ASURA_LLM_MODEL", _DEFAULT_MODEL)
        return AnthropicLLMClient(model=model)
    return NullLLMClient()
