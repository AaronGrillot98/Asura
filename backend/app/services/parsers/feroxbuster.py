"""Feroxbuster JSON parser.

Feroxbuster writes NDJSON (one JSON object per line) when run with
`--json --silent`. Records have `type` values like `response`, `error`,
and a configuration banner; we only care about successful responses.

Each discovered URL becomes an info-level finding tagged
`content-discovery`. The Command Center groups these under a single
"discovered endpoint" lane rather than treating each as a vulnerability.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, str):
        out: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for record in _records(raw):
        if record.get("type") != "response":
            continue
        url = record.get("url")
        status = record.get("status")
        if not url or not isinstance(status, int):
            continue
        # Treat 4xx other than 401/403 as uninteresting noise; everything
        # else (2xx, 3xx, 401, 403, 5xx) is worth surfacing.
        if 400 <= status < 500 and status not in (401, 403):
            continue
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="feroxbuster",
                title=f"Discovered endpoint: {url}",
                category="content-discovery",
                severity=Severity.info,
                confidence=Confidence.high,
                impact=f"Endpoint responded with HTTP {status}.",
                recommendation="Triage whether this endpoint is intentionally exposed.",
                reproduction=f"feroxbuster -u <base> -w <wordlist>  # discovered {url}",
                false_positive_reasoning="Direct HTTP response from the target.",
                raw=record,
                summary=f"feroxbuster {status} {url}",
                affected_asset=url,
                affected_component=record.get("method") or "GET",
                is_demo_data=is_demo_data,
            )
        )
    return findings
