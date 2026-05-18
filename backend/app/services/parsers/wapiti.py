"""Wapiti JSON parser (`-f json -o -`).

Wapiti groups vulnerabilities by category under a `vulnerabilities` map:

    {
      "vulnerabilities": {
        "SQL Injection": [{"level": 3, "module": "sql", "info": "...",
                           "method": "GET", "path": "/x", "http_request": "..."}],
        "Backup file":   [...]
      },
      "infos":     {...},
      "anomalies": {...}
    }

Each item becomes one Finding. Wapiti reports `level` 1–3 (low / medium /
high); we map 3→high, 2→medium, 1→low. Items under `infos` come through
as info-severity, `anomalies` as low.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_LEVEL_TO_SEVERITY = {
    3: Severity.high,
    2: Severity.medium,
    1: Severity.low,
}


def _records(raw: object) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _items(bucket: object) -> list[dict[str, Any]]:
    if isinstance(bucket, dict):
        out: list[dict[str, Any]] = []
        for items in bucket.values():
            if isinstance(items, list):
                out.extend(i for i in items if isinstance(i, dict))
        return out
    if isinstance(bucket, list):
        return [i for i in bucket if isinstance(i, dict)]
    return []


def _bucket_items(doc: dict[str, Any], key: str) -> list[tuple[str, dict[str, Any]]]:
    bucket = doc.get(key)
    if not isinstance(bucket, dict):
        return []
    rows: list[tuple[str, dict[str, Any]]] = []
    for category, items in bucket.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                rows.append((category, item))
    return rows


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _records(raw)
    findings: list[Finding] = []

    for category, item in _bucket_items(doc, "vulnerabilities"):
        level = item.get("level")
        sev = _LEVEL_TO_SEVERITY.get(level if isinstance(level, int) else 0, Severity.medium)
        findings.append(_make(category, item, sev, project_id, scan_id, asset_id, is_demo_data))

    for category, item in _bucket_items(doc, "anomalies"):
        findings.append(_make(category, item, Severity.low, project_id, scan_id, asset_id, is_demo_data))

    for category, item in _bucket_items(doc, "infos"):
        findings.append(_make(category, item, Severity.info, project_id, scan_id, asset_id, is_demo_data))

    return findings


def _make(
    category: str,
    item: dict[str, Any],
    severity: Severity,
    project_id: str,
    scan_id: str | None,
    asset_id: str,
    is_demo_data: bool,
) -> Finding:
    module = item.get("module") or "wapiti"
    method = item.get("method") or "GET"
    path = item.get("path") or "/"
    info = item.get("info") or item.get("name") or category
    return make_finding(
        project_id=project_id,
        scan_id=scan_id,
        asset_id=asset_id,
        scanner="wapiti",
        title=f"{category} on {path}",
        category="web",
        severity=severity,
        confidence=Confidence.medium,
        impact=str(info)[:500],
        recommendation="Review the wapiti report for the exact payload and patch the affected handler.",
        reproduction=item.get("http_request") or f"{method} {path}",
        false_positive_reasoning=(
            "Wapiti probes with payloads; reflective output can sometimes look like a hit. "
            "Cross-check with the raw http_request before triaging as exploitable."
        ),
        raw=item,
        summary=f"wapiti {category} {module} {method} {path}",
        affected_asset=path,
        affected_component=f"{module} ({method})",
        is_demo_data=is_demo_data,
    )
