"""Nuclei JSONL parser."""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict) and "results" in raw:
        return list(raw["results"])
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
    for rec in _records(raw):
        info = rec.get("info") or {}
        template_id = rec.get("template-id") or rec.get("templateID") or info.get("name") or "nuclei-template"
        matched_at = rec.get("matched-at") or rec.get("host") or "unknown"
        severity = map_severity(info.get("severity"))
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="nuclei",
                title=info.get("name") or template_id,
                category="web",
                severity=severity,
                confidence=Confidence.high,
                impact=info.get("description") or "Template match observed on the target.",
                recommendation=info.get("remediation") or "Review the matched response and apply the template's recommended mitigation.",
                reproduction=f"Nuclei template {template_id} matched {matched_at}.",
                false_positive_reasoning="Match was produced by a published Nuclei template with documented matchers.",
                raw=rec,
                summary=f"Nuclei matched {template_id} on {matched_at}.",
                affected_asset=matched_at,
                affected_component=template_id,
                cwe=list(info.get("classification", {}).get("cwe-id") or []),
                cve=list(info.get("classification", {}).get("cve-id") or []),
                is_demo_data=is_demo_data,
            )
        )
    return findings
