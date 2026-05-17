"""Semgrep JSON parser."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _results(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [r for r in raw.get("results", []) if isinstance(r, dict)]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _results(raw):
        check_id = rec.get("check_id") or "semgrep-rule"
        path = rec.get("path") or "unknown"
        line = (rec.get("start") or {}).get("line") or 0
        extra = rec.get("extra") or {}
        severity = map_severity(extra.get("severity"))
        message = extra.get("message") or check_id
        cwes = [m for m in (extra.get("metadata", {}).get("cwe") or []) if isinstance(m, str)]
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="semgrep",
                title=check_id,
                category="code",
                severity=severity,
                confidence=Confidence.medium,
                impact=message,
                recommendation=extra.get("metadata", {}).get("fix_recommendation") or "Review the rule guidance and adjust the flagged code.",
                reproduction=f"Semgrep {check_id} matched {path}:{line}",
                false_positive_reasoning="Rule match was produced against source code; review with the rule's intent in mind.",
                raw=rec,
                summary=f"Semgrep matched {check_id} at {path}:{line}.",
                affected_asset=path,
                affected_component=f"{path}:{line}",
                file_path=path,
                cwe=cwes,
                is_demo_data=is_demo_data,
            )
        )
    return findings
