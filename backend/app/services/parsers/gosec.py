"""gosec JSON parser (Go SAST)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Finding

from ._common import make_finding, map_severity, map_confidence


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(raw, dict):
        return findings
    for issue in raw.get("Issues") or []:
        if not isinstance(issue, dict):
            continue
        rule_id = issue.get("rule_id") or "gosec-rule"
        file_path = issue.get("file") or "unknown"
        line = issue.get("line") or 0
        severity = map_severity(issue.get("severity"))
        confidence = map_confidence(issue.get("confidence"))
        cwe_id = ((issue.get("cwe") or {}).get("ID")) if isinstance(issue.get("cwe"), dict) else None
        cwes = [f"CWE-{cwe_id}"] if cwe_id else []
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="gosec",
                title=f"{rule_id}: {issue.get('details', '')}".strip().rstrip(":"),
                category="code",
                severity=severity,
                confidence=confidence,
                impact=issue.get("details") or "gosec flagged a Go security issue.",
                recommendation="Review the rule guidance and apply the suggested fix.",
                reproduction=f"gosec {rule_id} matched {file_path}:{line}",
                false_positive_reasoning="gosec matched a documented rule against Go source.",
                raw=issue,
                summary=f"gosec {rule_id} at {file_path}:{line}",
                affected_asset=file_path,
                affected_component=f"{file_path}:{line}",
                file_path=file_path,
                cwe=cwes,
                is_demo_data=is_demo_data,
            )
        )
    return findings
