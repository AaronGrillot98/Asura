"""Generic SARIF parser.

SARIF (Static Analysis Results Interchange Format) is the standard output
of CodeQL, Semgrep (with `--sarif`), Trivy, and many others. This parser
normalizes a SARIF v2.1.0 log into Asura `Finding` objects.
"""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "info": "info",
    "none": "info",
}


def _runs(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        return []
    return [r for r in raw.get("runs", []) if isinstance(r, dict)]


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for run in _runs(raw):
        tool_name = (((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif-tool").lower()
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId") or "sarif-rule"
            message = (result.get("message") or {}).get("text") or rule_id
            level = result.get("level") or "warning"
            severity = map_severity(_LEVEL_TO_SEVERITY.get(str(level).lower(), "medium"))
            # Locations is a list of physicalLocation -> artifactLocation.uri + region.startLine.
            file_path = "unknown"
            line = 0
            for loc in result.get("locations") or []:
                physical = (loc or {}).get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}
                file_path = artifact.get("uri") or file_path
                line = region.get("startLine") or line
                if file_path != "unknown":
                    break
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner=tool_name,
                    title=f"{rule_id}: {message}".strip().rstrip(":"),
                    category="code",
                    severity=severity,
                    confidence=Confidence.medium,
                    impact=message,
                    recommendation="Review the rule documentation in the SARIF log for remediation guidance.",
                    reproduction=f"{tool_name} matched {rule_id} at {file_path}:{line}",
                    false_positive_reasoning=f"{tool_name} reported the match via SARIF; review rule context.",
                    raw=result,
                    summary=f"{tool_name} {rule_id} at {file_path}:{line}",
                    affected_asset=file_path,
                    affected_component=f"{file_path}:{line}",
                    file_path=file_path,
                    is_demo_data=is_demo_data,
                )
            )
    return findings
