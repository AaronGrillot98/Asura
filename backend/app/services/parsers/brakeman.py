"""Brakeman JSON parser (Ruby on Rails SAST)."""
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
    for warning in raw.get("warnings") or []:
        if not isinstance(warning, dict):
            continue
        warning_type = warning.get("warning_type") or "Brakeman warning"
        check_name = warning.get("check_name") or warning_type
        file_path = warning.get("file") or "unknown"
        line = warning.get("line") or 0
        confidence = map_confidence(warning.get("confidence"))
        # Brakeman doesn't ship a severity; infer from confidence.
        severity = map_severity({
            "high": "high", "medium": "medium", "low": "low",
        }.get(str(warning.get("confidence", "")).lower(), "medium"))
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="brakeman",
                title=f"{check_name}: {warning_type}",
                category="code",
                severity=severity,
                confidence=confidence,
                impact=warning.get("message") or warning_type,
                recommendation=warning.get("user_input") and "Validate and sanitize the highlighted input." or "Review the Brakeman guidance for this check.",
                reproduction=f"Brakeman {check_name} flagged {file_path}:{line}.",
                false_positive_reasoning="Brakeman matched a documented Rails security pattern.",
                raw=warning,
                summary=f"Brakeman {check_name} at {file_path}:{line}",
                affected_asset=file_path,
                affected_component=f"{file_path}:{line}",
                file_path=file_path,
                is_demo_data=is_demo_data,
            )
        )
    return findings
