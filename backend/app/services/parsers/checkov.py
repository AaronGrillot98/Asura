"""Checkov JSON parser."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _failed(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [r for r in (raw.get("results") or {}).get("failed_checks", []) if isinstance(r, dict)]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-cloud",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _failed(raw):
        check_id = rec.get("check_id") or "checkov"
        file_path = rec.get("file_path") or "iac"
        severity = map_severity(rec.get("severity") or "medium")
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="checkov",
                title=f"{check_id}: {rec.get('check_name')}",
                category="iac",
                severity=severity,
                confidence=Confidence.high,
                impact=rec.get("check_name") or "IaC misconfiguration flagged by Checkov.",
                recommendation=rec.get("guideline") or "Review the linked Checkov guidance.",
                reproduction=f"Checkov {check_id} failed on {file_path}.",
                false_positive_reasoning="Checkov evaluated the resource against its documented rule.",
                raw=rec,
                summary=rec.get("check_name") or check_id,
                affected_asset=file_path,
                affected_component=rec.get("resource") or check_id,
                file_path=file_path,
                is_demo_data=is_demo_data,
            )
        )
    return findings
