"""Bandit JSON parser (Python SAST)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity, map_confidence


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
        test_id = rec.get("test_id") or rec.get("test_name") or "bandit-rule"
        file_path = rec.get("filename") or "unknown"
        line = rec.get("line_number") or 0
        severity = map_severity(rec.get("issue_severity"))
        confidence = map_confidence(rec.get("issue_confidence"))
        cwe = rec.get("issue_cwe") or {}
        cwes = []
        if isinstance(cwe, dict) and cwe.get("id"):
            cwes.append(f"CWE-{cwe['id']}")
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="bandit",
                title=f"{test_id}: {rec.get('issue_text', '')}".strip().rstrip(":"),
                category="code",
                severity=severity,
                confidence=confidence,
                impact=rec.get("issue_text") or "Bandit flagged a Python security issue.",
                recommendation=rec.get("more_info") or "Review the linked Bandit guidance and address the issue.",
                reproduction=f"Bandit {test_id} matched {file_path}:{line}",
                false_positive_reasoning="Bandit matched a documented rule against Python source.",
                raw=rec,
                summary=f"Bandit {test_id} at {file_path}:{line}",
                affected_asset=file_path,
                affected_component=f"{file_path}:{line}",
                file_path=file_path,
                cwe=cwes,
                is_demo_data=is_demo_data,
            )
        )
    return findings
