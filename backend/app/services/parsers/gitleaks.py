"""Gitleaks JSON parser."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict) and "findings" in raw:
        return list(raw["findings"])
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
    for rec in _records(raw):
        rule = rec.get("RuleID") or rec.get("rule") or "secret"
        file_path = rec.get("File") or rec.get("file") or "unknown"
        line = rec.get("StartLine") or rec.get("line") or 0
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="gitleaks",
                title=f"Possible secret: {rule}",
                category="secrets",
                severity=Severity.high,
                confidence=Confidence.high,
                impact="Leaked credentials can grant access to downstream systems if still valid.",
                recommendation="Rotate the credential, remove it from git history, and add the pattern to your secret-scanning baseline.",
                reproduction=f"Gitleaks matched rule {rule} in {file_path}:{line}.",
                false_positive_reasoning="Pattern matched a configured secret signature; verify with the owning team.",
                raw=rec,
                summary=f"Gitleaks matched rule {rule} in {file_path}:{line}.",
                affected_asset=file_path,
                affected_component=f"{file_path}:{line}",
                file_path=file_path,
                cwe=["CWE-798"],
                is_demo_data=is_demo_data,
            )
        )
    return findings
