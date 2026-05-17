"""Syft SBOM parser — emits informational findings only.

Syft itself is not a vulnerability scanner; it produces a software bill of
materials. We surface one info-level finding per package so the SBOM appears
in the evidence view without inflating risk scores.
"""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _artifacts(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [a for a in raw.get("artifacts", []) if isinstance(a, dict)]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-image",
    is_demo_data: bool = False,
    max_items: int = 25,
) -> list[Finding]:
    findings: list[Finding] = []
    for art in _artifacts(raw)[:max_items]:
        name = art.get("name") or "package"
        version = art.get("version") or "unknown"
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="syft",
                title=f"SBOM entry: {name}@{version}",
                category="sbom",
                severity=Severity.info,
                confidence=Confidence.confirmed,
                impact="Package listed in the SBOM. Use with grype/osv-scanner to identify vulnerabilities.",
                recommendation="Track this dependency in your SBOM baseline.",
                reproduction=f"Syft enumerated {name}@{version}.",
                false_positive_reasoning="SBOM enumeration of installed packages — informational only.",
                raw=art,
                summary=f"{name}@{version}",
                affected_asset=asset_id,
                affected_component=f"{name}@{version}",
                is_demo_data=is_demo_data,
            )
        )
    return findings
