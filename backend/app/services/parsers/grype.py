"""Grype JSON parser."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _matches(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [m for m in raw.get("matches", []) if isinstance(m, dict)]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-image",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for match in _matches(raw):
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        name = artifact.get("name") or "package"
        version = artifact.get("version") or "unknown"
        vid = vuln.get("id") or "GRYPE-UNKNOWN"
        severity = map_severity(vuln.get("severity"))
        fix = (vuln.get("fix") or {}).get("versions") or []
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="grype",
                title=f"{name}@{version} {vid}",
                category="container",
                severity=severity,
                confidence=Confidence.high,
                impact=vuln.get("description") or "Vulnerable dependency detected by Grype.",
                recommendation=f"Upgrade {name} to {', '.join(fix) or 'a patched release'}.",
                reproduction=f"Grype matched {vid} on {name} {version}.",
                false_positive_reasoning="Grype matched the installed version against its vulnerability feed.",
                raw=match,
                summary=f"{vid} affecting {name} {version}.",
                affected_asset=asset_id,
                affected_component=f"{name}@{version}",
                cve=[vid] if vid.startswith("CVE-") else [],
                is_demo_data=is_demo_data,
            )
        )
    return findings
