"""govulncheck JSON parser (Go modules)."""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        if "Vulns" in raw and isinstance(raw["Vulns"], list):
            return [v for v in raw["Vulns"] if isinstance(v, dict)]
        return [raw]
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
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _records(raw):
        # govulncheck emits OSV-style records under `osv` key in newer versions.
        osv = rec.get("osv") or rec
        if not isinstance(osv, dict):
            continue
        vid = osv.get("id") or rec.get("id") or "GO-UNKNOWN"
        if not vid.startswith(("GO-", "CVE-", "GHSA-")):
            # Skip non-finding events (progress, etc.).
            continue
        summary = osv.get("summary") or rec.get("summary") or "Go vulnerability"
        affected = osv.get("affected") or []
        package_name = "go-module"
        if isinstance(affected, list) and affected and isinstance(affected[0], dict):
            package_name = (affected[0].get("package") or {}).get("name") or package_name
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="govulncheck",
                title=f"{package_name} {vid}",
                category="dependency",
                severity=Severity.medium,
                confidence=Confidence.high,
                impact=summary,
                recommendation="Upgrade the affected Go module to a patched release.",
                reproduction=f"govulncheck matched {vid} on {package_name}.",
                false_positive_reasoning="govulncheck matched a Go module against the official Go vulnerability database.",
                raw=rec,
                summary=f"{vid} affecting {package_name}",
                affected_asset="go.mod",
                affected_component=package_name,
                cve=[a for a in (osv.get("aliases") or []) if isinstance(a, str) and a.startswith("CVE-")],
                is_demo_data=is_demo_data,
            )
        )
    return findings
