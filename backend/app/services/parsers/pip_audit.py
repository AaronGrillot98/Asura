"""pip-audit JSON parser (Python dependencies)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


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
    deps = raw.get("dependencies", [])
    if not isinstance(deps, list):
        return findings
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name") or "package"
        version = dep.get("version") or "unknown"
        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vid = vuln.get("id") or "PYSEC-UNKNOWN"
            fix_versions = vuln.get("fix_versions") or []
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="pip-audit",
                    title=f"{name}@{version} {vid}",
                    category="dependency",
                    severity=Severity.medium,
                    confidence=Confidence.high,
                    impact=vuln.get("description") or "Vulnerable Python dependency detected.",
                    recommendation=(
                        f"Upgrade {name} to {', '.join(fix_versions)}." if fix_versions
                        else f"Upgrade {name} past the vulnerable range."
                    ),
                    reproduction=f"pip-audit matched {vid} on {name} {version}.",
                    false_positive_reasoning="pip-audit matched the installed package against the PyPA advisory feed.",
                    raw={"package": {"name": name, "version": version}, "vulnerability": vuln},
                    summary=f"{vid} affecting {name} {version}.",
                    affected_asset="python-requirements",
                    affected_component=f"{name}@{version}",
                    cve=[vid] if vid.startswith("CVE-") else [],
                    is_demo_data=is_demo_data,
                )
            )
    return findings
