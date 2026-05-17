"""Trivy JSON parser (vulnerabilities + misconfigurations + secrets)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _iter_results(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [r for r in raw.get("Results", []) if isinstance(r, dict)]
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
    for block in _iter_results(raw):
        target = block.get("Target") or "container"
        for vuln in block.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            severity = map_severity(vuln.get("Severity"))
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="trivy",
                    title=f"{vuln.get('PkgName')} {vuln.get('VulnerabilityID')}",
                    category="container",
                    severity=severity,
                    confidence=Confidence.high,
                    impact=vuln.get("Description") or "Vulnerable package detected.",
                    recommendation=f"Upgrade {vuln.get('PkgName')} to {vuln.get('FixedVersion') or 'a patched release'}.",
                    reproduction=f"Trivy matched {vuln.get('VulnerabilityID')} on {target}.",
                    false_positive_reasoning="Trivy correlated an installed package version against an advisory feed.",
                    raw={"target": target, **vuln},
                    summary=f"{vuln.get('VulnerabilityID')} affecting {vuln.get('PkgName')} {vuln.get('InstalledVersion')}.",
                    affected_asset=target,
                    affected_component=f"{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}",
                    cve=[vuln.get("VulnerabilityID")] if vuln.get("VulnerabilityID", "").startswith("CVE-") else [],
                    is_demo_data=is_demo_data,
                )
            )
        for misc in block.get("Misconfigurations") or []:
            if not isinstance(misc, dict):
                continue
            severity = map_severity(misc.get("Severity"))
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="trivy",
                    title=f"Misconfiguration: {misc.get('Title') or misc.get('ID')}",
                    category="iac",
                    severity=severity,
                    confidence=Confidence.medium,
                    impact=misc.get("Description") or "Misconfiguration flagged by Trivy.",
                    recommendation=misc.get("Resolution") or "Review the linked guidance.",
                    reproduction=f"Trivy matched {misc.get('ID')} on {target}.",
                    false_positive_reasoning="Static evaluation against the documented rule set.",
                    raw={"target": target, **misc},
                    summary=misc.get("Description") or misc.get("Title") or "Trivy misconfiguration.",
                    affected_asset=target,
                    affected_component=misc.get("ID") or "trivy-check",
                    is_demo_data=is_demo_data,
                )
            )
    return findings
