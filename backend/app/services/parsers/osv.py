"""osv-scanner JSON parser."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


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
    for result in raw.get("results", []):
        if not isinstance(result, dict):
            continue
        source = (result.get("source") or {}).get("path") or "lockfile"
        for pkg in result.get("packages", []):
            if not isinstance(pkg, dict):
                continue
            pkg_info = pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                severity_label = "medium"
                for sev in vuln.get("severity", []):
                    if isinstance(sev, dict) and sev.get("type") == "CVSS_V3":
                        score = sev.get("score") or ""
                        if "HIGH" in str(score).upper():
                            severity_label = "high"
                        elif "CRITICAL" in str(score).upper():
                            severity_label = "critical"
                aliases = [a for a in vuln.get("aliases", []) if isinstance(a, str)]
                cve = [a for a in aliases if a.startswith("CVE-")]
                findings.append(
                    make_finding(
                        project_id=project_id,
                        scan_id=scan_id,
                        asset_id=asset_id,
                        scanner="osv-scanner",
                        title=f"{pkg_info.get('name')} {vuln.get('id')}",
                        category="dependency",
                        severity=map_severity(severity_label),
                        confidence=Confidence.high,
                        impact=vuln.get("summary") or "Vulnerable dependency detected.",
                        recommendation=f"Upgrade {pkg_info.get('name')} past the vulnerable range.",
                        reproduction=f"osv-scanner matched {vuln.get('id')} on {pkg_info.get('name')} {pkg_info.get('version')} in {source}.",
                        false_positive_reasoning="OSV.dev advisory matched the installed package range.",
                        raw={"source": source, "package": pkg_info, "vulnerability": vuln},
                        summary=f"{vuln.get('id')} affecting {pkg_info.get('name')} {pkg_info.get('version')}.",
                        affected_asset=source,
                        affected_component=f"{pkg_info.get('name')}@{pkg_info.get('version')}",
                        cve=cve,
                        is_demo_data=is_demo_data,
                    )
                )
    return findings
