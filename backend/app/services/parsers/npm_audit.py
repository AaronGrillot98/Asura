"""npm audit JSON parser."""
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
    vulns = raw.get("vulnerabilities") or {}
    if not isinstance(vulns, dict):
        return findings
    for pkg_name, payload in vulns.items():
        if not isinstance(payload, dict):
            continue
        severity = map_severity(payload.get("severity"))
        # `via` can be a list of strings or advisory dicts.
        via = payload.get("via") or []
        advisory_ids: list[str] = []
        cves: list[str] = []
        for item in via:
            if isinstance(item, dict):
                if item.get("url"):
                    advisory_ids.append(str(item.get("url")))
                title = item.get("title") or ""
                if title.startswith("CVE-"):
                    cves.append(title)
            elif isinstance(item, str):
                advisory_ids.append(item)
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="npm-audit",
                title=f"npm advisory affecting {pkg_name}",
                category="dependency",
                severity=severity,
                confidence=Confidence.high,
                impact=f"npm audit flagged {pkg_name} as {payload.get('severity', 'vulnerable')}.",
                recommendation=(
                    payload.get("fixAvailable")
                    and f"Run npm audit fix or upgrade {pkg_name}."
                    or f"Upgrade {pkg_name} past the vulnerable range."
                ),
                reproduction=f"npm audit reported {pkg_name} via {', '.join(advisory_ids) or 'an advisory feed'}.",
                false_positive_reasoning="npm audit matched the installed package against its registry advisory feed.",
                raw={"package": pkg_name, "payload": payload},
                summary=f"{pkg_name} flagged by npm audit",
                affected_asset="npm-lockfile",
                affected_component=pkg_name,
                cve=cves,
                is_demo_data=is_demo_data,
            )
        )
    return findings
