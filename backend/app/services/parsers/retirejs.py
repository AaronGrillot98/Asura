"""Retire.js JSON parser (`--outputformat json`).

retire emits a top-level array of `{file, results: [{component, version,
vulnerabilities: [...]}, ...]}`. Each vulnerability has a `severity`
(`low|medium|high|critical`) and `identifiers` with optional CVE / issue
references.

We produce one Finding per vulnerability so de-dup keys land on
`(component, version, cve)`.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if isinstance(raw, dict):
        # `retire --outputformat json` may emit `{"version": ..., "data": [...]}`.
        if isinstance(raw.get("data"), list):
            return [r for r in raw["data"] if isinstance(r, dict)]
        return [raw]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for record in _records(raw):
        file_path = record.get("file") or record.get("source") or ""
        for result in record.get("results") or []:
            if not isinstance(result, dict):
                continue
            component = result.get("component") or "library"
            version = result.get("version") or "?"
            for vuln in result.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                identifiers = vuln.get("identifiers") or {}
                cves = list(identifiers.get("CVE") or [])
                summary = identifiers.get("summary") or vuln.get("info") or [""]
                if isinstance(summary, list):
                    summary_text = "; ".join(str(s) for s in summary)[:500]
                else:
                    summary_text = str(summary)[:500]
                findings.append(
                    make_finding(
                        project_id=project_id,
                        scan_id=scan_id,
                        asset_id=asset_id,
                        scanner="retirejs",
                        title=f"{component} {version} — vulnerable JS library",
                        category="dependency",
                        severity=map_severity(vuln.get("severity")),
                        confidence=Confidence.high,
                        impact=summary_text or f"{component} {version} matches a known retire.js advisory.",
                        recommendation=f"Upgrade {component} to a version that addresses the listed advisories.",
                        reproduction=f"retire --path {file_path or '<asset>'}",
                        false_positive_reasoning=(
                            "retire.js matches by signature, hash, or filename — bundled or vendored "
                            "copies with custom patches may report despite being unaffected."
                        ),
                        raw=vuln,
                        summary=f"retirejs {component}@{version}",
                        affected_asset=file_path or component,
                        affected_component=f"{component}@{version}",
                        cve=cves,
                        is_demo_data=is_demo_data,
                    )
                )
    return findings
