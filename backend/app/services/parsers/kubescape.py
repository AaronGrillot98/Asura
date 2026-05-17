"""kubescape JSON parser (`--format json`).

Two shapes show up in practice depending on the kubescape version:
  - Top-level `results` (resource list) with `controls` per resource.
  - Top-level `controls` keyed by control id (newer versions).
This parser is tolerant of both.
"""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-host",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(raw, dict):
        return findings

    # ---- shape A: results[].controls[] -------------------------------
    for resource in raw.get("results") or []:
        if not isinstance(resource, dict):
            continue
        resource_id = resource.get("resourceID") or resource.get("resourceId") or "k8s-resource"
        for control in resource.get("controls") or []:
            if not isinstance(control, dict):
                continue
            status_block = control.get("status") or {}
            status = status_block.get("status") if isinstance(status_block, dict) else None
            if status not in {"failed", "warning"}:
                continue
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="kubescape",
                    title=control.get("name") or control.get("controlID") or "kubescape-control",
                    category="kubernetes",
                    severity=map_severity(control.get("severity") or status),
                    confidence=Confidence.medium,
                    impact=control.get("description") or "kubescape control failed.",
                    recommendation=control.get("remediation") or "Review the kubescape control documentation.",
                    reproduction=f"kubescape control {control.get('controlID')} flagged {resource_id}.",
                    false_positive_reasoning="kubescape evaluates cluster state against published frameworks (NSA, MITRE, ARMO).",
                    raw=control,
                    summary=f"kubescape {control.get('controlID')} on {resource_id}",
                    affected_asset=resource_id,
                    affected_component=control.get("controlID"),
                    is_demo_data=is_demo_data,
                )
            )

    # ---- shape B: controls keyed by id -------------------------------
    controls_map = raw.get("controls")
    if isinstance(controls_map, dict):
        for control_id, control in controls_map.items():
            if not isinstance(control, dict):
                continue
            status = (control.get("status") or "").lower()
            if status not in {"failed", "warning"}:
                continue
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="kubescape",
                    title=control.get("name") or control_id,
                    category="kubernetes",
                    severity=map_severity(control.get("severity")),
                    confidence=Confidence.medium,
                    impact=control.get("description") or "kubescape control failed.",
                    recommendation=control.get("remediation") or "Review the kubescape control documentation.",
                    reproduction=f"kubescape control {control_id} failed.",
                    false_positive_reasoning="kubescape evaluates cluster state against published frameworks.",
                    raw=control,
                    summary=f"kubescape {control_id}",
                    affected_asset=asset_id,
                    affected_component=control_id,
                    is_demo_data=is_demo_data,
                )
            )

    return findings
