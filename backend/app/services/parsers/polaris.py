"""Polaris audit JSON parser.

Polaris emits one big document with a `Results` list, where each entry
is a Kubernetes resource. Each resource has a nested `Results` dict
keyed by check id; each check has `Success`, `Severity` (`ignore` /
`warning` / `danger`), `Message`, and `Category`.

A failing check (`Success: false`) becomes one finding. Polaris severity
maps:
  - `danger`  → high
  - `warning` → medium
  - anything else → low
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_SEVERITY_MAP = {
    "danger": Severity.high,
    "warning": Severity.medium,
    "ignore": Severity.info,
}


def _doc(raw: object) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-cluster",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _doc(raw)
    findings: list[Finding] = []
    for resource in doc.get("Results") or []:
        if not isinstance(resource, dict):
            continue
        kind = resource.get("Kind") or "Resource"
        name = resource.get("Name") or "resource"
        namespace = resource.get("Namespace") or "default"
        resource_id = f"{kind}/{namespace}/{name}"
        checks = resource.get("Results") or {}
        if not isinstance(checks, dict):
            continue
        for check_id, check in checks.items():
            if not isinstance(check, dict):
                continue
            if check.get("Success") is True:
                continue
            sev_raw = (check.get("Severity") or "").lower()
            severity = _SEVERITY_MAP.get(sev_raw, Severity.low)
            message = check.get("Message") or check_id
            category = check.get("Category") or "kubernetes"
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="polaris",
                    title=f"{check_id} — {message[:120]}",
                    category="kubernetes",
                    severity=severity,
                    confidence=Confidence.high,
                    impact=message,
                    recommendation=(
                        "Review the Polaris control documentation and update the manifest "
                        "or PodSecurity policy to satisfy the check."
                    ),
                    reproduction=f"polaris audit --audit-path . # {check_id} failed on {resource_id}",
                    false_positive_reasoning=(
                        "Polaris evaluates static manifests against best-practice rules; some checks "
                        "may not apply to every workload type."
                    ),
                    raw=check,
                    summary=f"polaris {check_id} on {resource_id} ({category})",
                    affected_asset=resource_id,
                    affected_component=check_id,
                    is_demo_data=is_demo_data,
                )
            )
    return findings
