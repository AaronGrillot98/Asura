"""Terrascan JSON parser.

`terrascan scan -o json` emits a violations report:

    {
      "results": {
        "violations": [
          {
            "rule_name":       "publiclyExposedSubnet",
            "description":     "Ensure subnets are not publicly exposed",
            "rule_id":         "AC_AWS_0006",
            "severity":        "MEDIUM",
            "category":        "Network Security",
            "resource_name":   "public_subnet",
            "resource_type":   "aws_subnet",
            "file":            "main.tf",
            "line":            42
          }
        ],
        "scan_summary": { "policies_validated": 100, ... }
      }
    }
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding, map_severity


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-iac",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _coerce_dict(raw)
    if not isinstance(doc, dict):
        return []
    inner = doc.get("results") or {}
    violations = inner.get("violations") if isinstance(inner, dict) else []
    if not isinstance(violations, list):
        return []

    findings: list[Finding] = []
    for v in violations:
        if not isinstance(v, dict):
            continue
        rule = v.get("rule_name") or v.get("rule_id") or "(unnamed rule)"
        severity = map_severity(v.get("severity"), default=Severity.medium)
        file_name = v.get("file") or ""
        line = v.get("line") or 0
        resource = v.get("resource_name") or ""
        resource_type = v.get("resource_type") or ""
        category = (v.get("category") or "iac").lower()

        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="terrascan",
                title=f"{rule} ({resource_type}) — {file_name}:{line}",
                category="iac",
                severity=severity,
                confidence=Confidence.high,
                impact=v.get("description") or f"Terrascan flagged `{rule}` on `{resource}` ({resource_type}).",
                recommendation=(
                    f"Apply the policy fix for rule `{v.get('rule_id') or rule}` to the resource "
                    f"`{resource}` in {file_name}."
                ),
                reproduction=f"terrascan matched rule `{rule}` at {file_name}:{line} (category: {category})",
                false_positive_reasoning=(
                    "Terrascan applies static policies; intentionally permissive resources may "
                    "warrant a per-resource skip via `terrascan_skip` annotation."
                ),
                raw=v,
                summary=f"terrascan {rule} @ {file_name}:{line}",
                affected_asset=file_name,
                affected_component=f"{resource_type}:{resource}" if resource_type and resource else (resource or None),
                file_path=file_name,
                owasp=["A05:2021-Security Misconfiguration"],
                is_demo_data=is_demo_data,
            )
        )
    return findings


def _coerce_dict(raw: object) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return None
