"""Prowler JSON parser (`--output-formats json`).

Prowler emits one JSON object per check finding. Recent versions output an
array of records like:
  {
    "check_id": "iam_password_policy_minimum_length_14",
    "service_name": "iam",
    "status": "FAIL"|"PASS"|"WARN",
    "severity": "high"|"medium"|"low"|"informational",
    "resource_id": "AccountPasswordPolicy",
    "region": "us-east-1",
    "description": "...",
    "remediation": {"recommendation": {"text": "..."}}
  }
"""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        for key in ("findings", "results", "checks"):
            if isinstance(raw.get(key), list):
                return [r for r in raw[key] if isinstance(r, dict)]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-cloud",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _records(raw):
        status = (rec.get("status") or "").upper()
        if status == "PASS":
            continue
        check_id = rec.get("check_id") or rec.get("checkID") or "prowler-check"
        service = rec.get("service_name") or rec.get("Service") or ""
        region = rec.get("region") or rec.get("Region") or ""
        resource = rec.get("resource_id") or rec.get("ResourceId") or "cloud-resource"
        remediation_block = rec.get("remediation") or {}
        if isinstance(remediation_block, dict):
            recommendation_text = (
                (remediation_block.get("recommendation") or {}).get("text")
                if isinstance(remediation_block.get("recommendation"), dict)
                else None
            ) or remediation_block.get("text")
        else:
            recommendation_text = str(remediation_block)
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="prowler",
                title=f"{service} · {check_id}",
                category="cloud",
                severity=map_severity(rec.get("severity")),
                confidence=Confidence.high,
                impact=rec.get("description") or rec.get("status_extended") or f"prowler {check_id} flagged {resource}.",
                recommendation=recommendation_text or "Apply the prowler remediation guidance for this check.",
                reproduction=f"prowler reported {status} for {check_id} on {resource} ({region}).",
                false_positive_reasoning="prowler reads live cloud configuration via read-only API calls.",
                raw=rec,
                summary=f"prowler {status} {check_id} {resource}",
                affected_asset=resource,
                affected_component=f"{service}/{region}" if service else region or "cloud",
                is_demo_data=is_demo_data,
            )
        )
    return findings
