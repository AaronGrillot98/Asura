"""kube-score JSON parser (`-o json`).

The JSON is a list:
  [
    {"object_name": "...", "type_meta": {...}, "file_name": "...",
     "checks": [
       {"check": {"name": "..."}, "grade": 0..10, "comments": [
         {"summary": "...", "description": "..."}
       ]}
     ]}
  ]

kube-score grades:
  10 — OK
   5 — Critical (skip the check; usually grade=0 means failure)
   1 — Failure
A grade < 7 is treated as a finding.
"""
from __future__ import annotations

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-host",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(raw, list):
        return findings
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        object_name = entry.get("object_name") or "k8s-object"
        file_name = entry.get("file_name") or "manifest"
        for check_entry in entry.get("checks") or []:
            if not isinstance(check_entry, dict):
                continue
            grade = check_entry.get("grade")
            if not isinstance(grade, int) or grade >= 7:
                continue
            check_name = (check_entry.get("check") or {}).get("name") or "kube-score-check"
            comments = check_entry.get("comments") or []
            summary = "; ".join(
                str(c.get("summary") or "") for c in comments if isinstance(c, dict)
            )
            severity = Severity.high if grade <= 1 else Severity.medium
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="kube-score",
                    title=f"{check_name} on {object_name}",
                    category="kubernetes",
                    severity=severity,
                    confidence=Confidence.medium,
                    impact=summary or "kube-score flagged a Kubernetes best-practice issue.",
                    recommendation="Apply the kube-score guidance for this check.",
                    reproduction=f"kube-score grade {grade} on {file_name} / {object_name} / {check_name}.",
                    false_positive_reasoning="kube-score evaluates manifests against documented best-practice checks.",
                    raw={"object_name": object_name, "file_name": file_name, "check": check_entry},
                    summary=f"kube-score grade={grade} {object_name}",
                    affected_asset=object_name,
                    affected_component=check_name,
                    file_path=file_name,
                    is_demo_data=is_demo_data,
                )
            )
    return findings
