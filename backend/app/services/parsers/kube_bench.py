"""kube-bench JSON parser (`run --json`).

The shape:
  {
    "Controls": [
      {"id": "1", "version": "...", "tests": [
        {"section": "1.1", "results": [
          {"test_number": "1.1.1", "test_desc": "...", "status": "FAIL"|"WARN"|"PASS",
           "remediation": "..."}
        ]}
      ]}
    ],
    "totals": {...}
  }
"""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding

_STATUS_TO_SEVERITY = {
    "FAIL": Severity.high,
    "WARN": Severity.medium,
    "PASS": Severity.info,
}


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
    for control in raw.get("Controls") or []:
        if not isinstance(control, dict):
            continue
        for test in control.get("tests") or []:
            if not isinstance(test, dict):
                continue
            for result in test.get("results") or []:
                if not isinstance(result, dict):
                    continue
                status = (result.get("status") or "").upper()
                if status == "PASS":
                    continue  # only surface failures + warnings
                test_id = result.get("test_number") or "kube-bench-test"
                description = result.get("test_desc") or test_id
                severity = _STATUS_TO_SEVERITY.get(status, Severity.medium)
                findings.append(
                    make_finding(
                        project_id=project_id,
                        scan_id=scan_id,
                        asset_id=asset_id,
                        scanner="kube-bench",
                        title=f"CIS {test_id}: {description}",
                        category="kubernetes",
                        severity=severity,
                        confidence=Confidence.high,
                        impact=description,
                        recommendation=result.get("remediation") or "Follow the CIS Kubernetes Benchmark remediation for this control.",
                        reproduction=f"kube-bench reported {status} for {test_id}.",
                        false_positive_reasoning="kube-bench compares cluster state against the CIS Kubernetes Benchmark.",
                        raw=result,
                        summary=f"kube-bench {status} {test_id}",
                        affected_asset=asset_id,
                        affected_component=f"CIS {test_id}",
                        is_demo_data=is_demo_data,
                    )
                )
    return findings
