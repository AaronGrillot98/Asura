"""OWASP ZAP JSON parser."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity, map_confidence


def _alerts(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        alerts: list[dict[str, Any]] = []
        for site in raw.get("site", []) or []:
            for alert in (site or {}).get("alerts", []) or []:
                if isinstance(alert, dict):
                    alerts.append(alert)
        # Some ZAP exports use a flat "alerts" key.
        for alert in raw.get("alerts", []) or []:
            if isinstance(alert, dict):
                alerts.append(alert)
        return alerts
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
    for rec in _alerts(raw):
        name = rec.get("name") or rec.get("alert") or "ZAP alert"
        risk = rec.get("riskdesc") or rec.get("risk") or "Medium"
        url = rec.get("url") or "unknown"
        cwes = []
        if rec.get("cweid"):
            cwes.append(f"CWE-{rec.get('cweid')}")
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="zap",
                title=name,
                category="web",
                severity=map_severity(str(risk).split()[0] if risk else "medium"),
                confidence=map_confidence(rec.get("confidence")),
                impact=rec.get("desc") or "ZAP observed the alert condition on a scanned URL.",
                recommendation=rec.get("solution") or "Apply ZAP's recommended mitigation.",
                reproduction=f"ZAP raised '{name}' on {url}.",
                false_positive_reasoning="ZAP attached the matched evidence inline; review for accuracy.",
                raw=rec,
                summary=f"{name} at {url}",
                affected_asset=url,
                affected_component=name,
                cwe=cwes,
                owasp=[rec.get("wascid") or "OWASP DAST"] if rec.get("wascid") else [],
                is_demo_data=is_demo_data,
            )
        )
    return findings
