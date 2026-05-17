"""Bearer JSON parser (privacy + security static analysis)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding

from ._common import make_finding, map_severity


def _iter_findings(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        return []
    flat: list[dict[str, Any]] = []
    # Bearer's JSON groups findings by severity (`critical`, `high`, ...).
    for severity_bucket in ("critical", "high", "medium", "low", "warning", "info"):
        items = raw.get(severity_bucket)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    item = {**item, "_bucket_severity": severity_bucket}
                    flat.append(item)
    # Also accept a flat 'findings' list.
    items = raw.get("findings")
    if isinstance(items, list):
        flat.extend(i for i in items if isinstance(i, dict))
    return flat


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _iter_findings(raw):
        rule_id = rec.get("id") or rec.get("rule") or "bearer-rule"
        title = rec.get("title") or rec.get("description") or rule_id
        file_path = rec.get("filename") or rec.get("file") or "unknown"
        line = rec.get("line_number") or rec.get("line") or 0
        severity = map_severity(rec.get("severity") or rec.get("_bucket_severity"))
        cwes = []
        if isinstance(rec.get("cwe_ids"), list):
            cwes = [f"CWE-{c}" if not str(c).startswith("CWE-") else str(c) for c in rec["cwe_ids"]]
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="bearer",
                title=title,
                category="code",
                severity=severity,
                confidence=Confidence.medium,
                impact=rec.get("description") or title,
                recommendation=rec.get("documentation_url") or "Review Bearer's documentation for the matched rule.",
                reproduction=f"Bearer {rule_id} matched {file_path}:{line}",
                false_positive_reasoning="Bearer matched a configured privacy/security rule against source.",
                raw=rec,
                summary=f"Bearer {rule_id} at {file_path}:{line}",
                affected_asset=file_path,
                affected_component=f"{file_path}:{line}",
                file_path=file_path,
                cwe=cwes,
                is_demo_data=is_demo_data,
            )
        )
    return findings
