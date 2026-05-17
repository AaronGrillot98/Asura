"""ESLint JSON parser (uses the security plugin or any ruleset)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_SEVERITY_BY_LEVEL: dict[int, Severity] = {
    0: Severity.info,
    1: Severity.medium,  # warning
    2: Severity.high,    # error
}


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(raw, list):
        return findings
    for file_record in raw:
        if not isinstance(file_record, dict):
            continue
        file_path = file_record.get("filePath") or "unknown"
        for msg in file_record.get("messages") or []:
            if not isinstance(msg, dict):
                continue
            rule_id = msg.get("ruleId") or "eslint-rule"
            line = msg.get("line") or 0
            severity = _SEVERITY_BY_LEVEL.get(int(msg.get("severity") or 1), Severity.medium)
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="eslint-security",
                    title=f"{rule_id}: {msg.get('message', '')}".strip().rstrip(":"),
                    category="code",
                    severity=severity,
                    confidence=Confidence.medium,
                    impact=msg.get("message") or "ESLint flagged a code-quality / security issue.",
                    recommendation="Address the lint message per the rule's documentation.",
                    reproduction=f"ESLint {rule_id} matched {file_path}:{line}",
                    false_positive_reasoning="ESLint matched a configured rule against JS/TS source.",
                    raw={"file": file_path, **msg},
                    summary=f"ESLint {rule_id} at {file_path}:{line}",
                    affected_asset=file_path,
                    affected_component=f"{file_path}:{line}",
                    file_path=file_path,
                    is_demo_data=is_demo_data,
                )
            )
    return findings
