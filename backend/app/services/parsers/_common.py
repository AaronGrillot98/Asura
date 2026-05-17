"""Shared parser helpers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.models.schemas import Confidence, Evidence, EvidenceType, Finding, Severity
from app.services.evidence_store import content_hash

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "informational": Severity.info,
    "unknown": Severity.low,
}


def map_severity(value: Any, default: Severity = Severity.medium) -> Severity:
    if value is None:
        return default
    key = str(value).strip().lower()
    return SEVERITY_MAP.get(key, default)


def map_confidence(value: Any, default: Confidence = Confidence.medium) -> Confidence:
    if value is None:
        return default
    key = str(value).strip().lower()
    return {
        "low": Confidence.low,
        "medium": Confidence.medium,
        "high": Confidence.high,
        "confirmed": Confidence.confirmed,
    }.get(key, default)


def build_evidence(
    *,
    finding_id: str,
    scanner: str,
    summary: str,
    raw: dict[str, Any],
    file_path: str | None = None,
    is_demo_data: bool = False,
) -> Evidence:
    """Build an in-memory Evidence record. Persistence is left to the runner."""
    return Evidence(
        id=f"ev-{uuid4().hex[:10]}",
        finding_id=finding_id,
        evidence_type=EvidenceType.scanner_output,
        scanner=scanner,
        raw=raw,
        summary=summary,
        source_tool=scanner,
        file_path=file_path,
        captured_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        content_hash=content_hash(raw),
        is_demo_data=is_demo_data,
    )


def make_finding(
    *,
    project_id: str,
    scan_id: str | None,
    asset_id: str,
    scanner: str,
    title: str,
    severity: Severity,
    confidence: Confidence | int = Confidence.medium,
    impact: str,
    recommendation: str,
    reproduction: str,
    false_positive_reasoning: str,
    raw: dict[str, Any],
    summary: str,
    category: str = "security",
    affected_asset: str | None = None,
    affected_component: str | None = None,
    file_path: str | None = None,
    cwe: list[str] | None = None,
    cve: list[str] | None = None,
    owasp: list[str] | None = None,
    is_demo_data: bool = False,
) -> Finding:
    finding_id = f"f-{scanner}-{uuid4().hex[:8]}"
    evidence = build_evidence(
        finding_id=finding_id,
        scanner=scanner,
        summary=summary,
        raw=raw,
        file_path=file_path,
        is_demo_data=is_demo_data,
    )
    now = datetime.now(timezone.utc)
    return Finding(
        id=finding_id,
        project_id=project_id,
        scan_id=scan_id,
        asset_id=asset_id,
        scanner=scanner,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        status="new",
        affected_asset=affected_asset,
        affected_component=affected_component,
        impact=impact,
        reproduction=reproduction,
        false_positive_reasoning=false_positive_reasoning,
        recommendation=recommendation,
        cwe=cwe or [],
        cve=cve or [],
        owasp_mapping=owasp or [],
        source_tools=[scanner],
        first_seen=now,
        last_seen=now,
        created_at=now,
        evidence=[evidence],
        is_demo_data=is_demo_data,
    )
