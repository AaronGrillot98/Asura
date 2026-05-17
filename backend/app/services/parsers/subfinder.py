"""subfinder JSONL parser (passive subdomain enumeration)."""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict) and "results" in raw:
        return [r for r in raw["results"] if isinstance(r, dict)]
    if isinstance(raw, str):
        out: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-host",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _records(raw):
        host = rec.get("host") or rec.get("subdomain") or "unknown"
        source = rec.get("source") or "passive"
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="subfinder",
                title=f"Discovered subdomain: {host}",
                category="recon",
                severity=Severity.info,
                confidence=Confidence.high,
                impact="An additional attack surface entry exists for this domain.",
                recommendation="Confirm the subdomain is intentional and inventoried.",
                reproduction=f"subfinder identified {host} via source '{source}'.",
                false_positive_reasoning="subfinder aggregates multiple passive sources; cross-validate with DNS lookups before treating as definitive.",
                raw=rec,
                summary=f"subdomain {host}",
                affected_asset=host,
                affected_component="dns",
                is_demo_data=is_demo_data,
            )
        )
    return findings
