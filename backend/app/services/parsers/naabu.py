"""naabu JSONL parser (fast port scanner)."""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
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
        host = rec.get("host") or rec.get("ip") or "unknown"
        port = rec.get("port") or 0
        protocol = rec.get("protocol") or "tcp"
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="naabu",
                title=f"Open port {protocol}/{port} on {host}",
                category="network",
                severity=Severity.info,
                confidence=Confidence.high,
                impact="Open port may expose a service to attackers if not intentional.",
                recommendation="Confirm the port is intentional, document it, and apply network policy if it should be restricted.",
                reproduction=f"naabu reported {protocol}/{port} open on {host}.",
                false_positive_reasoning="naabu confirmed an open TCP port via SYN scan.",
                raw=rec,
                summary=f"open {protocol}/{port} on {host}",
                affected_asset=host,
                affected_component=f"{protocol}/{port}",
                is_demo_data=is_demo_data,
            )
        )
    return findings
