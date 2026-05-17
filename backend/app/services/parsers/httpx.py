"""httpx JSONL parser (HTTP fingerprinting)."""
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
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _records(raw):
        url = rec.get("url") or rec.get("input") or "unknown"
        status = rec.get("status_code") or rec.get("status-code") or 0
        title = rec.get("title") or rec.get("webserver") or "HTTP service"
        tech = rec.get("tech") or rec.get("technologies") or []
        if isinstance(tech, list):
            tech_str = ", ".join(str(t) for t in tech[:5])
        else:
            tech_str = str(tech)
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="httpx",
                title=f"HTTP {status} at {url}",
                category="recon",
                severity=Severity.info,
                confidence=Confidence.high,
                impact=(
                    f"HTTP service responded {status}; "
                    f"title='{title}', tech=[{tech_str or 'unknown'}]."
                ),
                recommendation="Confirm the service belongs to you and is intentional.",
                reproduction=f"httpx probed {url} and recorded status {status}.",
                false_positive_reasoning="httpx records HTTP probe results verbatim; interpretation is up to the analyst.",
                raw=rec,
                summary=f"HTTP {status} at {url}",
                affected_asset=url,
                affected_component=str(title),
                is_demo_data=is_demo_data,
            )
        )
    return findings
