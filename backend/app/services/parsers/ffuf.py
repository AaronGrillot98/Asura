"""ffuf JSON parser (`-of json`)."""
from __future__ import annotations

from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _results(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [r for r in raw.get("results") or [] if isinstance(r, dict)]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def _severity_for(status: int) -> Severity:
    if status >= 500:
        return Severity.low
    if status >= 400:
        return Severity.info
    if 300 <= status < 400:
        return Severity.low
    if 200 <= status < 300:
        return Severity.medium  # an unexpected 200 is the interesting case
    return Severity.info


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _results(raw):
        url = rec.get("url") or "unknown"
        status = int(rec.get("status") or 0)
        length = rec.get("length") or 0
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="ffuf",
                title=f"Reachable: HTTP {status} {url}",
                category="web",
                severity=_severity_for(status),
                confidence=Confidence.high,
                impact=f"ffuf discovered an HTTP {status} response at {url} ({length} bytes).",
                recommendation="Confirm the endpoint is intentional. Anything 200/302/401 on an admin / debug path is worth investigating.",
                reproduction=f"ffuf matched {url} returning HTTP {status}.",
                false_positive_reasoning="ffuf reports the raw HTTP response; treat 200s on sensitive paths as suspicious.",
                raw=rec,
                summary=f"ffuf {status} {url}",
                affected_asset=url,
                affected_component="content_discovery",
                is_demo_data=is_demo_data,
            )
        )
    return findings
