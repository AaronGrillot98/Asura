"""Dirsearch text parser.

Plain-text output (one line per discovery):
  `[14:23:45] 200 -    1KB - /admin/`
  `[14:23:46] 301 -  256B  - /login`
  `[14:23:47] 403 -    0B  - /private`
"""
from __future__ import annotations

import re

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_LINE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)?(\d{3})\s+-?\s*([0-9.]+\s*[KMGT]?B)?\s+-?\s*(\S+)",
    re.MULTILINE,
)


def _severity_for(status: int) -> Severity:
    if 200 <= status < 300:
        return Severity.medium
    if 300 <= status < 400:
        return Severity.low
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
    text = raw if isinstance(raw, str) else ""
    if not text and isinstance(raw, dict):
        text = str(raw.get("stdout") or "")
    for match in _LINE.finditer(text):
        status = int(match.group(1))
        size = match.group(2) or ""
        path = match.group(3)
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="dirsearch",
                title=f"Discovered: {status} {path}",
                category="web",
                severity=_severity_for(status),
                confidence=Confidence.high,
                impact=f"dirsearch discovered {path} returning HTTP {status} ({size}).",
                recommendation="Confirm the endpoint is intentional and review for sensitive content.",
                reproduction=f"dirsearch found {path} returning HTTP {status}.",
                false_positive_reasoning="dirsearch reports observed HTTP responses; cross-validate before treating as definitive.",
                raw={"path": path, "status": status, "size": size},
                summary=f"dirsearch {status} {path}",
                affected_asset=path,
                affected_component="content_discovery",
                is_demo_data=is_demo_data,
            )
        )
    return findings
