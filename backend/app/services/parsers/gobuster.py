"""Gobuster text parser.

Gobuster's default text output is one line per match. The most common shapes:
  `/admin                (Status: 200) [Size: 1234]`
  `Found: /admin           (Status: 200) [Size: 1234]`
  `https://example.com/admin (Status: 200) [Size: 1234]`
This parser is tolerant of all three.
"""
from __future__ import annotations

import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_LINE = re.compile(
    r"^(?:Found:\s+)?(\S+)\s+\(Status:\s*(\d{3})\)\s*(?:\[Size:\s*([0-9]+)\])?",
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
        path = match.group(1)
        status = int(match.group(2))
        size = int(match.group(3) or 0)
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="gobuster",
                title=f"Discovered: {status} {path}",
                category="web",
                severity=_severity_for(status),
                confidence=Confidence.high,
                impact=f"gobuster discovered {path} returning HTTP {status} ({size} bytes).",
                recommendation="Confirm the endpoint is intentional. Sensitive paths returning 200 are the highest-value follow-up.",
                reproduction=f"gobuster found {path} returning HTTP {status}.",
                false_positive_reasoning="gobuster reports observed HTTP responses; cross-validate before treating as definitive.",
                raw={"path": path, "status": status, "size": size},
                summary=f"gobuster {status} {path}",
                affected_asset=path,
                affected_component="content_discovery",
                is_demo_data=is_demo_data,
            )
        )
    return findings
