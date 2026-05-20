"""Kiterunner text parser.

`kr scan` emits one match per line with columns:

    POST    400 [   42,    3,   1] https://target.example/api/v1/users 0cf6ddabe16e6b6c4eaba3...
    GET     200 [  104,    8,   2] https://target.example/healthz      7b5d9c00abc...

Columns: METHOD STATUS [size_words, size_lines, size_chars] URL kite-id

Status code drives severity (200/201/204 are interesting; 403 less so
but still useful for fingerprinting; 5xx points at unstable endpoints).
"""
from __future__ import annotations

import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_LINE = re.compile(
    r"^\s*([A-Z]{3,7})\s+(\d{3})\s+\[\s*([\d,\s]+)\]\s+(\S+)(?:\s+(\S+))?\s*$"
)


def _severity_for(status: int) -> Severity:
    if 200 <= status < 300:
        return Severity.medium
    if status in (401, 403):
        return Severity.low
    if status in (301, 302, 307, 308):
        return Severity.low
    if 400 <= status < 500:
        return Severity.info
    if 500 <= status < 600:
        return Severity.low
    return Severity.info


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-api",
    is_demo_data: bool = False,
) -> list[Finding]:
    text = _coerce_text(raw)
    if not text:
        return []

    findings: list[Finding] = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        method = m.group(1)
        status = int(m.group(2))
        size = m.group(3).strip()
        url = m.group(4)
        kite_id = (m.group(5) or "").strip()

        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="kiterunner",
                title=f"{method} {status} {url}",
                category="api",
                severity=_severity_for(status),
                confidence=Confidence.high,
                impact=(
                    f"Kiterunner found that {method} {url} returns HTTP {status} "
                    f"({size}). Endpoints surfacing through API-aware wordlists frequently lack the "
                    "same auth controls as documented routes."
                ),
                recommendation=(
                    "Confirm the endpoint is intentional, verify it enforces the project's auth "
                    "policy, and add it to API documentation or scope rules if it should remain."
                ),
                reproduction=f"{method} {url}  ->  HTTP {status} ({size}) (kite-id: {kite_id or 'n/a'})",
                false_positive_reasoning=(
                    "Kiterunner reports observed HTTP responses; servers can blanket-route unknown "
                    "paths to a generic handler, producing many hits that share one source."
                ),
                raw={
                    "method": method,
                    "status": status,
                    "url": url,
                    "size": size,
                    "kite_id": kite_id,
                },
                summary=f"kiterunner {method} {status} {url}",
                affected_asset=url,
                affected_component=method,
                owasp=["A05:2021-Security Misconfiguration"],
                is_demo_data=is_demo_data,
            )
        )
    return findings


def _coerce_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("stdout", "output", "text"):
            val = raw.get(key)
            if isinstance(val, str):
                return val
    if isinstance(raw, list):
        return "\n".join(str(item) for item in raw if item)
    return ""
