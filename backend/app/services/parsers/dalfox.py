"""Dalfox JSON parser.

Dalfox's `--format json` (or `-o json`) emits an array of finding objects:

    [
      {
        "type": "G",                 # G=Generated, R=Reflected, V=Verified
        "inject_type": "BAV",        # injection class
        "method": "GET",
        "data": "https://target/?q=<payload>",
        "param": "q",
        "payload": "<svg/onload=alert(1)>",
        "evidence": "<svg/onload=alert(1)>",
        "cwe": "CWE-79",
        "severity": "High",
        "poc_type": "plain",
        "message_id": 0,
        "message_str": "Reflected XSS via param `q`"
      }
    ]

The `type` field decides confidence:
- `V` (Verified): high  — Dalfox triggered + observed the payload
- `R` (Reflected): medium — payload echoed but not necessarily executable
- `G` (Generated): low — candidate payload, not yet probed
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding, map_severity


_CONFIDENCE_BY_TYPE: dict[str, Confidence] = {
    "v": Confidence.confirmed,
    "r": Confidence.high,
    "g": Confidence.low,
}


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    results = _coerce_list(raw)
    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type", "")).strip().lower()
        confidence = _CONFIDENCE_BY_TYPE.get(kind, Confidence.medium)
        severity = map_severity(item.get("severity"), default=Severity.high)
        param = item.get("param") or "?"
        method = item.get("method") or "GET"
        payload = item.get("payload") or ""
        url = item.get("data") or item.get("url") or ""
        cwe = [item.get("cwe")] if item.get("cwe") else []

        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="dalfox",
                title=f"XSS candidate on {param} ({method})",
                category="web",
                severity=severity,
                confidence=confidence,
                impact=(
                    item.get("message_str")
                    or f"Dalfox flagged a {kind.upper() or 'candidate'} XSS via parameter `{param}`."
                ),
                recommendation=(
                    "Validate exploitability in a sandbox, then encode/escape user input and add a CSP that blocks inline scripts."
                ),
                reproduction=f"{method} {url}  with param `{param}` = `{payload}`",
                false_positive_reasoning=(
                    "Reflected/Generated dalfox results require manual confirmation; "
                    "Verified results were triggered by dalfox in-process."
                ),
                raw=item,
                summary=f"dalfox xss({kind or '?'}) on {param}",
                affected_asset=url or param,
                affected_component=param,
                cwe=cwe,
                owasp=["A03:2021-Injection"],
                is_demo_data=is_demo_data,
            )
        )
    return findings


def _coerce_list(raw: object) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        # Some dalfox versions wrap results in {"version": ..., "findings": [...]}
        for key in ("findings", "results", "data"):
            value = raw.get(key)
            if isinstance(value, list):
                return value
        return []
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return _coerce_list(decoded)
    return []
