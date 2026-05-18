"""jwt_tool text parser.

jwt_tool is text-only — there is no JSON output. We parse stdout looking
for the headlines it prints:

  - "Token header values:" / "Token payload values:" → one info finding
    summarising the decoded JWT.
  - "[!] " / "[+] Vulnerability" → one medium/high finding per issue.

Common issue lines we treat as high:
  - "alg=none" / "none algorithm" — auth bypass.
  - "JWT signature reuse" / "JWT confusion" — auth bypass.
  - "weak key" / "weak HMAC secret" — credential exposure.
"""
from __future__ import annotations

import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_HIGH_PATTERNS = (
    re.compile(r"alg\s*=\s*none", re.IGNORECASE),
    re.compile(r"none\s+algorithm", re.IGNORECASE),
    re.compile(r"jwt\s+confusion", re.IGNORECASE),
    re.compile(r"signature\s+reuse", re.IGNORECASE),
    re.compile(r"weak\s+(hmac\s+)?key", re.IGNORECASE),
    re.compile(r"key.?confusion", re.IGNORECASE),
)


def _classify(message: str) -> Severity:
    if any(p.search(message) for p in _HIGH_PATTERNS):
        return Severity.high
    return Severity.medium


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-api",
    is_demo_data: bool = False,
) -> list[Finding]:
    text = raw if isinstance(raw, str) else ""
    if not text:
        return []

    findings: list[Finding] = []

    # ---- Token summary (info) -----------------------------------------
    if "Token header values:" in text or "Token payload values:" in text:
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="jwt-tool",
                title="Decoded JWT",
                category="api",
                severity=Severity.info,
                confidence=Confidence.high,
                impact="jwt_tool decoded the supplied JWT.",
                recommendation="Inspect claims, exp/iat, and signing algorithm.",
                reproduction="jwt_tool <token>",
                false_positive_reasoning="Pure decode; no detection logic involved.",
                raw={"text": text[:4000]},
                summary="jwt_tool decoded JWT",
                affected_asset="<jwt>",
                affected_component="header+payload",
                is_demo_data=is_demo_data,
            )
        )

    # ---- Vulnerability lines (medium/high) ----------------------------
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        marker = None
        if stripped.startswith("[!]"):
            marker = stripped[3:].strip()
        elif stripped.startswith("[+] Vulnerability"):
            marker = stripped[3:].strip()
        elif stripped.startswith("Vulnerability:"):
            marker = stripped[len("Vulnerability:"):].strip()
        if not marker:
            continue
        # Skip the informational "[!] No additional checks performed" style notes.
        lower = marker.lower()
        if "no additional" in lower or "checking" in lower:
            continue
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="jwt-tool",
                title=marker[:140],
                category="api",
                severity=_classify(marker),
                confidence=Confidence.medium,
                impact=marker,
                recommendation=(
                    "Validate signing algorithm on the server side; rotate signing keys; "
                    "reject `alg=none` and disallow client-controlled algorithm choice."
                ),
                reproduction="jwt_tool <token>",
                false_positive_reasoning=(
                    "jwt_tool flags issues from the decoded token alone; some warnings only "
                    "apply if the server accepts the manipulated token."
                ),
                raw={"line": stripped},
                summary=f"jwt_tool: {marker[:80]}",
                affected_asset="<jwt>",
                affected_component="signature/claims",
                is_demo_data=is_demo_data,
            )
        )

    return findings
