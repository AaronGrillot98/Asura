"""docker-bench-security JSON parser (`-j`).

The script wraps the CIS Docker Benchmark. JSON output has a top-level
`tests` list (one entry per top-level section: Host Configuration,
Daemon Configuration, ...) and each section has a `results` list with:

  - `id`      — CIS rule number (e.g. "1.1.1")
  - `desc`    — rule description
  - `result`  — "PASS" | "WARN" | "INFO" | "NOTE"
  - `details` — free-form notes

We only emit findings for `result: WARN` (the only "you should fix this"
state). `NOTE` and `INFO` come through at info-severity. `PASS` is
discarded — passing CIS checks aren't findings.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_RESULT_TO_SEVERITY = {
    "WARN": Severity.medium,
    "NOTE": Severity.info,
    "INFO": Severity.info,
}


def _doc(raw: object) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-host",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _doc(raw)
    findings: list[Finding] = []
    for section in doc.get("tests") or []:
        if not isinstance(section, dict):
            continue
        section_desc = section.get("desc") or section.get("id") or "CIS section"
        for result in section.get("results") or []:
            if not isinstance(result, dict):
                continue
            outcome = (result.get("result") or "").upper()
            if outcome not in _RESULT_TO_SEVERITY:
                continue
            rule_id = result.get("id") or "docker-bench"
            desc = result.get("desc") or rule_id
            details = result.get("details") or ""
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="docker-bench-security",
                    title=f"CIS {rule_id} — {desc[:120]}",
                    category="container",
                    severity=_RESULT_TO_SEVERITY[outcome],
                    confidence=Confidence.high,
                    impact=f"{desc}. {details}".strip(),
                    recommendation=(
                        "Consult the CIS Docker Benchmark for the recommended remediation "
                        "for this rule."
                    ),
                    reproduction=f"docker-bench-security -j  # CIS {rule_id}",
                    false_positive_reasoning=(
                        "docker-bench-security inspects the live daemon and host config; some "
                        "checks legitimately don't apply in certain managed environments (EKS, GKE, etc.)."
                    ),
                    raw=result,
                    summary=f"docker-bench {rule_id} {outcome}",
                    affected_asset=section_desc,
                    affected_component=rule_id,
                    is_demo_data=is_demo_data,
                )
            )
    return findings
