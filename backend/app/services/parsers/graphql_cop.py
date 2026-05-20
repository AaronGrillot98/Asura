"""graphql-cop JSON parser.

`graphql-cop -t <url> -o json` emits an array of audit results:

    [
      {
        "title": "Introspection Query Enabled",
        "severity": "HIGH",
        "color": "RED",
        "description": "Field suggestions are enabled...",
        "impact": "Disable introspection in production.",
        "result": true,
        "curl_verify": "curl -X POST ..."
      }
    ]

`result: true` means the check fired (a problem was detected). Checks
that returned `false` are dropped so we only emit findings for actual
hits.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding, map_severity


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-api",
    is_demo_data: bool = False,
) -> list[Finding]:
    items = _coerce_list(raw)

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        # graphql-cop emits a row per check; only the ones that triggered
        # are interesting.
        if item.get("result") is False:
            continue
        title = item.get("title") or "GraphQL audit hit"
        severity = map_severity(item.get("severity"), default=Severity.medium)
        description = item.get("description") or ""
        impact = item.get("impact") or description
        curl_verify = item.get("curl_verify") or ""

        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="graphql-cop",
                title=f"GraphQL: {title}",
                category="api",
                severity=severity,
                confidence=Confidence.high,
                impact=impact or f"graphql-cop check `{title}` triggered against the target endpoint.",
                recommendation=(
                    item.get("impact")
                    or "Review the GraphQL server hardening guide and disable the offending feature in production."
                ),
                reproduction=curl_verify or f"graphql-cop check `{title}` returned true",
                false_positive_reasoning=(
                    "graphql-cop checks are HTTP probes against the configured endpoint; non-prod "
                    "environments routinely enable introspection / suggestions / batching."
                ),
                raw=item,
                summary=f"graphql-cop {title}",
                affected_component=title,
                owasp=["A05:2021-Security Misconfiguration", "A04:2021-Insecure Design"],
                is_demo_data=is_demo_data,
            )
        )
    return findings


def _coerce_list(raw: object) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("findings", "results", "data"):
            val = raw.get(key)
            if isinstance(val, list):
                return val
        return []
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return _coerce_list(decoded)
    return []
