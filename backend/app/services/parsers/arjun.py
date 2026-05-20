"""Arjun JSON parser.

Arjun's `-oJ <file>` output groups discovered parameters by URL:

    {
      "https://target.example/api/items": {
        "params": ["debug", "userId", "verbose"],
        "method": "GET",
        "headers": { ... }
      }
    }

Each discovered parameter is its own Finding so analysts can pivot
from the parameter name straight into a downstream fuzz / XSS pass.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _coerce_dict(raw)
    if not isinstance(doc, dict):
        return []

    findings: list[Finding] = []
    for url, info in doc.items():
        if not isinstance(info, dict):
            continue
        params = info.get("params") or info.get("parameters") or []
        method = info.get("method") or "GET"
        if not isinstance(params, list):
            continue
        for param in params:
            name = str(param).strip()
            if not name:
                continue
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="arjun",
                    title=f"Hidden parameter `{name}` on {method} {url}",
                    category="web",
                    severity=Severity.info,
                    confidence=Confidence.high,
                    impact=(
                        f"Arjun found that `{url}` responds to the undocumented parameter `{name}` "
                        f"on {method}. Hidden parameters frequently expose debug toggles, raw filters, "
                        "or alternate auth surfaces."
                    ),
                    recommendation=(
                        f"Fuzz `{name}` with payloads appropriate for its data type, and verify the "
                        "parameter isn't tied to internal admin functionality."
                    ),
                    reproduction=f"arjun -u {url} -m {method}  ->  parameter `{name}` accepted",
                    false_positive_reasoning=(
                        "Arjun heuristically detects parameter reflection; some matches are caused "
                        "by frameworks accepting any parameter and ignoring it."
                    ),
                    raw={"url": url, "method": method, "parameter": name, "all_params": params},
                    summary=f"arjun param {name} @ {url}",
                    affected_asset=url,
                    affected_component=name,
                    owasp=["A05:2021-Security Misconfiguration"],
                    is_demo_data=is_demo_data,
                )
            )
    return findings


def _coerce_dict(raw: object) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return None
