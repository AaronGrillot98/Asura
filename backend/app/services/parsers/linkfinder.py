"""LinkFinder text parser.

`python linkfinder.py -i <url|file> -o cli` writes one extracted
endpoint per line, sometimes prefixed with the source file when
multiple inputs were passed:

    /api/v1/users
    /admin/dashboard
    /js/app.bundle.js: /api/v1/users
    /js/app.bundle.js: wss://target.example/realtime

We tolerate both formats and emit one Finding per discovered link so
analysts can roll the endpoint set up into their attack surface map.
"""
from __future__ import annotations

import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


# Source-prefixed lines look like:  /path/to/app.js: /api/something
_PREFIXED = re.compile(r"^\s*([^:\s][^:]*?):\s*(\S+)\s*$")
_BARE = re.compile(r"^\s*(\S+)\s*$")


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    text = _coerce_text(raw)
    if not text:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        source = ""
        endpoint = ""
        m = _PREFIXED.match(stripped)
        if m:
            source, endpoint = m.group(1).strip(), m.group(2).strip()
        else:
            m = _BARE.match(stripped)
            if not m:
                continue
            endpoint = m.group(1).strip()
        # Endpoint must look at least URL-ish — drop obvious noise like
        # version tokens or empty matches.
        if not endpoint or len(endpoint) < 2 or endpoint.startswith(("#", "//")) and not endpoint.startswith("//"):
            continue
        key = (source, endpoint)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="linkfinder",
                title=f"Endpoint `{endpoint}` extracted from JS",
                category="web",
                severity=Severity.info,
                confidence=Confidence.medium,
                impact=(
                    f"LinkFinder extracted `{endpoint}` from "
                    f"{f'`{source}` ' if source else ''}"
                    "client-side JavaScript. Hidden endpoints often reveal admin routes, internal "
                    "APIs, or unauthenticated debug surfaces."
                ),
                recommendation=(
                    "Probe the endpoint for authentication requirements and add it to the "
                    "active scan surface if it's in scope."
                ),
                reproduction=(
                    f"linkfinder -i {source or '<bundle>'} -o cli  ->  {endpoint}"
                ),
                false_positive_reasoning=(
                    "LinkFinder uses regex over JS source; templated strings and dead-code paths "
                    "can produce endpoints that never resolve at runtime."
                ),
                raw={"source": source, "endpoint": endpoint},
                summary=f"linkfinder {endpoint}",
                affected_asset=endpoint,
                affected_component=source or None,
                file_path=source or None,
                owasp=["A05:2021-Security Misconfiguration"],
                is_demo_data=is_demo_data,
            )
        )
    return findings


def _coerce_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("stdout", "output", "endpoints", "links"):
            val = raw.get(key)
            if isinstance(val, str):
                return val
            if isinstance(val, list):
                return "\n".join(str(item) for item in val if item)
    if isinstance(raw, list):
        return "\n".join(str(item) for item in raw if item)
    return ""
