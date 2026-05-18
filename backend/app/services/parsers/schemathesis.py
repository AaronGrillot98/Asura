"""Schemathesis text parser.

Schemathesis has no first-class JSON report; its stable formats are
JUnit XML (`--report junit`) and the pretty-printed text summary it
writes to stdout. We parse the text summary — every section between
`____` underscore separators is a single failing test case, with a
`Status Code Conformance` / `Server error` / `Schema conformance` line
identifying the check kind.

Each failed test case becomes one finding. The schema id (`POST /users`)
is the affected component, the check label is the title.
"""
from __future__ import annotations

import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


# Schemathesis prints separator lines that are dozens of underscores
# followed by the schema location, e.g. "_____ POST /users _____".
_HEADER = re.compile(r"^_{3,}\s*(?P<schema>[A-Z]+\s+\S+)\s*_{3,}\s*$")
_CHECK_FAIL = re.compile(r"^\s*\d+\.\s*(?P<check>[A-Za-z][\w \-]+)\s*$")
_SERVER_ERROR = re.compile(r"^\s*\[(?P<code>\d{3})\]\s*Server Error.*$")


_CHECK_SEVERITY = {
    "server error": Severity.high,
    "status code conformance": Severity.medium,
    "schema conformance": Severity.medium,
    "response schema conformance": Severity.medium,
    "negative data acceptance": Severity.medium,
    "content type conformance": Severity.low,
    "response headers conformance": Severity.low,
    "not a server error": Severity.high,
}


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
    current_schema: str | None = None
    current_block: list[str] = []
    seen: set[tuple[str, str]] = set()

    def flush(schema: str | None, block: list[str]) -> None:
        if not schema or not block:
            return
        check_label: str | None = None
        for line in block:
            m = _CHECK_FAIL.match(line)
            if m:
                check_label = m.group("check").strip()
                break
            m2 = _SERVER_ERROR.match(line)
            if m2:
                check_label = f"Server Error ({m2.group('code')})"
                break
        if not check_label:
            # No recognizable check label — skip the block (likely a
            # summary / overview section).
            return
        key = (schema, check_label)
        if key in seen:
            return
        seen.add(key)
        sev = _CHECK_SEVERITY.get(check_label.lower(), Severity.medium)
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="schemathesis",
                title=f"{check_label} — {schema}",
                category="api",
                severity=sev,
                confidence=Confidence.high,
                impact=f"{check_label} failed for {schema}.",
                recommendation=(
                    "Run schemathesis locally with `--show-trace` and the same seed to "
                    "reproduce, then patch the handler or update the schema to match."
                ),
                reproduction=f"schemathesis run <spec> --checks all  # failure on {schema}",
                false_positive_reasoning=(
                    "Schemathesis generates inputs from the schema — false positives appear when "
                    "the schema overstates what the API accepts."
                ),
                raw={"schema": schema, "check": check_label, "block": "\n".join(block)[:2000]},
                summary=f"schemathesis {check_label} {schema}",
                affected_asset=schema,
                affected_component=check_label,
                is_demo_data=is_demo_data,
            )
        )

    for line in text.splitlines():
        header = _HEADER.match(line)
        if header:
            flush(current_schema, current_block)
            current_schema = header.group("schema").strip()
            current_block = []
            continue
        if current_schema is not None:
            current_block.append(line)

    flush(current_schema, current_block)
    return findings
