"""YARA text parser.

YARA's default text output is one match per line:

    SuspiciousMacro samples/doc.bin
    CryptoMiner    /workspace/var/cron/spoolsv
    EternalBlue    samples/win/eb.exe

The optional `-s` flag adds matched strings on indented lines below the
header. We keep the parser tolerant: it accepts both shapes and drops
anything that doesn't look like a match line.
"""
from __future__ import annotations

import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


# Rule names are identifier-like; path can be anything until end-of-line.
_MATCH_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$")


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-fs",
    is_demo_data: bool = False,
) -> list[Finding]:
    text = _coerce_text(raw)
    if not text:
        return []

    findings: list[Finding] = []
    current_strings: list[str] = []
    last_match: tuple[str, str] | None = None

    def _flush() -> None:
        nonlocal last_match, current_strings
        if last_match is None:
            return
        rule, path = last_match
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="yara",
                title=f"{rule} matched {path}",
                category="detection",
                severity=Severity.high,
                confidence=Confidence.high,
                impact=(
                    f"YARA rule `{rule}` matched `{path}`. Confirm whether the rule's "
                    "context (malware, miner, dual-use binary) applies to your environment."
                ),
                recommendation=(
                    "Inspect the file with `file`/`strings`, quarantine if untrusted, and "
                    "correlate with EDR telemetry on the host of origin."
                ),
                reproduction=f"yara <rules> {path} -> rule `{rule}` triggered",
                false_positive_reasoning=(
                    "YARA matches are byte-pattern driven; legitimate software can hit "
                    "shared signatures (cryptography, packers, language runtimes)."
                ),
                raw={"rule": rule, "path": path, "strings": current_strings},
                summary=f"yara {rule} @ {path}",
                affected_asset=path,
                affected_component=rule,
                file_path=path,
                owasp=["A05:2021-Security Misconfiguration"],
                is_demo_data=is_demo_data,
            )
        )
        last_match = None
        current_strings = []

    for line in text.splitlines():
        if not line.strip():
            continue
        # Indented continuations carry matched strings when `-s` was used.
        if line.startswith((" ", "\t")) and last_match is not None:
            current_strings.append(line.strip())
            continue
        match = _MATCH_LINE.match(line)
        if not match:
            continue
        _flush()
        last_match = (match.group(1), match.group(2))
    _flush()
    return findings


def _coerce_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("stdout", "output", "text", "matches"):
            val = raw.get(key)
            if isinstance(val, str) and val:
                return val
    if isinstance(raw, list):
        return "\n".join(str(item) for item in raw if item)
    return ""
