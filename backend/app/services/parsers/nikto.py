"""Nikto JSON parser (`-Format json -output -`).

Nikto emits one JSON document per host with a `vulnerabilities` list.
Each vuln has an id, method, url, and a one-line `msg`. Severity isn't
reported; we map to `medium` by default and bump to `high` for the
findings whose message screams "exposure" (admin paths, auth bypass,
default creds, traversal).
"""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_HIGH_KEYWORDS = (
    "default credentials",
    "admin",
    "directory traversal",
    "remote code execution",
    "authentication bypass",
    "sql injection",
    "shellshock",
    "log4shell",
    "exposed",
)


def _severity_from_message(msg: str) -> Severity:
    lower = (msg or "").lower()
    if any(kw in lower for kw in _HIGH_KEYWORDS):
        return Severity.high
    return Severity.medium


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if isinstance(raw, list):
        # nikto emits an array of host dicts when scanning multiple targets.
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-web",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for host_record in _records(raw):
        host = host_record.get("host") or host_record.get("ip") or "host"
        port = host_record.get("port")
        base = f"{host}:{port}" if port else str(host)
        for vuln in host_record.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            msg = vuln.get("msg") or "Nikto finding"
            url = vuln.get("url") or "/"
            method = vuln.get("method") or "GET"
            vuln_id = vuln.get("id") or vuln.get("OSVDB") or "nikto"
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="nikto",
                    title=msg.split(".")[0][:140] or f"Nikto {vuln_id}",
                    category="web",
                    severity=_severity_from_message(msg),
                    confidence=Confidence.medium,
                    impact=msg,
                    recommendation="Review the flagged URL and harden the server config.",
                    reproduction=f"{method} {base}{url}",
                    false_positive_reasoning=(
                        "Nikto fingerprints known issues; some triggers are based on banners "
                        "and may produce false positives on aggressively hardened or rewritten servers."
                    ),
                    raw=vuln,
                    summary=f"nikto {vuln_id}: {msg[:80]}",
                    affected_asset=f"{base}{url}",
                    affected_component=f"{method} {url}",
                    is_demo_data=is_demo_data,
                )
            )
    return findings
