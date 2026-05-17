"""trufflehog JSON / JSONL parser (secrets)."""
from __future__ import annotations

import json
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _records(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        if "results" in raw and isinstance(raw["results"], list):
            return [r for r in raw["results"] if isinstance(r, dict)]
        return [raw]
    if isinstance(raw, str):
        out: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _records(raw):
        detector = rec.get("DetectorName") or rec.get("detector") or "secret"
        verified = bool(rec.get("Verified"))
        # SourceMetadata.Data.Filesystem.file is the canonical filesystem hit.
        source_meta = (rec.get("SourceMetadata") or {}).get("Data") or {}
        fs = (source_meta.get("Filesystem") or {}) if isinstance(source_meta, dict) else {}
        git = (source_meta.get("Git") or {}) if isinstance(source_meta, dict) else {}
        file_path = fs.get("file") or git.get("file") or "unknown"
        line = fs.get("line") or git.get("line") or 0
        confidence = Confidence.confirmed if verified else Confidence.high
        severity = Severity.critical if verified else Severity.high
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="trufflehog",
                title=f"Secret detected: {detector}{' (verified)' if verified else ''}",
                category="secrets",
                severity=severity,
                confidence=confidence,
                impact="Detected credential may grant access to downstream systems if still valid.",
                recommendation="Rotate the credential, remove it from git history, and add the pattern to your secret-scanning baseline.",
                reproduction=f"trufflehog matched detector '{detector}' in {file_path}:{line}.",
                false_positive_reasoning=(
                    "trufflehog verified the credential against the provider's live API."
                    if verified
                    else "trufflehog matched the credential pattern; verification was not attempted or failed."
                ),
                raw=rec,
                summary=f"trufflehog {detector} at {file_path}:{line}",
                affected_asset=file_path,
                affected_component=f"{file_path}:{line}",
                file_path=file_path,
                cwe=["CWE-798"],
                is_demo_data=is_demo_data,
            )
        )
    return findings
