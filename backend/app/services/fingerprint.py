"""Finding fingerprinting.

Two scans on the same target should not produce duplicate findings. The
fingerprint hashes the small set of identity-bearing fields so a repository
can detect a recurrence and update `last_seen` instead of inserting again.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

from app.models.schemas import Finding


def _coerce(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(_coerce(item) for item in value))
    return str(value).strip().lower()


def finding_fingerprint(finding: Finding) -> str:
    """Stable identity hash for a Finding.

    The fields included are deliberately narrow — title is excluded because
    minor wording changes shouldn't break dedupe; raw evidence is excluded
    because it's per-run.
    """
    parts: list[str] = [
        _coerce(finding.scanner),
        _coerce(finding.category),
        _coerce(finding.asset_id),
        _coerce(finding.affected_asset),
        _coerce(finding.affected_component),
        _coerce(finding.cwe),
        _coerce(finding.cve),
    ]
    # If the evidence record carries a file path / rule id, include it so
    # parser-driven findings dedupe by location.
    for ev in finding.evidence:
        parts.append(_coerce(ev.file_path))
        rule = ev.raw.get("rule") if isinstance(ev.raw, dict) else None
        parts.append(_coerce(rule))
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings de-duplicated by fingerprint, keeping the first seen."""
    seen: dict[str, Finding] = {}
    order: list[str] = []
    for f in findings:
        fp = f.fingerprint_hash or finding_fingerprint(f)
        if fp in seen:
            continue
        # Stamp the fingerprint so downstream code can rely on it.
        f.fingerprint_hash = fp
        seen[fp] = f
        order.append(fp)
    return [seen[fp] for fp in order]
