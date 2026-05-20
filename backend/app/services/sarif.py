"""SARIF 2.1.0 import + export.

SARIF (Static Analysis Results Interchange Format) is the lingua franca for
security tool output — GitHub Code Scanning, CodeQL, Semgrep, Snyk, Trivy,
Bandit and many others all speak it. Supporting it both directions means
ASURA plugs into any CI pipeline with one HTTP call:

  # CI -> ASURA (ingest scanner output)
  curl -X POST http://asura/api/projects/<id>/imports/sarif \
       -H 'Content-Type: application/sarif+json' \
       --data-binary @semgrep.sarif

  # ASURA -> CI (publish to GitHub Code Scanning, etc.)
  curl http://asura/api/projects/<id>/findings.sarif > asura.sarif

The export keeps round-trip fidelity by writing ASURA-specific fields under
`properties.*` so a re-import preserves severity / confidence / CWE / CVE.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import uuid4

from app.models.schemas import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
)
from app.services.fingerprint import finding_fingerprint


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


class SarifParseError(ValueError):
    """Raised when the uploaded document doesn't look like SARIF 2.1.0."""


# ---------------------------------------------------------------------------
# Severity <-> SARIF level mapping
# ---------------------------------------------------------------------------
# SARIF spec defines four levels: "none", "note", "warning", "error".
# GitHub Code Scanning additionally honors a numeric `security-severity`
# (0.0–10.0) in `properties` for ordering. We map both.

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.critical: "error",
    Severity.high:     "error",
    Severity.medium:   "warning",
    Severity.low:      "note",
    Severity.info:     "note",
}

_SEVERITY_TO_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.critical: "9.5",
    Severity.high:     "8.0",
    Severity.medium:   "5.5",
    Severity.low:      "3.0",
    Severity.info:     "0.0",
}

_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error":   Severity.high,    # default for `error` if no numeric hint
    "warning": Severity.medium,
    "note":    Severity.low,
    "none":    Severity.info,
}


def _severity_from_security_severity(value: str | float | int | None) -> Severity | None:
    """GitHub's `properties.security-severity` (0-10) takes precedence over `level`."""
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    # CVSS-style buckets
    if score >= 9.0: return Severity.critical
    if score >= 7.0: return Severity.high
    if score >= 4.0: return Severity.medium
    if score > 0.0:  return Severity.low
    return Severity.info


def _confidence_value(c: Confidence | int | str | None) -> str:
    """Confidence may be enum, int, or string — normalize to a string token."""
    if c is None:
        return "medium"
    if isinstance(c, Confidence):
        return c.value
    if isinstance(c, int):
        # legacy int confidence: 0-100 → bucketed
        if c >= 90: return "confirmed"
        if c >= 70: return "high"
        if c >= 40: return "medium"
        return "low"
    return str(c)


# ---------------------------------------------------------------------------
# Export — Finding[] -> SARIF dict
# ---------------------------------------------------------------------------

def findings_to_sarif(
    findings: Iterable[Finding],
    *,
    tool_name: str = "asura",
    tool_version: str = "1.0.0",
    tool_uri: str = "https://github.com/aarongrillot/asura",
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from ASURA findings.

    Findings are grouped by their `scanner` attribute so each scanner
    becomes its own SARIF run with a properly named driver — that's how
    GitHub Code Scanning expects multi-tool uploads to be structured.
    Findings with no scanner are bundled under an `asura` aggregator run.
    """
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.scanner or tool_name, []).append(f)

    runs: list[dict[str, Any]] = []
    for scanner, scanner_findings in grouped.items():
        rules_index: dict[str, int] = {}
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        for f in scanner_findings:
            rule_id = _rule_id_for(f)
            if rule_id not in rules_index:
                rules_index[rule_id] = len(rules)
                rules.append(_rule_for_finding(rule_id, f))
            results.append(_result_for_finding(f, rule_id=rule_id, rule_index=rules_index[rule_id]))

        runs.append({
            "tool": {
                "driver": {
                    "name": scanner,
                    "version": tool_version if scanner == tool_name else "unknown",
                    "informationUri": tool_uri,
                    "rules": rules,
                },
            },
            "results": results,
            "properties": {
                "asura.exportedAt": datetime.now(timezone.utc).isoformat(),
                "asura.findingCount": len(scanner_findings),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": runs,
    }


def _rule_id_for(f: Finding) -> str:
    """Stable rule id — prefer the first CWE if present, else slugify the title."""
    if f.cwe:
        return f.cwe[0]
    if f.category and f.category != "security":
        return f"asura.{_slugify(f.category)}"
    return f"asura.{_slugify(f.title)[:48]}"


def _slugify(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s.strip().lower())
    return re.sub(r"-+", "-", s).strip("-") or "finding"


def _rule_for_finding(rule_id: str, f: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": f.title[:140]},
        "fullDescription":  {"text": (f.description or f.impact or f.title)[:1200]},
        "properties": {
            "tags": ["security", *(f.attack_tags or [])],
            "security-severity": _SEVERITY_TO_SECURITY_SEVERITY.get(f.severity, "0.0"),
            "asura.category": f.category,
        },
    }
    if f.recommendation:
        rule["help"] = {"text": f.recommendation}
    if f.cwe:
        rule["properties"]["cwe"] = list(f.cwe)
    return rule


def _result_for_finding(f: Finding, *, rule_id: str, rule_index: int) -> dict[str, Any]:
    locations = _locations_for_finding(f)
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.title},
        "properties": {
            # Round-trip metadata — preserved verbatim on re-import so the
            # ASURA fields don't lose fidelity in a CI loop.
            "asura.id": f.id,
            "asura.severity": f.severity.value,
            "asura.confidence": _confidence_value(f.confidence),
            "asura.status": f.status,
            "asura.scanner": f.scanner,
            "asura.assetId": f.asset_id,
            "security-severity": _SEVERITY_TO_SECURITY_SEVERITY.get(f.severity, "0.0"),
        },
    }
    if f.cwe:
        result["properties"]["cwe"] = list(f.cwe)
    if f.cve:
        result["properties"]["cve"] = list(f.cve)
    if locations:
        result["locations"] = locations
    # Always emit a fingerprint so a re-import dedupes against the
    # original record. Seeded findings ship without one — compute on demand.
    fp = f.fingerprint_hash or finding_fingerprint(f)
    result["fingerprints"] = {"asura/v1": fp}
    if f.remediation or f.recommendation:
        result["fixes"] = [{"description": {"text": f.remediation or f.recommendation or ""}}]
    return result


def _locations_for_finding(f: Finding) -> list[dict[str, Any]]:
    """Prefer an evidence record's file_path. Fall back to affected_asset/asset_id."""
    out: list[dict[str, Any]] = []
    for ev in f.evidence:
        if ev.file_path:
            artifact: dict[str, Any] = {"uri": ev.file_path}
            location: dict[str, Any] = {"physicalLocation": {"artifactLocation": artifact}}
            if ev.line_start is not None:
                region: dict[str, Any] = {"startLine": ev.line_start}
                if ev.line_end is not None:
                    region["endLine"] = ev.line_end
                location["physicalLocation"]["region"] = region
            out.append(location)
    if out:
        return out
    uri = f.affected_asset or f.affected_component or f.asset_id
    if uri:
        return [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
    return []


# ---------------------------------------------------------------------------
# Import — SARIF dict -> Finding[]
# ---------------------------------------------------------------------------

def sarif_to_findings(doc: dict[str, Any], *, project_id: str) -> list[Finding]:
    """Walk a SARIF document and synthesize Finding records.

    The importer is forgiving: missing fields get sensible defaults, levels
    convert via `_LEVEL_TO_SEVERITY`, and ASURA's own round-trip metadata
    under `properties.asura.*` is honored when present.
    """
    if not isinstance(doc, dict):
        raise SarifParseError("SARIF document must be a JSON object.")
    if doc.get("version") != SARIF_VERSION:
        raise SarifParseError(f"Only SARIF {SARIF_VERSION} is supported (got {doc.get('version')!r}).")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise SarifParseError("SARIF document is missing `runs` array.")

    findings: list[Finding] = []
    for run in runs:
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        scanner_name = driver.get("name") or "sarif-import"
        rules_by_id = {r.get("id"): r for r in (driver.get("rules") or []) if isinstance(r, dict)}
        rules_list = driver.get("rules") or []

        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            findings.append(_finding_from_result(
                result=result,
                project_id=project_id,
                scanner=scanner_name,
                rules_by_id=rules_by_id,
                rules_list=rules_list,
            ))
    return findings


def _finding_from_result(
    *,
    result: dict[str, Any],
    project_id: str,
    scanner: str,
    rules_by_id: dict[str, dict[str, Any]],
    rules_list: list[dict[str, Any]],
) -> Finding:
    props = result.get("properties") or {}
    rule_id = result.get("ruleId")
    rule_index = result.get("ruleIndex")
    rule: dict[str, Any] = {}
    if isinstance(rule_index, int) and 0 <= rule_index < len(rules_list):
        rule = rules_list[rule_index] or {}
    if rule_id and rule_id in rules_by_id:
        rule = rules_by_id[rule_id]
    rule_props = (rule or {}).get("properties") or {}

    # Severity — round-trip first, then security-severity, then level.
    severity = (
        _coerce_severity(props.get("asura.severity"))
        or _severity_from_security_severity(props.get("security-severity")
                                            or rule_props.get("security-severity"))
        or _LEVEL_TO_SEVERITY.get(result.get("level") or "warning", Severity.medium)
    )

    confidence = _coerce_confidence(props.get("asura.confidence"))

    message = ((result.get("message") or {}).get("text") or "").strip()
    short_desc = ((rule.get("shortDescription") or {}).get("text") or "").strip()
    title = (message or short_desc or rule_id or "Imported SARIF finding").splitlines()[0][:240]

    full_desc = ((rule.get("fullDescription") or {}).get("text") or "").strip()
    help_text = ((rule.get("help") or {}).get("text") or "").strip()

    locations = result.get("locations") or []
    primary_loc = locations[0] if locations else {}
    artifact = ((primary_loc.get("physicalLocation") or {}).get("artifactLocation") or {})
    region = ((primary_loc.get("physicalLocation") or {}).get("region") or {})
    file_path = artifact.get("uri")
    start_line = region.get("startLine")
    end_line = region.get("endLine")

    asset_id = props.get("asura.assetId") or (f"sarif:{file_path}" if file_path else f"sarif:{scanner}")
    affected_asset = file_path

    cwe_list = _coerce_str_list(props.get("cwe") or rule_props.get("cwe"))
    cve_list = _coerce_str_list(props.get("cve"))

    now = datetime.now(timezone.utc)
    fingerprints = result.get("fingerprints")
    fingerprint = None
    if isinstance(fingerprints, dict):
        fingerprint = fingerprints.get("asura/v1") or next(iter(fingerprints.values()), None)

    evidence_record = Evidence(
        id=str(uuid4()),
        finding_id="",          # back-filled by the import endpoint after the Finding is created
        evidence_type=EvidenceType.scanner_output,
        scanner=scanner,
        raw={
            "rule": rule_id,
            "level": result.get("level"),
            "sarif_message": message,
        },
        summary=full_desc[:280] if full_desc else title,
        content=None,
        source_tool=scanner,
        file_path=file_path,
        line_start=start_line,
        line_end=end_line,
        captured_at=now,
    )

    finding_id = props.get("asura.id") or str(uuid4())

    return Finding(
        id=str(finding_id),
        project_id=project_id,
        asset_id=str(asset_id),
        scanner=scanner,
        title=title,
        category=str(rule_props.get("asura.category") or "security"),
        severity=severity,
        confidence=confidence,
        affected_asset=affected_asset,
        description=full_desc or None,
        impact=full_desc or title,
        remediation=help_text or None,
        reproduction=f"See {file_path}:{start_line}" if file_path and start_line else "See source location",
        false_positive_reasoning="",
        recommendation=help_text or "",
        cwe=cwe_list,
        cve=cve_list,
        source_tools=[scanner],
        evidence=[evidence_record],
        fingerprint_hash=fingerprint,
        is_demo_data=False,
    )


def _coerce_severity(value: Any) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(str(value).lower())
    except ValueError:
        return None


def _coerce_confidence(value: Any) -> Confidence:
    if value is None:
        return Confidence.medium
    try:
        return Confidence(str(value).lower())
    except ValueError:
        return Confidence.medium


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return []
