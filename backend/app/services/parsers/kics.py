"""KICS (Keeping Infrastructure as Code Secure) JSON parser.

KICS' `--report-formats json -o <dir>` writes `results.json` shaped like:

    {
      "kics_version": "1.7.8",
      "queries": [
        {
          "query_name": "S3 Bucket Without Versioning",
          "query_id":   "...",
          "severity":   "MEDIUM",
          "platform":   "Terraform",
          "category":   "Observability",
          "description":"...",
          "cwe":        "CWE-200",
          "files": [
            {
              "file_name":  "main.tf",
              "line":       42,
              "issue_type": "MissingAttribute",
              "search_key": "aws_s3_bucket[example]",
              "expected_value": "versioning.enabled should be true",
              "actual_value":   "versioning.enabled is undefined"
            }
          ]
        }
      ]
    }
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
    asset_id: str = "asset-iac",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _coerce_dict(raw)
    if not isinstance(doc, dict):
        return []
    queries = doc.get("queries") or []
    if not isinstance(queries, list):
        return []

    findings: list[Finding] = []
    for q in queries:
        if not isinstance(q, dict):
            continue
        query_name = q.get("query_name") or "(unnamed query)"
        severity = map_severity(q.get("severity"), default=Severity.medium)
        platform = q.get("platform") or "IaC"
        cwe = [q.get("cwe")] if q.get("cwe") else []
        description = q.get("description") or ""
        category = (q.get("category") or "iac").lower()

        for file_match in q.get("files", []):
            if not isinstance(file_match, dict):
                continue
            file_name = file_match.get("file_name") or ""
            line = file_match.get("line") or 0
            search_key = file_match.get("search_key") or ""
            expected = file_match.get("expected_value") or ""
            actual = file_match.get("actual_value") or ""

            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="kics",
                    title=f"{query_name} ({platform}) — {file_name}:{line}",
                    category=category if category in {"iac", "observability"} else "iac",
                    severity=severity,
                    confidence=Confidence.high,
                    impact=description or f"KICS flagged `{query_name}` in {file_name}:{line}.",
                    recommendation=(
                        f"Set `{expected}` for `{search_key}`. Current state: `{actual}`."
                        if expected and actual
                        else "Review the query rationale and apply the recommended IaC pattern."
                    ),
                    reproduction=f"KICS query `{query_name}` matched {file_name}:{line} with key `{search_key}`.",
                    false_positive_reasoning=(
                        "KICS' policies are pattern-driven over the IaC AST; "
                        "intentionally permissive resources may need a per-file ignore comment."
                    ),
                    raw=file_match,
                    summary=f"kics {query_name} @ {file_name}:{line}",
                    affected_asset=file_name,
                    affected_component=search_key,
                    file_path=file_name,
                    cwe=cwe,
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
