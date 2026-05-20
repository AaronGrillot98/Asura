"""detect-secrets baseline parser.

`detect-secrets scan --baseline -` emits a JSON document keyed by file path:

    {
      "version": "1.4.0",
      "plugins_used": [...],
      "results": {
        "src/config.py": [
          {
            "type": "AWS Access Key",
            "filename": "src/config.py",
            "hashed_secret": "abc...",
            "is_verified": false,
            "is_secret": null,
            "line_number": 42
          }
        ],
        ...
      }
    }

The plaintext is intentionally absent — only the hashed digest survives.
We carry the hash + type + line into the Finding so analysts can pivot
back to the source file at that exact line.
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
    asset_id: str = "asset-repo",
    is_demo_data: bool = False,
) -> list[Finding]:
    doc = _coerce_dict(raw)
    if not isinstance(doc, dict):
        return []
    results = doc.get("results") or {}
    if not isinstance(results, dict):
        return []

    findings: list[Finding] = []
    for file_path, entries in results.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            secret_type = entry.get("type") or "Secret"
            line = entry.get("line_number") or 0
            digest = entry.get("hashed_secret") or "(no hash)"
            verified = entry.get("is_verified")
            # Verified secrets are pretty rare for detect-secrets (it doesn't
            # exfil to validate by default); when true, bump severity.
            severity = Severity.critical if verified else Severity.high
            confidence = Confidence.confirmed if verified else Confidence.high

            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="detect-secrets",
                    title=f"{secret_type} candidate in {file_path}:{line}",
                    category="secrets",
                    severity=severity,
                    confidence=confidence,
                    impact=(
                        f"detect-secrets flagged a `{secret_type}` at {file_path}:{line}. "
                        "Verified secrets indicate the credential was confirmed live; unverified "
                        "results require manual review."
                    ),
                    recommendation=(
                        "Rotate the credential immediately if real, remove it from history "
                        "(`git filter-repo`), and add the file to .gitignore. Store secrets in a "
                        "vault (AWS Secrets Manager, HashiCorp Vault, GitHub Encrypted Secrets)."
                    ),
                    reproduction=f"detect-secrets scan flagged {secret_type} at {file_path}:{line} (sha256 hashed)",
                    false_positive_reasoning=(
                        "detect-secrets uses entropy + plugin heuristics — high-entropy IDs and "
                        "test fixtures can match; verify with `detect-secrets audit baseline`."
                    ),
                    raw={
                        "type": secret_type,
                        "file": file_path,
                        "line": line,
                        "hashed_secret": digest,
                        "is_verified": verified,
                    },
                    summary=f"detect-secrets {secret_type} @ {file_path}:{line}",
                    affected_asset=file_path,
                    affected_component=str(line),
                    file_path=file_path,
                    cwe=["CWE-798"],     # use of hard-coded credentials
                    owasp=["A07:2021-Identification and Authentication Failures"],
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
