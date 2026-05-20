"""SecretFinder text parser.

`python SecretFinder.py -i <url|file> -o cli` prints one match per
line in a `type:value` shape, sometimes prefixed with the source:

    google_api_key : AIzaSyB-...
    /js/app.bundle.js: aws_access_key : AKIA...
    slack_token : xoxb-...

We carry the secret *type* but never the raw value into Finding fields
exposed by the UI — the value lives only inside the `raw` dict so audit
viewers can see it on demand but report exports stay clean.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


# `[source: ]<type> : <value>` — value may contain spaces if the regex
# was greedy, so we capture to end of line.
_PREFIXED = re.compile(r"^\s*([^:\s][^:]*?):\s*([A-Za-z][\w_]*)\s*:\s*(.+?)\s*$")
_BARE = re.compile(r"^\s*([A-Za-z][\w_]*)\s*:\s*(.+?)\s*$")


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
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        source = ""
        secret_type = ""
        value = ""
        m = _PREFIXED.match(stripped)
        if m:
            source, secret_type, value = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        else:
            m = _BARE.match(stripped)
            if not m:
                continue
            secret_type, value = m.group(1).strip(), m.group(2).strip()
        if not secret_type or not value:
            continue

        # Never persist the plaintext into a top-level field — store only
        # a SHA-256 prefix so an audit trail still has identity.
        digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
        digest_short = digest[:12]

        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="secretfinder",
                title=f"{secret_type} pattern in {source or 'JS bundle'}",
                category="secrets",
                severity=Severity.high,
                confidence=Confidence.medium,
                impact=(
                    f"SecretFinder matched a `{secret_type}` regex in "
                    f"{f'`{source}`' if source else 'an inline script or fetched JS bundle'}. "
                    "Live credentials embedded in JavaScript are reachable by every visitor."
                ),
                recommendation=(
                    "Treat the value as compromised: rotate the credential, move secrets to a "
                    "server-side proxy or environment-injected build artifact, and add an automated "
                    "secret scan to your CI."
                ),
                reproduction=(
                    f"SecretFinder -i {source or '<bundle>'} -o cli  ->  type=`{secret_type}` sha256={digest_short}"
                ),
                false_positive_reasoning=(
                    "SecretFinder uses regex heuristics; high-entropy IDs, version tokens, and "
                    "redacted placeholders can match."
                ),
                # `raw` keeps the digest fingerprint AND the original value so
                # auditors can confirm in-context — viewers should treat raw
                # contents as sensitive.
                raw={
                    "type": secret_type,
                    "source": source,
                    "value_sha256": digest,
                    "value": value,
                },
                summary=f"secretfinder {secret_type} (sha256:{digest_short})",
                affected_asset=source or "(inline)",
                affected_component=secret_type,
                file_path=source or None,
                cwe=["CWE-798"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                is_demo_data=is_demo_data,
            )
        )
    return findings


def _coerce_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("stdout", "output", "secrets", "matches"):
            val = raw.get(key)
            if isinstance(val, str):
                return val
            if isinstance(val, list):
                return "\n".join(str(item) for item in val if item)
    if isinstance(raw, list):
        return "\n".join(str(item) for item in raw if item)
    return ""
