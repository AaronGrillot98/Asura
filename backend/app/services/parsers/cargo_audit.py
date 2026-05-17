"""cargo-audit JSON parser (Rust dependencies)."""
from __future__ import annotations

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
    findings: list[Finding] = []
    if not isinstance(raw, dict):
        return findings
    vulns = (raw.get("vulnerabilities") or {}).get("list") or []
    if not isinstance(vulns, list):
        return findings
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        advisory = vuln.get("advisory") or {}
        package = vuln.get("package") or {}
        name = package.get("name") or "package"
        version = package.get("version") or "unknown"
        aid = advisory.get("id") or "RUSTSEC-UNKNOWN"
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner="cargo-audit",
                title=f"{name} {version} {aid}",
                category="dependency",
                severity=Severity.medium,
                confidence=Confidence.high,
                impact=advisory.get("description") or "Rust crate flagged as vulnerable.",
                recommendation="Upgrade the crate to a patched version per the advisory.",
                reproduction=f"cargo-audit matched {aid} on {name} {version}.",
                false_positive_reasoning="cargo-audit matched the locked crate against the RustSec advisory database.",
                raw=vuln,
                summary=f"{aid} affecting {name} {version}.",
                affected_asset="Cargo.lock",
                affected_component=f"{name}@{version}",
                cve=[c for c in (advisory.get("aliases") or []) if isinstance(c, str) and c.startswith("CVE-")],
                is_demo_data=is_demo_data,
            )
        )
    return findings
