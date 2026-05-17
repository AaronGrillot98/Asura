"""Parsers normalize tool output into Asura `Finding` objects.

Each parser exposes a single `parse(raw, *, project_id, scan_id, asset_id, is_demo_data=False) -> list[Finding]`.

These parsers are deliberately minimal: they cover the fields the rest of
Asura actually uses (severity, affected_asset, evidence) and they degrade
gracefully on unexpected input rather than raising.
"""
from __future__ import annotations

from typing import Callable

from app.models.schemas import Finding

from . import (  # noqa: F401  re-export the parser modules
    checkov,
    gitleaks,
    grype,
    nmap,
    nuclei,
    osv,
    semgrep,
    syft,
    trivy,
    zap,
)

ParserFn = Callable[..., list[Finding]]

PARSERS: dict[str, ParserFn] = {
    "nmap": nmap.parse,
    "nmap_xml": nmap.parse,
    "nuclei": nuclei.parse,
    "nuclei_json": nuclei.parse,
    "semgrep": semgrep.parse,
    "semgrep_json": semgrep.parse,
    "trivy": trivy.parse,
    "trivy_json": trivy.parse,
    "gitleaks": gitleaks.parse,
    "gitleaks_json": gitleaks.parse,
    "osv-scanner": osv.parse,
    "osv_json": osv.parse,
    "checkov": checkov.parse,
    "checkov_json": checkov.parse,
    "zap": zap.parse,
    "zap_json": zap.parse,
    "syft": syft.parse,
    "syft_json": syft.parse,
    "grype": grype.parse,
    "grype_json": grype.parse,
}


def parse(parser_name: str, raw: object, **kwargs) -> list[Finding]:
    """Dispatch to the named parser. Returns [] if the parser is unknown."""
    fn = PARSERS.get(parser_name)
    if fn is None:
        return []
    return fn(raw, **kwargs)
