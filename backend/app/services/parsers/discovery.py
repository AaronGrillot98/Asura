"""Generic recon/discovery parser.

A lot of recon tools (amass, dnsx, katana, gau, waybackurls, hakrawler,
webanalyze, whatweb, tlsx, shuffledns, assetfinder, etc.) emit similar
output: a JSONL stream or a bare-host-per-line stream describing
discovered hosts / URLs / subdomains.

This parser is shared across all of them so each tool produces real
informational findings without us having to write 12 nearly-identical
files. Per-tool parsers should be added when the tool emits richer
data (e.g. tlsx's TLS metadata, whatweb's tech fingerprints) that
warrants its own normalization.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


_HOST_FIELDS = ("host", "subdomain", "name", "hostname", "fqdn", "url", "address", "target")


def _iter_records(raw: object) -> Iterable[dict[str, Any] | str]:
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, (dict, str)) and item:
                yield item
        return
    if isinstance(raw, dict):
        # If it's a single record with a host field, yield it directly.
        if any(k in raw for k in _HOST_FIELDS):
            yield raw
        # If it has a "results" list, walk that.
        results = raw.get("results")
        if isinstance(results, list):
            for item in results:
                if isinstance(item, (dict, str)):
                    yield item
        return
    if isinstance(raw, str):
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                yield line


def _value_for_host(record: dict[str, Any] | str) -> str | None:
    if isinstance(record, str):
        return record
    for field in _HOST_FIELDS:
        if field in record and record[field]:
            value = record[field]
            if isinstance(value, list):
                value = value[0] if value else None
            if value:
                return str(value)
    return None


def parse(
    raw: object,
    *,
    scanner: str = "discovery",
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-host",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for rec in _iter_records(raw):
        host = _value_for_host(rec)
        if not host:
            continue
        raw_payload = rec if isinstance(rec, dict) else {"value": rec}
        findings.append(
            make_finding(
                project_id=project_id,
                scan_id=scan_id,
                asset_id=asset_id,
                scanner=scanner,
                title=f"Discovered: {host}",
                category="recon",
                severity=Severity.info,
                confidence=Confidence.medium,
                impact="A reachable asset / endpoint / subdomain was identified.",
                recommendation="Confirm the asset is intentional and inventoried.",
                reproduction=f"{scanner} surfaced {host}.",
                false_positive_reasoning=(
                    f"{scanner} reports discovery without authentication; "
                    f"validate before treating as definitive."
                ),
                raw=raw_payload,
                summary=f"{scanner} discovery: {host}",
                affected_asset=host,
                affected_component="discovery",
                is_demo_data=is_demo_data,
            )
        )
    return findings


# Per-tool wrappers so the dispatch table can name each scanner explicitly.
def _wrap(scanner: str):
    def _parse(raw, *, project_id="demo", scan_id=None, asset_id="asset-host", is_demo_data=False):
        return parse(
            raw,
            scanner=scanner,
            project_id=project_id,
            scan_id=scan_id,
            asset_id=asset_id,
            is_demo_data=is_demo_data,
        )
    _parse.__name__ = f"parse_{scanner.replace('-', '_')}"
    return _parse


amass_parse = _wrap("amass")
dnsx_parse = _wrap("dnsx")
katana_parse = _wrap("katana")
gau_parse = _wrap("gau")
waybackurls_parse = _wrap("waybackurls")
hakrawler_parse = _wrap("hakrawler")
webanalyze_parse = _wrap("webanalyze")
whatweb_parse = _wrap("whatweb")
wafw00f_parse = _wrap("wafw00f")
tlsx_parse = _wrap("tlsx")
shuffledns_parse = _wrap("shuffledns")
assetfinder_parse = _wrap("assetfinder")
