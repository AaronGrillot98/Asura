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
    bandit,
    bearer,
    brakeman,
    cargo_audit,
    checkov,
    dirsearch,
    discovery,
    eslint,
    ffuf,
    gitleaks,
    gobuster,
    gosec,
    govulncheck,
    grype,
    httpx,
    kube_bench,
    kube_score,
    kubescape,
    naabu,
    nmap,
    npm_audit,
    nuclei,
    osv,
    pip_audit,
    prowler,
    sarif,
    semgrep,
    subfinder,
    syft,
    trivy,
    trufflehog,
    zap,
)

ParserFn = Callable[..., list[Finding]]

PARSERS: dict[str, ParserFn] = {
    # core 10
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
    # AppSec / dependency / secrets
    "bandit": bandit.parse,
    "bandit_json": bandit.parse,
    "pip-audit": pip_audit.parse,
    "pip_audit_json": pip_audit.parse,
    "npm-audit": npm_audit.parse,
    "npm_audit_json": npm_audit.parse,
    "cargo-audit": cargo_audit.parse,
    "cargo_audit_json": cargo_audit.parse,
    "govulncheck": govulncheck.parse,
    "govulncheck_json": govulncheck.parse,
    "gosec": gosec.parse,
    "gosec_json": gosec.parse,
    "brakeman": brakeman.parse,
    "brakeman_json": brakeman.parse,
    "eslint-security": eslint.parse,
    "eslint_json": eslint.parse,
    "bearer": bearer.parse,
    "bearer_json": bearer.parse,
    "trufflehog": trufflehog.parse,
    "trufflehog_json": trufflehog.parse,
    # recon
    "subfinder": subfinder.parse,
    "subfinder_json": subfinder.parse,
    "httpx": httpx.parse,
    "httpx_json": httpx.parse,
    "naabu": naabu.parse,
    "naabu_json": naabu.parse,
    # recon (shared discovery normalization until each tool gets a richer parser)
    "amass": discovery.amass_parse,
    "amass_json": discovery.amass_parse,
    "dnsx": discovery.dnsx_parse,
    "dnsx_json": discovery.dnsx_parse,
    "katana": discovery.katana_parse,
    "katana_json": discovery.katana_parse,
    "gau": discovery.gau_parse,
    "gau_json": discovery.gau_parse,
    "waybackurls": discovery.waybackurls_parse,
    "waybackurls_text": discovery.waybackurls_parse,
    "hakrawler": discovery.hakrawler_parse,
    "hakrawler_json": discovery.hakrawler_parse,
    "webanalyze": discovery.webanalyze_parse,
    "webanalyze_json": discovery.webanalyze_parse,
    "whatweb": discovery.whatweb_parse,
    "whatweb_json": discovery.whatweb_parse,
    "wafw00f": discovery.wafw00f_parse,
    "wafw00f_json": discovery.wafw00f_parse,
    "tlsx": discovery.tlsx_parse,
    "tlsx_json": discovery.tlsx_parse,
    "shuffledns": discovery.shuffledns_parse,
    "shuffledns_json": discovery.shuffledns_parse,
    "assetfinder": discovery.assetfinder_parse,
    "assetfinder_text": discovery.assetfinder_parse,
    # fuzzers (slice 10)
    "ffuf": ffuf.parse,
    "ffuf_json": ffuf.parse,
    "gobuster": gobuster.parse,
    "gobuster_text": gobuster.parse,
    "dirsearch": dirsearch.parse,
    "dirsearch_text": dirsearch.parse,
    # K8s / cloud (slice 10)
    "kube-bench": kube_bench.parse,
    "kube_bench_json": kube_bench.parse,
    "kubescape": kubescape.parse,
    "kubescape_json": kubescape.parse,
    "kube-score": kube_score.parse,
    "kube_score_json": kube_score.parse,
    "prowler": prowler.parse,
    "prowler_json": prowler.parse,
    # generic
    "sarif": sarif.parse,
}


def parse(parser_name: str, raw: object, **kwargs) -> list[Finding]:
    """Dispatch to the named parser. Returns [] if the parser is unknown."""
    fn = PARSERS.get(parser_name)
    if fn is None:
        return []
    return fn(raw, **kwargs)
