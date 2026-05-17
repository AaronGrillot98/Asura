"""Recon and audit pipelines — chains of scanner stages.

A pipeline is a named, ordered list of stages. Each stage points at a
registered scanner. Stages whose `input_source == "previous_assets"` get
their targets from the **affected_asset** field of the previous stage's
findings (deduped, capped at `max_followups`). This is how the runner walks
e.g. subfinder → httpx → nuclei without the caller having to script it.

The presets here are deliberately small — three named workflows that prove
the chaining model. New presets can be added by appending to `_PRESETS`.
"""
from __future__ import annotations

from typing import Optional

from app.models.schemas import Pipeline, PipelineStage, ScanMode

_PRESETS: list[Pipeline] = [
    Pipeline(
        id="passive-recon",
        name="Passive web recon",
        description=(
            "Enumerate subdomains, probe HTTP, then run Nuclei info-templates "
            "against discovered hosts. No active fuzzing. Suitable for the "
            "discovery phase of an authorized engagement."
        ),
        risk_level="low",
        requires_authorized_scope=False,
        tags=["recon", "passive", "web"],
        stages=[
            PipelineStage(
                name="Enumerate subdomains",
                scanner="subfinder",
                mode=ScanMode.passive,
                input_source="target",
                description="Passive subdomain enumeration via public sources.",
            ),
            PipelineStage(
                name="HTTP probe discovered hosts",
                scanner="httpx",
                mode=ScanMode.active,
                input_source="previous_assets",
                max_followups=30,
                description="Probe each subdomain for an HTTP response.",
            ),
        ],
    ),
    Pipeline(
        id="code-audit",
        name="Code audit (passive)",
        description=(
            "Parallel passive scans of a repository: code (Semgrep), secrets "
            "(Gitleaks), and dependencies (OSV-Scanner). All target the same "
            "path. Safe to run on any code you own."
        ),
        risk_level="low",
        requires_authorized_scope=False,
        tags=["code", "sast", "secrets", "dependencies"],
        stages=[
            PipelineStage(name="Static analysis", scanner="semgrep", mode=ScanMode.passive),
            PipelineStage(name="Secret scanning", scanner="gitleaks", mode=ScanMode.passive),
            PipelineStage(name="Dependency vulnerabilities", scanner="osv-scanner", mode=ScanMode.passive),
        ],
    ),
    Pipeline(
        id="container-audit",
        name="Container audit",
        description=(
            "Build an SBOM with Syft, then run Grype + Trivy against the same "
            "image / directory. Catches vulnerable packages, misconfigurations, "
            "and leaked secrets baked into the image."
        ),
        risk_level="low",
        requires_authorized_scope=False,
        tags=["container", "sbom", "supply_chain"],
        stages=[
            PipelineStage(name="SBOM", scanner="syft", mode=ScanMode.passive),
            PipelineStage(name="Vulnerabilities (Grype)", scanner="grype", mode=ScanMode.passive),
            PipelineStage(name="Vulns + misconfig (Trivy)", scanner="trivy", mode=ScanMode.passive),
        ],
    ),
]

_PRESETS_BY_ID = {p.id: p for p in _PRESETS}


def list_pipelines() -> list[Pipeline]:
    return list(_PRESETS)


def get_pipeline(pipeline_id: str) -> Optional[Pipeline]:
    return _PRESETS_BY_ID.get(pipeline_id)
