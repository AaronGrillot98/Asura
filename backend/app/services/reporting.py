"""Report generation.

Produces structured Markdown and JSON reports with the full section set
required by the Asura product spec. Every report stamps a scope statement,
an authorization statement, and a safety statement so the deliverable is
suitable for handing to a stakeholder.
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from uuid import uuid4

from app.models.schemas import (
    AttackPath,
    Confidence,
    Evidence,
    Finding,
    Project,
    Report,
    ScannerRun,
    Severity,
)
from app.services.evidence_store import content_hash
from app.services.pentest_brain import PentestBrain
from app.services.merkle import build_tree, step_to_dict
from app.services.signing import canonical_json, hash_sections, sign_report_bundle

_TOOL_PARSER_HINT = {
    "nmap": "nmap_xml", "nuclei": "nuclei_json", "semgrep": "semgrep_json",
    "trivy": "trivy_json", "gitleaks": "gitleaks_json", "osv-scanner": "osv_json",
    "checkov": "checkov_json", "zap": "zap_json", "syft": "syft_json", "grype": "grype_json",
}


def _scope_statement(project: Project) -> str:
    rules = project.scope_rules
    return (
        f"This engagement is scoped to project '{project.name}'. "
        f"Allowed domains: {', '.join(rules.domains) or 'n/a'}. "
        f"Allowed URLs: {', '.join(rules.urls) or 'n/a'}. "
        f"Allowed CIDRs: {', '.join(rules.cidrs) or 'n/a'}. "
        f"Allowed repos: {', '.join(rules.repos) or 'n/a'}. "
        f"Allowed containers: {', '.join(rules.containers) or 'n/a'}. "
        f"Blocked targets: {', '.join(rules.blocked_targets) or 'n/a'}. "
        f"Active mode allowed: {rules.allow_active}. Lab mode allowed: {rules.allow_lab}."
    )


def _authorization_statement(project: Project) -> str:
    rules = project.scope_rules
    pieces = ["Active and lab scans require explicit authorization confirmation per scan request."]
    if rules.allow_active:
        pieces.append("This project's scope grants active scanning against the listed assets.")
    if rules.allow_lab:
        pieces.append("Lab validation is enabled and limited to targets with lab_mode_enabled=True.")
    pieces.append("Every scope decision is recorded in the Audit Log.")
    return " ".join(pieces)


def _safety_statement() -> str:
    return (
        "Asura runs only authorized, evidence-preserving scanners. It does not perform "
        "destructive exploitation, persistence, data exfiltration, credential theft, or "
        "stealth operations. Every finding cites raw evidence with a content hash; "
        "PentestBrain claims are bounded by the supplied evidence and labeled as "
        "confirmed, likely, or hypothesis."
    )


def _executive_summary(findings: list[Finding], paths: list[AttackPath]) -> str:
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity}
    return (
        f"Asura reviewed {len(findings)} normalized finding(s) across "
        f"{len({f.scanner for f in findings})} tool(s). "
        f"Critical: {counts[Severity.critical]}, High: {counts[Severity.high]}, "
        f"Medium: {counts[Severity.medium]}, Low: {counts[Severity.low]}, "
        f"Info: {counts[Severity.info]}. "
        f"{len(paths)} attack-path hypothesis/hypotheses were proposed; each cites the "
        f"evidence IDs that produced it."
    )


def _risk_overview(findings: list[Finding]) -> dict[str, int]:
    return {sev.value: sum(1 for f in findings if f.severity == sev) for sev in Severity}


def _section_findings_by_severity(findings: list[Finding]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {sev.value: [] for sev in Severity}
    for f in findings:
        out[f.severity.value].append({
            "id": f.id,
            "title": f.title,
            "scanner": f.scanner,
            "affected_asset": f.affected_asset,
            "confidence": (f.confidence.value if isinstance(f.confidence, Confidence) else f.confidence),
            "evidence_ids": [ev.id for ev in f.evidence],
            "fingerprint": f.fingerprint_hash,
            "is_demo_data": f.is_demo_data,
        })
    return out


def _section_evidence(findings: list[Finding]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for f in findings:
        for ev in f.evidence:
            refs.append({
                "id": ev.id,
                "finding_id": f.id,
                "scanner": ev.scanner,
                "content_hash": ev.content_hash,
                "raw_output_path": ev.raw_output_path,
                "file_path": ev.file_path,
                "captured_at": ev.captured_at.isoformat() if ev.captured_at else None,
            })
    return refs


def _section_scanner_runs(runs: list[ScannerRun]) -> list[dict[str, Any]]:
    return [
        {
            "id": run.id,
            "scanner": run.scanner,
            "mode": run.mode.value if hasattr(run.mode, "value") else run.mode,
            "status": run.status,
            "target": run.target,
            "exit_code": run.exit_code,
            "is_demo_data": run.is_demo_data,
            "message": run.message,
        }
        for run in runs
    ]


def _section_tools_used(findings: list[Finding]) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for f in findings:
        if f.scanner in seen:
            continue
        seen.add(f.scanner)
        out.append({
            "id": f.scanner,
            "parser": _TOOL_PARSER_HINT.get(f.scanner, "n/a"),
        })
    return out


def build_report(
    *,
    repos,
    project_id: str,
    kind: str = "markdown",
) -> Report:
    project = repos.projects.get(project_id)
    if project is None:
        raise ValueError(f"Project {project_id} not found")
    brain = PentestBrain(repos)
    ranked = brain.rank_findings(project_id)
    attack_paths = [
        p for p in repos.attack_paths.list(lambda ap: ap.project_id == project_id)
    ]
    if not attack_paths:
        attack_paths = brain.propose_attack_paths(project_id)
    runs = [r for r in repos.runs.list() if r.project_id == project_id]
    remediations = brain.generate_remediation_plan(project_id)

    sections: dict[str, Any] = {
        "engagement_summary": {
            "project": project.name,
            "description": project.description,
            "risk_score": project.risk_score,
        },
        "scope": project.scope_rules.model_dump(mode="json"),
        "authorization_statement": _authorization_statement(project),
        "methodology": [
            "Scope enforcement before every scanner run",
            "Evidence-first finding normalization",
            "Deterministic correlation into attack-path hypotheses",
            "Confidence ceiling based on corroborating tool diversity",
        ],
        "tools_used": _section_tools_used(ranked),
        "executive_summary": _executive_summary(ranked, attack_paths),
        "risk_overview": _risk_overview(ranked),
        "attack_paths": [path.model_dump(mode="json") for path in attack_paths],
        "findings": [f.model_dump(mode="json") for f in ranked],
        "findings_by_severity": _section_findings_by_severity(ranked),
        "evidence": _section_evidence(ranked),
        "remediation_roadmap": [task.model_dump(mode="json") for task in remediations],
        "scanner_runs": _section_scanner_runs(runs),
        "raw_evidence_refs": _section_evidence(ranked),
        "agent_outputs": [
            brain.correlate_findings(project_id).model_dump(mode="json"),
            brain._scope_summary(project_id).model_dump(mode="json"),  # noqa: SLF001
        ],
        "safety_statement": _safety_statement(),
        "scope_statement": _scope_statement(project),
    }

    title = f"{project.name} Security Report"
    now = datetime.now(timezone.utc)
    report = Report(
        id=f"report-{project_id}-{kind}-{uuid4().hex[:8]}",
        project_id=project_id,
        report_type=("json" if kind == "json" else "markdown"),
        kind=("json" if kind == "json" else "markdown"),
        title=title,
        generated_at=now,
        sections=sections,
        scope_statement=_scope_statement(project),
        authorization_statement=_authorization_statement(project),
        safety_statement=_safety_statement(),
        content_hash=content_hash(sections),
        pdf_status="not_generated",
        is_demo_data=any(f.is_demo_data for f in ranked) or project.is_demo_data,
    )
    return report


def render_markdown(report: Report) -> str:
    """Render the structured `Report` as a Markdown document."""
    s = report.sections
    lines: list[str] = []
    lines.append(f"# {report.title}")
    lines.append("")
    lines.append(f"Generated: {report.generated_at.isoformat()}")
    if report.is_demo_data:
        lines.append("")
        lines.append("> **Demo data:** the findings in this report are seeded demo evidence, not the result of a live scan.")
    lines.extend(["", "## Engagement Summary", "",
                 s["engagement_summary"]["description"], "",
                 f"Project risk score: {s['engagement_summary']['risk_score']}/100"])
    lines.extend(["", "## Scope", "", s["scope_statement"]])
    lines.extend(["", "## Authorization Statement", "", s["authorization_statement"]])
    lines.extend(["", "## Methodology", ""])
    for item in s["methodology"]:
        lines.append(f"- {item}")
    lines.extend(["", "## Tools Used", ""])
    for tool in s["tools_used"]:
        lines.append(f"- `{tool['id']}` (parser: {tool['parser']})")
    lines.extend(["", "## Executive Summary", "", s["executive_summary"]])
    lines.extend(["", "## Risk Overview", ""])
    for sev, count in s["risk_overview"].items():
        lines.append(f"- {sev}: {count}")
    lines.extend(["", "## Attack Paths", ""])
    for path in s["attack_paths"]:
        lines.append(f"### {path['title']}")
        lines.append("")
        lines.append(path.get("narrative") or path.get("summary") or "")
        lines.append("")
        lines.append(f"Status: {path.get('status', 'hypothesis')}  Confidence: {path.get('confidence')}")
        lines.append("")
        for step in path.get("recommended_next_steps", []):
            lines.append(f"- {step}")
        lines.append("")
    lines.extend(["", "## Findings by Severity", ""])
    for sev, items in s["findings_by_severity"].items():
        if not items:
            continue
        lines.append(f"### {sev.upper()}")
        lines.append("")
        for item in items:
            lines.append(f"- {item['title']} — scanner: {item['scanner']}, affected: {item['affected_asset']}")
        lines.append("")
    lines.extend(["", "## Evidence", ""])
    for ev in s["evidence"][:20]:
        lines.append(f"- evidence `{ev['id']}` ({ev['scanner']}) hash=`{ev['content_hash']}`")
    lines.extend(["", "## Remediation Roadmap", ""])
    for task in s["remediation_roadmap"]:
        lines.append(f"- [{task['priority'].upper()}] {task['title']}")
    lines.extend(["", "## Appendix: Scanner Runs", ""])
    for run in s["scanner_runs"]:
        demo = " (demo)" if run.get("is_demo_data") else ""
        lines.append(f"- `{run['scanner']}` mode={run['mode']} status={run['status']} target={run['target']}{demo}")
    lines.extend(["", "## Appendix: Raw Evidence References", ""])
    for ev in s["raw_evidence_refs"][:50]:
        lines.append(f"- `{ev['id']}` finding=`{ev['finding_id']}` hash=`{ev['content_hash']}`")
    lines.extend(["", "## Safety Statement", "", s["safety_statement"], ""])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Merkle tree of evidence + signed bundle
# ---------------------------------------------------------------------------

def _evidence_leaves(sections: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ordered evidence leaf list used as the Merkle source."""
    leaves: list[dict[str, Any]] = []
    for ev in sections.get("evidence", []):
        # Fall back to a deterministic hash of the metadata if the
        # evidence record never persisted a content_hash (which is true
        # for the seeded demo set).
        h = ev.get("content_hash") or canonical_json({
            "id": ev.get("id"),
            "finding_id": ev.get("finding_id"),
            "scanner": ev.get("scanner"),
            "file_path": ev.get("file_path"),
        }).hex()
        leaves.append({
            "evidence_id": ev.get("id"),
            "finding_id": ev.get("finding_id"),
            "scanner": ev.get("scanner"),
            "leaf_hash": h.removeprefix("sha256:") if isinstance(h, str) else h,
        })
    return leaves


def build_signed_bundle(report: Report) -> dict[str, Any]:
    """Build the signed bundle for a Report.

    The bundle contains the full sections payload, a Merkle root over
    every evidence record, the per-leaf inclusion proof, and an Ed25519
    signature over the bundle's integrity-bearing header. A verifier
    only needs the public key (served at /api/reports/signing-key) plus
    the trusted root to check any single evidence record without
    receiving the rest of the report.
    """
    sections = report.sections
    leaves = _evidence_leaves(sections)
    tree = build_tree([leaf["leaf_hash"] for leaf in leaves])

    proofs: list[dict[str, Any]] = []
    for idx, leaf in enumerate(leaves):
        steps = [step_to_dict(s) for s in tree.inclusion_proof(idx)] if leaves else []
        proofs.append({**leaf, "leaf_index": idx, "proof": steps})

    sections_hash = hash_sections(sections)
    envelope = sign_report_bundle(
        report_id=report.id,
        generated_at=report.generated_at,
        content_hash=sections_hash,
        merkle_root=f"sha256:{tree.root_hex}",
        sections=sections,
    )
    envelope["title"] = report.title
    envelope["project_id"] = report.project_id
    envelope["evidence_leaves"] = proofs
    envelope["evidence_count"] = len(leaves)
    return envelope


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

def render_pdf(report: Report) -> bytes:
    """Render the Report as a PDF using fpdf2 (pure-Python, no system deps).

    The layout intentionally mirrors `render_markdown` section ordering
    so a reader who's seen the markdown version isn't disoriented. A
    signed footer at the end carries the Ed25519 signature + key id +
    Merkle root so the printed page is itself a verifiable artifact.
    """
    # Imported lazily so the rest of reporting.py stays importable even
    # if fpdf2 isn't installed (e.g. a slim test profile).
    from fpdf import FPDF

    bundle = build_signed_bundle(report)
    s = report.sections

    pdf = FPDF(unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(left=18, top=18, right=18)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    _safe_cell(pdf, report.title, h=10, ln=True)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(110, 110, 110)
    _safe_cell(pdf, f"Generated {report.generated_at.isoformat()}", h=5, ln=True)
    if report.is_demo_data:
        pdf.set_text_color(180, 60, 60)
        _safe_cell(pdf, "DEMO DATA — findings are seeded, not from a live scan.", h=5, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    _pdf_heading(pdf, "Engagement Summary")
    _pdf_paragraph(pdf, s["engagement_summary"]["description"])
    _pdf_paragraph(pdf, f"Project risk score: {s['engagement_summary']['risk_score']}/100")

    _pdf_heading(pdf, "Scope")
    _pdf_paragraph(pdf, s["scope_statement"])

    _pdf_heading(pdf, "Authorization Statement")
    _pdf_paragraph(pdf, s["authorization_statement"])

    _pdf_heading(pdf, "Executive Summary")
    _pdf_paragraph(pdf, s["executive_summary"])

    _pdf_heading(pdf, "Risk Overview")
    for sev, count in s["risk_overview"].items():
        _pdf_paragraph(pdf, f"• {sev.upper()}: {count}", indent=4)

    _pdf_heading(pdf, "Top Findings")
    for sev_label, items in s["findings_by_severity"].items():
        if not items:
            continue
        pdf.set_font("Helvetica", "B", 10)
        _safe_cell(pdf, sev_label.upper(), h=6, ln=True)
        pdf.set_font("Helvetica", "", 9)
        for item in items[:25]:
            _pdf_paragraph(pdf, f"• {item['title']}  —  scanner: {item['scanner']}", indent=4)
        pdf.ln(1)

    _pdf_heading(pdf, "Attack Paths")
    if s["attack_paths"]:
        for path in s["attack_paths"][:10]:
            pdf.set_font("Helvetica", "B", 11)
            _safe_cell(pdf, path.get("title", "(untitled)"), h=6, ln=True)
            pdf.set_font("Helvetica", "", 9)
            _pdf_paragraph(pdf, path.get("narrative") or path.get("summary") or "")
            _pdf_paragraph(pdf, f"Status: {path.get('status', 'hypothesis')}  ·  Confidence: {path.get('confidence')}")
    else:
        _pdf_paragraph(pdf, "No attack-path hypotheses produced for this engagement.")

    _pdf_heading(pdf, "Remediation Roadmap")
    for task in s["remediation_roadmap"][:20]:
        _pdf_paragraph(pdf, f"[{task['priority'].upper()}] {task['title']}", indent=4)

    _pdf_heading(pdf, "Evidence References")
    pdf.set_font("Helvetica", "", 8)
    for ev in s["evidence"][:60]:
        _pdf_paragraph(
            pdf,
            f"{ev['id']}  ·  {ev['scanner']}  ·  hash={ev['content_hash'] or '(none)'}",
            indent=2,
        )

    _pdf_heading(pdf, "Safety Statement")
    _pdf_paragraph(pdf, s["safety_statement"])

    _pdf_heading(pdf, "Cryptographic Footer")
    pdf.set_font("Courier", "", 7.5)
    pdf.set_text_color(60, 60, 60)
    _safe_cell(pdf, f"signing_key_id : {bundle['signing_key_id']}", h=4, ln=True)
    _safe_cell(pdf, f"algorithm      : {bundle['algorithm']}", h=4, ln=True)
    _safe_cell(pdf, f"content_hash   : {bundle['content_hash']}", h=4, ln=True)
    _safe_cell(pdf, f"merkle_root    : {bundle['merkle_root']}", h=4, ln=True)
    _safe_cell(pdf, f"evidence_count : {bundle['evidence_count']}", h=4, ln=True)
    _safe_cell(pdf, "signature (base64, 88 chars):", h=4, ln=True)
    sig = bundle["signature"]
    # Split the signature so it fits inside the printable area.
    for chunk_start in range(0, len(sig), 64):
        _safe_cell(pdf, sig[chunk_start:chunk_start + 64], h=4, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)
    pdf.set_font("Helvetica", "I", 7.5)
    _safe_cell(
        pdf,
        "Verify: fetch the Ed25519 public key from /api/reports/signing-key and "
        "the signed JSON bundle from /api/reports/{project_id}/signed.json, "
        "then check signature over the canonicalized {report_id, generated_at, "
        "content_hash, merkle_root}.",
        h=4, ln=True,
    )

    out_io = BytesIO()
    pdf.output(out_io)
    return out_io.getvalue()


def _pdf_heading(pdf: "FPDF", title: str) -> None:  # type: ignore[name-defined]
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(40, 60, 110)
    _safe_cell(pdf, title, h=7, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)


def _pdf_paragraph(pdf: "FPDF", body: str, *, indent: int = 0) -> None:  # type: ignore[name-defined]
    if not body:
        return
    safe = _ascii_safe(body)
    # Always reset to a known X then pass an explicit width. Without
    # this, a previous `set_x` from another helper can leave the cursor
    # near the right margin and `multi_cell(0, …)` computes a zero/
    # negative wrap width and raises "Not enough horizontal space".
    pdf.set_x(pdf.l_margin + indent)
    width = max(20.0, pdf.epw - indent)
    pdf.multi_cell(w=width, h=4.5, text=safe)


def _safe_cell(pdf: "FPDF", text: str, *, h: float, ln: bool) -> None:  # type: ignore[name-defined]
    pdf.cell(0, h=h, text=_ascii_safe(text), new_x="LMARGIN" if ln else "RIGHT", new_y="NEXT" if ln else "TOP")


def _ascii_safe(text: str) -> str:
    """fpdf2's core fonts (Helvetica/Courier) only carry latin-1 glyphs.

    Strip anything outside that range so we never crash on, e.g.,
    em-dashes or curly quotes that came from the markdown source.
    """
    if not isinstance(text, str):
        text = str(text)
    return text.encode("latin-1", errors="replace").decode("latin-1")
