"""Report generation.

Produces structured Markdown and JSON reports with the full section set
required by the Asura product spec. Every report stamps a scope statement,
an authorization statement, and a safety statement so the deliverable is
suitable for handing to a stakeholder.
"""
from __future__ import annotations

from datetime import datetime, timezone
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
