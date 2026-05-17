"""Acme FlightOps Demo — seeded dataset for the dashboard / reports flow.

Every finding here is fake demo evidence; `is_demo_data=True` propagates from
findings into attack paths, scanner runs, reports, and the UI banner.

Project id stays `"demo"` so existing API consumers keep working — only the
display name and underlying content changed.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.models.schemas import (
    AgentOutput,
    Asset,
    AttackPath,
    AttackPathEdge,
    AttackPathNode,
    AuthorizedScope,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Project,
    ScannerRun,
    ScanSchedule,
    ScopeRules,
    Severity,
    Target,
    Workspace,
)

_NOW = datetime(2026, 5, 16, 18, 0, tzinfo=timezone.utc)

WORKSPACE = Workspace(
    id="workspace-demo",
    name="Acme FlightOps Workspace",
    created_at=_NOW,
)

_SCOPE_RULES = ScopeRules(
    domains=["flightops.acme.example", "demo.asura.local"],
    urls=[
        "https://flightops.acme.example",
        "https://flightops.acme.example/api/admin",
        "https://flightops.acme.example/admin",
        "https://demo.asura.local",
        "https://demo.asura.local/api/admin",
    ],
    cidrs=["10.10.7.0/24"],
    repos=["git://acme/flightops-platform", "git://demo/asura-lab"],
    containers=["ghcr.io/acme/flightops:latest", "ghcr.io/demo/asura-lab:latest"],
    blocked_targets=["169.254.169.254"],
    allow_active=True,
    allow_lab=False,
    max_requests_per_second=2,
    timeout_seconds=900,
)

PROJECT = Project(
    id="demo",
    workspace_id=WORKSPACE.id,
    name="Acme FlightOps Demo",
    description=(
        "Acme FlightOps demo project. Seeded vulnerable web app, repo, container, "
        "and cloud policy used to demonstrate evidence-grounded correlation and "
        "attack-path reasoning."
    ),
    scope_rules=_SCOPE_RULES,
    risk_score=88,
    targets=[
        "https://flightops.acme.example",
        "git://acme/flightops-platform",
        "ghcr.io/acme/flightops:latest",
        "https://demo.asura.local",
        "git://demo/asura-lab",
        "ghcr.io/demo/asura-lab:latest",
    ],
    created_at=_NOW,
    is_demo_data=True,
)

ASSETS = [
    Asset(id="asset-web", project_id="demo", kind="web_app", name="FlightOps Public Admin", address="https://flightops.acme.example", exposure="public", criticality="critical"),
    Asset(id="asset-repo", project_id="demo", kind="repo", name="flightops-platform", address="git://acme/flightops-platform", exposure="private", criticality="high"),
    Asset(id="asset-host", project_id="demo", kind="host", name="edge-01", address="edge-01.flightops.acme.example", exposure="public", criticality="high"),
    Asset(id="asset-image", project_id="demo", kind="container", name="flightops:latest", address="ghcr.io/acme/flightops:latest", exposure="private", criticality="medium"),
    Asset(id="asset-api", project_id="demo", kind="api_spec", name="Admin API", address="https://flightops.acme.example/api/admin", exposure="public", criticality="critical"),
    Asset(id="asset-cloud", project_id="demo", kind="dependency", name="Acme Cloud IAM", address="iam://acme/flightops-admin-role", exposure="internal", criticality="high"),
]

TARGETS = [
    Target(id="target-web", project_id="demo", kind="url", value="https://flightops.acme.example", authorized=True, owned_internal=True, is_demo_data=True, created_at=_NOW),
    Target(id="target-repo", project_id="demo", kind="repo", value="git://acme/flightops-platform", authorized=True, owned_internal=True, is_demo_data=True, created_at=_NOW),
    Target(id="target-host", project_id="demo", kind="host", value="edge-01.flightops.acme.example", authorized=True, owned_internal=True, is_demo_data=True, created_at=_NOW),
    Target(id="target-image", project_id="demo", kind="container", value="ghcr.io/acme/flightops:latest", authorized=True, owned_internal=True, is_demo_data=True, created_at=_NOW),
    Target(id="target-api", project_id="demo", kind="url", value="https://flightops.acme.example/api/admin", authorized=True, owned_internal=True, is_demo_data=True, created_at=_NOW),
]

SCOPES = [
    AuthorizedScope(
        id="scope-demo",
        project_id="demo",
        name="Acme FlightOps authorized scope",
        scope_rules=_SCOPE_RULES,
        explicit_authorization_grant=True,
        grantor="Acme Security Engineering",
        granted_at=_NOW,
        audit_note="Demo scope; do not use as a template for production engagements.",
        is_demo_data=True,
    )
]

SCHEDULES = [
    ScanSchedule(
        id="schedule-passive-daily",
        project_id="demo",
        name="Daily passive sweep (placeholder)",
        cron="0 4 * * *",
        scanners=["semgrep", "gitleaks", "osv-scanner", "trivy"],
        enabled=False,
        is_demo_data=True,
        created_at=_NOW,
    )
]


def _evidence(finding_id: str, scanner: str, summary: str, raw: dict, *, file_path: str | None = None) -> Evidence:
    return Evidence(
        id=f"ev-{finding_id}",
        finding_id=finding_id,
        evidence_type=EvidenceType.scanner_output,
        scanner=scanner,
        raw=raw,
        summary=summary,
        source_tool=scanner,
        file_path=file_path,
        captured_at=_NOW,
        created_at=_NOW,
        content_hash=None,  # demo: hashing happens when persisted
        is_demo_data=True,
    )


def _finding(
    *,
    fid: str,
    asset_id: str,
    scanner: str,
    title: str,
    category: str,
    severity: Severity,
    confidence,
    impact: str,
    recommendation: str,
    reproduction: str,
    fp_reason: str,
    evidence_raw: dict,
    evidence_summary: str,
    evidence_file: str | None = None,
    affected_asset: str | None = None,
    affected_component: str | None = None,
    cwe: list[str] | None = None,
    cve: list[str] | None = None,
    owasp: list[str] | None = None,
    related: list[str] | None = None,
) -> Finding:
    ev = _evidence(fid, scanner, evidence_summary, evidence_raw, file_path=evidence_file)
    return Finding(
        id=fid,
        project_id="demo",
        workspace_id="workspace-demo",
        asset_id=asset_id,
        target_id=None,
        scanner=scanner,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        status="new",
        affected_asset=affected_asset,
        affected_component=affected_component,
        impact=impact,
        recommendation=recommendation,
        reproduction=reproduction,
        false_positive_reasoning=fp_reason,
        cwe=cwe or [],
        cve=cve or [],
        owasp_mapping=owasp or [],
        source_tools=[scanner],
        related_finding_ids=related or [],
        evidence=[ev],
        first_seen=_NOW,
        last_seen=_NOW,
        created_at=_NOW,
        is_demo_data=True,
    )


FINDINGS: list[Finding] = [
    _finding(
        fid="f-secret",
        asset_id="asset-repo",
        scanner="gitleaks",
        title="Privileged API token committed to repository",
        category="secrets",
        severity=Severity.critical,
        confidence=96,
        impact="A leaked administrative token can let an attacker call privileged backend APIs.",
        recommendation="Revoke the token, rotate dependent credentials, remove it from git history, and enforce pre-commit secret scanning.",
        reproduction="Gitleaks matched a fake FlightOps admin token in config/demo.env on line 12.",
        fp_reason="The token matches the configured internal prefix and appears in an environment file, not documentation.",
        evidence_raw={"file": "config/demo.env", "line": 12, "rule": "asura-admin-token"},
        evidence_summary="Secret pattern matched in repository history.",
        evidence_file="config/demo.env",
        affected_asset="git://acme/flightops-platform",
        affected_component="config/demo.env:12",
        cwe=["CWE-798"],
        owasp=["OWASP A07:2021 Identification and Authentication Failures"],
        related=["f-cors", "f-nuclei-admin", "f-checkov-iam"],
    ),
    _finding(
        fid="f-osv",
        asset_id="asset-repo",
        scanner="osv-scanner",
        title="Vulnerable npm dependency: axios <0.21.1",
        category="dependency",
        severity=Severity.high,
        confidence=Confidence.high,
        impact="A vulnerable HTTP client introduces a known SSRF vector reachable from the API tier.",
        recommendation="Upgrade axios to 0.21.1 or later and re-run osv-scanner against the lockfile.",
        reproduction="osv-scanner matched GHSA-jx5p-h2ch-7p2v on axios@0.20.0 in package-lock.json.",
        fp_reason="OSV.dev advisory matched the installed package range.",
        evidence_raw={"package": "axios", "installed": "0.20.0", "advisory": "GHSA-jx5p-h2ch-7p2v"},
        evidence_summary="Vulnerable axios version flagged by OSV.",
        evidence_file="package-lock.json",
        affected_asset="git://acme/flightops-platform",
        affected_component="axios@0.20.0",
        cve=["CVE-2020-28168"],
    ),
    _finding(
        fid="f-semgrep-auth",
        asset_id="asset-repo",
        scanner="semgrep",
        title="Missing auth check on internal route",
        category="code",
        severity=Severity.high,
        confidence=88,
        impact="An internal admin route is reachable without authentication when called via a normalized path.",
        recommendation="Add an authentication guard to the internal route and integration tests for the unauthenticated case.",
        reproduction="Semgrep rule routes.missing-auth matched src/routes/admin.ts at line 42.",
        fp_reason="The matched code path lacks any authorization check before returning admin data.",
        evidence_raw={"file": "src/routes/admin.ts", "line": 42, "rule": "routes.missing-auth"},
        evidence_summary="Semgrep flagged a route handler without an auth guard.",
        evidence_file="src/routes/admin.ts",
        affected_asset="git://acme/flightops-platform",
        affected_component="src/routes/admin.ts:42",
        cwe=["CWE-862"],
        owasp=["OWASP A01:2021 Broken Access Control"],
        related=["f-nuclei-admin"],
    ),
    _finding(
        fid="f-nuclei-admin",
        asset_id="asset-web",
        scanner="nuclei",
        title="Exposed admin route on public host",
        category="web",
        severity=Severity.high,
        confidence=Confidence.high,
        impact="A management surface is reachable from the public internet, amplifying any auth weakness.",
        recommendation="Restrict the admin route to a private network or VPN-fronted ingress.",
        reproduction="Nuclei template http/exposures/panels/admin-panel matched https://flightops.acme.example/admin.",
        fp_reason="Nuclei template confirmed an HTTP 200 admin-panel response on the public host.",
        evidence_raw={"template": "http/exposures/panels/admin-panel", "matched_at": "https://flightops.acme.example/admin"},
        evidence_summary="Nuclei matched the admin-panel template on the public host.",
        affected_asset="https://flightops.acme.example/admin",
        affected_component="admin-panel",
        cwe=["CWE-284"],
        related=["f-semgrep-auth", "f-secret"],
    ),
    _finding(
        fid="f-cors",
        asset_id="asset-web",
        scanner="zap",
        title="Weak CORS policy with credential reflection",
        category="web",
        severity=Severity.medium,
        confidence=82,
        impact="A malicious site may be able to read authenticated API responses if victim credentials are present.",
        recommendation="Replace reflection with an explicit origin allowlist and remove credential support where unnecessary.",
        reproduction="ZAP observed Access-Control-Allow-Credentials with reflected Origin on /api.",
        fp_reason="The response reflects attacker-controlled Origin and includes credential support.",
        evidence_raw={"url": "https://flightops.acme.example/api", "header": "Access-Control-Allow-Credentials: true"},
        evidence_summary="CORS origin reflection with credentials.",
        affected_asset="https://flightops.acme.example/api",
        affected_component="CORS",
        cwe=["CWE-942"],
        owasp=["OWASP A05:2021 Security Misconfiguration"],
        related=["f-secret", "f-nuclei-admin"],
    ),
    _finding(
        fid="f-trivy-image",
        asset_id="asset-image",
        scanner="trivy",
        title="Container image includes vulnerable OpenSSL package",
        category="container",
        severity=Severity.medium,
        confidence=78,
        impact="A vulnerable crypto package increases the blast radius if the container is reachable or compromised.",
        recommendation="Rebuild the image from a patched base and pin package updates in CI.",
        reproduction="Trivy matched the installed OpenSSL version against a known vulnerability record.",
        fp_reason="The package is present in the runtime layer and the vulnerable version range matches.",
        evidence_raw={"package": "openssl", "installed": "3.0.2", "fixed": "3.0.8"},
        evidence_summary="OpenSSL vulnerable package in runtime image.",
        affected_asset="ghcr.io/acme/flightops:latest",
        affected_component="openssl@3.0.2",
        cve=["CVE-2023-0286"],
    ),
    _finding(
        fid="f-checkov-iam",
        asset_id="asset-cloud",
        scanner="checkov",
        title="Overbroad IAM policy allows wildcard actions",
        category="iac",
        severity=Severity.high,
        confidence=90,
        impact="Wildcard actions on the FlightOps admin role increase privilege if the credential is leaked.",
        recommendation="Scope the policy actions to least privilege; remove wildcards on sensitive services.",
        reproduction="Checkov rule CKV_AWS_111 failed on terraform/iam/admin_role.tf.",
        fp_reason="Policy explicitly allows Action='*' on Resource='*' for the admin role.",
        evidence_raw={"file": "terraform/iam/admin_role.tf", "check": "CKV_AWS_111"},
        evidence_summary="IaC misconfiguration: wildcard IAM action on the admin role.",
        evidence_file="terraform/iam/admin_role.tf",
        affected_asset="iam://acme/flightops-admin-role",
        affected_component="terraform/iam/admin_role.tf",
        cwe=["CWE-732"],
        owasp=["OWASP A05:2021 Security Misconfiguration"],
        related=["f-secret"],
    ),
    _finding(
        fid="f-zap-headers",
        asset_id="asset-web",
        scanner="zap",
        title="Missing security headers on public host",
        category="web",
        severity=Severity.low,
        confidence=Confidence.high,
        impact="Missing headers (CSP, HSTS, X-Frame-Options) weaken defense-in-depth against client-side attacks.",
        recommendation="Add CSP, Strict-Transport-Security, and X-Frame-Options to the edge proxy.",
        reproduction="ZAP passive scan reported missing CSP and HSTS on https://flightops.acme.example.",
        fp_reason="Headers explicitly absent in the production response.",
        evidence_raw={"missing": ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]},
        evidence_summary="ZAP passive scan flagged missing security headers.",
        affected_asset="https://flightops.acme.example",
        affected_component="response headers",
        cwe=["CWE-693"],
    ),
    _finding(
        fid="f-nmap-tls",
        asset_id="asset-host",
        scanner="nmap",
        title="Edge host accepts legacy TLS 1.0 with weak ciphers",
        category="network",
        severity=Severity.medium,
        confidence=Confidence.high,
        impact="Weak transport security may permit downgrade or known cipher attacks.",
        recommendation="Disable TLS 1.0/1.1 and weak ciphers at the edge load balancer.",
        reproduction="Nmap ssl-enum-ciphers reported TLS 1.0 with RC4 enabled on tcp/443.",
        fp_reason="Service banner and cipher list confirm legacy protocol support.",
        evidence_raw={"port": 443, "protocol": "tcp", "tls_versions": ["TLS 1.0", "TLS 1.2"], "weak_ciphers": ["RC4-MD5"]},
        evidence_summary="Nmap ssl-enum-ciphers found TLS 1.0 with RC4 enabled.",
        affected_asset="edge-01.flightops.acme.example",
        affected_component="tcp/443 TLS",
        cwe=["CWE-326"],
    ),
    _finding(
        fid="f-zap-ratelimit",
        asset_id="asset-api",
        scanner="zap",
        title="API endpoint missing rate limiting",
        category="api",
        severity=Severity.medium,
        confidence=Confidence.medium,
        impact="An unauthenticated API route returns successfully under sustained request volume without throttling.",
        recommendation="Add a per-IP/per-token rate limit at the API gateway and add a regression test.",
        reproduction="ZAP active scan sustained 100 RPS against /api/admin/export with no 429 responses.",
        fp_reason="The endpoint accepted the full sustained request volume with HTTP 200 responses.",
        evidence_raw={"url": "https://flightops.acme.example/api/admin/export", "observed_rps": 100, "status": 200},
        evidence_summary="ZAP active scan observed 100 RPS without rate limiting.",
        affected_asset="https://flightops.acme.example/api/admin/export",
        affected_component="rate_limit",
        owasp=["OWASP API4:2023 Unrestricted Resource Consumption"],
        related=["f-semgrep-auth"],
    ),
]


def _node(fid: str, kind: str = "finding") -> AttackPathNode:
    f = next((f for f in FINDINGS if f.id == fid), None)
    return AttackPathNode(
        id=fid,
        label=f.title if f else fid,
        kind=kind,
        severity=f.severity if f else None,
        ref_id=fid,
    )


def _edge(src: str, dst: str, label: str, kind: str = "enables") -> AttackPathEdge:
    return AttackPathEdge(source=src, target=dst, label=label, kind=kind)


def _path(*, pid: str, title: str, summary: str, narrative: str, finding_ids: list[str], severity: Severity, status: str, confidence: Confidence, risk: int, next_steps: list[str]) -> AttackPath:
    nodes = [_node(fid) for fid in finding_ids]
    edges = [_edge(src, dst, "enables") for src, dst in zip(finding_ids, finding_ids[1:])]
    evidence_refs = [ev.id for fid in finding_ids for f in FINDINGS if f.id == fid for ev in f.evidence]
    return AttackPath(
        id=pid,
        project_id="demo",
        title=title,
        summary=summary,
        narrative=narrative,
        confidence=confidence,
        risk_score=risk,
        severity=severity,
        status=status,  # type: ignore[arg-type]
        finding_ids=finding_ids,
        evidence_refs=evidence_refs,
        nodes=nodes,
        edges=edges,
        remediation_order=finding_ids,
        recommended_next_steps=next_steps,
        safe_validation_needed=next_steps[:1],
        remediation_summary="; ".join(next_steps),
        created_at=_NOW,
        is_demo_data=True,
    )


ATTACK_PATHS: list[AttackPath] = [
    _path(
        pid="ap-admin-takeover",
        title="Likely admin privilege escalation chain",
        summary=(
            "A leaked privileged token, permissive CORS, an exposed admin route, "
            "and a missing-auth code path combine into a credible admin compromise path."
        ),
        narrative=(
            "Gitleaks evidence and a Semgrep rule both touch the admin surface; "
            "ZAP corroborates the CORS misconfiguration and Nuclei the public "
            "admin route. Together they amplify each other into a likely "
            "account-takeover chain."
        ),
        finding_ids=["f-secret", "f-cors", "f-nuclei-admin", "f-semgrep-auth"],
        severity=Severity.critical,
        status="likely",
        confidence=Confidence.high,
        risk=94,
        next_steps=[
            "Rotate the leaked token and remove it from git history.",
            "Replace CORS reflection with an explicit origin allowlist.",
            "Re-test the admin route once the secret is rotated.",
        ],
    ),
    _path(
        pid="ap-container-exposure",
        title="Container-to-service exposure chain",
        summary=(
            "A vulnerable OpenSSL package inside the container, weak TLS on the "
            "edge host, and missing security headers form a credible exposure chain."
        ),
        narrative=(
            "Trivy identifies the vulnerable package; Nmap shows legacy TLS at the "
            "edge; ZAP confirms missing defense-in-depth headers. Each individually "
            "is a low-to-medium issue, but together they reduce the cost of "
            "exploitation against the public surface."
        ),
        finding_ids=["f-trivy-image", "f-nmap-tls", "f-zap-headers"],
        severity=Severity.high,
        status="hypothesis",
        confidence=Confidence.medium,
        risk=72,
        next_steps=[
            "Rebuild the container image on a patched base.",
            "Disable TLS 1.0/1.1 and weak ciphers at the edge.",
            "Add CSP, HSTS, and X-Frame-Options to responses.",
        ],
    ),
    _path(
        pid="ap-cloud-permission",
        title="Cloud permission risk chain",
        summary=(
            "The leaked credential, an overbroad IAM policy, and a sensitive API "
            "endpoint without rate limiting together form a plausible permission "
            "abuse and data exposure path."
        ),
        narrative=(
            "Gitleaks evidence, Checkov's wildcard-action finding, and ZAP's "
            "rate-limit observation overlap on the admin export endpoint. The "
            "attacker need not be sophisticated — the surface is wide and the "
            "credential is already present in the repo."
        ),
        finding_ids=["f-secret", "f-checkov-iam", "f-zap-ratelimit"],
        severity=Severity.high,
        status="hypothesis",
        confidence=Confidence.medium,
        risk=78,
        next_steps=[
            "Rotate the leaked credential.",
            "Scope the IAM policy down to least privilege.",
            "Add per-token rate limiting at the API gateway.",
        ],
    ),
]

AGENT_OUTPUTS = [
    AgentOutput(
        agent="pentest_brain",
        summary="Three evidence-backed attack-path hypotheses correlate findings across SAST, DAST, SCA, container, and IaC tools.",
        confidence=Confidence.high,
        supporting_finding_ids=[f.id for f in FINDINGS],
        cited_evidence_ids=[ev.id for f in FINDINGS for ev in f.evidence],
        attack_path={"ids": [p.id for p in ATTACK_PATHS], "unsupported_claims": []},
        recommended_next_steps=[
            "Fix the missing admin-route auth check.",
            "Rotate the leaked demo token and CI credentials.",
            "Constrain the IAM admin role to least privilege.",
        ],
    ),
    AgentOutput(
        agent="pentest_brain",
        summary=(
            "Scope allows passive scans and active scans for the listed FlightOps "
            "domains, CIDRs, repos, and containers. Lab mode is disabled."
        ),
        confidence=Confidence.confirmed,
        cited_evidence_ids=[],
        recommended_next_steps=[
            "Keep lab mode disabled unless running intentionally vulnerable targets.",
        ],
    ),
]

SCANNER_RUNS: list[ScannerRun] = [
    ScannerRun(
        id="run-gitleaks", project_id="demo", scanner="gitleaks", mode="passive", status="completed",
        target="git://acme/flightops-platform",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 secret finding normalized.",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-semgrep", project_id="demo", scanner="semgrep", mode="passive", status="completed",
        target="git://acme/flightops-platform",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 auth finding normalized.",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-osv", project_id="demo", scanner="osv-scanner", mode="passive", status="completed",
        target="git://acme/flightops-platform",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 dependency vulnerability normalized.",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-trivy", project_id="demo", scanner="trivy", mode="passive", status="completed",
        target="ghcr.io/acme/flightops:latest",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 container vulnerability normalized.",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-checkov", project_id="demo", scanner="checkov", mode="passive", status="completed",
        target="git://acme/flightops-platform",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 IaC misconfiguration normalized.",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-nuclei", project_id="demo", scanner="nuclei", mode="active", status="completed",
        target="https://flightops.acme.example",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 admin-panel exposure normalized.",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-zap", project_id="demo", scanner="zap", mode="active", status="completed",
        target="https://flightops.acme.example",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 3 web findings normalized (CORS, headers, rate-limit).",
        is_demo_data=True,
    ),
    ScannerRun(
        id="run-nmap", project_id="demo", scanner="nmap", mode="active", status="completed",
        target="edge-01.flightops.acme.example",
        started_at=_NOW, finished_at=_NOW,
        message="DEMO MODE — 1 TLS finding normalized.",
        is_demo_data=True,
    ),
]

RISK_TREND = [
    {"date": "2026-05-10", "score": 72},
    {"date": "2026-05-11", "score": 74},
    {"date": "2026-05-12", "score": 80},
    {"date": "2026-05-13", "score": 85},
    {"date": "2026-05-14", "score": 82},
    {"date": "2026-05-15", "score": 89},
    {"date": "2026-05-16", "score": 88},
]
