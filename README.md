<div align="center">

# Asura

**Self-hosted security command center for authorized testing.**
Orchestrates 26 real scanners. Preserves evidence. Correlates attack paths. Refuses to pretend a scan happened.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active%20development-orange.svg)](#roadmap)
[![Backend tests](https://img.shields.io/badge/backend%20tests-139%20passing-brightgreen.svg)](backend/tests)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)
[![Tools](https://img.shields.io/badge/wired%20scanners-26%20of%2090-blue.svg)](#wired-scanners)

</div>

---

> **Stop running ten security tools and reading ten JSON files.**
> Asura runs the scanners, preserves the raw output with a content hash, deduplicates findings across tools, correlates them into attack-path hypotheses, and produces a report you can hand to a stakeholder.

```text
                 ┌───────────────────────────────────────────────────────┐
                 │                                                       │
   Authorized ──▶│   ScopeGuard ──▶ DemoRunner          │ JobQueue       │
   target /      │   (allow │ block) ──▶ SubprocessRunner│ (background    │
   scope         │                  ──▶ DockerRunner    │  threads + RQ) │
                 │                                                       │
                 │              ▼                                        │
                 │       Parsers (Nmap XML, Nuclei JSON, SARIF, …)       │
                 │              ▼                                        │
                 │       Evidence Vault (sha256, never overwrite)        │
                 │              ▼                                        │
                 │       Repositories (Findings, Runs, Audit, Jobs)      │
                 │              ▼                                        │
                 │       PentestBrain  ─▶  ranks · dedupes · correlates  │
                 │              ▼                                        │
                 │       Reports (Markdown + JSON, scope + safety stmt)  │
                 │                                                       │
                 └───────────────────────────────────────────────────────┘
```

## What it does

- **Runs real scanners** — 26 are wired end-to-end today (Nmap, Nuclei, Semgrep, Trivy, Gitleaks, OSV-Scanner, Checkov, OWASP ZAP, Syft, Grype, plus 10 language-specific tools, plus 6 ProjectDiscovery recon tools, plus a generic SARIF importer for CodeQL).
- **Zero local install needed** — 20 of the 26 ship with canonical Docker images. If a binary isn't on PATH, Asura runs `docker run --rm <image>` automatically. Set `ASURA_PREFER_DOCKER=1` to always prefer the container path.
- **Background jobs + pipelines** — `POST /api/scans/async` returns immediately with a job id; poll `/api/jobs/{id}` for progress. Three preset pipelines (`passive-recon`, `code-audit`, `container-audit`) chain multiple scanners with optional asset-passing between stages.
- **Evidence-first** — every finding carries at least one `Evidence` record with a sha256 content hash and the exact argv used. Raw payloads land at `evidence/<workspace>/<project>/<scan_id>/<tool>.json` and are never overwritten.
- **Scope-gated** — the safety guard rejects scans against private IPs without `owned_internal=True`, requires explicit authorization for active/lab modes, blocks high-risk tools outside lab mode, and writes one `AuditLog` row per decision (allow or block).
- **Deterministic reasoning** — `PentestBrain` ranks, deduplicates by fingerprint, correlates findings into attack-path hypotheses, and generates remediation plans. **Every claim cites the evidence IDs that produced it** — no hallucinated vulns.
- **Reports you can hand to a stakeholder** — Markdown + JSON with engagement summary, scope statement, authorization statement, methodology, tools used, executive summary, risk overview, attack paths, findings by severity, evidence references, remediation roadmap, and a safety statement.

## What it is *not*

Asura is not an unauthorized hacking tool, malware framework, phishing kit, credential stealer, ransomware builder, or fake AI scanner. The blocked-capability list is enforced in code and exposed at `GET /api/safety/blocked`. The default scanner mode is passive; active and lab modes require explicit per-scan authorization.

## Use cases

| You want to… | Asura does it via |
|--------------|-------------------|
| Audit your own repo for code issues, leaked secrets, vulnerable deps, and IaC misconfigs in one pass | The `code-audit` pipeline: Semgrep + Gitleaks + OSV-Scanner running in parallel against the repo, results normalized into one Findings view. |
| Scan a container image without manually running 4 different tools | The `container-audit` pipeline: Syft (SBOM) → Grype (vulns) + Trivy (vulns + misconfig + secrets). |
| Do passive recon on an authorized scope | The `passive-recon` pipeline: Subfinder → HTTPx (probes each discovered subdomain). Asset chaining is automatic. |
| Run a long scan without blocking your browser tab | "Run in background" on the Run-scan form (or `POST /api/scans/async`). Tracks progress at `/jobs/{id}`. |
| Use Asura on a fresh machine without installing nmap / nuclei / trivy / etc. | Install Docker. Asura's runner auto-falls-back to the registered image for every wired scanner. |
| Hand a customer a deliverable | `POST /api/reports/{project_id}` returns Markdown + JSON with 14 sections including a scope + authorization + safety statement. |
| Prove every claim about a finding is grounded in real data | Every `Finding.evidence[i]` carries a sha256 `content_hash` of the raw scanner output; every `PentestBrain` claim returns `cited_evidence_ids`. |

## Install

```bash
git clone https://github.com/AaronGrillot98/Asura
cd Asura
cp .env.example .env
docker compose up -d
```

Or run the dev stack directly without Docker:

```bash
# terminal 1 — backend
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Open <http://localhost:3000>. Backend at <http://localhost:8000/docs>.

## Your first real scan

```bash
# Option A — install one scanner locally
pipx install semgrep

# Option B — don't install anything; Asura will auto-run scanners in Docker
# (most of the wired 20 have canonical images registered)
```

Then on the dashboard:

1. Click **Run scan** (top right of the Command Center).
2. Target: `/path/to/your/repo` for code, or `https://your.authorized.target` for web.
3. Pick a scanner — `semgrep` is a good first run.
4. Mode: `passive`.
5. **Submit**.

The Command Center refreshes. The scan run appears under `/scans` with a message ending in *"via local binary …"* or *"via Docker image …"* so you know exactly which execution path ran. New findings appear under `/findings`. The raw payload lands on disk at `evidence/…/<tool>.json` with a sha256 content hash.

For long scans, check **Run in background** on the form. The job is queued, you get a job id, and you can poll progress at `/jobs/{id}`.

## Pipelines

Pipelines are named chains of scanner stages. Three ship today:

| ID | Stages | Risk |
|----|--------|------|
| `passive-recon` | subfinder → httpx (probes discovered subdomains) | low |
| `code-audit` | Semgrep · Gitleaks · OSV-Scanner | low |
| `container-audit` | Syft → Grype + Trivy | low |

Run one from the `/pipelines` page or:

```bash
curl -X POST http://localhost:8000/api/pipelines/run \
  -H 'Content-Type: application/json' \
  -d '{"project_id":"demo","pipeline_id":"code-audit","target":"/path/to/repo"}'
```

The response contains a `job_id`. Poll `/api/jobs/{job_id}` for progress.

## Dashboard tour

| Route | What you see |
|-------|--------------|
| `/` | Command Center: hero metrics, risk trend chart, coverage-by-domain grid, most-dangerous attack path, "fix these first", scanner health, brain reasoning, top findings, quick links. |
| `/projects` | Workspace projects with status dots; **New project** opens a wizard for scope rules + grantor. |
| `/projects/{id}` | Per-project dashboard with inline targets editor + Run scan + Delete. |
| `/jobs` | Background job queue with status, progress %, runs produced, findings created. |
| `/pipelines` | Preset chains with "Run pipeline" forms inline. |
| `/findings` and `/findings/{id}` | Filterable table; Evidence Drawer with raw JSON, content hash, command metadata. |
| `/attack-paths/{id}` | xyflow graph of nodes/edges + remediation roadmap. |
| `/arsenal` | Catalog of 94 registered tools with status dots, install badges, lab-only markers. |
| `/audit` | Every scope decision (allow / block) with timestamp + reason. |
| `/safety` | The blocked-capability list — pulled live from `/api/safety/blocked`. |
| `/reports` | Markdown + JSON report downloads. |

Press **`/`** anywhere to open the global search palette (also `Ctrl/Cmd+K`). Search across projects, findings, tools, scanner runs, and attack paths.

## Wired scanners

| Pack | Tools |
|------|-------|
| Core engines (10) | nmap · nuclei · semgrep · trivy · gitleaks · osv-scanner · checkov · zap · syft · grype |
| AppSec / language (10) | bandit · pip-audit · npm-audit · cargo-audit · govulncheck · gosec · brakeman · eslint-security · bearer · trufflehog |
| Recon — dedicated (3) | subfinder · httpx · naabu |
| Recon — shared discovery (12) | amass · dnsx · katana · gau · waybackurls · hakrawler · webanalyze · whatweb · wafw00f · tlsx · shuffledns · assetfinder |
| Generic | SARIF (CodeQL + any SARIF-emitting tool) |

Plus ~65 more registered in the catalog (`/arsenal`) as `planned`, `reference`, `analyzer`, `importer`, or `blocked` — visible with truthful state, intentionally not runnable until their parsers land.

## Safety model

- **Scan modes**: `passive` (default — non-invasive), `active` (authorized scope + explicit confirmation), `lab` (intentionally vulnerable targets only).
- **Scope guard** runs before every scanner. Blocks: target out of scope, private IPs without `owned_internal=True`, active scans without explicit authorization, high-risk tools outside lab mode, blocked-capability tools (period).
- **Blocked capabilities** (refused outright, exposed at `/api/safety/blocked` and `/safety`): malware, persistence, credential theft, phishing, ransomware, botnets, destructive payloads, stealth, unauthorized exploitation, data exfiltration, DDoS.
- **Audit log**: every scope decision (allow or block) writes a row with timestamp + actor + reason + payload. Visible at `/audit`.
- **No fake scan claims**: `is_demo_data: true` flows from the storage layer to the UI banner. Real subprocess runs never produce the demo flag.

See [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) for the complete contract.

## Architecture

```text
frontend/  Next.js 15 (App Router) · React 19 · @xyflow/react · recharts
           Theme-aware design tokens, sidebar with section labels, command palette (/)

backend/   FastAPI · Pydantic 2 · Python 3.11+
           app/
             api/routes.py            HTTP surface
             models/schemas.py        Domain models (Pydantic)
             repositories/            In-memory Repository[T] (SQL impl pending)
             security/                ScopeGuard, BLOCKED_CAPABILITIES, private-network gate
             services/
               runner.py              Decision tree: demo / docker / local subprocess
               parsers/               Per-tool output normalizers
               evidence_store.py      sha256 content hashing
               fingerprint.py         Finding dedupe
               pentest_brain.py       Evidence-grounded reasoning
               job_queue.py           Inline-thread queue (RQ opt-in)
               job_runner.py          Single-scan + multi-stage pipeline callbacks
               pipelines.py           Preset pipeline registry
               reporting.py           Markdown + JSON report builder

evidence/  Raw scanner output, content-hashed, never overwritten
reports/   Generated reports
```

Documentation index:

- [Architecture](docs/ARCHITECTURE.md)
- [Safety model](docs/SAFETY_MODEL.md)
- [Tool registry](docs/TOOL_REGISTRY.md)
- [Arsenal](docs/ARSENAL.md)
- [Scanner runners](docs/SCANNER_RUNNERS.md) — three execution paths (demo / local / Docker)
- [Evidence vault](docs/EVIDENCE_VAULT.md)
- [PentestBrain](docs/PENTEST_BRAIN.md)
- [Reporting](docs/REPORTING.md)
- [Demo mode](docs/DEMO_MODE.md)
- [QA checklist](docs/QA_CHECKLIST.md)

## Roadmap

Active development. Next moves, in priority order:

1. **Custom Nuclei templates** — drag-drop upload, then "Run with these templates" on the scan form.
2. **More catalog tools wired** — Fuzzers (ffuf · gobuster · dirsearch) and the K8s/cloud cluster (kube-bench · prowler · kubescape).
3. **Persistence layer** — SQLAlchemy + Alembic + Postgres behind the `Repository[T]` interface. Repo abstraction is already in place; just need the SQL implementation.
4. **Authenticated scanning** — JWT/cookie injection for Nuclei + ZAP so they can scan behind a login.
5. **LLM-assisted triage in PentestBrain** — same citation guard preserved. Bring up the signal-to-noise ratio across hundreds of findings.
6. **Burp / mitmproxy traffic ingestion** — browse with the proxy, automatically build a target inventory.
7. **SARIF import/export everywhere** — CI integration becomes one HTTP POST.
8. **PDF report rendering**.
9. **CI workflow** (GitHub Actions) running pytest + lint + npm audit on PRs.
10. **Signed reports + Merkle-proof immutable evidence references**.

## Contributing

Tested with Python 3.11 / 3.13 and Node 20+. Tests are pytest (backend) and the standard Next.js stack (frontend).

```bash
# backend
cd backend && python -m pytest -q

# frontend
cd frontend && npm run lint && npm run build
```

PRs welcome — see [docs/ADDING_A_TOOL.md](docs/ADDING_A_TOOL.md) for the contract a new scanner needs to satisfy.

## Ethical use

Asura is for assets you own, lab environments, CTFs, training, bug-bounty engagements you are authorized to participate in, and defensive / blue-team work. Active scanning without authorization is illegal in most jurisdictions. Use this only against systems you have written permission to test.

## License

[MIT](LICENSE)
