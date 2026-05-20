<div align="center">

<img src="docs/asura-banner.svg" alt="Asura — self-hosted security command center" width="100%"/>

# Asura

**Self-hosted security command center for authorized testing.**
Orchestrates 57 real scanners. Preserves evidence. Correlates attack paths. Refuses to pretend a scan happened.

[![CI](https://github.com/AaronGrillot98/Asura/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronGrillot98/Asura/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active%20development-gold.svg)](#roadmap)
[![Backend tests](https://img.shields.io/badge/backend%20tests-274%20passing-brightgreen.svg)](backend/tests)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)
[![Tools](https://img.shields.io/badge/wired%20scanners-57%20of%2094-purple.svg)](#wired-scanners)
[![Persistence](https://img.shields.io/badge/persistence-SQLite%20%7C%20Postgres-gold.svg)](#persistence)

</div>

---

> **Stop running ten security tools and reading ten JSON files.**
> Asura runs the scanners, preserves the raw output with a content hash, deduplicates findings across tools, correlates them into attack-path hypotheses, and produces a **signed PDF report** with a Merkle-rooted evidence trail you can hand to a stakeholder.

**CI integration is one HTTP POST in either direction:** ingest SARIF from CodeQL/Semgrep/Snyk/Trivy/Bandit, or stream ASURA's findings back to GitHub Code Scanning. Multi-user workspaces, JWT sessions, and long-lived service tokens for CI all ship today — see [docs/AUTH.md](docs/AUTH.md) and [docs/SARIF.md](docs/SARIF.md).

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
                 │       Repositories (in-memory · SQLite · Postgres)    │
                 │              ▼                                        │
                 │       PentestBrain  ─▶  ranks · dedupes · correlates  │
                 │              ▼                                        │
                 │       Reports (Markdown + JSON, scope + safety stmt)  │
                 │                                                       │
                 └───────────────────────────────────────────────────────┘
```

## What it does

- **Runs real scanners** — 57 are wired end-to-end today across core engines, AppSec language packs, recon, fuzzers, K8s/cloud, IaC, API testing, secret scanning, XSS validation, YARA detection, and SARIF importers. The other ~37 are registered in the catalog with truthful state (`planned` / `reference` / `analyzer` / `importer` / `blocked`).
- **Zero local install needed** — most wired tools ship with canonical Docker images. If a binary isn't on PATH, Asura runs `docker run --rm <image>` automatically. Set `ASURA_PREFER_DOCKER=1` to always prefer the container path.
- **Background jobs + pipelines** — `POST /api/scans/async` returns immediately with a job id; poll `/api/jobs/{id}` for progress. Three preset pipelines (`passive-recon`, `code-audit`, `container-audit`) chain multiple scanners with optional asset-passing between stages.
- **Evidence-first** — every finding carries at least one `Evidence` record with a sha256 content hash and the exact argv used. Raw payloads land at `evidence/<workspace>/<project>/<scan_id>/<tool>.json` and are never overwritten.
- **Scope-gated** — the safety guard rejects scans against private IPs without `owned_internal=True`, requires explicit authorization for active/lab modes, blocks high-risk tools outside lab mode, and writes one `AuditLog` row per decision (allow or block).
- **Deterministic reasoning** — `PentestBrain` ranks, deduplicates by fingerprint, correlates findings into attack-path hypotheses, and generates remediation plans. **Every claim cites the evidence IDs that produced it** — no hallucinated vulns.
- **Optional LLM-assisted triage** — configure an Anthropic API key on `/settings/llm` (Fernet-encrypted at rest, never returned by the API) or set `ASURA_LLM_TRIAGE=1` + `ANTHROPIC_API_KEY` for headless deployments. Routes the ranked finding list through Claude for clustering and false-positive scoring. The citation guard discards any LLM output that references evidence ids the brain never handed it, so hallucinated findings can't leak into the response. The deterministic baseline still ships as the default.
- **Proxy traffic ingestion** — upload a HAR capture from Burp / mitmproxy / Caido / DevTools. Asura deduplicates hosts, builds an endpoint catalog with method + path + params + status codes, surfaces auth-protected paths (401/403), and creates one Target per unique host so the new endpoints are immediately scannable.
- **Persistence built-in** — flip `ASURA_USE_SQL=1` for SQLite or Postgres. Projects, scans, findings, evidence, runs, audit logs, jobs, and remediations survive restarts behind the same Repository interface tests already use.
- **Authenticated scanning** — Fernet-encrypted auth profiles (bearer / basic / header / cookie) are injected into Nuclei + HTTPx + ZAP at runtime; for ZAP, Asura generates a per-scan `--hook` script that wires Replacer rules at daemon-startup and wipes itself after the scan. Custom Nuclei templates uploaded through the UI are content-hashed and stored on disk.
- **Multi-user access control** — built-in user accounts, workspaces, role-scoped membership (owner / admin / member / viewer), Ed25519-prefixed JWT sessions, and long-lived `asura_st_*` service tokens for CI. PBKDF2-HMAC-SHA256 password hashing (600k iters), no external auth dependency. SSO/OIDC stub ready to wire to your IdP. Auth is opt-in via `ASURA_AUTH_DISABLED=0` — the seeded demo flow works without login by default. See [docs/AUTH.md](docs/AUTH.md).
- **SARIF 2.1.0 round-trip** — `GET /api/projects/<id>/findings.sarif` exports your findings as a SARIF document with one run per scanner driver; `POST /api/projects/<id>/imports/sarif` ingests SARIF from any tool (CodeQL, Semgrep, Snyk, Trivy, Bandit, gitleaks…). Round-trip metadata under `properties.asura.*` + `fingerprints.asura/v1` so re-imports dedupe instead of cloning. **CI integration = one curl.** See [docs/SARIF.md](docs/SARIF.md).
- **Signed reports + Merkle-rooted evidence** — Every report is exportable as a **signed PDF** (Ed25519 footer printed on the page) or **signed JSON envelope** with per-evidence Merkle inclusion proofs. The public key is published at `/api/reports/signing-key`; a stateless verifier at `/api/reports/verify-evidence` checks any single evidence record against the signed root without trusting the rest of the report. See [docs/REPORTS.md](docs/REPORTS.md).
- **Reports you can hand to a stakeholder** — Markdown + JSON + signed PDF + signed JSON, all with engagement summary, scope statement, authorization statement, methodology, tools used, executive summary, risk overview, attack paths, findings by severity, evidence references, remediation roadmap, and a safety statement.

## What it is *not*

Asura is not an unauthorized hacking tool, malware framework, phishing kit, credential stealer, ransomware builder, or fake AI scanner. The blocked-capability list is enforced in code and exposed at `GET /api/safety/blocked`. The default scanner mode is passive; active and lab modes require explicit per-scan authorization.

## Use cases

| You want to… | Asura does it via |
|--------------|-------------------|
| Audit your own repo for code issues, leaked secrets, vulnerable deps, and IaC misconfigs in one pass | The `code-audit` pipeline: Semgrep + Gitleaks + OSV-Scanner running in parallel against the repo, results normalized into one Findings view. |
| Scan a container image without manually running 4 different tools | The `container-audit` pipeline: Syft (SBOM) → Grype (vulns) + Trivy (vulns + misconfig + secrets). |
| Do passive recon on an authorized scope | The `passive-recon` pipeline: Subfinder → HTTPx (probes each discovered subdomain). Asset chaining is automatic. |
| Run a long scan without blocking your browser tab | "Run in background" on the Run-scan form (or `POST /api/scans/async`). Tracks progress at `/jobs/{id}`. |
| Use Asura on a fresh machine without installing 50+ binaries | Install Docker. Asura's runner auto-falls-back to the registered image for every wired scanner. |
| Scan past a login / behind a bearer token | Save an auth profile under `/auth-profiles`; pick it from the Run-scan form. Credentials never leave disk in plaintext. |
| Hand a customer a deliverable | `GET /api/reports/<id>/pdf` returns a signed PDF; `/markdown` and `/json` are still there. Each version carries the engagement summary, scope + authorization + safety statement, and 14 sections of content. |
| Prove every claim about a finding is grounded in real data | Every `Finding.evidence[i]` carries a sha256 `content_hash`; every report ships an Ed25519 signature over the canonical sections + Merkle-rooted audit path per evidence record. Pull `/api/reports/signing-key` once, verify forever. |
| Pipe scanner output into a single dashboard from CI | Mint a service token (`POST /api/auth/tokens`), then `curl -X POST $ASURA/api/projects/$PROJECT/imports/sarif --data-binary @semgrep.sarif`. One POST, dedup-aware. |
| Share a workspace with teammates without standing up Auth0 | First user signs up at `/signup` and becomes owner; invite others by email under workspace settings. Roles: owner / admin / member / viewer. JWT in a SameSite=Lax cookie, 12h default TTL. |

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
# (most of the wired 44 have canonical images registered)
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

19 routes ship today, all behind the same dark purple/gold theme:

| Route | What you see |
|-------|--------------|
| `/` | Command Center: hero metrics, risk trend chart, coverage-by-domain grid, most-dangerous attack path, "fix these first", scanner health, brain reasoning, top findings, quick links. |
| `/projects` · `/projects/{id}` · `/projects/new` | Workspace projects with status dots; wizard for scope rules + grantor; per-project dashboard with inline targets editor + Run scan + Delete. |
| `/scans` · `/scans/{id}` | Scanner run history with status, args, exit code, evidence link, scope decision. |
| `/jobs` · `/jobs/{id}` | Background job queue with status, progress %, runs produced, findings created. |
| `/pipelines` | Preset chains with "Run pipeline" forms inline. |
| `/findings` · `/findings/{id}` | Filterable table; Evidence Drawer with raw JSON, content hash, command metadata. |
| `/attack-paths` · `/attack-paths/{id}` | xyflow graph of nodes/edges + remediation roadmap. |
| `/arsenal` | Catalog of 94 registered tools with status dots, install badges, lab-only markers. |
| `/templates` | Custom Nuclei template upload + content-hashed registry. |
| `/auth-profiles` | Fernet-encrypted credentials for authenticated scanning (bearer / basic / header / cookie). |
| `/audit` | Every scope decision (allow / block) with timestamp + reason. |
| `/safety` | The blocked-capability list — pulled live from `/api/safety/blocked`. |
| `/reports` | Markdown · signed PDF · signed JSON · SARIF — download from the dashboard topbar. |
| `/login` · `/signup` | Local password auth + (stubbed) SSO link. Hidden unless `ASURA_AUTH_DISABLED=0`. |

Press **`/`** anywhere to open the global search palette (also `Ctrl/Cmd+K`). Search across projects, findings, tools, scanner runs, and attack paths.

## Wired scanners

| Pack | Tools |
|------|-------|
| Core engines (10) | nmap · nuclei · semgrep · trivy · gitleaks · osv-scanner · checkov · zap · syft · grype |
| AppSec / language (10) | bandit · pip-audit · npm-audit · cargo-audit · govulncheck · gosec · brakeman · eslint-security · bearer · trufflehog |
| Recon — dedicated (3) | subfinder · httpx · naabu |
| Recon — shared discovery (12) | amass · dnsx · katana · gau · waybackurls · hakrawler · webanalyze · whatweb · wafw00f · tlsx · shuffledns · assetfinder |
| Web fuzzers + DAST (7) | ffuf · gobuster · dirsearch · sqlmap · feroxbuster · nikto · wapiti |
| Web XSS validation (1) | dalfox |
| Dependency / SCA (1) | retirejs |
| API testing (2) | schemathesis · jwt-tool |
| K8s / cloud (5) | kube-bench · kube-score · kubescape · prowler · polaris |
| Container benchmark (1) | docker-bench-security |
| IaC (2) | kics · terrascan |
| Secrets (extra) (1) | detect-secrets |
| Detection engineering (1) | yara |
| Importers (1) | SARIF (CodeQL + any SARIF-emitting tool) |

**57 wired, 94 in the catalog.** The remaining ~37 are visible under `/arsenal` with truthful state (`planned` / `reference` / `analyzer` / `importer` / `blocked`) — intentionally not runnable until their parsers land.

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
           Purple/black/gold theme, sidebar with section labels, command palette (/)

backend/   FastAPI · Pydantic 2 · SQLAlchemy 2 · Python 3.11+
           app/
             api/routes.py            HTTP surface (projects, scans, findings, reports, SARIF, …)
             api/auth_routes.py       Login, register, /me, service tokens, workspace members, SSO stub
             models/schemas.py        Domain models (Pydantic) — User, Membership, Workspace, ApiToken, …
             db/                      SQLAlchemy engine, ORM rows, init_db()
             repositories/            Repository[T] — in-memory + SQL impls (users + memberships in-memory)
             security/
               auth.py                PBKDF2 password hash, Ed25519-prefixed HS256 JWT, bearer middleware
               scope_guard.py         BLOCKED_CAPABILITIES + private-network gate
             services/
               runner.py              Decision tree: demo / docker / local subprocess
               parsers/               Per-tool output normalizers
               evidence_store.py      sha256 content hashing
               fingerprint.py         Finding dedupe
               pentest_brain.py       Evidence-grounded reasoning
               job_queue.py           Inline-thread queue (RQ opt-in)
               job_runner.py          Single-scan + multi-stage pipeline callbacks
               pipelines.py           Preset pipeline registry
               templates_service.py   Custom Nuclei template registry
               auth_profile_service.py Fernet-encrypted credential store
               reporting.py           Markdown + JSON + PDF report builder
               sarif.py               SARIF 2.1.0 export + import (round-trip aware)
               merkle.py              RFC-6962-style Merkle tree + inclusion proofs
               signing.py             Ed25519 keypair, persisted, sign/verify report bundles

evidence/  Raw scanner output, content-hashed, never overwritten
templates/ Custom Nuclei templates with sha256 verification
auth/      Fernet-encrypted auth profiles (never logged in cleartext)
reports/   Generated reports
```

Documentation index:

- [Architecture](docs/ARCHITECTURE.md)
- [Safety model](docs/SAFETY_MODEL.md)
- [Auth + multi-user workspaces](docs/AUTH.md) — JWT, service tokens, OIDC stub
- [SARIF round-trip](docs/SARIF.md) — one-POST CI integration
- [Reports — PDF, signed bundles, Merkle proofs](docs/REPORTS.md)
- [Tool registry](docs/TOOL_REGISTRY.md)
- [Arsenal](docs/ARSENAL.md)
- [Scanner runners](docs/SCANNER_RUNNERS.md) — three execution paths (demo / local / Docker)
- [Evidence vault](docs/EVIDENCE_VAULT.md)
- [PentestBrain](docs/PENTEST_BRAIN.md)
- [Reporting](docs/REPORTING.md)
- [Demo mode](docs/DEMO_MODE.md)
- [QA checklist](docs/QA_CHECKLIST.md)

## Persistence

By default Asura uses an in-memory store seeded from `demo_store` on each
restart. To persist projects, scans, findings, evidence, and audit logs
across restarts:

```bash
# SQLite (zero-config, file at ./asura.db)
export ASURA_USE_SQL=1

# Or Postgres (real production)
export ASURA_USE_SQL=1
export DATABASE_URL=postgresql+psycopg://asura:asura@db:5432/asura
```

Tables are created automatically on first boot. The seed only runs when
the demo project is missing, so restarts are idempotent. Templates and
auth profiles keep their own encrypted file-system storage independent of
this toggle (see `templates/` and `auth/`).

The schema uses an indexed-column + JSON-payload pattern so new
optional Pydantic fields don't need a migration — they live inside the
JSON column. When you start indexing on a new field, Alembic takes
over: set `ASURA_USE_ALEMBIC=1` to make `init_db()` run
`alembic upgrade head` instead of `create_all`, or run the CLI:

```bash
cd backend
py scripts/migrate.py upgrade       # upgrade to head
py scripts/migrate.py current       # show recorded revision
py scripts/migrate.py history       # show full revision history
```

See [docs/MIGRATIONS.md](docs/MIGRATIONS.md) for revision authoring and
the create_all-vs-Alembic parity contract.

## What shipped recently

| Slice | Highlight |
|-------|-----------|
| 19 | HAR ingestion + GitHub Actions CI |
| 20 | Dashboard refresh — token discipline, a11y, Dashy-inspired card system + neon theme |
| 21 | **SARIF 2.1.0 import + export** — one-POST CI integration ([docs](docs/SARIF.md)) |
| 22 | **Multi-user workspaces + JWT auth + service tokens** — Asura's own access control ([docs](docs/AUTH.md)) |
| 23 | **Signed PDF reports + Merkle-rooted evidence proofs** ([docs](docs/REPORTS.md)) |
| 24 | **+5 wired scanners** — dalfox (XSS), detect-secrets, kics + terrascan (IaC), yara (detection). 57 of 94 now runner-ready. |

## Roadmap

Active development. Next moves, in priority order:

1. **OIDC implementation** — fill in the PKCE flow behind the existing `/api/auth/sso/oidc/*` stubs (issuer discovery, callback, ID-token validation).
2. **Merkle transparency log** — append-only log of report roots so consumers can detect retroactive edits across reports.
3. **Workspace-scoped data filtering** — once `ASURA_AUTH_DISABLED=0` is the production norm, gate every project/finding listing by the caller's workspace memberships.
4. **More scanner packs** — fill in the ~42 `planned` rows in the catalog, prioritized by user demand.

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
