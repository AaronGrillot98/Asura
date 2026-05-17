# QA Report

Date: 2026-05-17

## Scope

This QA pass covered the hardened safe MVP architecture:

- Core engine lock for Nmap, Nuclei, Semgrep, Trivy, Gitleaks, OSV-Scanner, Checkov, OWASP ZAP, Syft, and Grype.
- Registry contract enforcement for all Arsenal tools.
- AppSec and dependency runner registration for CodeQL, Bandit, pip-audit, npm audit, cargo-audit, govulncheck, gosec, Brakeman, ESLint security plugins, and Bearer.
- Recon runner registration for Subfinder, Amass, httpx, Naabu, dnsx, Katana, Gau, Waybackurls, Hakrawler, webanalyze, WhatWeb, wafw00f, tlsx, shuffledns, and Assetfinder.
- Project scope rules and ScopeGuard enforcement.
- Scanner adapter architecture.
- Structured JSON agent scaffolds.
- Seeded demo project with nine evidence-backed findings and two attack paths.
- Markdown and JSON report exports.
- Runner generation from the registry source of truth.
- Safety gates for modes, authorization, and target handling.
- Frontend build, lint, and dependency audit.
- Backend tests, import/compile checks, dependency consistency, and live endpoint smoke tests.

## Results

- Backend tests: `38 passed`
- Backend compile: `python -m compileall app` passed
- Python dependency check: `pip check` passed
- Frontend lint: `npm run lint` passed
- Frontend build: `npm run build` passed
- Frontend dependency audit: `npm audit` reported `0 vulnerabilities`
- API health: `/api/health` returned `ok`
- Registry contract: `/api/arsenal/contract` returned `valid: true`
- Dashboard smoke test: `http://127.0.0.1:3000` returned `200`

## Live Contract Snapshot

```json
{
  "valid": true,
  "errors": [],
  "contract_version": "2026-05-17.2",
  "tool_count": 47,
  "core_runner_count": 10,
  "optional_count": 33,
  "reference_count": 3,
  "executable_count": 43,
  "blocked_count": 1
}
```

## Security QA Checks

- Passive Nmap execution is blocked.
- Active/lab scans require explicit authorization.
- Targets starting with option prefixes are blocked.
- Targets containing control characters are blocked.
- Invalid Arsenal execution filters return `400`.
- Blocked tools cannot define modes, commands, or executables.
- Reference tools cannot define commands.
- Runner tools must define command templates for every declared mode.
- Non-safe active/lab tools must require authorized scope.
- Command templates can only use approved placeholders.
- Step 3 AppSec/dependency tools are passive, safe-default runner integrations and do not expand the default core engine.
- Step 4 passive recon tools do not require active scope; active recon tools require authorized scope and risk warnings.

## Production Readiness Notes

Strong enough now:

- Registry is enforced instead of advisory.
- Core runner definitions are generated from `tools.yaml`, preventing Arsenal/runner drift.
- The first 10 tools are locked by tests.
- The frontend has a CI-safe lint command.
- Dependency audit and backend dependency consistency are clean.

Remaining before real enterprise pentest use:

- Persist scanner runs, raw logs, evidence files, findings, and audit events in PostgreSQL.
- Move scanner execution into isolated worker containers with CPU, memory, timeout, and network controls.
- Add per-project scope objects with CIDR/domain/repo allowlists and deny rules.
- Implement parsers for all first 10 outputs and normalize to findings/evidence.
- Store scanner stdout/stderr as evidence artifacts, not only short status messages.
- Add authentication, authorization, workspace roles, and audit trails.
- Add rate limiting, scan concurrency limits, and cancellation.
- Add signed report exports and immutable evidence references.
- Add CI pipeline that runs tests, lint, build, audit, and contract validation on every pull request.
