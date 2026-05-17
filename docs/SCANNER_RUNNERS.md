# Scanner runners

Asura's runner is **real by default**: when a scan is submitted from the
Command Center or `POST /api/scans`, the registered tool is executed and
its output is parsed, evidence-stamped, and persisted to the repository.

## Wired runners (26)

| Pack | Tools |
|------|-------|
| Core engines (10) | nmap · nuclei · semgrep · trivy · gitleaks · osv-scanner · checkov · zap · syft · grype |
| AppSec / language (9) | bandit (Python) · pip-audit · npm-audit · cargo-audit · govulncheck (Go) · gosec · brakeman (Rails) · eslint-security · bearer |
| Secrets (1) | trufflehog |
| Recon — dedicated (3) | subfinder · httpx · naabu |
| Recon — shared discovery (12) | amass · dnsx · katana · gau · waybackurls · hakrawler · webanalyze · whatweb · wafw00f · tlsx · shuffledns · assetfinder |
| Generic | SARIF (CodeQL + any SARIF-emitting tool) |

The 12 shared-discovery tools use a common parser (`discovery.py`) that
emits one info-level "discovered host" finding per record. Per-tool
parsers will replace this when richer normalization is warranted (TLS
metadata for tlsx, technology fingerprints for whatweb / webanalyze).


## Execution paths

`run_scanner` picks one of these paths per scan, in order:

1. **Demo** — `ASURA_DEMO_MODE=1` returns seeded output, no subprocess
   spawned. `ScannerRun.is_demo_data = true`.
2. **Docker (preferred)** — `ASURA_PREFER_DOCKER=1` AND the tool has a
   `docker_image` AND `docker` is on PATH. Runs in a container even when
   the local binary exists.
3. **Local binary** — the tool's `executable` is on PATH. Runs as a
   normal subprocess.
4. **Docker (fallback)** — local binary missing, but the tool has a
   `docker_image` AND `docker` is on PATH. Runs in a container
   automatically.
5. **Failed with hint** — neither runtime is available. Returns
   `status=failed` with the registry's `install_hint`, the Docker image
   that would be used, and a pointer to `ASURA_DEMO_MODE=1`.

The chosen path is recorded in `ScannerRun.message` (e.g. *"semgrep
completed (0); 12 finding(s) parsed (via Docker image
semgrep/semgrep:latest)."*) and the `args` field captures the exact
argv used.

## The end-to-end loop

For each scanner in the request, `app.services.runner.run_scanner`:

1. Validates the target (no control characters, no option-prefix
   injection, length capped).
2. Runs the scope guard for the project + mode (passive / active / lab).
3. Picks an execution path (see above).
4. Builds an argv-only command from the registry's template, never a
   shell string.
5. Executes via `subprocess.run(args, capture_output=True, timeout=900)`.
6. Decodes stdout (JSON first, falls back to raw text) and writes the raw
   payload to `evidence/<workspace>/<project>/<scan_id>/<tool>.json` with
   a sha256 `content_hash` (never overwrites — collision suffix `-N`).
7. Looks up the tool's registered `parser` (e.g. `semgrep_json`) and
   invokes it. The parser returns `list[Finding]` with inline `Evidence`.
8. Fingerprints each finding, deduplicates against existing findings in
   the project, and persists new ones to `repos.findings` /
   `repos.evidence`. Recurrences just bump `last_seen`.
9. Returns the `ScannerRun` with `evidence_ids`, `findings_created`,
   `args`, `exit_code`, and a one-line message.

## Docker execution

When a tool runs via Docker:

- The runner spawns `docker run --rm -i [mounts] <docker_image> <args>`.
- For tools whose `target_kind` is `filesystem` or `mixed` (semgrep,
  gitleaks, trivy fs, syft, grype, checkov, bearer, trufflehog), the
  target's directory is **bind-mounted read-only at `/scan`** and the
  command's target argument is rewritten to that mount point.
- For tools whose `target_kind` is `url` / `host`, no mount is added.
- The container's stdout is captured the same way as a local subprocess
  and fed through the same parser pipeline.
- No `--privileged`, no host socket mount, no extra capabilities.
  Network access uses Docker's default bridge driver.

To override an image, edit the tool's `docker_image` field in
`backend/registry/tools.yaml` (e.g. pin a specific tag). The 20 tools
that ship with images today are listed below.

## Wired tools with Docker images

| Tool | Image | Target kind |
|------|-------|-------------|
| nmap | `instrumentisto/nmap:latest` | host |
| nuclei | `projectdiscovery/nuclei:latest` | url |
| semgrep | `semgrep/semgrep:latest` | filesystem |
| trivy | `aquasec/trivy:latest` | mixed |
| gitleaks | `zricethezav/gitleaks:latest` | filesystem |
| osv-scanner | `ghcr.io/google/osv-scanner:latest` | filesystem |
| checkov | `bridgecrew/checkov:latest` | filesystem |
| zap | `softwaresecurityproject/zap-stable:latest` | url |
| syft | `anchore/syft:latest` | mixed |
| grype | `anchore/grype:latest` | mixed |
| bearer | `bearer/bearer:latest` | filesystem |
| trufflehog | `trufflesecurity/trufflehog:latest` | filesystem |
| subfinder | `projectdiscovery/subfinder:latest` | host |
| httpx | `projectdiscovery/httpx:latest` | url |
| naabu | `projectdiscovery/naabu:latest` | host |
| amass | `caffix/amass:latest` | host |
| dnsx | `projectdiscovery/dnsx:latest` | host |
| katana | `projectdiscovery/katana:latest` | url |
| tlsx | `projectdiscovery/tlsx:latest` | host |
| shuffledns | `projectdiscovery/shuffledns:latest` | host |

Language-specific tools (bandit, pip-audit, npm-audit, cargo-audit,
govulncheck, gosec, brakeman, eslint-security) don't ship Docker images
because users running them typically already have the language toolchain
installed. Their install hints point at `pipx`, `cargo`, `go install`, etc.

## Demo mode

Setting `ASURA_DEMO_MODE=1` makes every subsequent scan return seeded
output (`is_demo_data: true`, no subprocess spawned). The seeded Acme
FlightOps project remains in the repositories regardless of the env var
so the dashboard is never empty.

## Adding a new runner

1. Register the tool in `backend/registry/tools.yaml` with valid
   `executable`, `commands` (one per declared mode), `parser`,
   `input_types`, `output_formats`, `supported_os`, and a `risk_level`.
2. Implement a parser at `backend/app/services/parsers/<tool>.py`:

   ```python
   def parse(raw, *, project_id="demo", scan_id=None, asset_id="...",
             is_demo_data=False) -> list[Finding]:
       ...
   ```

3. Add the parser to `app/services/parsers/__init__.py::PARSERS`.
4. The runner picks it up automatically. Add it to `CORE_SCANNER_IDS`
   in `scanner_registry.py` only if it's a first-class engine.

## Scope guard decisions

`decide_scope()` returns a structured `ScopeDecision`. Reasons surfaced
to the API:

| Reason code | Meaning |
|-------------|---------|
| `passive_in_scope` / `active_in_scope` / `lab_in_scope` | Allowed |
| `passive_target_out_of_scope` | Target not listed in project scope |
| `active_disabled_for_project` | `allow_active=false` on the project |
| `active_requires_authorization` | `explicit_authorization=false` |
| `active_target_out_of_scope` | Target not in scope |
| `private_ip_not_marked_internal` | Active scan against private/loopback IP without `target.owned_internal=true` |
| `high_risk_requires_lab_mode` | Tool `risk_level` high/restricted outside the auth-active allowlist |
| `high_noise_confirmation_required` | Caller must set `confirm_high_noise=true` |
| `lab_disabled_for_project` / `lab_requires_authorization` / `target_lab_mode_disabled` | Lab-mode preconditions failed |

Every decision (allow or block) writes one `AuditLog` row visible at
`GET /api/audit` and on the `/audit` page in the UI.

## Failure modes

- **Binary missing** → `status: failed`, message includes the binary
  name, the registry install hint, and a pointer to `ASURA_DEMO_MODE=1`.
  No demo fallback by accident.
- **Timeout** (>900s) → `status: failed` with timeout message.
- **Parser raised** → `status: failed` with parser exception name +
  message. No partial findings persisted.
- **Empty output with non-zero exit code** → `status: failed`,
  message captures the last 1000 chars of stderr.
