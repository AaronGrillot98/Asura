# Tool registry

Tool metadata lives in `backend/registry/tools.yaml` and is validated at load
time by `app.services.tool_registry.validate_contract`. The contract report
is exposed at `GET /api/arsenal/contract`.

## Required fields

```yaml
- id: nuclei                    # lowercase, no spaces
  name: Nuclei                  # display name
  pack: Web App Security Pack   # grouping for the Arsenal UI
  category: web scanning
  execution: core_runner        # see below
  modes: [passive, active, lab] # subset; reference tools may omit
  install_status: not_installed # bundled | available | not_installed | external | blocked
  integration_status: runner    # runner | parser | planned | reference | importer | analyzer | blocked
  license: MIT
  official_url: https://github.com/projectdiscovery/nuclei
  executable: nuclei            # null for non-executable entries
  input_types: [url, host]
  output_formats: [jsonl, sarif]
  parser: nuclei_json
  safe_default: true
  requires_authorized_scope: true
  requires_lab_mode: false       # optional; default false
  docker_available: true
  supported_os: [linux, macos, windows]
  commands:
    - mode: passive
      command: "nuclei -u {{target}} -severity info,low,medium -jsonl"
  recommended_use: "..."
  risk_warning: "..."            # nullable
  risk_level: medium             # low | medium | high | restricted | blocked
  tags: [web, vulnscan]          # optional
```

## Execution classes

- **`core_runner`** — first-class engine. The first 10 are locked: Nmap,
  Nuclei, Semgrep, Trivy, Gitleaks, OSV-Scanner, Checkov, ZAP, Syft, Grype.
- **`optional_pack`** — registered, optionally with a runner. Use
  `integration_status: planned` to register the tool without making it
  runnable.
- **`reference`** — linked for documentation only. Cannot define commands.
- **`importer`** — pulls external data (Postman / OpenAPI). Cannot run.
- **`analyzer`** — operates on existing artifacts (baselines, rule files).
  Cannot run.
- **`blocked`** — refused capability. Must not define commands, modes, or
  executable. Asura's safety contract surfaces these in the Arsenal UI.

## Catalog growth

Today the registry ships **94 entries** — the 90 product-spec tools plus
four legacy/policy entries (`cyberchef`, `shodan`, `sqlmap`,
`rat-builders`). New additions for the 90-spec list are catalog-only:
`integration_status: planned`, empty `commands`, and the appropriate
`risk_level`. Wiring runners + parsers for the remaining 80 tools is
roadmap-tracked.

## Allowed command placeholders

Command templates may only use the following placeholders, enforced by the
contract:

`target`, `wordlist`, `database`, `provider`, `rules`, `model_type`,
`resolver_list`.

Anything else fails the contract. Static commands (no placeholders) on
executable tools also fail.

## Disallowed launchers

Command templates that start with `sudo `, `rm `, `del `, `powershell `, or
`cmd ` fail the contract. The validator is intentionally narrow — wrap any
sudo-requiring tool in a documented privileged install path instead.
