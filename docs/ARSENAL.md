# Arsenal

The Arsenal is a registry-driven catalog of every tool Asura knows about.
It currently lists 94 entries (the 90 from the product spec plus four
legacy/policy entries kept for context).

## Tool states

- **core_runner** — first-class scanner with a runner + parser
  implementation in Asura. (10 tools: nmap, nuclei, semgrep, trivy,
  gitleaks, osv-scanner, checkov, zap, syft, grype.)
- **optional_pack** — registered in the catalog. May or may not have a live
  runner yet; check `integration_status`.
- **reference** — linked for documentation and workflow guidance. Asura
  never executes reference tools.
- **importer** — pulls external data into Asura's internal model (e.g.
  Postman / OpenAPI). No execution.
- **analyzer** — operates on existing artifacts (e.g. baselines, rule
  files) without spawning a process.
- **blocked** — Asura refuses to ship this capability. No commands, no
  modes, no executable.

## `integration_status`

- `runner` — connected end-to-end.
- `parser` — parser ready, runner pending.
- `planned` — registered in the catalog but not runnable.
- `reference` / `importer` / `analyzer` — see above.
- `blocked` — see above.

The UI shows a green "Runnable" badge only when `integration_status ==
"runner"` and `execution != "blocked"`. Everything else displays
"Catalog-only" with a tooltip.

## `risk_level` and `requires_lab_mode`

- `risk_level ∈ {low, medium, high, restricted, blocked}`.
- `requires_lab_mode=true` is set for the DFIR / memory forensics
  cluster (chainsaw, hayabusa, velociraptor, volatility3, plaso,
  timesketch). These cannot run outside `LAB_VALIDATION_MODE`.

The scope guard enforces these constraints before any runner is invoked.

## Tags + filters

Tools carry an optional `tags: list[str]` so the UI can offer fast filters:
`#web`, `#cloud`, `#dfir`, `#kubernetes`, `#secrets`, etc. The
`GET /api/arsenal` endpoint accepts `search`, `pack`, `execution`, `risk`,
`tag`, `lab_only`, and `installed` filters.

## Blocked-capabilities list

`GET /api/safety/blocked` exposes the canonical list of capabilities Asura
refuses to ship (malware, persistence, credential theft, phishing,
ransomware, botnet, destructive payload, stealth, unauthorized
exploitation, data exfiltration, DDoS). The Arsenal UI links to that page.
