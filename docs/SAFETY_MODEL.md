# Safety model

Asura is for authorized security testing only. The safety contract below is
enforced in code; the API exposes it at `GET /api/safety/blocked` so the
docs, UI, and audit log all read from one source.

## Scan modes

| Mode | Use cases | Required preconditions |
|------|-----------|------------------------|
| `PASSIVE_MODE` | Repo, dependency, SBOM, secret, static analysis, header checks, non-invasive recon | Target must be in the project scope rules or `project.targets`. |
| `AUTHORIZED_ACTIVE_MODE` | Active web scanning, port scanning, crawling, bounded fuzzing, authenticated API tests against explicitly scoped targets | `allow_active=true`, `explicit_authorization=true`, target in scope, and (for private IPs) `target.owned_internal=true`. |
| `LAB_VALIDATION_MODE` | Intentionally vulnerable apps, CTF boxes, training labs, explicit lab targets | `allow_lab=true`, `explicit_authorization=true`, target in scope, `target.lab_mode_enabled=true`. |

## Scope guard rules

The guard runs before every scanner invocation and emits a structured
`ScopeDecision`:

```json
{
  "allowed": true,
  "reason": null,
  "reason_code": "active_in_scope",
  "audit_log_id": "audit-…",
  "requires_explicit_high_noise_confirm": false
}
```

Common block reasons:

- `passive_target_out_of_scope`
- `active_disabled_for_project`
- `active_requires_authorization`
- `active_target_out_of_scope`
- `private_ip_not_marked_internal`
- `high_risk_requires_lab_mode`
- `high_noise_confirmation_required`
- `lab_disabled_for_project`
- `lab_requires_authorization`
- `target_lab_mode_disabled`

Every decision (allow or block) writes one `AuditLog` row visible at
`GET /api/audit` and the `/audit` page in the UI.

## High-risk tool gate

Tools with `risk_level ∈ {high, restricted}` require `LAB_VALIDATION_MODE`
unless they're on the small allowlist for authorized-active use: `nuclei`,
`zap`, `ffuf`, `feroxbuster`, `nikto`. Even those still need explicit
authorization and a scope match.

## High-noise confirmation

Active scans with `ffuf`, `feroxbuster`, `gobuster`, `nikto`, `kiterunner`,
`naabu`, or `amass` flip `requires_explicit_high_noise_confirm: true`. The
operator must pass `confirm_high_noise=true` in `POST /api/scans` for the
scan to proceed.

## Blocked capabilities (refused outright)

Exposed at `GET /api/safety/blocked` and on the `/safety` page:

- malware
- persistence
- credential theft
- phishing
- ransomware
- botnet
- destructive payload
- stealth / detection evasion
- unauthorized exploitation
- data exfiltration
- DDoS

Asura will not ship these capabilities even with explicit authorization.
The blocked-tool execution class in `tools.yaml` is validated by the
contract: blocked tools cannot declare commands, modes, or an executable.

## Findings + evidence

- Every finding must carry at least one `Evidence` record.
- Evidence persisted to disk gets a sha256 `content_hash` and a never-overwrite
  rule (see [EVIDENCE_VAULT.md](EVIDENCE_VAULT.md)).
- PentestBrain claims must cite the evidence IDs they were derived from. The
  test suite fails the build if a non-empty claim has zero citations.

## Demo data labelling

Asura "does not pretend a scan happened." The demo project's findings carry
`is_demo_data: true`, which flows into attack paths, scanner runs, reports,
and the dashboard banner. There is no code path that strips this flag.
