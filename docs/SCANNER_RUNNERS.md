# Scanner runners

Asura ships two runner implementations, selected by environment variable.

## `DemoRunner` (default)

Runs whenever `ASURA_ENABLE_REAL_SCANNERS` is unset, `0`, or `false`. Produces
a deterministic completed `ScannerRun` with:

- `is_demo_data: true`
- `args: []`
- `exit_code: 0`
- `message: "DEMO MODE — ..."`

DemoRunner never spawns a subprocess. It lets the dashboard, reporting, and
evidence flows work end-to-end on a fresh install with zero scanners.

## `SubprocessRunner` (opt-in)

Activated by `ASURA_ENABLE_REAL_SCANNERS=1`. Calls the tool whose
`executable` is in PATH, using the registered command template from
`registry/tools.yaml`. Target validation runs first — control characters,
option-prefix targets (`-rf …`), and oversize inputs are rejected before any
process is launched. Output is captured and the final 1000 characters are
stored on the `ScannerRun.message` field; `args` and `exit_code` are recorded
for the audit log.

## Adding a new runner

1. Register the tool in `backend/registry/tools.yaml` with valid
   `executable`, `commands`, `parser`, and modes.
2. Add a parser under `backend/app/services/parsers/` that normalizes the
   tool's raw output into `Finding` objects.
3. Add the parser to `app/services/parsers/__init__.py::PARSERS`.
4. Update `CORE_SCANNER_IDS` in `scanner_registry.py` only if the new tool is
   a first-class core engine — otherwise the runner picks it up automatically.

## Common scope guard reasons returned to callers

| Reason code | Meaning |
|-------------|---------|
| `passive_in_scope` | Allowed |
| `passive_target_out_of_scope` | Target not listed in project scope |
| `active_disabled_for_project` | `allow_active=false` on the project |
| `active_requires_authorization` | `explicit_authorization=false` |
| `active_target_out_of_scope` | Target not in scope |
| `private_ip_not_marked_internal` | Active scan against private/loopback IP without `target.owned_internal=true` |
| `high_risk_requires_lab_mode` | Tool risk_level high/restricted outside the auth-active allowlist |
| `high_noise_confirmation_required` | Caller must set `confirm_high_noise=true` |
| `lab_disabled_for_project` / `lab_requires_authorization` / `target_lab_mode_disabled` | Lab-mode preconditions failed |
