# Demo mode

Asura runs **real scans by default**. The demo content exists for two
narrow reasons:

1. **Out-of-the-box dashboard**: the seeded Acme FlightOps project means
   the Command Center isn't empty before you've installed any scanners.
   You can click through every page and see what a populated workspace
   looks like.
2. **Air-gapped review / screenshots**: set `ASURA_DEMO_MODE=1` in the
   backend environment and every scan you submit returns clearly-labelled
   seeded output instead of spawning a subprocess.

## What seeded content includes

- One project: **Acme FlightOps Demo** (`id = demo`, `is_demo_data: true`).
- Ten findings spanning secrets, code, web, container, IaC, network, API.
- Three correlated attack-path hypotheses with evidence citations.
- Eight scanner runs, every one stamped `is_demo_data: true`.
- Two `AgentOutput` summaries from PentestBrain.

## How "demo vs real" is tracked

`is_demo_data: bool` lives at the storage layer on every entity that can
hold scan output: `Project`, `Finding`, `Evidence`, `ScannerRun`,
`AttackPath`, `Report`. The flag flows into the dashboard banner, the
report header, and the Findings page filter (`demo=true/false`).

The flag is **only set when seeded data is added or when a scan runs with
`ASURA_DEMO_MODE=1`**. Real subprocess runs never produce `is_demo_data:
true` records — there is no code path that strips or fakes the flag.

## The `ASURA_DEMO_MODE` env var

| Value | Behaviour |
|-------|-----------|
| unset / `0` / `false` | Real subprocess execution (default). |
| `1` / `true` / `yes` / `on` | Every `run_scanner` call returns a seeded `ScannerRun` with `is_demo_data: true`. No subprocess spawned. |

The seeded Acme FlightOps project stays in the repositories regardless of
the env var, so the dashboard is never blank. Toggling the var only
affects new scan submissions.

## Removing the seed for production use

To start clean (no demo project), comment out the `seed_repos(_REPOS)`
call in `backend/app/repositories/__init__.py::get_repos`. The
repositories will start empty and the UI will render empty states until
you create your first project. A "remove demo seed" toggle is on the
roadmap.
