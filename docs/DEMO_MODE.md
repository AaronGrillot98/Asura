# Demo mode

Out-of-the-box Asura ships with a seeded **Acme FlightOps Demo** project so
the full dashboard, evidence, attack-path, and reporting flows work without
any scanners installed.

## What you see

- One project: **Acme FlightOps Demo** (id `demo`).
- Ten findings spanning secrets, code, web, container, IaC, network, and
  API categories.
- Three correlated attack-path hypotheses with evidence citations.
- Eight scanner runs, every one stamped `is_demo_data: true`.
- A banner on the Command Center: "Demo mode — findings on this dashboard
  are seeded demo evidence, not the result of a live scan."

## Why this exists

The product promise is "Asura does not pretend a scan happened." Demo data
is therefore **labelled at the storage layer**: `is_demo_data: bool` flows
from findings into attack paths, reports, and the UI banner. The demo
project also fails the "no fake claims" test gracefully — every demo
finding has at least one evidence record.

## Turning the demo banner off

The banner reads `data.is_demo_data` from `/api/dashboard/{id}`. Once a real
project (one with `is_demo_data: false`) is added and its findings come
from real parser output, the banner disappears for that view.

## Switching to real scans

1. Set `ASURA_ENABLE_REAL_SCANNERS=1` in the backend environment.
2. Confirm the tool is installed on the host or available via Docker.
3. POST to `/api/scans` with a target in the project's authorized scope.

If a tool is not installed, the `SubprocessRunner` returns a `failed`
`ScannerRun` with the executable name — it does not fall back to demo
content.
