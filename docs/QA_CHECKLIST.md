# QA checklist

Run this before tagging a foundation release.

## Backend

- [ ] `pytest -q` is green from `backend/` (baseline 87 tests).
- [ ] `GET /api/health` returns `{"status":"ok"}`.
- [ ] `GET /api/dashboard/demo` renders 10 findings, 3 attack paths,
      `is_demo_data: true`, and a populated `fix_first` array.
- [ ] `GET /api/safety/blocked` returns 11 blocked capabilities.
- [ ] `GET /api/arsenal` returns ≥ 94 tools; the 90 spec IDs are all
      present.
- [ ] `GET /api/arsenal?lab_only=true` returns the 6 DFIR forensics tools.
- [ ] `POST /api/scans` against an out-of-scope target returns 400 with a
      clear reason and writes one row to `/api/audit`.
- [ ] `POST /api/scans` against an in-scope target succeeds, the run shows
      up in `/api/scans`, and audit log records the allow decision.
- [ ] Reports: `POST /api/reports/demo` with `{"kind":"markdown"}` returns
      a body containing **Safety Statement**, **Authorization Statement**,
      and **Scope** sections.
- [ ] With `ASURA_DEMO_MODE=1`, no `subprocess.run` is reached —
      `test_runner_modes.test_demo_mode_env_var_returns_seeded_run`
      enforces this.
- [ ] Without `ASURA_DEMO_MODE`, the runner attempts real execution and
      returns `failed` (with the install hint) when the binary is missing —
      `test_runner_modes.test_default_runner_is_real_execution` enforces this.
- [ ] Mocked end-to-end loop test
      (`test_runner_loop.test_real_run_writes_evidence_and_creates_findings`)
      verifies subprocess output → parser → evidence vault → findings repo.

## Frontend

- [ ] `npm run build` is green.
- [ ] `npm run lint` is clean.
- [ ] `/` renders the Command Center with the demo-mode banner.
- [ ] `/findings` table loads; severity filter chips work.
- [ ] `/findings/{id}` shows the Evidence Drawer with raw JSON.
- [ ] `/attack-paths/{id}` renders the xyflow graph.
- [ ] `/arsenal` renders all 94 tools grouped by pack; planned tools show
      "Catalog-only".
- [ ] `/reports` exposes Markdown + JSON download buttons.
- [ ] `/audit` lists scope decisions after a few `POST /api/scans` calls.
- [ ] `/safety` lists the 11 blocked capabilities.

## Safety review

- [ ] Every finding has at least one evidence record.
- [ ] Every brain output has `cited_evidence_ids` (except scope summary,
      which intentionally cites none).
- [ ] No planned tool is reachable via `run_scanner`.
- [ ] No lab-only tool runs outside `LAB_VALIDATION_MODE`.
- [ ] No blocked tool can construct a command (validator enforces).
- [ ] Demo findings are flagged `is_demo_data: true` end-to-end.
