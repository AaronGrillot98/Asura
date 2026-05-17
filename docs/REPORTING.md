# Reporting

`app.services.reporting.build_report` produces structured reports that the
API returns as either JSON or Markdown.

## Sections (every report)

1. Engagement Summary
2. Scope
3. Authorization Statement
4. Methodology
5. Tools Used
6. Executive Summary
7. Risk Overview
8. Attack Paths
9. Findings by Severity
10. Evidence (with content hashes)
11. Remediation Roadmap
12. Appendix: Scanner Runs
13. Appendix: Raw Evidence References
14. Safety Statement

## Endpoints

- `POST /api/reports/{project_id}` with body `{"kind": "markdown" | "json"}` —
  builds, persists, and returns the report.
- `GET /api/reports/{project_id}/markdown` — convenience download as
  `text/markdown`.
- `GET /api/reports/{project_id}/json` — convenience structured JSON.

Every report stamps:

- `scope_statement` (text)
- `authorization_statement` (text)
- `safety_statement` (text)
- `content_hash` (sha256 of canonical JSON of the sections)
- `pdf_status: "not_generated"` (PDF rendering is roadmapped)
- `is_demo_data` (true if any underlying finding/project is demo data)

## Markdown rendering

`render_markdown(report)` walks the sections and emits a Markdown document
suitable for download. The demo banner appears at the top when
`is_demo_data` is true.
