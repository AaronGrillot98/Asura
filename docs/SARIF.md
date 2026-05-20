# SARIF — one-POST CI integration

ASURA speaks **SARIF 2.1.0** both directions:

| Verb | Endpoint                                            | Purpose                                                                                  |
|------|-----------------------------------------------------|------------------------------------------------------------------------------------------|
| GET  | `/api/projects/<id>/findings.sarif`                 | Export all findings as a SARIF document, one run per scanner driver.                     |
| POST | `/api/projects/<id>/imports/sarif`                  | Ingest a SARIF document from any tool (CodeQL, Semgrep, Snyk, Trivy, Bandit, gitleaks…). |

The import endpoint accepts the raw SARIF JSON in the body
(`Content-Type: application/sarif+json` or `application/json`) **or** a
multipart upload. Findings dedupe by the standard ASURA fingerprint, so
re-uploading the same CI artifact bumps `last_seen` instead of cloning.

## CI → ASURA — one curl

```bash
# Run your favorite scanner, pipe its SARIF output straight to ASURA.
semgrep --config p/security-audit --sarif > semgrep.sarif

curl -sS -X POST "$ASURA/api/projects/$PROJECT/imports/sarif" \
     -H 'Content-Type: application/sarif+json' \
     --data-binary @semgrep.sarif
```

Response:

```json
{
  "project_id": "demo",
  "runs_processed": 1,
  "results_processed": 1,
  "findings_created": 1,
  "findings_updated": 0,
  "tool_drivers": ["semgrep"],
  "skipped": []
}
```

## ASURA → CI — one curl

```bash
# Pull everything for a project and hand it to GitHub Code Scanning.
curl -sS "$ASURA/api/projects/$PROJECT/findings.sarif" > asura.sarif

gh code-scanning upload-sarif --sarif-id "$(date +%s)" --sarif-file asura.sarif
```

## GitHub Actions

```yaml
- name: Run Semgrep
  run: semgrep --config p/security-audit --sarif > semgrep.sarif

- name: Ship to ASURA
  run: |
    curl -fsSL -X POST "${{ secrets.ASURA_URL }}/api/projects/${{ vars.PROJECT_ID }}/imports/sarif" \
      -H 'Content-Type: application/sarif+json' \
      --data-binary @semgrep.sarif
```

## Severity mapping

The importer prefers, in this order:
1. `properties["asura.severity"]` — present when round-tripping ASURA's own export.
2. `properties["security-severity"]` — numeric 0–10, as GitHub Code Scanning uses.
   * `≥ 9.0` → `critical`
   * `≥ 7.0` → `high`
   * `≥ 4.0` → `medium`
   * `> 0`  → `low`
   * `0`    → `info`
3. SARIF `level` field — `error → high`, `warning → medium`, `note → low`, `none → info`.

## Round-trip fidelity

The exporter stamps these under `properties.*` so a re-import recovers them losslessly:

| Property                | What it preserves          |
|-------------------------|----------------------------|
| `asura.id`              | Original finding id        |
| `asura.severity`        | Exact `critical/high/...`  |
| `asura.confidence`      | `low/medium/high/confirmed`|
| `asura.status`          | `open/triaged/fixed/...`   |
| `asura.scanner`         | Source scanner             |
| `asura.assetId`         | Asset reference            |
| `fingerprints.asura/v1` | Dedup hash                 |
| `cwe`, `cve`            | Both lists, on result + rule |

Foreign tool output (no `asura.*` props) maps cleanly via the severity ladder
above and synthesizes an `asset_id` of the form `sarif:<file-uri>`.
