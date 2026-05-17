# Evidence Vault

Every finding in Asura carries at least one `Evidence` record. The vault
preserves the raw payload, a content hash, and the command metadata so
findings can be audited months later.

## File layout

Raw payloads are written to:

```
<ASURA_EVIDENCE_DIR>/<workspace>/<project>/<scan_id>/<tool>.json
```

`ASURA_EVIDENCE_DIR` defaults to `./evidence` at the repo root.

## Content hashing

`evidence_store.content_hash(payload)` returns the sha256 of the canonical
JSON representation of the payload (sorted keys, separator-stripped). The
same hash is computed both at parse time (in memory) and at write time (on
disk) so tampering is detectable.

## Never overwrite

When a write would collide with an existing file, a `-1`, `-2`, … suffix is
appended. Historical evidence is preserved; the latest scan is the only one
that owns the un-suffixed filename.

## Reading evidence from the API

- `GET /api/evidence/{id}` returns the stored `Evidence` record.
- `GET /api/findings/{id}` returns the finding plus its inline evidence list,
  which is what the Evidence Drawer in the UI reads.

## Caveats

- Demo evidence is **not** automatically persisted to disk; the demo store
  seeds in-memory evidence with `content_hash=null`. Hash columns become
  populated as soon as a runner persists evidence via `make_evidence(...)`.
- Evidence file paths are stored as strings, not symlinks; moving the
  evidence directory invalidates the reference but does not corrupt the
  hash.
