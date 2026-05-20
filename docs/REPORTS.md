# Reports — PDF, signed bundles, and Merkle proofs

Every ASURA report is now a verifiable artifact. Each project exposes
four export shapes, all driven by the same underlying `build_report()`
pass:

| Verb | Endpoint                                      | Use                                                       |
|------|-----------------------------------------------|-----------------------------------------------------------|
| GET  | `/api/reports/<project_id>/markdown`          | Plain markdown (existing flow, unchanged).                |
| GET  | `/api/reports/<project_id>/json`              | Plain JSON (existing flow).                               |
| GET  | `/api/reports/<project_id>/pdf`               | **Signed PDF** — Ed25519 footer, Merkle root, key id.     |
| GET  | `/api/reports/<project_id>/signed.json`       | **Signed JSON envelope** + per-evidence Merkle proofs.    |
| GET  | `/api/reports/signing-key`                    | Public key (PEM, SPKI) + stable `key_id`.                 |
| POST | `/api/reports/verify-evidence`                | Stateless Merkle-proof verifier.                          |

## The signed bundle

```jsonc
{
  "report_id":      "report-demo-json-87b3c0a4",
  "generated_at":   "2026-05-19T04:57:33.969446+00:00",
  "content_hash":   "sha256:a8ee63...",         // sha256 over canonical(sections)
  "merkle_root":    "sha256:e7742b...",         // RFC-6962-style binary Merkle tree
  "algorithm":      "ed25519",
  "signing_key_id": "asura-ed25519-2f6cf6999ad9",
  "signature":      "<base64 ed25519 sig>",     // 64 raw bytes, 88 base64 chars
  "sections":       { /* full report body */ },
  "evidence_count": 10,
  "evidence_leaves": [
    {
      "evidence_id": "ev-f-secret",
      "finding_id":  "f-secret",
      "scanner":     "gitleaks",
      "leaf_hash":   "0a1b2c...",
      "leaf_index":  0,
      "proof": [
        { "sibling": "<hex>", "side": "right" },
        { "sibling": "<hex>", "side": "right" },
        ...
      ]
    }
  ]
}
```

The **signed payload** is exactly the JCS-canonicalized object
`{report_id, generated_at, content_hash, merkle_root}`. Everything else
(sections, leaves) is integrity-checked transitively through the two
hashes.

## Verifying a report (Python, 12 lines)

```python
import base64, json, urllib.request
from cryptography.hazmat.primitives import serialization

key  = json.loads(urllib.request.urlopen(f"{ASURA}/api/reports/signing-key").read())
bun  = json.loads(urllib.request.urlopen(f"{ASURA}/api/reports/{PROJECT}/signed.json").read())
pub  = serialization.load_pem_public_key(key["public_key_pem"].encode())

header = {
    "report_id":    bun["report_id"],
    "generated_at": bun["generated_at"],
    "content_hash": bun["content_hash"],
    "merkle_root":  bun["merkle_root"],
}
pub.verify(base64.b64decode(bun["signature"]),
           json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
print("Signature OK")
```

## Verifying that an evidence record was in the report

You hold only the leaf hash + a Merkle audit path + the trusted root
(typically pinned from a signed bundle on a status page). No need to
trust the API for anything other than the initial public key.

```bash
curl -fsSL -X POST "$ASURA/api/reports/verify-evidence" \
     -H 'Content-Type: application/json' \
     -d '{
           "leaf_hash":   "0a1b2c...",
           "proof":       [{"sibling":"<hex>","side":"right"}, ...],
           "merkle_root": "sha256:e7742b..."
         }'
# -> {"valid": true, "merkle_root": "sha256:e7742b..."}
```

Or run the same recomputation locally with the snippet in
[backend/app/services/merkle.py](../backend/app/services/merkle.py):
`verify_inclusion(leaf=leaf_hash, proof=proof, expected_root=root)`.

## The PDF

Rendered with `fpdf2` (pure-Python, no system deps). Section order
mirrors the markdown report so readers aren't disoriented. The final
section is a **Cryptographic Footer** that prints, in Courier:

```
signing_key_id : asura-ed25519-2f6cf6999ad9
algorithm      : ed25519
content_hash   : sha256:a8ee63...
merkle_root    : sha256:e7742b...
evidence_count : 10
signature (base64, 88 chars):
1ym+ecAyN5Qk5YKOJbn422QAL8kjEDoNiA6gCyq8...
```

Pair that with a printout of the public key (or its `key_id` pinned
elsewhere) and the printed page is itself a verifiable artifact.

## Key management

- Single Ed25519 keypair per backend deployment.
- Generated on first start, persisted to `./asura-signing-key.pem`
  (override via `ASURA_SIGNING_KEY_PATH`).
- File permissions are tightened to `0o600` where the OS supports it.
- Rotation: replace the PEM and restart. The `key_id` will visibly
  change (`asura-ed25519-<first 12 hex of pubkey>`), so consumers see
  immediately when a new key is in use.
- In multi-replica deployments, mount the same PEM into every backend
  instance so signatures stay stable across replicas.

## Why Ed25519 + Merkle

- **Ed25519**: small signatures (64 bytes), constant-time verification,
  no nonce footgun (unlike ECDSA), and native support in `cryptography`.
- **Merkle proofs (RFC-6962 leaf/inner prefixes)**: a single signed root
  commits to the entire evidence set, but verifying a *single* record
  only requires O(log n) sibling hashes — your auditor doesn't need the
  full report to confirm one finding's evidence was included.

## What's NOT in scope this slice

- No revocation list (yet) — rotating the key file is the only way to
  invalidate signatures.
- No transparency log (yet) — there's nothing append-only to compare
  successive roots against. Adding a Merkle log on top of the per-report
  trees is the natural next step.
