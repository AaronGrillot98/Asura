"""Ed25519 signing for ASURA reports.

The signing key is a single Ed25519 keypair persisted to disk on first
use. The public key is exposed at ``GET /api/reports/signing-key`` so a
verifier can fetch it once and check every subsequent signed bundle
without trusting the API for anything other than the initial key
material.

Path defaults to ``./asura-signing-key.pem`` (next to the working
directory) and can be overridden with ``ASURA_SIGNING_KEY_PATH``. In
multi-replica deployments, mount the same PEM into every backend
instance so signatures stay stable across replicas.

Algorithm choice: Ed25519. Small signatures (64 bytes), constant-time
verification, no nonce-misuse footgun, native support in `cryptography`
(already in requirements.txt — no new dep here).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


DEFAULT_KEY_PATH = "asura-signing-key.pem"
KEY_ID_PREFIX = "asura-ed25519-"


def _key_path() -> Path:
    return Path(os.environ.get("ASURA_SIGNING_KEY_PATH", DEFAULT_KEY_PATH)).expanduser()


def _load_or_generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return ``(private_key, key_id)``.

    ``key_id`` is a stable, public-key-derived identifier: ``asura-ed25519-<first 12 hex chars of public key>``.
    This means the same key always has the same id, and a key rotation
    produces a visibly different id without us having to track versions
    in a separate file.
    """
    path = _key_path()
    if path.exists():
        with path.open("rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError(f"Key file {path} is not an Ed25519 PEM.")
    else:
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Windows + non-POSIX filesystems silently no-op this; the
            # equivalent ACL hardening is the deployment's responsibility.
            pass

    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = KEY_ID_PREFIX + pub_bytes.hex()[:12]
    return priv, key_id


# Cache the keypair at module load — we re-read after the first call so
# tests can swap the env-var and call `reset_signing_key_for_tests()`.
_PRIVATE_KEY: Ed25519PrivateKey | None = None
_KEY_ID: str | None = None


def _ensure_key() -> tuple[Ed25519PrivateKey, str]:
    global _PRIVATE_KEY, _KEY_ID
    if _PRIVATE_KEY is None or _KEY_ID is None:
        _PRIVATE_KEY, _KEY_ID = _load_or_generate_keypair()
    return _PRIVATE_KEY, _KEY_ID


def reset_signing_key_for_tests() -> None:
    """Force the next call to re-read from disk."""
    global _PRIVATE_KEY, _KEY_ID
    _PRIVATE_KEY = None
    _KEY_ID = None


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def public_key_pem() -> str:
    """Return the Ed25519 public key in PEM (SPKI) form."""
    priv, _ = _ensure_key()
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def signing_key_id() -> str:
    _, kid = _ensure_key()
    return kid


def canonical_json(obj: Any) -> bytes:
    """JCS-ish canonicalization: sorted keys, no whitespace, UTF-8.

    Good enough for our needs: signatures are computed and verified by
    the same library so we don't need full RFC 8785 — but sorted-keys +
    no-whitespace is the bare minimum to avoid signature drift on a
    pretty-printed re-serialize.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_bytes(payload: bytes) -> bytes:
    priv, _ = _ensure_key()
    return priv.sign(payload)


def verify_signature(payload: bytes, signature: bytes, public_pem: str | None = None) -> bool:
    """Verify a signature. If `public_pem` is None we use the in-process
    private key's matching public key — useful for round-trip tests."""
    if public_pem is None:
        priv, _ = _ensure_key()
        pub = priv.public_key()
    else:
        pub = serialization.load_pem_public_key(public_pem.encode("ascii"))
        if not isinstance(pub, Ed25519PublicKey):
            return False
    try:
        pub.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def sign_report_bundle(
    *,
    report_id: str,
    generated_at: datetime | None,
    content_hash: str,
    merkle_root: str,
    sections: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce a signed envelope around a report.

    The signed payload is exactly the JCS-canonicalized form of
    ``{report_id, generated_at, content_hash, merkle_root}`` — i.e. the
    minimum integrity-bearing fields. A consumer who wants to verify
    re-hashes the report sections to derive `content_hash`, recomputes
    `merkle_root` from the evidence leaves they have, and runs
    `verify_signature` on the canonicalized header.

    `sections` is included in the returned envelope for convenience but
    is NOT part of the signed payload — the consumer already verified
    it via `content_hash`.
    """
    iso = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    header = {
        "report_id": report_id,
        "generated_at": iso,
        "content_hash": content_hash,
        "merkle_root": merkle_root,
    }
    sig = sign_bytes(canonical_json(header))
    _, kid = _ensure_key()
    envelope: dict[str, Any] = {
        **header,
        "algorithm": "ed25519",
        "signing_key_id": kid,
        "signature": base64.b64encode(sig).decode("ascii"),
    }
    if sections is not None:
        envelope["sections"] = sections
    return envelope


def hash_sections(sections: Any) -> str:
    """Stable hash over the canonical JSON of a sections dict.

    Returns the hex digest with the `sha256:` URI prefix so signed
    bundles are self-describing.
    """
    digest = hashlib.sha256(canonical_json(sections)).hexdigest()
    return f"sha256:{digest}"
