"""Evidence persistence.

Writes raw scanner output to disk as canonical JSON and records a sha256
content hash. Files live under `ASURA_EVIDENCE_DIR` (default `./evidence`).

We never overwrite an existing evidence file: a collision suffix `-N` is
appended to keep historical evidence intact.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models.schemas import Evidence, EvidenceType


def _canonical_json(payload: Any) -> bytes:
    """Stable JSON representation used for hashing and disk writes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def content_hash(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _resolve_root() -> Path:
    root = os.environ.get("ASURA_EVIDENCE_DIR")
    if root:
        return Path(root)
    # Fall back to a repo-relative path so the demo works out-of-the-box.
    return Path(__file__).resolve().parents[3] / "evidence"


def _unique_path(target_path: Path) -> Path:
    if not target_path.exists():
        return target_path
    stem = target_path.stem
    suffix = target_path.suffix or ".json"
    counter = 1
    while True:
        candidate = target_path.with_name(f"{stem}-{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def write_evidence_file(
    *,
    workspace_id: str,
    project_id: str,
    scan_id: str,
    tool: str,
    payload: Any,
) -> tuple[Path, str]:
    """Write the canonical-JSON payload to disk and return (path, sha256)."""
    root = _resolve_root() / workspace_id / project_id / scan_id
    root.mkdir(parents=True, exist_ok=True)
    target_path = _unique_path(root / f"{tool}.json")
    data = _canonical_json(payload)
    target_path.write_bytes(data)
    return target_path, hashlib.sha256(data).hexdigest()


def make_evidence(
    *,
    finding_id: str,
    scanner: str,
    summary: str,
    raw: dict[str, Any],
    workspace_id: str = "workspace-demo",
    project_id: str = "demo",
    scan_id: str | None = None,
    evidence_type: EvidenceType = EvidenceType.scanner_output,
    file_path: str | None = None,
    is_demo_data: bool = False,
    command_metadata: dict[str, Any] | None = None,
    persist: bool = True,
) -> Evidence:
    """Build an Evidence record, optionally writing the raw payload to disk."""
    raw_output_path: str | None = None
    hash_value: str | None = None
    if persist:
        scan_key = scan_id or f"adhoc-{uuid4().hex[:8]}"
        path, hash_value = write_evidence_file(
            workspace_id=workspace_id,
            project_id=project_id,
            scan_id=scan_key,
            tool=scanner,
            payload=raw,
        )
        raw_output_path = str(path)
    else:
        hash_value = content_hash(raw)
    return Evidence(
        id=f"ev-{uuid4().hex[:10]}",
        finding_id=finding_id,
        evidence_type=evidence_type,
        scanner=scanner,
        raw=raw,
        summary=summary,
        source_tool=scanner,
        file_path=file_path,
        captured_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        raw_output_path=raw_output_path,
        content_hash=hash_value,
        command_metadata=command_metadata,
        is_demo_data=is_demo_data,
    )
