"""Custom Nuclei template storage.

Templates live on disk under `templates/<workspace_id>/`. Each upload gets a
unique id and the original filename is sanitised before storage. An in-memory
index is rebuilt from disk on startup so a backend restart preserves uploads.

Security:
- Filenames are sanitised (alphanumerics + `-_.` only); user input never
  reaches the filesystem unfiltered.
- Files larger than `MAX_BYTES` are rejected.
- Content must parse as YAML and look enough like a Nuclei template (top-level
  `id:` and `info:` keys) to avoid storing garbage.
- Files are mounted read-only when nuclei runs in Docker, so a template
  cannot write to its container's filesystem.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4

import yaml

from app.models.schemas import NucleiTemplate

MAX_BYTES = 1 * 1024 * 1024  # 1 MB
ALLOWED_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _templates_root() -> Path:
    """Repo-root `templates/` directory; created on demand."""
    base = os.environ.get("ASURA_TEMPLATES_DIR")
    if base:
        return Path(base)
    # backend/app/services/templates_service.py → repo root is parents[3]
    return Path(__file__).resolve().parents[3] / "templates"


def _sanitise_filename(name: str) -> str:
    """Strip path separators, restrict to allowed characters, enforce .yaml."""
    base = os.path.basename((name or "").strip()) or "template.yaml"
    base = base.replace(" ", "_")
    base = "".join(ch for ch in base if ALLOWED_FILENAME.match(ch))
    if not base:
        base = "template.yaml"
    if not (base.endswith(".yaml") or base.endswith(".yml")):
        base = base + ".yaml"
    return base[:120]  # absolute cap on length


def _content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_template_metadata(content: bytes) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Pull (template_id, info_name, severity) out of the YAML, if present.

    Returns (None, None, None) when parsing fails so the upload still
    succeeds — we don't want a slightly-off template to be unstorable.
    """
    try:
        document: Any = yaml.safe_load(content)
    except Exception:
        return None, None, None
    if not isinstance(document, dict):
        return None, None, None
    template_id = document.get("id") if isinstance(document.get("id"), str) else None
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    info_name = info.get("name") if isinstance(info.get("name"), str) else None
    severity = info.get("severity") if isinstance(info.get("severity"), str) else None
    return template_id, info_name, severity


class TemplateValidationError(ValueError):
    pass


class TemplatesService:
    """File-system backed index of uploaded Nuclei templates."""

    def __init__(self, repos) -> None:
        self.repos = repos
        self._loaded = False

    # ---- bootstrap ----------------------------------------------------
    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        # We don't reload from disk on every call; the repository is the
        # source of truth at runtime. If the process restarts and the repo
        # is empty but template files exist, we rebuild the index.
        if self.repos.templates.count() > 0:
            return
        root = _templates_root()
        if not root.exists():
            return
        for workspace_dir in root.iterdir():
            if not workspace_dir.is_dir():
                continue
            for path in workspace_dir.glob("*.yaml"):
                self._rehydrate(workspace_dir.name, path)

    def _rehydrate(self, workspace_id: str, path: Path) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        stem = path.stem
        # rehydrated filenames are "<template_id>__<filename>"
        if "__" not in stem:
            return
        template_id, _, original_stem = stem.partition("__")
        filename = f"{original_stem}{path.suffix}"
        parsed_id, info_name, severity = _parse_template_metadata(data)
        record = NucleiTemplate(
            id=template_id,
            workspace_id=workspace_id,
            filename=filename,
            display_name=filename,
            template_id=parsed_id,
            info_name=info_name,
            severity=severity,
            size_bytes=len(data),
            content_hash=_content_hash(data),
            uploaded_at=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc),
        )
        self.repos.templates.add(record)

    # ---- CRUD ---------------------------------------------------------
    def list(self, workspace_id: Optional[str] = None) -> list[NucleiTemplate]:
        self.ensure_loaded()
        items = self.repos.templates.list()
        if workspace_id:
            items = [t for t in items if t.workspace_id == workspace_id]
        return sorted(items, key=lambda t: t.uploaded_at, reverse=True)

    def get(self, template_id: str) -> Optional[NucleiTemplate]:
        self.ensure_loaded()
        return self.repos.templates.get(template_id)

    def upload(
        self,
        *,
        workspace_id: str,
        filename: str,
        content: bytes,
        description: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
    ) -> NucleiTemplate:
        self.ensure_loaded()
        if not content:
            raise TemplateValidationError("Template file is empty.")
        if len(content) > MAX_BYTES:
            raise TemplateValidationError(
                f"Template is too large ({len(content)} bytes); max {MAX_BYTES}."
            )
        safe = _sanitise_filename(filename)
        parsed_id, info_name, severity = _parse_template_metadata(content)
        if not parsed_id:
            raise TemplateValidationError(
                "File does not look like a Nuclei template (no top-level `id:` field)."
            )
        record_id = f"tpl-{uuid4().hex[:12]}"
        target_path = self._path_for(workspace_id, record_id, safe)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(content)
        record = NucleiTemplate(
            id=record_id,
            workspace_id=workspace_id,
            filename=safe,
            display_name=(info_name or safe),
            description=description,
            tags=list(tags or []),
            template_id=parsed_id,
            info_name=info_name,
            severity=severity,
            size_bytes=len(content),
            content_hash=_content_hash(content),
            uploaded_at=datetime.now(timezone.utc),
        )
        self.repos.templates.add(record)
        return record

    def delete(self, template_id: str) -> bool:
        self.ensure_loaded()
        record = self.repos.templates.get(template_id)
        if record is None:
            return False
        try:
            self._path_for(record.workspace_id, record.id, record.filename).unlink(missing_ok=True)
        except OSError:
            pass
        return self.repos.templates.delete(template_id)

    def read_content(self, template_id: str) -> Optional[bytes]:
        record = self.get(template_id)
        if record is None:
            return None
        path = self._path_for(record.workspace_id, record.id, record.filename)
        try:
            return path.read_bytes()
        except OSError:
            return None

    def path_for(self, template_id: str) -> Optional[Path]:
        record = self.get(template_id)
        if record is None:
            return None
        path = self._path_for(record.workspace_id, record.id, record.filename)
        return path if path.exists() else None

    def resolve_paths(self, template_ids: Iterable[str]) -> tuple[list[Path], list[str]]:
        """Return (paths, missing_ids) for a set of template IDs."""
        paths: list[Path] = []
        missing: list[str] = []
        for tid in template_ids:
            path = self.path_for(tid)
            if path is None:
                missing.append(tid)
            else:
                paths.append(path)
        return paths, missing

    def workspace_dir(self, workspace_id: str) -> Path:
        return _templates_root() / workspace_id

    # ---- internals ----------------------------------------------------
    @staticmethod
    def _path_for(workspace_id: str, record_id: str, filename: str) -> Path:
        return _templates_root() / workspace_id / f"{record_id}__{filename}"
