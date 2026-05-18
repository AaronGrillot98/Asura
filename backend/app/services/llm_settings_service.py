"""LLM triage settings — Fernet-encrypted file storage.

The triage feature ships off by default. Users turn it on either via env
vars (`ASURA_LLM_TRIAGE=1` + `ANTHROPIC_API_KEY`) — the headless path —
or via the Settings page, which writes a single encrypted file at
`auth/.llm-settings.json`. The factory `get_llm_client()` checks the
settings store first; env vars are the fallback.

The Fernet key is shared with `auth_profile_service` (same `auth/`
directory, same key file) so anyone wiping the auth directory wipes the
LLM key too. This is the same threat model as auth profiles: protect
the directory at the filesystem layer, never expose the secret over the
API.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.models.schemas import LLMSettings, LLMSettingsUpdate
from app.services.auth_profile_service import _fernet  # reuse the shared key


_DEFAULT_MODEL = "claude-haiku-4-5-20251001"


def _settings_root() -> Path:
    base = os.environ.get("ASURA_AUTH_DIR")
    if base:
        return Path(base)
    return Path(__file__).resolve().parents[3] / "auth"


def _settings_path() -> Path:
    return _settings_root() / ".llm-settings.json"


def _preview(value: str) -> str:
    if not value:
        return ""
    tail = value[-4:]
    return f"…{tail}" if len(value) > 4 else tail


class LLMSettingsService:
    """Single-tenant settings record. There is one LLM config per Asura
    instance (workspace-scoped settings can come later if multi-tenancy
    lands)."""

    # ------------------------------------------------------------------
    def get(self) -> LLMSettings:
        path = _settings_path()
        if not path.exists():
            return LLMSettings(enabled=False, model=_DEFAULT_MODEL)
        try:
            blob = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return LLMSettings(enabled=False, model=_DEFAULT_MODEL)
        return LLMSettings(
            enabled=bool(blob.get("enabled", False)),
            model=str(blob.get("model") or _DEFAULT_MODEL),
            api_key_preview=blob.get("api_key_preview"),
            api_key_configured=bool(blob.get("api_key_encrypted")),
            updated_at=_parse_dt(blob.get("updated_at")),
        )

    # ------------------------------------------------------------------
    def update(self, payload: LLMSettingsUpdate) -> LLMSettings:
        """Persist the new settings.

        Rule: if `payload.api_key` is None, we preserve the previously
        stored key (so users can toggle `enabled` or change the model
        without re-entering the secret). To wipe the key explicitly,
        call `delete()`.
        """
        path = _settings_path()
        existing: dict = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = {}

        encrypted = existing.get("api_key_encrypted")
        preview = existing.get("api_key_preview")
        if payload.api_key is not None:
            stripped = payload.api_key.strip()
            if not stripped:
                # Empty string is treated as "wipe the key" — same effect
                # as DELETE but the rest of the settings (enabled/model)
                # land in this PUT.
                encrypted = None
                preview = None
            else:
                encrypted = _fernet().encrypt(stripped.encode("utf-8")).decode("ascii")
                preview = _preview(stripped)

        blob = {
            "enabled": bool(payload.enabled) and bool(encrypted),
            "model": payload.model or _DEFAULT_MODEL,
            "api_key_encrypted": encrypted,
            "api_key_preview": preview,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(blob), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

        return self.get()

    # ------------------------------------------------------------------
    def delete(self) -> bool:
        path = _settings_path()
        if not path.exists():
            return False
        try:
            path.unlink()
        except OSError:
            return False
        return True

    # ------------------------------------------------------------------
    def decrypted_api_key(self) -> Optional[str]:
        """Read the encrypted key off disk and decrypt. Plaintext never
        leaves this function — `get_llm_client()` consumes it inline and
        hands the resulting client to PentestBrain."""
        path = _settings_path()
        if not path.exists():
            return None
        try:
            blob = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        encrypted = blob.get("api_key_encrypted")
        if not encrypted:
            return None
        try:
            return _fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return None


def _parse_dt(value) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
