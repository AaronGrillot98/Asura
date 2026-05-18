"""LLM settings UI surface — encrypted file storage + API + factory wiring.

Three concerns:

1. **Round-trip** — write through the service, read back via the service.
   The encrypted file on disk never contains the plaintext key.
2. **API masking** — `GET /api/settings/llm` returns only a 4-char
   preview; `PUT` accepts a write-only `api_key` field; the raw key never
   appears in any response body.
3. **Factory precedence** — `get_llm_client()` prefers UI settings over
   env vars; a configured UI store with `enabled=true` wins even if the
   env var pair is set. When the UI store is wiped, env vars take over.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import LLMSettingsUpdate
from app.services.llm import (
    AnthropicLLMClient,
    NullLLMClient,
    get_llm_client,
)
from app.services.llm_settings_service import LLMSettingsService


client = TestClient(app)


def _isolated_auth_dir(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"ASURA_AUTH_DIR", "ASURA_LLM_TRIAGE", "ANTHROPIC_API_KEY", "ASURA_LLM_MODEL"}}
    env["ASURA_AUTH_DIR"] = str(tmp_path)
    return env


# ---------------------------------------------------------------------------
# Service-level: round-trip + on-disk encryption
# ---------------------------------------------------------------------------


def test_default_settings_when_no_file_exists(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        settings = LLMSettingsService().get()
    assert settings.enabled is False
    assert settings.api_key_configured is False
    assert settings.api_key_preview is None
    assert settings.model == "claude-haiku-4-5-20251001"


def test_update_persists_encrypted_key_with_preview(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        service = LLMSettingsService()
        result = service.update(LLMSettingsUpdate(
            enabled=True,
            model="claude-sonnet-4-6",
            api_key="sk-ant-secret-value-9999",
        ))
    assert result.enabled is True
    assert result.model == "claude-sonnet-4-6"
    assert result.api_key_configured is True
    assert result.api_key_preview == "…9999"
    # The plaintext key never lands in the file.
    settings_file = tmp_path / ".llm-settings.json"
    text = settings_file.read_text("utf-8")
    assert "sk-ant-secret-value-9999" not in text
    assert "api_key_encrypted" in text


def test_update_without_api_key_preserves_existing_key(tmp_path: Path) -> None:
    """Toggling `enabled` or changing the model alone must not wipe the
    stored key — that's the whole point of the optional api_key field."""
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        service = LLMSettingsService()
        service.update(LLMSettingsUpdate(enabled=True, model="m1", api_key="sk-original-key-1234"))
        # Update with api_key=None: should keep the original.
        result = service.update(LLMSettingsUpdate(enabled=False, model="m2", api_key=None))
        assert result.api_key_configured is True
        assert result.api_key_preview == "…1234"
        assert result.enabled is False  # honored the toggle
        assert result.model == "m2"
        # Decryption still returns the original key.
        assert service.decrypted_api_key() == "sk-original-key-1234"


def test_update_with_empty_string_api_key_wipes_the_key(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        service = LLMSettingsService()
        service.update(LLMSettingsUpdate(enabled=True, model="m", api_key="sk-original"))
        result = service.update(LLMSettingsUpdate(enabled=True, model="m", api_key=""))
        assert result.api_key_configured is False
        assert result.api_key_preview is None
        # And `enabled` is forced false when the key is missing.
        assert result.enabled is False


def test_delete_removes_the_settings_file(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        service = LLMSettingsService()
        service.update(LLMSettingsUpdate(enabled=True, model="m", api_key="sk-12345"))
        assert (tmp_path / ".llm-settings.json").exists()
        assert service.delete() is True
        assert not (tmp_path / ".llm-settings.json").exists()
        # Calling delete again is a no-op (returns False, not exception).
        assert service.delete() is False


def test_decrypted_api_key_roundtrips(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        service = LLMSettingsService()
        service.update(LLMSettingsUpdate(enabled=True, model="m", api_key="sk-round-trip-9876"))
        assert service.decrypted_api_key() == "sk-round-trip-9876"


# ---------------------------------------------------------------------------
# API surface — masking guarantees
# ---------------------------------------------------------------------------


def test_api_get_returns_default_when_unconfigured(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.get("/api/settings/llm")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["api_key_configured"] is False
    assert body["api_key_preview"] is None


def test_api_put_never_echoes_the_raw_api_key(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.put(
            "/api/settings/llm",
            json={"enabled": True, "model": "claude-haiku-4-5-20251001",
                  "api_key": "sk-ant-do-not-leak-77777"},
        )
    assert response.status_code == 200
    body = response.json()
    serialized = json.dumps(body)
    assert "sk-ant-do-not-leak-77777" not in serialized
    assert body["api_key_preview"] == "…7777"
    assert body["api_key_configured"] is True
    assert body["enabled"] is True


def test_api_get_after_put_still_masks_the_key(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        client.put(
            "/api/settings/llm",
            json={"enabled": True, "model": "m", "api_key": "sk-secret-abcdef"},
        )
        response = client.get("/api/settings/llm")
    body = response.json()
    assert "sk-secret-abcdef" not in json.dumps(body)
    assert body["api_key_preview"] == "…cdef"


def test_api_delete_returns_204_even_when_nothing_to_delete(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        response = client.delete("/api/settings/llm")
    assert response.status_code == 204


# ---------------------------------------------------------------------------
# Factory precedence
# ---------------------------------------------------------------------------


def test_factory_uses_ui_settings_when_enabled(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        LLMSettingsService().update(
            LLMSettingsUpdate(enabled=True, model="m-ui", api_key="sk-ui-key")
        )
        client_inst = get_llm_client()
    assert isinstance(client_inst, AnthropicLLMClient)
    assert client_inst.model == "m-ui"
    assert client_inst._api_key == "sk-ui-key"


def test_factory_skips_ui_settings_when_disabled_falls_back_to_env(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    env["ASURA_LLM_TRIAGE"] = "1"
    env["ANTHROPIC_API_KEY"] = "sk-env-key"
    env["ASURA_LLM_MODEL"] = "m-env"
    with mock.patch.dict(os.environ, env, clear=True):
        # Configure UI settings but leave enabled=False.
        LLMSettingsService().update(
            LLMSettingsUpdate(enabled=False, model="m-ui", api_key="sk-ui-key")
        )
        client_inst = get_llm_client()
    assert isinstance(client_inst, AnthropicLLMClient)
    assert client_inst.model == "m-env"
    assert client_inst._api_key == "sk-env-key"


def test_factory_falls_back_to_null_when_nothing_configured(tmp_path: Path) -> None:
    env = _isolated_auth_dir(tmp_path)
    with mock.patch.dict(os.environ, env, clear=True):
        client_inst = get_llm_client()
    assert isinstance(client_inst, NullLLMClient)


def test_factory_ui_with_enabled_but_no_key_falls_back_to_env(tmp_path: Path) -> None:
    """The UI's enabled flag can't override the missing-key reality. If the
    settings file says enabled=true but stores no key, we should NOT
    silently pretend the LLM is configured — fall back to env-var path."""
    env = _isolated_auth_dir(tmp_path)
    env["ASURA_LLM_TRIAGE"] = "1"
    env["ANTHROPIC_API_KEY"] = "sk-env-key"
    with mock.patch.dict(os.environ, env, clear=True):
        # Force write a settings file that has enabled=true but no key.
        # The service won't let us via update() — `enabled` is forced
        # false when the key is missing. So we write the file directly.
        path = Path(env["ASURA_AUTH_DIR"]) / ".llm-settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"enabled": True, "model": "m-ui",
                                    "api_key_encrypted": None, "api_key_preview": None,
                                    "updated_at": "2026-05-17T00:00:00+00:00"}))
        client_inst = get_llm_client()
    # Should fall through to env vars.
    assert isinstance(client_inst, AnthropicLLMClient)
    assert client_inst._api_key == "sk-env-key"
