"""Auth profile storage.

Credentials are sensitive. The on-disk form is Fernet-encrypted with a key
that lives at `auth/.asura-auth-key`. The key is generated on first use if
not present. The key file is in `.gitignore`; the operator is responsible
for protecting it via filesystem permissions and for backing it up before
deleting `auth/` entirely (otherwise stored profiles become unreadable).

The API surface (`schemas.AuthProfile`) only exposes a 4-char preview of
the credential — never the full secret. Only the runner sees the
plaintext via `decrypted_headers(profile_id)`, and it builds argv `-H`
flags from it.

API responses include the public AuthProfile shape; the
`AuthProfileCreate` model carries the secret fields server-side for upload
and is never persisted in its raw form.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from app.models.schemas import AuthProfile, AuthProfileCreate, AuthType


_AUTH_DIR_ENV = "ASURA_AUTH_DIR"


def _auth_root() -> Path:
    base = os.environ.get(_AUTH_DIR_ENV)
    if base:
        return Path(base)
    # backend/app/services/auth_profile_service.py → repo root is parents[3]
    return Path(__file__).resolve().parents[3] / "auth"


def _key_path() -> Path:
    return _auth_root() / ".asura-auth-key"


def _load_or_create_key() -> bytes:
    """Return the Fernet key bytes, generating + persisting one if absent."""
    path = _key_path()
    if path.exists():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    path.write_bytes(key)
    try:
        # Best-effort: tighten permissions on POSIX. No-op on Windows.
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def _preview(value: str) -> str:
    if not value:
        return ""
    tail = value[-4:]
    return f"…{tail}" if len(value) > 4 else tail


def _serialise_credentials(payload: AuthProfileCreate) -> dict[str, str]:
    """Pull just the secret fields out of the create payload."""
    if payload.auth_type == "bearer":
        if not payload.token:
            raise ValueError("Bearer profiles require `token`.")
        return {"token": payload.token}
    if payload.auth_type == "basic":
        if not (payload.username and payload.password):
            raise ValueError("Basic profiles require `username` and `password`.")
        return {"username": payload.username, "password": payload.password}
    if payload.auth_type == "header":
        if not (payload.header_name and payload.header_value):
            raise ValueError("Header profiles require `header_name` and `header_value`.")
        return {"header_name": payload.header_name, "header_value": payload.header_value}
    if payload.auth_type == "cookie":
        if not payload.cookie:
            raise ValueError("Cookie profiles require `cookie`.")
        return {"cookie": payload.cookie}
    raise ValueError(f"Unsupported auth_type: {payload.auth_type}")


def _preview_for(auth_type: AuthType, creds: dict[str, str]) -> str:
    if auth_type == "bearer":
        return _preview(creds.get("token", ""))
    if auth_type == "basic":
        return f"{creds.get('username', '')}/…"
    if auth_type == "header":
        return f"{creds.get('header_name', '')}: …{_preview(creds.get('header_value', ''))}"
    if auth_type == "cookie":
        return _preview(creds.get("cookie", ""))
    return ""


def _credentials_to_headers(auth_type: AuthType, creds: dict[str, str]) -> list[tuple[str, str]]:
    """Translate a decrypted credential payload into HTTP header tuples."""
    if auth_type == "bearer":
        return [("Authorization", f"Bearer {creds['token']}")]
    if auth_type == "basic":
        raw = f"{creds['username']}:{creds['password']}".encode("utf-8")
        return [("Authorization", f"Basic {base64.b64encode(raw).decode('ascii')}")]
    if auth_type == "header":
        return [(creds["header_name"], creds["header_value"])]
    if auth_type == "cookie":
        return [("Cookie", creds["cookie"])]
    return []


class AuthProfileService:
    """File-system backed index of encrypted auth profiles."""

    def __init__(self, repos) -> None:
        self.repos = repos
        self._loaded = False

    # ---- bootstrap ----------------------------------------------------
    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.repos.auth_profiles.count() > 0:
            return
        root = _auth_root()
        if not root.exists():
            return
        for workspace_dir in root.iterdir():
            if not workspace_dir.is_dir():
                continue
            for path in workspace_dir.glob("*.json"):
                self._rehydrate(workspace_dir.name, path)

    def _rehydrate(self, workspace_id: str, path: Path) -> None:
        try:
            blob = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        try:
            record = AuthProfile.model_validate(blob.get("profile") or {})
        except Exception:
            return
        record = record.model_copy(update={"workspace_id": workspace_id})
        self.repos.auth_profiles.add(record)

    # ---- CRUD ---------------------------------------------------------
    def list(self, workspace_id: Optional[str] = None) -> list[AuthProfile]:
        self.ensure_loaded()
        items = self.repos.auth_profiles.list()
        if workspace_id:
            items = [p for p in items if p.workspace_id == workspace_id]
        return sorted(items, key=lambda p: p.created_at, reverse=True)

    def get(self, profile_id: str) -> Optional[AuthProfile]:
        self.ensure_loaded()
        return self.repos.auth_profiles.get(profile_id)

    def create(
        self,
        *,
        workspace_id: str,
        payload: AuthProfileCreate,
    ) -> AuthProfile:
        self.ensure_loaded()
        creds = _serialise_credentials(payload)  # raises ValueError on bad input
        profile_id = f"auth-{uuid4().hex[:12]}"
        record = AuthProfile(
            id=profile_id,
            name=payload.name,
            workspace_id=workspace_id,
            auth_type=payload.auth_type,
            target_match=payload.target_match,
            description=payload.description,
            credential_preview=_preview_for(payload.auth_type, creds),
            created_at=datetime.now(timezone.utc),
            is_demo_data=False,
        )
        # Persist encrypted-at-rest.
        encrypted = _fernet().encrypt(json.dumps(creds).encode("utf-8")).decode("ascii")
        blob = {
            "profile": record.model_dump(mode="json"),
            "credentials_fernet": encrypted,
        }
        path = self._path_for(workspace_id, profile_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(blob), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.repos.auth_profiles.add(record)
        return record

    def delete(self, profile_id: str) -> bool:
        self.ensure_loaded()
        record = self.repos.auth_profiles.get(profile_id)
        if record is None:
            return False
        try:
            self._path_for(record.workspace_id, profile_id).unlink(missing_ok=True)
        except OSError:
            pass
        return self.repos.auth_profiles.delete(profile_id)

    def decrypted_headers(self, profile_id: str) -> list[tuple[str, str]]:
        """Read the encrypted credentials from disk and return HTTP header
        tuples. The plaintext never leaves this function — callers receive
        header tuples ready for argv injection."""
        self.ensure_loaded()
        record = self.repos.auth_profiles.get(profile_id)
        if record is None:
            return []
        try:
            blob = json.loads(self._path_for(record.workspace_id, profile_id).read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        try:
            creds_bytes = _fernet().decrypt(blob["credentials_fernet"].encode("ascii"))
        except (InvalidToken, KeyError):
            return []
        creds = json.loads(creds_bytes.decode("utf-8"))
        return _credentials_to_headers(record.auth_type, creds)

    # ---- internals ----------------------------------------------------
    @staticmethod
    def _path_for(workspace_id: str, profile_id: str) -> Path:
        return _auth_root() / workspace_id / f"{profile_id}.json"
