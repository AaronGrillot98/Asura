"""Authentication primitives for ASURA.

Three things live here:

1. **Password hashing.** PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023
   recommendation). No external dep — `hashlib` ships with Python.
2. **JWT (HS256).** Hand-rolled to avoid pulling a JOSE library. Tokens
   carry the user id, workspace memberships, and a `kind` discriminator
   so we can distinguish user-session tokens from long-lived service
   tokens for CI.
3. **FastAPI dependencies.** `current_user_optional` (returns `None`
   when auth is disabled or no token is present) and `current_user`
   (raises 401 unless auth is disabled).

Auth can be disabled with `ASURA_AUTH_DISABLED=1`, which is the default
so the seeded demo works out of the box. Production deployments should
unset it (and set `ASURA_JWT_SECRET` to something non-default).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from fastapi import Depends, Header, HTTPException, status

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_SECRET = "asura-dev-secret-CHANGE-ME"
_DEFAULT_TTL_MIN = 60 * 12        # 12h sessions
_PBKDF2_ITERS = 600_000
_PBKDF2_SALT_BYTES = 16
_PBKDF2_DKLEN = 32


def auth_disabled() -> bool:
    """Return True when AUTH gating is off (default — preserves the demo)."""
    val = os.environ.get("ASURA_AUTH_DISABLED", "1").strip().lower()
    return val in {"1", "true", "yes", "on"}


def jwt_secret() -> str:
    return os.environ.get("ASURA_JWT_SECRET") or _DEFAULT_SECRET


def jwt_ttl_minutes() -> int:
    raw = os.environ.get("ASURA_JWT_TTL_MIN")
    if raw and raw.isdigit():
        return int(raw)
    return _DEFAULT_TTL_MIN


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plaintext: str) -> str:
    """Return a PBKDF2-HMAC-SHA256 hash in the format
    ``pbkdf2_sha256$<iters>$<salt-b64>$<digest-b64>``.

    The format mirrors Django's so we could swap to passlib later
    without re-hashing user records.
    """
    if not plaintext:
        raise ValueError("Password may not be empty.")
    salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt, _PBKDF2_ITERS, _PBKDF2_DKLEN)
    return "pbkdf2_sha256${iters}${salt}${digest}".format(
        iters=_PBKDF2_ITERS,
        salt=base64.b64encode(salt).decode("ascii"),
        digest=base64.b64encode(dk).decode("ascii"),
    )


def verify_password(plaintext: str, stored_hash: str | None) -> bool:
    """Constant-time verify. Returns False on any parse error or mismatch."""
    if not plaintext or not stored_hash:
        return False
    try:
        scheme, iters_s, salt_b64, digest_b64 = stored_hash.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt, iters, len(expected))
    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# JWT (HS256, hand-rolled)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def create_jwt(
    *,
    user_id: str,
    email: str,
    workspaces: Iterable[str] = (),
    kind: str = "session",
    ttl_minutes: int | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[str, datetime]:
    """Sign an HS256 JWT. Returns ``(token, expires_at)``.

    The `kind` claim is `"session"` for user-session tokens and
    `"service"` for long-lived CI tokens — services tokens are otherwise
    indistinguishable on the wire so the bearer middleware doesn't care.
    """
    now = datetime.now(timezone.utc)
    ttl = ttl_minutes if ttl_minutes is not None else jwt_ttl_minutes()
    exp = now + timedelta(minutes=ttl)
    payload: dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "workspaces": list(workspaces),
        "kind": kind,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    if extra:
        payload.update(extra)
    header = {"alg": "HS256", "typ": "JWT"}
    head_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pl_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{head_b64}.{pl_b64}".encode("ascii")
    sig = hmac.new(jwt_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{head_b64}.{pl_b64}.{_b64url_encode(sig)}", exp


class JwtError(ValueError):
    """Raised when a JWT fails to parse or verify."""


def decode_jwt(token: str) -> dict[str, Any]:
    """Verify signature, expiry, and structure; return the payload dict.

    Constant-time signature compare. Allows a small 30s clock skew."""
    if not token or token.count(".") != 2:
        raise JwtError("Malformed JWT.")
    head_b64, pl_b64, sig_b64 = token.split(".")
    try:
        sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise JwtError("Bad signature encoding.") from exc
    signing_input = f"{head_b64}.{pl_b64}".encode("ascii")
    expected = hmac.new(jwt_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise JwtError("Bad signature.")
    try:
        payload = json.loads(_b64url_decode(pl_b64))
    except Exception as exc:
        raise JwtError("Bad payload.") from exc
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise JwtError("Missing exp.")
    if exp + 30 < datetime.now(timezone.utc).timestamp():
        raise JwtError("Token expired.")
    return payload


# ---------------------------------------------------------------------------
# Service-token hashing (separate from password hash so we can rotate
# either without touching the other)
# ---------------------------------------------------------------------------

SERVICE_TOKEN_PREFIX = "asura_st_"


def generate_service_token() -> tuple[str, str, str]:
    """Mint a new opaque service token.

    Returns ``(plaintext, token_hash, display_prefix)``. The plaintext is
    only returned this once; only the hash and the 8-char prefix are
    stored.
    """
    raw = secrets.token_urlsafe(32)
    plaintext = f"{SERVICE_TOKEN_PREFIX}{raw}"
    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return plaintext, digest, plaintext[:12]


def hash_service_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """Resolved authentication state for the current request."""
    user_id: str
    email: str
    workspaces: list[str]
    kind: str             # "session" | "service" | "anonymous"
    token_payload: dict[str, Any] | None = None


_ANONYMOUS = AuthContext(
    user_id="anonymous",
    email="anonymous@asura.local",
    workspaces=[],
    kind="anonymous",
)


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def current_user_optional(
    authorization: Optional[str] = Header(default=None),
) -> AuthContext:
    """Return the resolved auth context. Falls back to anonymous when
    auth is disabled OR no Authorization header is present and the route
    chooses not to enforce."""
    token = _extract_bearer(authorization)

    # Service-token path: tokens are looked up in the repo by hash; the
    # repo layer is imported lazily here to avoid a circular import at
    # module load time (auth.py is imported by repositories.seed).
    if token and token.startswith(SERVICE_TOKEN_PREFIX):
        from app.repositories import get_repos
        repos = get_repos()
        token_hash = hash_service_token(token)
        rec = repos.api_tokens.find(lambda t: t.token_hash == token_hash and not t.revoked_at)
        if rec is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service token.")
        if rec.expires_at and rec.expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Service token expired.")
        user = repos.users.get(rec.user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token owner inactive.")
        # Stamp last_used (best-effort; in-memory repos make this trivial)
        rec.last_used_at = datetime.now(timezone.utc)
        repos.api_tokens.update(rec)
        return AuthContext(
            user_id=user.id,
            email=user.email,
            workspaces=[rec.workspace_id],
            kind="service",
        )

    if token:
        try:
            payload = decode_jwt(token)
        except JwtError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        return AuthContext(
            user_id=str(payload.get("sub") or ""),
            email=str(payload.get("email") or ""),
            workspaces=list(payload.get("workspaces") or []),
            kind=str(payload.get("kind") or "session"),
            token_payload=payload,
        )

    if auth_disabled():
        return _ANONYMOUS
    # No token, auth required.
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_user(ctx: AuthContext = Depends(current_user_optional)) -> AuthContext:
    """Like `current_user_optional` but anonymous is rejected unless
    auth is disabled. Use for endpoints that must have a real user."""
    if ctx.kind == "anonymous" and not auth_disabled():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return ctx


def require_workspace_role(ctx: AuthContext, workspace_id: str, *, allow_roles: Iterable[str] = ("owner", "admin", "member", "viewer")) -> None:
    """Guard helper for endpoints that act on a specific workspace.

    Anonymous (auth-disabled) requests always pass. Authenticated requests
    must have a Membership row in the target workspace with a role in
    `allow_roles`.
    """
    if ctx.kind == "anonymous":
        return
    from app.repositories import get_repos
    repos = get_repos()
    membership = repos.memberships.find(
        lambda m: m.user_id == ctx.user_id and m.workspace_id == workspace_id
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this workspace.")
    allow = set(allow_roles)
    if membership.role.value not in allow:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires role one of {sorted(allow)}.")
