"""Auth + workspace membership endpoints.

Mounted under ``/api`` from ``app.main``. The bearer token flow:

1. ``POST /api/auth/register`` — first user on a fresh deployment becomes
   the founding owner of a new workspace. Subsequent registrations either
   require an existing admin (via ``POST /api/workspaces/<id>/members``)
   or are rejected.
2. ``POST /api/auth/login`` — exchange email/password for a session JWT.
3. ``GET /api/auth/me`` — verify the token and return the user's record.
4. ``POST /api/auth/tokens`` — mint a long-lived service token (the
   "one curl" CI integration).
5. SSO stubs under ``/api/auth/sso/oidc/*`` are wired but inactive until
   ``ASURA_OIDC_ISSUER`` is set.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.models.schemas import (
    ApiToken,
    ApiTokenCreated,
    ApiTokenPublic,
    InviteRequest,
    LoginRequest,
    LoginResponse,
    Membership,
    RegisterRequest,
    Role,
    TokenCreateRequest,
    User,
    UserPublic,
    Workspace,
    WorkspaceMember,
)
from app.repositories import get_repos
from app.security.auth import (
    AuthContext,
    SERVICE_TOKEN_PREFIX,
    auth_disabled,
    create_jwt,
    current_user,
    current_user_optional,
    generate_service_token,
    hash_password,
    jwt_ttl_minutes,
    require_workspace_role,
    verify_password,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_workspaces(user_id: str) -> list[str]:
    repos = get_repos()
    return [m.workspace_id for m in repos.memberships.list() if m.user_id == user_id]


def _to_public(user: User) -> UserPublic:
    return UserPublic(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _token_public(t: ApiToken) -> ApiTokenPublic:
    return ApiTokenPublic(
        id=t.id, name=t.name, workspace_id=t.workspace_id, prefix=t.prefix,
        created_at=t.created_at, expires_at=t.expires_at,
        last_used_at=t.last_used_at, revoked_at=t.revoked_at,
    )


# ---------------------------------------------------------------------------
# /api/auth/*
# ---------------------------------------------------------------------------

@router.post("/auth/register", response_model=LoginResponse)
def register(req: RegisterRequest) -> LoginResponse:
    """First-run bootstrap: create a user + (optionally) a new workspace.

    If the system has no users yet, this is the founding-owner flow. If
    users already exist, registration is closed via this endpoint — new
    members must be invited via ``POST /api/workspaces/<id>/members``.
    """
    repos = get_repos()
    if repos.users.find(lambda u: u.email.lower() == req.email.lower()):
        raise HTTPException(status_code=409, detail="Email already registered.")

    is_first_user = repos.users.count() == 0
    if not is_first_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Open registration is closed. Ask a workspace admin to invite you.",
        )

    now = datetime.now(timezone.utc)
    user = User(
        id=f"user-{uuid4().hex[:12]}",
        email=req.email.strip(),
        display_name=req.display_name.strip() or req.email.split("@")[0],
        password_hash=hash_password(req.password),
        is_active=True,
        created_at=now,
        last_login_at=now,
    )
    repos.users.add(user)

    ws_id = f"workspace-{uuid4().hex[:8]}"
    repos.workspaces.add(Workspace(id=ws_id, name=req.workspace_name or "Default Workspace", created_at=now))
    repos.memberships.add(Membership(
        id=f"membership-{uuid4().hex[:8]}",
        workspace_id=ws_id, user_id=user.id, role=Role.owner, created_at=now,
    ))

    token, exp = create_jwt(user_id=user.id, email=user.email, workspaces=[ws_id])
    return LoginResponse(access_token=token, expires_in=jwt_ttl_minutes() * 60, user=_to_public(user))


@router.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest) -> LoginResponse:
    repos = get_repos()
    user = repos.users.find(lambda u: u.email.lower() == req.email.lower())
    # Constant work whether the user exists or not (timing-attack hygiene):
    # if the lookup misses, verify against a dummy hash so the response
    # time matches the success path.
    dummy = "pbkdf2_sha256$600000$AAAA$AAAA"
    ok = verify_password(req.password, user.password_hash if user else dummy)
    if not user or not ok or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    user.last_login_at = datetime.now(timezone.utc)
    repos.users.update(user)

    workspaces = _user_workspaces(user.id)
    token, _exp = create_jwt(user_id=user.id, email=user.email, workspaces=workspaces)
    return LoginResponse(access_token=token, expires_in=jwt_ttl_minutes() * 60, user=_to_public(user))


@router.get("/auth/me", response_model=UserPublic)
def me(ctx: AuthContext = Depends(current_user)) -> UserPublic:
    if ctx.kind == "anonymous":
        # auth disabled — synthesize the seeded demo owner so the frontend
        # still has a "current user" to render.
        repos = get_repos()
        demo = repos.users.find(lambda u: u.email == "owner@asura.local")
        if demo is not None:
            return _to_public(demo)
        # No demo seed yet either — return a fixed anonymous record.
        return UserPublic(
            id="anonymous", email="anonymous@asura.local", display_name="Anonymous",
            is_active=True, created_at=datetime.now(timezone.utc),
        )
    repos = get_repos()
    user = repos.users.get(ctx.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User no longer exists.")
    return _to_public(user)


@router.post("/auth/logout")
def logout(ctx: AuthContext = Depends(current_user_optional)) -> dict[str, str]:
    """Stateless logout — the frontend just drops the token. This endpoint
    exists so the UI has a single place to call and so future revocation
    lists have a hook."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# API tokens (long-lived service credentials for CI)
# ---------------------------------------------------------------------------

@router.post("/auth/tokens", response_model=ApiTokenCreated)
def create_api_token(
    req: TokenCreateRequest,
    ctx: AuthContext = Depends(current_user),
) -> ApiTokenCreated:
    """Mint a service token scoped to a specific workspace.

    The plaintext is returned exactly once. Subsequent listings show only
    metadata + prefix.
    """
    require_workspace_role(ctx, req.workspace_id, allow_roles=("owner", "admin", "member"))
    repos = get_repos()
    plaintext, digest, prefix = generate_service_token()
    now = datetime.now(timezone.utc)
    expires_at: datetime | None = None
    if req.expires_in_days:
        expires_at = now + timedelta(days=req.expires_in_days)
    user_id = ctx.user_id if ctx.kind != "anonymous" else "user-demo-owner"
    record = ApiToken(
        id=f"tok-{uuid4().hex[:10]}",
        user_id=user_id,
        workspace_id=req.workspace_id,
        name=req.name.strip() or "Untitled",
        token_hash=digest,
        prefix=prefix,
        created_at=now,
        expires_at=expires_at,
    )
    repos.api_tokens.add(record)
    return ApiTokenCreated(token=plaintext, record=_token_public(record))


@router.get("/auth/tokens", response_model=list[ApiTokenPublic])
def list_api_tokens(
    workspace_id: Optional[str] = None,
    ctx: AuthContext = Depends(current_user),
) -> list[ApiTokenPublic]:
    repos = get_repos()
    items: list[ApiToken] = []
    for tok in repos.api_tokens.list():
        if workspace_id and tok.workspace_id != workspace_id:
            continue
        if ctx.kind != "anonymous" and tok.user_id != ctx.user_id:
            continue
        items.append(tok)
    items.sort(key=lambda t: t.created_at, reverse=True)
    return [_token_public(t) for t in items]


@router.delete("/auth/tokens/{token_id}", status_code=204, response_class=Response)
def revoke_api_token(token_id: str, ctx: AuthContext = Depends(current_user)) -> Response:
    repos = get_repos()
    tok = repos.api_tokens.get(token_id)
    if tok is None:
        raise HTTPException(status_code=404, detail="Token not found.")
    if ctx.kind != "anonymous" and tok.user_id != ctx.user_id:
        require_workspace_role(ctx, tok.workspace_id, allow_roles=("owner", "admin"))
    tok.revoked_at = datetime.now(timezone.utc)
    repos.api_tokens.update(tok)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# /api/workspaces/*
# ---------------------------------------------------------------------------

@router.get("/workspaces", response_model=list[Workspace])
def list_my_workspaces(ctx: AuthContext = Depends(current_user_optional)) -> list[Workspace]:
    repos = get_repos()
    if ctx.kind == "anonymous":
        return repos.workspaces.list()
    member_ws_ids = {m.workspace_id for m in repos.memberships.list() if m.user_id == ctx.user_id}
    return [w for w in repos.workspaces.list() if w.id in member_ws_ids]


@router.get("/workspaces/{workspace_id}/members", response_model=list[WorkspaceMember])
def list_members(
    workspace_id: str,
    ctx: AuthContext = Depends(current_user_optional),
) -> list[WorkspaceMember]:
    require_workspace_role(ctx, workspace_id)
    repos = get_repos()
    out: list[WorkspaceMember] = []
    for m in repos.memberships.list():
        if m.workspace_id != workspace_id:
            continue
        user = repos.users.get(m.user_id)
        if user is None:
            continue
        out.append(WorkspaceMember(user=_to_public(user), role=m.role, joined_at=m.created_at))
    return out


@router.post("/workspaces/{workspace_id}/members", response_model=WorkspaceMember)
def invite_member(
    workspace_id: str,
    invite: InviteRequest,
    ctx: AuthContext = Depends(current_user),
) -> WorkspaceMember:
    """Add an existing user (by email) to the workspace, or create a
    placeholder user record they can later claim via SSO/password reset.

    For simplicity we create the user if missing with no password — the
    user must complete a password set/SSO link before they can log in.
    """
    require_workspace_role(ctx, workspace_id, allow_roles=("owner", "admin"))
    repos = get_repos()
    if repos.workspaces.get(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found.")

    user = repos.users.find(lambda u: u.email.lower() == invite.email.lower())
    now = datetime.now(timezone.utc)
    if user is None:
        user = User(
            id=f"user-{uuid4().hex[:12]}",
            email=invite.email.strip(),
            display_name=invite.email.split("@")[0],
            password_hash=None,        # claimed via SSO link or password reset
            is_active=True,
            created_at=now,
        )
        repos.users.add(user)
    # Idempotent: if they're already a member, return the existing row.
    existing = repos.memberships.find(
        lambda m: m.workspace_id == workspace_id and m.user_id == user.id
    )
    if existing is not None:
        return WorkspaceMember(user=_to_public(user), role=existing.role, joined_at=existing.created_at)
    membership = Membership(
        id=f"membership-{uuid4().hex[:8]}",
        workspace_id=workspace_id, user_id=user.id, role=invite.role, created_at=now,
    )
    repos.memberships.add(membership)
    return WorkspaceMember(user=_to_public(user), role=membership.role, joined_at=membership.created_at)


@router.delete("/workspaces/{workspace_id}/members/{user_id}", status_code=204, response_class=Response)
def remove_member(
    workspace_id: str,
    user_id: str,
    ctx: AuthContext = Depends(current_user),
) -> Response:
    require_workspace_role(ctx, workspace_id, allow_roles=("owner", "admin"))
    repos = get_repos()
    membership = repos.memberships.find(
        lambda m: m.workspace_id == workspace_id and m.user_id == user_id
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found.")
    if membership.role == Role.owner:
        owners = [m for m in repos.memberships.list()
                  if m.workspace_id == workspace_id and m.role == Role.owner]
        if len(owners) <= 1:
            raise HTTPException(status_code=409, detail="Cannot remove the last owner.")
    repos.memberships.delete(membership.id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# SSO / OIDC — stub
# ---------------------------------------------------------------------------

@router.get("/auth/sso/oidc/start")
def oidc_start() -> dict[str, str]:
    """Begin an OIDC PKCE flow. Real implementation lives behind
    ``ASURA_OIDC_ISSUER`` — when unset, this endpoint advertises that SSO
    isn't configured so the frontend can hide the button cleanly."""
    issuer = os.environ.get("ASURA_OIDC_ISSUER")
    if not issuer:
        raise HTTPException(
            status_code=503,
            detail="SSO not configured. Set ASURA_OIDC_ISSUER to enable.",
        )
    # TODO: implement PKCE — fetch issuer's discovery doc, build authorize
    # URL with state+nonce+code_challenge, store state in a short-lived
    # repo, return {"redirect_url": "..."}.
    raise HTTPException(status_code=501, detail="OIDC flow not yet implemented.")


@router.get("/auth/sso/oidc/callback")
def oidc_callback(code: str, state: str) -> dict[str, str]:
    """OIDC callback — exchanges `code` for tokens, validates the ID
    token, upserts the User by `sso_subject`, then redirects with a
    session JWT."""
    if not os.environ.get("ASURA_OIDC_ISSUER"):
        raise HTTPException(status_code=503, detail="SSO not configured.")
    raise HTTPException(status_code=501, detail="OIDC callback not yet implemented.")
