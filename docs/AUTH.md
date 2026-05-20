# Auth + multi-user workspaces

ASURA ships its own access control system: local password auth, JWT
session tokens, long-lived service tokens for CI, role-scoped workspace
membership, and a SSO/OIDC stub ready to wire to your IdP.

## Quick start

By default `ASURA_AUTH_DISABLED=1` so the seeded demo flow runs without
any login. To turn auth on:

```bash
export ASURA_AUTH_DISABLED=0
export ASURA_JWT_SECRET="change-this-to-a-strong-random-string"
# optional — 12h is the default session TTL
export ASURA_JWT_TTL_MIN=720
```

Then sign in with the seeded demo owner:

| Field    | Value                |
|----------|----------------------|
| Email    | `owner@asura.local`  |
| Password | `asura`              |

…or hit `POST /api/auth/register` from a fresh deployment to create the
founding owner with your own credentials. (Registration is open *only*
when the system has no users yet; subsequent members must be invited.)

## Roles

| Role     | Can do                                                             |
|----------|--------------------------------------------------------------------|
| `owner`  | Everything in the workspace, including transferring or deleting it |
| `admin`  | Invite + remove members, mint service tokens, edit projects        |
| `member` | Read/write project data, run scans, ingest SARIF                   |
| `viewer` | Read-only access                                                   |

The last owner of a workspace can't be removed — promote someone else
first.

## Endpoints

```
POST /api/auth/register                              # founding-owner bootstrap
POST /api/auth/login                                 # email/password -> JWT
POST /api/auth/logout                                # stateless drop
GET  /api/auth/me                                    # validate token, return user
POST /api/auth/tokens                                # mint service token
GET  /api/auth/tokens                                # list your tokens
DELETE /api/auth/tokens/<id>                         # revoke

GET  /api/workspaces                                 # workspaces I'm a member of
GET  /api/workspaces/<id>/members
POST /api/workspaces/<id>/members                    # invite (admin+)
DELETE /api/workspaces/<id>/members/<user_id>        # remove (admin+)

GET  /api/auth/sso/oidc/start                        # 503 until OIDC configured
GET  /api/auth/sso/oidc/callback                     # 501 — stub
```

All bearer-protected endpoints accept either:

- **Session JWT** — `Authorization: Bearer eyJ…` (12h default TTL)
- **Service token** — `Authorization: Bearer asura_st_…` (no TTL by
  default; opt-in expiry via `expires_in_days`)

## Service tokens — the CI integration story

```bash
# Mint once (token plaintext shown only this one time)
curl -fsSL -X POST "$ASURA/api/auth/tokens" \
     -H "Authorization: Bearer $SESSION_JWT" \
     -H "Content-Type: application/json" \
     -d '{"name":"github-actions","workspace_id":"workspace-demo","expires_in_days":365}'
# -> { "token": "asura_st_…", "record": { ... } }

# Use it from CI for SARIF ingest (see docs/SARIF.md)
curl -fsSL -X POST "$ASURA/api/projects/$PROJECT/imports/sarif" \
     -H "Authorization: Bearer asura_st_…" \
     -H 'Content-Type: application/sarif+json' \
     --data-binary @semgrep.sarif
```

The plaintext is **only** returned at creation time; afterwards we store
a SHA-256 hash plus an 8-char prefix for the listing UI. To revoke, hit
`DELETE /api/auth/tokens/<id>` — the bearer middleware checks
`revoked_at` and `expires_at` on every request.

## Password storage

PBKDF2-HMAC-SHA256, **600 000 iterations** (OWASP 2023 guidance), 16-byte
salt, 32-byte digest. Format mirrors Django's so we can migrate to
passlib later without re-hashing:

```
pbkdf2_sha256$600000$<salt-base64>$<digest-base64>
```

Verification uses `hmac.compare_digest` so login timing doesn't leak
whether the email matched.

## SSO / OIDC

Stub endpoints live under `/api/auth/sso/oidc/*`. They return 503 until
`ASURA_OIDC_ISSUER` is set, then 501 (not yet implemented). The
real implementation lands in a follow-up slice — the on-disk skeleton
is in [backend/app/api/auth_routes.py](../backend/app/api/auth_routes.py).

When implemented, the flow will be standard PKCE:
1. Frontend calls `GET /api/auth/sso/oidc/start` → backend builds
   authorize URL with state + nonce + code_challenge, returns redirect.
2. IdP redirects back to `GET /api/auth/sso/oidc/callback?code=…&state=…`.
3. Backend exchanges code for tokens, validates the ID token signature,
   upserts the `User` row by `(sso_issuer, sso_subject)`, mints a
   session JWT and redirects to `/`.

## Environment variables

| Var                     | Default                       | Notes                                              |
|-------------------------|-------------------------------|----------------------------------------------------|
| `ASURA_AUTH_DISABLED`   | `1`                           | `0` to require auth; keep `1` for demo            |
| `ASURA_JWT_SECRET`      | `asura-dev-secret-CHANGE-ME`  | **Must** be overridden in production               |
| `ASURA_JWT_TTL_MIN`     | `720` (12h)                   | Session TTL in minutes                             |
| `ASURA_OIDC_ISSUER`     | unset                         | When set, SSO endpoints become available           |
