/**
 * Client-side auth helpers.
 *
 * The token lives in a SameSite=Lax cookie so it survives a hard reload
 * and is readable by both server components (via next/headers) and
 * client-side fetches (via document.cookie). It's intentionally NOT
 * HttpOnly — the JWT is a bearer token the frontend must attach to API
 * calls, so JS needs to read it. Tradeoff: XSS-exposed. Mitigation:
 * short TTL (12h default) and the standard same-origin/CORS controls.
 */

const TOKEN_COOKIE = "asura-token";
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type AuthUser = {
  id: string;
  email: string;
  display_name: string;
  is_active: boolean;
  created_at: string;
  last_login_at?: string | null;
};

export type LoginResult = {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: AuthUser;
};

// ---------- token storage ---------------------------------------------------

export function getToken(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${TOKEN_COOKIE}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function setToken(token: string, expiresInSeconds: number): void {
  if (typeof document === "undefined") return;
  const maxAge = Math.max(60, expiresInSeconds | 0);
  document.cookie = `${TOKEN_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
}

export function clearToken(): void {
  if (typeof document === "undefined") return;
  document.cookie = `${TOKEN_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
}

// ---------- auth-aware fetch ------------------------------------------------

export function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Thin wrapper that attaches the bearer header when a token is set.
 * Falls back to a vanilla fetch when no token is present so demo (auth
 * disabled) keeps working.
 */
export async function authFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers || {});
  const token = getToken();
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return fetch(input, { ...init, headers });
}

// ---------- /api/auth/* wrappers --------------------------------------------

export async function login(email: string, password: string): Promise<LoginResult> {
  const res = await fetch(`${API_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(detail || `Login failed (${res.status})`);
  }
  const result = (await res.json()) as LoginResult;
  setToken(result.access_token, result.expires_in);
  return result;
}

export async function register(
  email: string,
  password: string,
  display_name: string,
  workspace_name?: string,
): Promise<LoginResult> {
  const res = await fetch(`${API_URL}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, display_name, workspace_name }),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(detail || `Register failed (${res.status})`);
  }
  const result = (await res.json()) as LoginResult;
  setToken(result.access_token, result.expires_in);
  return result;
}

export async function fetchCurrentUser(): Promise<AuthUser | null> {
  const token = getToken();
  if (!token) {
    // No token — try the endpoint anyway in case auth is disabled and
    // the backend will synthesize the demo user for us.
  }
  const res = await fetch(`${API_URL}/api/auth/me`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401) return null;
  if (!res.ok) throw new Error(`auth/me returned ${res.status}`);
  return (await res.json()) as AuthUser;
}

export async function logout(): Promise<void> {
  try {
    await authFetch(`${API_URL}/api/auth/logout`, { method: "POST" });
  } catch {
    // Logout is best-effort — even if the network call fails, drop the
    // local token so the UI reflects logged-out state.
  }
  clearToken();
}

// ---------- workspace + tokens (light-weight for the settings page) ---------

export type Workspace = { id: string; name: string; created_at: string };

export type WorkspaceMember = {
  user: AuthUser;
  role: "owner" | "admin" | "member" | "viewer";
  joined_at: string;
};

export type ApiTokenPublic = {
  id: string;
  name: string;
  workspace_id: string;
  prefix: string;
  created_at: string;
  expires_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
};

export type ApiTokenCreated = {
  token: string;
  record: ApiTokenPublic;
};

export async function listWorkspaces(): Promise<Workspace[]> {
  const res = await authFetch(`${API_URL}/api/workspaces`);
  if (!res.ok) throw new Error(`workspaces returned ${res.status}`);
  return res.json();
}

export async function listMembers(workspaceId: string): Promise<WorkspaceMember[]> {
  const res = await authFetch(`${API_URL}/api/workspaces/${workspaceId}/members`);
  if (!res.ok) throw new Error(`members returned ${res.status}`);
  return res.json();
}

export async function inviteMember(
  workspaceId: string,
  email: string,
  role: WorkspaceMember["role"] = "member",
): Promise<WorkspaceMember> {
  const res = await authFetch(`${API_URL}/api/workspaces/${workspaceId}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function listApiTokens(): Promise<ApiTokenPublic[]> {
  const res = await authFetch(`${API_URL}/api/auth/tokens`);
  if (!res.ok) throw new Error(`tokens returned ${res.status}`);
  return res.json();
}

export async function createApiToken(
  workspaceId: string,
  name: string,
  expiresInDays?: number,
): Promise<ApiTokenCreated> {
  const res = await authFetch(`${API_URL}/api/auth/tokens`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ workspace_id: workspaceId, name, expires_in_days: expiresInDays }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function revokeApiToken(id: string): Promise<void> {
  const res = await authFetch(`${API_URL}/api/auth/tokens/${id}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`revoke returned ${res.status}`);
}
