"use client";

import { useEffect, useState } from "react";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import {
  createAuthProfile,
  deleteAuthProfile,
  listAuthProfiles,
  type AuthProfile,
  type AuthProfileCreate,
  type AuthType,
} from "@/lib/api";

const TYPE_LABEL: Record<AuthType, string> = {
  bearer: "Bearer token",
  basic: "Basic (user / password)",
  header: "Custom header",
  cookie: "Cookie",
};

export function AuthProfilesManager({ initial }: { initial: AuthProfile[] }) {
  const [profiles, setProfiles] = useState<AuthProfile[]>(initial);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<AuthProfileCreate>({
    name: "",
    auth_type: "bearer",
    target_match: "",
    description: "",
    token: "",
    username: "",
    password: "",
    header_name: "",
    header_value: "",
    cookie: "",
  });

  async function refresh() {
    try {
      setProfiles(await listAuthProfiles());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!form.name.trim()) {
      setError("Name is required.");
      return;
    }
    setBusy(true);
    try {
      // Only send the fields relevant to the selected auth_type so we don't
      // include empty strings that confuse validation.
      const payload: AuthProfileCreate = {
        name: form.name.trim(),
        auth_type: form.auth_type,
        target_match: form.target_match?.trim() || null,
        description: form.description?.trim() || null,
      };
      if (form.auth_type === "bearer") payload.token = form.token?.trim();
      if (form.auth_type === "basic") {
        payload.username = form.username?.trim();
        payload.password = form.password ?? "";
      }
      if (form.auth_type === "header") {
        payload.header_name = form.header_name?.trim();
        payload.header_value = form.header_value ?? "";
      }
      if (form.auth_type === "cookie") payload.cookie = form.cookie ?? "";
      await createAuthProfile(payload);
      setForm({
        ...form,
        name: "",
        token: "",
        username: "",
        password: "",
        header_name: "",
        header_value: "",
        cookie: "",
      });
      setOpen(false);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!confirm("Delete this auth profile? The encrypted file on disk will be removed.")) return;
    try {
      await deleteAuthProfile(id);
      setProfiles((cur) => cur.filter((p) => p.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {error ? (
        <div className="banner danger" style={{ fontSize: 13 }}>{error}</div>
      ) : null}

      <section className="panel">
        <div className="panelTitle" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Profiles ({profiles.length})</h2>
          {open ? null : (
            <button type="button" onClick={() => setOpen(true)}>
              <Plus size={14} /> New profile
            </button>
          )}
        </div>

        {open ? (
          <form
            onSubmit={onSubmit}
            style={{ display: "grid", gap: 10, border: "1px solid var(--border-1)", borderRadius: 8, padding: 12, marginBottom: 14 }}
          >
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <label style={{ display: "grid", gap: 4 }}>
                <span style={{ color: "var(--text-3)", fontSize: 12 }}>Name</span>
                <input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g. Acme staging bearer"
                />
              </label>
              <label style={{ display: "grid", gap: 4 }}>
                <span style={{ color: "var(--text-3)", fontSize: 12 }}>Type</span>
                <select
                  value={form.auth_type}
                  onChange={(e) => setForm({ ...form, auth_type: e.target.value as AuthType })}
                  style={{ height: 38 }}
                >
                  {(Object.keys(TYPE_LABEL) as AuthType[]).map((k) => (
                    <option key={k} value={k}>{TYPE_LABEL[k]}</option>
                  ))}
                </select>
              </label>
            </div>

            {form.auth_type === "bearer" ? (
              <label style={{ display: "grid", gap: 4 }}>
                <span style={{ color: "var(--text-3)", fontSize: 12 }}>Token</span>
                <input
                  type="password"
                  value={form.token ?? ""}
                  onChange={(e) => setForm({ ...form, token: e.target.value })}
                  placeholder="eyJhbGciOi..."
                />
              </label>
            ) : null}
            {form.auth_type === "basic" ? (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <label style={{ display: "grid", gap: 4 }}>
                  <span style={{ color: "var(--text-3)", fontSize: 12 }}>Username</span>
                  <input value={form.username ?? ""} onChange={(e) => setForm({ ...form, username: e.target.value })} />
                </label>
                <label style={{ display: "grid", gap: 4 }}>
                  <span style={{ color: "var(--text-3)", fontSize: 12 }}>Password</span>
                  <input type="password" value={form.password ?? ""} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                </label>
              </div>
            ) : null}
            {form.auth_type === "header" ? (
              <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 10 }}>
                <label style={{ display: "grid", gap: 4 }}>
                  <span style={{ color: "var(--text-3)", fontSize: 12 }}>Header name</span>
                  <input value={form.header_name ?? ""} onChange={(e) => setForm({ ...form, header_name: e.target.value })} placeholder="X-Api-Key" />
                </label>
                <label style={{ display: "grid", gap: 4 }}>
                  <span style={{ color: "var(--text-3)", fontSize: 12 }}>Header value</span>
                  <input type="password" value={form.header_value ?? ""} onChange={(e) => setForm({ ...form, header_value: e.target.value })} />
                </label>
              </div>
            ) : null}
            {form.auth_type === "cookie" ? (
              <label style={{ display: "grid", gap: 4 }}>
                <span style={{ color: "var(--text-3)", fontSize: 12 }}>Cookie</span>
                <input
                  type="password"
                  value={form.cookie ?? ""}
                  onChange={(e) => setForm({ ...form, cookie: e.target.value })}
                  placeholder="session=abc123; logged_in=true"
                />
              </label>
            ) : null}

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <label style={{ display: "grid", gap: 4 }}>
                <span style={{ color: "var(--text-3)", fontSize: 12 }}>Target match (optional)</span>
                <input
                  value={form.target_match ?? ""}
                  onChange={(e) => setForm({ ...form, target_match: e.target.value })}
                  placeholder="https://staging.acme.example"
                />
              </label>
              <label style={{ display: "grid", gap: 4 }}>
                <span style={{ color: "var(--text-3)", fontSize: 12 }}>Description (optional)</span>
                <input
                  value={form.description ?? ""}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Used by the bug bounty engagement"
                />
              </label>
            </div>

            <div style={{ display: "flex", gap: 8 }}>
              <button type="submit" disabled={busy}>
                {busy ? "Saving…" : "Save profile"}
              </button>
              <button
                type="button"
                className="button ghost"
                onClick={() => { setOpen(false); setError(null); }}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : null}

        {profiles.length === 0 ? (
          <div className="emptyState">
            <KeyRound size={28} style={{ color: "var(--text-3)" }} />
            <strong>No auth profiles yet</strong>
            <span style={{ color: "var(--text-3)" }}>
              Click <strong>New profile</strong> to capture a Bearer token, Basic auth, custom
              header, or Cookie value. Profiles are stored Fernet-encrypted on the
              backend; the API only returns a 4-char preview.
            </span>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Preview</th>
                <th>Target match</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {profiles.map((p) => (
                <tr key={p.id}>
                  <td><strong style={{ color: "var(--text-1)" }}>{p.name}</strong></td>
                  <td><small>{TYPE_LABEL[p.auth_type]}</small></td>
                  <td><code className="inlineCode">{p.credential_preview}</code></td>
                  <td><small>{p.target_match ?? "—"}</small></td>
                  <td><small>{p.created_at}</small></td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      type="button"
                      onClick={() => onDelete(p.id)}
                      title="Delete profile"
                      style={{ background: "transparent", color: "var(--danger)", border: 0, cursor: "pointer", padding: 4, height: "auto" }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
