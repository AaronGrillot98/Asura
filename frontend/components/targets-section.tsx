"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  addTarget,
  deleteTarget,
  type Target,
  type TargetCreate,
} from "@/lib/api";

const KINDS: TargetCreate["kind"][] = [
  "url",
  "host",
  "domain",
  "ip",
  "cidr",
  "repo",
  "container",
  "api_spec",
];

export function TargetsSection({ projectId, initial }: { projectId: string; initial: Target[] }) {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>(initial);
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<TargetCreate["kind"]>("url");
  const [value, setValue] = useState("");
  const [authorized, setAuthorized] = useState(true);
  const [ownedInternal, setOwnedInternal] = useState(false);
  const [labMode, setLabMode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onAdd(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!value.trim()) {
      setError("Target value is required.");
      return;
    }
    setBusy(true);
    try {
      const created = await addTarget(projectId, {
        kind,
        value: value.trim(),
        authorized,
        owned_internal: ownedInternal,
        lab_mode_enabled: labMode,
      });
      setTargets((prev) => [...prev, created]);
      setValue("");
      setOpen(false);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(targetId: string) {
    if (!confirm("Remove this target? The project's scope rules stay intact.")) {
      return;
    }
    try {
      await deleteTarget(projectId, targetId);
      setTargets((prev) => prev.filter((t) => t.id !== targetId));
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <section className="panel">
      <div className="panelTitle" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>Targets ({targets.length})</h2>
        {open ? null : (
          <button type="button" className="button" onClick={() => setOpen(true)}>
            <Plus size={14} /> Add target
          </button>
        )}
      </div>

      {error ? (
        <div className="banner danger" style={{ marginBottom: "var(--space-3)" }}>{error}</div>
      ) : null}

      {open ? (
        <form onSubmit={onAdd} style={{ display: "grid", gap: 10, marginBottom: 14, padding: 10, border: "1px solid #1f2937", borderRadius: 8 }}>
          <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 10 }}>
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ color: "#94a3b8", fontSize: 12 }}>Kind</span>
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value as TargetCreate["kind"])}
                style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13, height: 40 }}
              >
                {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </label>
            <label style={{ display: "grid", gap: 4 }}>
              <span style={{ color: "#94a3b8", fontSize: 12 }}>Value</span>
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="https://example.com, edge-01.example.com, 10.0.0.0/24, git://example/repo, ghcr.io/example/img:latest"
                style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13 }}
              />
            </label>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 13, color: "#cbd5e1" }}>
            <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              Authorized: I have permission to test this target.
            </label>
            <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <input type="checkbox" checked={ownedInternal} onChange={(e) => setOwnedInternal(e.target.checked)} />
              Owned / internal — required for active scans against private IPs.
            </label>
            <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <input type="checkbox" checked={labMode} onChange={(e) => setLabMode(e.target.checked)} />
              Lab-mode enabled — intentionally vulnerable lab / CTF / training target.
            </label>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button type="submit" className="button" disabled={busy}>
              {busy ? "Saving…" : "Save target"}
            </button>
            <button type="button" className="button" style={{ background: "#1f2937", color: "#e8eef6" }} onClick={() => { setOpen(false); setError(null); }}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      {targets.length === 0 ? (
        <div className="emptyState">
          No targets yet. Add one to start scanning — the project&apos;s scope
          rules will gate every scanner before it runs.
        </div>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "#94a3b8", fontSize: 12 }}>
              <th style={{ padding: "8px 6px" }}>Kind</th>
              <th style={{ padding: "8px 6px" }}>Value</th>
              <th style={{ padding: "8px 6px" }}>Authorized</th>
              <th style={{ padding: "8px 6px" }}>Owned</th>
              <th style={{ padding: "8px 6px" }}>Lab</th>
              <th style={{ padding: "8px 6px" }}></th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} style={{ borderTop: "1px solid #1f2937" }}>
                <td style={{ padding: "8px 6px" }}><code className="inlineCode">{t.kind}</code></td>
                <td style={{ padding: "8px 6px", color: "#cbd5e1", fontSize: 13 }}>{t.value}</td>
                <td style={{ padding: "8px 6px", color: t.authorized ? "#86efac" : "#fca5a5", fontSize: 12 }}>{t.authorized ? "yes" : "no"}</td>
                <td style={{ padding: "8px 6px", color: "#94a3b8", fontSize: 12 }}>{t.owned_internal ? "yes" : "—"}</td>
                <td style={{ padding: "8px 6px", color: "#94a3b8", fontSize: 12 }}>{t.lab_mode_enabled ? "yes" : "—"}</td>
                <td style={{ padding: "8px 6px", textAlign: "right" }}>
                  <button
                    type="button"
                    onClick={() => onDelete(t.id)}
                    style={{ background: "transparent", color: "#fca5a5", border: 0, cursor: "pointer", padding: 4 }}
                    title="Remove target"
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
  );
}
