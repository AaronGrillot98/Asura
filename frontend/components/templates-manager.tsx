"use client";

import { useEffect, useRef, useState } from "react";
import { Eye, FileCode, Trash2, Upload } from "lucide-react";
import {
  deleteTemplate,
  listTemplates,
  templateContentUrl,
  uploadTemplate,
  type NucleiTemplate,
} from "@/lib/api";

const SEVERITY_TONE: Record<string, string> = {
  critical: "var(--sev-critical-fg)",
  high: "var(--sev-high-fg)",
  medium: "var(--sev-medium-fg)",
  low: "var(--sev-low-fg)",
  info: "var(--sev-info-fg)",
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function TemplatesManager({ initial }: { initial: NucleiTemplate[] }) {
  const [templates, setTemplates] = useState<NucleiTemplate[]>(initial);
  const [busy, setBusy] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");

  async function refresh() {
    try {
      const next = await listTemplates();
      setTemplates(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleFiles(files: FileList | File[]) {
    setError(null);
    setBusy(true);
    try {
      for (const file of Array.from(files)) {
        await uploadTemplate(file, {
          description: description.trim() || undefined,
          tags: tags.trim() || undefined,
        });
      }
      setDescription("");
      setTags("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  function onDragOver(event: React.DragEvent) {
    event.preventDefault();
    setDragOver(true);
  }

  function onDragLeave() {
    setDragOver(false);
  }

  async function onDrop(event: React.DragEvent) {
    event.preventDefault();
    setDragOver(false);
    if (event.dataTransfer.files.length > 0) {
      await handleFiles(event.dataTransfer.files);
    }
  }

  async function onPick() {
    inputRef.current?.click();
  }

  async function onInputChange(event: React.ChangeEvent<HTMLInputElement>) {
    if (event.target.files && event.target.files.length > 0) {
      await handleFiles(event.target.files);
      event.target.value = "";
    }
  }

  async function onDelete(id: string) {
    if (!confirm("Delete this template? It will be removed from disk.")) return;
    try {
      await deleteTemplate(id);
      setTemplates((cur) => cur.filter((t) => t.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  // Refresh on mount in case the server-side fetch staled. refresh is stable
  // (closure-captures setTemplates only); empty deps is intentional.
  useEffect(() => {
    void refresh();
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <section
        className="panel"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        style={{
          borderStyle: dragOver ? "solid" : "dashed",
          borderColor: dragOver ? "var(--accent)" : "var(--border-2)",
          background: dragOver ? "var(--bg-active)" : "var(--bg-2)",
          transition: "border-color var(--motion-fast), background var(--motion-fast)",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10, padding: "12px 0" }}>
          <div className="metricIcon"><Upload size={20} /></div>
          <div style={{ textAlign: "center" }}>
            <strong style={{ color: "var(--text-1)" }}>Drop YAML templates here</strong>
            <p style={{ marginTop: 4, color: "var(--text-3)", fontSize: 13 }}>
              ≤ 1 MB per file · must contain a top-level <code className="inlineCode">id:</code> field
            </p>
          </div>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".yaml,.yml,application/x-yaml,text/yaml"
            onChange={onInputChange}
            style={{ display: "none" }}
          />
          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", justifyContent: "center" }}>
            <button type="button" onClick={onPick} disabled={busy}>
              <Upload size={14} /> {busy ? "Uploading…" : "Pick a file"}
            </button>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, width: "100%", maxWidth: 560 }}>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (optional)"
              style={{ fontSize: 12 }}
            />
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="Tags (comma-separated)"
              style={{ fontSize: 12 }}
            />
          </div>
        </div>
        {error ? (
          <div role="alert" aria-live="assertive" className="banner danger" style={{ marginTop: 10, fontSize: 13 }}>
            {error}
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="panelTitle">
          <h2>Uploaded templates ({templates.length})</h2>
        </div>
        {templates.length === 0 ? (
          <div className="emptyState">
            <FileCode size={28} style={{ color: "var(--text-3)" }} />
            <strong>No templates yet</strong>
            <span style={{ color: "var(--text-3)" }}>
              Drop a Nuclei template above. Pick it on the Run-scan form when nuclei is selected.
            </span>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Display name</th>
                <th>Template ID</th>
                <th>Severity</th>
                <th>Size</th>
                <th>Tags</th>
                <th>Uploaded</th>
                <th>Hash</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {templates.map((t) => (
                <tr key={t.id}>
                  <td><strong style={{ color: "var(--text-1)" }}>{t.display_name}</strong></td>
                  <td><code className="inlineCode">{t.template_id ?? "—"}</code></td>
                  <td>
                    <small style={{ color: t.severity ? SEVERITY_TONE[t.severity] : "var(--text-3)", textTransform: "uppercase", fontWeight: 700 }}>
                      {t.severity ?? "—"}
                    </small>
                  </td>
                  <td><small>{formatBytes(t.size_bytes)}</small></td>
                  <td>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {t.tags.length === 0 ? <small style={{ color: "var(--text-3)" }}>—</small> : null}
                      {t.tags.map((tag) => (
                        <span key={tag} className="inlineCode" style={{ fontSize: 10 }}>#{tag}</span>
                      ))}
                    </div>
                  </td>
                  <td><small>{t.uploaded_at}</small></td>
                  <td><small style={{ fontFamily: "var(--font-mono)" }}>{t.content_hash.slice(0, 10)}</small></td>
                  <td style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                    <a
                      href={templateContentUrl(t.id)}
                      target="_blank"
                      rel="noreferrer"
                      title="View raw YAML"
                      style={{ color: "var(--accent)", display: "inline-flex", alignItems: "center", padding: 4 }}
                    >
                      <Eye size={14} />
                    </a>
                    <button
                      type="button"
                      onClick={() => onDelete(t.id)}
                      title="Delete template"
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
