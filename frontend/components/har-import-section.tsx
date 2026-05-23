"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Upload, Globe, Lock, FileCode2 } from "lucide-react";
import { importHar, type HarImportSummary } from "@/lib/api";


type Status =
  | { kind: "idle" }
  | { kind: "uploading" }
  | { kind: "error"; message: string }
  | { kind: "ok"; summary: HarImportSummary };


export function HarImportSection({ projectId }: { projectId: string }) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [respectScope, setRespectScope] = useState(true);

  async function onPick(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setStatus({ kind: "uploading" });
    try {
      const summary = await importHar(projectId, file, { respectScope });
      setStatus({ kind: "ok", summary });
      router.refresh();
    } catch (err) {
      setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    } finally {
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  return (
    <section className="panel">
      <div className="panelTitle">
        <h2>Import HAR capture</h2>
        <small>From Burp, mitmproxy, Caido, or browser DevTools.</small>
      </div>

      <p className="muted" style={{ marginBottom: "var(--space-3)" }}>
        Browse the target through a proxy, export the captured traffic as
        HAR, and upload it here. Asura parses every request, deduplicates
        hosts, surfaces auth-protected paths (401 / 403), and creates one{" "}
        <strong>Target</strong> per unique host so you can run scanners
        against them. Endpoint catalog + JS file inventory come back in
        the summary.
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--space-3)", alignItems: "center" }}>
        <input
          ref={inputRef}
          type="file"
          accept=".har,application/json"
          onChange={onPick}
          style={{ display: "none" }}
        />
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          disabled={status.kind === "uploading"}
        >
          <Upload size={14} /> {status.kind === "uploading" ? "Importing…" : "Upload .har file"}
        </button>
        <label className="checkboxField">
          <input
            type="checkbox"
            checked={respectScope}
            onChange={(e) => setRespectScope(e.target.checked)}
          />
          <span>Skip hosts outside project scope</span>
        </label>
      </div>

      {status.kind === "error" ? (
        <div role="alert" aria-live="assertive" className="banner danger" style={{ marginTop: "var(--space-3)" }}>{status.message}</div>
      ) : null}

      {status.kind === "ok" ? (
        <div style={{ marginTop: "var(--space-4)", display: "grid", gap: "var(--space-3)" }}>
          <div role="status" aria-live="polite" className="banner info">
            Processed <strong>{status.summary.entries_processed}</strong> request(s).{" "}
            <strong>{status.summary.new_targets.length}</strong> new target(s) created.{" "}
            <strong>{status.summary.endpoints.length}</strong> unique endpoint(s).
          </div>

          <div className="metrics" style={{ gridTemplateColumns: "repeat(4, minmax(0, 1fr))" }}>
            <Metric icon={<Globe size={14} />} label="Hosts" value={status.summary.hosts.length} />
            <Metric icon={<Upload size={14} />} label="Endpoints" value={status.summary.endpoints.length} />
            <Metric icon={<Lock size={14} />} label="Auth-required" value={status.summary.auth_required_paths.length} />
            <Metric icon={<FileCode2 size={14} />} label="JS files" value={status.summary.js_files.length} />
          </div>

          {status.summary.hosts.length > 0 ? (
            <details>
              <summary className="muted" style={{ cursor: "pointer" }}>
                Hosts ({status.summary.hosts.length})
              </summary>
              <ul style={{ marginTop: "var(--space-2)", display: "grid", gap: 2, listStyle: "none", padding: 0 }}>
                {status.summary.hosts.map((h) => (
                  <li key={h}>
                    <code className="inlineCode">{h}</code>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}

          {status.summary.auth_required_paths.length > 0 ? (
            <details>
              <summary className="muted" style={{ cursor: "pointer" }}>
                Auth-required paths ({status.summary.auth_required_paths.length})
              </summary>
              <ul style={{ marginTop: "var(--space-2)", display: "grid", gap: 2, listStyle: "none", padding: 0 }}>
                {status.summary.auth_required_paths.slice(0, 50).map((p) => (
                  <li key={p}>
                    <code className="inlineCode">{p}</code>
                  </li>
                ))}
                {status.summary.auth_required_paths.length > 50 ? (
                  <li className="muted">
                    …and {status.summary.auth_required_paths.length - 50} more.
                  </li>
                ) : null}
              </ul>
            </details>
          ) : null}

          {status.summary.endpoints.length > 0 ? (
            <details>
              <summary className="muted" style={{ cursor: "pointer" }}>
                Endpoint catalog ({status.summary.endpoints.length})
              </summary>
              <div style={{ marginTop: "var(--space-2)", maxHeight: 320, overflowY: "auto", border: "1px solid var(--border-1)", borderRadius: "var(--radius)" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Host</th>
                      <th>Path</th>
                      <th>Status</th>
                      <th>Params</th>
                      <th>Hits</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.summary.endpoints.slice(0, 200).map((e) => (
                      <tr key={`${e.method}-${e.host}-${e.path}`}>
                        <td><code className="inlineCode">{e.method}</code></td>
                        <td>{e.host}</td>
                        <td><code className="inlineCode">{e.path}</code></td>
                        <td>{e.status_codes.join(", ") || "—"}</td>
                        <td>{e.param_names.length > 0 ? e.param_names.join(", ") : <span className="muted">—</span>}</td>
                        <td>{e.seen_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {status.summary.endpoints.length > 200 ? (
                  <p className="muted" style={{ padding: "var(--space-2)" }}>
                    Showing first 200 of {status.summary.endpoints.length}.
                  </p>
                ) : null}
              </div>
            </details>
          ) : null}

          {status.summary.skipped.length > 0 ? (
            <details>
              <summary className="muted" style={{ cursor: "pointer" }}>
                Skipped ({status.summary.skipped.length})
              </summary>
              <ul style={{ marginTop: "var(--space-2)", display: "grid", gap: 2, listStyle: "none", padding: 0, color: "var(--text-3)", fontSize: "var(--text-sm)" }}>
                {status.summary.skipped.slice(0, 30).map((s, i) => (
                  <li key={`${i}-${s}`}>{s}</li>
                ))}
                {status.summary.skipped.length > 30 ? (
                  <li>…and {status.summary.skipped.length - 30} more.</li>
                ) : null}
              </ul>
            </details>
          ) : null}
        </div>
      ) : null}

      <p className="muted" style={{ marginTop: "var(--space-4)", fontSize: "var(--text-sm)" }}>
        <strong>Export tips:</strong> Burp Pro → Project options → Misc → Logger → Save as HAR.
        mitmproxy → <code className="inlineCode">mitmdump --set hardump=capture.har</code>.
        Chrome DevTools → Network tab → right-click → Save all as HAR with content.
      </p>
    </section>
  );
}


function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="metric">
      <span>
        <span style={{ marginRight: 6, verticalAlign: "middle" }}>{icon}</span>
        {label}
      </span>
      <strong>{value}</strong>
    </div>
  );
}
