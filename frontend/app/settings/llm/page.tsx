"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  deleteLLMSettings,
  getLLMSettings,
  updateLLMSettings,
  type LLMSettings,
} from "@/lib/api";


const MODEL_OPTIONS = [
  { value: "claude-haiku-4-5-20251001", label: "Claude Haiku 4.5 — fast + cheap (recommended)" },
  { value: "claude-sonnet-4-6", label: "Claude Sonnet 4.6 — higher quality" },
  { value: "claude-opus-4-7", label: "Claude Opus 4.7 — best for hard clusters" },
];

type Status =
  | { kind: "idle" }
  | { kind: "saving" }
  | { kind: "saved" }
  | { kind: "error"; message: string };


export default function LLMSettingsPage() {
  const [settings, setSettings] = useState<LLMSettings | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [model, setModel] = useState(MODEL_OPTIONS[0].value);
  const [apiKey, setApiKey] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const current = await getLLMSettings();
        if (cancelled) return;
        setSettings(current);
        setEnabled(current.enabled);
        setModel(current.model);
      } catch (err) {
        if (!cancelled) {
          setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setStatus({ kind: "saving" });
    try {
      const next = await updateLLMSettings({
        enabled,
        model,
        api_key: apiKey === "" ? null : apiKey,
      });
      setSettings(next);
      setEnabled(next.enabled);
      setModel(next.model);
      setApiKey("");
      setStatus({ kind: "saved" });
    } catch (err) {
      setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  async function handleClearKey() {
    if (!confirm("Wipe the stored API key? You'll need to re-enter it to enable LLM triage again.")) {
      return;
    }
    setStatus({ kind: "saving" });
    try {
      await deleteLLMSettings();
      const next = await getLLMSettings();
      setSettings(next);
      setEnabled(next.enabled);
      setModel(next.model);
      setApiKey("");
      setStatus({ kind: "saved" });
    } catch (err) {
      setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Settings</span>
          <h1>LLM triage</h1>
          <p>
            PentestBrain runs deterministic clustering by default — free, no API
            calls, no key required. Configure an Anthropic API key here to
            unlock LLM-assisted clustering + false-positive scoring. The
            citation guard still discards any LLM output that references
            evidence ids the brain never handed it.
          </p>
        </div>
      </header>

      {loading ? (
        <div className="loadingState">
          <span className="spinner" />
          <span>Loading settings…</span>
        </div>
      ) : (
        <div className="grid two" style={{ display: "grid", gap: "var(--space-4)", gridTemplateColumns: "1fr 1fr" }}>
          <section className="panel">
            <div className="panelTitle">
              <h2>Current state</h2>
              <span className={`tag ${settings?.enabled && settings?.api_key_configured ? "accent" : ""}`}>
                {settings?.enabled && settings?.api_key_configured ? "LLM mode" : "Deterministic"}
              </span>
            </div>
            <dl className="kvList">
              <dt>Provider</dt>
              <dd>{settings?.provider ?? "anthropic"}</dd>
              <dt>Model</dt>
              <dd>{settings?.model}</dd>
              <dt>API key</dt>
              <dd>
                {settings?.api_key_configured ? (
                  <>Configured · <code>{settings.api_key_preview}</code></>
                ) : (
                  <span className="muted">Not configured</span>
                )}
              </dd>
              {settings?.updated_at ? (
                <>
                  <dt>Updated</dt>
                  <dd className="muted" style={{ fontSize: "var(--text-sm)" }}>
                    {new Date(settings.updated_at).toLocaleString()}
                  </dd>
                </>
              ) : null}
            </dl>
            <p className="muted" style={{ marginTop: "var(--space-3)", fontSize: "var(--text-sm)" }}>
              A single triage call sends ~50 findings of metadata to the model —
              typically a fraction of a cent on Haiku.
            </p>
          </section>

          <section className="panel">
            <div className="panelTitle">
              <h2>Update settings</h2>
            </div>
            <form onSubmit={handleSave} className="formCard" style={{ background: "transparent", padding: 0, border: 0 }}>
              <label className="checkboxField">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                <span>Enable LLM-assisted triage</span>
              </label>

              <div className="formField">
                <span className="formLabel">Model</span>
                <select value={model} onChange={(e) => setModel(e.target.value)}>
                  {MODEL_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>

              <div className="formField">
                <span className="formLabel">
                  Anthropic API key
                  {settings?.api_key_configured ? " (leave blank to keep the stored key)" : ""}
                </span>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={settings?.api_key_configured ? "leave blank to keep current key" : "sk-ant-..."}
                  autoComplete="off"
                  style={{ fontFamily: "var(--font-mono)" }}
                />
                <span className="helpText">
                  Stored encrypted at rest. The API never returns it; only a 4-char preview.
                  Get a key at{" "}
                  <a href="https://console.anthropic.com" target="_blank" rel="noreferrer">
                    console.anthropic.com
                  </a>.
                </span>
              </div>

              <div className="formActions">
                <button type="submit" disabled={status.kind === "saving"}>
                  {status.kind === "saving" ? "Saving…" : "Save settings"}
                </button>
                {settings?.api_key_configured ? (
                  <button
                    type="button"
                    className="button danger"
                    onClick={handleClearKey}
                    disabled={status.kind === "saving"}
                  >
                    Wipe API key
                  </button>
                ) : null}
                {status.kind === "saved" ? (
                  <span className="statusText ok">Saved.</span>
                ) : null}
                {status.kind === "error" ? (
                  <span className="statusText danger">{status.message}</span>
                ) : null}
              </div>
            </form>
          </section>
        </div>
      )}

      <p className="muted" style={{ marginTop: "var(--space-4)", fontSize: "var(--text-sm)" }}>
        Headless deployments can configure the same toggle via the{" "}
        <code className="inlineCode">ASURA_LLM_TRIAGE</code> and{" "}
        <code className="inlineCode">ANTHROPIC_API_KEY</code> environment variables.
        UI settings take precedence when both are set. See{" "}
        <Link href="/">the Command Center</Link> for what triage actually
        looks like on a project.
      </p>
    </div>
  );
}
