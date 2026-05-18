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

  if (loading) {
    return <main style={{ padding: 24 }}>Loading…</main>;
  }

  return (
    <main style={{ padding: 24, maxWidth: 720 }}>
      <nav style={{ marginBottom: 12 }}>
        <Link href="/">← Dashboard</Link>
      </nav>

      <header style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>LLM triage settings</h1>
        <p style={{ color: "var(--text-3)", margin: "6px 0 0" }}>
          PentestBrain runs deterministic clustering by default — free, no API
          calls, no key required. Configure an Anthropic API key here to
          unlock LLM-assisted clustering + false-positive scoring. The
          citation guard still discards any LLM output that references
          evidence ids the brain never handed it.
        </p>
      </header>

      <section
        style={{
          border: "1px solid var(--border-1)",
          borderRadius: 8,
          padding: 14,
          marginBottom: 18,
          background: "var(--surface-1)",
        }}
      >
        <h2 style={{ marginTop: 0 }}>Current state</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 12px", margin: 0 }}>
          <dt style={{ color: "var(--text-3)" }}>Engine:</dt>
          <dd style={{ margin: 0 }}>
            {settings?.enabled && settings?.api_key_configured ? (
              <strong style={{ color: "var(--accent-purple, #7c3aed)" }}>LLM mode</strong>
            ) : (
              <span>Deterministic (free)</span>
            )}
          </dd>
          <dt style={{ color: "var(--text-3)" }}>Provider:</dt>
          <dd style={{ margin: 0 }}>{settings?.provider ?? "anthropic"}</dd>
          <dt style={{ color: "var(--text-3)" }}>Model:</dt>
          <dd style={{ margin: 0 }}>{settings?.model}</dd>
          <dt style={{ color: "var(--text-3)" }}>API key:</dt>
          <dd style={{ margin: 0 }}>
            {settings?.api_key_configured
              ? <>Configured · <code>{settings.api_key_preview}</code></>
              : <span style={{ color: "var(--text-3)" }}>Not configured</span>}
          </dd>
        </dl>
      </section>

      <form
        onSubmit={handleSave}
        style={{
          border: "1px solid var(--border-1)",
          borderRadius: 8,
          padding: 14,
          background: "var(--surface-1)",
        }}
      >
        <h2 style={{ marginTop: 0 }}>Update settings</h2>

        <label style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14 }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span>Enable LLM-assisted triage</span>
        </label>

        <label style={{ display: "block", marginBottom: 14 }}>
          <div style={{ marginBottom: 4, color: "var(--text-2)" }}>Model</div>
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            style={{ width: "100%", padding: 6, background: "var(--surface-2)", color: "var(--text-1)", border: "1px solid var(--border-1)", borderRadius: 6 }}
          >
            {MODEL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </label>

        <label style={{ display: "block", marginBottom: 14 }}>
          <div style={{ marginBottom: 4, color: "var(--text-2)" }}>
            Anthropic API key{settings?.api_key_configured ? " (leave blank to keep the stored key)" : ""}
          </div>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={settings?.api_key_configured ? "leave blank to keep current key" : "sk-ant-..."}
            autoComplete="off"
            style={{ width: "100%", padding: 6, background: "var(--surface-2)", color: "var(--text-1)", border: "1px solid var(--border-1)", borderRadius: 6, fontFamily: "monospace" }}
          />
          <small style={{ color: "var(--text-3)" }}>
            Stored encrypted at rest. The API never returns it; only a 4-char preview.
            Get a key at <a href="https://console.anthropic.com" target="_blank" rel="noreferrer">console.anthropic.com</a>.
          </small>
        </label>

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            type="submit"
            disabled={status.kind === "saving"}
            style={{
              padding: "6px 14px",
              background: "var(--accent-purple, #7c3aed)",
              color: "white",
              border: "none",
              borderRadius: 6,
              cursor: status.kind === "saving" ? "wait" : "pointer",
            }}
          >
            {status.kind === "saving" ? "Saving…" : "Save settings"}
          </button>

          {settings?.api_key_configured ? (
            <button
              type="button"
              onClick={handleClearKey}
              disabled={status.kind === "saving"}
              style={{
                padding: "6px 14px",
                background: "transparent",
                color: "var(--danger, #f87171)",
                border: "1px solid var(--danger, #f87171)",
                borderRadius: 6,
                cursor: "pointer",
              }}
            >
              Wipe API key
            </button>
          ) : null}

          {status.kind === "saved" ? <small style={{ color: "var(--success, #34d399)" }}>Saved.</small> : null}
          {status.kind === "error" ? <small style={{ color: "var(--danger, #f87171)" }}>{status.message}</small> : null}
        </div>
      </form>

      <section style={{ marginTop: 22, fontSize: 13, color: "var(--text-3)" }}>
        <strong>Cost estimate (Anthropic pricing):</strong> a single triage call sends ~50 findings of
        metadata to the model — typically a fraction of a cent on Haiku.
        Without enabling this, every triage call uses the deterministic
        baseline at zero cost.
      </section>
    </main>
  );
}
