"use client";

import { useEffect, useState } from "react";
import { ASURA_API_URL } from "@/lib/api";

type Health =
  | { kind: "checking" }
  | { kind: "ok"; latencyMs: number }
  | { kind: "stale"; detail: string }
  | { kind: "down"; detail: string };

/**
 * Polls `/api/health` every 12s. Shows a coloured dot in the sidebar
 * footer + a hover tooltip with detail. If the backend is unreachable,
 * the dot goes red and the tooltip surfaces the actual error so the
 * user knows immediately to restart their uvicorn.
 */
export function BackendHealth() {
  const [health, setHealth] = useState<Health>({ kind: "checking" });

  useEffect(() => {
    let cancelled = false;

    async function ping() {
      const started = performance.now();
      try {
        const response = await fetch(`${ASURA_API_URL}/api/health`, {
          cache: "no-store",
          signal: AbortSignal.timeout(5000),
        });
        const latencyMs = Math.round(performance.now() - started);
        if (!response.ok) {
          if (!cancelled) {
            setHealth({
              kind: "stale",
              detail: `HTTP ${response.status} from /api/health (${latencyMs}ms)`,
            });
          }
          return;
        }
        const body = (await response.json()) as { status?: string; service?: string };
        if (body.status === "ok") {
          if (!cancelled) setHealth({ kind: "ok", latencyMs });
        } else {
          if (!cancelled) {
            setHealth({ kind: "stale", detail: `Unexpected health body: ${JSON.stringify(body)}` });
          }
        }
      } catch (err) {
        if (!cancelled) {
          setHealth({
            kind: "down",
            detail:
              err instanceof Error
                ? `${err.name}: ${err.message}`
                : String(err),
          });
        }
      }
    }

    ping();
    const interval = setInterval(ping, 12_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  let label = "Checking…";
  let dotClass = "info";
  let tooltip = "Pinging the backend";
  if (health.kind === "ok") {
    label = `API ${health.latencyMs}ms`;
    dotClass = "ok";
    tooltip = `Backend healthy at ${ASURA_API_URL} (${health.latencyMs}ms)`;
  } else if (health.kind === "stale") {
    label = "API stale";
    dotClass = "warn";
    tooltip = health.detail;
  } else if (health.kind === "down") {
    label = "API offline";
    dotClass = "danger";
    tooltip = `Cannot reach ${ASURA_API_URL}. ${health.detail}. Start the backend: \`uvicorn app.main:app\`.`;
  }

  return (
    <div
      title={tooltip}
      aria-label={tooltip}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        color: "var(--text-3)",
        fontSize: 11,
        textTransform: "uppercase",
        letterSpacing: "0.1em",
        fontWeight: 700,
        cursor: "help",
      }}
    >
      <span className={`statusDot ${dotClass}`} />
      <span>{label}</span>
    </div>
  );
}
