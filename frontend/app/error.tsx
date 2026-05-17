"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";

/**
 * Per-route error boundary. Replaces the default "Internal Server Error"
 * page with something diagnostic: the actual error message, a "is the
 * backend running?" check, and a retry button.
 */
export default function RouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const [backend, setBackend] = useState<"checking" | "ok" | "unreachable">("checking");
  const [statusText, setStatusText] = useState<string>("");

  useEffect(() => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    (async () => {
      try {
        const response = await fetch(`${apiUrl}/api/health`, { cache: "no-store" });
        if (response.ok) {
          setBackend("ok");
          setStatusText(`Backend healthy at ${apiUrl}.`);
        } else {
          setBackend("unreachable");
          setStatusText(`Backend at ${apiUrl} returned ${response.status} ${response.statusText}.`);
        }
      } catch (err) {
        setBackend("unreachable");
        setStatusText(`Could not reach ${apiUrl}: ${err instanceof Error ? err.message : String(err)}`);
      }
    })();
  }, []);

  const looksLikeFetchError =
    /fetch failed|ECONNREFUSED|getaddrinfo|Network|net::ERR|ECONNRESET|HTTP \d{3}|returned \d{3}/.test(
      error.message,
    );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <header className="topbar">
        <div>
          <span className="eyebrow">Page error</span>
          <h1>Something broke while rendering this page</h1>
          <p>
            The frontend caught an unhandled error from a server component or
            data fetch. The full error is below, plus a quick backend health
            check to narrow down the cause.
          </p>
        </div>
        <div className="topbarActions">
          <button type="button" onClick={reset} className="button">
            <RotateCw size={14} /> Retry
          </button>
          <Link href="/" className="button ghost">
            Back to Command Center
          </Link>
        </div>
      </header>

      <section className="panel">
        <div className="panelTitle">
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <AlertTriangle size={16} style={{ color: "var(--warn)" }} />
            <h2>Error detail</h2>
          </div>
          {error.digest ? (
            <small style={{ color: "var(--text-3)" }}>digest: <code className="inlineCode">{error.digest}</code></small>
          ) : null}
        </div>
        <p style={{ color: "var(--text-1)", fontWeight: 600, marginBottom: 8 }}>{error.name}</p>
        <pre style={{ background: "var(--bg-0)", border: "1px solid var(--border-1)", color: "var(--text-2)", padding: 12, borderRadius: 8, fontSize: 12, overflow: "auto", whiteSpace: "pre-wrap" }}>
{error.message}
        </pre>
      </section>

      <section className="panel">
        <div className="panelTitle">
          <h2>Backend health check</h2>
        </div>
        <p style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className={`statusDot ${backend === "ok" ? "ok" : backend === "unreachable" ? "danger" : "info"}`} />
          {backend === "checking"
            ? "Pinging the backend…"
            : statusText}
        </p>
        {(backend === "unreachable" || looksLikeFetchError) ? (
          <>
            <p style={{ marginTop: 10, color: "var(--text-2)" }}>
              The most common cause of this page is a backend that is not
              running or running stale code. Try:
            </p>
            <pre style={{ background: "var(--bg-0)", border: "1px solid var(--border-1)", color: "var(--text-2)", padding: 12, borderRadius: 8, fontSize: 12, marginTop: 8 }}>
{`# from the asura/backend directory
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# if "address already in use" — an old uvicorn is still running.
# Windows:   tasklist | findstr python   →   taskkill /F /PID <pid>
# macOS/Linux:  lsof -i :8000   →   kill -9 <pid>`}
            </pre>
          </>
        ) : null}
      </section>
    </div>
  );
}
