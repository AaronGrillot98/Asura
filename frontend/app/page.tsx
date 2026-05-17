import Link from "next/link";
import { Dashboard } from "@/components/dashboard";
import { getArsenal, getDashboard, type ArsenalSummary, type DashboardSummary } from "@/lib/api";

export const dynamic = "force-dynamic";

type FetchResult<T> = { ok: T } | { error: string };

async function safeFetch<T>(fn: () => Promise<T>): Promise<FetchResult<T>> {
  try {
    return { ok: await fn() };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

export default async function Home() {
  const [dashResult, arsenalResult] = await Promise.all([
    safeFetch<DashboardSummary>(() => getDashboard()),
    safeFetch<ArsenalSummary>(() => getArsenal()),
  ]);

  // If both failed, render a focused diagnostic instead of crashing the route.
  if ("error" in dashResult && "error" in arsenalResult) {
    return (
      <div>
        <header className="topbar">
          <div>
            <span className="eyebrow">Command Center</span>
            <h1>Backend unreachable</h1>
            <p>
              Neither the dashboard nor the arsenal endpoint responded. Start
              the backend, then click Retry.
            </p>
          </div>
          <Link href="/" className="button">Retry</Link>
        </header>
        <section className="panel">
          <div className="panelTitle">
            <h2>Why this happened</h2>
          </div>
          <p>
            Two server-side fetches both failed. The most common cause is the
            FastAPI backend not running, or running an older build that
            doesn&apos;t expose the routes the dashboard requires.
          </p>
          <pre style={{ background: "var(--bg-0)", border: "1px solid var(--border-1)", color: "var(--text-2)", padding: 12, borderRadius: 8, fontSize: 12, marginTop: 12, overflow: "auto" }}>
{`# /api/dashboard/demo  →  ${dashResult.error}
# /api/arsenal         →  ${arsenalResult.error}

# Start (or restart) the backend with the latest code:
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Already running? Kill the stale one first:
#   Windows:  netstat -ano | findstr :8000   →   taskkill /F /PID <pid>
#   macOS/Linux:  lsof -i :8000  →  kill -9 <pid>`}
          </pre>
        </section>
      </div>
    );
  }

  // If only the arsenal failed, the dashboard can still render with an empty
  // arsenal — degrades gracefully rather than crashing.
  const dashboard: DashboardSummary | null = "ok" in dashResult ? dashResult.ok : null;
  const arsenal: ArsenalSummary = "ok" in arsenalResult
    ? arsenalResult.ok
    : { tools: [], packs: [], pack_summaries: [], blocked_policy: [], blocked_capabilities: [] };

  if (!dashboard) {
    // dashboard fetch failed but arsenal is up — explain succinctly.
    return (
      <div>
        <header className="topbar">
          <div>
            <span className="eyebrow">Command Center</span>
            <h1>Dashboard endpoint failed</h1>
            <p>{(dashResult as { error: string }).error}</p>
          </div>
          <Link href="/" className="button">Retry</Link>
        </header>
        <section className="panel">
          <p>
            The arsenal endpoint is healthy, so partial backend coverage is
            available. Try restarting the backend and the dashboard should
            return.
          </p>
        </section>
      </div>
    );
  }

  return <Dashboard data={dashboard} arsenal={arsenal} />;
}
