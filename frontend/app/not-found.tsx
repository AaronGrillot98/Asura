import Link from "next/link";
import { Compass } from "lucide-react";

export default function NotFound() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <header className="topbar">
        <div>
          <span className="eyebrow">404</span>
          <h1>Not found</h1>
          <p>The page or resource you requested does not exist in this workspace.</p>
        </div>
      </header>

      <section className="panel">
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div className="metricIcon"><Compass size={20} /></div>
          <div style={{ flex: 1 }}>
            <p style={{ color: "var(--text-1)", margin: 0 }}>
              Try one of the workspace entry points:
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 12 }}>
              <Link href="/" className="button">Command Center</Link>
              <Link href="/projects" className="button ghost">Projects</Link>
              <Link href="/findings" className="button ghost">Findings</Link>
              <Link href="/arsenal" className="button ghost">Arsenal</Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
