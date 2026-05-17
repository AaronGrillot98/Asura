import Link from "next/link";
import { getAttackPaths } from "@/lib/api";
import { ConfidenceBadge, DemoBadge, SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function AttackPathsPage() {
  const paths = await getAttackPaths("demo");
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Correlation</span>
          <h1>Attack Paths</h1>
          <p>{paths.length} hypothesis/hypotheses correlate findings across tools.</p>
        </div>
      </header>

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {paths.map((path) => (
          <section className="panel" key={path.id}>
            <div className="panelTitle" style={{ justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {path.severity ? <SeverityBadge severity={path.severity} /> : null}
                <ConfidenceBadge confidence={path.confidence ?? "medium"} />
                <DemoBadge demo={path.is_demo_data} />
                <h2 style={{ margin: 0 }}>{path.title}</h2>
              </div>
              <Link href={`/attack-paths/${path.id}`}>Open →</Link>
            </div>
            <p style={{ color: "#cbd5e1" }}>{path.summary}</p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
              {path.finding_ids.map((id) => (
                <span key={id} className="inlineCode" style={{ fontSize: 11 }}>{id}</span>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
