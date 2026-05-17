import Link from "next/link";
import { notFound } from "next/navigation";
import { getAttackPath } from "@/lib/api";
import { AttackPathGraph } from "@/components/attack-path-graph";
import { ConfidenceBadge, DemoBadge, SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function AttackPathDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let path;
  try {
    path = await getAttackPath(id);
  } catch {
    notFound();
  }
  if (!path) notFound();

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow"><Link href="/attack-paths">Attack Paths</Link> / {path.id}</span>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {path.severity ? <SeverityBadge severity={path.severity} /> : null}
            <ConfidenceBadge confidence={path.confidence ?? "medium"} />
            <DemoBadge demo={path.is_demo_data} />
            <span>{path.title}</span>
          </h1>
          <p>{path.narrative ?? path.summary}</p>
        </div>
      </header>

      <section className="panel">
        <div className="panelTitle"><h2>Graph</h2></div>
        <AttackPathGraph path={path} />
      </section>

      <section className="grid two" style={{ marginTop: 14 }}>
        <section className="panel">
          <div className="panelTitle"><h2>Next safe validation step</h2></div>
          {(path.safe_validation_needed ?? []).length === 0 ? (
            <p style={{ color: "#94a3b8" }}>No further validation step required.</p>
          ) : (
            <ul style={{ paddingLeft: 18, color: "#cbd5e1" }}>
              {(path.safe_validation_needed ?? []).map((s, idx) => <li key={idx}>{s}</li>)}
            </ul>
          )}
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Remediation</h2></div>
          {(path.recommended_next_steps ?? []).length === 0 ? (
            <p style={{ color: "#94a3b8" }}>{path.remediation_summary ?? "Review the linked findings."}</p>
          ) : (
            <ol style={{ paddingLeft: 18, color: "#cbd5e1" }}>
              {(path.recommended_next_steps ?? []).map((s, idx) => <li key={idx}>{s}</li>)}
            </ol>
          )}
        </section>
      </section>
    </div>
  );
}
