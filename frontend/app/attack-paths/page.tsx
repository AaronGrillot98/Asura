import Link from "next/link";
import { GitBranch } from "lucide-react";
import { getAttackPaths } from "@/lib/api";
import { ConfidenceBadge, DemoBadge, SeverityBadge } from "@/components/badges";
import { EmptyState, SectionHeader } from "@/components/primitives";

export const dynamic = "force-dynamic";

export default async function AttackPathsPage() {
  const paths = await getAttackPaths("demo");
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Correlation</span>
          <h1>Attack Paths</h1>
          <p>{paths.length} hypothesis/hypotheses correlating findings across tools.</p>
        </div>
      </header>

      <SectionHeader title="Hypotheses" count={paths.length} />

      {paths.length === 0 ? (
        <EmptyState
          icon={<GitBranch size={28} />}
          title="No attack paths yet"
          description="PentestBrain correlates findings into hypotheses once a scan produces evidence. Run a scan to start the loop."
        />
      ) : (
        <div className="grid two">
          {paths.map((path) => (
            <article className="card interactive" key={path.id}>
              <div className="cardHeader">
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  {path.severity ? <SeverityBadge severity={path.severity} /> : null}
                  <ConfidenceBadge confidence={path.confidence ?? "medium"} />
                  <DemoBadge demo={path.is_demo_data} />
                </div>
              </div>
              <div className="cardTitle">{path.title}</div>
              <p className="cardBody">{path.summary}</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {path.finding_ids.map((id) => (
                  <span key={id} className="inlineCode">{id}</span>
                ))}
              </div>
              <div className="cardFooter">
                <span>{path.finding_ids.length} finding(s) correlated</span>
                <Link href={`/attack-paths/${path.id}`}>Open →</Link>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
