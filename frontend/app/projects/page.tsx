import Link from "next/link";
import { Plus } from "lucide-react";
import { getProjects } from "@/lib/api";
import { DemoBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function ProjectsPage() {
  const projects = await getProjects();
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Projects</span>
          <h1>Projects</h1>
          <p>{projects.length} project(s) registered in this workspace.</p>
        </div>
        <Link href="/projects/new" className="button">
          <Plus size={14} /> New project
        </Link>
      </header>
      <section className="panel">
        {projects.map((p) => (
          <article key={p.id} style={{ padding: "12px 0", borderTop: "1px solid #1f2937" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong style={{ fontSize: 16 }}>{p.name}</strong>{" "}
                <DemoBadge demo={p.is_demo_data} />
                <p style={{ color: "#94a3b8", margin: "4px 0 0" }}>{p.description}</p>
                <small style={{ color: "#94a3b8" }}>
                  Risk score: {p.risk_score}/100 · targets: {p.targets.length}
                </small>
              </div>
              <Link href={`/projects/${p.id}`} className="button">Open →</Link>
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
