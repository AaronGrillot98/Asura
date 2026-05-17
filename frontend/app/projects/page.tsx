import Link from "next/link";
import { Boxes, Plus } from "lucide-react";
import { getProjects } from "@/lib/api";
import { DemoBadge } from "@/components/badges";
import { EmptyState, SectionHeader, StatusDot } from "@/components/primitives";

export const dynamic = "force-dynamic";

export default async function ProjectsPage() {
  const projects = await getProjects();
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Workspace</span>
          <h1>Projects</h1>
          <p>{projects.length} project(s) registered in this workspace.</p>
        </div>
        <Link href="/projects/new" className="button">
          <Plus size={14} /> New project
        </Link>
      </header>

      <SectionHeader
        title="All projects"
        count={projects.length}
        description="The seeded demo is read-only; user-created projects can be edited and deleted."
      />

      {projects.length === 0 ? (
        <EmptyState
          icon={<Boxes size={28} />}
          title="No projects yet"
          description="Create a project to declare authorized scope and start scanning your own systems."
          action={
            <Link href="/projects/new" className="button">
              <Plus size={14} /> New project
            </Link>
          }
        />
      ) : (
        <div className="grid two">
          {projects.map((p) => {
            const status = p.is_demo_data ? "info" : "ok";
            const statusTitle = p.is_demo_data ? "Seeded demo project" : "User project";
            return (
              <article className="card interactive" key={p.id}>
                <div className="cardHeader">
                  <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                    <StatusDot kind={status} title={statusTitle} />
                    <div>
                      <div className="cardTitle">{p.name}</div>
                      <small style={{ color: "var(--text-3)" }}>{p.id}</small>
                    </div>
                  </div>
                  <DemoBadge demo={p.is_demo_data} />
                </div>
                <p className="cardBody">{p.description}</p>
                <div className="cardFooter">
                  <span>
                    Risk score: <strong style={{ color: "var(--text-1)" }}>{p.risk_score}/100</strong> · targets: {p.targets.length}
                  </span>
                  <Link href={`/projects/${p.id}`}>Open →</Link>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
