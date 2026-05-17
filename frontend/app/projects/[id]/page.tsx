import Link from "next/link";
import { notFound } from "next/navigation";
import { getProject } from "@/lib/api";
import { DemoBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function ProjectDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let project;
  try {
    project = await getProject(id);
  } catch {
    notFound();
  }
  if (!project) notFound();

  const rules = project.scope_rules;
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow"><Link href="/projects">Projects</Link> / {project.id}</span>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {project.name} <DemoBadge demo={project.is_demo_data} />
          </h1>
          <p>{project.description}</p>
        </div>
      </header>

      <section className="grid two">
        <section className="panel">
          <div className="panelTitle"><h2>Scope</h2></div>
          {rules ? (
            <ul style={{ color: "#cbd5e1", lineHeight: 1.7, paddingLeft: 18 }}>
              <li>Domains: {rules.domains.join(", ") || "none"}</li>
              <li>URLs: {rules.urls.join(", ") || "none"}</li>
              <li>CIDRs: {rules.cidrs.join(", ") || "none"}</li>
              <li>Repos: {rules.repos.join(", ") || "none"}</li>
              <li>Containers: {rules.containers.join(", ") || "none"}</li>
              <li>Active allowed: {String(rules.allow_active)}</li>
              <li>Lab allowed: {String(rules.allow_lab)}</li>
              <li>Max RPS: {rules.max_requests_per_second}</li>
            </ul>
          ) : (
            <p style={{ color: "#94a3b8" }}>No scope rules attached.</p>
          )}
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Targets</h2></div>
          <ul style={{ color: "#cbd5e1", lineHeight: 1.7, paddingLeft: 18 }}>
            {project.targets.map((t) => <li key={t}><code className="inlineCode">{t}</code></li>)}
          </ul>
        </section>
      </section>
    </div>
  );
}
