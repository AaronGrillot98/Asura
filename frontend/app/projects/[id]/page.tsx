import Link from "next/link";
import { notFound } from "next/navigation";
import { getDashboard, getProject, getTargets } from "@/lib/api";
import { DemoBadge, SeverityBadge } from "@/components/badges";
import { TargetsSection } from "@/components/targets-section";
import { DeleteProjectButton } from "@/components/delete-project-button";
import { RunScanForm } from "@/components/run-scan-form";

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
  const [targets, dashboard] = await Promise.all([
    getTargets(id),
    getDashboard(id),
  ]);
  const rules = project.scope_rules;
  const criticalCount = dashboard.findings.filter((f) => f.severity === "critical").length;
  const highCount = dashboard.findings.filter((f) => f.severity === "high").length;
  const recentRuns = dashboard.scanner_runs.slice(0, 5);

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
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <RunScanForm projectId={project.id} lockProject />
          <DeleteProjectButton
            projectId={project.id}
            projectName={project.name}
            disabled={project.is_demo_data}
          />
        </div>
      </header>

      <section className="metrics">
        <article className="metric">
          <span>Risk score</span>
          <strong>{project.risk_score}/100</strong>
        </article>
        <article className="metric">
          <span>Findings · critical</span>
          <strong>{criticalCount}</strong>
        </article>
        <article className="metric">
          <span>Findings · high</span>
          <strong>{highCount}</strong>
        </article>
        <article className="metric">
          <span>Scanner runs</span>
          <strong>{dashboard.scanner_runs.length}</strong>
        </article>
      </section>

      <section className="grid two">
        <section className="panel">
          <div className="panelTitle"><h2>Authorized scope</h2></div>
          {rules ? (
            <ul style={{ color: "#cbd5e1", lineHeight: 1.7, paddingLeft: 18 }}>
              <li>Domains: {rules.domains.join(", ") || "none"}</li>
              <li>URLs: {rules.urls.join(", ") || "none"}</li>
              <li>CIDRs: {rules.cidrs.join(", ") || "none"}</li>
              <li>Repos: {rules.repos.join(", ") || "none"}</li>
              <li>Containers: {rules.containers.join(", ") || "none"}</li>
              <li>Blocked targets: {rules.blocked_targets.join(", ") || "none"}</li>
              <li>Active allowed: <strong>{String(rules.allow_active)}</strong></li>
              <li>Lab allowed: <strong>{String(rules.allow_lab)}</strong></li>
              <li>Max RPS: {rules.max_requests_per_second} · timeout: {rules.timeout_seconds}s</li>
            </ul>
          ) : (
            <p style={{ color: "#94a3b8" }}>No scope rules attached.</p>
          )}
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Recent scanner runs</h2></div>
          {recentRuns.length === 0 ? (
            <div className="emptyState">
              No scans yet. Use <strong>Run scan</strong> above to start one.
            </div>
          ) : (
            <ul style={{ color: "#cbd5e1", lineHeight: 1.8, paddingLeft: 0, listStyle: "none" }}>
              {recentRuns.map((run) => (
                <li key={run.id} style={{ display: "flex", justifyContent: "space-between", borderTop: "1px solid #1f2937", padding: "6px 0", fontSize: 13 }}>
                  <span><code className="inlineCode">{run.scanner}</code> · {run.mode}</span>
                  <span style={{ color: "#94a3b8" }}>{run.status}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>

      <TargetsSection projectId={project.id} initial={targets} />

      {dashboard.findings.length > 0 ? (
        <section className="panel" style={{ marginTop: 14 }}>
          <div className="panelTitle">
            <h2>Top findings</h2>
            <Link href={`/findings?project_id=${project.id}`} style={{ color: "#93c5fd", fontSize: 13 }}>
              View all →
            </Link>
          </div>
          <ul style={{ paddingLeft: 0, listStyle: "none" }}>
            {dashboard.findings.slice(0, 5).map((f) => (
              <li key={f.id} style={{ borderTop: "1px solid #1f2937", padding: "8px 0", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <SeverityBadge severity={f.severity} />
                  <span style={{ color: "#cbd5e1" }}>{f.title}</span>
                </div>
                <Link href={`/findings/${f.id}`} style={{ color: "#93c5fd", fontSize: 13 }}>Open →</Link>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
