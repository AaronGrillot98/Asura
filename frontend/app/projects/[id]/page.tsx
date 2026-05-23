import Link from "next/link";
import { notFound } from "next/navigation";
import { getDashboard, getProject, getTargets, type DashboardSummary, type Project, type Target } from "@/lib/api";
import { DemoBadge, SeverityBadge } from "@/components/badges";
import { TargetsSection } from "@/components/targets-section";
import { DeleteProjectButton } from "@/components/delete-project-button";
import { RunScanForm } from "@/components/run-scan-form";
import { HarImportSection } from "@/components/har-import-section";

export const dynamic = "force-dynamic";

type FetchResult<T> = { ok: T } | { error: string };

async function safeFetch<T>(fn: () => Promise<T>): Promise<FetchResult<T>> {
  try {
    return { ok: await fn() };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

function SectionError({ section, message }: { section: string; message: string }) {
  return (
    <div role="alert" aria-live="assertive" className="banner danger" style={{ marginTop: 12 }}>
      <strong>{section} could not load.</strong> {message} Restart the backend
      with the latest code and refresh the page. The rest of this view stayed
      online.
    </div>
  );
}

export default async function ProjectDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // Project lookup is the only fetch that *must* succeed for the page to make
  // sense. Everything else is wrapped so a single failing endpoint shows a
  // banner rather than crashing the whole route.
  let project: Project;
  try {
    project = await getProject(id);
  } catch (err) {
    if (err instanceof Error && /404|not found/i.test(err.message)) {
      notFound();
    }
    throw err;
  }
  if (!project) notFound();

  const [targetsResult, dashboardResult] = await Promise.all([
    safeFetch<Target[]>(() => getTargets(id)),
    safeFetch<DashboardSummary>(() => getDashboard(id)),
  ]);

  const targets: Target[] = "ok" in targetsResult ? targetsResult.ok : [];
  const dashboard: DashboardSummary | null = "ok" in dashboardResult ? dashboardResult.ok : null;

  const rules = project.scope_rules;
  const criticalCount = dashboard?.findings.filter((f) => f.severity === "critical").length ?? 0;
  const highCount = dashboard?.findings.filter((f) => f.severity === "high").length ?? 0;
  const recentRuns = dashboard?.scanner_runs.slice(0, 5) ?? [];

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

      {"error" in dashboardResult ? (
        <SectionError section="Project dashboard" message={dashboardResult.error} />
      ) : null}

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
          <strong>{dashboard?.scanner_runs.length ?? 0}</strong>
        </article>
      </section>

      <section className="grid two">
        <section className="panel">
          <div className="panelTitle"><h2>Authorized scope</h2></div>
          {rules ? (
            <ul style={{ color: "var(--text-2)", lineHeight: 1.7, paddingLeft: 18, margin: 0 }}>
              <li>Domains: {rules.domains.join(", ") || "none"}</li>
              <li>URLs: {rules.urls.join(", ") || "none"}</li>
              <li>CIDRs: {rules.cidrs.join(", ") || "none"}</li>
              <li>Repos: {rules.repos.join(", ") || "none"}</li>
              <li>Containers: {rules.containers.join(", ") || "none"}</li>
              <li>Blocked targets: {rules.blocked_targets.join(", ") || "none"}</li>
              <li>Active allowed: <strong style={{ color: "var(--text-1)" }}>{String(rules.allow_active)}</strong></li>
              <li>Lab allowed: <strong style={{ color: "var(--text-1)" }}>{String(rules.allow_lab)}</strong></li>
              <li>Max RPS: {rules.max_requests_per_second} · timeout: {rules.timeout_seconds}s</li>
            </ul>
          ) : (
            <p style={{ color: "var(--text-3)" }}>No scope rules attached.</p>
          )}
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Recent scanner runs</h2></div>
          {recentRuns.length === 0 ? (
            <div className="emptyState">
              No scans yet. Use <strong>Run scan</strong> above to start one.
            </div>
          ) : (
            <ul style={{ color: "var(--text-2)", lineHeight: 1.8, paddingLeft: 0, listStyle: "none", margin: 0 }}>
              {recentRuns.map((run) => (
                <li key={run.id} style={{ display: "flex", justifyContent: "space-between", borderTop: "1px solid var(--border-1)", padding: "6px 0", fontSize: 13 }}>
                  <span><code className="inlineCode">{run.scanner}</code> · {run.mode}</span>
                  <span style={{ color: "var(--text-3)" }}>{run.status}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>

      {"error" in targetsResult ? (
        <SectionError section="Targets" message={targetsResult.error} />
      ) : (
        <TargetsSection projectId={project.id} initial={targets} />
      )}

      <HarImportSection projectId={project.id} />

      {dashboard && dashboard.findings.length > 0 ? (
        <section className="panel" style={{ marginTop: 14 }}>
          <div className="panelTitle">
            <h2>Top findings</h2>
            <Link href={`/findings?project_id=${project.id}`} style={{ color: "var(--accent)", fontSize: 13 }}>
              View all →
            </Link>
          </div>
          <ul style={{ paddingLeft: 0, listStyle: "none", margin: 0 }}>
            {dashboard.findings.slice(0, 5).map((f) => (
              <li key={f.id} style={{ borderTop: "1px solid var(--border-1)", padding: "8px 0", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <SeverityBadge severity={f.severity} />
                  <span style={{ color: "var(--text-2)" }}>{f.title}</span>
                </div>
                <Link href={`/findings/${f.id}`} style={{ color: "var(--accent)", fontSize: 13 }}>Open →</Link>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
