import Link from "next/link";
import { notFound } from "next/navigation";
import { getJob, type ScanJob } from "@/lib/api";
import { StatusDot } from "@/components/primitives";

export const dynamic = "force-dynamic";

function kindForStatus(status: ScanJob["status"]): "ok" | "warn" | "danger" | "info" | "muted" {
  if (status === "completed") return "ok";
  if (status === "queued" || status === "running") return "info";
  if (status === "blocked") return "warn";
  if (status === "failed") return "danger";
  return "muted";
}

export default async function JobDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let job: ScanJob;
  try {
    job = await getJob(id);
  } catch {
    notFound();
  }

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow"><Link href="/jobs">Background jobs</Link> / {job.id}</span>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <StatusDot kind={kindForStatus(job.status)} title={job.status} />
            {job.kind === "pipeline" ? `Pipeline · ${job.pipeline_id}` : "Scan job"}
          </h1>
          <p>
            Status: <strong style={{ color: "var(--text-1)" }}>{job.status}</strong> ·{" "}
            Progress: <strong style={{ color: "var(--text-1)" }}>{job.progress_percent}%</strong> ·{" "}
            Backend: <code className="inlineCode">{job.backend}</code>
          </p>
        </div>
      </header>

      <section className="grid two">
        <section className="panel">
          <div className="panelTitle"><h2>Job</h2></div>
          <ul style={{ color: "var(--text-2)", lineHeight: 1.7, paddingLeft: 18, margin: 0 }}>
            <li>Created: <small>{job.created_at}</small></li>
            <li>Started: <small>{job.started_at ?? "—"}</small></li>
            <li>Finished: <small>{job.finished_at ?? "—"}</small></li>
            <li>Project: <Link href={`/projects/${job.project_id}`}>{job.project_id}</Link></li>
            <li>Runs produced: <strong style={{ color: "var(--text-1)" }}>{job.run_ids.length}</strong></li>
            <li>Findings created: <strong style={{ color: "var(--text-1)" }}>{job.findings_created}</strong></li>
          </ul>
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Scanner runs</h2></div>
          {job.run_ids.length === 0 ? (
            <p style={{ color: "var(--text-3)" }}>No runs produced.</p>
          ) : (
            <ul style={{ paddingLeft: 0, listStyle: "none", margin: 0 }}>
              {job.run_ids.map((runId) => (
                <li key={runId} style={{ borderTop: "1px solid var(--border-1)", padding: "6px 0" }}>
                  <Link href={`/scans/${runId}`} style={{ color: "var(--accent)" }}>
                    <code className="inlineCode">{runId}</code>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>

      {job.progress_text ? (
        <section className="panel" style={{ marginTop: 14 }}>
          <div className="panelTitle"><h2>Progress log</h2></div>
          <pre style={{ background: "var(--bg-0)", border: "1px solid var(--border-1)", color: "var(--text-2)", padding: 12, borderRadius: 8, fontSize: 12, whiteSpace: "pre-wrap", margin: 0 }}>
{job.progress_text}
          </pre>
        </section>
      ) : null}

      {job.error ? (
        <section className="panel" style={{ marginTop: 14 }}>
          <div className="panelTitle">
            <h2 style={{ color: "var(--danger)" }}>Error</h2>
          </div>
          <pre style={{ background: "var(--bg-0)", border: "1px solid var(--border-1)", color: "var(--danger)", padding: 12, borderRadius: 8, fontSize: 12, whiteSpace: "pre-wrap", margin: 0 }}>
{job.error}
          </pre>
        </section>
      ) : null}
    </div>
  );
}
