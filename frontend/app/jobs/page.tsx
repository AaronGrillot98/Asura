import Link from "next/link";
import { Activity } from "lucide-react";
import { listJobs } from "@/lib/api";
import { EmptyState, SectionHeader, StatusDot } from "@/components/primitives";

export const dynamic = "force-dynamic";

function kindForStatus(status: string): "ok" | "warn" | "danger" | "info" | "muted" {
  if (status === "completed") return "ok";
  if (status === "queued" || status === "running") return "info";
  if (status === "blocked") return "warn";
  if (status === "failed") return "danger";
  return "muted";
}

export default async function JobsPage() {
  const jobs = await listJobs();
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Operations</span>
          <h1>Background jobs</h1>
          <p>
            Every async scan and pipeline run lands here. Click a row to see the
            scanner runs the job produced.
          </p>
        </div>
      </header>

      <SectionHeader title="Recent jobs" count={jobs.length} />

      <section className="panel">
        {jobs.length === 0 ? (
          <EmptyState
            icon={<Activity size={28} />}
            title="No background jobs yet"
            description="Submit a scan with 'Run in background' checked, or run a pipeline preset from /pipelines."
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Pipeline / scanners</th>
                <th>Status</th>
                <th>Runs</th>
                <th>Findings</th>
                <th>Progress</th>
                <th>Started</th>
                <th>Backend</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => {
                const scanners = (job.scan_request?.scanners as string[] | undefined) ?? [];
                const subject = job.kind === "pipeline"
                  ? job.pipeline_id ?? "pipeline"
                  : scanners.length > 0 ? scanners.join(", ") : "scan";
                return (
                  <tr key={job.id}>
                    <td><code className="inlineCode">{job.kind}</code></td>
                    <td>
                      <Link href={`/jobs/${job.id}`} style={{ color: "var(--accent)" }}>{subject}</Link>
                    </td>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                        <StatusDot kind={kindForStatus(job.status)} title={job.status} />
                        <small>{job.status}</small>
                      </span>
                    </td>
                    <td><small>{job.run_ids.length}</small></td>
                    <td><small>{job.findings_created}</small></td>
                    <td>
                      <small style={{ minWidth: 80, display: "inline-block" }}>
                        {job.progress_percent}%
                      </small>
                    </td>
                    <td><small>{job.started_at ?? "—"}</small></td>
                    <td><small>{job.backend}</small></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
