"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Play } from "lucide-react";
import { runPipeline, type Project } from "@/lib/api";

type Status =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "submitted"; jobId: string }
  | { kind: "error"; message: string };

export function RunPipelineForm({
  pipelineId,
  pipelineName,
  projects,
}: {
  pipelineId: string;
  pipelineName: string;
  projects: Project[];
}) {
  const router = useRouter();
  const [projectId, setProjectId] = useState(projects[0]?.id ?? "demo");
  const [target, setTarget] = useState("");
  const [explicit, setExplicit] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!target.trim()) {
      setStatus({ kind: "error", message: "Target is required." });
      return;
    }
    setStatus({ kind: "submitting" });
    try {
      const response = await runPipeline({
        project_id: projectId,
        pipeline_id: pipelineId,
        target: target.trim(),
        explicit_authorization: explicit,
      });
      setStatus({ kind: "submitted", jobId: response.job_id });
      router.refresh();
    } catch (err) {
      setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      style={{ display: "grid", gap: 8, borderTop: "1px solid var(--border-1)", paddingTop: 10, marginTop: 6 }}
    >
      <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: 8 }}>
        <select
          value={projectId}
          onChange={(e) => setProjectId(e.target.value)}
          style={{ height: 36, fontSize: 12 }}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.is_demo_data ? " (demo)" : ""}
            </option>
          ))}
        </select>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="target — e.g. flightops.acme.example or /path/to/repo"
          style={{ fontSize: 12 }}
        />
      </div>
      <label style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-2)", fontSize: 12 }}>
        <input type="checkbox" checked={explicit} onChange={(e) => setExplicit(e.target.checked)} />
        I have explicit authorization to scan this target.
      </label>
      {status.kind === "error" ? (
        <div className="banner danger" style={{ fontSize: 12 }}>
          {status.message}
        </div>
      ) : null}
      {status.kind === "submitted" ? (
        <div className="banner info" style={{ fontSize: 12 }}>
          Submitted {pipelineName} → job <code className="inlineCode">{status.jobId}</code>.{" "}
          <a href={`/jobs/${status.jobId}`}>Track progress →</a>
        </div>
      ) : null}
      <div>
        <button type="submit" disabled={status.kind === "submitting"} style={{ height: 32, fontSize: 13 }}>
          <Play size={13} /> {status.kind === "submitting" ? "Submitting…" : "Run pipeline"}
        </button>
      </div>
    </form>
  );
}
