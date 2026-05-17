import { Workflow } from "lucide-react";
import { listPipelines, getProjects } from "@/lib/api";
import { EmptyState, SectionHeader } from "@/components/primitives";
import { RiskBadge } from "@/components/badges";
import { RunPipelineForm } from "@/components/run-pipeline-form";

export const dynamic = "force-dynamic";

const riskLabel: Record<string, "low" | "medium" | "high"> = {
  low: "low",
  medium: "medium",
  high: "high",
};

export default async function PipelinesPage() {
  const [pipelines, projects] = await Promise.all([listPipelines(), getProjects()]);
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Workflows</span>
          <h1>Pipelines</h1>
          <p>
            Named chains of scanner stages. Submit one and Asura walks every
            stage in the background, feeding discovered assets from one stage
            into the next where applicable.
          </p>
        </div>
      </header>

      <SectionHeader title="Presets" count={pipelines.length} />

      {pipelines.length === 0 ? (
        <EmptyState
          icon={<Workflow size={28} />}
          title="No pipelines registered"
          description="The backend's pipeline registry returned an empty list."
        />
      ) : (
        <div className="grid two">
          {pipelines.map((p) => (
            <article className="card" key={p.id}>
              <div className="cardHeader">
                <div>
                  <div className="cardTitle">{p.name}</div>
                  <small style={{ color: "var(--text-3)" }}>
                    <code className="inlineCode">{p.id}</code> · {p.stages.length} stage(s)
                  </small>
                </div>
                <RiskBadge risk={riskLabel[p.risk_level] ?? "low"} />
              </div>
              <p className="cardBody">{p.description}</p>
              <ol style={{ paddingLeft: 18, color: "var(--text-2)", lineHeight: 1.7, margin: 0 }}>
                {p.stages.map((s) => (
                  <li key={s.name} style={{ fontSize: 13 }}>
                    <strong style={{ color: "var(--text-1)" }}>{s.name}</strong>{" "}
                    <small style={{ color: "var(--text-3)" }}>
                      ({s.scanner} · {s.mode} · {s.input_source})
                    </small>
                  </li>
                ))}
              </ol>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                {p.tags.map((t) => (
                  <span key={t} className="inlineCode">#{t}</span>
                ))}
              </div>
              <RunPipelineForm pipelineId={p.id} pipelineName={p.name} projects={projects} />
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
