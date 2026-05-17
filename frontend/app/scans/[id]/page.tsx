import Link from "next/link";
import { notFound } from "next/navigation";
import { getScan } from "@/lib/api";
import { DemoBadge, ModeBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function ScanDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let run;
  try {
    run = await getScan(id);
  } catch {
    notFound();
  }
  if (!run) notFound();

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow"><Link href="/scans">Scanner Runs</Link> / {run.id}</span>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <code className="inlineCode">{run.scanner}</code>
            <ModeBadge mode={run.mode} />
            <DemoBadge demo={run.is_demo_data} />
            <small className={`status ${run.status}`}>{run.status}</small>
          </h1>
        </div>
      </header>

      <section className="grid two">
        <section className="panel">
          <div className="panelTitle"><h2>Run</h2></div>
          <ul style={{ color: "#cbd5e1", lineHeight: 1.7 }}>
            <li>Target: <code className="inlineCode">{run.target}</code></li>
            <li>Exit code: {run.exit_code ?? "—"}</li>
            <li>Started: {run.started_at ?? "—"}</li>
            <li>Finished: {run.finished_at ?? "—"}</li>
            <li>Evidence ids: {(run.evidence_ids ?? []).join(", ") || "—"}</li>
          </ul>
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Command / Message</h2></div>
          {(run.args ?? []).length > 0 ? (
            <pre style={{ background: "#0b1320", padding: 10, borderRadius: 8, color: "#cbd5e1", fontSize: 12 }}>
{(run.args ?? []).join(" ")}
            </pre>
          ) : (
            <p style={{ color: "#94a3b8" }}>No subprocess command recorded (demo mode).</p>
          )}
          <p style={{ marginTop: 12, color: "#cbd5e1" }}>{run.message}</p>
        </section>
      </section>
    </div>
  );
}
