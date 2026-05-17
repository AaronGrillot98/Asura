import Link from "next/link";
import { getScans } from "@/lib/api";
import { DemoBadge, ModeBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  const runs = await getScans("demo");
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Execution</span>
          <h1>Scanner Runs</h1>
          <p>{runs.length} run(s) recorded.</p>
        </div>
      </header>

      <section className="panel">
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "#94a3b8", fontSize: 12 }}>
              <th style={{ padding: "10px 6px" }}>Scanner</th>
              <th style={{ padding: "10px 6px" }}>Mode</th>
              <th style={{ padding: "10px 6px" }}>Status</th>
              <th style={{ padding: "10px 6px" }}>Target</th>
              <th style={{ padding: "10px 6px" }}>Exit</th>
              <th style={{ padding: "10px 6px" }}>Demo</th>
              <th style={{ padding: "10px 6px" }}>Message</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id} style={{ borderTop: "1px solid #1f2937" }}>
                <td style={{ padding: "10px 6px" }}><Link href={`/scans/${run.id}`}><code className="inlineCode">{run.scanner}</code></Link></td>
                <td style={{ padding: "10px 6px" }}><ModeBadge mode={run.mode} /></td>
                <td style={{ padding: "10px 6px" }}><small className={`status ${run.status}`}>{run.status}</small></td>
                <td style={{ padding: "10px 6px", color: "#cbd5e1", fontSize: 12 }}>{run.target}</td>
                <td style={{ padding: "10px 6px", color: "#94a3b8" }}>{run.exit_code ?? "—"}</td>
                <td style={{ padding: "10px 6px" }}><DemoBadge demo={run.is_demo_data} /></td>
                <td style={{ padding: "10px 6px", color: "#94a3b8", fontSize: 12, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{run.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
