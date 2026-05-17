import Link from "next/link";
import { getFindings } from "@/lib/api";
import { ConfidenceBadge, DemoBadge, SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function FindingsPage({
  searchParams,
}: {
  searchParams?: Promise<{ severity?: string; status?: string; demo?: string; project_id?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const findings = await getFindings({
    project_id: params.project_id ?? "demo",
    severity: params.severity,
    status: params.status,
    demo: params.demo === undefined ? undefined : params.demo === "true",
  });

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Findings</span>
          <h1>Findings</h1>
          <p>{findings.length} normalized finding(s) across the selected filters.</p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Link className="button" href="/findings?severity=critical">Critical</Link>
          <Link className="button" href="/findings?severity=high">High</Link>
          <Link className="button" href="/findings">Reset</Link>
        </div>
      </header>

      <section className="panel">
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "#94a3b8", fontSize: 12 }}>
              <th style={{ padding: "10px 6px" }}>Severity</th>
              <th style={{ padding: "10px 6px" }}>Confidence</th>
              <th style={{ padding: "10px 6px" }}>Title</th>
              <th style={{ padding: "10px 6px" }}>Tool</th>
              <th style={{ padding: "10px 6px" }}>Affected</th>
              <th style={{ padding: "10px 6px" }}>Status</th>
              <th style={{ padding: "10px 6px" }}></th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} style={{ borderTop: "1px solid #1f2937" }}>
                <td style={{ padding: "10px 6px" }}><SeverityBadge severity={f.severity} /></td>
                <td style={{ padding: "10px 6px" }}><ConfidenceBadge confidence={f.confidence} /></td>
                <td style={{ padding: "10px 6px" }}>
                  <Link href={`/findings/${f.id}`}>{f.title}</Link>
                  {f.is_demo_data ? <span style={{ marginLeft: 8 }}><DemoBadge demo /></span> : null}
                </td>
                <td style={{ padding: "10px 6px" }}><code className="inlineCode">{f.scanner}</code></td>
                <td style={{ padding: "10px 6px", color: "#94a3b8", fontSize: 12 }}>{f.affected_asset ?? f.asset_id}</td>
                <td style={{ padding: "10px 6px", color: "#94a3b8", fontSize: 12 }}>{f.status}</td>
                <td style={{ padding: "10px 6px" }}><Link href={`/findings/${f.id}`}>Details →</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
        {findings.length === 0 ? <div className="emptyState">No findings match these filters.</div> : null}
      </section>
    </div>
  );
}
