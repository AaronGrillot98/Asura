import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { getFindings } from "@/lib/api";
import { ConfidenceBadge, DemoBadge, SeverityBadge } from "@/components/badges";
import { EmptyState, SectionHeader } from "@/components/primitives";

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
          <span className="eyebrow">Operations</span>
          <h1>Findings</h1>
          <p>{findings.length} normalized finding(s) across the selected filters.</p>
        </div>
        <div className="topbarActions">
          <Link className="button ghost" href="/findings?severity=critical">Critical</Link>
          <Link className="button ghost" href="/findings?severity=high">High</Link>
          <Link className="button ghost" href="/findings">Reset</Link>
        </div>
      </header>

      <SectionHeader title="Findings" count={findings.length} />

      <section className="panel">
        {findings.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={28} />}
            title="No findings match these filters"
            description="Run a scan from the Command Center or relax the severity/status filters to see results."
            action={<Link href="/findings" className="button ghost">Reset filters</Link>}
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Title</th>
                <th>Tool</th>
                <th>Affected</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td><ConfidenceBadge confidence={f.confidence} /></td>
                  <td>
                    <Link href={`/findings/${f.id}`}>{f.title}</Link>
                    {f.is_demo_data ? <span style={{ marginLeft: 8 }}><DemoBadge demo /></span> : null}
                  </td>
                  <td><code className="inlineCode">{f.scanner}</code></td>
                  <td><small>{f.affected_asset ?? f.asset_id}</small></td>
                  <td><small>{f.status}</small></td>
                  <td><Link href={`/findings/${f.id}`}>Details →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
