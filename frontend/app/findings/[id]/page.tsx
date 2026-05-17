import Link from "next/link";
import { notFound } from "next/navigation";
import { getFinding } from "@/lib/api";
import { ConfidenceBadge, DemoBadge, SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function FindingDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let finding;
  try {
    finding = await getFinding(id);
  } catch {
    notFound();
  }
  if (!finding) notFound();

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow"><Link href="/findings">Findings</Link> / {finding.id}</span>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <SeverityBadge severity={finding.severity} />
            <ConfidenceBadge confidence={finding.confidence} />
            <DemoBadge demo={finding.is_demo_data} />
            <span>{finding.title}</span>
          </h1>
          <p>Tool: <code className="inlineCode">{finding.scanner}</code> · Category: {finding.category}</p>
        </div>
      </header>

      <section className="grid two">
        <section className="panel">
          <div className="panelTitle"><h2>Impact</h2></div>
          <p style={{ color: "#cbd5e1" }}>{finding.impact}</p>
          <div className="panelTitle" style={{ marginTop: 12 }}><h2>Recommendation</h2></div>
          <p style={{ color: "#cbd5e1" }}>{finding.recommendation}</p>
          <div className="panelTitle" style={{ marginTop: 12 }}><h2>Reproduction</h2></div>
          <p style={{ color: "#94a3b8" }}>{finding.reproduction}</p>
          <div className="panelTitle" style={{ marginTop: 12 }}><h2>False positive reasoning</h2></div>
          <p style={{ color: "#94a3b8" }}>{finding.false_positive_reasoning}</p>
        </section>
        <section className="panel">
          <div className="panelTitle"><h2>Evidence Drawer</h2></div>
          {finding.evidence.length === 0 ? (
            <div className="emptyState">No evidence recorded.</div>
          ) : (
            finding.evidence.map((ev) => (
              <article key={ev.id} style={{ padding: "10px 0", borderTop: "1px solid #1f2937" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "#94a3b8" }}>
                  <span>{ev.scanner}</span>
                  <code className="inlineCode" style={{ fontSize: 10 }}>{ev.content_hash ?? "(hash on persist)"}</code>
                </div>
                <p style={{ marginTop: 6, color: "#cbd5e1" }}>{ev.summary}</p>
                <pre style={{ background: "#0b1320", padding: 10, borderRadius: 8, overflow: "auto", fontSize: 12, color: "#cbd5e1" }}>
{JSON.stringify(ev.raw, null, 2)}
                </pre>
                {ev.raw_output_path ? (
                  <small style={{ color: "#94a3b8" }}>Persisted: <code className="inlineCode">{ev.raw_output_path}</code></small>
                ) : null}
              </article>
            ))
          )}
        </section>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <div className="panelTitle"><h2>Mappings</h2></div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", color: "#94a3b8", fontSize: 12 }}>
          {(finding.cwe ?? []).map((c) => <span key={c} className="inlineCode">{c}</span>)}
          {(finding.cve ?? []).map((c) => <span key={c} className="inlineCode">{c}</span>)}
          {(finding.owasp_mapping ?? []).map((c) => <span key={c} className="inlineCode">{c}</span>)}
        </div>
      </section>
    </div>
  );
}
