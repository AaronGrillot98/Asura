import Link from "next/link";
import { notFound } from "next/navigation";
import { Sparkles } from "lucide-react";
import {
  getProject,
  getTriage,
  type Project,
  type TriageReport,
} from "@/lib/api";
import { SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function ProjectTriage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
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

  let report: TriageReport | null = null;
  let errorMessage: string | null = null;
  try {
    report = await getTriage(id);
  } catch (err) {
    errorMessage = err instanceof Error ? err.message : String(err);
  }

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">
            <Link href={`/projects/${id}`}>← {project.name}</Link>
          </span>
          <h1>Triage</h1>
          <p>
            PentestBrain clusters findings and proposes a fix order. Every claim
            cites the evidence ids it used; the citation guard discards LLM
            output that references ids the brain never saw.
          </p>
        </div>
        {report ? (
          <div className="topbarActions">
            <span className={`tag ${report.engine === "llm" ? "accent" : ""}`}>
              {report.engine === "llm" ? "LLM mode" : "Deterministic"}
            </span>
            {report.engine === "deterministic" ? (
              <Link href="/settings/llm" className="button ghost">
                <Sparkles size={14} /> Configure LLM
              </Link>
            ) : null}
          </div>
        ) : null}
      </header>

      {errorMessage ? (
        <div className="banner danger">Could not load triage: {errorMessage}</div>
      ) : !report ? (
        <div className="loadingState">
          <span className="spinner" />
          <span>Building triage report…</span>
        </div>
      ) : (
        <>
          <section className="panel">
            <div className="panelTitle">
              <h2>Summary</h2>
              <small>
                {report.findings_considered} finding(s) considered
                {report.model ? ` · ${report.model}` : ""}
                {report.claims_dropped > 0 ? (
                  <>
                    {" "}· <strong>{report.claims_dropped}</strong> LLM claim(s) dropped by the citation guard
                  </>
                ) : null}
              </small>
            </div>
            <p>{report.summary}</p>
          </section>

          {report.clusters.length > 0 ? (
            <section className="panel">
              <div className="panelTitle">
                <h2>Clusters ({report.clusters.length})</h2>
                <small>Related findings the brain grouped together.</small>
              </div>
              <div className="grid two" style={{ display: "grid", gap: "var(--space-3)", gridTemplateColumns: "repeat(2, minmax(0, 1fr))" }}>
                {report.clusters.map((c) => (
                  <article key={c.id} className="card">
                    <div className="cardHeader">
                      <SeverityBadge severity={c.severity} />
                      <strong className="cardTitle">{c.title}</strong>
                      <small className="cardSubtle">{c.confidence}</small>
                    </div>
                    <p className="cardBody">{c.summary}</p>
                    <p className="muted" style={{ fontSize: "var(--text-sm)" }}>{c.reasoning}</p>
                    {c.fix_recommendation ? (
                      <p style={{ fontSize: "var(--text-sm)", marginTop: "var(--space-2)" }}>
                        <strong>Fix: </strong>
                        {c.fix_recommendation}
                      </p>
                    ) : null}
                    <small className="muted">
                      {c.finding_ids.length} finding(s) · cites {c.cited_evidence_ids.length} evidence record(s)
                    </small>
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          {report.false_positive_candidates.length > 0 ? (
            <section className="panel">
              <div className="panelTitle">
                <h2>False-positive candidates ({report.false_positive_candidates.length})</h2>
                <small>Suggestions only. A human triager confirms before changing a finding&apos;s status.</small>
              </div>
              <ul style={{ display: "grid", gap: "var(--space-2)", listStyle: "none", margin: 0, padding: 0 }}>
                {report.false_positive_candidates.map((fp) => (
                  <li key={fp.finding_id} className="card">
                    <div className="cardHeader">
                      <Link href={`/findings/${fp.finding_id}`} className="cardTitle">
                        {fp.finding_id}
                      </Link>
                      <small className="cardSubtle">
                        cites {fp.cited_evidence_ids.length} evidence record(s)
                      </small>
                    </div>
                    <p className="cardBody" style={{ fontSize: "var(--text-sm)" }}>{fp.reasoning}</p>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {report.priority_order.length > 0 ? (
            <section className="panel">
              <div className="panelTitle">
                <h2>Recommended fix order</h2>
                <small>Rank 1 = fix first.</small>
              </div>
              <ol style={{ display: "grid", gap: "var(--space-2)", listStyle: "none", margin: 0, padding: 0 }}>
                {report.priority_order.map((p) => (
                  <li key={`${p.rank}-${p.finding_id}`} className="card">
                    <div className="cardHeader">
                      <span className="tag">#{p.rank}</span>
                      <Link href={`/findings/${p.finding_id}`} className="cardTitle">
                        {p.finding_id}
                      </Link>
                    </div>
                    <p className="muted" style={{ fontSize: "var(--text-sm)" }}>{p.reasoning}</p>
                  </li>
                ))}
              </ol>
            </section>
          ) : null}
        </>
      )}
    </div>
  );
}
