import Link from "next/link";
import { notFound } from "next/navigation";
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
    <main style={{ padding: 24 }}>
      <nav style={{ marginBottom: 12 }}>
        <Link href={`/projects/${id}`}>← {project.name}</Link>
      </nav>

      <header style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>Triage</h1>
        <p style={{ color: "var(--text-3)", margin: "4px 0 0" }}>
          PentestBrain clusters findings and proposes a fix order. Every claim
          cites the evidence ids it used; the citation guard discards LLM
          output that references ids the brain never saw.
        </p>
      </header>

      {errorMessage ? (
        <div className="banner danger">Could not load triage: {errorMessage}</div>
      ) : !report ? null : (
        <>
          <section
            style={{
              border: "1px solid var(--border-1)",
              borderRadius: 8,
              padding: 14,
              marginBottom: 18,
              background: "var(--surface-1)",
            }}
          >
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
              <span
                style={{
                  fontSize: 12,
                  padding: "2px 8px",
                  borderRadius: 999,
                  background: report.engine === "llm" ? "var(--accent-purple, #7c3aed)" : "var(--surface-2)",
                  color: report.engine === "llm" ? "white" : "var(--text-2)",
                }}
              >
                engine: {report.engine}
                {report.model ? ` · ${report.model}` : ""}
              </span>
              <small style={{ color: "var(--text-3)" }}>
                {report.findings_considered} finding(s) considered
                {report.claims_dropped > 0 ? (
                  <> · <strong>{report.claims_dropped}</strong> LLM claim(s) dropped by the citation guard</>
                ) : null}
              </small>
              {report.engine === "deterministic" ? (
                <Link
                  href="/settings/llm"
                  style={{ marginLeft: "auto", fontSize: 12, color: "var(--accent-purple, #7c3aed)" }}
                >
                  Configure LLM triage →
                </Link>
              ) : null}
            </div>
            <p style={{ marginTop: 10, color: "var(--text-2)" }}>{report.summary}</p>
          </section>

          {report.clusters.length > 0 ? (
            <section style={{ marginBottom: 22 }}>
              <h2 style={{ marginBottom: 8 }}>Clusters</h2>
              <div style={{ display: "grid", gap: 12 }}>
                {report.clusters.map((c) => (
                  <article
                    key={c.id}
                    style={{
                      border: "1px solid var(--border-1)",
                      borderRadius: 8,
                      padding: 12,
                      background: "var(--surface-1)",
                    }}
                  >
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
                      <SeverityBadge severity={c.severity} />
                      <strong>{c.title}</strong>
                      <small style={{ color: "var(--text-3)", marginLeft: "auto" }}>
                        confidence: {c.confidence}
                      </small>
                    </div>
                    <p style={{ margin: "4px 0", color: "var(--text-2)" }}>{c.summary}</p>
                    <p style={{ margin: "4px 0", color: "var(--text-3)", fontSize: 13 }}>{c.reasoning}</p>
                    {c.fix_recommendation ? (
                      <p style={{ margin: "6px 0", fontSize: 13 }}>
                        <strong>Fix:</strong> {c.fix_recommendation}
                      </p>
                    ) : null}
                    <small style={{ color: "var(--text-3)" }}>
                      {c.finding_ids.length} finding(s) · cites {c.cited_evidence_ids.length} evidence record(s)
                    </small>
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          {report.false_positive_candidates.length > 0 ? (
            <section style={{ marginBottom: 22 }}>
              <h2 style={{ marginBottom: 8 }}>False-positive candidates</h2>
              <p style={{ color: "var(--text-3)", marginTop: 0 }}>
                Suggestions only. A human triager confirms before changing a finding&apos;s status.
              </p>
              <div style={{ display: "grid", gap: 8 }}>
                {report.false_positive_candidates.map((fp) => (
                  <article
                    key={fp.finding_id}
                    style={{
                      border: "1px solid var(--border-1)",
                      borderRadius: 8,
                      padding: 10,
                      background: "var(--surface-1)",
                    }}
                  >
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <Link href={`/findings/${fp.finding_id}`}>{fp.finding_id}</Link>
                      <small style={{ color: "var(--text-3)", marginLeft: "auto" }}>
                        cites {fp.cited_evidence_ids.length} evidence record(s)
                      </small>
                    </div>
                    <p style={{ margin: "4px 0 0", fontSize: 13, color: "var(--text-2)" }}>{fp.reasoning}</p>
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          {report.priority_order.length > 0 ? (
            <section>
              <h2 style={{ marginBottom: 8 }}>Recommended fix order</h2>
              <ol style={{ paddingLeft: 18 }}>
                {report.priority_order.map((p) => (
                  <li key={`${p.rank}-${p.finding_id}`} style={{ marginBottom: 6 }}>
                    <Link href={`/findings/${p.finding_id}`}>{p.finding_id}</Link>
                    <span style={{ marginLeft: 8, color: "var(--text-3)", fontSize: 13 }}>{p.reasoning}</span>
                  </li>
                ))}
              </ol>
            </section>
          ) : null}
        </>
      )}
    </main>
  );
}
