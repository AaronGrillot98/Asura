"use client";

import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Download,
  GitBranch,
  Network,
  PackageCheck,
  Radar,
  ShieldAlert,
  TerminalSquare,
} from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ArsenalSummary, DashboardSummary, Finding, ScannerRun, Severity } from "@/lib/api";
import { reportUrl } from "@/lib/api";
import { RunScanForm } from "@/components/run-scan-form";
import {
  Card,
  EmptyState,
  MetricCard,
  SectionHeader,
  StatusDot,
  type StatusKind,
} from "@/components/primitives";
import { ConfidenceBadge, SeverityBadge } from "@/components/badges";

const severityWeight: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const COVERAGE_DOMAINS: { id: string; label: string; categories: string[] }[] = [
  { id: "code", label: "Code", categories: ["code"] },
  { id: "web", label: "Web", categories: ["web", "dast"] },
  { id: "api", label: "API", categories: ["api", "api security"] },
  { id: "container", label: "Container", categories: ["container", "sbom"] },
  { id: "secrets", label: "Secrets", categories: ["secrets"] },
  { id: "deps", label: "Dependencies", categories: ["dependency"] },
  { id: "iac", label: "IaC / Cloud", categories: ["iac"] },
  { id: "network", label: "Network", categories: ["network"] },
  { id: "ai", label: "AI / LLM", categories: ["llm security", "ai"] },
];

function countSeverity(findings: Finding[], severity: Severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

function runHealth(run: ScannerRun): StatusKind {
  if (run.status === "completed") return "ok";
  if (run.status === "queued" || run.status === "running") return "info";
  if (run.status === "blocked") return "warn";
  return "danger";
}

function coverageCount(findings: Finding[], categories: string[]): number {
  const set = new Set(categories.map((c) => c.toLowerCase()));
  return findings.filter((f) => set.has((f.category || "").toLowerCase())).length;
}

export function Dashboard({ data, arsenal }: { data: DashboardSummary; arsenal: ArsenalSummary }) {
  const path = data.attack_paths[0];
  const criticalCount = countSeverity(data.findings, "critical");
  const highCount = countSeverity(data.findings, "high");
  const runnableTools = arsenal.tools.filter(
    (t) => t.integration_status === "runner" && t.execution !== "blocked",
  ).length;

  const sortedFindings = [...data.findings].sort(
    (a, b) => severityWeight[b.severity] - severityWeight[a.severity],
  );
  const fixOrder = path?.remediation_order ?? [];
  const fixList = fixOrder
    .map((id) => data.findings.find((f) => f.id === id))
    .filter((f): f is Finding => f !== undefined);

  return (
    <>
      {data.is_demo_data ? (
        <div className="banner demo">
          <strong>Demo mode:</strong> findings on this dashboard are seeded
          demo evidence, not the result of a live scan. Set{" "}
          <code className="inlineCode">ASURA_DEMO_MODE=1</code> on the backend
          to freeze every new scan on seeded output.
        </div>
      ) : null}

      <header className="topbar">
        <div>
          <span className="eyebrow">
            Workspace / {data.is_demo_data ? "Demo" : "Live"}
          </span>
          <h1>{data.project.name}</h1>
          <p>{data.project.description}</p>
        </div>
        <div className="topbarActions">
          <RunScanForm projectId={data.project.id} />
          <a className="button ghost" href={reportUrl(data.project.id)}>
            <Download size={14} />
            Export report
          </a>
        </div>
      </header>

      {/* ---- Hero metrics --------------------------------------------------- */}
      <section className="metrics">
        <MetricCard
          label="Executive risk"
          value={`${data.project.risk_score}/100`}
          tone={data.project.risk_score >= 80 ? "danger" : data.project.risk_score >= 60 ? "warn" : "ok"}
          icon={<AlertTriangle size={16} />}
        />
        <MetricCard
          label="Critical findings"
          value={criticalCount}
          tone={criticalCount > 0 ? "danger" : "ok"}
          icon={<ShieldAlert size={16} />}
          hint={`${highCount} high`}
        />
        <MetricCard
          label="Scanner runs"
          value={data.scanner_runs.length}
          tone="ok"
          icon={<Activity size={16} />}
          hint={`${data.scanner_runs.filter((r) => r.status === "completed").length} completed`}
        />
        <MetricCard
          label="Runner-ready tools"
          value={runnableTools}
          tone="ok"
          icon={<PackageCheck size={16} />}
          hint={`${arsenal.tools.length} registered`}
        />
      </section>

      {/* ---- Risk + Coverage ----------------------------------------------- */}
      <SectionHeader title="Risk overview" description="Trend and surface coverage at a glance." />
      <div className="grid two">
        <section className="panel">
          <div className="panelTitle">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Activity size={16} />
              <h2>Risk Trend</h2>
            </div>
            {data.risk_trend.length === 0 ? (
              <small>No history yet</small>
            ) : (
              <small>
                {data.risk_trend.length} day(s) · latest{" "}
                {data.risk_trend[data.risk_trend.length - 1]?.score}
              </small>
            )}
          </div>
          {data.risk_trend.length === 0 ? (
            <EmptyState
              icon={<Activity size={24} />}
              title="No history yet"
              description="Submit a scan to start accumulating a risk trend for this project."
            />
          ) : (
            <div className="chart">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.risk_trend}>
                  <defs>
                    <linearGradient id="risk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.36} />
                      <stop offset="95%" stopColor="var(--danger)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border-1)" vertical={false} />
                  <XAxis dataKey="date" stroke="var(--text-3)" tick={{ fontSize: 11 }} />
                  <YAxis stroke="var(--text-3)" tick={{ fontSize: 11 }} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{
                      background: "var(--bg-2)",
                      border: "1px solid var(--border-2)",
                      color: "var(--text-1)",
                      borderRadius: 8,
                    }}
                  />
                  <Area type="monotone" dataKey="score" stroke="var(--danger)" fill="url(#risk)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panelTitle">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Radar size={16} />
              <h2>Coverage by domain</h2>
            </div>
            <small>Findings per category</small>
          </div>
          <div className="grid three" style={{ gap: 8 }}>
            {COVERAGE_DOMAINS.map((domain) => {
              const count = coverageCount(data.findings, domain.categories);
              return (
                <div key={domain.id} className="card" style={{ padding: 12, gap: 4 }}>
                  <span className="cardSubtle">{domain.label}</span>
                  <strong style={{ fontSize: 20, color: count > 0 ? "var(--text-1)" : "var(--text-3)" }}>{count}</strong>
                </div>
              );
            })}
          </div>
        </section>
      </div>

      {/* ---- Attack path + Fix these first --------------------------------- */}
      {path ? (
        <>
          <SectionHeader
            title="Active hypotheses"
            description="The most dangerous chain in this project and the fixes that retire it."
            actions={
              <Link href="/attack-paths" className="button ghost">
                All paths →
              </Link>
            }
          />
          <div className="grid two">
            <Card>
              <div className="cardHeader">
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <GitBranch size={16} />
                  <span className="cardSubtle">Most dangerous chain</span>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  {path.severity ? <SeverityBadge severity={path.severity} /> : null}
                  <ConfidenceBadge confidence={path.confidence ?? "medium"} />
                </div>
              </div>
              <div className="cardTitle">{path.title}</div>
              <p className="cardBody">{path.narrative ?? path.summary}</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {path.finding_ids.map((id) => (
                  <span key={id} className="inlineCode">{id}</span>
                ))}
              </div>
              <div className="cardFooter">
                <span>{path.finding_ids.length} finding(s) correlated</span>
                <Link href={`/attack-paths/${path.id}`}>Open →</Link>
              </div>
            </Card>

            <section className="panel">
              <div className="panelTitle">
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <CheckCircle2 size={16} />
                  <h2>Fix these first</h2>
                </div>
                <small>Ordered for impact</small>
              </div>
              {fixList.length === 0 ? (
                <EmptyState
                  icon={<CheckCircle2 size={24} />}
                  title="Nothing to fix yet"
                  description="As findings land in this project, the brain orders them for impact here."
                />
              ) : (
                <div className="fixList">
                  {fixList.slice(0, 5).map((finding, index) => (
                    <Link
                      href={`/findings/${finding.id}`}
                      key={finding.id}
                      className="fix"
                      style={{ textDecoration: "none" }}
                    >
                      <span>{index + 1}</span>
                      <div>
                        <strong>{finding.title}</strong>
                        <small>{finding.recommendation}</small>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </section>
          </div>
        </>
      ) : null}

      {/* ---- Scanner health card grid -------------------------------------- */}
      <SectionHeader
        title="Scanner health"
        count={data.scanner_runs.length}
        description="Recent runs across this project."
        actions={
          <Link href="/scans" className="button ghost">
            All runs →
          </Link>
        }
      />
      {data.scanner_runs.length === 0 ? (
        <EmptyState
          icon={<TerminalSquare size={24} />}
          title="No scanner runs yet"
          description="Submit a scan from above to record this project's first run."
        />
      ) : (
        <div className="grid three">
          {data.scanner_runs.slice(0, 6).map((run) => {
            const kind = runHealth(run);
            return (
              <Card key={run.id} interactive>
                <Link href={`/scans/${run.id}`} style={{ textDecoration: "none", color: "inherit", display: "contents" }}>
                  <div className="cardHeader">
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <StatusDot kind={kind} title={run.status} />
                      <div>
                        <div className="cardTitle">
                          <code className="inlineCode">{run.scanner}</code>
                        </div>
                        <small style={{ color: "var(--text-3)" }}>{run.mode}</small>
                      </div>
                    </div>
                    <small className={`status ${run.status}`}>{run.status}</small>
                  </div>
                  <p className="cardBody" style={{ fontSize: 12, color: "var(--text-3)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {run.target}
                  </p>
                  <div className="cardFooter">
                    <span>{run.findings_created ?? 0} finding(s) created</span>
                    <span>{run.is_demo_data ? "demo" : "live"}</span>
                  </div>
                </Link>
              </Card>
            );
          })}
        </div>
      )}

      {/* ---- Brain reasoning ----------------------------------------------- */}
      {data.agent_outputs.length > 0 ? (
        <>
          <SectionHeader
            title="PentestBrain reasoning"
            description="Every claim cites the evidence IDs that produced it."
          />
          <div className="grid two">
            {data.agent_outputs.map((output, idx) => (
              <Card key={`${output.agent}-${idx}`}>
                <div className="cardHeader">
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <StatusDot kind={output.confidence === "confirmed" || output.confidence === "high" ? "ok" : output.confidence === "medium" ? "info" : "muted"} />
                    <span className="cardSubtle">{output.agent.replaceAll("_", " ")}</span>
                  </div>
                  <small style={{ color: "var(--text-3)" }}>{output.confidence}</small>
                </div>
                <p className="cardBody">{output.summary}</p>
                {output.cited_evidence_ids && output.cited_evidence_ids.length > 0 ? (
                  <small style={{ color: "var(--text-3)" }}>
                    Cites {output.cited_evidence_ids.length} evidence record(s).
                  </small>
                ) : null}
                {output.recommended_next_steps.length > 0 ? (
                  <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-2)", lineHeight: 1.6 }}>
                    {output.recommended_next_steps.slice(0, 3).map((step, i) => (
                      <li key={i} style={{ fontSize: 13 }}>{step}</li>
                    ))}
                  </ul>
                ) : null}
              </Card>
            ))}
          </div>
        </>
      ) : null}

      {/* ---- Top findings (link out for full table) ------------------------ */}
      <SectionHeader
        title="Top findings"
        count={sortedFindings.length}
        description="Highest-severity findings in this project."
        actions={
          <Link href={`/findings?project_id=${data.project.id}`} className="button ghost">
            All findings →
          </Link>
        }
      />
      {sortedFindings.length === 0 ? (
        <EmptyState
          icon={<ShieldAlert size={24} />}
          title="No findings yet"
          description="Submit a scan to start populating this project's findings."
        />
      ) : (
        <div className="grid two">
          {sortedFindings.slice(0, 6).map((finding) => (
            <Card key={finding.id} interactive>
              <Link href={`/findings/${finding.id}`} style={{ textDecoration: "none", color: "inherit", display: "contents" }}>
                <div className="cardHeader">
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <SeverityBadge severity={finding.severity} />
                    <ConfidenceBadge confidence={finding.confidence} />
                  </div>
                  <small style={{ color: "var(--text-3)" }}>
                    <code className="inlineCode">{finding.scanner}</code>
                  </small>
                </div>
                <div className="cardTitle">{finding.title}</div>
                <p className="cardBody" style={{ fontSize: 13 }}>{finding.impact}</p>
                <div className="cardFooter">
                  <span>{finding.affected_asset ?? finding.asset_id}</span>
                  <span>Open →</span>
                </div>
              </Link>
            </Card>
          ))}
        </div>
      )}

      {/* ---- Quick links --------------------------------------------------- */}
      <SectionHeader title="Quick links" />
      <div className="grid three">
        <Link href="/arsenal" style={{ textDecoration: "none", color: "inherit" }}>
          <Card interactive>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div className="metricIcon"><PackageCheck size={16} /></div>
              <div>
                <div className="cardTitle">Arsenal</div>
                <small style={{ color: "var(--text-3)" }}>
                  {arsenal.tools.length} tools · {runnableTools} runner-ready
                </small>
              </div>
            </div>
          </Card>
        </Link>
        <Link href="/reports" style={{ textDecoration: "none", color: "inherit" }}>
          <Card interactive>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div className="metricIcon"><Download size={16} /></div>
              <div>
                <div className="cardTitle">Reports</div>
                <small style={{ color: "var(--text-3)" }}>Markdown + JSON with scope, evidence, safety statement</small>
              </div>
            </div>
          </Card>
        </Link>
        <Link href="/audit" style={{ textDecoration: "none", color: "inherit" }}>
          <Card interactive>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div className="metricIcon"><Network size={16} /></div>
              <div>
                <div className="cardTitle">Audit log</div>
                <small style={{ color: "var(--text-3)" }}>Every scope decision recorded</small>
              </div>
            </div>
          </Card>
        </Link>
      </div>
    </>
  );
}
